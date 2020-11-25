use std::convert::TryInto;
use slog::{error, debug, trace};
use crate::user;
use crate::user::types::{Salt, AuthToken, HardenedPassword};

#[derive(Debug)]
pub struct LoginRequest {
    pub name: user::Name,
    pub password: String,
}

#[derive(Debug)]
pub struct LoginSuccessful {
    pub name: user::Name,
    pub cookie: AuthToken,
}

#[derive(Debug)]
pub enum LoginError<GetUser, SetCookie> {
    BadUserPassword,
    DbGetUserError(GetUser),
    DbSetCookieError(SetCookie),
}

pub struct SignupRequest {
    pub name: user::Name,
    pub password: String,
}

pub async fn signup<Db: user::Db>(database: &mut Db, request: SignupRequest) -> Result<AuthToken, user::InsertError<Db::InsertUserError>> {
    let salt = Salt::random();
    let hardened_password = HardenedPassword::harden(&request.password, &salt);
    let cookie = AuthToken::random();
    let record = user::DbRecord {
        name: request.name,
        hardened_password,
        salt,
        cookie: Some(cookie),
    };

    database.insert_new_user(record).await?;
    Ok(cookie)
}

pub async fn check_login<Db: user::Db>(database: &mut Db, request: LoginRequest) -> Result<LoginSuccessful, LoginError<Db::GetUserError, Db::SetCookieError>> {
    let user = database
        .get_user(request.name.clone())
        .await
        .map_err(LoginError::DbGetUserError)?;

    // This function is supposed to be constant time with respect to the user entry existing
    // That's why it looks "weird" - it hashes the password with constant salt
    let salt = user.as_ref().map_or(&Salt::EMPTY, |user| &user.salt);
    let hardened_password = HardenedPassword::harden(&request.password, &salt);
    let user = user.ok_or(LoginError::BadUserPassword)?;

    if hardened_password == user.hardened_password {
        let cookie = AuthToken::random();

        database
            .set_cookie(user.name, Some(cookie))
            .await
            .map_err(LoginError::DbSetCookieError)?;

        Ok(LoginSuccessful { name: request.name, cookie, })
    } else {
        Err(LoginError::BadUserPassword)
    }
}

pub struct AuthRequest {
    user_name: user::Name,
    auth_token: String,
}

#[must_use]
pub enum AuthStatus {
    LoggedIn(user::Name),
    NotLoggedIn,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError<GetUserError: 'static + std::error::Error> {
    #[error("failed to get user")]
    GetUser(#[source] GetUserError),
    #[error("invalid authentication token")]
    InvalidAuthToken(#[source] user::types::AuthTokenError),
}

async fn check_cookie<Db: user::Db>(database: &mut Db, request: AuthRequest, logger: slog::Logger) -> Result<AuthStatus, AuthError<Db::GetUserError>> where Db::GetUserError: 'static {
    let req_cookie = request.auth_token.parse::<AuthToken>().map_err(AuthError::InvalidAuthToken)?;

    debug!(logger, "retrieving user"; "user" => &request.user_name);

    let user = database
        .get_user(request.user_name)
        .await
        .map_err(AuthError::GetUser)?;

    let (user_name, db_cookie) = match user {
        Some(user::DbRecord { name, cookie: Some (cookie), .. }) => (name, cookie),
        _ => return Ok(AuthStatus::NotLoggedIn),
    };

    trace!(logger, "checking cookie"; "db_cookie" => &db_cookie, "user_cookie" => &request.auth_token);

    if req_cookie == db_cookie {
        Ok(AuthStatus::LoggedIn(user_name))
    } else {
        Ok(AuthStatus::NotLoggedIn)
    }
}

pub enum RequestError {
    MissingCookies,
    BadCookies,
    NoUserRegistered,
    InternalError,
    InvalidUserName,
}

// Can't be async fn because of https://github.com/rust-lang/rust/issues/63033
pub async fn auth_request<Db: user::Db, S: crate::webserver::Server>(database: &mut Db, request: S::Request, logger: slog::Logger) -> Result<user::Authenticated, RequestError> where Db::GetUserError: 'static {
    use crate::webserver::Request;

    let user_name = request.get_cookie("user_name").map(ToOwned::to_owned).map(TryInto::try_into).transpose().map_err(|error| { error!(logger, "invalid user name"; "error" => %error); RequestError::InvalidUserName })?;
    let auth_token = request.get_cookie("auth_token");

    let auth_request = match (user_name, auth_token) {
        (Some(user_name), Some(auth_token)) => AuthRequest { user_name, auth_token: auth_token.to_owned(), },
        (None, None) => {
            return Err(match database.get_user(user::Name::ADMIN).await {
                Ok(Some(_)) => RequestError::MissingCookies,
                Ok(None) => RequestError::NoUserRegistered,
                Err(error) => {
                    error!(logger, "failed to check presence of the admin user"; "error" => %error);
                    RequestError::InternalError
                },
            })
        },
        _ => return Err(RequestError::MissingCookies),
    };

    let logger = logger.new(slog::o!("user_name" => auth_request.user_name.clone()));

    debug!(logger, "authenticating user");

    let result = check_cookie(database, auth_request, logger.clone()).await;
    match result {
        Ok(AuthStatus::NotLoggedIn) => Err(RequestError::BadCookies),
        Ok(AuthStatus::LoggedIn(user_name)) => Ok(user::Authenticated::user_logged_in(user_name)),
        Err(AuthError::InvalidAuthToken(error)) => {
            error!(logger, "Invalid authentication token"; "error" => %error);
            Err(RequestError::BadCookies)
        },
        Err(error) => {
            error!(logger, "Failed to check cookie"; "error" => %error);
            Err(RequestError::InternalError)
        },
    }
}

#[cfg(test)]
mod tests {
    use hmap::hmap;
    use super::*;
    use crate::mock_db::Db;
    use std::convert::TryInto;

    #[test]
    fn missing_user() {
        let mut db = Db::from(hmap!("satoshi".to_owned() => user::DbRecord {
            name: "satoshi".to_owned().try_into().unwrap(),
            hardened_password: "000000000000000000000000000000000000000000000000000775f05a074000".parse().unwrap(),
            salt: "0000000000000000000775f05a074000".parse().unwrap(),
            cookie: None,
        }));

        let request = LoginRequest {
            name: "dorian".to_owned().try_into().unwrap(),
            password: "I'm not Satoshi".to_owned(),
        };

        let result = tokio_test::block_on(super::check_login(&mut db, request));
        let err = result.unwrap_err();

        match err {
            LoginError::BadUserPassword => (),
            x => panic!("Unexpected result: {:?}", x),
        }
    }

    #[test]
    fn bad_password() {
        let mut db = Db::from(hmap!("satoshi".to_owned() => user::DbRecord {
            name: "satoshi".to_owned().try_into().unwrap(),
            hardened_password: "000000000000000000000000000000000000000000000000000775f05a074000".parse().unwrap(),
            salt: "0000000000000000000775f05a074000".parse().unwrap(),
            cookie: None,
        }));

        let request = LoginRequest {
            name: "satoshi".to_owned().try_into().unwrap(),
            password: "shitcoin".to_owned(),
        };

        let result = tokio_test::block_on(super::check_login(&mut db, request));
        let err = result.unwrap_err();

        match err {
            LoginError::BadUserPassword => (),
            x => panic!("Unexpected result: {:?}", x),
        }
    }

    #[test]
    fn login_success() {
        let mut db = Db::from(hmap!("satoshi".to_owned() => user::DbRecord {
            name: "satoshi".to_owned().try_into().unwrap(),
            hardened_password: "78e78942ef998339bf975422c27d0be88edd4601f4bee1d544b8af12bcd5b7f7".parse().unwrap(),
            salt: "0000000000000000000775f05a074000".parse().unwrap(),
            cookie: None,
        }));

        let request = LoginRequest {
            name: "satoshi".to_owned().try_into().unwrap(),
            password: "If you don't believe me or don't get it I don't have the time to explain".to_owned(),
        };

        let result = tokio_test::block_on(super::check_login(&mut db, request)).expect("login failed");

        assert_eq!(&*result.name, "satoshi");
    }

    #[test]
    fn signup() {
        let mut db = Db::default();
        let request = SignupRequest {
            name: "admin".to_owned().try_into().unwrap(),
            password: "nbusr123".to_owned(),
        };

        tokio_test::block_on(super::signup(&mut db, request)).expect("Signup failed");

        let request = LoginRequest {
            name: "admin".to_owned().try_into().unwrap(),
            password: "nbusr123".to_owned(),
        };

        let result = tokio_test::block_on(super::check_login(&mut db, request)).expect("login failed");

        assert_eq!(&*result.name, "admin");

        let request = LoginRequest {
            name: "admin".to_owned().try_into().unwrap(),
            password: "government".to_owned(),
        };

        let result = tokio_test::block_on(super::check_login(&mut db, request));
        let err = result.unwrap_err();

        match err {
            LoginError::BadUserPassword => (),
            x => panic!("Unexpected result: {:?}", x),
        }

        let request = SignupRequest {
            name: "admin".to_owned().try_into().unwrap(),
            password: "scam".to_owned(),
        };

        match tokio_test::block_on(super::signup(&mut db, request)) {
            Err(crate::user::db::InsertUserError::UserExists) => (),
            x => panic!("Unexpected result: {:?}", x),
        }

    }
}
