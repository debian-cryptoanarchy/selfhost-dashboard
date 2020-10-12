use hex::FromHex;
use serde_derive::{Serialize, Deserialize};
use std::str::FromStr;
use std::convert::{TryFrom, TryInto};
use core::future::Future;
use std::collections::HashMap;
use std::fmt;
use slog::{error, debug, trace};

const ADMIN_USER_NAME: &'static str = "admin";

// 128 bits is sufficient
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct Salt([u8; 16]);

impl FromStr for Salt {
    type Err = SaltError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        FromHex::from_hex(value)
            .map(Salt)
            .map_err(SaltError)
    }
}

impl<'a> TryFrom<&'a str> for Salt {
    type Error = SaltError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl TryFrom<String> for Salt {
    type Error = SaltError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct SaltError(hex::FromHexError);

impl tokio_postgres::types::ToSql for crate::login::Salt {
    fn to_sql(&self, ty: &tokio_postgres::types::Type, out: &mut tokio_postgres::types::private::BytesMut) -> Result<tokio_postgres::types::IsNull, Box<dyn std::error::Error + 'static + Sync + Send>> {
        (&(self.0) as &[u8]).to_sql(ty, out)
    }

    fn accepts(ty: &tokio_postgres::types::Type) -> bool {
        <&[u8]>::accepts(ty)
    }


    fn to_sql_checked(&self, ty: &tokio_postgres::types::Type, out: &mut tokio_postgres::types::private::BytesMut) -> Result<tokio_postgres::types::IsNull, Box<dyn std::error::Error + 'static + Sync + Send>> {
        (&(self.0) as &[u8]).to_sql_checked(ty, out)
    }
}

impl<'a> tokio_postgres::types::FromSql<'a> for crate::login::Salt {
    fn from_sql(ty: &tokio_postgres::types::Type, raw: &'a [u8]) -> Result<Self, Box<dyn std::error::Error + 'static + Sync + Send>> {
        let &arr = <&'a [u8]>::from_sql(ty, raw)?
            .try_into()
            .map_err(|error| Box::new(error))?;
        Ok(Self(arr))
    }

    fn accepts(ty: &tokio_postgres::types::Type) -> bool {
        <&'a [u8]>::accepts(ty)
    }
}
// 256 bit to avoid collisions
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct HardenedPassword([u8; 32]);

impl FromStr for HardenedPassword {
    type Err = HardenedPasswordError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        FromHex::from_hex(value)
            .map(HardenedPassword)
            .map_err(HardenedPasswordError)
    }
}

impl<'a> TryFrom<&'a str> for HardenedPassword {
    type Error = HardenedPasswordError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl TryFrom<String> for HardenedPassword {
    type Error = HardenedPasswordError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl tokio_postgres::types::ToSql for crate::login::HardenedPassword {
    fn to_sql(&self, ty: &tokio_postgres::types::Type, out: &mut tokio_postgres::types::private::BytesMut) -> Result<tokio_postgres::types::IsNull, Box<dyn std::error::Error + 'static + Sync + Send>> {
        (&(self.0) as &[u8]).to_sql(ty, out)
    }

    fn accepts(ty: &tokio_postgres::types::Type) -> bool {
        <&[u8]>::accepts(ty)
    }


    fn to_sql_checked(&self, ty: &tokio_postgres::types::Type, out: &mut tokio_postgres::types::private::BytesMut) -> Result<tokio_postgres::types::IsNull, Box<dyn std::error::Error + 'static + Sync + Send>> {
        (&(self.0) as &[u8]).to_sql_checked(ty, out)
    }
}

impl<'a> tokio_postgres::types::FromSql<'a> for crate::login::HardenedPassword {
    fn from_sql(ty: &tokio_postgres::types::Type, raw: &'a [u8]) -> Result<Self, Box<dyn std::error::Error + 'static + Sync + Send>> {
        let &arr = <&'a [u8]>::from_sql(ty, raw)?
            .try_into()
            .map_err(|error| Box::new(error))?;
        Ok(Self(arr))
    }

    fn accepts(ty: &tokio_postgres::types::Type) -> bool {
        <&'a [u8]>::accepts(ty)
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct HardenedPasswordError(hex::FromHexError);

#[derive(Clone, Debug)]
pub struct UserRecord {
    pub name: String,
    pub hardened_password: HardenedPassword,
    pub salt: Salt,
    pub cookie: Option<String>,
}

#[derive(Debug)]
pub enum InsertUserError<E> {
    UserExists,
    DatabaseError(E),
}

pub trait UserDb {
    type GetUserError: std::error::Error;
    type GetUserFuture: Future<Output=Result<Option<UserRecord>, Self::GetUserError>>;
    type InsertUserError: std::error::Error;
    type InsertUserFuture: Future<Output=Result<(), InsertUserError<Self::InsertUserError>>>;
    type SetCookieError: std::error::Error;
    type SetCookieFuture: Future<Output=Result<(), Self::SetCookieError>>;

    fn get_user(&mut self, name: &str) -> Self::GetUserFuture;
    /// Must NOT overrite existing user!
    fn insert_new_user(&mut self, record: UserRecord) -> Self::InsertUserFuture;
    fn set_cookie(&mut self, name: &str, value: Option<&str>) -> Self::SetCookieFuture;
}

#[derive(Debug)]
pub struct LoginRequest {
    pub name: String,
    pub password: String,
}

#[derive(Debug)]
pub struct LoginSuccessful {
    pub name: String,
    pub cookie: String,
}

#[derive(Debug)]
pub enum LoginError<GetUser, SetCookie> {
    BadUserPassword,
    DbGetUserError(GetUser),
    DbSetCookieError(SetCookie),
}

impl<T, U> LoginError<T, U> {
    pub fn is_internal(&self) -> bool {
        match self {
            LoginError::BadUserPassword => false,
            LoginError::DbGetUserError(_) => true,
            LoginError::DbSetCookieError(_) => true,
        }
    }
}

fn harden_password(password: &str, salt: &Salt) -> HardenedPassword {
    let params = scrypt::ScryptParams::recommended();
    let mut output = HardenedPassword([0; 32]);
    scrypt::scrypt(password.as_ref(), &salt.0, &params, &mut output.0)
        // The only possible error is input error, which is impossible
        // because we pass in a constant
        .expect("Failed to run scrypt");

    output
}

fn generate_cookie() -> String {
    use hex::ToHex;

    let cookie = rand::random::<[u8; 16]>();
    cookie.encode_hex()
}

// Compares the inputs in constant time
fn const_eq(first: &[u8; 32], second: &[u8; 32]) -> bool {
    first
        .iter()
        .zip(second)
        .map(|(a, b)| (a != b) as usize)
        .sum::<usize>() == 0
}

pub struct SignupRequest {
    pub name: String,
    pub password: String,
}

pub async fn signup<Db: UserDb>(database: &mut Db, request: SignupRequest) -> Result<String, InsertUserError<Db::InsertUserError>> {
    let salt = Salt(rand::random());
    let hardened_password = harden_password(&request.password, &salt);
    let cookie = generate_cookie();
    let record = UserRecord {
        name: request.name,
        hardened_password,
        salt,
        cookie: Some(cookie.clone()),
    };

    database.insert_new_user(record).await?;
    Ok(cookie)
}

pub async fn check_login<Db: UserDb>(database: &mut Db, request: LoginRequest) -> Result<LoginSuccessful, LoginError<Db::GetUserError, Db::SetCookieError>> {
    let user = database
        .get_user(&request.name)
        .await
        .map_err(LoginError::DbGetUserError)?;

    // This function is supposed to be constant time with respect to the user entry existing
    // That's why it looks "weird" - it hashes the password with constant salt
    static EMPTY_SALT: Salt = Salt([0; 16]);

    let salt = user.as_ref().map_or(&EMPTY_SALT, |user| &user.salt);
    let hardened_password = harden_password(&request.password, &salt);
    let user = user.ok_or(LoginError::BadUserPassword)?;

    if const_eq(&hardened_password.0, &user.hardened_password.0) {
        let cookie = generate_cookie();

        database
            .set_cookie(&user.name, Some(&cookie))
            .await
            .map_err(LoginError::DbSetCookieError)?;

        Ok(LoginSuccessful { name: request.name, cookie, })
    } else {
        Err(LoginError::BadUserPassword)
    }
}

pub struct AuthRequest {
    user_name: String,
    auth_token: String,
}

#[must_use]
pub enum AuthStatus {
    LoggedIn(String),
    NotLoggedIn,
}

pub enum AuthError<GetUserError> {
    GetUser(GetUserError),
    InvalidAuthTokenLen,
    DbCorrupted,
}

impl<E: fmt::Display> fmt::Display for AuthError<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AuthError::GetUser(error) => write!(f, "failed to get user: {}", error),
            AuthError::InvalidAuthTokenLen => write!(f, "invalid lenght of authentication token"),
            AuthError::DbCorrupted => write!(f, "database corrupted (invalid length of cookie in database)"),
        }
    }
}


async fn check_cookie<Db: UserDb>(database: &mut Db, request: AuthRequest, logger: slog::Logger) -> Result<AuthStatus, AuthError<Db::GetUserError>> {
    debug!(logger, "retrieving user"; "user" => &request.user_name);
    let user = database
        .get_user(&request.user_name)
        .await
        .map_err(AuthError::GetUser)?;

    let (user_name, db_cookie) = match user {
        Some(UserRecord { name, cookie: Some (cookie), .. }) => (name, cookie),
        _ => return Ok(AuthStatus::NotLoggedIn),
    };

    trace!(logger, "checking cookie"; "db_cookie" => &db_cookie, "user_cookie" => &request.auth_token);

    let db_cookie = <&[u8; 32]>::try_from(db_cookie.as_bytes()).map_err(|_| AuthError::DbCorrupted)?;
    let req_cookie = <&[u8; 32]>::try_from(request.auth_token.as_bytes()).map_err(|_| AuthError::InvalidAuthTokenLen)?;

    if const_eq(req_cookie, db_cookie) {
        Ok(AuthStatus::LoggedIn(user_name))
    } else {
        Ok(AuthStatus::NotLoggedIn)
    }
}

pub struct AuthenticatedUser {
    name: String,
}

impl AuthenticatedUser {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn is_admin(&self) -> bool {
        self.name == ADMIN_USER_NAME
    }

    pub async fn logout<Db: UserDb>(&self, database: &mut Db) -> Result<(), Db::SetCookieError> {
        database
            .set_cookie(&self.name, None)
            .await
    }
}

// Can't be async fn because of https://github.com/rust-lang/rust/issues/63033
pub fn auth_request<'a, Db: UserDb, S: crate::webserver::Server>(prefix: &'a str, database: &'a mut Db, request: S::Request, logger: slog::Logger) -> impl 'a + Future<Output=Result<AuthenticatedUser, S::ResponseBuilder>> where S::Request: 'a {
    let prefix = prefix.to_owned();
    async move {
        use crate::webserver::RedirectKind;
        use crate::webserver::Request;
        use crate::webserver::ResponseBuilder;

        let user_name = request.get_cookie("user_name");
        let auth_token = request.get_cookie("auth_token");

        let auth_request = match (user_name, auth_token) {
            (Some(user_name), Some(auth_token)) => AuthRequest { user_name: user_name.to_owned(), auth_token: auth_token.to_owned(), },
            (None, None) => {
                let suffix = match database.get_user(ADMIN_USER_NAME).await {
                    Ok(Some(_)) => "",
                    Ok(None) => "#uninitialized=true",
                    Err(error) => {
                        error!(logger, "failed to check presence of the admin user"; "error" => %error);

                        let mut response = S::ResponseBuilder::with_status(500);
                        response.set_body("Internal server error".to_owned());
                        return Err(response);
                    },
                };
                return Err(S::ResponseBuilder::redirect(&format!("{}/login{}", prefix, suffix), RedirectKind::SeeOther));
            },
            _ => return Err(S::ResponseBuilder::redirect(&format!("{}/login", prefix), RedirectKind::SeeOther)),
        };

        let logger = logger.new(slog::o!("user_name" => auth_request.user_name.clone()));

        debug!(logger, "authenticating user");

        let result = check_cookie(database, auth_request, logger.clone()).await;
        match result {
            Ok(AuthStatus::NotLoggedIn) => Err(S::ResponseBuilder::redirect(&format!("{}/login", prefix), RedirectKind::SeeOther)),
            Ok(AuthStatus::LoggedIn(user_name)) => Ok(AuthenticatedUser { name: user_name }),
            Err(AuthError::InvalidAuthTokenLen) => {
                error!(logger, "Invalid auth token length");
                let mut response = S::ResponseBuilder::with_status(400);
                response.set_body("Invalid length of authentication token".to_owned());
                Err(response)
            },
            Err(error) => {
                error!(logger, "Failed to check cookie"; "error" => %error);
                let mut response = S::ResponseBuilder::with_status(500);
                response.set_body("Internal server error".to_owned());
                Err(response)
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use hmap::hmap;
    use super::*;
    use crate::mock_db::Db;

    #[test]
    fn missing_user() {
        let mut db = Db::from(hmap!("satoshi".to_owned() => UserRecord {
            name: "satoshi".to_owned(),
            hardened_password: "000000000000000000000000000000000000000000000000000775f05a074000".parse().unwrap(),
            salt: "0000000000000000000775f05a074000".parse().unwrap(),
            cookie: None,
        }));

        let request = LoginRequest {
            name: "dorian".to_owned(),
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
        let mut db = Db::from(hmap!("satoshi".to_owned() => UserRecord {
            name: "satoshi".to_owned(),
            hardened_password: "000000000000000000000000000000000000000000000000000775f05a074000".parse().unwrap(),
            salt: "0000000000000000000775f05a074000".parse().unwrap(),
            cookie: None,
        }));

        let request = LoginRequest {
            name: "satoshi".to_owned(),
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
        let mut db = Db::from(hmap!("satoshi".to_owned() => UserRecord {
            name: "satoshi".to_owned(),
            hardened_password: "78e78942ef998339bf975422c27d0be88edd4601f4bee1d544b8af12bcd5b7f7".parse().unwrap(),
            salt: "0000000000000000000775f05a074000".parse().unwrap(),
            cookie: None,
        }));

        let request = LoginRequest {
            name: "satoshi".to_owned(),
            password: "If you don't believe me or don't get it I don't have the time to explain".to_owned(),
        };

        let result = tokio_test::block_on(super::check_login(&mut db, request)).expect("login failed");

        assert_eq!(result.name, "satoshi");
    }

    #[test]
    fn signup() {
        let mut db = Db::default();
        let request = SignupRequest {
            name: "admin".to_owned(),
            password: "nbusr123".to_owned(),
        };

        tokio_test::block_on(super::signup(&mut db, request)).expect("Signup failed");

        let request = LoginRequest {
            name: "admin".to_owned(),
            password: "nbusr123".to_owned(),
        };

        let result = tokio_test::block_on(super::check_login(&mut db, request)).expect("login failed");

        assert_eq!(result.name, "admin");

        let request = LoginRequest {
            name: "admin".to_owned(),
            password: "government".to_owned(),
        };

        let result = tokio_test::block_on(super::check_login(&mut db, request));
        let err = result.unwrap_err();

        match err {
            LoginError::BadUserPassword => (),
            x => panic!("Unexpected result: {:?}", x),
        }

        let request = SignupRequest {
            name: "admin".to_owned(),
            password: "scam".to_owned(),
        };

        match tokio_test::block_on(super::signup(&mut db, request)) {
            Err(super::InsertUserError::UserExists) => (),
            x => panic!("Unexpected result: {:?}", x),
        }

    }
}
