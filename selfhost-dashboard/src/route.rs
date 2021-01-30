use std::convert::TryFrom;
use std::path::Path;
use crate::webserver::{Request, HttpMethod};
use std::future::Future;
use std::sync::Arc;
use slog::{error, info, debug, trace};
use crate::user;
use crate::app;
use crate::primitives::Stringly;

#[cfg(not(feature = "mock_system"))]
const STATIC_DIR: &str = "/usr/share/selfhost-dashboard/static";

#[cfg(feature = "mock_system")]
const STATIC_DIR: &'static str = "./static";

const COOKIE_LIFETIME_SECONDS: u64 = 3600 * 24 * 365; // one year

enum LoginReason {
    LoggedOut,
    BadCredentials,
    BadInput,
}

impl LoginReason {
    fn suffix(&self) -> &'static str {
        match self {
            LoginReason::LoggedOut => "",
            LoginReason::BadCredentials => "#failure=credentials",
            LoginReason::BadInput => "#failure=input",
        }
    }
}

enum Error {
    NotAuthorized,
    Forbidden(&'static str),
    InvalidData(&'static str),
    NotFound,
    Internal,
    RedirectToLogin(LoginReason),
    RedirectToRegistration,
}

impl From<&'_ DirectoryTraversalError> for Error {
    fn from(_value: &DirectoryTraversalError) -> Self {
        Error::InvalidData("directory traversal is not allowed")
    }
}

impl From<&'_ app::OpenError> for Error {
    fn from(value: &app::OpenError) -> Self {
        use app::OpenError;

        match value {
            OpenError::NonAdmin => Error::Forbidden("Non-admins are not authorized to open admin-only apps"),
            OpenError::RejectedWithMessage(_) | OpenError::RejectedWithInvalidMessage => Error::Forbidden("You are not allowed to open this application"),
            OpenError::EntryPointExec { .. } | OpenError::EntryPointFailedWithMessage { .. } |  OpenError::EntryPointFailedWithInvalidMessage { .. } |
            OpenError::SystemUserNotFound | OpenError::TaskJoin(_) | OpenError::EntryPointKilledWithMessage { .. } |
            OpenError::EntryPointKilledWithInvalidMessage | OpenError::EntryPointWaitFailed { .. } | OpenError::ReadingStdoutFailed { .. } => Error::Internal,
        }
    }
}

fn log_and_convert<E>(logger: &slog::Logger) -> impl '_ + FnOnce(E) -> Error where E: 'static + std::error::Error, for<'a> &'a E: Into<Error> {
    move |error| {
        let ret = (&error).into();
        error!(logger, "request failed"; "error" => #error);
        ret
    }
}

fn api_auth(error: crate::login::RequestError) -> Error {
    use crate::login::RequestError;

    match error {
        RequestError::MissingCookies => Error::NotAuthorized,
        RequestError::BadCookies => Error::NotAuthorized,
        RequestError::NoUserRegistered => Error::NotAuthorized,
        RequestError::InternalError => Error::Internal,
        RequestError::InvalidUserName => Error::InvalidData("invalid user name"),
    }
}

fn view_auth(error: crate::login::RequestError) -> Error {
    use crate::login::RequestError;

    match error {
        RequestError::MissingCookies => Error::RedirectToLogin(LoginReason::LoggedOut),
        RequestError::BadCookies => Error::RedirectToLogin(LoginReason::LoggedOut),
        RequestError::NoUserRegistered => Error::RedirectToRegistration,
        RequestError::InternalError => Error::Internal,
        RequestError::InvalidUserName => Error::RedirectToLogin(LoginReason::BadInput),
    }
}

impl Error {
    fn response<S: crate::webserver::Server>(self, prefix: &str) -> S::ResponseBuilder {
        use crate::webserver::ResponseBuilder;

        match self {
            Error::NotAuthorized => {
                let mut builder = S::ResponseBuilder::with_status(401);
                builder.set_body("Not authorized".to_owned().into());
                builder
            },
            Error::Forbidden(message) => {
                let mut builder = S::ResponseBuilder::with_status(403);
                builder.set_body(format!("Forbidden: {}", message).into());
                builder
            },
            Error::InvalidData(message) => {
                let mut builder = S::ResponseBuilder::with_status(400);
                builder.set_body(format!("Invalid request: {}", message).into());
                builder
            },
            Error::NotFound => {
                let mut builder = S::ResponseBuilder::with_status(404);
                builder.set_body("Not found".to_owned().into());
                builder
            },
            Error::Internal => {
                let mut builder = S::ResponseBuilder::with_status(500);
                builder.set_body("Internal server error".to_owned().into());
                builder
            },
            Error::RedirectToLogin(reason) => S::ResponseBuilder::redirect(&format!("{}/login{}", prefix, reason.suffix()), crate::webserver::RedirectKind::SeeOther),
            Error::RedirectToRegistration => S::ResponseBuilder::redirect(&format!("{}/login#uninitialized=true", prefix), crate::webserver::RedirectKind::SeeOther),
        }
    }
}

// Logs the error and replaces it with a simple version.
fn e<'a, E: 'static + std::error::Error>(new_err: Error, message: &'static str, logger: &'a slog::Logger) -> impl 'a + FnOnce(E) -> Error {
    move |error| {
        error!(logger, "{}", message; "error" => #error);
        new_err
    }
}

str_validation_newtype!(SafeResourcePath);

impl<S: Stringly> SafeResourcePath<S> {
    pub fn prefix(&self, prefix: &'static str) -> SafeResourcePath<String> {
        SafeResourcePath(format!("{}/{}", prefix, self.0.as_ref()))
    }
}

impl SafeResourcePath<&'static str> {
    /// Allowing only static shoud make sure it's either a literal or explicit leak.
    fn from_literal(value: &'static str) -> Self {
        SafeResourcePath(value)
    }
}

impl TryFrom<String> for SafeResourcePath<String> {
    type Error = DirectoryTraversalError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.starts_with("../") || value.ends_with("/..") || value.contains("/../") {
            Err(DirectoryTraversalError)
        } else {
            Ok(SafeResourcePath(value))
        }
    }
}

impl<'a> TryFrom<&'a str> for SafeResourcePath<&'a str> {
    type Error = DirectoryTraversalError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        if value.starts_with("../") || value.ends_with("/..") || value.contains("/../") {
            Err(DirectoryTraversalError)
        } else {
            Ok(SafeResourcePath(value))
        }
    }
}

impl<S: Stringly> From<app::Name<S>> for SafeResourcePath<S> {
    fn from(value: app::Name<S>) -> Self {
        SafeResourcePath(value.into_inner())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("directory traversal is not allowed")]
pub struct DirectoryTraversalError;

fn internal_server_error<S: crate::webserver::Server>() -> S::ResponseBuilder {
    use crate::webserver::ResponseBuilder;
 
    let mut builder = S::ResponseBuilder::with_status(500);
    builder.set_body("Internal server error".into());
    builder
}

fn scan_content_type<P: AsRef<Path>>(file_path: P, logger: &slog::Logger) -> Result<String, ()> {
    match file_path.as_ref().extension().and_then(|extension| extension.to_str()) {
        Some("html") => return Ok("text/html".to_owned()),
        Some("css") => return Ok("text/css".to_owned()),
        Some("js") => return Ok("text/javascript".to_owned()),
        Some("png") => return Ok("image/png".to_owned()),
        Some("svg") => return Ok("image/svg+xml".to_owned()),
        _ => (),
    }
    let output = std::process::Command::new("file")
        .arg("-i")
        .arg(file_path.as_ref())
        .output()
        .map_err(|error| error!(logger, "failed to execute file"; "error" => #error))?;

    if !output.status.success() {
        error!(logger, "file -i {} failed", file_path.as_ref().display(); "exit_code" => %output.status);
        return Err(())
    }

    String::from_utf8(output.stdout)
        .map_err(|error| error!(logger, "failed to decode content type"; "error" => #error))
        .map(|mut content_type| {
            content_type.retain(|c| c != '\n');
            content_type
        })
}

pub fn serve_static_abs<S: crate::webserver::Server, Str: Stringly>(abs_path: &SafeResourcePath<Str>, content_type: Option<&str>, logger: slog::Logger) -> S::ResponseBuilder {
    use crate::webserver::ResponseBuilder;

    let logger = logger.new(slog::o!("static_file_path" => abs_path.as_ref().into_owned()));
    debug!(logger, "Attempting to serve a file");
    // This is to return 404 instead of 500
    if !Path::new(&**abs_path).exists() {
        error!(logger, "file not found"; "path" => %abs_path);
        return not_found::<S>();
    }

    let content_type_owned;
    let content_type = match content_type {
        Some(content_type) => content_type,
        None => {
            let result = scan_content_type(&**abs_path, &logger);
            content_type_owned = match result {
                Ok(content_type) => content_type,
                Err(_) => return internal_server_error::<S>(),
            };
            &content_type_owned
        },
    };

    debug!(logger, "scanned content type"; "content_type" => content_type);

    let file_contents = std::fs::read(&**abs_path);
    let file_contents = match file_contents {
        Ok(file_contents) => file_contents,
        Err(error) => {
            error!(logger, "failed to serve a static file"; "path" => %abs_path, "error" => #error);
            return internal_server_error::<S>();
        },
    };

    let mut builder = S::ResponseBuilder::with_status(200);
    builder.set_body(file_contents);
    builder.set_content_type(content_type);
    builder
}

pub fn serve_static<S: crate::webserver::Server, Str: Stringly>(resource: &SafeResourcePath<Str>, content_type: Option<&str>, logger: slog::Logger) -> S::ResponseBuilder {
    // We must NOT use Path::join because that function would replace the path if it's
    // absolute.
    let abs_path = resource.prefix(STATIC_DIR);

    serve_static_abs::<S, _>(&abs_path, content_type, logger)
}

fn not_found<S: crate::webserver::Server>() -> S::ResponseBuilder {
    use crate::webserver::ResponseBuilder;

    let mut builder = S::ResponseBuilder::with_status(404);
    builder.set_body("Error: Page not found".into());
    builder.set_content_type("text/html");
    builder
}

pub async fn route<S: crate::webserver::Server, Db: 'static + user::Db + Send>(prefix: Arc<str>, user_db: Db, apps: Arc<app::config::Apps>, request: S::Request, logger: slog::Logger) -> S::ResponseBuilder where S::Request: Send + Sync, Db::SetCookieFuture: Send, Db::GetUserFuture: Send, Db::GetUserError: Send, Db::SetCookieError: Send, Db::InsertUserFuture: Send {
    match route_raw::<S, _>(Arc::clone(&prefix), user_db, apps, request, logger).await {
        Ok(response) => response,
        Err(error) => error.response::<S>(&prefix),
    }
}

fn route_raw<S: crate::webserver::Server, Db: 'static + user::Db + Send>(prefix: Arc<str>, mut user_db: Db, apps: Arc<app::config::Apps>, request: S::Request, logger: slog::Logger) -> impl Future<Output=Result<S::ResponseBuilder, Error>> + Send where S::Request: Send + Sync, Db::SetCookieFuture: Send, Db::GetUserFuture: Send, Db::GetUserError: Send, Db::SetCookieError: Send, Db::InsertUserFuture: Send {
    use crate::webserver::ResponseBuilder;
    use crate::login::SignupRequest;

    let logger = logger.new(slog::o!("path" => request.path().to_owned(), "method" => format!("{:?}", request.method())));

    async move {
        let path = if request.path().starts_with(&*prefix) {
            &request.path()[prefix.len()..]
        } else {
            error!(logger, "invalid path");
            return Err(Error::NotFound);
        };

        let (component, remaining) = if path.is_empty() {
            ("", "")
        } else {
            match path[1..].find('/') {
                Some(idx) => {
                    let idx = idx + 1; // find started at offset 1
                    (&path[..idx], &path[(idx + 1)..])
                },
                None => (path, ""),
            }
        };

        trace!(logger, "about to route"; "component" => component, "remaining" => remaining);

        match (component, request.method()) {
            ("", HttpMethod::Get) | ("/", HttpMethod::Get) => {
                // There's nothing secret here, but redirecting the user immediately is a better
                // UX.
                crate::login::auth_request::<_, S>(&mut user_db, request, logger.clone()).await.map_err(view_auth)?;
                Ok(serve_static::<S, _>(&SafeResourcePath::from_literal("index.html"), Some("text/html"), logger))
            },
            ("/static", HttpMethod::Get) => {
                let path = SafeResourcePath::try_from(remaining.to_owned())
                    .map_err(log_and_convert(&logger))?;

                Ok(serve_static::<S, _>(&path, None, logger))
            },
            ("/icons", HttpMethod::Get) => {
                let icon_path = SafeResourcePath::<&str>::try_from(remaining)
                    .map_err(log_and_convert(&logger))?;

                let icon_path = icon_path.prefix(app::config::DIRS.app_icons);
                Ok(serve_static_abs::<S, _>(&icon_path, None, logger))
            },
            ("/apps", HttpMethod::Get) => {
                let user = crate::login::auth_request::<_, S>(&mut user_db, request, logger.clone())
                    .await
                    .map_err(api_auth)?;

                Ok(app::get_apps::<S>(&user, &prefix, &apps))
            },
            ("/login", HttpMethod::Get) => Ok(serve_static::<S, _>(&SafeResourcePath::from_literal("login.html"), Some("text/html"), logger)),
            ("/login", HttpMethod::Post) => {
                use crate::login::LoginError;

                let name = request
                    .post_form_arg("username")
                    .map_err(|error| { error!(logger, "failed to decode form data"; "error" => #error); Error::RedirectToLogin(LoginReason::BadInput) })?
                    .ok_or_else(|| { error!(logger, "missing user name"); Error::RedirectToLogin(LoginReason::BadInput) })?;
                let password = request
                    .post_form_arg("password")
                    .map_err(|error| { error!(logger, "failed to decode form data"; "error" => #error); Error::RedirectToLogin(LoginReason::BadInput) })?
                    .ok_or_else(|| { error!(logger, "missing user password"); Error::RedirectToLogin(LoginReason::BadInput) })?;

                let name = user::Name::try_from(name.to_owned()).map_err(e(Error::InvalidData("user name contains invalid character"), "invalid user name", &logger))?;

                let login_request = crate::login::LoginRequest {
                    name: name.clone(),
                    password: password.to_owned(),
                };
                let result = crate::login::check_login(&mut user_db, login_request).await;

                match result {
                    Ok(success) => {
                        let mut builder = S::ResponseBuilder::redirect(&prefix, crate::webserver::RedirectKind::SeeOther);
                        builder.set_cookie("user_name", &success.name, Some(COOKIE_LIFETIME_SECONDS));
                        builder.set_cookie("auth_token", &success.cookie.to_string(), Some(COOKIE_LIFETIME_SECONDS));
                        Ok(builder)
                    },
                    Err(LoginError::BadUserPassword) => {
                        if &*name == "admin" {
                            let signup_request = SignupRequest {
                                name: name.to_owned(),
                                password: password.to_owned(),
                            };

                            match crate::login::signup(&mut user_db, signup_request).await {
                                Ok(cookie) => {
                                    let mut builder = S::ResponseBuilder::redirect(&prefix, crate::webserver::RedirectKind::SeeOther);
                                    builder.set_cookie("user_name", &name, Some(COOKIE_LIFETIME_SECONDS));
                                    builder.set_cookie("auth_token", &cookie.to_string(), Some(COOKIE_LIFETIME_SECONDS));
                                    Ok(builder)
                                },
                                Err(user::InsertError::UserExists) => {
                                    error!(logger, "Invalid user name or password");
                                    Err(Error::RedirectToLogin(LoginReason::BadCredentials))
                                },
                                Err(user::InsertError::DatabaseError(error)) => {
                                    error!(logger, "failed to insert user due to database error"; "error" => #error);
                                    Err(Error::Internal)
                                },
                            }
                        } else {
                            Err(Error::RedirectToLogin(LoginReason::BadCredentials))
                        }
                    },
                    Err(LoginError::DbGetUserError(error)) => {
                        error!(logger, "failed to retrieve the user"; "error" => #error);
                        Err(Error::Internal)
                    },
                    Err(LoginError::DbSetCookieError(error)) => {
                        error!(logger, "failed to set authentication cookie"; "error" => #error);
                        Err(Error::Internal)
                    },
                }
            },
            ("/open-app", HttpMethod::Get) => {
                let app_name = app::Name::try_from(remaining.to_owned()).map_err(e(Error::InvalidData("invalid application name"), "failed to parse app name", &logger))?;

                let logger = logger.new(slog::o!("app" => app_name.clone()));

                let user = crate::login::auth_request::<_, S>(&mut user_db, request, logger.clone())
                    .await
                    .map_err(view_auth)?;
                let app = match apps.get(&*app_name) {
                    Some(app) => app,
                    None => {
                        error!(logger, "application not found");
                        return Err(Error::NotFound);
                    },
                };

                let url = app.get_open_url(&app_name, &user).await.map_err(log_and_convert(&logger))?;

                Ok(S::ResponseBuilder::redirect(&url, crate::webserver::RedirectKind::Temporary))
            },
            ("/logout", HttpMethod::Get) => {
                let user = crate::login::auth_request::<_, S>(&mut user_db, request, logger.clone()).await.map_err(view_auth)?;
                let logger = logger.new(slog::o!("user_name" => user.name().to_owned()));

                user.logout(&mut user_db).await.map_err(e(Error::Internal, "failed to log out", &logger))?;

                info!(logger, "user logged out");
                let mut builder = S::ResponseBuilder::redirect(&format!("{}/login", prefix), crate::webserver::RedirectKind::SeeOther);
                builder.set_cookie("user_name", "", Some(0));
                builder.set_cookie("auth_token", "", Some(0));
                Ok(builder)
            },
            _ => Err(Error::NotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SafeResourcePath;
    test_str_val_ok!(resource_path_simple, SafeResourcePath, "foo");
    test_str_val_ok!(resource_path_slash_begin, SafeResourcePath, "/foo");
    test_str_val_ok!(resource_path_two_slashes, SafeResourcePath, "/foo/bar");
    test_str_val_ok!(resource_path_dot, SafeResourcePath, "/foo/bar.png");
    test_str_val_ok!(resource_path_hidden, SafeResourcePath, "/foo/.png");
    test_str_val_err!(resource_path_traversal_begin, SafeResourcePath, "../foo");
    test_str_val_err!(resource_path_traversal_end, SafeResourcePath, "foo/..");
    test_str_val_err!(resource_path_traversal_middle, SafeResourcePath, "foo/../bar");
    test_str_val_err!(resource_path_traversal_consecutive, SafeResourcePath, "foo/../../bar");
}
