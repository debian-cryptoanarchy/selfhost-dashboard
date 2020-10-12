use std::convert::TryFrom;
use std::path::Path;
use crate::webserver::{Request, HttpMethod};
use std::future::Future;
use std::sync::Arc;
use slog::{error, warn, info, debug, trace};
use std::fmt;

#[cfg(not(feature = "mock_system"))]
const STATIC_DIR: &'static str = "/usr/share/selfhost-dashboard/static";

#[cfg(feature = "mock_system")]
const STATIC_DIR: &'static str = "./static";

#[derive(Copy, Clone)]
struct AppName<S: AsRef<str>>(S);

impl<S: AsRef<str>> AppName<S> {
    fn into_inner(self) -> S {
        self.0
    }
}

impl<S: AsRef<str>> std::ops::Deref for AppName<S> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

/*
impl<S: AsRef<str>> AsRef<str> for AppName<S> {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}
*/

impl<S: AsRef<str>> fmt::Display for AppName<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self.0.as_ref(), f)
    }
}

impl<S: AsRef<str>> fmt::Debug for AppName<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self.0.as_ref(), f)
    }
}

impl TryFrom<String> for AppName<String> {
    type Error = InvalidAppName;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if let Some((pos, invalid_char)) = value.chars().enumerate().find(|&(_, c)| c != '-' && (c < 'a' || c > 'z')) {
            Err(InvalidAppName {
                pos,
                invalid_char,
                name: value.into(),
            })
        } else {
            Ok(AppName(value))
        }
    }
}

impl<S: AsRef<str>> slog::Value for AppName<S> {
    fn serialize(&self, record: &slog::Record, key: slog::Key, serializer: &mut dyn slog::Serializer) -> slog::Result {
        serializer.emit_str(key, self.0.as_ref())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid app name '{name}', forbidden char '{invalid_char} at {pos}")]
struct InvalidAppName {
    name: String,
    pos: usize,
    invalid_char: char,
}

pub struct SafeResourcePath<S>(S);

impl<S: AsRef<str>> SafeResourcePath<S> {
    pub fn template(&self, prefix: &'static str, suffix: &'static str) -> SafeResourcePath<String> {
        SafeResourcePath(format!("{}/{}/{}", prefix, self.0.as_ref(), suffix))
    }

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

impl<S: AsRef<str>> std::ops::Deref for SafeResourcePath<S> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl<S: AsRef<str>> AsRef<str> for SafeResourcePath<S> {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl<S: AsRef<str>> fmt::Display for SafeResourcePath<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self.0.as_ref(), f)
    }
}

impl<S: AsRef<str>> fmt::Debug for SafeResourcePath<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self.0.as_ref(), f)
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

impl<S: AsRef<str>> From<AppName<S>> for SafeResourcePath<S> {
    fn from(value: AppName<S>) -> Self {
        SafeResourcePath(value.into_inner())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("directory traversal is not allowed")]
pub struct DirectoryTraversalError;

fn bail_to_login<S: crate::webserver::Server>(message: &str, logger: slog::Logger) -> S::ResponseBuilder {
    error!(logger, "login failed"; "reason" => message);
    serve_static::<S, _>(&SafeResourcePath::from_literal("login.html"), Some("text/html"), logger)
}

fn bail_to_login_with_err<E: std::fmt::Display, S: crate::webserver::Server>(message: &str, error: &E, logger: slog::Logger) -> S::ResponseBuilder {
    error!(logger, "login failed"; "reason" => message, "error" => %error);
    serve_static::<S, _>(&SafeResourcePath::from_literal("login.html"), Some("text/html"), logger)
}

fn internal_server_error<S: crate::webserver::Server>() -> S::ResponseBuilder {
    use crate::webserver::ResponseBuilder;
 
    let mut builder = S::ResponseBuilder::with_status(500);
    builder.set_body("Internal server error".into());
    builder
}

fn scan_content_type<P: AsRef<Path>>(file_path: P, logger: &slog::Logger) -> Result<String, ()> {
    let output = std::process::Command::new("file")
        .arg("-i")
        .arg(file_path.as_ref())
        .output()
        .map_err(|error| error!(logger, "failed to execute file"; "error" => %error))?;

    if !output.status.success() {
        error!(logger, "file -i {} failed", file_path.as_ref().display(); "exit_code" => %output.status);
        return Err(())
    }

    String::from_utf8(output.stdout)
        .map_err(|error| error!(logger, "failed to decode content type"; "error" => %error))
        .map(|mut content_type| {
            content_type.retain(|c| c != '\n');
            content_type
        })
}

pub fn serve_static_abs<S: crate::webserver::Server, Str: AsRef<str>>(abs_path: &SafeResourcePath<Str>, content_type: Option<&str>, logger: slog::Logger) -> S::ResponseBuilder {
    use crate::webserver::ResponseBuilder;

    let logger = logger.new(slog::o!("static_file_path" => abs_path.as_ref().to_owned()));
    debug!(logger, "Attempting to serve a file");
    // This is to return 404 instead of 500
    if !Path::new(abs_path.as_ref()).exists() {
        error!(logger, "file not found"; "path" => %abs_path);
        return not_found::<S>();
    }

    let content_type_owned;
    let content_type = match content_type {
        Some(content_type) => content_type,
        None => {
            let result = scan_content_type(abs_path.as_ref(), &logger);
            content_type_owned = match result {
                Ok(content_type) => content_type,
                Err(_) => return internal_server_error::<S>(),
            };
            &content_type_owned
        },
    };

    debug!(logger, "scanned content type"; "content_type" => content_type);

    let file_contents = std::fs::read_to_string(abs_path.as_ref());
    let file_contents = match file_contents {
        Ok(file_contents) => file_contents,
        Err(error) => {
            error!(logger, "failed to serve a static file"; "path" => %abs_path, "error" => %error);
            return internal_server_error::<S>();
        },
    };

    let mut builder = S::ResponseBuilder::with_status(200);
    builder.set_body(file_contents);
    builder.set_content_type(content_type);
    builder
}

pub fn serve_static<S: crate::webserver::Server, Str: AsRef<str>>(resource: &SafeResourcePath<Str>, content_type: Option<&str>, logger: slog::Logger) -> S::ResponseBuilder {
    use crate::webserver::ResponseBuilder;

    // We must NOT use Path::join because that function would replace the path if it's
    // absolute.
    let abs_path = resource.prefix(STATIC_DIR);

    serve_static_abs::<S, _>(&abs_path, content_type, logger)
}

fn open_dynamic<S: crate::webserver::Server, Str: AsRef<str>>(app_name: &AppName<Str>, user: &crate::login::AuthenticatedUser, logger: &slog::Logger) -> Result<String, S::ResponseBuilder> {
    use crate::webserver::ResponseBuilder;

    let entry_point_path = format!("{}/{}/open", crate::apps::config::DIRS.app_entry_points, app_name);
    let output = std::process::Command::new(&entry_point_path)
        .arg(user.name())
        .output()
        .map_err(|error| {
            error!(logger, "failed to execute entry point"; "error" => %error, "entry_point_path" => entry_point_path);
            internal_server_error::<S>()
        })?;

    if !output.status.success() {
        let is_internal = match (output.status.code(), String::from_utf8(output.stderr)) {
            (Some(1), Ok(message)) => { error!(logger, "access to app rejected"; "exit_code" => %output.status, "message" => message); false },
            (Some(1), Err(_)) => { error!(logger, "access to app rejected (invalid debug message)"; "exit_code" => %output.status); false },
            (Some(other), Ok(message)) => { error!(logger, "access to app failed"; "exit_code" => %output.status, "message" => message); true },
            (Some(other), Err(_)) => { error!(logger, "access to app failed (invalid debug message)"; "exit_code" => %output.status); true },
            (None, Ok(message)) => { error!(logger, "entry point killed by a signal"; "exit_code" => %output.status, "message" => message); true },
            (None, Err(_)) => { error!(logger, "entry point killed by a signaled (invalid debug message)"; "exit_code" => %output.status); true },
        };

        return Err(if is_internal {
            internal_server_error::<S>()
        } else {
            let mut builder = S::ResponseBuilder::with_status(403);
            builder.set_body("You are not allowed to access this application".to_owned());
            builder
        });
    }

    String::from_utf8(output.stdout).map_err(|error| {
        error!(logger, "failed to decode url suffix"; "error" => %error);
        internal_server_error::<S>()
    })
}

fn not_found<S: crate::webserver::Server>() -> S::ResponseBuilder {
    use crate::webserver::ResponseBuilder;

    let mut builder = S::ResponseBuilder::with_status(404);
    builder.set_body("Error: Page not found".into());
    builder.set_content_type("text/html");
    builder
}

pub fn route<S: crate::webserver::Server, Db: 'static + crate::login::UserDb + Send>(prefix: Arc<str>, mut user_db: Db, apps: Arc<crate::apps::config::Apps>, request: S::Request, logger: slog::Logger) -> impl Future<Output=S::ResponseBuilder> + Send where S::Request: Send + Sync, Db::SetCookieFuture: Send, Db::GetUserFuture: Send, Db::GetUserError: Send, Db::SetCookieError: Send, Db::InsertUserFuture: Send {
    use crate::webserver::ResponseBuilder;
    use crate::login::{SignupRequest, InsertUserError};

    let logger = logger.new(slog::o!("path" => request.path().to_owned(), "method" => format!("{:?}", request.method())));

    async move {
        let path = if request.path().starts_with(&*prefix) {
            &request.path()[prefix.len()..]
        } else {
            return not_found::<S>();
        };

        let (component, remaining) = if path.is_empty() {
            ("", "")
        } else {
            match path[1..].find('/') {
                Some(idx) => (&path[..(idx + 1)], &path[(idx + 2)..]),
                None => (path, ""),
            }
        };

        trace!(logger, "about to route"; "component" => component, "remaining" => remaining);

        match (component, request.method()) {
            ("", HttpMethod::Get) | ("/", HttpMethod::Get) => {
                // There's nothing secret here, but redirecting the user immediately is a better
                // UX.
                match crate::login::auth_request::<_, S>(&prefix, &mut user_db, request, logger.clone()).await {
                    Ok(_) => serve_static::<S, _>(&SafeResourcePath::from_literal("index.html"), Some("text/html"), logger),
                    Err(response) => response,
                }
            },
            ("/static", HttpMethod::Get) => {
                let path = match SafeResourcePath::try_from(remaining.to_owned()) {
                    Ok(path) => path,
                    Err(_) => {
                        warn!(logger, "directory traversal detected");
                        return not_found::<S>();
                    },
                };

                serve_static::<S, _>(&path, None, logger)
            },
            ("/icons", HttpMethod::Get) => {
                let icon_path = match SafeResourcePath::try_from(remaining) {
                    Ok(app_name) => app_name,
                    Err(error) => {
                        error!(logger, "invalid app name"; "error" => %error);
                        let mut builder = S::ResponseBuilder::with_status(400);
                        builder.set_body("Invalid app name, only lower case letters and dashes are allowed.".to_owned());
                        return builder;
                    }
                };

                let icon_path = icon_path.prefix(crate::apps::config::DIRS.app_icons);
                serve_static_abs::<S, _>(&icon_path, None, logger)
            },
            ("/apps", HttpMethod::Get) => {
                let user = match crate::login::auth_request::<_, S>(&prefix, &mut user_db, request, logger.clone()).await {
                    Ok(user) => user,
                    Err(response) => return response,
                };

                crate::apps::get_apps::<S>(&user, &prefix, &apps)
            },
            ("/login", HttpMethod::Get) => serve_static::<S, _>(&SafeResourcePath::from_literal("login.html"), Some("text/html"), logger),
            ("/login", HttpMethod::Post) => {
                use crate::login::LoginError;

                let name = request.post_form_arg("username");
                let password = request.post_form_arg("password");

                let (name, password) = match (name, password) {
                    (Ok(Some(name)), Ok(Some(password))) => (name.to_owned(), password.to_owned()),
                    (Ok(None), Ok(Some(_))) => return bail_to_login::<S>("missing user name", logger),
                    (Ok(Some(_)), Ok(None)) => return bail_to_login::<S>("missing user password", logger),
                    (Ok(None), Ok(None)) => return bail_to_login::<S>("missing user name and password", logger),
                    (Err(error), _) | (_, Err(error)) => return bail_to_login_with_err::<_, S>("failed to decode form data", &error, logger),
                };

                let login_request = crate::login::LoginRequest {
                    name: name.clone(),
                    password: password.clone(),
                };
                let result = crate::login::check_login(&mut user_db, login_request).await;

                match result {
                    Ok(success) => {
                        let mut builder = S::ResponseBuilder::redirect(&prefix, crate::webserver::RedirectKind::SeeOther);
                        builder.set_cookie("user_name", &success.name, Some(31536000));
                        builder.set_cookie("auth_token", &success.cookie, Some(31536000));
                        builder
                    },
                    Err(LoginError::BadUserPassword) => {
                        if name == "admin" {
                            let signup_request = SignupRequest {
                                name: name.clone(),
                                password,
                            };

                            match crate::login::signup(&mut user_db, signup_request).await {
                                Ok(cookie) => {
                                    let mut builder = S::ResponseBuilder::redirect(&prefix, crate::webserver::RedirectKind::SeeOther);
                                    builder.set_cookie("user_name", &name, Some(31536000));
                                    builder.set_cookie("auth_token", &cookie, Some(31536000));
                                    builder
                                },
                                Err(InsertUserError::UserExists) => bail_to_login::<S>("invalid user name or password", logger),
                                Err(InsertUserError::DatabaseError(error)) => {
                                    error!(logger, "failed to insert user due to database error"; "error" => %error);
                                    internal_server_error::<S>()
                                },
                            }
                        } else {
                            bail_to_login::<S>("invalid user name or password", logger)
                        }
                    },
                    Err(LoginError::DbGetUserError(error)) => bail_to_login_with_err::<_, S>("failed to retrieve the user", &error, logger),
                    Err(LoginError::DbSetCookieError(error)) => bail_to_login_with_err::<_, S>("failed to set authentication cookie", &error, logger),
                }
            },
            ("/open_app", HttpMethod::Get) => {
                use crate::apps::config::EntryPoint;

                let app_name = match AppName::try_from(remaining.to_owned()) {
                    Ok(app_name) => app_name,
                    Err(error) => {
                        error!(logger, "invalid app name"; "error" => %error);
                        let mut builder = S::ResponseBuilder::with_status(400);
                        builder.set_body("Invalid app name, only lower case letters and dashes are allowed.".to_owned());
                        return builder;
                    }
                };

                let logger = logger.new(slog::o!("app" => app_name.clone()));

                let user = match crate::login::auth_request::<_, S>(&prefix, &mut user_db, request, logger.clone()).await {
                    Ok(user) => user,
                    Err(response) => return response,
                };

                let app = match apps.get(&*app_name) {
                    Some(app) => app,
                    None => {
                        return not_found::<S>();
                    },
                };

                if app.admin_only && !user.is_admin() {
                    let mut builder = S::ResponseBuilder::with_status(403);
                    builder.set_body("Non-admins are not authorized to open admin-only apps".to_owned());
                    return builder;
                }

                let owned_url;
                let url = match &app.entry_point {
                    EntryPoint::Static { url, } => url,
                    EntryPoint::Dynamic => {
                        owned_url = match open_dynamic::<S, _>(&app_name, &user, &logger) {
                            Ok(url) => url,
                            Err(response) => return response,
                        };
                        &owned_url
                    },
                };

                S::ResponseBuilder::redirect(url, crate::webserver::RedirectKind::Temporary)
            },
            ("/logout", HttpMethod::Get) => {
                let user = match crate::login::auth_request::<_, S>(&prefix, &mut user_db, request, logger.clone()).await {
                    Ok(user) => user,
                    Err(response) => return response,
                };

                let logger = logger.new(slog::o!("user_name" => user.name().to_owned()));

                match user.logout(&mut user_db).await {
                    Ok(_) => {
                        info!(logger, "user logged out");
                        let mut builder = S::ResponseBuilder::redirect(&format!("{}/login", prefix), crate::webserver::RedirectKind::SeeOther);
                        builder.set_cookie("user_name", "", Some(0));
                        builder.set_cookie("auth_token", "", Some(0));
                        builder
                    },
                    Err(error) => {
                        error!(logger, "failed to log out"; "error" => %error);
                        internal_server_error::<S>()
                    },
                }
            },
            _ => not_found::<S>(),
        }
    }
}
