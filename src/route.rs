use std::path::Path;
use crate::webserver::{Request, HttpMethod};
use std::future::Future;
use std::sync::Arc;
use slog::{error};

#[cfg(not(feature = "mock_system"))]
const STATIC_DIR: &'static str = "/usr/share/selfhost-dashboard/static";

#[cfg(feature = "mock_system")]
const STATIC_DIR: &'static str = "./static";

fn bail_to_login<S: crate::webserver::Server>(message: &str, logger: slog::Logger) -> S::ResponseBuilder {
    error!(logger, "login failed"; "reason" => message);
    serve_static::<S>("login.html", "text/html", logger)
}

fn bail_to_login_with_err<E: std::fmt::Display, S: crate::webserver::Server>(message: &str, error: &E, logger: slog::Logger) -> S::ResponseBuilder {
    error!(logger, "login failed"; "reason" => message, "error" => %error);
    serve_static::<S>("login.html", "text/html", logger)
}

fn internal_server_error<S: crate::webserver::Server>() -> S::ResponseBuilder {
    use crate::webserver::ResponseBuilder;
 
    let mut builder = S::ResponseBuilder::with_status(500);
    builder.set_body("Internal server error".into());
    builder
}

pub fn serve_static<S: crate::webserver::Server>(resource: &str, content_type: &str, logger: slog::Logger) -> S::ResponseBuilder {
    use crate::webserver::ResponseBuilder;
 
    let file_contents = std::fs::read_to_string(Path::new("/usr/share/selfhost-dashboard/static").join(resource));
    let file_contents = match file_contents {
        Ok(file_contents) => file_contents,
        Err(error) => {
            error!(logger, "failed to serve a static file"; "resource" => resource, "error" => %error);
            return internal_server_error::<S>();
        },
    };

    let mut builder = S::ResponseBuilder::with_status(200);
    builder.set_body(file_contents);
    builder.set_content_type(content_type);
    builder
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

        let component = if path.is_empty() {
            ""
        } else {
            match path[1..].find('/') {
                Some(idx) => &path[..(idx + 1)],
                None => path,
            }
        };

        match (component, request.method()) {
            ("", HttpMethod::Get) | ("/", HttpMethod::Get) => {
                // There's nothing secret here, but redirecting the user immediately is a better
                // UX.
                match crate::login::auth_request::<_, S>(&prefix, &mut user_db, request, logger.clone()).await {
                    Ok(_) => serve_static::<S>("index.html", "text/html", logger),
                    Err(response) => response,
                }
            },
            ("/apps", HttpMethod::Get) => {
                let user = match crate::login::auth_request::<_, S>(&prefix, &mut user_db, request, logger.clone()).await {
                    Ok(user) => user,
                    Err(response) => return response,
                };

                crate::apps::get_apps::<S>(&user, &prefix, &apps)
            },
            ("/login", HttpMethod::Get) => serve_static::<S>("login.html", "text/html", logger),
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
            _ => not_found::<S>(),
        }
    }
}
