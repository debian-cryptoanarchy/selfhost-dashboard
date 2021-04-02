mod config {
    #![allow(clippy::all)]
    #![allow(unused)]
    include!(concat!(env!("OUT_DIR"), "/configure_me_config.rs"));
}

use config::{Config, ResultExt};

#[macro_use]
extern crate serde_derive;
extern crate configure_me;
pub extern crate hex;

#[macro_use]
mod newtype_macros;
mod marker;
mod primitives;
mod user;
mod login;
mod app;
mod webserver;
mod route;
mod io;
mod postgres_impl;
mod hyper_impl;
mod http_impl;
mod slog_impl;
#[cfg(any(test, feature = "mock_system"))]
mod mock_db;

use std::fmt;
use std::sync::Arc;
use slog::error;

#[derive(serde_derive::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

impl From<LogLevel> for sloggers::types::Severity {
    fn from(value: LogLevel) -> Self {
        use sloggers::types::Severity;

        match value {
            LogLevel::Trace => Severity::Trace,
            LogLevel::Debug => Severity::Debug,
            LogLevel::Info => Severity::Info,
            LogLevel::Warning => Severity::Warning,
            LogLevel::Error => Severity::Error,
            LogLevel::Critical => Severity::Critical,
        }
    }
}

pub struct InvalidLogLevel {
    input: String,
}

impl fmt::Display for InvalidLogLevel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid log level '{}'", self.input)
    }
}


impl std::str::FromStr for LogLevel {
    type Err = InvalidLogLevel;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "trace" => Ok(LogLevel::Trace),
            "debug" => Ok(LogLevel::Debug),
            "info" => Ok(LogLevel::Info),
            "warning" => Ok(LogLevel::Warning),
            "error" => Ok(LogLevel::Error),
            "critical" => Ok(LogLevel::Critical),
            _ => Err(InvalidLogLevel { input: s.to_owned(), })
        }
    }
}

impl configure_me::parse_arg::ParseArgFromStr for LogLevel {
    fn describe_type<W: fmt::Write>(mut writer: W) -> fmt::Result {
        write!(writer, "one of: trace, debug, info, warning, error, critical")
    }
}

trait LogResultExt {
    type Item;

    fn die_on_error(self, logger: &slog::Logger, message: &str) -> Self::Item;
}

impl<T, E> LogResultExt for Result<T, E> where E: 'static + std::error::Error {
    type Item = T;

    fn die_on_error(self, logger: &slog::Logger, message: &str) -> Self::Item {
        self.unwrap_or_else(|error| {
            slog::error!(logger, "{}", message; "error" => #error);
            std::process::exit(1)
        })
    }
}

#[tokio::main]
async fn main() {
    use sloggers::Build;
    use crate::webserver::{self, Request};

    let (config, _) = Config::including_optional_config_files(&["/etc/selfhost-dashboard/interface.conf", "/etc/selfhost-dashboard/database"]).unwrap_or_exit();

    let logger = sloggers::terminal::TerminalLoggerBuilder::new()
        .destination(sloggers::terminal::Destination::Stderr)
        .level(config.log_level)
        .build()
        .expect("failed to create logger");

    let request_logger = logger.clone();

    #[cfg(not(feature = "mock_system"))]
    let db_client = postgres_impl::Database::connect(&config.pg_uri, tokio_postgres::tls::NoTls)
        .die_on_error(&logger, "Failed to connect to the database");

    #[cfg(feature = "mock_system")]
    let db_client = mock_db::Db::default();

    #[cfg(not(feature = "mock_system"))]
    db_client
        .init_tables()
        .await
        .die_on_error(&logger, "Failed to initialize tables in the database");

    let root_path: Arc<str> = config.root_path.into();

    let apps = app::config::load_and_check_apps(logger.clone()).die_on_error(&logger, "failed to load apps");
    let apps = Arc::new(apps);

    let server = hyper::Server::bind(&([127, 0, 0, 1], config.bind_port).into());

    let server = webserver::Server::serve(server, move |request| {
        slog::info!(request_logger, "received request"; "path" => request.path(), "method" => ?request.method());
        route::route::<hyper::server::Builder<hyper::server::conn::AddrIncoming>, _>(Arc::clone(&root_path), db_client.clone(), Arc::clone(&apps), request, request_logger.clone())
    });

    let server = async {
        if let Err(error) = server.await {
            error!(logger, "web server failed"; "error" => #error);
        }
    };

    server.await
}
