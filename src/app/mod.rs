use crate::user;
use crate::primitives::Stringly;

pub mod api {
    #[derive(serde_derive::Serialize)]
    pub struct App {
        pub name: String,
        pub icon: String,
        pub url: String,
    }

    #[derive(serde_derive::Serialize)]
    pub struct AppsResponse {
        pub apps: Vec<App>,
    }
}

pub mod config {
    use std::path::Path;
    use std::collections::HashMap;
    use serde::de::DeserializeOwned;
    use std::os::unix::fs::PermissionsExt;

    #[derive(serde_derive::Deserialize)]
    #[non_exhaustive]
    pub enum EntryPoint {
        #[non_exhaustive]
        Static { url: String, },
        Dynamic,
    }

    #[derive(serde_derive::Deserialize)]
    #[non_exhaustive]
    pub struct SelfhostAppConfig {
        pub root_path: String,
    }

    #[derive(serde_derive::Deserialize)]
    #[non_exhaustive]
    pub struct AppInfo {
        pub user_friendly_name: String,
        pub admin_only: bool,
        pub entry_point: EntryPoint,
    }

    pub type Apps = HashMap<String, super::App>;

    pub struct Dirs {
        pub app_info: &'static str,
        pub app_icons: &'static str,
        pub app_entry_points: &'static str,
        pub selfhost_apps: &'static str,
    }

    #[cfg(not(feature = "mock_system"))]
    pub const DIRS: Dirs = Dirs {
        app_info: "/etc/selfhost-dashboard/apps",
        app_icons: "/usr/share/selfhost-dashboard/apps/icons",
        app_entry_points: "/usr/lib/selfhost-dashboard/apps/entry_points",
        selfhost_apps: "/etc/selfhost/apps",
    };

    #[cfg(feature = "mock_system")]
    pub const DIRS: Dirs = Dirs {
        app_info: "./test_data/etc/selfhost-dashboard/apps",
        app_icons: "./test_data/usr/share/selfhost-dashboard/apps/icons",
        app_entry_points: "./test_data/usr/lib/selfhost-dashboard/apps/entry_points",
        selfhost_apps: "./test_data/etc/selfhost/apps",
    };

    #[derive(Debug, thiserror::Error)]
    pub enum LoadTomlError {
        #[error("IO error")]
        Io(#[from] std::io::Error),
        #[error("failed to parse TOML")]
        Toml(#[from] toml::de::Error),
    }

    fn load_toml<T: DeserializeOwned, P: AsRef<Path>>(file_name: P) -> Result<T, LoadTomlError> {
        let file_contents = std::fs::read(file_name)?;
        toml::from_slice(&file_contents).map_err(Into::into)
    }

    #[derive(Debug, thiserror::Error)]
    pub enum LoadYamlError {
        #[error("IO error")]
        Io(#[from] std::io::Error),
        #[error("failed to parse YAML")]
        Yaml(#[from] serde_yaml::Error),
    }

    fn load_yaml<T: DeserializeOwned, P: AsRef<Path>>(file_name: P) -> Result<T, LoadYamlError> {
        let file_contents = std::fs::read(file_name)?;
        serde_yaml::from_slice(&file_contents).map_err(Into::into)
    }

    #[derive(Debug, thiserror::Error)]
    pub enum LoadAppError {
        #[error("failed to load TOML")]
        Toml(#[from] LoadTomlError),
        #[error("failed to load YAML")]
        Yaml(#[from] LoadYamlError),
        #[error("the application is missing the main icon")]
        MissingIcon,
        #[error("failed to stat entry point")]
        StatEntyrPoint(std::io::Error),
        #[error("the entry point has invalid permissions")]
        BadEntryPointPerm(u32),
        #[error("empty root path")]
        EmptyRootPath,
    }

    /// Loads app info and does sanity checking of associated files
    fn load_and_check_app(name: &str) -> Result<super::App, LoadAppError> {
        let app_info_path = Path::new(DIRS.app_info).join(name).join("meta.toml");
        let app_info = load_toml::<AppInfo, _>(app_info_path).map_err(LoadAppError::Toml)?;
        let main_icon_file = Path::new(DIRS.app_icons).join(name).join("entry_main.png");
        if !main_icon_file.exists() {
            return Err(LoadAppError::MissingIcon);
        }
        if let EntryPoint::Dynamic = app_info.entry_point {
            let entry_point_path = Path::new(DIRS.app_entry_points).join(name).join("open");
            let stat = entry_point_path.metadata().map_err(LoadAppError::StatEntyrPoint)?;
            let perm = stat.permissions();
            let perm_bits = perm.mode();
            // The entry point must be readable & executable by group and NOT writable by others
            if perm_bits & 0o052 != 0o050 {
                return Err(LoadAppError::BadEntryPointPerm(perm_bits));
            }
        }

        let selfhost_config = load_yaml::<SelfhostAppConfig, _>(format!("{}/{}.conf", DIRS.selfhost_apps, name))?;

        if selfhost_config.root_path.is_empty() {
            return Err(LoadAppError::EmptyRootPath);
        }

        Ok(super::App {
            app_info,
            root_path: selfhost_config.root_path,
        })
    }

    pub enum BadApp {
        LoadFailed(LoadAppError),
        NonUtf8Path,
    }

    pub trait BadAppLogger {
        fn bad_app_found(&mut self, path: &Path, reason: BadApp);
        fn ignored_app(&mut self, path: &Path);
    }

    impl<T: BadAppLogger> BadAppLogger for &mut T {
        fn bad_app_found(&mut self, path: &Path, reason: BadApp) {
            (*self).bad_app_found(path, reason);
        }

        fn ignored_app(&mut self, path: &Path) {
            (*self).ignored_app(path);
        }
    }

    #[derive(Debug)]
    pub enum LoadAppsError {
        OpenDir(std::io::Error),
        ReadDirEntry(std::io::Error),
    }

    pub fn load_and_check_apps<L: BadAppLogger>(mut logger: L) -> Result<Apps, LoadAppsError> {
        let mut apps = HashMap::new();
        for file in std::fs::read_dir(DIRS.app_info).map_err(LoadAppsError::OpenDir)? {
            let file = file.map_err(LoadAppsError::ReadDirEntry)?;
            let file_name = file.file_name();
            let file_name = match file_name.to_str() {
                Some(file_name) => file_name,
                None => {
                    logger.bad_app_found(&Path::new(DIRS.app_info).join(file_name), BadApp::NonUtf8Path);
                    continue;
                },
            };
            let app = load_and_check_app(file_name);
            let app = match app {
                Ok(app) => app,
                Err(error) => {
                    logger.bad_app_found(&Path::new(DIRS.app_info).join(file_name), BadApp::LoadFailed(error));
                    continue;
                },
            };
            apps.insert(file_name.to_owned(), app);
        }
        Ok(apps)
    }
}

pub fn get_apps<S: crate::webserver::Server>(user: &user::Authenticated, prefix: &str, app_info: &config::Apps) -> S::ResponseBuilder {
    use crate::webserver::ResponseBuilder;

    let apps = app_info
        .iter()
        .filter(|(_, app)| user.is_admin() || !app.app_info.admin_only)
        .map(|(k, v)| {
            let icon = format!("/icons/{}/entry_main.png", k);
            let url = match &v.app_info.entry_point {
                config::EntryPoint::Static { url, } => format!("{}{}", v.root_path, url),
                config::EntryPoint::Dynamic => format!("{}/open-app/{}", prefix, k),
            };

            api::App {
                name: v.app_info.user_friendly_name.clone(),
                icon,
                url,
            }
        })
        .collect();

    let resp = api::AppsResponse {
        apps,
    };

    let serialized_response = serde_json::to_string(&resp).expect("Serialization to string should never fail");
    let mut builder = S::ResponseBuilder::with_status(200);
    builder.set_content_type("application/json");
    builder.set_body(serialized_response.into());

    builder
}

str_char_whitelist_newtype!(Name, NameError, "application name", |c| c != '-' && (c < 'a' || c > 'z'));

pub struct App {
    app_info: config::AppInfo,
    root_path: String,
}

impl App {
    fn open_dynamic<Str: Stringly>(app_name: &Name<Str>, user: &user::Authenticated) -> Result<String, OpenError> {
        let entry_point_path = format!("{}/{}/open", self::config::DIRS.app_entry_points, app_name);
        let output = std::process::Command::new(&entry_point_path)
            .arg(user.name())
            .output()
            .map_err(OpenError::EntryPointExec)?;

        if !output.status.success() {
            return Err(match (output.status.code(), String::from_utf8(output.stderr)) {
                (Some(1), Ok(message)) => OpenError::RejectedWithMessage(message),
                (Some(1), Err(_)) => OpenError::RejectedWithInvalidMessage,
                (Some(exit_code), Ok(message)) => OpenError::EntryPointFailedWithMessage { message, exit_code, },
                (Some(exit_code), Err(_)) => OpenError::EntryPointFailedWithInvalidMessage { exit_code, },
                (None, Ok(message)) => OpenError::EntryPointKilledWithMessage { message },
                (None, Err(_)) => OpenError::EntryPointKilledWithInvalidMessage,
            });
        }

        String::from_utf8(output.stdout).map_err(OpenError::DecodingFailed)
    }

    pub fn get_open_url(&self, app_name: &Name, user: &user::Authenticated) -> Result<String, OpenError> {
        if self.app_info.admin_only && !user.is_admin() {
            return Err(OpenError::NonAdmin.into());
        }

        Ok(match &self.app_info.entry_point {
            config::EntryPoint::Static { url, } => format!("{}{}", self.root_path, url),
            config::EntryPoint::Dynamic => format!("{}{}", self.root_path, App::open_dynamic(&app_name, &user)?),
        })
    }
}

#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    #[error("the user is not an administrator")]
    NonAdmin,
    #[error("failed to execute entry point")]
    EntryPointExec(#[source] std::io::Error),
    #[error("user is not allowed to open the application: {0}")]
    RejectedWithMessage(String),
    #[error("user is not allowed to open the application (invalid message)")]
    RejectedWithInvalidMessage,
    #[error("entry point failed, exit code: {exit_code}, message: {message}")]
    EntryPointFailedWithMessage { message: String, exit_code: i32, },
    #[error("entry point failed, exit code: {exit_code}, (invalid message)")]
    EntryPointFailedWithInvalidMessage { exit_code: i32, },
    #[error("entry point killed, message: {message}")]
    EntryPointKilledWithMessage { message: String, },
    #[error("entry point killed, (invalid message)")]
    EntryPointKilledWithInvalidMessage,
    #[error("decoding of the resulting URL failed")]
    DecodingFailed(std::string::FromUtf8Error),
}

#[cfg(test)]
mod tests {
    use super::Name;

    test_str_val_ok!(app_name_simple, Name, "foo");
    test_str_val_ok!(app_name_dash, Name, "foo-bar");
    test_str_val_err!(app_name_underscore, Name, "foo_bar");
    test_str_val_err!(app_name_dot, Name, "foo.bar");
    test_str_val_err!(app_name_space, Name, "foo bar");
    test_str_val_err!(app_name_slash, Name, "foo/bar");
}
