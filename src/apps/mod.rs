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

    enum Never {}

    pub struct Reserved(Never);

    #[derive(serde_derive::Deserialize)]
    #[non_exhaustive]
    pub enum EntryPoint {
        #[non_exhaustive]
        Static { url: String, },
        Dynamic,
    }

    #[derive(serde_derive::Deserialize)]
    #[non_exhaustive]
    pub struct AppInfo {
        pub user_friendly_name: String,
        pub admin_only: bool,
        pub entry_point: EntryPoint,
    }

    pub type Apps = HashMap<String, AppInfo>;

    pub struct Dirs {
        pub app_info: &'static str,
        pub app_icons: &'static str,
        pub app_entry_points: &'static str,
    }

    #[cfg(not(feature = "mock_system"))]
    pub const DIRS: Dirs = Dirs {
        app_info: "/etc/selfhost-dashboard/apps",
        app_icons: "/usr/share/selfhost-dashboard/apps/icons",
        app_entry_points: "/usr/lib/selfhost-dashboard/apps/entry_points",
    };

    #[cfg(feature = "mock_system")]
    pub const DIRS: Dirs = Dirs {
        app_info: "./test_data/etc/selfhost-dashboard/apps",
        app_icons: "./test_data/usr/share/selfhost-dashboard/apps/icons",
        app_entry_points: "./test_data/usr/lib/selfhost-dashboard/apps/entry_points",
    };

    #[derive(Debug, thiserror::Error)]
    enum LoadTomlError {
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
    pub enum LoadAppError {
        #[error("failed to parse TOML")]
        Toml(LoadTomlError),
        #[error("the application is missing the main icon")]
        MissingIcon,
        #[error("the application is missing the main entry point")]
        MissingEntryPoint,
        #[error("failed to stat entry point")]
        StatEntyrPoint(std::io::Error),
        #[error("the entry point has invalid permissions")]
        BadEntryPointPerm(u32),
    }

    /// Loads app info and does sanity checking of associated files
    fn load_and_check_app(name: &str) -> Result<AppInfo, LoadAppError> {
        let app_info_path = Path::new(DIRS.app_info).join(name).join("meta.toml");
        let app_info = load_toml::<AppInfo, _>(app_info_path).map_err(LoadAppError::Toml)?;
        let main_icon_file = Path::new(DIRS.app_icons).join(name).join("main.png");
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
        Ok(app_info)
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
            let app_info = load_and_check_app(file_name);
            let app_info = match app_info {
                Ok(app_info) => app_info,
                Err(error) => {
                    logger.bad_app_found(&Path::new(DIRS.app_info).join(file_name), BadApp::LoadFailed(error));
                    continue;
                },
            };
            apps.insert(file_name.to_owned(), app_info);
        }
        Ok(apps)
    }
}

pub fn get_apps<S: crate::webserver::Server>(user: &crate::login::AuthenticatedUser, prefix: &str, app_info: &config::Apps) -> S::ResponseBuilder {
    use crate::webserver::ResponseBuilder;

    let apps = app_info
        .iter()
        .filter(|(_, app)| user.is_admin() || !app.admin_only)
        .map(|(k, v)| {
            let icon = format!("{}/{}/entry_main.png", config::DIRS.app_icons, k);
            let url = match &v.entry_point {
                config::EntryPoint::Static { url, } => url.to_owned(),
                config::EntryPoint::Dynamic => format!("{}/open_app/{}", prefix, k),
            };

            api::App {
                name: v.user_friendly_name.clone(),
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
    builder.set_body(serialized_response);

    builder
}
