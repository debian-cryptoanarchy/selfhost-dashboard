use slog::{error, info, Logger};
use std::path::Path;
use crate::app::config::BadApp;

impl<T> crate::app::config::BadAppLogger for Logger<T> where T: slog::SendSyncUnwindSafeDrain<Ok=(), Err=slog::Never> {
    fn bad_app_found(&mut self, path: &Path, reason: BadApp) {
        match reason {
            BadApp::LoadFailed(error) => error!(self, "failed to load app"; "path" => ?path, "error" => ?error),
            BadApp::NonUtf8Path => error!(self, "invalid app name"; "path" => ?path, "reason" => "not UTF-8"),
        }
    }

    fn ignored_app(&mut self, path: &Path) {
        info!(self, "path ignored"; "path" => ?path);
    }
}
