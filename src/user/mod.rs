pub mod types;
pub mod db;

pub use types::UserName as Name;
pub use db::UserDb as Db;
pub use db::UserRecord as DbRecord;
pub use types::AuthenticatedUser as Authenticated;
pub use db::InsertUserError as InsertError;
