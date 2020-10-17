use core::future::Future;
use super::types::AuthToken;
use crate::primitives::Stringly;

#[derive(Clone, Debug)]
pub struct UserRecord {
    pub name: super::Name,
    pub hardened_password: super::types::HardenedPassword,
    pub salt: super::types::Salt,
    pub cookie: Option<AuthToken>,
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

    fn get_user<S: 'static + Stringly + Send + Sync>(&mut self, name: super::Name<S>) -> Self::GetUserFuture;
    /// Must NOT overrite existing user!
    fn insert_new_user(&mut self, record: UserRecord) -> Self::InsertUserFuture;
    fn set_cookie<S: 'static + Stringly + Send + Sync>(&mut self, name: super::Name<S>, value: Option<AuthToken>) -> Self::SetCookieFuture;
}
