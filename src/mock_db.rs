use std::collections::HashMap;
use std::pin::Pin;
use void::Void as Never;
use std::future::Future;
use crate::user::{self, types::AuthToken};
use std::sync::{Arc, RwLock};
use crate::primitives::Stringly;

#[derive(Default, Clone)]
pub struct Db(Arc<RwLock<HashMap<String, user::DbRecord>>>);

impl From<HashMap<String, user::DbRecord>> for Db {
    fn from(value: HashMap<String, user::DbRecord>) -> Self {
        Db(Arc::new(RwLock::new(value)))
    }
}

impl user::Db for Db {
    type GetUserError = Never;
    type GetUserFuture = Pin<Box<dyn 'static + Send + Future<Output=Result<Option<user::DbRecord>, Self::GetUserError>>>>;
    type InsertUserError = Never;
    type InsertUserFuture = Pin<Box<dyn 'static + Send + Future<Output=Result<(), user::InsertError<Self::InsertUserError>>>>>;
    // We don't care about error handling in tests, just panic
    type SetCookieError = Never;
    type SetCookieFuture = Pin<Box<dyn 'static + Send + Future<Output=Result<(), Self::SetCookieError>>>>;

    fn get_user<S: 'static + Stringly>(&mut self, name: user::Name<S>) -> Self::GetUserFuture {
        let result = self.0.read().unwrap().get(&*name).map(Clone::clone);
        Box::pin(async move { Ok(result)} )
    }

    fn insert_new_user(&mut self, record: user::DbRecord) -> Self::InsertUserFuture {
        let mut inserted = false;
        self.0.write().unwrap().entry((*record.name).to_owned()).or_insert_with(|| { inserted = true; record });
        let result = if inserted {
            Ok(())
        } else {
            Err(user::InsertError::UserExists)
        };

        Box::pin(async move { result })
    }

    fn set_cookie<S: 'static + Stringly>(&mut self, name: user::Name<S>, value: Option<AuthToken>) -> Self::SetCookieFuture {
        let result = self.0.write().unwrap().get_mut(&*name).expect("User doesn't exist").cookie = value;
        Box::pin(async move { Ok(result) })
    }
}

