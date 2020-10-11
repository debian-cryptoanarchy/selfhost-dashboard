use std::collections::HashMap;
use std::pin::Pin;
use void::Void as Never;
use std::future::Future;
use crate::login::{InsertUserError, UserRecord};
use std::sync::{Arc, RwLock};

#[derive(Default, Clone)]
pub struct Db(Arc<RwLock<HashMap<String, UserRecord>>>);

impl From<HashMap<String, UserRecord>> for Db {
    fn from(value: HashMap<String, UserRecord>) -> Self {
        Db(Arc::new(RwLock::new(value)))
    }
}


impl crate::login::UserDb for Db {
    type GetUserError = Never;
    type GetUserFuture = Pin<Box<dyn 'static + Send + Future<Output=Result<Option<UserRecord>, Self::GetUserError>>>>;
    type InsertUserError = Never;
    type InsertUserFuture = Pin<Box<dyn 'static + Send + Future<Output=Result<(), InsertUserError<Self::InsertUserError>>>>>;
    // We don't care about error handling in tests, just panic
    type SetCookieError = Never;
    type SetCookieFuture = Pin<Box<dyn 'static + Send + Future<Output=Result<(), Self::SetCookieError>>>>;

    fn get_user(&mut self, name: &str) -> Self::GetUserFuture {
        let result = self.0.read().unwrap().get(name).map(Clone::clone);
        Box::pin(async move { Ok(result)} )
    }

    fn insert_new_user(&mut self, record: UserRecord) -> Self::InsertUserFuture {
        let mut inserted = false;
        self.0.write().unwrap().entry(record.name.clone()).or_insert_with(|| { inserted = true; record });
        let result = if inserted {
            Ok(())
        } else {
            Err(InsertUserError::UserExists)
        };

        Box::pin(async move { result })
    }

    fn set_cookie(&mut self, name: &str, value: Option<&str>) -> Self::SetCookieFuture {
        let result = self.0.write().unwrap().get_mut(name).expect("User doesn't exist").cookie = value.map(ToOwned::to_owned);
        Box::pin(async move { Ok(result) })
    }
}

