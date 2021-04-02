// We want to typechck the code even if it's not used
#![cfg_attr(not(feature = "mock_systen"), allow(unused))]

use std::borrow::Borrow;
use std::pin::Pin;
use std::future::Future;
use crate::user::{self, types::AuthToken};
use crate::primitives::Stringly;
use tokio_postgres::tls::{MakeTlsConnect, TlsConnect};
use tokio_postgres::Socket;
use deadpool_postgres::PoolError;

macro_rules! deser_row {
    ($row:expr, $($field:ident$(: $type:ty)?),*) => {
        $(
            let $field $(: $type)? = $row.try_get(stringify!($field))?;
        )*
    };
}

#[derive(Clone)]
pub struct Database {
    client: deadpool_postgres::Pool,
}

impl Database {
    pub fn connect<T>(connection_string: &str, tls: T) -> Result<Self, tokio_postgres::Error> where T: MakeTlsConnect<Socket> + Clone + Send + Sync + 'static, T::Stream: Send + Sync, T::TlsConnect: Send + Sync, <T::TlsConnect as TlsConnect<Socket>>::Future: Send {
        Ok(Database { client: deadpool_postgres::Pool::new(deadpool_postgres::Manager::from_config(connection_string.parse()?, tls, Default::default()), 8) })
    }
}

impl Database {
    pub fn init_tables(&self) -> impl '_ + Future<Output=Result<(), PoolError>> {
        // client contains Arc
        let client = self.client.clone();

        async move {
            client
                .get()
                .await?
                .batch_execute("CREATE TABLE IF NOT EXISTS users (name VARCHAR PRIMARY KEY, hardened_password BYTEA, salt BYTEA, auth_token BYTEA)")
                .await
                .map_err(Into::into)
        }
    }
}

type PinnedSendFutureResult<T, E> = Pin<Box<dyn Future<Output=Result<T, E>> + Send>>;

impl user::Db for Database {
    type GetUserError = PoolError;
    type InsertUserError = PoolError;
    type SetCookieError = PoolError;
    type GetUserFuture = PinnedSendFutureResult<Option<user::DbRecord>, Self::GetUserError>;
    type InsertUserFuture = PinnedSendFutureResult<(), user::InsertError<Self::InsertUserError>>;
    type SetCookieFuture = PinnedSendFutureResult<(), Self::SetCookieError>;

    fn get_user<S: 'static + Stringly + Send + Sync>(&mut self, name: user::Name<S>) -> Self::GetUserFuture {
        // client contains Arc
        let client = self.client.clone();

        Box::pin(async move {
            let row = client
                .get()
                .await?
                .borrow()
                .query_opt("SELECT * FROM users WHERE name = $1", &[&name])
                .await?;

            row
                .map(|row| {
                    deser_row!(row, name, hardened_password, salt, auth_token);

                    Ok(user::DbRecord {
                        name,
                        hardened_password,
                        salt,
                        cookie: auth_token,
                    })
                })
                .transpose()
        })
    }

    fn insert_new_user(&mut self, record: user::DbRecord) -> Self::InsertUserFuture {
        // client contains Arc
        let client = self.client.clone();

        Box::pin(async move {
            client
                .get()
                .await
                .map_err(user::InsertError::DatabaseError)?
                .borrow()
                .query("INSERT INTO users (name, hardened_password, salt, auth_token) VALUES ($1, $2, $3, $4)", &[&record.name, &record.hardened_password, &record.salt, &record.cookie])
                .await
                .map_err(Into::into)
                .map_err(user::InsertError::DatabaseError)?;
            Ok(())
        })
    }

    fn set_cookie<S: 'static + Stringly + Send + Sync>(&mut self, name: user::Name<S>, value: Option<AuthToken>) -> Self::SetCookieFuture {
        // client contains Arc
        let client = self.client.clone();

        Box::pin(async move {
            client
                .get()
                .await?
                .borrow()
                .query("UPDATE users SET auth_token = $1 WHERE name = $2", &[&value, &name])
                .await?;
            Ok(())
        })
    }
}
