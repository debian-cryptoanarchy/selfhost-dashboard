// We want to typechck the code even if it's not used
#![cfg_attr(not(feature = "mock_systen"), allow(unused))]

use std::borrow::Borrow;
use std::pin::Pin;
use std::future::Future;
use crate::user::{self, types::AuthToken};
use crate::primitives::Stringly;

macro_rules! deser_row {
    ($row:expr, $($field:ident$(: $type:ty)?),*) => {
        $(
            let $field $(: $type)? = $row.try_get(stringify!($field))?;
        )*
    };
}

#[derive(Debug, Clone)]
pub struct Database<T> where T: Borrow<tokio_postgres::Client> {
    client: T,
}

impl<T> Database<T> where T: Borrow<tokio_postgres::Client> {
    pub fn new(client: T) -> Self {
        Database {
            client,
        }
    }
}

impl<C> Database<C> where C: Borrow<tokio_postgres::Client> + From<tokio_postgres::Client> {
    pub async fn connect<T>(connection_string: &str, tls: T) -> Result<(Self, tokio_postgres::Connection<tokio_postgres::Socket, T::Stream>), tokio_postgres::Error> where T: tokio_postgres::tls::MakeTlsConnect<tokio_postgres::Socket> {
        tokio_postgres::connect(connection_string, tls)
            .await
            .map(|(client, conn)| (Database::new(client.into()), conn))
    }
}

impl<T> Database<T> where T: 'static + Borrow<tokio_postgres::Client> + Clone + Send + Sync {
    pub fn init_tables(&self) -> impl Future<Output=Result<(), tokio_postgres::Error>> {
        let this = self.clone();
        async move {
            this
                .client
                .borrow()
                .batch_execute("CREATE TABLE IF NOT EXISTS users (name VARCHAR PRIMARY KEY, hardened_password BYTEA, salt BYTEA, auth_token BYTEA)")
                .await
        }
    }
}

type PinnedSendFutureResult<T, E> = Pin<Box<dyn Future<Output=Result<T, E>> + Send>>;

impl<T> user::Db for Database<T> where T: 'static + Borrow<tokio_postgres::Client> + Clone + Send + Sync {
    type GetUserError = tokio_postgres::Error;
    type InsertUserError = tokio_postgres::Error;
    type SetCookieError = tokio_postgres::Error;
    type GetUserFuture = PinnedSendFutureResult<Option<user::DbRecord>, Self::GetUserError>;
    type InsertUserFuture = PinnedSendFutureResult<(), user::InsertError<Self::InsertUserError>>;
    type SetCookieFuture = PinnedSendFutureResult<(), Self::SetCookieError>;

    fn get_user<S: 'static + Stringly + Send + Sync>(&mut self, name: user::Name<S>) -> Self::GetUserFuture {
        let this = self.clone();

        Box::pin(async move {
            let row = this
                .client
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
        let this = self.clone();

        Box::pin(async move {
            this
                .client
                .borrow()
                .query("INSERT INTO users (name, hardened_password, salt, auth_token) VALUES ($1, $2, $3, $4)", &[&record.name, &record.hardened_password, &record.salt, &record.cookie])
                .await
                .map_err(user::InsertError::DatabaseError)?;
            Ok(())
        })
    }

    fn set_cookie<S: 'static + Stringly + Send + Sync>(&mut self, name: user::Name<S>, value: Option<AuthToken>) -> Self::SetCookieFuture {
        let this = self.clone();

        Box::pin(async move {
            this
                .client
                .borrow()
                .query("UPDATE users SET auth_token = $1 WHERE name = $2", &[&value, &name])
                .await?;
            Ok(())
        })
    }
}

pub type ArcDatabase = Database<std::sync::Arc<tokio_postgres::Client>>;
