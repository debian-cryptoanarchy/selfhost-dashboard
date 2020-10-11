use std::future::Future;
use std::fmt;

pub trait IsFatal {
    fn is_fatal(&self) -> bool;
}

pub trait Server {
    type ServeError: std::error::Error;
    type Request: Request;
    type ResponseBuilder: ResponseBuilder;
    type ServeFuture: Future<Output=Result<(), Self::ServeError>>;

    fn serve<Fun, Fut>(self, handler: Fun) -> Self::ServeFuture where Fun: 'static + Sync + Send + Clone + Fn(Self::Request) -> Fut, Fut: Future<Output=Self::ResponseBuilder> + Send;
}

#[derive(Debug)]
pub enum HttpMethod {
    Get,
    Post,
    Other,
}

pub trait Request {
    fn path(&self) -> &str;
    fn method(&self) -> HttpMethod;
    fn post_form_arg(&self, key: &str) -> Result<Option<&str>, PostFormError>;
    fn get_cookie(&self, key: &str) -> Option<&str>;
}

pub trait Connection {
    type ResponseBuilder: ResponseBuilder;
    type ReplyError: std::error::Error;
    type ReplyFuture: Future<Output=Result<(), Self::ReplyError>>;

    fn reply(self, builder: Self::ResponseBuilder) -> Self::ReplyFuture;
}

#[derive(Debug)]
pub struct PostFormError {
    message: String,
}

impl PostFormError {
    pub fn different_data_type(data_type: Option<&str>) -> Self {
        let message = data_type
            .map(|data_type| format!("Invalid data, expected form found {}", data_type)).unwrap_or_else(|| format!("Unknown data type, expected form"));

        PostFormError {
            message,
        }
    }

    pub fn malformed_data(details: Option<&str>) -> Self {
        let message = details
            .map(|details| format!("Malformed form data: {}", details)).unwrap_or_else(|| format!("Malformed form data"));

        PostFormError {
            message
        }
    }
}

impl fmt::Display for PostFormError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}


pub enum RedirectKind {
    Permanent,
    Temporary,
    SeeOther,
}

pub trait ResponseBuilder: Sized {
    fn with_status(status: u16) -> Self;
    fn set_body(&mut self, body: String);
    fn set_content_type(&mut self, content_type: &str);
    fn set_cookie(&mut self, key: &str, value: &str, expires_after_seconds: Option<u64>);
    fn redirect(url: &str, kind: RedirectKind) -> Self;
}
