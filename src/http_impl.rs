use std::convert::{TryFrom, TryInto};
use http::response::Builder as HttpResponseBuilder;

pub struct ResponseBuilder {
    inner: HttpResponseBuilder,
    body: Option<Vec<u8>>,
}

impl ResponseBuilder {
    fn new(status: http::status::StatusCode) -> Self {
        ResponseBuilder {
            inner: HttpResponseBuilder::new().status(status),
            body: None,
        }
    }

    pub fn finalize<B: From<Vec<u8>>>(self) -> http::Result<http::Response<B>> {
        self.inner.body(self.body.unwrap_or_else(Default::default).into())
    }
}

impl crate::webserver::ResponseBuilder for ResponseBuilder {
    fn with_status(status: u16) -> Self {
        Self::new(status.try_into().expect("invalid sttus code"))
    }

    fn set_body(&mut self, body: String) {
        self.body = Some(body.into());
    }

    fn set_content_type(&mut self, content_type: &str) {
        self.inner.headers_mut().expect("http API is retarded").insert(http::header::CONTENT_TYPE, http::header::HeaderValue::try_from(content_type).expect("Invalid value for content type"));
    }

    fn set_cookie(&mut self, key: &str, value: &str, expires_after_seconds: Option<u64>) {
        let cookie_string = match expires_after_seconds {
            Some(max_age) => format!("{}={}; Max-Age={}; HttpOnly; SameSite=Lax", key, value, max_age),
            None => format!("{}={}; HttpOnly; SameSite=Lax", key, value)
        };
        let cookie = cookie_string
            .try_into()
            .expect("invalid Set-Cookie header");
        self.inner.headers_mut().expect("http API is retarded").append(http::header::SET_COOKIE, cookie);
    }

    fn redirect(url: &str, kind: crate::webserver::RedirectKind) -> Self {
        use crate::webserver::RedirectKind;

        let status = match kind {
            RedirectKind::Temporary => http::status::StatusCode::TEMPORARY_REDIRECT,
            RedirectKind::Permanent => http::status::StatusCode::PERMANENT_REDIRECT,
            RedirectKind::SeeOther => http::status::StatusCode::SEE_OTHER,
        };

        let mut builer = Self::new(status);
        builer.inner.headers_mut().expect("http API is retarded").insert(http::header::LOCATION, url.try_into().expect("invalid value for redirect URL"));
        builer
    }
}
