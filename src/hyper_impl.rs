use std::collections::HashMap;
use std::future::Future;
use hyper::service::{make_service_fn, service_fn};

const MAX_REQUEST_LEN: usize = 4096;

pub struct ParsedRequest {
    //request: http::Request<hyper::Body>,
    request_parts: http::request::Parts,
    form_data: HashMap<String, String>,
    cookies: HashMap<String, String>,
}

impl ParsedRequest {
    async fn parse(request: http::Request<hyper::Body>) -> Self {
        use futures::StreamExt;

        let cookies = request
            .headers()
            .get_all(http::header::COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|cookie| cookie.split("; ").filter_map(|pair| {
                let mut spliter = pair.splitn(2, '=');
                let key = spliter.next()?;
                let val = spliter.next()?;
                Some((key.to_owned(), val.to_owned()))
            }))
            .collect();

        let (parts, body) = request.into_parts();
        let body_bytes = body
            .scan(0usize, move |len, item| {
                if let Ok(bytes) = &item {
                    *len = (*len).saturating_add(bytes.len());
                }
                let len = *len;
                async move {
                    if len <= MAX_REQUEST_LEN {
                        item.ok()
                    } else {
                        None
                    }
                }
            })
            .fold(Vec::<u8>::new(), |mut vec, bytes| { vec.extend(&bytes); async move { vec }})
            .await;

        let form_data = url::form_urlencoded::parse(&body_bytes)
            .into_owned()
            .collect();

        ParsedRequest {
            request_parts: parts,
            form_data,
            cookies,
        }
    }
}

impl crate::webserver::Request for ParsedRequest {
    fn path(&self) -> &str {
        self.request_parts.uri.path()
    }

    fn method(&self) -> crate::webserver::HttpMethod {
        use crate::webserver::HttpMethod;

        match self.request_parts.method {
            http::Method::GET => HttpMethod::Get,
            http::Method::POST => HttpMethod::Post,
            _ => HttpMethod::Other,
        }
    }

    fn post_form_arg(&self, key: &str) -> Result<Option<&str>, crate::webserver::PostFormError> {
        Ok(self.form_data.get(key).map(AsRef::as_ref))
    }

    fn get_cookie(&self, key: &str) -> Option<&str> {
        self.cookies.get(key).map(AsRef::as_ref)
    }
}

impl<T> crate::webserver::Server for hyper::server::Builder<T> where T: 'static + hyper::server::accept::Accept, T::Conn: tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin + Send + 'static, T::Error: std::error::Error + Send + Sync {
    type ServeError = hyper::Error;
    type Request = ParsedRequest;
    type ResponseBuilder = crate::http_impl::ResponseBuilder;
    type ServeFuture = std::pin::Pin<Box<dyn Future<Output=Result<(), Self::ServeError>>>>;

    fn serve<Fun, Fut>(self, handler: Fun) -> Self::ServeFuture where Fun: 'static + Sync + Send + Clone + Fn(Self::Request) -> Fut, Fut: Future<Output=Self::ResponseBuilder> + Send {
        let make_svc = make_service_fn(move |_| {
            let handler = handler.clone();
            async move {
                Ok::<_, hyper::Error>(service_fn(move |request| {
                    let handler = handler.clone();
                    async move {
                        let request = ParsedRequest::parse(request).await;
                        let response = handler(request).await;
                        response.finalize::<hyper::Body>()
                    }
                }))
            }
        });

        Box::pin(self.serve(make_svc))
    }
}
