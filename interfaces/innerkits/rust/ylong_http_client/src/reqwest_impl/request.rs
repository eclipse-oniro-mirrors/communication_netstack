/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crate::{Method, Version};
use reqwest::header::{HeaderMap, HeaderName};
use reqwest::{Body, Url};
use std::error::Error;
use std::fmt::{Debug, Display, Formatter};

/// HTTP request implementation.
///
/// Request is a message type that can be sent from a HTTP client to a HTTP server.
///
/// # Examples
///
/// ```
/// use ylong_http_client::{Method, Request};
///
/// let request = Request::builder()
///     .method(Method::GET)
///     .url("www.example.com")
///     .build("Hello World".as_bytes());
/// ```
pub struct Request<T> {
    pub(crate) inner: RequestInner,
    pub(crate) body: T,
}

impl Request<()> {
    /// Creates a `RequestBuilder` that can construct a `Request`.
    ///
    /// # Examples
    ///
    /// ```
    /// use ylong_http_client::Request;
    ///
    /// let builder = Request::builder();
    /// ```
    pub fn builder() -> RequestBuilder {
        RequestBuilder::new()
    }
}

/// A builder that can construct a `Request`.
///
/// # Examples
///
/// ```
/// use ylong_http_client::RequestBuilder;
///
/// let builder = RequestBuilder::new();
/// ```
pub struct RequestBuilder {
    inner: Result<RequestInner, InvalidRequest>,
}

impl RequestBuilder {
    /// Creates a `RequestBuilder`.
    ///
    /// # Examples
    ///
    /// ```
    /// use ylong_http_client::RequestBuilder;
    ///
    /// let builder = RequestBuilder::new();
    /// ```
    pub fn new() -> Self {
        Self {
            inner: Ok(RequestInner::default()),
        }
    }

    /// Sets `Method` of this request.
    ///
    /// # Examples
    ///
    /// ```
    /// use ylong_http_client::{Method, RequestBuilder};
    ///
    /// let builder = RequestBuilder::new().method(Method::GET);
    /// ```
    pub fn method(mut self, method: Method) -> Self {
        self.inner = self.inner.map(|mut r| {
            r.method = method;
            r
        });
        self
    }

    /// Sets `Url` of this request.
    ///
    /// # Examples
    ///
    /// ```
    /// use ylong_http_client::{Method, RequestBuilder};
    ///
    /// let builder = RequestBuilder::new().url("www.example.com");
    /// ```
    pub fn url(mut self, url: &str) -> Self {
        self.inner = self.inner.and_then(|mut r| {
            r.url = Url::parse(url).map_err(|_| InvalidRequest)?;
            Ok(r)
        });
        self
    }

    /// Adds a header to this request.
    ///
    /// # Examples
    ///
    /// ```
    /// use ylong_http_client::RequestBuilder;
    ///
    /// let builder = RequestBuilder::new().header("Content-Length", "100");
    /// ```
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.inner = self.inner.and_then(|mut r| {
            r.headers.insert(
                HeaderName::from_bytes(name.as_bytes()).map_err(|_| InvalidRequest)?,
                value.parse().map_err(|_| InvalidRequest)?,
            );
            Ok(r)
        });
        self
    }

    /// Sets the `Version` of the request.
    ///
    /// # Examples
    ///
    /// ```
    /// use ylong_http_client::{RequestBuilder, Version};
    ///
    /// let builder = RequestBuilder::new().version(Version::HTTP_11);
    /// ```
    pub fn version(mut self, version: Version) -> Self {
        self.inner = self.inner.map(|mut r| {
            r.version = version;
            r
        });
        self
    }

    /// Creates a `Request` that uses this `RequestBuilder` configuration and
    /// the provided body.
    ///
    /// # Error
    ///
    /// This method fails if some configurations are wrong.
    ///
    /// # Examples
    ///
    /// ```
    /// use ylong_http_client::RequestBuilder;
    ///
    /// let request = RequestBuilder::new().build("HelloWorld".as_bytes()).unwrap();
    /// ```
    pub fn build<T: Into<Body>>(self, body: T) -> Result<Request<T>, InvalidRequest> {
        Ok(Request {
            inner: self.inner?,
            body,
        })
    }
}

impl Default for RequestBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) struct RequestInner {
    pub(crate) method: Method,
    pub(crate) url: Url,
    pub(crate) headers: HeaderMap,
    pub(crate) version: Version,
}

impl Default for RequestInner {
    fn default() -> Self {
        Self {
            method: Default::default(),
            url: Url::parse("https://example.net").unwrap(),
            headers: Default::default(),
            version: Default::default(),
        }
    }
}

/// Error that occurs when an illegal `Request` is constructed.
pub struct InvalidRequest;

impl Debug for InvalidRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InvalidRequest").finish()
    }
}

impl Display for InvalidRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("Invalid Request")
    }
}

impl Error for InvalidRequest {}
