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

mod downloader;
mod uploader;

pub use downloader::{DownloadOperator, Downloader, DownloaderBuilder};
pub use uploader::{UploadOperator, Uploader, UploaderBuilder};

use crate::{Certificate, HttpClientError, Proxy, Redirect, Request, Timeout, TlsVersion};
use reqwest::{Body, Response};
use tokio::io::AsyncRead;
use tokio_util::io::ReaderStream;

/// An asynchronous `Client` to make requests with.
///
/// The Client has various configuration values to tweak, but the defaults
/// are set to what is usually the most commonly desired value. To configure a
/// `Client`, use `Client::builder()`.
///
/// The `Client` holds a connection pool internally, so it is advised that
/// you create one and **reuse** it.
///
/// You do **not** have to wrap the `Client` in an [`Rc`] or [`Arc`] to **reuse** it,
/// because it already uses an [`Arc`] internally.
///
/// [`Rc`]: std::rc::Rc
///
/// # Examples
///
/// ```no_run
/// # use ylong_http_client::async_impl::Client;
/// # use ylong_http_client::Request;
///
/// # async fn send_request() {
/// // Creates a `Client`.
/// let client = Client::builder().build().unwrap();
///
/// // Constructs your `Request`.
/// let request = Request::builder().build("".as_bytes()).unwrap();
///
/// // Sends your request through `Client` and gets the response.
/// let _response = client.request(request).await;
/// # }
/// ```
#[derive(Clone)]
pub struct Client(reqwest::Client);

impl Client {
    /// Creates a `ClientBuilder` to configure a `Client`.
    ///
    /// This is the same as `ClientBuilder::new()`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use reqwest::Client;
    ///
    /// let builder = Client::builder();
    /// ```
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// Sends a `Request` and gets the `Response`.
    ///
    /// A `Request` can be built manually with `Request::new()` or obtained
    /// from a RequestBuilder with `RequestBuilder::build()`.
    ///
    /// # Errors
    ///
    /// This method fails if there was an error while sending request,
    /// redirect loop was detected or redirect limit was exhausted.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use ylong_http_client::async_impl::Client;
    /// # use ylong_http_client::Request;
    ///
    /// # async fn send_request() {
    /// // Creates a `Client`.
    /// let client = Client::builder().build().unwrap();
    ///
    /// // Constructs your `Request`.
    /// let request = Request::builder().build("".as_bytes()).unwrap();
    ///
    /// // Sends your request through `Client` and gets the response.
    /// let _response = client.request(request).await;
    /// # }
    /// ```
    pub async fn request<T: AsyncRead + Unpin + Send + Sync + 'static>(
        &self,
        request: Request<T>,
    ) -> Result<Response, HttpClientError> {
        self.0
            .request(request.inner.method, request.inner.url)
            .headers(request.inner.headers)
            .version(request.inner.version)
            .body(Body::wrap_stream(ReaderStream::new(request.body)))
            .send()
            .await
            .map_err(HttpClientError::from)
    }
}

/// A `ClientBuilder` can be used to create a `Client` with custom configuration.
///
/// # Examples
///
/// ```
/// # use ylong_http_client::async_impl::ClientBuilder;
///
/// let builder = ClientBuilder::new();
/// ```
pub struct ClientBuilder(reqwest::ClientBuilder);

impl ClientBuilder {
    /// Creates a `ClientBuilder` to configure a `Client`.
    ///
    /// This is the same as `Client::builder()`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::async_impl::ClientBuilder;
    ///
    /// let builder = ClientBuilder::new();
    /// ```
    pub fn new() -> Self {
        Self(reqwest::ClientBuilder::new())
    }

    /// Only uses HTTP/1.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::async_impl::ClientBuilder;
    ///
    /// let builder = ClientBuilder::new().http1_only();
    /// ```
    pub fn http1_only(self) -> Self {
        Self(self.0.http1_only())
    }

    /// Only use HTTP/2.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::async_impl::ClientBuilder;
    ///
    /// let builder = ClientBuilder::new().http2_prior_knowledge();
    /// ```
    pub fn http2_prior_knowledge(self) -> Self {
        Self(self.0.http2_prior_knowledge())
    }

    /// Enables a request timeout.
    ///
    /// The timeout is applied from when the request starts connecting until the
    /// response body has finished.
    ///
    /// Default is `Timeout::none()`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::async_impl::ClientBuilder;
    /// # use ylong_http_client::Timeout;
    ///
    /// let builder = ClientBuilder::new()
    ///     .request_timeout(Timeout::none());
    /// ```
    pub fn request_timeout(self, timeout: Timeout) -> Self {
        match timeout.inner() {
            Some(duration) => Self(self.0.timeout(duration)),
            None => self,
        }
    }

    /// Sets a timeout for only the connect phase of a `Client`.
    ///
    /// Default is `Timeout::none()`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::async_impl::ClientBuilder;
    /// # use ylong_http_client::Timeout;
    ///
    /// let builder = ClientBuilder::new()
    ///     .connect_timeout(Timeout::none());
    /// ```
    pub fn connect_timeout(self, timeout: Timeout) -> Self {
        match timeout.inner() {
            Some(duration) => Self(self.0.connect_timeout(duration)),
            None => self,
        }
    }

    /// Sets a `RedirectPolicy` for this client.
    ///
    /// Default will follow redirects up to a maximum of 10.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::async_impl::ClientBuilder;
    /// # use ylong_http_client::Redirect;
    ///
    /// let builder = ClientBuilder::new().redirect(Redirect::none());
    /// ```
    pub fn redirect(self, redirect: Redirect) -> Self {
        Self(self.0.redirect(redirect.inner()))
    }

    /// Adds a `Proxy` to the list of proxies the `Client` will use.
    ///
    /// # Note
    ///
    /// Adding a proxy will disable the automatic usage of the "system" proxy.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::async_impl::ClientBuilder;
    /// # use ylong_http_client::Redirect;
    ///
    /// let builder = ClientBuilder::new().redirect(Redirect::none());
    /// ```
    pub fn proxy(self, proxy: Proxy) -> Self {
        match proxy.inner() {
            Some(proxy) => Self(self.0.proxy(proxy)),
            None => Self(self.0.no_proxy()),
        }
    }

    /// Sets the maximum allowed TLS version for connections.
    ///
    /// By default there's no maximum.
    ///
    /// # Note
    ///
    /// `tls::Version::TLS_1_3` cannot be set as a maximum.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::async_impl::ClientBuilder;
    /// # use ylong_http_client::{Redirect, TlsVersion};
    ///
    /// let builder = ClientBuilder::new().max_tls_version(TlsVersion::TLS_1_2);
    /// ```
    pub fn max_tls_version(self, version: TlsVersion) -> Self {
        if version != TlsVersion::TLS_1_3 {
            Self(self.0.max_tls_version(version))
        } else {
            self
        }
    }

    /// Sets the minimum required TLS version for connections.
    ///
    /// By default the TLS backend's own default is used.
    ///
    /// # Note
    ///
    /// `tls::Version::TLS_1_3` cannot be set as a minimum.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::async_impl::ClientBuilder;
    /// # use ylong_http_client::{Redirect, TlsVersion};
    ///
    /// let builder = ClientBuilder::new().min_tls_version(TlsVersion::TLS_1_2);
    /// ```
    pub fn min_tls_version(self, version: TlsVersion) -> Self {
        if version != TlsVersion::TLS_1_3 {
            Self(self.0.min_tls_version(version))
        } else {
            self
        }
    }

    /// Adds a custom root certificate.
    ///
    /// This can be used to connect to a server that has a self-signed
    /// certificate for example.
    ///
    /// ```
    /// # use ylong_http_client::async_impl::ClientBuilder;
    /// # use ylong_http_client::{Redirect, TlsVersion, Certificate};
    ///
    /// # fn set_cert(cert: Certificate) {
    /// let builder = ClientBuilder::new().add_root_certificate(cert);
    /// # }
    /// ```
    pub fn add_root_certificate(self, cert: Certificate) -> Self {
        Self(self.0.add_root_certificate(cert))
    }

    /// Returns a `Client` that uses this `ClientBuilder` configuration.
    ///
    /// # Errors
    ///
    /// This method fails if a TLS backend cannot be initialized, or the resolver
    /// cannot load the system configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::async_impl::ClientBuilder;
    /// # use ylong_http_client::{Redirect, TlsVersion};
    ///
    /// let client = ClientBuilder::new().build().unwrap();
    /// ```
    pub fn build(self) -> Result<Client, HttpClientError> {
        self.0.build().map(Client).map_err(HttpClientError::from)
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}
