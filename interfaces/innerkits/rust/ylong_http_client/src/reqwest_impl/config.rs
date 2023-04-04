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

use crate::HttpClientError;
use std::cmp;
use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use std::time::Duration;

/// Timeout settings.
///
/// # Examples
///
/// ```
/// # use ylong_http_client::Timeout;
///
/// let timeout = Timeout::none();
/// ```
pub struct Timeout(Option<Duration>);

impl Timeout {
    /// Creates a `Timeout` without limiting the timeout.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::Timeout;
    ///
    /// let timeout = Timeout::none();
    /// ```
    pub fn none() -> Self {
        Self(None)
    }

    /// Creates a `Timeout` from the specified number of seconds.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::Timeout;
    ///
    /// let timeout = Timeout::from_secs(9);
    /// ```
    pub fn from_secs(secs: u64) -> Self {
        Self(Some(Duration::from_secs(secs)))
    }

    pub(crate) fn inner(&self) -> Option<Duration> {
        self.0
    }
}

/// Speed limit settings.
///
/// # Examples
///
/// ```
/// # use ylong_http_client::SpeedLimit;
///
/// let limit = SpeedLimit::none();
/// ```
pub struct SpeedLimit {
    min: (u64, Duration),
    max: u64,
}

impl SpeedLimit {
    /// Sets the minimum speed and the seconds for which the current speed is
    /// allowed to be less than this minimum speed.
    ///
    /// The unit of speed is bytes per second, and the unit of duration is seconds.
    ///
    /// The minimum speed cannot exceed the maximum speed that has been set. If
    /// the set value exceeds the currently set maximum speed, the minimum speed
    /// will be set to the current maximum speed.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::SpeedLimit;
    ///
    /// // Sets minimum speed is 1024B/s, the duration is 10s.
    /// let limit = SpeedLimit::none().min_speed(1024, 10);
    /// ```
    pub fn min_speed(mut self, min: u64, duration: u64) -> Self {
        self.min = (cmp::min(self.max, min), Duration::from_secs(duration));
        self
    }

    /// Sets the maximum speed.
    ///
    /// The unit of speed is bytes per second.
    ///
    /// The maximum speed cannot be lower than the minimum speed that has been
    /// set. If the set value is lower than the currently set minimum speed, the
    /// maximum speed will be set to the current minimum speed.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::SpeedLimit;
    ///
    /// let limit = SpeedLimit::none().max_speed(1024);
    /// ```
    pub fn max_speed(mut self, max: u64) -> Self {
        self.max = cmp::max(self.min.0, max);
        self
    }

    /// Creates a `SpeedLimit` without limiting the speed.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::SpeedLimit;
    ///
    /// let limit = SpeedLimit::none();
    /// ```
    pub fn none() -> Self {
        Self {
            min: (0, Duration::MAX),
            max: u64::MAX,
        }
    }
}

/// Redirect settings.
///
/// # Examples
///
/// ```
/// # use ylong_http_client::Redirect;
///
/// let redirect = Redirect::none();
/// ```
#[derive(Default)]
pub struct Redirect(reqwest::redirect::Policy);

impl Redirect {
    /// Creates a `Redirect` without redirection.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::Redirect;
    ///
    /// let redirect = Redirect::none();
    /// ```
    pub fn none() -> Self {
        Self(reqwest::redirect::Policy::none())
    }

    /// Creates a `Redirect` from the specified times.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::Redirect;
    ///
    /// let redirect = Redirect::limited(10);
    /// ```
    pub fn limited(max: usize) -> Self {
        Self(reqwest::redirect::Policy::limited(max))
    }

    pub(crate) fn inner(self) -> reqwest::redirect::Policy {
        self.0
    }
}

/// Proxy settings.
///
/// # Examples
///
/// ```
/// # use ylong_http_client::Proxy;
///
/// let proxy = Proxy::none();
/// ```
pub struct Proxy(Option<reqwest::Proxy>);

impl Proxy {
    /// Creates a `Proxy` without any proxies.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::Proxy;
    ///
    /// let proxy = Proxy::none();
    /// ```
    pub fn none() -> Self {
        Self(None)
    }

    /// Creates a `ProxyBuilder`. This builder can help you construct a proxy
    /// that proxy all HTTP traffic to the passed URL.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::Proxy;
    ///
    /// let proxy = Proxy::http("http://proxy.example.com");
    /// ```
    pub fn http(url: &str) -> ProxyBuilder {
        ProxyBuilder(
            reqwest::Proxy::http(url).map_err(|_| HttpClientError::build(Some(InvalidProxy))),
        )
    }

    /// Creates a `ProxyBuilder`. This builder can help you construct a proxy
    /// that proxy all HTTPS traffic to the passed URL.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::Proxy;
    ///
    /// let proxy = Proxy::https("https://proxy.example.com");
    /// ```
    pub fn https(url: &str) -> ProxyBuilder {
        ProxyBuilder(
            reqwest::Proxy::https(url).map_err(|_| HttpClientError::build(Some(InvalidProxy))),
        )
    }

    /// Creates a `ProxyBuilder`. This builder can help you construct a proxy
    /// that proxy **all** traffic to the passed URL.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::Proxy;
    ///
    /// let proxy = Proxy::all("http://proxy.example.com");
    /// ```
    pub fn all(url: &str) -> ProxyBuilder {
        ProxyBuilder(
            reqwest::Proxy::all(url).map_err(|_| HttpClientError::build(Some(InvalidProxy))),
        )
    }

    pub(crate) fn inner(self) -> Option<reqwest::Proxy> {
        self.0
    }
}

/// A builder that constructs a `Proxy`.
///
/// # Examples
///
/// ```
/// # use ylong_http_client::Proxy;
///
/// let proxy = Proxy::all("http://proxy.example.com")
///     .basic_auth("Aladdin", "open sesame")
///     .build();
/// ```
pub struct ProxyBuilder(Result<reqwest::Proxy, HttpClientError>);

impl ProxyBuilder {
    /// Sets the `Proxy-Authorization` header using Basic auth.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::Proxy;
    ///
    /// let builder = Proxy::all("http://proxy.example.com")
    ///     .basic_auth("Aladdin", "open sesame");
    /// ```
    pub fn basic_auth(mut self, username: &str, password: &str) -> Self {
        self.0 = self.0.map(|mut p| {
            p = p.basic_auth(username, password);
            p
        });
        self
    }

    /// Constructs a `Proxy`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::Proxy;
    ///
    /// let proxy = Proxy::all("http://proxy.example.com").build();
    /// ```
    pub fn build(self) -> Result<Proxy, HttpClientError> {
        Ok(Proxy(Some(self.0?)))
    }
}

struct InvalidProxy;

impl Debug for InvalidProxy {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InvalidProxy").finish()
    }
}

impl Display for InvalidProxy {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("Invalid Request")
    }
}

impl Error for InvalidProxy {}
