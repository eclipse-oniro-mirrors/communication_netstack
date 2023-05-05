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

mod builder;
mod operator;

use builder::WantsBody;
use operator::Console;

pub use builder::DownloaderBuilder;
pub use operator::{DownloadFuture, DownloadOperator, ProgressFuture};

use crate::{ErrorKind, HttpClientError, SpeedLimit, Timeout};
use reqwest::Response;
use std::time::Duration;
use tokio::time::Instant;

/// A downloader that can help you download the response body.
///
/// A `Downloader` provides a template method for downloading the body and
/// needs to use a structure that implements [`DownloadOperator`] trait to read
/// the body.
///
/// The `DownloadOperator` trait provides two kinds of methods - [`download`]
/// and [`progress`], where:
///
/// - `download` methods are responsible for reading and copying the body to
/// certain places.
///
/// - `progress` methods are responsible for progress display.
///
/// You only need to provide a structure that implements the `DownloadOperator`
/// trait to complete the download process.
///
/// A default structure `Console` which implements `DownloadOperator` is
/// provided to show download message on console. You can use
/// `Downloader::console` to build a `Downloader` which based on it.
///
/// [`DownloadOperator`]: DownloadOperator
/// [`download`]: DownloadOperator::download
/// [`progress`]: DownloadOperator::progress
///
/// # Examples
///
/// `Console`:
/// ```no_run
/// # use ylong_http_client::async_impl::Downloader;
/// # use ylong_http_client::Response;
///
/// # async fn download_and_show_progress_on_console(response: Response) {
/// // Creates a default `Downloader` that show progress on console.
/// let mut downloader = Downloader::console(response);
/// let _ = downloader.download().await;
/// # }
/// ```
///
/// `Custom`:
/// ```no_run
/// # use std::pin::Pin;
/// # use std::task::{Context, Poll};
/// # use ylong_http_client::async_impl::{Downloader, DownloadOperator};
/// # use ylong_http_client::{HttpClientError, Response, SpeedLimit, Timeout};
///
/// # async fn download_and_show_progress(response: Response) {
/// // Customizes your own `DownloadOperator`.
/// struct MyDownloadOperator;
///
/// impl DownloadOperator for MyDownloadOperator {
///     fn poll_download(
///         self: Pin<&mut Self>,
///         cx: &mut Context<'_>,
///         data: &[u8],
///     ) -> Poll<Result<usize, HttpClientError>> {
///         todo!()
///     }
///
///     fn poll_progress(
///         self: Pin<&mut Self>,
///         cx: &mut Context<'_>,
///         downloaded: u64,
///         total: Option<u64>
///     ) -> Poll<Result<(), HttpClientError>> {
///         // Writes your customize method.
///         todo!()
///     }
/// }
///
/// // Creates a default `Downloader` based on `MyDownloadOperator`.
/// // Configures your downloader by using `DownloaderBuilder`.
/// let mut downloader = Downloader::builder()
///     .body(response)
///     .operator(MyDownloadOperator)
///     .timeout(Timeout::none())
///     .speed_limit(SpeedLimit::none())
///     .build();
/// let _ = downloader.download().await;
/// # }
/// ```
pub struct Downloader<T> {
    operator: T,
    body: Response,
    config: DownloadConfig,
    info: Option<DownloadInfo>,
}

impl Downloader<()> {
    /// Creates a `Downloader` that based on a default `DownloadOperator` which
    /// show progress on console.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use ylong_http_client::async_impl::Downloader;
    /// # use ylong_http_client::Response;
    ///
    /// # async fn download_and_show_progress_on_console(response: Response) {
    /// // Creates a default `Downloader` that show progress on console.
    /// let mut downloader = Downloader::console(response);
    /// let _ = downloader.download().await;
    /// # }
    /// ```
    pub fn console(response: Response) -> Downloader<Console> {
        Self::builder().body(response).console().build()
    }

    /// Creates a `DownloaderBuilder` and configures downloader step by step.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::async_impl::Downloader;
    ///
    /// let builder = Downloader::builder();
    /// ```
    pub fn builder() -> DownloaderBuilder<WantsBody> {
        DownloaderBuilder::new()
    }
}

impl<T: DownloadOperator + Unpin> Downloader<T> {
    /// Starts downloading that uses this `Downloader`'s configurations.
    ///
    /// The download and progress methods of the `DownloadOperator` will be
    /// called multiple times until the download is complete.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::async_impl::Downloader;
    /// # use ylong_http_client::Response;
    ///
    /// # async fn download_response_body(response: Response) {
    /// let mut downloader = Downloader::console(response);
    /// let _result = downloader.download().await;
    /// # }
    /// ```
    pub async fn download(&mut self) -> Result<(), HttpClientError> {
        // Construct new download info, or reuse previous info.
        if self.info.is_none() {
            self.info = Some(DownloadInfo::new(self.body.content_length()));
        }
        self.limited_download().await
    }

    // Downloads response body with speed limitation.
    // TODO: Speed Limit.
    async fn limited_download(&mut self) -> Result<(), HttpClientError> {
        const DOWNLOADER_PROGRESS_DURATION: Duration = Duration::from_secs(1);

        loop {
            self.check_timeout()?;
            self.show_progress_with_duration(DOWNLOADER_PROGRESS_DURATION)
                .await?;
            if self.transfer_data().await? {
                return Ok(());
            }
        }
    }

    async fn transfer_data(&mut self) -> Result<bool, HttpClientError> {
        let data = match self.body.chunk().await {
            Ok(None) => {
                self.show_progress_now().await?;
                return Ok(true);
            }
            Ok(Some(data)) => data,
            Err(e) => {
                return Err(HttpClientError::new_with_cause(
                    ErrorKind::BodyTransfer,
                    Some(e),
                ))
            }
        };

        let mut size = 0;
        while size != data.len() {
            size += self.operator.download(&data.as_ref()[size..]).await?;
        }
        self.info.as_mut().unwrap().downloaded_bytes += data.len() as u64;
        Ok(false)
    }

    fn check_timeout(&mut self) -> Result<(), HttpClientError> {
        if let Some(timeout) = self.config.timeout.inner() {
            let now = Instant::now();
            if now.duration_since(self.info.as_mut().unwrap().start_time) >= timeout {
                return Err(HttpClientError::new(ErrorKind::Timeout));
            }
        }
        Ok(())
    }

    async fn show_progress_now(&mut self) -> Result<(), HttpClientError> {
        self.show_progress_with_duration(Duration::default()).await
    }

    async fn show_progress_with_duration(
        &mut self,
        duration: Duration,
    ) -> Result<(), HttpClientError> {
        let info = self.info.as_mut().unwrap();
        let now = Instant::now();
        if now.duration_since(info.last_progress_time) >= duration {
            self.operator
                .progress(info.downloaded_bytes, info.total_bytes)
                .await?;
            info.last_progress_time = Instant::now();
        }
        Ok(())
    }
}

struct DownloadInfo {
    pub(crate) start_time: Instant,
    pub(crate) last_progress_time: Instant,
    pub(crate) downloaded_bytes: u64,
    pub(crate) total_bytes: Option<u64>,
}

impl DownloadInfo {
    fn new(total_bytes: Option<u64>) -> Self {
        Self {
            start_time: Instant::now(),
            last_progress_time: Instant::now(),
            downloaded_bytes: 0,
            total_bytes,
        }
    }
}

struct DownloadConfig {
    pub(crate) timeout: Timeout,
    pub(crate) speed_limit: SpeedLimit,
}

impl Default for DownloadConfig {
    fn default() -> Self {
        Self {
            timeout: Timeout::none(),
            speed_limit: SpeedLimit::none(),
        }
    }
}
