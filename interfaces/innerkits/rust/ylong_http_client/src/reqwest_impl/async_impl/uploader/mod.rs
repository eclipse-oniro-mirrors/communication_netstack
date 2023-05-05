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
mod multipart;
mod operator;

pub use builder::{UploaderBuilder, WantsReader};
pub use multipart::{MultiPart, Part};
pub use operator::{Console, UploadOperator};

use crate::HttpClientError;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, ReadBuf};
use tokio::time::Instant;
use tokio_util::io::ReaderStream;

/// An uploader that can help you upload the request body.
///
/// An `Uploader` provides a template method for uploading a file or a slice and
/// needs to use a structure that implements [`UploadOperator`] trait to read
/// the file or the slice and convert it into request body.
///
/// The `UploadOperator` trait provides a [`progress`] method which is
/// responsible for progress display.
///
/// You only need to provide a structure that implements the `UploadOperator`
/// trait to complete the upload process.
///
/// A default structure `Console` which implements `UploadOperator` is
/// provided to show download message on console. You can use
/// `Uploader::console` to build a `Uploader` which based on it.
///
/// [`UploadOperator`]: UploadOperator
/// [`progress`]: UploadOperator::progress
///
/// # Examples
///
/// `Console`:
/// ```no_run
/// # use ylong_http_client::async_impl::Uploader;
/// # use ylong_http_client::Response;
///
/// // Creates a default `Uploader` that show progress on console.
/// let mut uploader = Uploader::console("HelloWorld".as_bytes());
/// ```
///
/// `Custom`:
/// ```no_run
/// # use std::pin::Pin;
/// # use std::task::{Context, Poll};
/// # use tokio::io::ReadBuf;
/// # use ylong_http_client::async_impl::{Uploader, UploadOperator};
/// # use ylong_http_client::{Response, SpeedLimit, Timeout};
/// # use ylong_http_client::HttpClientError;
///
/// # async fn upload_and_show_progress(response: Response) {
/// // Customizes your own `UploadOperator`.
/// struct MyUploadOperator;
///
/// impl UploadOperator for MyUploadOperator {
///     fn poll_progress(
///         self: Pin<&mut Self>,
///         cx: &mut Context<'_>,
///         uploaded: u64,
///         total: Option<u64>
///     ) -> Poll<Result<(), HttpClientError>> {
///         todo!()
///     }
/// }
///
/// // Creates a default `Uploader` based on `MyUploadOperator`.
/// // Configures your uploader by using `UploaderBuilder`.
/// let uploader = Uploader::builder().reader("HelloWorld".as_bytes()).operator(MyUploadOperator).build();
/// # }
/// ```
pub struct Uploader<R, T> {
    reader: R,
    operator: T,
    config: UploadConfig,
    info: Option<UploadInfo>,
}

impl<R: AsyncRead + Unpin> Uploader<R, Console> {
    /// Creates an `Uploader` with a `Console` operator which displays process on console.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::async_impl::Uploader;
    ///
    /// let uploader = Uploader::console("HelloWorld".as_bytes());
    /// ```
    pub fn console(reader: R) -> Uploader<R, Console> {
        UploaderBuilder::new().reader(reader).console().build()
    }
}

impl Uploader<(), ()> {
    /// Creates an `UploaderBuilder` and configures uploader step by step.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::async_impl::Uploader;
    ///
    /// let builder = Uploader::builder();
    /// ```
    pub fn builder() -> UploaderBuilder<WantsReader> {
        UploaderBuilder::new()
    }
}

impl<R, T> Uploader<R, T>
where
    T: UploadOperator + Unpin,
{
    fn show_progress_now(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), HttpClientError>> {
        self.show_progress_with_duration(cx, Duration::default())
    }

    fn show_progress_with_duration(
        &mut self,
        cx: &mut Context<'_>,
        duration: Duration,
    ) -> Poll<Result<(), HttpClientError>> {
        let info = self.info.as_mut().unwrap();
        let now = Instant::now();
        if info.last_progress.duration_since(now) >= duration {
            return match Pin::new(&mut self.operator).poll_progress(
                cx,
                info.uploaded_bytes,
                self.config.total_bytes,
            ) {
                Poll::Ready(Ok(())) => {
                    info.last_progress = Instant::now();
                    Poll::Ready(Ok(()))
                }
                x => x,
            };
        }
        Poll::Ready(Ok(()))
    }
}

impl<R, T> AsyncRead for Uploader<R, T>
where
    R: AsyncRead + Unpin,
    T: UploadOperator + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        const UPLOADER_PROGRESS_DURATION: Duration = Duration::from_secs(1);

        if self.info.is_none() {
            self.info = Some(UploadInfo::new());
        }

        let filled = buf.filled().len();
        match Pin::new(&mut self.reader).poll_read(cx, buf) {
            Poll::Ready(Ok(_)) => {}
            x => return x,
        }

        let new_filled = buf.filled().len();

        let mut progress = false;
        self.info.as_mut().unwrap().uploaded_bytes += (new_filled - filled) as u64;

        if let Some(total_size) = self.config.total_bytes {
            progress = total_size == self.info.as_ref().unwrap().uploaded_bytes;
        }

        match if progress {
            self.show_progress_now(cx)
        } else {
            self.show_progress_with_duration(cx, UPLOADER_PROGRESS_DURATION)
        } {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(_)) => Poll::Ready(Err(std::io::ErrorKind::Other.into())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<R, U> From<Uploader<R, U>> for reqwest::Body
where
    R: AsyncRead + Send + Sync + Unpin + 'static,
    U: UploadOperator + Unpin + Send + Sync + 'static,
{
    fn from(value: Uploader<R, U>) -> Self {
        reqwest::Body::wrap_stream(ReaderStream::new(value))
    }
}

impl<R, T> AsRef<R> for Uploader<R, T> {
    fn as_ref(&self) -> &R {
        &self.reader
    }
}

#[derive(Default)]
struct UploadConfig {
    total_bytes: Option<u64>,
}

struct UploadInfo {
    last_progress: Instant,
    uploaded_bytes: u64,
}

impl UploadInfo {
    fn new() -> Self {
        Self {
            last_progress: Instant::now(),
            uploaded_bytes: 0,
        }
    }
}
