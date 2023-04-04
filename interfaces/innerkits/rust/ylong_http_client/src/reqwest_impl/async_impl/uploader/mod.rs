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

pub use builder::{UploaderBuilder, WantsOperator};
pub use operator::{Console, UploadOperator};

use crate::reqwest_impl::consts::UPLOADER_PROGRESS_DURATION;
use crate::HttpClientError;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, ReadBuf};
use tokio::time::Instant;

/// An uploader that can help you upload the request body.
///
/// An `Uploader` provides a template method for uploading a file or a slice and
/// needs to use a structure that implements [`UploadOperator`] trait to read
/// the file or the slice and convert it into request body.
///
/// The `UploadOperator` trait provides two kinds of methods - [`upload`]
/// and [`progress`], where:
///
/// - `upload` methods are responsible for reading the file or slice and
/// converting it into a request body.
///
/// - `progress` methods are responsible for progress display.
///
/// You only need to provide a structure that implements the `UploadOperator`
/// trait to complete the upload process.
///
/// A default structure `Console` which implements `UploadOperator` is
/// provided to show download message on console. You can use
/// `Uploader::console` to build a `Uploader` which based on it.
///
/// [`UploadOperator`]: UploadOperator
/// [`upload`]: UploadOperator::download
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
/// # use ylong_http_client::{HttpClientError, Response, SpeedLimit, Timeout};
///
/// # async fn upload_and_show_progress(response: Response) {
/// // Customizes your own `UploadOperator`.
/// struct MyUploadOperator;
///
/// impl UploadOperator for MyUploadOperator {
///     fn poll_upload(
///         self: Pin<&mut Self>,
///         cx: &mut Context<'_>,
///         buf: &mut ReadBuf<'_>
///     ) -> Poll<Result<(), HttpClientError>> {
///         todo!()
///     }
///
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
/// let uploader = Uploader::builder().operator(MyUploadOperator).build();
/// # }
/// ```
pub struct Uploader<T> {
    operator: T,
    config: UploadConfig,
    info: Option<UploadInfo>,
}

impl Uploader<()> {
    pub fn console<R: AsyncRead + Unpin>(reader: R) -> Uploader<Console<R>> {
        UploaderBuilder::new().console(reader).build()
    }

    pub fn builder() -> UploaderBuilder<WantsOperator> {
        UploaderBuilder::new()
    }
}

impl<U: UploadOperator + Unpin> Uploader<U> {
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

impl<U: UploadOperator + Unpin> AsyncRead for Uploader<U> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.info.is_none() {
            self.info = Some(UploadInfo::new());
        }

        let filled = buf.filled().len();
        match Pin::new(&mut self.operator).poll_upload(cx, buf) {
            Poll::Ready(Ok(_)) => {}
            Poll::Ready(Err(_)) => return Poll::Ready(Err(std::io::ErrorKind::Other.into())),
            Poll::Pending => return Poll::Pending,
        }

        let new_filled = buf.filled().len();
        self.info.as_mut().unwrap().uploaded_bytes += (new_filled - filled) as u64;
        match if filled != new_filled {
            self.show_progress_with_duration(cx, UPLOADER_PROGRESS_DURATION)
        } else {
            self.show_progress_now(cx)
        } {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(_)) => Poll::Ready(Err(std::io::ErrorKind::Other.into())),
            Poll::Pending => Poll::Pending,
        }
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
