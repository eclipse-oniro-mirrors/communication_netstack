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

use super::{Console, UploadConfig, UploadOperator, Uploader};
use tokio::io::AsyncRead;

/// A builder that can create a `Uploader`.
///
/// You can use this builder to build a `Uploader` step by step.
///
/// # Examples
///
/// ```
/// # use ylong_http_client::async_impl::{UploaderBuilder, Uploader};
///
/// let uploader = UploaderBuilder::new().console("Hello World".as_bytes()).build();
/// ```
pub struct UploaderBuilder<S> {
    state: S,
}

/// A state indicates that `UploaderBuilder` wants an `UploadOperator`.
pub struct WantsOperator;

impl UploaderBuilder<WantsOperator> {
    /// Creates a `UploaderBuilder` in the `WantsOperator` state.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::async_impl::UploaderBuilder;
    ///
    /// let builder = UploaderBuilder::new();
    /// ```
    pub fn new() -> Self {
        Self {
            state: WantsOperator,
        }
    }

    /// Sets a customized `UploaderBuilder`.
    ///
    /// Then the `UploaderBuilder` will switch to `WantsConfig` state.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::pin::Pin;
    /// # use std::task::{Context, Poll};
    /// use tokio::io::ReadBuf;
    /// # use ylong_http_client::async_impl::{UploaderBuilder, Uploader, UploadOperator};
    /// # use ylong_http_client::{HttpClientError, Response};
    ///
    /// struct MyOperator;
    ///
    /// impl UploadOperator for MyOperator {
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
    /// let builder = UploaderBuilder::new().operator(MyOperator);
    /// ```
    pub fn operator<T: UploadOperator>(self, operator: T) -> UploaderBuilder<WantsConfig<T>> {
        UploaderBuilder {
            state: WantsConfig {
                operator,
                config: UploadConfig::default(),
            },
        }
    }

    /// Sets a `Console` to this `Uploader`. The download result and progress
    /// will be displayed on the console.
    ///
    /// The `Console` needs a `Reader` to display.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::async_impl::{UploaderBuilder, Uploader};
    /// # use ylong_http_client::Response;
    ///
    /// let builder = UploaderBuilder::new().console("Hello World".as_bytes());
    /// ```
    pub fn console<R: AsyncRead + Unpin>(
        self,
        reader: R,
    ) -> UploaderBuilder<WantsConfig<Console<R>>> {
        UploaderBuilder {
            state: WantsConfig {
                operator: Console::from_reader(reader),
                config: UploadConfig::default(),
            },
        }
    }
}

impl Default for UploaderBuilder<WantsOperator> {
    fn default() -> Self {
        Self::new()
    }
}

/// A state indicates that `UploaderBuilder` wants some configurations.
pub struct WantsConfig<T> {
    operator: T,
    config: UploadConfig,
}

impl<T> UploaderBuilder<WantsConfig<T>> {
    /// Sets the total bytes of the uploaded content.
    ///
    /// Default is `None` which means that you don't know the size of the content.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::async_impl::{UploaderBuilder, Uploader};
    ///
    /// let builder = UploaderBuilder::new()
    ///     .console("Hello World".as_bytes())
    ///     .total_bytes(Some(11));
    /// ```
    pub fn total_bytes(mut self, total_bytes: Option<u64>) -> Self {
        self.state.config.total_bytes = total_bytes;
        self
    }

    /// Returns a `Uploader` that uses this `UploaderBuilder` configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::async_impl::{UploaderBuilder, Uploader};
    /// # use ylong_http_client::Response;
    ///
    /// let downloader = UploaderBuilder::new()
    ///     .console("Hello World".as_bytes())
    ///     .build();
    /// ```
    pub fn build(self) -> Uploader<T> {
        Uploader {
            operator: self.state.operator,
            config: self.state.config,
            info: None,
        }
    }
}
