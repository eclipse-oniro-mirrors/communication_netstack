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

use std::error::Error;

/// Errors that may occur during the download process.
///
/// You can return `DownloadError::user_aborted` in [`DownloadOperator::poll_download`]
/// and [`DownloadOperator::poll_progress`] function to stop downloading.
///
/// [`DownloadOperator::poll_download`]: super::DownloadOperator::poll_download
/// [`DownloadOperator::poll_progress`]: super::DownloadOperator::poll_progress
///
/// # Example
///
/// ```
/// # use ylong_http_client::async_impl::DownloadError;
///
/// // Creates a `UserAborted` error.
/// let aborted = DownloadError::user_aborted();
/// ```
///
#[derive(Debug)]
pub struct DownloadError {
    kind: ErrorKind,
}

impl DownloadError {
    /// Creates a `UserAborted` error that can stop the downloading process.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::async_impl::DownloadError;
    ///
    /// let aborted = DownloadError::user_aborted();
    /// ```
    pub fn user_aborted() -> Self {
        Self {
            kind: ErrorKind::UserAborted,
        }
    }

    /// Creates a `IO` error that can stop the downloading process.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::error::Error;
    /// # use ylong_http_client::async_impl::DownloadError;
    ///
    /// # fn create_io_error<T: Into<Box<dyn Error + Send + Sync>>>(error: T) {
    /// let io = DownloadError::io(error);
    /// # }
    /// ```
    pub fn io<T: Into<Box<dyn Error + Send + Sync>>>(cause: T) -> Self {
        Self {
            kind: ErrorKind::IO(cause.into()),
        }
    }

    /// Checks if this `DownloadError` is a `UserAborted` error.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::async_impl::DownloadError;
    ///
    /// let aborted = DownloadError::user_aborted();
    /// assert!(aborted.is_user_aborted_error());
    /// ```
    pub fn is_user_aborted_error(&self) -> bool {
        matches!(self.kind, ErrorKind::UserAborted)
    }

    /// Checks if this `DownloadError` is a `Timeout` error.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::async_impl::DownloadError;
    ///
    /// let aborted = DownloadError::user_aborted();
    /// assert!(!aborted.is_timeout_error());
    /// ```
    pub fn is_timeout_error(&self) -> bool {
        matches!(self.kind, ErrorKind::Timeout)
    }

    /// Checks if this `DownloadError` is an `IO` error.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::async_impl::DownloadError;
    ///
    /// let aborted = DownloadError::user_aborted();
    /// assert!(!aborted.is_io_error());
    /// ```
    pub fn is_io_error(&self) -> bool {
        matches!(self.kind, ErrorKind::IO(_))
    }

    pub(crate) fn timeout() -> Self {
        Self {
            kind: ErrorKind::Timeout,
        }
    }
}

#[derive(Debug)]
enum ErrorKind {
    IO(Box<dyn Error + Send + Sync>),
    Timeout,
    UserAborted,
}
