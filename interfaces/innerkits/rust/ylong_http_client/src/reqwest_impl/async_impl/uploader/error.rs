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

/// Errors that may occur during the upload process.
///
/// You can return `UploadError::user_aborted` in [`UploadOperator::poll_upload`]
/// and [`UploadOperator::poll_progress`] function to stop uploading.
///
/// [`UploadOperator::poll_download`]: super::UploadOperator::poll_upload
/// [`UploadOperator::poll_progress`]: super::UploadOperator::poll_progress
///
/// # Example
///
/// ```
/// # use ylong_http_client::async_impl::UploadError;
///
/// // Creates a `UserAborted` error.
/// let aborted = UploadError::user_aborted();
/// ```
///
pub struct UploadError {
    kind: ErrorKind,
}

impl UploadError {
    /// Creates a `UserAborted` error that can stop the uploading process.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::async_impl::UploadError;
    ///
    /// let aborted = UploadError::user_aborted();
    /// ```
    pub fn user_aborted() -> Self {
        Self {
            kind: ErrorKind::UserAborted,
        }
    }

    /// Checks if this `UploadError` is a `UserAborted` error.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::async_impl::UploadError;
    ///
    /// let aborted = UploadError::user_aborted();
    /// assert!(aborted.is_user_aborted_error());
    /// ```
    pub fn is_user_aborted_error(&self) -> bool {
        matches!(self.kind, ErrorKind::UserAborted)
    }

    /// Checks if this `UploadError` is an `IO` error.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::async_impl::UploadError;
    ///
    /// let aborted = UploadError::user_aborted();
    /// assert!(!aborted.is_io_error());
    /// ```
    pub fn is_io_error(&self) -> bool {
        matches!(self.kind, ErrorKind::IO(_))
    }

    pub(crate) fn io<T: Into<Box<dyn Error + Send + Sync>>>(cause: T) -> Self {
        Self {
            kind: ErrorKind::IO(cause.into()),
        }
    }
}

enum ErrorKind {
    IO(Box<dyn Error + Send + Sync>),
    UserAborted,
}
