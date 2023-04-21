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
use std::fmt::{Debug, Display, Formatter};

/// Errors that may occur in this crate.
pub struct HttpClientError {
    cause: Box<dyn Error + Send + Sync>,
}

impl<T> From<T> for HttpClientError
where
    T: Error + Send + Sync + 'static,
{
    fn from(e: T) -> Self {
        Self { cause: Box::new(e) }
    }
}

impl Debug for HttpClientError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpClientError")
            .field("cause", &self.cause)
            .finish()
    }
}

impl Display for HttpClientError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("HttpClientError:")?;
        Display::fmt(&self.cause, f)
    }
}
