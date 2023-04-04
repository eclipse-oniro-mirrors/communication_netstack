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

//! HTTP Client implementation based on `Reqwest`.

pub mod async_impl;

mod config;
mod consts;
mod error;
mod request;

pub use config::{Proxy, Redirect, SpeedLimit, Timeout};
pub use error::{ErrorKind, HttpClientError};
pub use request::{InvalidRequest, Request, RequestBuilder};

pub use reqwest::{tls::Version as TlsVersion, Certificate, Method, Response, Version};
