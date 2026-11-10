// Copyright (C) 2024 Huawei Device Co., Ltd.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::HashMap;
use std::pin::Pin;

use cxx::SharedPtr;

use crate::task::RequestTask;
use crate::wrapper;
use crate::wrapper::ffi::{GetExtraInfoItem, GetHeaders, HttpClientResponse, HttpClientTask};

/// http client response
pub struct Response<'a> {
    inner: ResponseInner<'a>,
}

impl<'a> Response<'a> {
    /// Get Response Code
    pub fn status(&self) -> ResponseCode {
        let response = self.inner.to_response();
        response.GetResponseCode().try_into().unwrap_or_default()
    }

    pub fn headers(&self) -> HashMap<String, String> {
        let ptr = self.inner.to_response() as *const HttpClientResponse as *mut HttpClientResponse;
        let p = unsafe { Pin::new_unchecked(ptr.as_mut().unwrap()) };

        let mut headers = GetHeaders(p).into_iter();
        let mut ret = HashMap::new();
        loop {
            if let Some(key) = headers.next() {
                if let Some(value) = headers.next() {
                    ret.insert(key.to_lowercase(), value);
                    continue;
                }
            }
            break;
        }
        ret
    }

    pub fn cookies(&self) -> String {
        let response = self.inner.to_response();
        response.GetCookies().to_string()
    }

    pub fn get_result(&self) -> String {
        let response = self.inner.to_response();
        response.GetResult().to_string()
    }

    pub fn performance_timing(&self) -> PerformanceInfo {
        performance_from_response(self.inner.to_response())
    }

    pub fn get_expect_data_type(&self) -> HttpDataType {
        let response = self.inner.to_response();
        let data_type = HttpDataType::try_from(response.GetExpectDataType()).unwrap_or_default();
        data_type
    }

    pub fn connection_extra_info(&self) -> ConnectionExtraInfo {
        extra_info_from_response(self.inner.to_response())
    }

    pub(crate) fn from_ffi(inner: &'a HttpClientResponse) -> Self {
        Self {
            inner: ResponseInner::Ref(inner),
        }
    }

    pub(crate) fn from_shared(inner: SharedPtr<HttpClientTask>) -> Self {
        Self {
            inner: ResponseInner::Shared(inner),
        }
    }
}

enum ResponseInner<'a> {
    Ref(&'a HttpClientResponse),
    Shared(SharedPtr<HttpClientTask>),
}

impl<'a> ResponseInner<'a> {
    fn to_response(&self) -> &HttpClientResponse {
        match self {
            ResponseInner::Ref(inner) => inner,
            ResponseInner::Shared(inner) => RequestTask::pin_mut(inner)
                .GetResponse()
                .into_ref()
                .get_ref(),
        }
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
pub enum ResponseCode {
    #[default]
    None = 0,
    Ok = 200,
    Created,
    Accepted,
    NotAuthoritative,
    NoContent,
    Reset,
    Partial,
    MultChoice = 300,
    MovedPerm,
    MovedTemp,
    SeeOther,
    NotModified,
    UseProxy,
    BadRequest = 400,
    Unauthorized,
    PaymentRequired,
    Forbidden,
    NotFound,
    BadMethod,
    NotAcceptable,
    ProxyAuth,
    ClientTimeout,
    Conflict,
    Gone,
    LengthRequired,
    PreconFailed,
    EntityTooLarge,
    ReqTooLong,
    UnsupportedType,
    InternalError = 500,
    NotImplemented,
    BadGateway,
    Unavailable,
    GatewayTimeout,
    Version,
}

#[derive(Clone)]
pub struct PerformanceInfo {
    pub dns_timing: f64,
    pub tcp_timing: f64,
    pub tls_timing: f64,
    pub first_send_timing: f64,
    pub first_receive_timing: f64,
    pub total_timing: f64,
    pub redirect_timing: f64,
}

/// connection extra info of the http response
#[derive(Clone)]
pub struct ConnectionExtraInfo {
    pub network_protocol_name: String,
    pub tls_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub local_address: String,
    pub remote_address: String,
    pub local_port: i32,
    pub remote_port: i32,
    pub is_reused_connection: bool,
    pub is_proxy_connection: bool,
    pub is_cache_hit: bool,
    pub redirect_count: i32,
}

const PARAM_KEY_NETWORK_PROTOCOL_NAME: &str = "networkProtocolName";
const PARAM_KEY_TLS_VERSION: &str = "tlsVersion";
const PARAM_KEY_CIPHER_SUITE: &str = "cipherSuite";
const PARAM_KEY_LOCAL_ADDRESS: &str = "localAddress";
const PARAM_KEY_REMOTE_ADDRESS: &str = "remoteAddress";
const PARAM_KEY_LOCAL_PORT: &str = "localPort";
const PARAM_KEY_REMOTE_PORT: &str = "remotePort";
const PARAM_KEY_IS_REUSED_CONNECTION: &str = "isReusedConnection";
const PARAM_KEY_IS_PROXY_CONNECTION: &str = "isProxyConnection";
const PARAM_KEY_IS_CACHE_HIT: &str = "isCacheHit";
const PARAM_KEY_REDIRECT_COUNT: &str = "redirectCount";

pub(crate) fn performance_from_response(res: &HttpClientResponse) -> PerformanceInfo {
    let ptr = res as *const HttpClientResponse as *mut HttpClientResponse;
    let pin = unsafe { Pin::new_unchecked(ptr.as_mut().unwrap()) };
    let info = wrapper::ffi::GetPerformanceTiming(pin);
    PerformanceInfo {
        dns_timing: info.dns_timing,
        tcp_timing: info.tcp_timing,
        tls_timing: info.tls_timing,
        first_send_timing: info.first_send_timing,
        first_receive_timing: info.first_receive_timing,
        total_timing: info.total_timing,
        redirect_timing: info.redirect_timing,
    }
}

pub(crate) fn extra_info_from_response(res: &HttpClientResponse) -> ConnectionExtraInfo {
    let get = |key: &str| -> String {
        cxx::let_cxx_string!(key_cxx = key);
        GetExtraInfoItem(res, &key_cxx)
    };
    let parse_i32 = |value: String, default_value: i32| -> i32 {
        value.trim().parse::<i32>().unwrap_or(default_value)
    };
    let parse_bool = |value: String| -> bool { value.trim().to_lowercase() == "true" };
    let tls_version = get(PARAM_KEY_TLS_VERSION);
    let cipher_suite = get(PARAM_KEY_CIPHER_SUITE);
    ConnectionExtraInfo {
        network_protocol_name: get(PARAM_KEY_NETWORK_PROTOCOL_NAME),
        tls_version: if tls_version.is_empty() { None } else { Some(tls_version) },
        cipher_suite: if cipher_suite.is_empty() { None } else { Some(cipher_suite) },
        local_address: get(PARAM_KEY_LOCAL_ADDRESS),
        remote_address: get(PARAM_KEY_REMOTE_ADDRESS),
        local_port: parse_i32(get(PARAM_KEY_LOCAL_PORT), -1),
        remote_port: parse_i32(get(PARAM_KEY_REMOTE_PORT), -1),
        is_reused_connection: parse_bool(get(PARAM_KEY_IS_REUSED_CONNECTION)),
        is_proxy_connection: parse_bool(get(PARAM_KEY_IS_PROXY_CONNECTION)),
        is_cache_hit: parse_bool(get(PARAM_KEY_IS_CACHE_HIT)),
        redirect_count: parse_i32(get(PARAM_KEY_REDIRECT_COUNT), 0),
    }
}

/// http data type
#[derive(Debug, Default)]
pub enum HttpDataType {
    StringType = 0,
    ObjectType,
    ArrayBuffer,
    #[default]
    None,
}

impl HttpDataType {
    pub fn to_i32(&self) -> i32 {
        match self {
            HttpDataType::StringType => 0,
            HttpDataType::ObjectType => 1,
            HttpDataType::ArrayBuffer => 2,
            _=> -1,
        }
    }
}