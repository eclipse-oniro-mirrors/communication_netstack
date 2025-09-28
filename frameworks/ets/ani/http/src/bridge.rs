// Copyright (C) 2025 Huawei Device Co., Ltd.
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

use ani_rs::business_error::BusinessError;
use netstack_rs::error::HttpClientError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[ani_rs::ani]
pub struct Cleaner {
    pub native_ptr: i64,
}

#[ani_rs::ani(path = "L@ohos/net/http/http/HttpRequestInner")]
pub struct HttpRequest {
    pub native_ptr: i64,
}

#[ani_rs::ani]
pub enum AddressFamily {
    Default,

    OnlyV4,

    OnlyV6,
}

#[derive(Serialize, Deserialize)]
pub enum Data<'a> {
    S(String),
    Record(HashMap<String, String>),
    ArrayBuffer(&'a [u8]),
}

#[derive(Serialize, Deserialize)]
pub enum UsingProxy {
    Boolean(bool),
    // HttpProxy
}

#[ani_rs::ani]
pub struct HttpRequestOptions<'a> {
    pub method: Option<RequestMethod>,

    pub extra_data: Option<Data<'a>>,

    pub expect_data_type: Option<HttpDataType>,

    pub using_cache: Option<bool>,

    pub priority: Option<i32>,

    pub header: Option<HashMap<String, String>>,

    pub read_timeout: Option<i32>,

    pub connect_timeout: Option<i32>,

    pub using_protocol: Option<HttpProtocol>,

    pub using_proxy: Option<UsingProxy>,

    pub ca_path: Option<String>,

    pub resume_from: Option<i32>,

    pub resume_to: Option<i32>,

    pub client_cert: Option<ClientCert>,

    pub dns_over_https: Option<String>,

    pub dns_servers: Option<Vec<String>>,

    pub max_limit: Option<i32>,

    #[serde(borrow)]
    pub multi_form_data_list: Option<Vec<MultiFormData<'a>>>,

    // certificate_pinning:Option< CertificatePinning | CertificatePinning[]>,
    pub remote_validation: Option<String>,

    pub tls_options: Option<String>,

    pub server_authentication: Option<ServerAuthentication>,

    pub address_family: Option<AddressFamily>,
}

#[ani_rs::ani]
pub struct ServerAuthentication {
    pub credential: Credential,
    pub authentication_type: Option<String>,
}

#[ani_rs::ani]
pub struct Credential {
    pub username: String,
    pub password: String,
}

pub struct TlsConfig {
    pub tls_version_min: TlsVersion,
    pub tls_version_max: TlsVersion,
    pub cipher_suites: Option<Vec<String>>,
}

#[allow(non_camel_case_types)]
#[ani_rs::ani]
pub enum TlsVersion {
    TlsV_1_0 = 4,

    TlsV_1_1 = 5,

    TlsV_1_2 = 6,

    TlsV_1_3 = 7,
}

#[ani_rs::ani]
pub struct MultiFormData<'a> {
    pub name: String,

    pub content_type: String,

    pub remote_file_name: Option<String>,

    #[serde(borrow)]
    pub data: Option<Data<'a>>,

    pub file_path: Option<String>,
}

#[ani_rs::ani(path = "L@ohos/net/http/http/CertType")]
pub enum CertType {
    Pem,

    Der,

    P12,
}

#[ani_rs::ani]
pub struct ClientCert {
    pub cert_path: String,

    pub cert_type: Option<CertType>,

    pub key_path: String,

    pub key_password: Option<String>,
}

pub struct CertificatePinning {
    pub public_key_hash: String,
    //pub hash_algorithm: 'SHA-256',
}

#[ani_rs::ani(path = "L@ohos/net/http/http/RequestMethod")]
pub enum RequestMethod {
    Options,

    Get,

    Head,

    Post,

    Put,

    Delete,

    Trace,

    Connect,
}

impl RequestMethod {
    pub fn to_str(&self) -> &str {
        match self {
            RequestMethod::Options => "OPTIONS",
            RequestMethod::Get => "GET",
            RequestMethod::Head => "HEAD",
            RequestMethod::Post => "POST",
            RequestMethod::Put => "PUT",
            RequestMethod::Delete => "DELETE",
            RequestMethod::Trace => "TRACE",
            RequestMethod::Connect => "CONNECT",
        }
    }
}

#[ani_rs::ani(path = "L@ohos/net/http/http/ResponseCode")]
pub enum ResponseCode {
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

    RangeNotSatisfiable,

    InternalError = 500,

    NotImplemented,

    BadGateway,

    Unavailable,

    GatewayTimeout,

    Version,
}

#[ani_rs::ani(path = "L@ohos/net/http/http/HttpProtocol")]
#[repr(i32)]
pub enum HttpProtocol {
    Http1_1,

    Http2,

    Http3,
}

impl HttpProtocol {
    pub fn to_i32(&self) -> i32 {
        // 0 indicate HTTP_NONE in http_client_request.h
        match self {
            HttpProtocol::Http1_1 => 1,
            HttpProtocol::Http2 => 2,
            HttpProtocol::Http3 => 3,
        }
    }
}

#[ani_rs::ani(path = "L@ohos/net/http/http/HttpDataType")]
pub enum HttpDataType {
    String,

    Object = 1,

    ArrayBuffer = 2,
}

#[derive(Serialize)]
pub enum ResponseCodeOutput {
    #[serde(rename = "L@ohos/net/http/http/ResponseCode;")]
    Code(ResponseCode),
    I32(i32),
}

#[ani_rs::ani(path = "L@ohos/net/http/http/HttpResponseInner", output = "only")]
pub struct HttpResponse {
    pub result: String,
    pub result_type: HttpDataType,
    pub response_code: ResponseCodeOutput,
    pub header: HashMap<String, String>,
    pub cookies: String,
    pub performance_timing: PerformanceTiming,
}

#[ani_rs::ani(path = "L@ohos/net/http/http/PerformanceTimingInner")]
pub struct PerformanceTiming {
    pub dns_timing: f64,
    pub tcp_timing: f64,
    pub tls_timing: f64,
    pub first_send_timing: f64,
    pub first_receive_timing: f64,
    pub total_finish_timing: f64,
    pub redirect_timing: f64,
    pub response_header_timing: f64,
    pub response_body_timing: f64,
    pub total_timing: f64,
}

impl PerformanceTiming {
    pub fn new() -> Self {
        Self {
            dns_timing: 0.0,
            tcp_timing: 0.0,
            tls_timing: 0.0,
            first_send_timing: 0.0,
            first_receive_timing: 0.0,
            total_finish_timing: 0.0,
            redirect_timing: 0.0,
            response_header_timing: 0.0,
            response_body_timing: 0.0,
            total_timing: 0.0,
        }
    }
}

impl From<netstack_rs::response::PerformanceInfo> for PerformanceTiming {
    fn from(value: netstack_rs::response::PerformanceInfo) -> Self {
        Self {
            dns_timing: value.dns_timing,
            tcp_timing: value.tcp_timing,
            tls_timing: value.tls_timing,
            first_send_timing: value.first_send_timing,
            first_receive_timing: value.first_receive_timing,
            total_finish_timing: 0.0,
            redirect_timing: value.redirect_timing,
            response_header_timing: 0.0,
            response_body_timing: 0.0,
            total_timing: value.total_timing,
        }
    }
}

#[ani_rs::ani(path = "L@ohos/net/http/http/HttpResponse")]
pub struct DataReceiveProgressInfo {
    pub receive_size: i32,
    pub total_size: i32,
}

#[ani_rs::ani(path = "L@ohos/net/http/http/HttpResponse")]
pub struct DataSendProgressInfo {
    pub send_size: i32,
    pub total_size: i32,
}

#[ani_rs::ani]
pub struct HttpResponseCache {
    pub native_ptr: i64,
}

pub fn convert_to_business_error(client_error: &HttpClientError) -> BusinessError {
    let error_code = client_error.code() as i32;
    let msg = client_error.msg().to_string();
    BusinessError::new(error_code, msg)
}
