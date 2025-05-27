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

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

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
    VecBuffer(&'a [u8]),
    // Object
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
pub enum HttpProtocol {
    Http1_1,

    Http2,

    Http3,
}

#[ani_rs::ani(path = "L@ohos/net/http/http/HttpDataType")]
pub enum HttpDataType {
    String,

    Object = 1,

    ArrayBuffer = 2,
}

#[ani_rs::ani(path = "L@ohos/net/http/http/HttpResponse")]
pub struct HttpResponse {
    // pub result: String | Object | VecBuffer,
    pub result_type: HttpDataType,

    // pub response_code: ResponseCode | i32,
    // pub header: Object,
    pub cookies: String,

    pub performance_timing: PerformanceTiming,
}

#[ani_rs::ani(path = "L@ohos/net/http/http/HttpResponse")]
pub struct PerformanceTiming {
    pub dns_timing: i32,

    pub tcp_timing: i32,

    pub tls_timing: i32,

    pub first_send_timing: i32,

    pub first_receive_timing: i32,

    pub total_finish_timing: i32,

    pub redirect_timing: i32,

    pub response_header_timing: i32,

    pub response_body_timing: i32,

    pub total_timing: i32,
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
