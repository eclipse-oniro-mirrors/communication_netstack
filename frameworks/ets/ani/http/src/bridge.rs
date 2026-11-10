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

use ani_rs::{business_error::BusinessError, global::GlobalRef, objects::{AniObject, AniRef}};
use netstack_rs::error::HttpClientError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[ani_rs::ani]
pub struct Cleaner {
    pub native_ptr: i64,
}

#[ani_rs::ani(path = "@ohos.net.http.http.HttpRequestInner")]
pub struct HttpRequest {
    pub native_ptr: i64,
}

#[ani_rs::ani(path = "@ohos.net.http.http.AddressFamily")]
#[repr(i32)]
pub enum AddressFamily {
    Default,

    OnlyV4,

    OnlyV6,
}

impl AddressFamily {
    pub fn to_i32(&self) -> i32 {
        match self {
            AddressFamily::Default => 0,
            AddressFamily::OnlyV4 => 1,
            AddressFamily::OnlyV6 => 2,
        }
    }
}

#[ani_rs::ani(path = "@ohos.net.connection.connection.HttpProxyInner")]
pub struct HttpProxy {
    pub host: String,

    pub port: i32,

    pub username: Option<String>,

    pub password: Option<String>,

    pub exclusion_list: Vec<String>,
}

#[ani_rs::ani(path = "@ohos.net.connection.connection.Socks5ProxyInner")]
pub struct Socks5Proxy {
    pub host: String,

    pub port: i32,

    pub username: Option<String>,

    pub password: Option<String>,

    pub dns_strategy: Option<i32>,

    pub exclusion_list: Option<Vec<String>>,
}

#[ani_rs::ani]
pub struct HttpRequestOptions<'local> {
    pub method: Option<RequestMethod>,

    pub extra_data: Option<AniObject<'local>>,

    pub expect_data_type: Option<HttpDataType>,

    pub using_cache: Option<bool>,

    pub priority: Option<i32>,

    pub header: Option<AniObject<'local>>,

    pub read_timeout: Option<i32>,

    pub connect_timeout: Option<i32>,

    pub using_protocol: Option<HttpProtocol>,

    pub using_proxy: Option<AniObject<'local>>,

    pub ca_path: Option<String>,

    pub ca_data: Option<String>,

    pub ssl_type: Option<String>,

    pub client_enc_cert: Option<ClientCert>,

    pub resume_from: Option<i64>,

    pub resume_to: Option<i64>,

    pub client_cert: Option<ClientCert>,

    pub dns_over_https: Option<String>,

    pub dns_servers: Option<Vec<String>>,

    pub max_limit: Option<i32>,

    pub multi_form_data_list: Option<Vec<MultiFormData<'local>>>,

    pub certificate_pinning: Option<AniObject<'local>>,

    pub remote_validation: Option<AniObject<'local>>,

    pub tls_options: Option<AniObject<'local>>,

    pub server_authentication: Option<ServerAuthentication>,

    pub address_family: Option<AddressFamily>,

    pub sni_host_name: Option<String>,
    pub max_redirects: Option<i32>,

    pub custom_method: Option<String>,

    pub path_preference: Option<String>,

    pub reuse_connections: Option<bool>,

    pub inactivity_ms: Option<i32>,

    pub using_socks5_proxy: Option<Socks5Proxy>,

    pub enable_partial_chain: Option<bool>,

    pub query_params: Option<AniObject<'local>>,

    pub body: Option<AniObject<'local>>,
}

#[ani_rs::ani(path = "@ohos.net.http.http.ServerAuthenticationInner")]
#[repr(C)]
pub struct ServerAuthentication {
    pub credential: Credential,
    pub authentication_type: Option<String>,
}

#[ani_rs::ani(path = "@ohos.net.http.http.CredentialInner")]
#[repr(C)]
pub struct Credential {
    pub username: String,
    pub password: String,
}

#[ani_rs::ani(path = "@ohos.net.http.http.TlsConfigInner")]
#[repr(C)]
pub struct TlsConfig {
    pub tls_version_min: TlsVersion,
    pub tls_version_max: TlsVersion,
    pub cipher_suites: Option<Vec<String>>,
}

#[allow(non_camel_case_types)]
#[ani_rs::ani(path = "@ohos.net.http.http.TlsVersion")]
#[repr(C)]
pub enum TlsVersion {
    TlsV_1_0 = 4,

    TlsV_1_1 = 5,

    TlsV_1_2 = 6,

    TlsV_1_3 = 7,
}

#[ani_rs::ani(path = "@ohos.net.http.http.MultiFormDataInner")]
#[repr(C)]
pub struct MultiFormData<'local> {
    pub name: String,

    pub content_type: String,

    pub remote_file_name: Option<String>,

    pub data: Option<AniObject<'local>>,

    pub file_path: Option<String>,
}

#[ani_rs::ani(path = "@ohos.net.http.http.CertType")]
#[repr(i32)]
pub enum CertType {
    Pem,

    Der,

    P12,
}

#[ani_rs::ani(path = "@ohos.net.http.http.ClientCertInner")]
#[repr(C)]
pub struct ClientCert {
    pub cert_path: String,

    pub cert_type: Option<CertType>,

    pub key_path: String,

    pub key_password: Option<String>,
}

#[ani_rs::ani(path = "@ohos.net.http.http.CertificatePinningInner")]
#[repr(C)]
pub struct CertificatePinning {
    pub public_key_hash: String,

    pub hash_algorithm: String,
}

#[ani_rs::ani(path = "@ohos.net.http.http.RequestMethod")]
pub enum RequestMethod {
    Options,

    Get,

    Head,

    Post,

    Put,

    Delete,

    Trace,

    Connect,

    Patch,
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
            RequestMethod::Patch => "PATCH",
        }
    }
}

#[ani_rs::ani(path = "@ohos.net.http.http.ResponseCode")]
#[derive(Clone)]
pub enum ResponseCode {
    Ok = 200,

    Created = 201,

    Accepted = 202,

    NotAuthoritative = 203,

    NoContent = 204,

    Reset = 205,

    Partial = 206,

    MultChoice = 300,

    MovedPerm = 301,

    MovedTemp = 302,

    SeeOther = 303,

    NotModified = 304,

    UseProxy = 305,

    BadRequest = 400,

    Unauthorized = 401,

    PaymentRequired = 402,

    Forbidden = 403,

    NotFound = 404,

    BadMethod = 405,

    NotAcceptable = 406,

    ProxyAuth = 407,

    ClientTimeout = 408,

    Conflict = 409,

    Gone = 410,

    LengthRequired = 411,

    PreconFailed = 412,

    EntityTooLarge = 413,

    ReqTooLong = 414,

    UnsupportedType = 415,

    RangeNotSatisfiable = 416,

    InternalError = 500,

    NotImplemented = 501,

    BadGateway = 502,

    Unavailable = 503,

    GatewayTimeout = 504,

    Version = 505,
}

#[ani_rs::ani(path = "@ohos.net.http.http.HttpProtocol")]
#[repr(i32)]
pub enum HttpProtocol {
    Http1_1 = 0,

    Http2 = 1,

    Http3 = 2,
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

#[ani_rs::ani(path = "@ohos.net.http.http.HttpDataType")]
#[derive(Clone)]
#[repr(i32)]
pub enum HttpDataType {
    String = 0,

    Object = 1,

    ArrayBuffer = 2,
}

impl HttpDataType {
    pub fn to_i32(&self) -> i32 {
        match self {
            HttpDataType::String => 0,
            HttpDataType::Object => 1,
            HttpDataType::ArrayBuffer => 2,
        }
    }
}

#[derive(Serialize, Clone)]
pub enum ResponseCodeOutput {
    #[serde(rename = "@ohos.net.http.http.ResponseCode")]
    Code(ResponseCode),
    I32(i32),
}

#[ani_rs::ani(path = "@ohos.net.http.http.ConnectionExtraInfoInner")]
pub struct ConnectionExtraInfo {
    pub network_protocol_name: String,

    pub tls_version: Option<TlsVersion>,

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

#[ani_rs::ani(path = "@ohos.net.http.http.ValidationContextInner")]
pub struct ValidationContext<'local> {
    pub pem_certs: Vec<String>,

    pub x509_certs: Vec<AniObject<'local>>,

    pub host: String,

    pub ip: String,
}

impl From<netstack_rs::response::ConnectionExtraInfo> for ConnectionExtraInfo {
    fn from(value: netstack_rs::response::ConnectionExtraInfo) -> Self {
        Self {
            network_protocol_name: value.network_protocol_name,
            tls_version: match value.tls_version.as_deref() {
                Some("TLS_V_1_0") => Some(TlsVersion::TlsV_1_0),
                Some("TLS_V_1_1") => Some(TlsVersion::TlsV_1_1),
                Some("TLS_V_1_2") => Some(TlsVersion::TlsV_1_2),
                Some("TLS_V_1_3") => Some(TlsVersion::TlsV_1_3),
                _ => None,
            },
            cipher_suite: value.cipher_suite,
            local_address: value.local_address,
            remote_address: value.remote_address,
            local_port: value.local_port,
            remote_port: value.remote_port,
            is_reused_connection: value.is_reused_connection,
            is_proxy_connection: value.is_proxy_connection,
            is_cache_hit: value.is_cache_hit,
            redirect_count: value.redirect_count,
        }
    }
}

#[ani_rs::ani(path = "@ohos.net.http.http.HttpResponseInner", output = "only")]
pub struct HttpResponse {
    pub result: GlobalRef<AniRef<'static>>,
    pub result_type: HttpDataType,
    pub response_code: ResponseCodeOutput,
    pub header: HashMap<String, String>,
    pub cookies: String,
    pub performance_timing: PerformanceTiming,
    pub connection_extra_info: Option<ConnectionExtraInfo>,
}

impl HttpResponse {
    pub fn new(
        result: GlobalRef<AniRef<'static>>,
        result_type: HttpDataType,
        code: i32,
        header: HashMap<String, String>,
        cookies: String,
        performance_timing: PerformanceTiming,
        connection_extra_info: Option<ConnectionExtraInfo>) -> Self {
        Self {
            result,
            result_type,
            response_code: ResponseCodeOutput::I32(code),
            header,
            cookies,
            performance_timing,
            connection_extra_info,
        }
    }
}

#[ani_rs::ani(path = "@ohos.net.http.http.PerformanceTimingInner")]
#[derive(Clone)]
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

#[ani_rs::ani(path = "@ohos.net.http.http.DataReceiveProgressInfoInner")]
#[derive(Clone)]
pub struct DataReceiveProgressInfo {
    pub receive_size: i32,
    pub total_size: i32,
}

#[ani_rs::ani(path = "@ohos.net.http.http.DataSendProgressInfoInner")]
#[derive(Clone)]
pub struct DataSendProgressInfo {
    pub send_size: i32,
    pub total_size: i32,
}

#[ani_rs::ani(path = "@ohos.net.http.http.HttpResponseCacheInner")]
pub struct HttpResponseCache {
    pub native_ptr: i64,
}

pub fn convert_to_business_error(client_error: &HttpClientError) -> BusinessError {
    let error_code = client_error.code() as i32;
    let msg = client_error.msg().to_string();
    BusinessError::new(error_code, msg)
}

impl From<ClientCert> for netstack_rs::request::ClientCert {
    fn from(cert: ClientCert) -> Self {
        unsafe { std::mem::transmute(cert) }
    }
}

impl From<ServerAuthentication> for netstack_rs::request::ServerAuthentication {
    fn from(auth: ServerAuthentication) -> Self {
        unsafe { std::mem::transmute(auth) }
    }
}

impl From<CertType> for netstack_rs::request::CertType {
    fn from(ct: CertType) -> Self {
        unsafe { std::mem::transmute(ct) }
    }
}

impl From<TlsVersion> for netstack_rs::request::TlsVersion {
    fn from(version: TlsVersion) -> Self {
        unsafe { std::mem::transmute(version) }
    }
}

impl From<TlsConfig> for netstack_rs::request::TlsConfig {
    fn from(config: TlsConfig) -> Self {
        unsafe { std::mem::transmute(config) }
    }
}
