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

use cxx::{let_cxx_string, SharedPtr, UniquePtr};
use std::collections::HashMap;

use crate::error::HttpClientError;
use crate::response::Response;
use crate::task::RequestTask;
use crate::wrapper;
use crate::wrapper::ffi::{
    HttpClientRequest,
    NewHttpClientRequest,
    SetBody,
    SetHttpProtocol,
    SetUsingHttpProxyType,
    SetSpecifiedHttpProxy,
    SetAddressFamily,
    SetExtraData,
    SetExpectDataType,
    SetClientCert,
    SetDNSServers,
    AddMultiFormData,
    SetServerAuthentication,
    SetTLSOptions,
    SetHeaderExt,
    SetQueryParams,
    SetCertificatePinning,
    SetUsingSocks5Proxy,
    SetMaxRedirects,
    SetSniHostName,
    SetInactivityMs,
    SetCaData,
    SetCustomMethod,
    SetSslType,
    SetClientEncCert,
    SetPathPreference,
    SetValidationCallback,
};

/// Builder for creating a Request.
pub struct Request<C: RequestCallback + 'static> {
    inner: UniquePtr<HttpClientRequest>,
    callback: Option<C>,
}

impl<C: RequestCallback> Request<C> {
    /// Create a new Request.
    pub fn new() -> Self {
        Self {
            inner: NewHttpClientRequest(),
            callback: None,
        }
    }

    /// Set the URL for the request.
    pub fn url(&mut self, url: &str) -> &mut Self {
        let_cxx_string!(url = url);
        self.inner.pin_mut().SetURL(&url);
        self
    }

    /// Set the method for the request.
    pub fn method(&mut self, method: &str) -> &mut Self {
        let_cxx_string!(method = method);
        self.inner.pin_mut().SetMethod(&method);
        self
    }

    /// Set a header for the request.
    pub fn header(&mut self, key: &str, value: &str) -> &mut Self {
        let_cxx_string!(key = key);
        let_cxx_string!(value = value);
        self.inner.pin_mut().SetHeader(&key, &value);
        self
    }

    pub fn header_ext(&mut self, extra_data: EscapedData) -> &mut Self {
        SetHeaderExt(self.inner.pin_mut(), &extra_data.into());
        self
    }
    /// Set the body for the request.
    pub fn body(&mut self, body: &[u8]) -> &mut Self {
        unsafe { SetBody(self.inner.pin_mut(), body.as_ptr(), body.len()) };
        self
    }

    /// Set a timeout for the request.
    pub fn timeout(&mut self, timeout: u32) -> &mut Self {
        self.inner.pin_mut().SetTimeout(timeout);
        self
    }

    /// Set a connect timeout for the request.
    pub fn connect_timeout(&mut self, timeout: u32) -> &mut Self {
        self.inner.pin_mut().SetConnectTimeout(timeout);
        self
    }

    /// Set a priority for the request.
    pub fn priority(&mut self, priority: u32) -> &mut Self {
        self.inner.pin_mut().SetPriority(priority);
        self
    }

    /// Set a protocol for the request.
    pub fn protocol(&mut self, protocol: i32) -> &mut Self {
        SetHttpProtocol(self.inner.pin_mut(), protocol);
        self
    }

    /// Set a proxy type for the request.
    pub fn using_proxy_type(&mut self, proxy_type: i32) -> &mut Self {
        SetUsingHttpProxyType(self.inner.pin_mut(), proxy_type);
        self
    }

    /// Set a specified http proxy for the request.
    pub fn specified_proxy(&mut self, proxy: HttpProxy) -> &mut Self {
        SetSpecifiedHttpProxy(self.inner.pin_mut(), &proxy.into());
        self
    }

    /// Set a max limit for the request.
    pub fn max_limit(&mut self, max_limit: u32) -> &mut Self {
        self.inner.pin_mut().SetMaxLimit(max_limit);
        self
    }

    /// Set a ca_path for the request.
    pub fn ca_path(&mut self, path: &str) -> &mut Self {
        let_cxx_string!(path = path);
        self.inner.pin_mut().SetCaPath(&path);
        self
    }
    
    /// Set a resume_from for the request.
    pub fn resume_from(&mut self, num: i64) -> &mut Self {
        self.inner.pin_mut().SetResumeFrom(num);
        self
    }
    
    /// Set a resume_to for the request.
    pub fn resume_to(&mut self, num: i64) -> &mut Self {
        self.inner.pin_mut().SetResumeTo(num);
        self
    }
    
    /// Set a address_family for the request.
    pub fn address_family(&mut self, family: i32) -> &mut Self {
        SetAddressFamily(self.inner.pin_mut(), family);
        self
    }

    /// Set a extra_data for the request.
    pub fn extra_data(&mut self, extra_data: EscapedData) -> &mut Self {
        SetExtraData(self.inner.pin_mut(), &extra_data.into());
        self
    }

    /// Set a expect_data_type for the request.
    pub fn expect_data_type(&mut self, expect_data_type: i32) -> &mut Self {
        SetExpectDataType(self.inner.pin_mut(), expect_data_type);
        self
    }

    /// Set a using_cache for the request.
    pub fn using_cache(&mut self, using_cache: bool) -> &mut Self {
        self.inner.pin_mut().SetUsingCache(using_cache);
        self
    }

    /// Set a client_cert for the request.
    pub fn client_cert(&mut self, client_cert: ClientCert) -> &mut Self {        
        SetClientCert(self.inner.pin_mut(), &client_cert.into());
        self
    }

    /// Set a dns_over_https for the request.
    pub fn dns_over_https(&mut self, dns_over_https: &str) -> &mut Self {
        let_cxx_string!(dns_over_https = dns_over_https);
        self.inner.pin_mut().SetDNSOverHttps(&dns_over_https);
        self
    }

    /// Set a dns_servers for the request.
    pub fn dns_servers(&mut self, dns_servers: Vec<String>) -> &mut Self {        
        SetDNSServers(self.inner.pin_mut(), &dns_servers);
        self
    }
       
    /// add a multi_form_data to the multi_form_data_list for the request.
    pub fn add_multi_form_data(&mut self, multi_form_data: MultiFormData) -> &mut Self {
        AddMultiFormData(self.inner.pin_mut(), &multi_form_data.into());
        self
    }

    /// Set a remote_validation for the request.
    pub fn remote_validation(&mut self, remote_validation: &str) -> &mut Self {
        let_cxx_string!(remote_validation = remote_validation);
        self.inner.pin_mut().SetRemoteValidation(&remote_validation);
        self
    }

    /// Set a tls_options for the request.
    pub fn tls_options(&mut self, tls_options: TlsConfig) -> &mut Self {
        SetTLSOptions(self.inner.pin_mut(), &tls_options.into());
        self
    }

    /// Set a server_authentication for the request.
    pub fn server_authentication(&mut self, server_authentication: ServerAuthentication) -> &mut Self {        
        SetServerAuthentication(self.inner.pin_mut(), &server_authentication.into());
        self
    }

    /// Set a certificate_pinning for the request.
    pub fn certificate_pinning(&mut self, pins: Vec<CertificatePinning>) -> &mut Self {
        let pins: Vec<wrapper::ffi::CertificatePinningRust> = pins.into_iter().map(Into::into).collect();
        SetCertificatePinning(self.inner.pin_mut(), &pins);
        self
    }

    /// Set a max redirects for the request.
    pub fn max_redirects(&mut self, max_redirects: i32) -> &mut Self {
        SetMaxRedirects(self.inner.pin_mut(), max_redirects);
        self
    }

    /// Set a sni host name for the request.
    pub fn sni_host_name(&mut self, host_name: &str) -> &mut Self {
        let_cxx_string!(host_name = host_name);
        SetSniHostName(self.inner.pin_mut(), &host_name);
        self
    }

    /// Set a reuse connections flag for the request.
    pub fn reuse_connections(&mut self, reuse_connections: bool) -> &mut Self {
        self.inner.pin_mut().SetReuseConnections(reuse_connections);
        self
    }

    /// Set a inactivity ms for the request.
    pub fn inactivity_ms(&mut self, inactivity_ms: i32) -> &mut Self {
        SetInactivityMs(self.inner.pin_mut(), inactivity_ms);
        self
    }

    /// Set query params for the request.
    pub fn query_params(&mut self, query_params: EscapedData) -> &mut Self {
        SetQueryParams(self.inner.pin_mut(), &query_params.into());
        self
    }

    /// Set a body or query configured flag for the request.
    pub fn body_or_query_configured(&mut self, configured: bool) -> &mut Self {
        self.inner.pin_mut().SetBodyOrQueryConfigured(configured);
        self
    }

    /// Set a ca data for the request.
    pub fn ca_data(&mut self, ca_data: &str) -> &mut Self {
        let_cxx_string!(ca_data = ca_data);
        SetCaData(self.inner.pin_mut(), &ca_data);
        self
    }

    /// Set a ssl type for the request.
    pub fn ssl_type(&mut self, ssl_type: &str) -> &mut Self {
        let_cxx_string!(ssl_type = ssl_type);
        SetSslType(self.inner.pin_mut(), &ssl_type);
        self
    }

    /// Set a client enc cert for the request.
    pub fn client_enc_cert(&mut self, client_enc_cert: ClientCert) -> &mut Self {
        SetClientEncCert(self.inner.pin_mut(), &client_enc_cert.into());
        self
    }

    /// Set a path preference for the request.
    pub fn path_preference(&mut self, path_preference: &str) -> &mut Self {
        let_cxx_string!(path_preference = path_preference);
        SetPathPreference(self.inner.pin_mut(), &path_preference);
        self
    }

    /// Set a custom method for the request.
    pub fn custom_method(&mut self, custom_method: &str) -> bool {
        let_cxx_string!(custom_method = custom_method);
        SetCustomMethod(self.inner.pin_mut(), &custom_method)
    }

    /// Set a socks5 proxy for the request.
    pub fn socks5_proxy(&mut self, proxy: Socks5Proxy) -> &mut Self {
        SetUsingSocks5Proxy(self.inner.pin_mut(), &proxy.into());
        self
    }

    /// Set a enable partial chain flag for the request.
    pub fn enable_partial_chain(&mut self, partial_chain: bool) -> &mut Self {
        self.inner.pin_mut().SetPartialChain(partial_chain);
        self
    }

    /// Set a can skip cert verify flag for the request.
    pub fn can_skip_cert_verify(&mut self, can_skip_cert_verify: bool) -> &mut Self {
        self.inner.pin_mut().SetCanSkipCertVerifyFlag(can_skip_cert_verify);
        self
    }

    /// Set a enable auto cookie flag for the request.
    pub fn enable_auto_cookie(&mut self, enable: bool) -> &mut Self {
        self.inner.pin_mut().SetEnableAutoCookie(enable);
        self
    }

    /// Set a custom certificate validation callback for the request.
    pub fn validation_callback(
        &mut self,
        callback: Box<dyn FnMut(Vec<String>, String, String) -> bool + Send>,
    ) -> &mut Self {
        SetValidationCallback(
            self.inner.pin_mut(),
            Box::new(wrapper::ValidationCallbackWrapper::new(callback)),
        );
        self
    }

    /// Set a callback for the request.
    pub fn callback(&mut self, callback: C) -> &mut Self {
        self.callback = Some(callback);
        self
    }

    /// Build the RequestTask.
    pub fn build(mut self) -> RequestTask {
        let mut task = RequestTask::from_http_request(&self.inner);
        if let Some(callback) = self.callback.take() {
            task.set_callback(Box::new(callback));
        }
        task
    }
}

/// Curl share handle for sharing cookies between requests with auto cookie enabled.
/// Mirrors the share handle created by NAPI CreateShareHandle in http_module.cpp.
#[derive(Clone)]
pub struct CookieShareHandle {
    inner: SharedPtr<crate::wrapper::ffi::CookieShareHandle>,
}

impl CookieShareHandle {
    /// Create a cookie share handle; returns None if curl_share_init fails.
    pub fn new() -> Option<Self> {
        let inner = crate::wrapper::ffi::CreateCookieShareHandle();
        inner.as_ref()?;
        Some(Self { inner })
    }

    pub(crate) fn inner(&self) -> SharedPtr<crate::wrapper::ffi::CookieShareHandle> {
        self.inner.clone()
    }
}

/// RequestCallback
#[allow(unused_variables)]
pub trait RequestCallback {
    /// Called when the request is successful.
    fn on_success(&mut self, response: Response, is_request_in_stream: bool) {}
    /// Called when the request fails.
    fn on_fail(&mut self, response: Response, error: HttpClientError, is_request_in_stream: bool) {}
    /// Called when the request is canceled.
    fn on_cancel(&mut self, response: Response, is_request_in_stream: bool) {}
    /// Called when data is received.
    fn on_data_receive(&mut self, data: &[u8], task: RequestTask) {}
    /// Called when progress is made.
    fn on_progress(&mut self, dl_total: u64, dl_now: u64, ul_total: u64, ul_now: u64) {}
    /// Called when the task is restarted.
    fn on_restart(&mut self) {}
    /// Called when header is received.
    fn on_header_receive(&mut self, header: String) {}
    /// Called when headers is received.
    fn on_headers_receive(&mut self, headers: HashMap<String, String>) {}
}

impl<C: RequestCallback> Default for Request<C> {
    fn default() -> Self {
        Self::new()
    }
}

pub fn has_internet_permission() -> bool {
    wrapper::ffi::HasInternetPermission()
}

pub fn run_cache(capacity: Option<i32>) {
    match capacity {
        Some(value) => {
            if value >= 0 {
                wrapper::ffi::RunCacheWithSize(value as usize);
            } else {
                wrapper::ffi::RunCache();
            }
        }
        None => {
            wrapper::ffi::RunCache();
        }
    }
}

pub fn flush_cache() {
    wrapper::ffi::FlushCache();
}

pub fn delete_cache() {
    wrapper::ffi::StopCacheAndDelete();
}
#[repr(i32)]
pub enum CertType {
    Pem,
    Der,
    P12,
}

#[repr(C)]
pub struct ClientCert {
    pub cert_path: String,
    pub cert_type: Option<CertType>,
    pub key_path: String,
    pub key_password: Option<String>,
}

#[derive(Clone, Default)]
#[repr(C)]
pub struct EscapedData {
    // Benchmark HttpDataType. StringType is 0, ObjectType is 1, ArrayBuffer is 2.
    pub data_type: u32,
    pub data: String,
}

impl EscapedData {
    pub fn new() -> Self {
        Self {
            data_type: 0,
            data: String::new(),
        }
    }
}

#[repr(C)]
pub struct MultiFormData {
    pub name: String,
    pub content_type: String,
    pub remote_file_name: String,
    pub data: String,
    pub file_path: String,
}

#[repr(C)]
pub struct ServerAuthentication {
    pub credential: Credential,
    pub authentication_type: Option<String>,
}

#[repr(C)]
pub struct Credential {
    pub username: String,
    pub password: String,
}

#[repr(C)]
pub struct TlsConfig {
    pub tls_version_min: TlsVersion,
    pub tls_version_max: TlsVersion,
    pub cipher_suites: Option<Vec<String>>,
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub enum TlsVersion {
    TlsV_1_0 = 4,

    TlsV_1_1 = 5,

    TlsV_1_2 = 6,

    TlsV_1_3 = 7,
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub enum HttpProxyType {
    NOT_USE = 0,

    USE_SPECIFIED,

    PROXY_TYPE_MAX,
}

impl HttpProxyType {
    pub fn to_i32(&self) -> i32 {
        match self {
            HttpProxyType::NOT_USE => 0,
            HttpProxyType::USE_SPECIFIED => 1,
            HttpProxyType::PROXY_TYPE_MAX => 2,
        }
    }
}

#[repr(C)]
pub struct HttpProxy {
    pub host: String,

    pub port: i32,

    pub exclusions: String,

    pub username: String,

    pub password: String,
}

pub struct Socks5Proxy {
    pub host: String,
    pub port: i32,
    pub username: String,
    pub password: String,
    pub dns_strategy: i32,
    pub exclusion_list: Vec<String>,
}

pub const SOCKS5_DNS_STRATEGY_UNSET: i32 = -1;

pub struct CertificatePinning {
    pub hash_algorithm: String,
    pub public_key_hash: String,
}
