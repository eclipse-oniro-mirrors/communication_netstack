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

use std::{
    collections::HashMap,
    ffi::CStr,
    net::{Ipv4Addr, Ipv6Addr},
    ptr,
    sync::atomic::{AtomicBool, Ordering},
};

use ani_rs::{
    business_error::BusinessError,
    global::GlobalRef,
    typed_array::ArrayBuffer,
    objects::{AniAsyncCallback, AniClass, AniFnObject, AniMethod, AniRef, AniObject, JsonValue},
    AniEnv, AniVm, signature
};
use netstack_rs::{
    error::HttpErrorCode,
    request::{
        Request,
        RequestCallback,
        EscapedData,
        CookieShareHandle,
        run_cache,
        flush_cache,
        delete_cache
    },
    task::RequestTask
};

use crate::{
    bridge::{
        convert_to_business_error, Cleaner, HttpRequest, HttpRequestOptions, HttpResponse, HttpResponseCache,
	TlsConfig, HttpProxy, CertificatePinning, Socks5Proxy, ValidationContext, HttpDataType,
    },
    callback::{clear_pending_error, TaskCallback, RequestSyncCallback, RequestSyncOutcome},
};

pub struct Task {
    pub request_task: Option<RequestTask>,
    pub callback: Option<TaskCallback>,
    pub is_destroy: AtomicBool,
    pub enable_auto_cookie: AtomicBool,
    pub cookie_share_handle: Option<CookieShareHandle>,
}

impl Task {
    pub fn new() -> Self {
        Self {
            request_task: None,
            callback: None,
            is_destroy: AtomicBool::new(false),
            enable_auto_cookie: AtomicBool::new(false),
            cookie_share_handle: None,
        }
    }
}

#[ani_rs::native]
pub fn create_http_ptr() -> Result<i64, BusinessError> {
    let request = Box::new(Task::new());
    let ptr = Box::into_raw(request);
    Ok(ptr as i64)
}

pub fn parse_escaped_data_from_original_data<'local>(env: &AniEnv, obj_data: AniObject<'local>) -> EscapedData {
    let string_class = env.find_class(signature::STRING).unwrap();
    let array_buffer_class = env.find_class(signature::ARRAY_BUFFER).unwrap();
    let mut res = EscapedData {
        data_type: 0,
        data: String::new(),
    };
    if env.instance_of(&obj_data, &string_class).unwrap() {
        res.data_type = 0;
        res.data = env.deserialize::<String>(obj_data).unwrap();
    } else if env.instance_of(&obj_data, &array_buffer_class).unwrap() {
        res.data_type = 2;
        let buffer = env.deserialize::<ArrayBuffer>(obj_data).unwrap();
        res.data = String::from_utf8_lossy(buffer.as_ref()).to_string();
    } else {
        let json_value = env.deserialize::<JsonValue>(obj_data).unwrap();
        res.data_type = 1;
        res.data = json_value.stringify(env).unwrap_or_default();
    };
    res
}

const ESCAPED_DATA_TYPE_OBJECT: u32 = 1;
const MAP_GETTER: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"get\0") };
const ENTRY_KEY: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"$0\0") };
const ENTRY_VALUE: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"$1\0") };
 
fn object_class<'local>(env: &AniEnv<'local>, obj_data: &AniObject<'local>) -> Option<AniClass<'local>> {
    let mut ani_type = ptr::null_mut();
    let status = unsafe {
        ((**env.inner).Object_GetType.unwrap())(env.inner, obj_data.as_raw(), &mut ani_type)
    };
    if status != 0 {
        error!("failed to get class of header object, status: {}", status);
        return None;
    }
    Some(AniClass::from_raw(ani_type))
}
 
fn find_entries_method<'local>(
    env: &AniEnv<'local>,
    obj_data: &AniObject<'local>,
) -> Option<AniMethod<'local>> {
    let class = object_class(env, obj_data)?;
    env.find_method(&class, MAP_GETTER).ok()?;
    env.find_method(&class, signature::ENTRIES).ok()
}
 
fn entry_item<'local>(
    env: &AniEnv<'local>,
    pair: &AniObject<'local>,
    name: &CStr,
) -> Option<AniRef<'local>> {
    match env.get_property::<AniRef>(pair, name) {
        Ok(item) if !env.is_undefined(&item).unwrap_or(true) => Some(item),
        _ => None,
    }
}
 
fn collect_header_entries<'local>(
    env: &AniEnv<'local>,
    iterator: AniObject<'local>,
) -> Option<AniObject<'local>> {
    let iterator_class = env.find_class(signature::ITERATOR).ok()?;
    let next_method = env.find_method(&iterator_class, signature::NEXT).ok()?;
    let record = env.new_record().ok()?;
    loop {
        let next = match env.call_method_ref(&iterator, &next_method, ()) {
            Ok(next) => next,
            Err(err) => {
                error!("failed to iterate header entries: {:?}", err);
                return None;
            }
        };
        let next: AniObject = next.into();
        let value = match env.get_property::<AniRef>(&next, signature::VALUE) {
            Ok(value) => value,
            Err(err) => {
                error!("failed to read header entry: {:?}", err);
                return None;
            }
        };
        if env.is_undefined(&value).unwrap_or(true) {
            break;
        }
        let pair: AniObject = value.into();
        let key = entry_item(env, &pair, ENTRY_KEY)?;
        let value = entry_item(env, &pair, ENTRY_VALUE)?;
        if let Err(err) = env.set_record(&record, &key, &value) {
            error!("failed to convert header entry: {:?}", err);
            return None;
        }
    }
    Some(record)
}
 
/// Convert the ETS `Map`/`HashMap` passed as `options.header` into the payload
/// `SetHeaderExt` expects, i.e. `data_type == OBJECT` plus a JSON object text.
fn parse_header_map_from_original_data<'local>(
    env: &AniEnv<'local>,
    obj_data: &AniObject<'local>,
) -> Option<EscapedData> {
    let method = find_entries_method(env, obj_data)?;
    let iterator = match env.call_method_ref(obj_data, &method, ()) {
        Ok(iterator) => iterator,
        Err(err) => {
            error!("failed to call entries() of header: {:?}", err);
            return None;
        }
    };
    let record = collect_header_entries(env, iterator.into())?;
    let jsontest = JsonValue::from(AniRef::from(record.clone())).stringify(env);

    match JsonValue::from(AniRef::from(record)).stringify(env) {
        Ok(json) => Some(EscapedData {
            data_type: ESCAPED_DATA_TYPE_OBJECT,
            data: json,
        }),
        Err(err) => {
            error!("failed to serialize header map: {:?}", err);
            None
        }
    }
}

const DNS_SERVER_SIZE: usize = 3;
fn normalize_dns_servers(dns_servers: Vec<String>) -> Vec<String> {
    let mut servers = Vec::with_capacity(DNS_SERVER_SIZE);
    for server in dns_servers {
        if servers.len() >= DNS_SERVER_SIZE {
            break;
        }
        if server.parse::<Ipv4Addr>().is_ok() || server.parse::<Ipv6Addr>().is_ok() {
            servers.push(server);
        }
    }
    servers
}

pub fn http_set_options<C: RequestCallback + 'static>(
    env: &AniEnv,
    request: &mut Request<C>,
    options: HttpRequestOptions) {
    let mut method_set = false;
    if let Some(custom_method) = options.custom_method {
        method_set = request.custom_method(&custom_method);
    }
    if !method_set {
        if let Some(method) = options.method {
            request.method(method.to_str());
        }
    }
    if let Some(priority) = options.priority {
        request.priority(priority as u32);
    }
    if let Some(read_timeout) = options.read_timeout {
        request.timeout(read_timeout as u32);
    }
    if let Some(connect_timeout) = options.connect_timeout {
        request.connect_timeout(connect_timeout as u32);
    }
    let has_body_or_query = options.body.is_some() || options.query_params.is_some();
    if has_body_or_query {
        request.body_or_query_configured(true);
        if let Some(body) = options.body {
            let array_buffer_class = env.find_class(signature::ARRAY_BUFFER).unwrap();
            if env.instance_of(&body, &array_buffer_class).unwrap() {
                let buffer = env.deserialize::<ArrayBuffer>(body).unwrap();
                request.body(buffer.as_ref());
            } else {
                let escaped = parse_escaped_data_from_original_data(env, body);
                request.body(escaped.data.as_bytes());
            }
        }
        if let Some(query_params) = options.query_params {
            let escaped = parse_escaped_data_from_original_data(env, query_params);
            request.query_params(escaped);
        }
    } else if let Some(extra_data) = options.extra_data {
        request.extra_data(parse_escaped_data_from_original_data(env, extra_data));
    }
    if let Some(headers) = options.header {
        let escaped = match parse_header_map_from_original_data(env, &headers) {
            Some(escaped) => escaped,
            None => parse_escaped_data_from_original_data(env, headers),
        };
        request.header_ext(escaped);
    }
    if let Some(protocol) = options.using_protocol {
        request.protocol(protocol.to_i32());
    }
    if let Some(using_proxy) = options.using_proxy {
        let obj_data = using_proxy;
        let bool_class = env.find_class(signature::BOOLEAN).unwrap();
        if env.instance_of(&obj_data, &bool_class).unwrap() {
            let opt = env.deserialize::<bool>(obj_data).unwrap();
            let using_type = if opt {
                netstack_rs::request::HttpProxyType::PROXY_TYPE_MAX
            } else {
                netstack_rs::request::HttpProxyType::NOT_USE
            };
            request.using_proxy_type(using_type.to_i32());
        } else {
            let opt = env.deserialize::<HttpProxy>(obj_data).unwrap();
            let mut exclusions = String::new();
            for item in opt.exclusion_list {
                exclusions.push_str(&item);
            }
            let mut http_proxy = netstack_rs::request::HttpProxy {
                host: opt.host,
                port: opt.port,
                exclusions: exclusions,
                username: opt.username.unwrap_or_default(),
                password: opt.password.unwrap_or_default(),
            };
            request.using_proxy_type(netstack_rs::request::HttpProxyType::USE_SPECIFIED.to_i32());
            request.specified_proxy(http_proxy);
        }
    }
    if let Some(&max_limit) = options.max_limit.as_ref() {
        request.max_limit(max_limit as u32);
    }
    if let Some(ca_path) = options.ca_path {
        request.ca_path(&ca_path);
    }
    if let Some(ca_data) = options.ca_data {
        request.ca_data(&ca_data);
    }
    if let Some(resume_from) = options.resume_from {
        request.resume_from(resume_from);
    }
    if let Some(resume_to) = options.resume_to {
        request.resume_to(resume_to);
    }
    if let Some(address_family) = options.address_family {
        request.address_family(address_family.to_i32());
    }
    if let Some(expect_data_type) = options.expect_data_type {
        request.expect_data_type(expect_data_type.to_i32());
    }
    if let Some(using_cache) = options.using_cache {
        request.using_cache(using_cache);
    }
    if let Some(client_cert) = options.client_cert {
        request.client_cert(client_cert.into());
    }
    if let Some(dns_over_https) = options.dns_over_https {
        request.dns_over_https(&dns_over_https);
    }
    if let Some(dns_servers) = options.dns_servers {
        let dns_servers = normalize_dns_servers(dns_servers);
        if !dns_servers.is_empty() {
            request.dns_servers(dns_servers);
        }
    }
    if let Some(multi_form_data_list) = options.multi_form_data_list {
        for item in multi_form_data_list {
            let mut escaped_data: Option<String> = None;
            if let Some(original_data) = item.data {
                escaped_data = Some(parse_escaped_data_from_original_data(env, original_data).data);
            }
            let mut multi_form_data = netstack_rs::request::MultiFormData {
                name: item.name,
                content_type: item.content_type,
                remote_file_name: item.remote_file_name.unwrap_or(String::new()),
                data: escaped_data.unwrap_or(String::new()),
                file_path: item.file_path.unwrap_or(String::new()),
            };
            request.add_multi_form_data(multi_form_data);
        }
    }
    if let Some(remote_validation) = options.remote_validation {
        let string_class = env.find_class(signature::STRING).unwrap();
        if env.instance_of(&remote_validation, &string_class).unwrap() {
            let mode = env.deserialize::<String>(remote_validation).unwrap();
            if mode == "skip" {
                request.can_skip_cert_verify(true);
            } else if mode != "system" {
                error!("RemoteValidationMode config error: invalid string value");
            }
        } else {
            set_validation_callback(env, request, remote_validation);
        }
    }
    if let Some(tls_options) = options.tls_options {
        let obj_data = tls_options;
        let string_class = env.find_class(signature::STRING).unwrap();
        if env.instance_of(&obj_data, &string_class).unwrap() {
            // noting todo
        } else {
            let opt = env.deserialize::<TlsConfig>(obj_data).unwrap();
            request.tls_options(opt.into());
        }
    }
    if let Some(server_authentication) = options.server_authentication {
        request.server_authentication(server_authentication.into());
    }
    if let Some(certificate_pinning) = options.certificate_pinning {
        let obj_data = certificate_pinning;
        let array_class = env.find_class(signature::ARRAY).unwrap();
        let mut pins = Vec::new();
        if env.instance_of(&obj_data, &array_class).unwrap() {
            let opt = env.deserialize::<Vec<CertificatePinning>>(obj_data).unwrap();
            for item in opt {
                pins.push(netstack_rs::request::CertificatePinning {
                    hash_algorithm: item.hash_algorithm,
                    public_key_hash: item.public_key_hash,
                });
            }
        } else {
            let opt = env.deserialize::<CertificatePinning>(obj_data).unwrap();
            pins.push(netstack_rs::request::CertificatePinning {
                hash_algorithm: opt.hash_algorithm,
                public_key_hash: opt.public_key_hash,
            });
        }
        request.certificate_pinning(pins);
    }
    if let Some(max_redirects) = options.max_redirects {
        request.max_redirects(max_redirects);
    }
    if let Some(sni_host_name) = options.sni_host_name {
        request.sni_host_name(&sni_host_name);
    }
    if let Some(reuse_connections) = options.reuse_connections {
        request.reuse_connections(reuse_connections);
    }
    if let Some(inactivity_ms) = options.inactivity_ms {
        request.inactivity_ms(inactivity_ms);
    }
    if let Some(ssl_type) = options.ssl_type {
        request.ssl_type(&ssl_type);
    }
    if let Some(client_enc_cert) = options.client_enc_cert {
        request.client_enc_cert(client_enc_cert.into());
    }
    if let Some(path_preference) = options.path_preference {
        request.path_preference(&path_preference);
    }
    if let Some(opt) = options.using_socks5_proxy {
        request.socks5_proxy(netstack_rs::request::Socks5Proxy {
            host: opt.host,
            port: opt.port,
            username: opt.username.unwrap_or_default(),
            password: opt.password.unwrap_or_default(),
            dns_strategy: opt.dns_strategy.unwrap_or(netstack_rs::request::SOCKS5_DNS_STRATEGY_UNSET),
            exclusion_list: opt.exclusion_list.unwrap_or_default(),
        });
    }
    if let Some(partial_chain) = options.enable_partial_chain {
        request.enable_partial_chain(partial_chain);
    }
}

fn set_validation_callback<C: RequestCallback + 'static>(
    env: &AniEnv,
    request: &mut Request<C>,
    callback: AniObject,
) {
    let callback_ref = GlobalRef(match env.create_global_ref(callback.into()) {
        Ok(callback_ref) => callback_ref,
        Err(err) => {
            error!("Failed to create reference for validation callback: {:?}", err);
            return;
        }
    });
    request.validation_callback(Box::new(move |pem_certs, host, ip| {
        invoke_validation_callback(&callback_ref, pem_certs, host, ip)
    }));
}

fn invoke_validation_callback(
    callback_ref: &AniRef<'static>,
    pem_certs: Vec<String>,
    host: String,
    ip: String,
) -> bool {
    if let Ok(env) = AniVm::get_instance().get_env() {
        return invoke_validation_callback_on_ets_thread(&env, callback_ref, pem_certs, host, ip);
    }

    let callback_raw = (*callback_ref).clone();
    let (tx, rx) = std::sync::mpsc::channel();
    let posted = ani_rs::send_event_from_closure(
        move || {
            let verdict = match AniVm::get_instance().get_env() {
                Ok(env) => invoke_validation_callback_on_ets_thread(&env, &callback_raw, pem_certs, host, ip),
                Err(err) => {
                    error!("failed to get environment for validation callback: {:?}", err);
                    false
                }
            };
            let _ = tx.send(verdict);
        },
        "http_validation_callback",
    );
    if let Err(err) = posted {
        error!("failed to post validation callback to ArkTS thread: {:?}", err);
        return false;
    }

    match rx.recv_timeout(std::time::Duration::from_secs(30)) {
        Ok(verdict) => verdict,
        Err(err) => {
            error!("validation callback timed out or channel closed: {:?}", err);
            false
        }
    }
}

fn invoke_validation_callback_on_ets_thread(
    env: &AniEnv,
    callback_ref: &AniRef<'static>,
    pem_certs: Vec<String>,
    host: String,
    ip: String,
) -> bool {
    static VALIDATION_CALLBACK_WRAPPER_CLASS: &CStr =
        unsafe { CStr::from_bytes_with_nul_unchecked(b"@ohos.net.http.http.ValidationCallbackWrapper\0") };
    static VALIDATION_CALLBACK_FUNC_METHOD: &CStr =
        unsafe { CStr::from_bytes_with_nul_unchecked(b"validationCallbackFunc\0") };

    let class = match env.find_class(VALIDATION_CALLBACK_WRAPPER_CLASS) {
        Ok(class) => class,
        Err(err) => {
            error!("failed to find validation callback wrapper class: {:?}", err);
            return false;
        }
    };
    let glue_method = match env.find_static_method(&class, VALIDATION_CALLBACK_FUNC_METHOD) {
        Ok(method) => method,
        Err(err) => {
            error!("failed to find validation callback glue method: {:?}", err);
            return false;
        }
    };
    let callback_obj: AniObject = (*callback_ref).clone().into();
    let context = ValidationContext {
        pem_certs,
        x509_certs: Vec::new(),
        host,
        ip,
    };
    let context_ref = match env.serialize(&context) {
        Ok(context_ref) => context_ref,
        Err(err) => {
            error!("failed to serialize validation context: {:?}", err);
            return false;
        }
    };
    let result = match env.call_static_method_ref(&class, &glue_method, (callback_obj, context_ref)) {
        Ok(result) => result,
        Err(err) => {
            error!("failed to call validation callback: {:?}", err);
            return false;
        }
    };
    match env.deserialize::<bool>(result.into()) {
        Ok(verdict) => verdict,
        Err(err) => {
            error!("callback returned invalid type: {:?}", err);
            false
        }
    }
}

#[ani_rs::native]
pub fn create_http_response_cache<'local>(
    env: &AniEnv<'local>, cacheSize : Option<i32>) -> Result<AniRef<'local>, BusinessError> {
    static HTTP_RESPONSE_CACHE_CLASS: &CStr =
        unsafe { CStr::from_bytes_with_nul_unchecked(b"@ohos.net.http.http.HttpResponseCacheInner\0") };
    static CTOR_SIGNATURE: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"l:\0") };

    let class = env.find_class(HTTP_RESPONSE_CACHE_CLASS).unwrap();
    let obj = env
        .new_object_with_signature(&class, CTOR_SIGNATURE, (0,))
        .unwrap();
    run_cache(cacheSize);
    Ok(obj.into())
}

#[ani_rs::native]
pub(crate) fn request(
    env: &AniEnv,
    this: HttpRequest,
    url: String,
    async_callback: AniAsyncCallback,
    options: Option<HttpRequestOptions>,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    if task.is_destroy.load(Ordering::Relaxed) {
        error!("Request is already destroyed");
        let business_error = BusinessError::new(
            HttpErrorCode::HttpUnknownOtherError as i32,
            "Request is already destroyed".to_string(),
        );
        let undefined: Option<bool> = None; //None will serialize arkts's undefined
        async_callback
            .execute_local(env, Some(business_error), (undefined,))
            .unwrap();
        return Ok(());
    }
    let mut request = Request::<TaskCallback>::new();

    request.url(url.as_str());
    if let Some(opts) = options {
        http_set_options(env, &mut request, opts);
    }
    let enable = task.enable_auto_cookie.load(Ordering::Relaxed);
    request.enable_auto_cookie(enable);

    let mut cb = match task.callback.as_ref() {
        Some(callback) => callback.for_request(),
        None => TaskCallback::new(),
    };
    cb.on_response = Some(async_callback.clone().into_global_callback(env).unwrap());
    let mut is_headers_once = false;
    if let Some(task_callback) = task.callback.as_mut() {
        if task_callback.is_headers_once {
            is_headers_once = true;
            task_callback.on_headers_receive = None;
            task_callback.is_headers_once = false;
        }
    }
    request.callback(cb);
    let mut request_task = request.build();
    if is_headers_once {
        request_task.set_is_headers_once(true);
    }
    if enable {
        if let Some(ref handle) = task.cookie_share_handle {
            request_task.set_cookie_share_handle(handle);
        }
    }
    if !request_task.start() {
        let error = request_task.get_error();
        error!("request_task.start error = {:?}", error);
        let business_error = convert_to_business_error(&error);
        let undefined: Option<bool> = None; //None will serialize arkts's undefined
        async_callback
            .execute_local(env, Some(business_error), (undefined,))
            .unwrap();
        return Ok(());
    }
    task.request_task = Some(request_task);
    Ok(())
}

const MAX_JSON_PARSE_SIZE: usize = 65536;

fn build_sync_result(
    env: &AniEnv,
    string_data: &String,
    data_type: netstack_rs::response::HttpDataType,
    header: &HashMap<String, String>,
) -> (GlobalRef<AniRef<'static>>, HttpDataType) {
    match data_type {
        netstack_rs::response::HttpDataType::StringType => {
            let result_ref = env.serialize(string_data).unwrap().into_global(env).unwrap();
            return (result_ref, HttpDataType::String);
        }
        netstack_rs::response::HttpDataType::ObjectType => {
            if string_data.len() <= MAX_JSON_PARSE_SIZE {
                if let Ok(json_value) = JsonValue::parse(env, string_data) {
                    let result_ref = AniRef::from(json_value).into_global(env).unwrap();
                    return (result_ref, HttpDataType::Object);
                }
            }
        }
        netstack_rs::response::HttpDataType::ArrayBuffer => {
            let array_buffer = ArrayBuffer::new_with_vec(string_data.as_bytes().to_vec());
            if let Ok(reference) = env.serialize(&array_buffer) {
                let result_ref = reference.into_global(env).unwrap();
                return (result_ref, HttpDataType::ArrayBuffer);
            }
        }
        _ => {}
    }

    // (HttpConstant::HTTP_CONTENT_TYPE_OCTET_STREAM / HTTP_CONTENT_TYPE_IMAGE).
    let is_binary_content = header.iter().any(|(key, value)| {
        key.eq_ignore_ascii_case("content-type")
            && (value.to_lowercase().contains("application/octet-stream") || value.to_lowercase().contains("image"))
    });
    if is_binary_content {
        let array_buffer = ArrayBuffer::new_with_vec(string_data.as_bytes().to_vec());
        if let Ok(reference) = env.serialize(&array_buffer) {
            let result_ref = reference.into_global(env).unwrap();
            return (result_ref, HttpDataType::ArrayBuffer);
        }
    }
    let result_ref = env.serialize(string_data).unwrap().into_global(env).unwrap();
    (result_ref, HttpDataType::String)
}

#[ani_rs::native]
pub(crate) fn request_sync(
    env: &AniEnv,
    this: HttpRequest,
    url: String,
    options: Option<HttpRequestOptions>,
) -> Result<HttpResponse, BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    if task.is_destroy.load(Ordering::Relaxed) {
        error!("Request is already destroyed");
        return Err(BusinessError::new(
            HttpErrorCode::HttpUnknownOtherError as i32,
            "Request is already destroyed".to_string(),
        ));
    }
    let mut request = Request::<RequestSyncCallback>::new();

    request.url(url.as_str());
    if let Some(opts) = options {
        http_set_options(env, &mut request, opts);
    }
    let enable = task.enable_auto_cookie.load(Ordering::Relaxed);
    request.enable_auto_cookie(enable);

    let (callback, outcome, condvar) = RequestSyncCallback::new();
    request.callback(callback);
    let mut request_task = request.build();
    if enable {
        if let Some(ref handle) = task.cookie_share_handle {
            request_task.set_cookie_share_handle(handle);
        }
    }
    if !request_task.start() {
        let error = request_task.get_error();
        error!("request_task.start error = {:?}", error);
        return Err(convert_to_business_error(&error));
    }

    let mut outcome_guard = match outcome.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    while outcome_guard.is_none() {
        outcome_guard = match condvar.wait(outcome_guard) {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
    }
    let outcome = outcome_guard.take().unwrap();

    let result = match outcome {
        RequestSyncOutcome::Success(result)
        | RequestSyncOutcome::Fail(result)
        | RequestSyncOutcome::Cancel(result) => result,
    };
    let (result_ref, result_type) = build_sync_result(env, &result.string_data, result.data_type, &result.header);
    Ok(HttpResponse::new(
        result_ref,
        result_type,
        result.code,
        result.header,
        result.cookies,
        result.performance_timing,
        Some(result.connection_extra_info),
    ))
}

#[ani_rs::native]
pub(crate) fn request_in_stream(
    env: &AniEnv,
    this: HttpRequest,
    url: String,
    async_callback: AniAsyncCallback,
    options: Option<HttpRequestOptions>,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    if task.is_destroy.load(Ordering::Relaxed) {
        error!("Request is already destroyed");
        let business_error = BusinessError::new(
            HttpErrorCode::HttpUnknownOtherError as i32,
            "Request is already destroyed".to_string(),
        );
        let undefined: Option<bool> = None; //None will serialize arkts's undefined
        async_callback
            .execute_local(env, Some(business_error), (undefined,))
            .unwrap();
        return Ok(());
    }
    let mut request = Request::<TaskCallback>::new();

    request.url(url.as_str());
    if let Some(opts) = options {
        http_set_options(env, &mut request, opts);
    }
    let enable = task.enable_auto_cookie.load(Ordering::Relaxed);
    request.enable_auto_cookie(enable);

    let mut cb = match task.callback.as_ref() {
        Some(callback) => callback.for_request(),
        None => TaskCallback::new(),
    };
    cb.on_response_in_stream = Some(async_callback.clone().into_global_callback(env).unwrap());
    let mut is_headers_once = false;
    if let Some(task_callback) = task.callback.as_mut() {
        if task_callback.is_headers_once {
            is_headers_once = true;
            task_callback.on_headers_receive = None;
            task_callback.is_headers_once = false;
        }
    }
    request.callback(cb);
    let mut request_task = request.build();
    request_task.set_is_request_in_stream(true);
    if is_headers_once {
        request_task.set_is_headers_once(true);
    }
    if enable {
        if let Some(ref handle) = task.cookie_share_handle {
            request_task.set_cookie_share_handle(handle);
        }
    }
    if !request_task.start() {
        let error = request_task.get_error();
        error!("request_task.start error = {:?}", error);
        let business_error = convert_to_business_error(&error);
        let undefined: Option<bool> = None; //None will serialize arkts's undefined
        async_callback
            .execute_local(env, Some(business_error), (undefined,))
            .unwrap();
        return Ok(());
    }
    task.request_task = Some(request_task);
    Ok(())
}

#[ani_rs::native]
pub(crate) fn enable_auto_cookie(
    this: HttpRequest,
    enable: bool,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    task.enable_auto_cookie.store(enable, Ordering::Relaxed);
    if enable {
        if task.cookie_share_handle.is_none() {
            match CookieShareHandle::new() {
                Some(handle) => {
                    task.cookie_share_handle = Some(handle);
                }
                None => {
                    error!("enableAutoCookie: failed to create share handle");
                }
            }
        }
    } else {
        task.cookie_share_handle = None;
    }
    Ok(())
}

#[ani_rs::native]
pub(crate) fn destroy(this: HttpRequest) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    if let Some(request_task) = task.request_task.take() {
        request_task.cancel();
    }
    task.cookie_share_handle = None;
    task.is_destroy.store(true, Ordering::Relaxed);
    Ok(())
}

#[ani_rs::native]
pub(crate) fn clean_http_request(env: &AniEnv, this: Cleaner) -> Result<(), BusinessError> {
    unsafe {
        let _ = Box::from_raw(this.native_ptr as *mut Task);
    };
    Ok(())
}

#[ani_rs::native]
pub(crate) fn clean_http_cache(this: Cleaner) -> Result<(), BusinessError> {
    Ok(())
}

pub(crate) fn on_header_receive(
    env: &AniEnv,
    this: HttpRequest,
    async_callback: AniAsyncCallback,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    match task.callback {
        Some(ref mut callback) => {
            // Convert the async callback to a global reference
            callback.on_header_receive = Some(async_callback.into_global_callback(env).unwrap());
        }
        None => {
            let mut task_callback = TaskCallback::new();
            task_callback.on_header_receive =
                Some(async_callback.into_global_callback(env).unwrap());
            task.callback = Some(task_callback);
        }
    }
    Ok(())
}

pub(crate) fn off_header_receive(
    this: HttpRequest,
    async_callback: AniAsyncCallback,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    match task.request_task {
        Some(ref mut request_task) => {
            request_task.off_header_receive();
        }
        None => {
            // noting todo
        }
    }
    match task.callback {
        Some(ref mut callback) => {
            callback.on_header_receive = None;
        }
        None => {
            // noting todo
        }
    }
    Ok(())
}

#[ani_rs::native]
pub(crate) fn on_headers_receive(
    env: &AniEnv,
    this: HttpRequest,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    match task.callback {
        Some(ref mut task_callback) => {
            // Convert the async callback to a global reference
            task_callback.on_headers_receive = Some(callback.into_global_callback(env).unwrap());
            task_callback.is_headers_once = false;
        }
        None => {
            let mut new_task_callback = TaskCallback::new();
            new_task_callback.on_headers_receive =
                Some(callback.into_global_callback(env).unwrap());
            new_task_callback.is_headers_once = false;
            task.callback = Some(new_task_callback);
        }
    }
    Ok(())
}

#[ani_rs::native]
pub(crate) fn off_headers_receive(
    this: HttpRequest,
    _callback: Option<AniFnObject>,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    match task.request_task {
        Some(ref mut request_task) => {
            request_task.off_headers_receive();
        }
        None => {
            // noting todo
        }
    }
    match task.callback {
        Some(ref mut task_callback) => {
            task_callback.on_headers_receive = None;
            task_callback.is_headers_once = false;
        }
        None => {
            // noting todo
        }
    }
    Ok(())
}

#[ani_rs::native]
pub(crate) fn on_data_receive(
    env: &AniEnv,
    this: HttpRequest,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    match task.callback {
        Some(ref mut task_callback) => {
            // Convert the async callback to a global reference
            task_callback.on_data_receive = Some(callback.into_global_callback(env).unwrap());
        }
        None => {
            let mut new_task_callback = TaskCallback::new();
            new_task_callback.on_data_receive = Some(callback.into_global_callback(env).unwrap());
            task.callback = Some(new_task_callback);
        }
    }
    Ok(())
}

#[ani_rs::native]
pub(crate) fn off_data_receive(
    this: HttpRequest,
    _callback: Option<AniFnObject>,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    match task.request_task {
        Some(ref mut request_task) => {
            request_task.off_data_receive();
        }
        None => {
            // noting todo
        }
    }
    match task.callback {
        Some(ref mut task_callback) => {
            task_callback.on_data_receive = None;
        }
        None => {
            // noting todo
        }
    }
    Ok(())
}

#[ani_rs::native]
pub(crate) fn on_data_end(
    env: &AniEnv,
    this: HttpRequest,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    match task.callback {
        Some(ref mut task_callback) => {
            // Convert the async callback to a global reference
            task_callback.on_data_end = Some(callback.into_global_callback(env).unwrap());
        }
        None => {
            let mut new_task_callback = TaskCallback::new();
            new_task_callback.on_data_end = Some(callback.into_global_callback(env).unwrap());
            task.callback = Some(new_task_callback);
        }
    }
    Ok(())
}

#[ani_rs::native]
pub(crate) fn off_data_end(
    env: &AniEnv,
    this: HttpRequest,
    _callback: Option<AniFnObject>,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    match task.callback {
        Some(ref mut task_callback) => {
            task_callback.on_data_end = None;
        }
        None => {
            // noting todo
        }
    }
    Ok(())
}

#[ani_rs::native]
pub(crate) fn on_data_receive_progress(
    env: &AniEnv,
    this: HttpRequest,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    match task.callback {
        Some(ref mut task_callback) => {
            // Convert the async callback to a global reference
            task_callback.on_data_receive_progress =
                Some(callback.into_global_callback(env).unwrap());
        }
        None => {
            let mut new_task_callback = TaskCallback::new();
            new_task_callback.on_data_receive_progress =
                Some(callback.into_global_callback(env).unwrap());
            task.callback = Some(new_task_callback);
        }
    }
    Ok(())
}

#[ani_rs::native]
pub(crate) fn off_data_receive_progress(
    this: HttpRequest,
    _callback: Option<AniFnObject>,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    match task.request_task {
        Some(ref mut request_task) => {
            request_task.off_progress();
        }
        None => {
            // noting todo
        }
    }
    match task.callback {
        Some(ref mut task_callback) => {
            task_callback.on_data_receive_progress = None;
        }
        None => {
            // noting todo
        }
    }
    Ok(())
}

#[ani_rs::native]
pub(crate) fn on_data_send_progress(
    env: &AniEnv,
    this: HttpRequest,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    match task.callback {
        Some(ref mut task_callback) => {
            // Convert the async callback to a global reference
            task_callback.on_data_send_progress =
                Some(callback.into_global_callback(env).unwrap());
        }
        None => {
            let mut new_task_callback = TaskCallback::new();
            new_task_callback.on_data_send_progress =
                Some(callback.into_global_callback(env).unwrap());
            task.callback = Some(new_task_callback);
        }
    }
    Ok(())
}

#[ani_rs::native]
pub(crate) fn off_data_send_progress(
    this: HttpRequest,
    _callback: Option<AniFnObject>,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    match task.request_task {
        Some(ref mut request_task) => {
            request_task.off_progress();
        }
        None => {
            // noting todo
        }
    }
    match task.callback {
        Some(ref mut task_callback) => {
            task_callback.on_data_send_progress = None;
        }
        None => {
            // noting todo
        }
    }
    Ok(())
}

#[ani_rs::native]
pub(crate) fn once_headers_receive(
    env: &AniEnv,
    this: HttpRequest,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    match task.callback {
        Some(ref mut task_callback) => {
            // Convert the async callback to a global reference
            task_callback.on_headers_receive = Some(callback.into_global_callback(env).unwrap());
            task_callback.is_headers_once = true;
        }
        None => {
            let mut new_task_callback = TaskCallback::new();
            new_task_callback.on_headers_receive =
                Some(callback.into_global_callback(env).unwrap());
            new_task_callback.is_headers_once = true;
            task.callback = Some(new_task_callback);
        }
    }
    match task.request_task {
        Some(ref mut request_task) => {
            request_task.set_is_headers_once(true);
        }
        None => {
            // noting todo
        }
    }
    Ok(())
}

#[ani_rs::native]
pub(crate) fn flush(this: HttpResponseCache) -> Result<(), BusinessError> {
    flush_cache();
    Ok(())
}

#[ani_rs::native]
pub(crate) fn delete(this: HttpResponseCache) -> Result<(), BusinessError> {
    delete_cache();
    Ok(())
}
