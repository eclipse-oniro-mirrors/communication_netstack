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

use ani_rs::business_error::BusinessError;
use serde::Deserialize;

#[ani_rs::ani]
pub struct Cleaner {
    pub native_ptr: i64,
}

#[ani_rs::ani]
pub struct WebSocket {
    pub native_ptr: i64,
}

#[ani_rs::ani(path = "L@ohos/net/connection/connection/HttpProxyInner")]
pub struct HttpProxy {
    pub host: String,

    pub port: i32,

    pub username: Option<String>,

    pub password: Option<String>,

    pub exclusion_list: Vec<String>,
}

#[derive(Deserialize)]
pub enum ProxyConfiguration {
    S(String),
    #[serde(rename = "L@ohos/net/connection/connection/HttpProxyInner;")]
    Proxy(HttpProxy),
}

#[ani_rs::ani]
pub struct WebSocketRequestOptions {
    pub header: Option<HashMap<String, String>>,

    pub ca_path: Option<String>,

    pub client_cert: Option<ClientCert>,

    pub proxy: Option<ProxyConfiguration>,
    pub protocol: Option<String>,
}

#[ani_rs::ani]
pub struct ClientCert {
    pub cert_path: String,

    pub key_path: String,

    pub key_password: Option<String>,
}

#[ani_rs::ani]
pub struct CloseResult {
    pub code: i32,
    pub reason: String,
}

#[ani_rs::ani]
pub struct WebSocketCloseOptions {
    pub code: Option<i32>,
    pub reason: Option<String>,
}

pub const fn convert_to_business_error(code: i32) -> BusinessError {
    match code {
        1004 => BusinessError::new_static(2302001, "Websocket Parse url error."),
        1020 => BusinessError::PERMISSION,
        _ => BusinessError::new_static(code, "Unknown error"),
    }
}