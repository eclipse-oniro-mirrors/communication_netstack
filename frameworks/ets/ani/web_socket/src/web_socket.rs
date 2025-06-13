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

use core::str;
use std::{collections::HashMap, ffi::CStr};

use ani_rs::{business_error::BusinessError, objects::AniRef, AniEnv};
use serde::{Deserialize, Serialize};

use crate::{
    bridge::{self, Cleaner},
    wrapper::WebSocket,
};

#[ani_rs::native]
pub(crate) fn web_socket_clean(this: Cleaner) -> Result<(), BusinessError> {
    let _ = unsafe { Box::from_raw(this.native_ptr as *mut WebSocket) };
    Ok(())
}

#[ani_rs::native]
pub fn create_web_socket<'local>(env: &AniEnv<'local>) -> Result<AniRef<'local>, BusinessError> {
    info!("Creating WebSocket instance");
    static WEB_SOCKET_CLASS: &CStr = unsafe {
        CStr::from_bytes_with_nul_unchecked(b"L@ohos/net/webSocket/webSocket/WebSocketInner;\0")
    };
    static CTOR_SIGNATURE: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"J:V\0") };
    let web_socket = Box::new(WebSocket::new());
    let ptr = Box::into_raw(web_socket);
    let class = env.find_class(WEB_SOCKET_CLASS).unwrap();
    let obj = env
        .new_object_with_signature(&class, CTOR_SIGNATURE, (ptr as i64,))
        .unwrap();
    Ok(obj.into())
}

#[ani_rs::native]
pub(crate) fn connect_sync(
    this: bridge::WebSocket,
    url: String,
    options: Option<bridge::WebSocketRequestOptions>,
) -> Result<bool, BusinessError> {
    info!("Connecting to WebSocket at URL: {}", url);

    let web_socket = unsafe { &mut *(this.native_ptr as *mut WebSocket) };
    let mut headers = HashMap::new();
    let (mut ca_path, mut client_cert, mut protocol) = (None, None, None);

    if let Some(options) = options {
        if let Some(header) = options.header {
            headers = header;
        }
        if let Some(path) = options.ca_path {
            ca_path = Some(path);
        }
        if let Some(cert) = options.client_cert {
            client_cert = Some(cert);
        }
        if let Some(p) = options.protocol {
            protocol = Some(p);
        }
    }
    web_socket
        .connect(&url, headers, ca_path, client_cert, protocol)
        .map(|_| true)
        .map_err(|e| BusinessError::new(e, format!("Failed to connect")))
}

#[derive(Serialize, Deserialize)]
pub(crate) enum Data<'a> {
    S(String),
    #[serde(borrow)]
    ArrayBuffer(&'a [u8]),
}

#[ani_rs::native]
pub(crate) fn send_sync(this: bridge::WebSocket, data: Data) -> Result<bool, BusinessError> {
    let web_socket = unsafe { &mut *(this.native_ptr as *mut WebSocket) };
    let s = match data {
        Data::S(s) => s,
        Data::ArrayBuffer(arr) => String::from_utf8_lossy(arr).to_string(),
    };
    web_socket
        .send(&s)
        .map(|_| true)
        .map_err(|e| BusinessError::new(e, format!("Failed to send data: {}", s)))
}

#[ani_rs::native]
pub(crate) fn close_sync(
    this: bridge::WebSocket,
    options: Option<bridge::WebSocketCloseOptions>,
) -> Result<bool, BusinessError> {
    let web_socket = unsafe { &mut *(this.native_ptr as *mut WebSocket) };

    let code = options.as_ref().and_then(|opt| opt.code).unwrap_or(0) as u32;
    let reason = options
        .as_ref()
        .and_then(|opt| opt.reason.as_ref())
        .map(|s| s.as_str())
        .unwrap_or("");

    web_socket
        .close(code as u32, &reason)
        .map(|_| true)
        .map_err(|e| BusinessError::new(e, format!("Failed to close: {}", reason)))
}
