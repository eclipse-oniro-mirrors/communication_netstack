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

pub struct WebSocket {
    client: cxx::UniquePtr<ffi::WebSocketClient>,
}

impl WebSocket {
    pub fn new() -> Self {
        let client = ffi::CreateWebSocket();
        WebSocket { client }
    }

    pub fn connect(&mut self, url: &str, headers: HashMap<String, String>) -> Result<(), i32> {
        let options = ffi::ConnectOptions {
            headers: headers
                .iter()
                .map(|(k, v)| [k.as_str(), v.as_str()])
                .flatten()
                .collect(),
        };
        let ret = ffi::Connect(self.client.pin_mut(), url, options);
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }

    pub fn send(&mut self, data: &str) -> Result<(), i32> {
        let ret = ffi::Send(self.client.pin_mut(), data);
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }

    pub fn close(&mut self, code: u32, reason: &str) -> Result<(), i32> {
        let options = ffi::CloseOption { code, reason };
        let ret = ffi::Close(self.client.pin_mut(), options);
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }
}

#[cxx::bridge(namespace = "OHOS::NetStackAni")]
mod ffi {

    pub struct ConnectOptions<'a> {
        headers: Vec<&'a str>,
    }

    struct CloseOption<'a> {
        code: u32,
        reason: &'a str,
    }

    unsafe extern "C++" {
        include!("websocket_ani.h");

        #[namespace = "OHOS::NetStack::WebSocketClient"]
        type WebSocketClient;

        fn CreateWebSocket() -> UniquePtr<WebSocketClient>;

        fn Connect(client: Pin<&mut WebSocketClient>, url: &str, options: ConnectOptions) -> i32;

        fn Send(client: Pin<&mut WebSocketClient>, data: &str) -> i32;

        fn Close(client: Pin<&mut WebSocketClient>, options: CloseOption) -> i32;
    }
}
