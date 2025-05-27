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

use std::{collections::HashMap, sync::Mutex};

use ani_rs::objects::GlobalRefCallback;
use netstack_rs::request::RequestCallback;

use crate::bridge::{DataReceiveProgressInfo, DataSendProgressInfo, HttpResponse};

pub struct TaskCallback {
    pub on_response: Mutex<Option<GlobalRefCallback<(HttpResponse,)>>>,
    pub on_header_receive: Mutex<Option<GlobalRefCallback<(HashMap<String, String>,)>>>,
    pub on_headers_receive: Mutex<Option<GlobalRefCallback<(HashMap<String, String>,)>>>,
    pub on_data_receive: Mutex<Option<GlobalRefCallback<(Vec<u8>,)>>>,

    pub on_data_end: Mutex<Option<GlobalRefCallback<()>>>,
    pub on_data_receive_progress: Mutex<Option<GlobalRefCallback<(DataReceiveProgressInfo,)>>>,
    pub on_data_send_progress: Mutex<Option<GlobalRefCallback<(DataSendProgressInfo,)>>>,
}

impl TaskCallback {
    pub fn new() -> Self {
        Self {
            on_response: Mutex::new(None),
            on_header_receive: Mutex::new(None),
            on_headers_receive: Mutex::new(None),
            on_data_receive: Mutex::new(None),

            on_data_end: Mutex::new(None),
            on_data_receive_progress: Mutex::new(None),
            on_data_send_progress: Mutex::new(None),
        }
    }
}

impl TaskCallback {
    pub fn set_on_response(&self, callback: GlobalRefCallback<(HttpResponse,)>) {
        *self.on_response.lock().unwrap() = Some(callback);
    }

    pub fn set_on_header_receive(&self, callback: GlobalRefCallback<(HashMap<String, String>,)>) {
        *self.on_header_receive.lock().unwrap() = Some(callback);
    }

    pub fn set_on_headers_receive(&self, callback: GlobalRefCallback<(HashMap<String, String>,)>) {
        *self.on_headers_receive.lock().unwrap() = Some(callback);
    }

    pub fn set_on_data_receive(&self, callback: GlobalRefCallback<(Vec<u8>,)>) {
        *self.on_data_receive.lock().unwrap() = Some(callback);
    }

    pub fn set_on_data_end(&self, callback: GlobalRefCallback<()>) {
        *self.on_data_end.lock().unwrap() = Some(callback);
    }

    pub fn set_on_data_receive_progress(
        &self,
        callback: GlobalRefCallback<(DataReceiveProgressInfo,)>,
    ) {
        *self.on_data_receive_progress.lock().unwrap() = Some(callback);
    }

    pub fn set_on_data_send_progress(&self, callback: GlobalRefCallback<(DataSendProgressInfo,)>) {
        *self.on_data_send_progress.lock().unwrap() = Some(callback);
    }
}

impl RequestCallback for TaskCallback {
    fn on_success(&mut self, response: netstack_rs::response::Response) {
        panic!("Request succeeded with response");
    }

    fn on_fail(&mut self, error: netstack_rs::error::HttpClientError) {
        panic!("Request failed with error");
    }

    fn on_cancel(&mut self) {}

    fn on_data_receive(&mut self, data: &[u8], task: netstack_rs::task::RequestTask) {}
}
