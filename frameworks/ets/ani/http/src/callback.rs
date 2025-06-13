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

use ani_rs::{box_type::BoxI32, objects::GlobalRefAsyncCallback};
use netstack_rs::{request::RequestCallback, response::Response};

use crate::bridge::{
    DataReceiveProgressInfo, DataSendProgressInfo, HttpDataType, HttpResponse, PerformanceTiming,
    ResponseCode, ResponseCodeOutput,
};

pub struct TaskCallback {
    pub on_response: Option<GlobalRefAsyncCallback<(HttpResponse,)>>,
    pub on_header_receive: Option<GlobalRefAsyncCallback<(HashMap<String, String>,)>>,
    pub on_headers_receive: Option<GlobalRefAsyncCallback<(HashMap<String, String>,)>>,
    pub on_data_receive: Option<GlobalRefAsyncCallback<(Vec<u8>,)>>,

    pub on_data_end: Option<GlobalRefAsyncCallback<()>>,
    pub on_data_receive_progress: Option<GlobalRefAsyncCallback<(DataReceiveProgressInfo,)>>,
    pub on_data_send_progress: Option<GlobalRefAsyncCallback<(DataSendProgressInfo,)>>,
}

impl TaskCallback {
    pub fn new() -> Self {
        Self {
            on_response: None,
            on_header_receive: None,
            on_headers_receive: None,
            on_data_receive: None,

            on_data_end: None,
            on_data_receive_progress: None,
            on_data_send_progress: None,
        }
    }
}

impl RequestCallback for TaskCallback {
    fn on_success(&mut self, response: netstack_rs::response::Response) {
        let code = response.status() as i32;
        info!("request success: {:?}", code);
        if let Some(callback) = self.on_data_end.take() {
            info!("on_data_end callback set");
            callback.execute(None, ());
        }
    }

    fn on_fail(&mut self, error: netstack_rs::error::HttpClientError) {
        info!("request fail");
    }

    fn on_cancel(&mut self) {}

    fn on_data_receive(&mut self, data: &[u8], mut task: netstack_rs::task::RequestTask) {
        let headers = task.headers();
        if let Some(callback) = self.on_response.take() {
            let response = task.response();
            let code = response.status() as i32;
            let response = HttpResponse {
                result_type: HttpDataType::String,
                response_code: ResponseCodeOutput::I32(BoxI32::new(code)),
                header: response.headers(),
                cookies: String::new(),
                performance_timing: PerformanceTiming::new(),
            };
            info!("on_response callback set");
            callback.execute(None, (response,));
        }

        if let Some(callback) = self.on_header_receive.as_ref() {
            info!("on_header_receive callback set");
            callback.execute(None, (headers.clone(),));
        }
    }
}
