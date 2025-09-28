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

use ani_rs::{business_error::BusinessError, objects::GlobalRefAsyncCallback};
use netstack_rs::{error::HttpErrorCode, request::RequestCallback};

use crate::bridge::{
    convert_to_business_error, DataReceiveProgressInfo, DataSendProgressInfo, HttpDataType,
    HttpResponse, PerformanceTiming, ResponseCodeOutput,
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
        if let Some(callback) = self.on_response.take() {
            let code = response.status() as i32;
            let response = HttpResponse {
                result_type: HttpDataType::String,
                response_code: ResponseCodeOutput::I32(code),
                header: response.headers(),
                cookies: response.cookies(),
                performance_timing: PerformanceTiming::from(response.performance_timing()),
                result: response.get_result(),
            };
            callback.execute(None, (response,));
        }

        if let Some(callback) = self.on_data_end.take() {
            callback.execute(None, ());
        }
    }

    fn on_fail(
        &mut self,
        response: netstack_rs::response::Response,
        error: netstack_rs::error::HttpClientError,
    ) {
        let code = response.status() as i32;
        error!("OnFiled. response_code = {}, error = {:?}", code, error);
        if let Some(callback) = self.on_response.take() {
            let business_error = convert_to_business_error(&error);
            let response = HttpResponse {
                result_type: HttpDataType::String,
                response_code: ResponseCodeOutput::I32(code),
                header: HashMap::new(),
                cookies: String::new(),
                performance_timing: PerformanceTiming::new(),
                result: String::new(),
            };
            callback.execute(Some(business_error), (response,));
        }
        if let Some(callback) = self.on_data_end.take() {
            callback.execute(None, ());
        }
    }

    fn on_cancel(&mut self, response: netstack_rs::response::Response) {
        let code = response.status() as i32;
        if let Some(callback) = self.on_response.take() {
            let business_error = BusinessError::new(
                HttpErrorCode::HttpWriteError as i32,
                "request canceled".to_string(),
            );
            let response = HttpResponse {
                result_type: HttpDataType::String,
                response_code: ResponseCodeOutput::I32(code),
                header: HashMap::new(),
                cookies: String::new(),
                performance_timing: PerformanceTiming::new(),
                result: String::new(),
            };
            callback.execute(Some(business_error), (response,));
        }
    }

    fn on_data_receive(&mut self, data: &[u8], mut task: netstack_rs::task::RequestTask) {
        let headers = task.headers();
        if let Some(callback) = self.on_header_receive.as_ref() {
            info!("on_header_receive callback set");
            callback.execute(None, (headers.clone(),));
        }
    }
}
