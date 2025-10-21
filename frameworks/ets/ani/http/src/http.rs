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
    ffi::CStr,
    sync::atomic::{AtomicBool, Ordering},
};

use ani_rs::{
    business_error::BusinessError,
    objects::{AniAsyncCallback, AniRef},
    AniEnv,
};
use netstack_rs::{error::HttpErrorCode, request::Request, task::RequestTask};

use crate::{
    bridge::{
        convert_to_business_error, Cleaner, HttpRequest, HttpRequestOptions, HttpResponseCache,
    },
    callback::TaskCallback,
};

pub struct Task {
    pub request_task: Option<RequestTask>,
    pub callback: Option<TaskCallback>,
    pub is_destroy: AtomicBool,
}

impl Task {
    pub fn new() -> Self {
        Self {
            request_task: None,
            callback: None,
            is_destroy: AtomicBool::new(false),
        }
    }
}

#[ani_rs::native]
pub fn create_http_ptr() -> Result<i64, BusinessError> {
    let request = Box::new(Task::new());
    let ptr = Box::into_raw(request);
    Ok(ptr as i64)
}

pub fn http_set_options(request: &mut Request<TaskCallback>, options: HttpRequestOptions) {
    if let Some(method) = options.method {
        request.method(method.to_str());
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
    if let Some(headers) = options.header {
        for (key, value) in &headers {
            request.header(key.as_str(), value.as_str());
        }
    }
    if let Some(protocol) = options.using_protocol {
        request.protocol(protocol.to_i32());
    }
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
        http_set_options(&mut request, opts);
    }

    let mut cb = task.callback.take().unwrap_or_else(TaskCallback::new);
    cb.on_response = Some(async_callback.clone().into_global_callback(env).unwrap());
    request.callback(cb);
    let mut request_task = request.build();
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
pub(crate) fn request_in_stream(
    this: HttpRequest,
    url: String,
    async_callback: AniAsyncCallback,
    options: Option<HttpRequestOptions>,
) -> Result<i32, BusinessError> {
    todo!()
}

#[ani_rs::native]
pub(crate) fn destroy(this: HttpRequest) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    if let Some(request_task) = task.request_task.take() {
        request_task.cancel();
    }
    task.is_destroy.store(true, Ordering::Relaxed);
    Ok(())
}

#[ani_rs::native]
pub(crate) fn clean_http_request(this: Cleaner) -> Result<(), BusinessError> {
    unsafe {
        let _ = Box::from_raw(this.native_ptr as *mut Task);
    };
    Ok(())
}

#[ani_rs::native]
pub(crate) fn clean_http_cache(this: Cleaner) -> Result<(), BusinessError> {
    todo!()
}

#[ani_rs::native]
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

#[ani_rs::native]
pub(crate) fn off_header_receive(
    this: HttpRequest,
    async_callback: AniAsyncCallback,
) -> Result<(), BusinessError> {
    todo!()
}

#[ani_rs::native]
pub(crate) fn on_headers_receive(
    env: &AniEnv,
    this: HttpRequest,
    async_callback: AniAsyncCallback,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    match task.callback {
        Some(ref mut callback) => {
            // Convert the async callback to a global reference
            callback.on_headers_receive = Some(async_callback.into_global_callback(env).unwrap());
        }
        None => {
            let mut task_callback = TaskCallback::new();
            task_callback.on_headers_receive =
                Some(async_callback.into_global_callback(env).unwrap());
            task.callback = Some(task_callback);
        }
    }
    Ok(())
}

#[ani_rs::native]
pub(crate) fn off_headers_receive(
    this: HttpRequest,
    async_callback: AniAsyncCallback,
) -> Result<(), BusinessError> {
    todo!()
}

#[ani_rs::native]
pub(crate) fn on_data_receive(
    env: &AniEnv,
    this: HttpRequest,
    async_callback: AniAsyncCallback,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    match task.callback {
        Some(ref mut callback) => {
            // Convert the async callback to a global reference
            callback.on_data_receive = Some(async_callback.into_global_callback(env).unwrap());
        }
        None => {
            let mut task_callback = TaskCallback::new();
            task_callback.on_data_receive = Some(async_callback.into_global_callback(env).unwrap());
            task.callback = Some(task_callback);
        }
    }
    Ok(())
}

#[ani_rs::native]
pub(crate) fn off_data_receive(
    this: HttpRequest,
    async_callback: AniAsyncCallback,
) -> Result<(), BusinessError> {
    todo!()
}

#[ani_rs::native]
pub(crate) fn on_data_end(
    env: &AniEnv,
    this: HttpRequest,
    async_callback: AniAsyncCallback,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    match task.callback {
        Some(ref mut callback) => {
            // Convert the async callback to a global reference
            callback.on_data_end = Some(async_callback.into_global_callback(env).unwrap());
        }
        None => {
            let mut task_callback = TaskCallback::new();
            task_callback.on_data_end = Some(async_callback.into_global_callback(env).unwrap());
            task.callback = Some(task_callback);
        }
    }
    Ok(())
}

#[ani_rs::native]
pub(crate) fn off_data_end(
    env: &AniEnv,
    this: HttpRequest,
    async_callback: AniAsyncCallback,
) -> Result<(), BusinessError> {
    todo!()
}

#[ani_rs::native]
pub(crate) fn on_data_receive_progress(
    env: &AniEnv,
    this: HttpRequest,
    async_callback: AniAsyncCallback,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    match task.callback {
        Some(ref mut callback) => {
            // Convert the async callback to a global reference
            callback.on_data_receive_progress =
                Some(async_callback.into_global_callback(env).unwrap());
        }
        None => {
            let mut task_callback = TaskCallback::new();
            task_callback.on_data_receive_progress =
                Some(async_callback.into_global_callback(env).unwrap());
            task.callback = Some(task_callback);
        }
    }
    Ok(())
}

#[ani_rs::native]
pub(crate) fn off_data_receive_progress(
    this: HttpRequest,
    async_callback: AniAsyncCallback,
) -> Result<(), BusinessError> {
    todo!()
}

#[ani_rs::native]
pub(crate) fn on_data_send_progress(
    env: &AniEnv,
    this: HttpRequest,
    async_callback: AniAsyncCallback,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    match task.callback {
        Some(ref mut callback) => {
            // Convert the async callback to a global reference
            callback.on_data_send_progress =
                Some(async_callback.into_global_callback(env).unwrap());
        }
        None => {
            let mut task_callback = TaskCallback::new();
            task_callback.on_data_send_progress =
                Some(async_callback.into_global_callback(env).unwrap());
            task.callback = Some(task_callback);
        }
    }
    Ok(())
}

#[ani_rs::native]
pub(crate) fn off_data_send_progress(
    this: HttpRequest,
    async_callback: AniAsyncCallback,
) -> Result<(), BusinessError> {
    todo!()
}

#[ani_rs::native]
pub(crate) fn once(
    this: HttpRequest,
    ty: String,
    async_callback: AniAsyncCallback,
) -> Result<(), BusinessError> {
    todo!()
}

#[ani_rs::native]
pub(crate) fn flush(this: HttpResponseCache) -> Result<(), BusinessError> {
    todo!()
}

#[ani_rs::native]
pub(crate) fn delete(this: HttpResponseCache) -> Result<(), BusinessError> {
    todo!()
}
