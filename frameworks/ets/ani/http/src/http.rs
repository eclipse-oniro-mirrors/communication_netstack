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

use std::{ffi::CStr, sync::Arc};

use ani_rs::{
    business_error::BusinessError,
    callback::Callback,
    objects::{AniFnObject, AniRef},
    AniEnv,
};
use netstack_rs::{request::Request, task::RequestTask};

use crate::{
    bridge::{Cleaner, HttpRequest, HttpRequestOptions, HttpResponse, HttpResponseCache},
    callback::TaskCallback,
};

static HTTP_REQUEST_CLASS: &CStr =
    unsafe { CStr::from_bytes_with_nul_unchecked(b"L@ohos/net/http/http/HttpRequestInner;\0") };
static CTOR_SIGNATURE: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"J:V\0") };

pub struct Task {
    pub request_task: Option<RequestTask>,
    pub callback: Arc<TaskCallback>,
}

impl Task {
    pub fn new() -> Self {
        Self {
            request_task: None,
            callback: Arc::new(TaskCallback::new()),
        }
    }
}

pub(crate) fn create_http<'local>(env: &AniEnv<'local>) -> Result<AniRef<'local>, BusinessError> {
    let request = Box::new(Task::new());

    let ptr = Box::into_raw(request);
    let class = env.find_class(HTTP_REQUEST_CLASS).unwrap();
    let obj = env
        .new_object_with_signature(&class, CTOR_SIGNATURE, (ptr as i64,))
        .unwrap();
    Ok(obj.into())
}

#[ani_rs::native]
pub(crate) fn request(
    env: &AniEnv,
    this: HttpRequest,
    url: String,
    callback: AniFnObject,
    options: Option<HttpRequestOptions>,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    let mut request = Request::<TaskCallback>::new();
    request.url(url.as_str());
    *task.callback.on_response.lock().unwrap() =
        Some(Callback::new(callback).into_global(env).unwrap());

    let mut request_task = request.build();
    request_task.start();
    task.request_task = Some(request_task);
    Ok(())
}

#[ani_rs::native]
pub(crate) fn request_in_stream(
    this: HttpRequest,
    url: String,
    callback: AniFnObject,
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
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    let callback = Callback::new(callback).into_global(env).unwrap();
    task.callback.set_on_header_receive(callback);
    Ok(())
}

#[ani_rs::native]
pub(crate) fn off_header_receive(
    this: HttpRequest,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    todo!()
}

#[ani_rs::native]
pub(crate) fn on_headers_receive(
    env: &AniEnv,
    this: HttpRequest,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    let callback = Callback::new(callback).into_global(env).unwrap();
    task.callback.set_on_headers_receive(callback);
    Ok(())
}

#[ani_rs::native]
pub(crate) fn off_headers_receive(
    this: HttpRequest,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    todo!()
}

#[ani_rs::native]
pub(crate) fn on_data_receive(
    env: &AniEnv,
    this: HttpRequest,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    let callback = Callback::new(callback).into_global(env).unwrap();
    task.callback.set_on_data_receive(callback);
    Ok(())
}

#[ani_rs::native]
pub(crate) fn off_data_receive(
    this: HttpRequest,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    todo!()
}

#[ani_rs::native]
pub(crate) fn on_data_end(
    env: &AniEnv,
    this: HttpRequest,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    let callback = Callback::new(callback).into_global(env).unwrap();
    task.callback.set_on_data_end(callback);
    Ok(())
}

#[ani_rs::native]
pub(crate) fn off_data_end(
    env: &AniEnv,
    this: HttpRequest,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    todo!()
}

#[ani_rs::native]
pub(crate) fn on_data_receive_progress(
    env: &AniEnv,
    this: HttpRequest,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    let callback = Callback::new(callback).into_global(env).unwrap();
    task.callback.set_on_data_receive_progress(callback);
    Ok(())
}

#[ani_rs::native]
pub(crate) fn off_data_receive_progress(
    this: HttpRequest,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    todo!()
}

#[ani_rs::native]
pub(crate) fn on_data_send_progress(
    env: &AniEnv,
    this: HttpRequest,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    let callback = Callback::new(callback).into_global(env).unwrap();
    task.callback.set_on_data_send_progress(callback);
    Ok(())
}

#[ani_rs::native]
pub(crate) fn off_data_send_progress(
    this: HttpRequest,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    todo!()
}

#[ani_rs::native]
pub(crate) fn once(
    this: HttpRequest,
    ty: String,
    callback: AniFnObject,
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
