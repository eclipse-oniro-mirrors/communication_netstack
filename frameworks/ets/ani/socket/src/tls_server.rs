// Copyright (C) 2026 Huawei Device Co., Ltd.
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

use std::ffi::CStr;
use std::mem;
use std::sync::Mutex;
use ani_rs::{
    business_error::BusinessError,
    objects::{AniFnObject, AniAsyncCallback, AniErrorCallback, AniRef, GlobalRefCallback, GlobalRefAsyncCallback, GlobalRefErrorCallback},
    AniEnv, AniVm,
};

use crate::{
    bridge,
    wrapper::TlsServerWrapper,
    tls_connect::construct_tls_connect_instance,
};

#[ani_rs::native]
pub fn construct_tls_server_instance<'local>(env: &AniEnv<'local>) -> Result<AniRef<'local>, BusinessError> {
    static TLS_SERVER_CLASS: &CStr = unsafe {
        CStr::from_bytes_with_nul_unchecked(b"@ohos.net.socket.socket.TLSSocketServerInner\0")
    };
    static CTOR_SIGNATURE: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"l:\0") };
    let wrapper = TlsServerWrapper::new();
    let ptr = Box::into_raw(Box::new(Mutex::new(wrapper))) as i64;
    let class = env.find_class(TLS_SERVER_CLASS).unwrap();
    let obj = env
        .new_object_with_signature(&class, CTOR_SIGNATURE, (ptr,))
        .unwrap();
    Ok(obj.into())
}

#[ani_rs::native]
pub(crate) fn destroy_tls_server_instance(mut ptr: i64) -> Result<(), BusinessError> {
    if ptr == 0 {
        return Ok(());
    }
    let _ = unsafe { Box::from_raw(ptr as *mut Mutex<TlsServerWrapper>) };
    ptr = 0;
    Ok(())
}


#[ani_rs::native]
pub(crate) fn listen_sync(this: bridge::TLSSocketServer, options: bridge::TLSConnectOptions) -> Result<(), BusinessError> {
    let mutex = unsafe { &*(this.native_ptr as *const Mutex<TlsServerWrapper>) };
    let mut socket = mutex.lock().unwrap();
    socket.listen(&options).map_err(|e| bridge::convert_to_business_error(e))
}

#[ani_rs::native]
pub(crate) fn get_state_sync(this: bridge::TLSSocketServer) -> Result<bridge::SocketStateBase, BusinessError> {    
    let mutex = unsafe { &*(this.native_ptr as *const Mutex<TlsServerWrapper>) };
    let mut socket = mutex.lock().unwrap();
    socket.get_state().map_err(|e| bridge::convert_to_business_error(e))
}

#[ani_rs::native]
pub(crate) fn get_socket_fd_sync(this: bridge::TLSSocketServer) -> Result<i32, BusinessError> {
    let mutex = unsafe { &*(this.native_ptr as *const Mutex<TlsServerWrapper>) };
    let mut socket = mutex.lock().unwrap();
    socket.get_socket_fd().map_err(|e| bridge::convert_to_business_error(e))
}

#[ani_rs::native]
pub(crate) fn close_sync(this: bridge::TLSSocketServer) -> Result<(), BusinessError> {
    let mutex = unsafe { &*(this.native_ptr as *const Mutex<TlsServerWrapper>) };
    let mut socket = mutex.lock().unwrap();
    socket.close().map_err(|e| bridge::convert_to_business_error(e))
}

#[ani_rs::native]
pub(crate) fn set_extra_options_sync(this: bridge::TLSSocketServer, options: bridge::TCPExtraOptions) -> Result<(), BusinessError> {
    let mutex = unsafe { &*(this.native_ptr as *const Mutex<TlsServerWrapper>) };
    let mut socket = mutex.lock().unwrap();
    socket.set_extra_options(&options).map_err(|e| bridge::convert_to_business_error(e))
}

#[ani_rs::native]
pub(crate) fn get_certificate_sync(this: bridge::TLSSocketServer) -> Result<bridge::X509CertRawData, BusinessError> {
    let mutex = unsafe { &*(this.native_ptr as *const Mutex<TlsServerWrapper>) };
    let mut socket = mutex.lock().unwrap();
    socket.get_certificate().map_err(|e| bridge::convert_to_business_error(e))
}

#[ani_rs::native]
pub(crate) fn get_protocol_sync(this: bridge::TLSSocketServer) -> Result<String, BusinessError> {
    let mutex = unsafe { &*(this.native_ptr as *const Mutex<TlsServerWrapper>) };
    let mut socket = mutex.lock().unwrap();
    socket.get_protocol().map_err(|e| bridge::convert_to_business_error(e))
}

#[ani_rs::native]
pub(crate) fn get_local_address_sync(this: bridge::TLSSocketServer) -> Result<bridge::NetAddress, BusinessError> {
    let mutex = unsafe { &*(this.native_ptr as *const Mutex<TlsServerWrapper>) };
    let mut socket = mutex.lock().unwrap();
    socket.get_local_address().map_err(|e| bridge::convert_to_business_error(e))
}

#[ani_rs::native]
pub(crate) fn on_connect_inner(env: &AniEnv, this: bridge::TLSSocketServer, callback: AniFnObject) -> Result<(), BusinessError> {
    let mutex_ptr = this.native_ptr as *mut Mutex<TlsServerWrapper>;
    let mutex = unsafe { &*(mutex_ptr as *const Mutex<TlsServerWrapper>) };
    let mut socket = mutex.lock().unwrap();
    socket.on_connect = Some(callback.into_global_callback(env).unwrap());
    socket.on_connect_native(mutex_ptr).map_err(|e| bridge::convert_to_business_error(e))?;
    Ok(())
}

#[ani_rs::native]
pub(crate) fn off_connect_inner(env: &AniEnv, this: bridge::TLSSocketServer, callback: AniFnObject) -> Result<(), BusinessError> {
    let mutex = unsafe { &*(this.native_ptr as *const Mutex<TlsServerWrapper>) };
    let mut socket = mutex.lock().unwrap();
    socket.on_connect = None;
    socket.off_connect_native().map_err(|e| bridge::convert_to_business_error(e))?;
    Ok(())
}

#[ani_rs::native]
pub(crate) fn on_error_inner(env: &AniEnv, this: bridge::TLSSocketServer, error_callback: AniErrorCallback) -> Result<(), BusinessError> {
    let mutex = unsafe { &*(this.native_ptr as *const Mutex<TlsServerWrapper>) };
    let mut socket = mutex.lock().unwrap();
    socket.on_error = Some(error_callback.into_global_callback(env).unwrap());
    socket.on_error_native().map_err(|e| bridge::convert_to_business_error(e))?;
    Ok(())
}

#[ani_rs::native]
pub(crate) fn off_error_inner(env: &AniEnv, this: bridge::TLSSocketServer, error_callback: AniErrorCallback) -> Result<(), BusinessError> {
    let mutex = unsafe { &*(this.native_ptr as *const Mutex<TlsServerWrapper>) };
    let mut socket = mutex.lock().unwrap();
    socket.on_error = None;
    socket.off_error_native().map_err(|e| bridge::convert_to_business_error(e))?;
    Ok(())
}

pub struct TlsServerConnectBox {
    pub on_connect: Option<GlobalRefCallback<(AniRef<'static>,)>>,
    server_mutex_ptr: *mut Mutex<TlsServerWrapper>,
}

impl TlsServerConnectBox {
    pub fn new(server_wrapper: &mut TlsServerWrapper, mutex_ptr: *mut Mutex<TlsServerWrapper>) -> Box<Self> {
        Box::new(TlsServerConnectBox {
            on_connect: server_wrapper.on_connect.take(),
            server_mutex_ptr: mutex_ptr,
        })
    }

    pub fn on_connect(&self, client_id: i32) -> i32 {
        let vm = AniVm::get_instance();
        let env = match vm.get_env().or_else(|_| vm.attach_current_thread()) {
            Ok(env) => env,
            Err(e) => {
                error!("Failed to get VM environment: {}", e);
                return -1;
            }
        };

        let conn_ref = {
            let mutex = unsafe { &*(self.server_mutex_ptr as *const Mutex<TlsServerWrapper>) };
            let mut wrapper = match mutex.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    error!("Mutex poisoned, recovering...");
                    poisoned.into_inner()
                }
            };
            
            match construct_tls_connect_instance(&env, &mut *wrapper, client_id) {
                Ok(conn) => conn,
                Err(e) => {
                    error!("Failed to construct instance: code={}, msg={}", e.code(), e.message());
                    return -1;
                }
            }
        };

        if let Some(callback) = &self.on_connect {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                callback.execute_spawn_thread((conn_ref,));
            }));
            
            match result {
                Ok(_) => 0,
                Err(panic_info) => {
                    error!("Callback panicked in on_connect: {:#?}", panic_info);
                    return -1
                }
            }
        } else {
            error!("on_connect callback not set");
            return -1
        }
    }
}

pub struct TlsServerErrorBox {
    pub on_error: Option<GlobalRefErrorCallback>,
}

impl TlsServerErrorBox {
    pub fn new(server_wrapper: &mut TlsServerWrapper) -> Box<Self> {
        Box::new(TlsServerErrorBox {
            on_error: server_wrapper.on_error.take(),
        })
    }

    pub fn on_error(&self, error_code: i32, error_string: String) -> i32 {
        if let Some(callback) = &self.on_error {
            let business_error = BusinessError::new(error_code, error_string);
            callback.execute_spawn_thread(business_error);
            return 0;
        } else {
            return -1;
        }
    }
}