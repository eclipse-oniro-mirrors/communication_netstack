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

use std::sync::Mutex;
use ani_rs::{
    business_error::BusinessError,
    typed_array::{ArrayBuffer, Uint8Array},
    objects::{GlobalRefCallback, GlobalRefAsyncCallback, GlobalRefErrorCallback, AniRef},
    AniEnv,
};
use crate::udp_socket::{UdpSocketMessageBox, UdpSocketListeningBox, UdpSocketCloseBox, UdpSocketErrorBox};
use crate::local_socket::{LocalSocketMessageBox, LocalSocketConnectBox, LocalSocketCloseBox, LocalSocketErrorBox};
use crate::local_socket_connection::{LocalSocketConnectionMessageBox, LocalSocketConnectionCloseBox, LocalSocketConnectionErrorBox};
use crate::local_socket_server::{LocalSocketServerConnectBox, LocalSocketServerErrorBox};
use crate::tcp_socket::{TcpSocketWrapper, TcpSocketMessageBox, TcpSocketConnectBox, TcpSocketCloseBox, TcpSocketErrorBox};
use crate::tcp_socket_connection::{TcpSocketConnectionMessageBox, TcpSocketConnectionCloseBox, TcpSocketConnectionErrorBox};
use crate::tcp_socket_server::{TcpSocketServerConnectBox, TcpSocketServerErrorBox};
use crate::tls_client::{TlsClientMessageBox, TlsClientConnectBox, TlsClientCloseBox, TlsClientErrorBox};
use crate::tls_server::{TlsServerConnectBox, TlsServerErrorBox};
use crate::tls_connect::{TlsConnectMessageBox, TlsConnectCloseBox, TlsConnectErrorBox};

use crate::bridge;
use crate::error::{SUCCESS, ERROR_INTERNAL};
use cxx::UniquePtr;

// ==================== TLS Socket Client Wrapper ====================
pub struct TlsClientWrapper {
    cpp_context: UniquePtr<ffi::TlsClientContext>,
    pub on_message: Option<GlobalRefCallback<(bridge::SocketMessageInfo,)>>,
    pub on_connect: Option<GlobalRefCallback<()>>,
    pub on_close: Option<GlobalRefCallback<()>>,
    pub on_error: Option<GlobalRefErrorCallback>,
}

impl TlsClientWrapper {
    pub fn new() -> Result<Self, i32> {
        let mut err = 0i32;
        let ctx = ffi::CreateTlsClientContext(&mut err);
        if err != 0 {
            return Err(err);
        }
        Ok(TlsClientWrapper {
            cpp_context: ctx,
            on_message: None,
            on_connect: None,
            on_close: None,
            on_error: None,
        })
    }

    pub fn new_from_tcp(tcp_wrapper: &mut TcpSocketWrapper) -> Result<Self, i32> {
        let mut err = 0i32;
        let ctx = ffi::CreateTlsClientContextFromTcpClientContext(tcp_wrapper.cpp_context.pin_mut(), &mut err);
        if err != 0 {
            return Err(err);
        }
        Ok(TlsClientWrapper {
            cpp_context: ctx,
            on_message: None,
            on_connect: None,
            on_close: None,
            on_error: None,
        })
    }

    pub fn bind(&mut self, address: &bridge::NetAddress) -> Result<(), i32> {
        let addr = ffi::FFINetAddress::from(address);
        let ret = ffi::TlsClientBind(self.cpp_context.pin_mut(), &addr);
        if ret != SUCCESS { return Err(ret); }
        Ok(())
    }

    pub fn connect(&mut self, options: &bridge::TLSConnectOptions) -> Result<(), i32> {
        let opts = ffi::FFITlsConnectOptions::from(options);
        let ret = ffi::TlsClientConnect(self.cpp_context.pin_mut(), &opts);
        if ret != SUCCESS { return Err(ret); }
        Ok(())
    }

    pub fn send(&mut self, options: &bridge::TCPSendOptions) -> Result<(), i32> {
        let opts = ffi::FFITcpSendOptions::from(options);
        let ret = ffi::TlsClientSend(self.cpp_context.pin_mut(), opts);
        if ret != SUCCESS { return Err(ret); }
        Ok(())
    }

    pub fn close(&mut self) -> Result<(), i32> {
        let ret = ffi::TlsClientClose(self.cpp_context.pin_mut());
        if ret != SUCCESS { return Err(ret); }
        Ok(())
    }

    pub fn get_state(&mut self) -> Result<bridge::SocketStateBase, i32> {
        let mut status = ffi::FFISocketStateBase {
            is_bound: false,
            is_close: false,
            is_connected: false,
        };
        let ret = ffi::TlsClientGetState(self.cpp_context.pin_mut(), &mut status);
        if ret != SUCCESS { return Err(ret); }
        Ok(bridge::SocketStateBase::from(&status))
    }

    pub fn get_remote_address(&mut self) -> Result<bridge::NetAddress, i32> {
        let mut addr = ffi::FFINetAddress {
            address: String::new(),
            has_family: false,
            family: 0,
            has_port: false,
            port: 0,
        };
        let ret = ffi::TlsClientGetRemoteAddress(self.cpp_context.pin_mut(), &mut addr);
        if ret != SUCCESS { return Err(ret); }
        Ok(bridge::NetAddress::from(&addr))
    }

    pub fn get_local_address(&mut self) -> Result<bridge::NetAddress, i32> {
        let mut addr = ffi::FFINetAddress {
            address: String::new(),
            has_family: false,
            family: 0,
            has_port: false,
            port: 0,
        };
        let ret = ffi::TlsClientGetLocalAddress(self.cpp_context.pin_mut(), &mut addr);
        if ret != SUCCESS { return Err(ret); }
        Ok(bridge::NetAddress::from(&addr))
    }

    pub fn get_socket_fd(&mut self) -> Result<i32, i32> {
        let mut fd = -1;
        let ret = ffi::TlsClientGetSocketFd(self.cpp_context.pin_mut(), &mut fd);
        if ret != SUCCESS { return Err(ret); }
        Ok(fd)
    }

    pub fn get_certificate(&mut self) -> Result<bridge::X509CertRawData, i32> {
        let mut cert = ffi::FFIX509CertRawData {
            data: Vec::new(),
            encoding_format: ffi::FFIEncodingFormat::FORMAT_DER,
        };
        let ret = ffi::TlsClientGetCertificate(self.cpp_context.pin_mut(), &mut cert);
        if ret != SUCCESS { return Err(ret); }
        Ok(bridge::X509CertRawData::from(&cert))
    }

    pub fn get_remote_certificate(&mut self) -> Result<bridge::X509CertRawData, i32> {
        let mut cert = ffi::FFIX509CertRawData {
            data: Vec::new(),
            encoding_format: ffi::FFIEncodingFormat::FORMAT_DER,
        };
        let ret = ffi::TlsClientGetRemoteCertificate(self.cpp_context.pin_mut(), &mut cert);
        if ret != SUCCESS { return Err(ret); }
        Ok(bridge::X509CertRawData::from(&cert))
    }

    pub fn get_protocol(&mut self) -> Result<String, i32> {
        let mut protocol = String::new();
        let ret = ffi::TlsClientGetProtocol(self.cpp_context.pin_mut(), &mut protocol);
        if ret != SUCCESS { return Err(ret); }
        Ok(protocol)
    }

    pub fn get_cipher_suite(&mut self) -> Result<Vec<String>, i32> {
        let mut cipher_suite = Vec::new();
        let ret = ffi::TlsClientGetCipherSuite(self.cpp_context.pin_mut(), &mut cipher_suite);
        if ret != SUCCESS { return Err(ret); }
        Ok(cipher_suite)
    }

    pub fn set_extra_options(&mut self, options: &bridge::TCPExtraOptions) -> Result<(), i32> {
        let opts = ffi::FFITcpExtraOptions::from(options);
        let ret = ffi::TlsClientSetExtraOptions(self.cpp_context.pin_mut(), &opts);
        if ret != SUCCESS { return Err(ret); }
        Ok(())
    }

    pub fn get_signature_algorithms(&mut self) -> Result<Vec<String>, i32> {
        let mut signature_algorithms = Vec::new();
        let ret = ffi::TlsClientGetSignatureAlgorithms(self.cpp_context.pin_mut(), &mut signature_algorithms);
        if ret != SUCCESS { return Err(ret); }
        Ok(signature_algorithms)
    }

    pub fn on_message_native(&mut self) -> Result<(), i32> {
        let mut callback_box = TlsClientMessageBox::new(self);
        let ret = ffi::TlsClientOnMessage(self.cpp_context.pin_mut(), callback_box);
        if ret != SUCCESS { return Err(ret); }
        Ok(())
    }
    
    pub fn on_connect_native(&mut self) -> Result<(), i32> {
        let mut callback_box = TlsClientConnectBox::new(self);
        let ret = ffi::TlsClientOnConnect(self.cpp_context.pin_mut(), callback_box);
        if ret != SUCCESS { return Err(ret); }
        Ok(())
    }

    pub fn on_close_native(&mut self) -> Result<(), i32> {
        let mut callback_box = TlsClientCloseBox::new(self);
        let ret = ffi::TlsClientOnClose(self.cpp_context.pin_mut(), callback_box);
        if ret != SUCCESS { return Err(ret); }
        Ok(())
    }

    pub fn on_error_native(&mut self) -> Result<(), i32> {
        let mut callback_box = TlsClientErrorBox::new(self);
        let ret = ffi::TlsClientOnError(self.cpp_context.pin_mut(), callback_box);
        if ret != SUCCESS { return Err(ret); }
        Ok(())
    }

    pub fn off_message_native(&mut self) -> Result<(), i32> {
        let ret = ffi::TlsClientOffMessage(self.cpp_context.pin_mut());
        if ret != SUCCESS { return Err(ret); }
        Ok(())
    }
    
    pub fn off_connect_native(&mut self) -> Result<(), i32> {
        let ret = ffi::TlsClientOffConnect(self.cpp_context.pin_mut());
        if ret != SUCCESS { return Err(ret); }
        Ok(())
    }
    
    pub fn off_close_native(&mut self) -> Result<(), i32> {
        let ret = ffi::TlsClientOffClose(self.cpp_context.pin_mut());
        if ret != SUCCESS { return Err(ret); }
        Ok(())
    }

    pub fn off_error_native(&mut self) -> Result<(), i32> {
        let ret = ffi::TlsClientOffError(self.cpp_context.pin_mut());
        if ret != SUCCESS { return Err(ret); }
        Ok(())
    }
}

// ==================== TLS Socket Server Wrapper ====================
pub struct TlsServerWrapper {
    cpp_context: UniquePtr<ffi::TlsServerContext>,
    pub on_connect: Option<GlobalRefCallback<(AniRef<'static>,)>>,
    pub on_error: Option<GlobalRefErrorCallback>,
}

impl TlsServerWrapper {
    pub fn new() -> Self {
        TlsServerWrapper {
            cpp_context: ffi::CreateTlsServerContext(),
            on_connect: None,
            on_error: None,
        }
    }

    pub fn listen(&mut self, options: &bridge::TLSConnectOptions) -> Result<(), i32> {
        let opts = ffi::FFITlsConnectOptions::from(options);
        let ret = ffi::TlsServerListen(self.cpp_context.pin_mut(), &opts);
        if ret != SUCCESS { return Err(ret); }
        Ok(())
    }

    pub fn get_state(&mut self) -> Result<bridge::SocketStateBase, i32> {
        let mut status = ffi::FFISocketStateBase {
            is_bound: false,
            is_close: false,
            is_connected: false,
        };
        let ret = ffi::TlsServerGetState(self.cpp_context.pin_mut(), &mut status);
        if ret != SUCCESS { return Err(ret); }
        Ok(bridge::SocketStateBase::from(&status))
    }

    pub fn get_socket_fd(&mut self) -> Result<i32, i32> {
        let mut fd = -1;
        let ret = ffi::TlsServerGetSocketFd(self.cpp_context.pin_mut(), &mut fd);
        if ret != SUCCESS { return Err(ret); }
        Ok(fd)
    }

    pub fn close(&mut self) -> Result<(), i32> {
        let ret = ffi::TlsServerClose(self.cpp_context.pin_mut());
        if ret != SUCCESS { return Err(ret); }
        Ok(())
    }

    pub fn set_extra_options(&mut self, options: &bridge::TCPExtraOptions) -> Result<(), i32> {
        let opts = ffi::FFITcpExtraOptions::from(options);
        let ret = ffi::TlsServerSetExtraOptions(self.cpp_context.pin_mut(), &opts);
        if ret != SUCCESS { return Err(ret); }
        Ok(())
    }

    pub fn get_certificate(&mut self) -> Result<bridge::X509CertRawData, i32> {
        let mut cert = ffi::FFIX509CertRawData {
            data: Vec::new(),
            encoding_format: ffi::FFIEncodingFormat::FORMAT_DER,
        };
        let ret = ffi::TlsServerGetCertificate(self.cpp_context.pin_mut(), &mut cert);
        if ret != SUCCESS { return Err(ret); }
        Ok(bridge::X509CertRawData::from(&cert))
    }

    pub fn get_protocol(&mut self) -> Result<String, i32> {
        let mut protocol = String::new();
        let ret = ffi::TlsServerGetProtocol(self.cpp_context.pin_mut(), &mut protocol);
        if ret != SUCCESS { return Err(ret); }
        Ok(protocol)
    }

    pub fn get_local_address(&mut self) -> Result<bridge::NetAddress, i32> {
        let mut addr = ffi::FFINetAddress {
            address: String::new(),
            has_family: false,
            family: 0,
            has_port: false,
            port: 0,
        };
        let ret = ffi::TlsServerGetLocalAddress(self.cpp_context.pin_mut(), &mut addr);
        if ret != SUCCESS { return Err(ret); }
        Ok(bridge::NetAddress::from(&addr))
    }

    pub fn on_connect_native(&mut self, mutex_ptr: *mut Mutex<TlsServerWrapper>) -> Result<(), i32> {
        let callback_box = TlsServerConnectBox::new(self, mutex_ptr);
        let ret = ffi::TlsServerOnConnect(self.cpp_context.pin_mut(), callback_box);
        if ret != SUCCESS { return Err(ret); }
        Ok(())
    }

    pub fn on_error_native(&mut self) -> Result<(), i32> {
        let callback_box = TlsServerErrorBox::new(self);
        let ret = ffi::TlsServerOnError(self.cpp_context.pin_mut(), callback_box);
        if ret != SUCCESS { return Err(ret); }
        Ok(())
    }
    
    pub fn off_connect_native(&mut self) -> Result<(), i32> {
        let ret = ffi::TlsServerOffConnect(self.cpp_context.pin_mut());
        if ret != SUCCESS { return Err(ret); }
        Ok(())
    }
    
    pub fn off_error_native(&mut self) -> Result<(), i32> {
        let ret = ffi::TlsServerOffError(self.cpp_context.pin_mut());
        if ret != SUCCESS { return Err(ret); }
        Ok(())
    }
}

// ==================== TLS Socket Connect Wrapper ====================
pub struct TlsConnectWrapper {
    cpp_context: UniquePtr<ffi::TlsConnectContext>,
    client_id: i32,
    pub on_message: Option<GlobalRefCallback<(bridge::SocketMessageInfo,)>>,
    pub on_close: Option<GlobalRefCallback<()>>,
    pub on_error: Option<GlobalRefErrorCallback>,
}

impl TlsConnectWrapper {
    pub(crate) fn new(server: &mut TlsServerWrapper, client_id: i32) -> Self {
        TlsConnectWrapper {
            cpp_context: ffi::CreateTlsConnectContext(server.cpp_context.pin_mut(), client_id),
            client_id,
            on_message: None,
            on_close: None,
            on_error: None,
        }
    }

    pub fn send(&mut self, options: &bridge::TCPSendOptions) -> Result<(), i32> {
        let opts = ffi::FFITcpSendOptions::from(options);
        let ret = ffi::TlsConnectSend(self.cpp_context.pin_mut(), opts);
        if ret != SUCCESS { return Err(ret); }
        Ok(())
    }

    pub fn close(&mut self) -> Result<(), i32> {
        let ret = ffi::TlsConnectClose(self.cpp_context.pin_mut());
        if ret != SUCCESS { return Err(ret); }
        Ok(())
    }

    pub fn get_remote_address(&mut self) -> Result<bridge::NetAddress, i32> {
        let mut addr = ffi::FFINetAddress {
            address: String::new(),
            has_family: false,
            family: 0,
            has_port: false,
            port: 0,
        };
        let ret = ffi::TlsConnectGetRemoteAddress(self.cpp_context.pin_mut(), &mut addr);
        if ret != SUCCESS { return Err(ret); }
        Ok(bridge::NetAddress::from(&addr))
    }

    pub fn get_local_address(&mut self) -> Result<bridge::NetAddress, i32> {
        let mut addr = ffi::FFINetAddress {
            address: String::new(),
            has_family: false,
            family: 0,
            has_port: false,
            port: 0,
        };
        let ret = ffi::TlsConnectGetLocalAddress(self.cpp_context.pin_mut(), &mut addr);
        if ret != SUCCESS { return Err(ret); }
        Ok(bridge::NetAddress::from(&addr))
    }

    pub fn get_socket_fd(&mut self) -> Result<i32, i32> {
        let mut fd = 0;
        let ret = ffi::TlsConnectGetSocketFd(self.cpp_context.pin_mut(), &mut fd);
        if ret < 0 { return Err(ret); }
        Ok(fd)
    }

    pub fn get_remote_certificate(&mut self) -> Result<bridge::X509CertRawData, i32> {
        let mut cert = ffi::FFIX509CertRawData {
            data: Vec::new(),
            encoding_format: ffi::FFIEncodingFormat::FORMAT_DER,
        };
        let ret = ffi::TlsConnectGetRemoteCertificate(self.cpp_context.pin_mut(), &mut cert);
        if ret != SUCCESS { return Err(ret); }
        Ok(bridge::X509CertRawData::from(&cert))
    }

    pub fn get_protocol(&mut self) -> Result<String, i32> {
        let mut protocol = String::new();
        let ret = ffi::TlsConnectGetProtocol(self.cpp_context.pin_mut(), &mut protocol);
        if ret != SUCCESS { return Err(ret); }
        Ok(protocol)
    }

    pub fn get_cipher_suite(&mut self) -> Result<Vec<String>, i32> {
        let mut cipher_suite = Vec::new();
        let ret = ffi::TlsConnectGetCipherSuites(self.cpp_context.pin_mut(), &mut cipher_suite);
        if ret != SUCCESS { return Err(ret); }
        Ok(cipher_suite)
    }

    pub fn get_signature_algorithms(&mut self) -> Result<Vec<String>, i32> {
        let mut signature_algorithms = Vec::new();
        let ret = ffi::TlsConnectGetSignatureAlgorithms(self.cpp_context.pin_mut(), &mut signature_algorithms);
        if ret != SUCCESS { return Err(ret); }
        Ok(signature_algorithms)
    }

    pub fn on_message_native(&mut self) -> Result<(), i32> {
        let callback_box = TlsConnectMessageBox::new(self);
        let ret = ffi::TlsConnectOnMessage(self.cpp_context.pin_mut(), callback_box);
        if ret != SUCCESS { return Err(ret); }
        Ok(())
    }

    pub fn off_message_native(&mut self) -> Result<(), i32> {
        let ret = ffi::TlsConnectOffMessage(self.cpp_context.pin_mut());
        if ret != SUCCESS { return Err(ret); }
        Ok(())
    }

    pub fn on_close_native(&mut self) -> Result<(), i32> {
        let callback_box = TlsConnectCloseBox::new(self);
        let ret = ffi::TlsConnectOnClose(self.cpp_context.pin_mut(), callback_box);
        if ret != SUCCESS { return Err(ret); }
        Ok(())
    }

    pub fn off_close_native(&mut self) -> Result<(), i32> {
        let ret = ffi::TlsConnectOffClose(self.cpp_context.pin_mut());
        if ret != SUCCESS { return Err(ret); }
        Ok(())
    }

    pub fn on_error_native(&mut self) -> Result<(), i32> {
        let callback_box = TlsConnectErrorBox::new(self);
        let ret = ffi::TlsConnectOnError(self.cpp_context.pin_mut(), callback_box);
        if ret != SUCCESS { return Err(ret); }
        Ok(())
    }

    pub fn off_error_native(&mut self) -> Result<(), i32> {
        let ret = ffi::TlsConnectOffError(self.cpp_context.pin_mut());
        if ret != SUCCESS { return Err(ret); }
        Ok(())
    }
}

#[cxx::bridge(namespace = "OHOS::NetStackAni")]
pub mod ffi {
    #[derive(Clone, Copy)]
    enum FFIProxyTypes {
        NONE = 0,
        SOCKS5 = 1,
    }

    #[derive(Clone, Copy)]
    enum FFIProtocol {
        TLSv12 = 0,
        TLSv13 = 1,
    }

    #[derive(Clone, Copy)]
    enum FFIEncodingFormat {
        FORMAT_DER = 0,
        FORMAT_PEM = 1,
        FORMAT_PKCS7 = 2,
    }
    struct FFINetAddress {
        address: String,
        has_family: bool,
        family: i32,
        has_port: bool,
        port: i32,
    }

    struct FFIProxyOptions {
        type_: FFIProxyTypes,
        address: FFINetAddress,
        has_username: bool,
        username: String,
        has_password: bool,
        password: String,
    }

    struct FFIExtraOptionsBase {
        has_receive_buffer_size: bool,
        receive_buffer_size: i32,
        has_send_buffer_size: bool,
        send_buffer_size: i32,
        has_reuse_address: bool,
        reuse_address: bool,
        has_socket_timeout: bool,
        socket_timeout: i32,
    }

    struct FFIUdpExtraOptions {
        has_receive_buffer_size: bool,
        receive_buffer_size: i32,
        has_send_buffer_size: bool,
        send_buffer_size: i32,
        has_reuse_address: bool,
        reuse_address: bool,
        has_socket_timeout: bool,
        socket_timeout: i32,
        has_broadcast: bool,
        broadcast: bool,
    }
    struct FFITcpExtraOptions {
        has_receive_buffer_size: bool,
        receive_buffer_size: i32,
        has_send_buffer_size: bool,
        send_buffer_size: i32,
        has_reuse_address: bool,
        reuse_address: bool,
        has_socket_timeout: bool,
        socket_timeout: i32,
        has_keep_alive: bool,
        keep_alive: bool,
        has_oob_inline: bool,
        oob_inline: bool,
        has_tcp_no_delay: bool,
        tcp_no_delay: bool,
        has_socket_linger: bool,
        socket_linger_on: bool,
        socket_linger_linger: i32,
        has_tcp_fast_open: bool,
        tcp_fast_open: bool,
    }

    struct FFITlsSecureOptions {
        has_ca: bool,
        ca: Vec<String>,
        has_cert: bool,
        cert: Vec<String>,
        has_key: bool,
        key: String,
        has_password: bool,
        password: String,
        has_protocols: bool,
        protocols: Vec<FFIProtocol>,
        has_use_remote_cipher_prefer: bool,
        use_remote_cipher_prefer: bool,
        has_signature_algorithms: bool,
        signature_algorithms: String,
        has_cipher_suite: bool,
        cipher_suite: String,
        has_is_bidirectional_authentication: bool,
        is_bidirectional_authentication: bool,
    }

    struct FFISocketRemoteInfo {
        address: String,
        family: String,
        port: i32,
        size: i32,
    }

    struct FFIX509CertRawData {
        data: Vec<u8>,
        encoding_format: FFIEncodingFormat,
    }

    struct FFISocketStateBase {
        is_bound: bool,
        is_close: bool,
        is_connected: bool,
    }

    struct FFILocalAddress {
        address: String,
    }

    struct FFILocalConnectOptions {
        address: FFILocalAddress,
        has_timeout: bool,
        timeout: i32,
    }

    struct FFILocalSendOptions {
        data: Vec<u8>,
        has_encoding: bool,
        encoding: String,
    }

    struct FFITcpSendOptions {
        data: Vec<u8>,
        has_encoding: bool,
        encoding: String,
    }

    struct FFITcpConnectOptions {
        address: FFINetAddress,
        has_timeout: bool,
        timeout: i32,
        has_proxy: bool,
        proxy: FFIProxyOptions,
    }

    struct FFIUdpSendOptions {
        data: Vec<u8>,
        address: FFINetAddress,
        has_proxy: bool,
        proxy: FFIProxyOptions,
    }

    struct FFITlsConnectOptions {
        address: FFINetAddress,
        secure_options: FFITlsSecureOptions,
        has_alpn_protocols: bool,
        alpn_protocols: Vec<String>,
        has_skip_remote_validation: bool,
        skip_remote_validation: bool,
        has_ssl_server_hostname_verification: bool,
        ssl_server_hostname_verification: bool,
        has_proxy: bool,
        proxy: FFIProxyOptions,
        has_timeout: bool,
        timeout: i32,
    }

    extern "Rust" {
        type UdpSocketMessageBox;
        type UdpSocketListeningBox;
        type UdpSocketCloseBox;
        type UdpSocketErrorBox;
        fn on_message(self: &UdpSocketMessageBox, data: Vec<u8>, address: String, family: String, port: i32, size: i32) -> i32;
        fn on_listening(self: &UdpSocketListeningBox) -> i32;
        fn on_close(self: &UdpSocketCloseBox) -> i32;
        fn on_error(self: &UdpSocketErrorBox, error_code: i32, error_string: String) -> i32;

        type LocalSocketMessageBox;
        type LocalSocketConnectBox;
        type LocalSocketCloseBox;
        type LocalSocketErrorBox;
        fn on_message(self: &LocalSocketMessageBox, data: Vec<u8>, address: String, size: i32) -> i32;
        fn on_connect(self: &LocalSocketConnectBox) -> i32;
        fn on_close(self: &LocalSocketCloseBox) -> i32;
        fn on_error(self: &LocalSocketErrorBox, error_code: i32, error_string: String) -> i32;

        type LocalSocketConnectionMessageBox;
        type LocalSocketConnectionCloseBox;
        type LocalSocketConnectionErrorBox;
        fn on_message(self: &LocalSocketConnectionMessageBox, data: Vec<u8>, address: String, size: i32) -> i32;
        fn on_close(self: &LocalSocketConnectionCloseBox) -> i32;
        fn on_error(self: &LocalSocketConnectionErrorBox, error_code: i32, error_string: String) -> i32;

        type LocalSocketServerConnectBox;
        type LocalSocketServerErrorBox;
        fn on_connect(self: &LocalSocketServerConnectBox, client_id: i32) -> i32;
        fn on_error(self: &LocalSocketServerErrorBox, error_code: i32, error_string: String) -> i32;

        type TcpSocketMessageBox;
        type TcpSocketConnectBox;
        type TcpSocketCloseBox;
        type TcpSocketErrorBox;
        fn on_message(self: &TcpSocketMessageBox, data: Vec<u8>, address: String, family: String, port: i32, size: i32) -> i32;
        fn on_connect(self: &TcpSocketConnectBox) -> i32;
        fn on_close(self: &TcpSocketCloseBox) -> i32;
        fn on_error(self: &TcpSocketErrorBox, error_code: i32, error_string: String) -> i32;

        type TcpSocketServerConnectBox;
        type TcpSocketServerErrorBox;
        fn on_connect(self: &TcpSocketServerConnectBox, client_id: i32) -> i32;
        fn on_error(self: &TcpSocketServerErrorBox, error_code: i32, error_string: String) -> i32;

        type TcpSocketConnectionMessageBox;
        type TcpSocketConnectionCloseBox;
        type TcpSocketConnectionErrorBox;
        fn on_message(self: &TcpSocketConnectionMessageBox, data: Vec<u8>, address: String, family: String, port: i32, size: i32) -> i32;
        fn on_close(self: &TcpSocketConnectionCloseBox) -> i32;
        fn on_error(self: &TcpSocketConnectionErrorBox, error_code: i32, error_string: String) -> i32;

        type TlsClientMessageBox;
        type TlsClientConnectBox;
        type TlsClientCloseBox;
        type TlsClientErrorBox;
        fn on_message(self: &TlsClientMessageBox, data: Vec<u8>, address: String, family: String, port: i32, size: i32) -> i32;
        fn on_connect(self: &TlsClientConnectBox) -> i32;
        fn on_close(self: &TlsClientCloseBox) -> i32;
        fn on_error(self: &TlsClientErrorBox, error_code: i32, error_string: String) -> i32;

        type TlsServerConnectBox;
        type TlsServerErrorBox;
        fn on_connect(self: &TlsServerConnectBox, client_id: i32) -> i32;
        fn on_error(self: &TlsServerErrorBox, error_code: i32, error_string: String) -> i32;

        type TlsConnectMessageBox;
        type TlsConnectCloseBox;
        type TlsConnectErrorBox;
        fn on_message(self: &TlsConnectMessageBox, data: Vec<u8>, address: String, family: String, port: i32, size: i32) -> i32;
        fn on_close(self: &TlsConnectCloseBox) -> i32;
        fn on_error(self: &TlsConnectErrorBox, error_code: i32, error_string: String) -> i32;

    }

    unsafe extern "C++" {
        include!("socket_ani.h");

        fn GetErrorCodeAndMessage(error_code: &mut i32) -> String;

        type UdpSocketContext;
        fn CreateUdpSocketContext() -> UniquePtr<UdpSocketContext>;
        fn CreateMulticastClientContext() -> UniquePtr<UdpSocketContext>;
        fn UdpClientBind(client: Pin<&mut UdpSocketContext>, addr: &FFINetAddress) -> i32;
        fn UdpClientSend(client: Pin<&mut UdpSocketContext>, send_opts: &FFIUdpSendOptions, proxy_opts: &FFIProxyOptions) -> i32;
        fn UdpClientClose(client: Pin<&mut UdpSocketContext>) -> i32;
        fn UdpClientGetState(client: Pin<&mut UdpSocketContext>, is_bound: &mut bool, is_close: &mut bool, is_connected: &mut bool) -> i32;
        fn UdpClientSetExtraOptions(client: Pin<&mut UdpSocketContext>, opts: &FFIUdpExtraOptions) -> i32;
        fn UdpClientGetSocketFd(client: Pin<&mut UdpSocketContext>, fd: &mut i32) -> i32;
        fn UdpClientGetLocalAddress(client: Pin<&mut UdpSocketContext>, address: &mut String, family: &mut i32, port: &mut i32) -> i32;
        fn UdpClientAddMembership(client: Pin<&mut UdpSocketContext>, multicast_addr: &str, family: i32, port: i32) -> i32;
        fn UdpClientDropMembership(client: Pin<&mut UdpSocketContext>, multicast_addr: &str, family: i32, port: i32) -> i32;
        fn UdpClientSetTtl(client: Pin<&mut UdpSocketContext>, ttl: i32) -> i32;
        fn UdpClientGetTtl(client: Pin<&mut UdpSocketContext>, ttl: &mut i32) -> i32;
        fn UdpClientSetLoopbackMode(client: Pin<&mut UdpSocketContext>, loopback: bool) -> i32;
        fn UdpClientGetLoopbackMode(client: Pin<&mut UdpSocketContext>, loopback: &mut bool) -> i32;
        fn UdpClientSetReuseAddress(client: Pin<&mut UdpSocketContext>, reuse: bool) -> i32;
        fn UdpSocketOnMessage(client: Pin<&mut UdpSocketContext>, callback: Box<UdpSocketMessageBox>) -> i32;
        fn UdpSocketOnListening(client: Pin<&mut UdpSocketContext>, callback: Box<UdpSocketListeningBox>) -> i32;
        fn UdpSocketOnClose(client: Pin<&mut UdpSocketContext>, callback: Box<UdpSocketCloseBox>) -> i32;
        fn UdpSocketOnError(client: Pin<&mut UdpSocketContext>, callback: Box<UdpSocketErrorBox>) -> i32;
        fn UdpSocketOffMessage(client: Pin<&mut UdpSocketContext>) -> i32;
        fn UdpSocketOffListening(client: Pin<&mut UdpSocketContext>) -> i32;
        fn UdpSocketOffClose(client: Pin<&mut UdpSocketContext>) -> i32;
        fn UdpSocketOffError(client: Pin<&mut UdpSocketContext>) -> i32;

        type LocalSocketContext;
        fn CreateLocalSocketContext() -> UniquePtr<LocalSocketContext>;
        fn LocalSocketBind(client: Pin<&mut LocalSocketContext>, addr: &FFILocalAddress) -> i32;
        fn LocalSocketConnect(client: Pin<&mut LocalSocketContext>, opts: &FFILocalConnectOptions) -> i32;
        fn LocalSocketSend(client: Pin<&mut LocalSocketContext>, opts: &FFILocalSendOptions) -> i32;
        fn LocalSocketClose(client: Pin<&mut LocalSocketContext>) -> i32;
        fn LocalSocketGetState(client: Pin<&mut LocalSocketContext>, is_bound: &mut bool, is_close: &mut bool, is_connected: &mut bool) -> i32;
        fn LocalSocketGetSocketFd(client: Pin<&mut LocalSocketContext>, fd: &mut i32) -> i32;
        fn LocalSocketSetExtraOptions(client: Pin<&mut LocalSocketContext>, opts: &FFIExtraOptionsBase) -> i32;
        fn LocalSocketGetExtraOptions(client: Pin<&mut LocalSocketContext>, opts: &mut FFIExtraOptionsBase) -> i32;
        fn LocalSocketGetLocalAddress(client: Pin<&mut LocalSocketContext>, address: &mut String) -> i32;
        fn LocalSocketOnMessage(client: Pin<&mut LocalSocketContext>, callback: Box<LocalSocketMessageBox>) -> i32;
        fn LocalSocketOnConnect(client: Pin<&mut LocalSocketContext>, callback: Box<LocalSocketConnectBox>) -> i32;
        fn LocalSocketOnClose(client: Pin<&mut LocalSocketContext>, callback: Box<LocalSocketCloseBox>) -> i32;
        fn LocalSocketOnError(client: Pin<&mut LocalSocketContext>, callback: Box<LocalSocketErrorBox>) -> i32;
        fn LocalSocketOffMessage(client: Pin<&mut LocalSocketContext>) -> i32;
        fn LocalSocketOffConnect(client: Pin<&mut LocalSocketContext>) -> i32;
        fn LocalSocketOffClose(client: Pin<&mut LocalSocketContext>) -> i32;
        fn LocalSocketOffError(client: Pin<&mut LocalSocketContext>) -> i32;

        type LocalSocketConnectionContext;
        fn CreateLocalSocketConnectionContext(server: Pin<&mut LocalSocketServerContext>, client_id: i32) -> UniquePtr<LocalSocketConnectionContext>;
        fn LocalSocketConnectionSend(connection: Pin<&mut LocalSocketConnectionContext>, opts: &FFILocalSendOptions) -> i32;
        fn LocalSocketConnectionClose(connection: Pin<&mut LocalSocketConnectionContext>) -> i32;
        fn LocalSocketConnectionGetLocalAddress(connection: Pin<&mut LocalSocketConnectionContext>, address: &mut String) -> i32;
        fn LocalSocketConnectionGetSocketFd(connection: Pin<&mut LocalSocketConnectionContext>, fd: &mut i32) -> i32;
        fn LocalSocketConnectionOnMessage(client: Pin<&mut LocalSocketConnectionContext>, callback: Box<LocalSocketConnectionMessageBox>) -> i32;
        fn LocalSocketConnectionOnClose(client: Pin<&mut LocalSocketConnectionContext>, callback: Box<LocalSocketConnectionCloseBox>) -> i32;
        fn LocalSocketConnectionOnError(client: Pin<&mut LocalSocketConnectionContext>, callback: Box<LocalSocketConnectionErrorBox>) -> i32;
        fn LocalSocketConnectionOffMessage(client: Pin<&mut LocalSocketConnectionContext>) -> i32;
        fn LocalSocketConnectionOffClose(client: Pin<&mut LocalSocketConnectionContext>) -> i32;
        fn LocalSocketConnectionOffError(client: Pin<&mut LocalSocketConnectionContext>) -> i32;

        type LocalSocketServerContext;
        fn CreateLocalSocketServerContext() -> UniquePtr<LocalSocketServerContext>;
        fn LocalSocketServerListen(server: Pin<&mut LocalSocketServerContext>, addr: &FFILocalAddress) -> i32;
        fn LocalSocketServerGetState(server: Pin<&mut LocalSocketServerContext>, is_bound: &mut bool, is_close: &mut bool, is_connected: &mut bool) -> i32;
        fn LocalSocketServerGetSocketFd(server: Pin<&mut LocalSocketServerContext>, fd: &mut i32) -> i32;
        fn LocalSocketServerSetExtraOptions(server: Pin<&mut LocalSocketServerContext>, opts: &FFIExtraOptionsBase) -> i32;
        fn LocalSocketServerGetExtraOptions(server: Pin<&mut LocalSocketServerContext>, opts: &mut FFIExtraOptionsBase) -> i32;
        fn LocalSocketServerGetLocalAddress(server: Pin<&mut LocalSocketServerContext>, address: &mut String) -> i32;
        fn LocalSocketServerClose(server: Pin<&mut LocalSocketServerContext>) -> i32;
        fn LocalSocketServerOnConnect(server: Pin<&mut LocalSocketServerContext>, callback: Box<LocalSocketServerConnectBox>) -> i32;
        fn LocalSocketServerOnError(server: Pin<&mut LocalSocketServerContext>, callback: Box<LocalSocketServerErrorBox>) -> i32;
        fn LocalSocketServerOffConnect(server: Pin<&mut LocalSocketServerContext>) -> i32;
        fn LocalSocketServerOffError(server: Pin<&mut LocalSocketServerContext>) -> i32;

        type TcpSocketContext;
        fn CreateTcpSocketContext() -> UniquePtr<TcpSocketContext>;
        fn TcpSocketBind(client: Pin<&mut TcpSocketContext>, addr: &FFINetAddress) -> i32;
        fn TcpSocketConnect(client: Pin<&mut TcpSocketContext>, opts: &FFITcpConnectOptions) -> i32;
        fn TcpSocketSend(client: Pin<&mut TcpSocketContext>, opts: &FFITcpSendOptions) -> i32;
        fn TcpSocketClose(client: Pin<&mut TcpSocketContext>) -> i32;
        fn TcpSocketGetState(client: Pin<&mut TcpSocketContext>, is_bound: &mut bool, is_close: &mut bool, is_connected: &mut bool) -> i32;
        fn TcpSocketGetRemoteAddress(client: Pin<&mut TcpSocketContext>, address: &mut String, family: &mut i32, port: &mut i32) -> i32;
        fn TcpSocketGetLocalAddress(client: Pin<&mut TcpSocketContext>, address: &mut String, family: &mut i32, port: &mut i32) -> i32;
        fn TcpSocketSetExtraOptions(client: Pin<&mut TcpSocketContext>, opts: &FFITcpExtraOptions) -> i32;
        fn TcpClientGetSocketFd(client: Pin<&mut TcpSocketContext>, fd: &mut i32) -> i32;
        fn TcpSocketOnMessage(client: Pin<&mut TcpSocketContext>, callback: Box<TcpSocketMessageBox>) -> i32;
        fn TcpSocketOnConnect(client: Pin<&mut TcpSocketContext>, callback: Box<TcpSocketConnectBox>) -> i32;
        fn TcpSocketOnClose(client: Pin<&mut TcpSocketContext>, callback: Box<TcpSocketCloseBox>) -> i32;
        fn TcpSocketOnError(client: Pin<&mut TcpSocketContext>, callback: Box<TcpSocketErrorBox>) -> i32;
        fn TcpSocketOffMessage(client: Pin<&mut TcpSocketContext>) -> i32;
        fn TcpSocketOffConnect(client: Pin<&mut TcpSocketContext>) -> i32;
        fn TcpSocketOffClose(client: Pin<&mut TcpSocketContext>) -> i32;
        fn TcpSocketOffError(client: Pin<&mut TcpSocketContext>) -> i32;

        type TcpSocketServerContext;
        fn CreateTcpSocketServerContext() -> UniquePtr<TcpSocketServerContext>;
        fn TcpSocketServerListen(server: Pin<&mut TcpSocketServerContext>, addr: &FFINetAddress) -> i32;
        fn TcpSocketServerGetState(server: Pin<&mut TcpSocketServerContext>, is_bound: &mut bool, is_close: &mut bool, is_connected: &mut bool) -> i32;
        fn TcpSocketServerSetExtraOptions(server: Pin<&mut TcpSocketServerContext>, opts: &FFITcpExtraOptions) -> i32;
        fn TcpSocketServerGetSocketFd(server: Pin<&mut TcpSocketServerContext>, fd: &mut i32) -> i32;
        fn TcpSocketServerClose(server: Pin<&mut TcpSocketServerContext>) -> i32;
        fn TcpSocketServerGetLocalAddress(server: Pin<&mut TcpSocketServerContext>, address: &mut String, family: &mut i32, port: &mut i32) -> i32;
        fn TcpSocketServerOnConnect(server: Pin<&mut TcpSocketServerContext>, callback: Box<TcpSocketServerConnectBox>) -> i32;
        fn TcpSocketServerOnError(server: Pin<&mut TcpSocketServerContext>, callback: Box<TcpSocketServerErrorBox>) -> i32;
        fn TcpSocketServerOffConnect(server: Pin<&mut TcpSocketServerContext>) -> i32;
        fn TcpSocketServerOffError(server: Pin<&mut TcpSocketServerContext>) -> i32;

        type TcpSocketConnectionContext;
        fn CreateTcpSocketConnectionContext(server: Pin<&mut TcpSocketServerContext>, client_id: i32) -> UniquePtr<TcpSocketConnectionContext>;
        fn TcpSocketConnectionSend(connection: Pin<&mut TcpSocketConnectionContext>, opts: &FFITcpSendOptions) -> i32;
        fn TcpSocketConnectionClose(connection: Pin<&mut TcpSocketConnectionContext>) -> i32;
        fn TcpSocketConnectionGetRemoteAddress(connection: Pin<&mut TcpSocketConnectionContext>, address: &mut String, family: &mut i32, port: &mut i32) -> i32;
        fn TcpSocketConnectionGetLocalAddress(connection: Pin<&mut TcpSocketConnectionContext>, address: &mut String, family: &mut i32, port: &mut i32) -> i32;
        fn TcpSocketConnectionGetSocketFd(connection: Pin<&mut TcpSocketConnectionContext>, fd: &mut i32) -> i32;
        fn TcpSocketConnectionOnMessage(connection: Pin<&mut TcpSocketConnectionContext>, callback: Box<TcpSocketConnectionMessageBox>) -> i32;
        fn TcpSocketConnectionOnClose(connection: Pin<&mut TcpSocketConnectionContext>, callback: Box<TcpSocketConnectionCloseBox>) -> i32;
        fn TcpSocketConnectionOnError(connection: Pin<&mut TcpSocketConnectionContext>, callback: Box<TcpSocketConnectionErrorBox>) -> i32;
        fn TcpSocketConnectionOffMessage(connection: Pin<&mut TcpSocketConnectionContext>) -> i32;
        fn TcpSocketConnectionOffClose(connection: Pin<&mut TcpSocketConnectionContext>) -> i32;
        fn TcpSocketConnectionOffError(connection: Pin<&mut TcpSocketConnectionContext>) -> i32;

        type TlsClientContext;
        fn CreateTlsClientContext(errCode: &mut i32) -> UniquePtr<TlsClientContext>;
        fn CreateTlsClientContextFromTcpClientContext(server: Pin<&mut TcpSocketContext>, errCode: &mut i32) -> UniquePtr<TlsClientContext>;
        fn TlsClientBind(client: Pin<&mut TlsClientContext>, addr: &FFINetAddress) -> i32;
        fn TlsClientConnect(client: Pin<&mut TlsClientContext>, opts: &FFITlsConnectOptions) -> i32;
        fn TlsClientSend(client: Pin<&mut TlsClientContext>, data: FFITcpSendOptions) -> i32;
        fn TlsClientClose(client: Pin<&mut TlsClientContext>) -> i32;
        fn TlsClientGetState(client: Pin<&mut TlsClientContext>, status: &mut FFISocketStateBase) -> i32;
        fn TlsClientGetRemoteAddress(client: Pin<&mut TlsClientContext>, address: &mut FFINetAddress) -> i32;
        fn TlsClientGetLocalAddress(client: Pin<&mut TlsClientContext>, address: &mut FFINetAddress) -> i32;
        fn TlsClientGetSocketFd(client: Pin<&mut TlsClientContext>, fd: &mut i32) -> i32;
        fn TlsClientGetCertificate(client: Pin<&mut TlsClientContext>, cert: &mut FFIX509CertRawData) -> i32;
        fn TlsClientGetRemoteCertificate(client: Pin<&mut TlsClientContext>, cert: &mut FFIX509CertRawData) -> i32;
        fn TlsClientGetProtocol(client: Pin<&mut TlsClientContext>, protocol: &mut String) -> i32;
        fn TlsClientGetCipherSuite(client: Pin<&mut TlsClientContext>, cipher_suite: &mut Vec<String>) -> i32;
        fn TlsClientGetSignatureAlgorithms(client: Pin<&mut TlsClientContext>, signature_algorithms: &mut Vec<String>) -> i32;
        fn TlsClientOnMessage(client: Pin<&mut TlsClientContext>, callback: Box<TlsClientMessageBox>) -> i32;
        fn TlsClientOnConnect(client: Pin<&mut TlsClientContext>, callback: Box<TlsClientConnectBox>) -> i32;
        fn TlsClientOnClose(client: Pin<&mut TlsClientContext>, callback: Box<TlsClientCloseBox>) -> i32;
        fn TlsClientOnError(client: Pin<&mut TlsClientContext>, callback: Box<TlsClientErrorBox>) -> i32;
        fn TlsClientOffMessage(client: Pin<&mut TlsClientContext>) -> i32;
        fn TlsClientOffConnect(client: Pin<&mut TlsClientContext>) -> i32;
        fn TlsClientOffClose(client: Pin<&mut TlsClientContext>) -> i32;
        fn TlsClientOffError(client: Pin<&mut TlsClientContext>) -> i32;
        fn TlsClientSetExtraOptions(client: Pin<&mut TlsClientContext>, opts: &FFITcpExtraOptions) -> i32;

        type TlsServerContext;
        fn CreateTlsServerContext() -> UniquePtr<TlsServerContext>;
        fn TlsServerListen(server: Pin<&mut TlsServerContext>, opts: &FFITlsConnectOptions) -> i32;
        fn TlsServerGetState(server: Pin<&mut TlsServerContext>, status: &mut FFISocketStateBase) -> i32;
        fn TlsServerGetSocketFd(server: Pin<&mut TlsServerContext>, fd: &mut i32) -> i32;
        fn TlsServerClose(server: Pin<&mut TlsServerContext>) -> i32;
        fn TlsServerSetExtraOptions(server: Pin<&mut TlsServerContext>, opts: &FFITcpExtraOptions) -> i32;
        fn TlsServerGetCertificate(server: Pin<&mut TlsServerContext>, cert: &mut FFIX509CertRawData) -> i32;
        fn TlsServerGetProtocol(server: Pin<&mut TlsServerContext>, protocol: &mut String) -> i32;
        fn TlsServerGetLocalAddress(server: Pin<&mut TlsServerContext>, address: &mut FFINetAddress) -> i32;
        fn TlsServerOnConnect(server: Pin<&mut TlsServerContext>, callback: Box<TlsServerConnectBox>) -> i32;
        fn TlsServerOnError(server: Pin<&mut TlsServerContext>, callback: Box<TlsServerErrorBox>) -> i32;
        fn TlsServerOffConnect(server: Pin<&mut TlsServerContext>) -> i32;
        fn TlsServerOffError(server: Pin<&mut TlsServerContext>) -> i32;

        type TlsConnectContext;
        fn CreateTlsConnectContext(server: Pin<&mut TlsServerContext>, client_id: i32) -> UniquePtr<TlsConnectContext>;
        fn TlsConnectSend(connection: Pin<&mut TlsConnectContext>, data: FFITcpSendOptions) -> i32;
        fn TlsConnectClose(connection: Pin<&mut TlsConnectContext>) -> i32;
        fn TlsConnectGetRemoteAddress(connection: Pin<&mut TlsConnectContext>, address: &mut FFINetAddress) -> i32;
        fn TlsConnectGetLocalAddress(connection: Pin<&mut TlsConnectContext>, address: &mut FFINetAddress) -> i32;
        fn TlsConnectGetSocketFd(connection: Pin<&mut TlsConnectContext>, fd: &mut i32) -> i32;
        fn TlsConnectGetRemoteCertificate(connection: Pin<&mut TlsConnectContext>,  cert: &mut FFIX509CertRawData) -> i32;
        fn TlsConnectGetProtocol(connection: Pin<&mut TlsConnectContext>, protocol: &mut String) -> i32;
        fn TlsConnectGetCipherSuites(connection: Pin<&mut TlsConnectContext>, cipher_suite: &mut Vec<String>) -> i32;
        fn TlsConnectGetSignatureAlgorithms(connection: Pin<&mut TlsConnectContext>, signature_algorithms: &mut Vec<String>) -> i32;
        fn TlsConnectOnMessage(connection: Pin<&mut TlsConnectContext>, callback: Box<TlsConnectMessageBox>) -> i32;
        fn TlsConnectOnClose(connection: Pin<&mut TlsConnectContext>, callback: Box<TlsConnectCloseBox>) -> i32;
        fn TlsConnectOnError(connection: Pin<&mut TlsConnectContext>, callback: Box<TlsConnectErrorBox>) -> i32;
        fn TlsConnectOffMessage(connection: Pin<&mut TlsConnectContext>) -> i32;
        fn TlsConnectOffClose(connection: Pin<&mut TlsConnectContext>) -> i32;
        fn TlsConnectOffError(connection: Pin<&mut TlsConnectContext>) -> i32;
    }
}

impl From<&bridge::NetAddress> for ffi::FFINetAddress {
    fn from(addr: &bridge::NetAddress) -> Self {
        ffi::FFINetAddress {
            address: addr.address.clone(),
            has_family: addr.family.is_some(),
            family: addr.family.unwrap_or(0),
            has_port: addr.port.is_some(),
            port: addr.port.unwrap_or(0),
        }
    }
}

impl From<&ffi::FFINetAddress> for bridge::NetAddress {
    fn from(addr: &ffi::FFINetAddress) -> Self {
        bridge::NetAddress {
            address: addr.address.clone(),
            family: if addr.has_family { Some(addr.family) } else { None },
            port: if addr.has_port { Some(addr.port) } else { None },
        }
    }
}

impl From<&bridge::ProxyOptions> for ffi::FFIProxyOptions {
    fn from(p: &bridge::ProxyOptions) -> Self {
        ffi::FFIProxyOptions {
            type_: match p.type_ {
                bridge::ProxyTypes::NONE   => ffi::FFIProxyTypes::NONE,
                bridge::ProxyTypes::SOCKS5 => ffi::FFIProxyTypes::SOCKS5,
            },
            address: ffi::FFINetAddress::from(&p.address),
            has_username: p.username.is_some(),
            username: p.username.clone().unwrap_or_default(),
            has_password: p.password.is_some(),
            password: p.password.clone().unwrap_or_default(),
        }
    }
}

impl From<&ffi::FFIProxyOptions> for bridge::ProxyOptions {
    fn from(p: &ffi::FFIProxyOptions) -> Self {
        bridge::ProxyOptions {
            type_: match p.type_ {
                ffi::FFIProxyTypes::NONE   => bridge::ProxyTypes::NONE,
                ffi::FFIProxyTypes::SOCKS5 => bridge::ProxyTypes::SOCKS5,
                _ => unreachable!("invalid FFIProxyTypes value"),
            },
            address: bridge::NetAddress::from(&p.address),
            username: if p.has_username { Some(p.username.clone()) } else { None },
            password: if p.has_password { Some(p.password.clone()) } else { None },
        }
    }
}

impl Default for ffi::FFIProxyOptions {
    fn default() -> Self {
        ffi::FFIProxyOptions {
            type_: ffi::FFIProxyTypes::NONE,
            address: ffi::FFINetAddress {
                address: String::new(),
                has_family: false, family: 0,
                has_port: false, port: 0,
            },
            has_username: false,
            username: String::new(),
            has_password: false,
            password: String::new(),
        }
    }
}

impl From<&bridge::ExtraOptionsBase> for ffi::FFIExtraOptionsBase {
    fn from(opts: &bridge::ExtraOptionsBase) -> Self {
        ffi::FFIExtraOptionsBase {
            has_receive_buffer_size: opts.receive_buffer_size.is_some(),
            receive_buffer_size: opts.receive_buffer_size.unwrap_or(0),
            has_send_buffer_size: opts.send_buffer_size.is_some(),
            send_buffer_size: opts.send_buffer_size.unwrap_or(0),
            has_reuse_address: opts.reuse_address.is_some(),
            reuse_address: opts.reuse_address.unwrap_or(false),
            has_socket_timeout: opts.socket_timeout.is_some(),
            socket_timeout: opts.socket_timeout.unwrap_or(0),
        }
    }
}

impl From<&ffi::FFIExtraOptionsBase> for bridge::ExtraOptionsBase {
    fn from(opts: &ffi::FFIExtraOptionsBase) -> Self {
        bridge::ExtraOptionsBase {
            receive_buffer_size: if opts.has_receive_buffer_size { Some(opts.receive_buffer_size) } else { None },
            send_buffer_size: if opts.has_send_buffer_size { Some(opts.send_buffer_size) } else { None },
            reuse_address: if opts.has_reuse_address { Some(opts.reuse_address) } else { None },
            socket_timeout: if opts.has_socket_timeout { Some(opts.socket_timeout) } else { None },
        }
    }
}

impl From<&bridge::UDPExtraOptions> for ffi::FFIUdpExtraOptions {
    fn from(opts: &bridge::UDPExtraOptions) -> Self {
        ffi::FFIUdpExtraOptions {
            has_receive_buffer_size: opts.receive_buffer_size.is_some(),
            receive_buffer_size: opts.receive_buffer_size.unwrap_or(0),
            has_send_buffer_size: opts.send_buffer_size.is_some(),
            send_buffer_size: opts.send_buffer_size.unwrap_or(0),
            has_reuse_address: opts.reuse_address.is_some(),
            reuse_address: opts.reuse_address.unwrap_or(false),
            has_socket_timeout: opts.socket_timeout.is_some(),
            socket_timeout: opts.socket_timeout.unwrap_or(0),
            has_broadcast: opts.broadcast.is_some(),
            broadcast: opts.broadcast.unwrap_or(false),
        }
    }
}

impl From<&ffi::FFIUdpExtraOptions> for bridge::UDPExtraOptions {
    fn from(opts: &ffi::FFIUdpExtraOptions) -> Self {
        bridge::UDPExtraOptions {
            receive_buffer_size: if opts.has_receive_buffer_size { Some(opts.receive_buffer_size) } else { None },
            send_buffer_size: if opts.has_send_buffer_size { Some(opts.send_buffer_size) } else { None },
            reuse_address: if opts.has_reuse_address { Some(opts.reuse_address) } else { None },
            socket_timeout: if opts.has_socket_timeout { Some(opts.socket_timeout) } else { None },
            broadcast: if opts.has_broadcast { Some(opts.broadcast) } else { None },
        }
    }
}

impl From<&bridge::TCPExtraOptions> for ffi::FFITcpExtraOptions {
    fn from(opts: &bridge::TCPExtraOptions) -> Self {
        let (has_linger, linger_on, linger_linger) = match opts.socket_linger.as_ref() {
            Some(l) => (true, l.on.unwrap_or(false), l.linger.unwrap_or(0)),
            None => (false, false, 0),
        };

        ffi::FFITcpExtraOptions {
            has_receive_buffer_size: opts.receive_buffer_size.is_some(),
            receive_buffer_size: opts.receive_buffer_size.unwrap_or(0),
            has_send_buffer_size: opts.send_buffer_size.is_some(),
            send_buffer_size: opts.send_buffer_size.unwrap_or(0),
            has_reuse_address: opts.reuse_address.is_some(),
            reuse_address: opts.reuse_address.unwrap_or(false),
            has_socket_timeout: opts.socket_timeout.is_some(),
            socket_timeout: opts.socket_timeout.unwrap_or(0),
            has_keep_alive: opts.keep_alive.is_some(),
            keep_alive: opts.keep_alive.unwrap_or(false),
            has_oob_inline: opts.oob_inline.is_some(),
            oob_inline: opts.oob_inline.unwrap_or(false),
            has_tcp_no_delay: opts.tcp_no_delay.is_some(),
            tcp_no_delay: opts.tcp_no_delay.unwrap_or(false),
            has_socket_linger: opts.socket_linger.is_some(),
            socket_linger_on: linger_on,
            socket_linger_linger: linger_linger,
            has_tcp_fast_open: opts.tcp_fast_open.is_some(),
            tcp_fast_open: opts.tcp_fast_open.unwrap_or(false),
        }
    }
}

impl From<&ffi::FFITcpExtraOptions> for bridge::TCPExtraOptions {
    fn from(opts: &ffi::FFITcpExtraOptions) -> Self {
        bridge::TCPExtraOptions {
            receive_buffer_size: if opts.has_receive_buffer_size { Some(opts.receive_buffer_size) } else { None },
            send_buffer_size: if opts.has_send_buffer_size { Some(opts.send_buffer_size) } else { None },
            reuse_address: if opts.has_reuse_address { Some(opts.reuse_address) } else { None },
            socket_timeout: if opts.has_socket_timeout { Some(opts.socket_timeout) } else { None },
            keep_alive: if opts.has_keep_alive { Some(opts.keep_alive) } else { None },
            oob_inline: if opts.has_oob_inline { Some(opts.oob_inline) } else { None },
            tcp_no_delay: if opts.has_tcp_no_delay { Some(opts.tcp_no_delay) } else { None },
            socket_linger: if opts.has_socket_linger {
                Some(bridge::SocketLingerOptions {
                    on: Some(opts.socket_linger_on),
                    linger: Some(opts.socket_linger_linger),
                }) } else { None },
            tcp_fast_open: if opts.has_tcp_fast_open { Some(opts.tcp_fast_open) } else { None },
        }
    }
}

impl From<&bridge::TLSSecureOptions> for ffi::FFITlsSecureOptions {
    fn from(sec: &bridge::TLSSecureOptions) -> Self {
        let (has_ca, ca_vec) = match &sec.ca {
            None => (false, vec![]),
            Some(bridge::UnionCaCert::S(s)) => (true, vec![s.clone()]),
            Some(bridge::UnionCaCert::Array(v)) => (true, v.clone()),
        };
        let (has_cert, cert_vec) = match &sec.cert {
            None => (false, vec![]),
            Some(bridge::UnionCaCert::S(s)) => (true, vec![s.clone()]),
            Some(bridge::UnionCaCert::Array(v)) => (true, v.clone()),
        };
        let (has_protocols, protocols_vec) = match &sec.protocols {
            None => (false, vec![]),
            Some(bridge::UnionProtocol::S(p)) => (true, vec![match p {
                bridge::Protocol::TLSv12 => ffi::FFIProtocol::TLSv12,
                bridge::Protocol::TLSv13 => ffi::FFIProtocol::TLSv13,
            }]),
            Some(bridge::UnionProtocol::Array(v)) => (
                true,
                v.iter()
                    .map(|p| match p {
                        bridge::Protocol::TLSv12 => ffi::FFIProtocol::TLSv12,
                        bridge::Protocol::TLSv13 => ffi::FFIProtocol::TLSv13,
                    })
                    .collect(),
            ),
        };
        ffi::FFITlsSecureOptions {
            has_ca,
            ca: ca_vec,
            has_cert,
            cert: cert_vec,
            has_key: sec.key.is_some(),
            key: sec.key.clone().unwrap_or_default(),
            has_password: sec.password.is_some(),
            password: sec.password.clone().unwrap_or_default(),
            has_protocols,
            protocols: protocols_vec,
            has_use_remote_cipher_prefer: sec.use_remote_cipher_prefer.is_some(),
            use_remote_cipher_prefer: sec.use_remote_cipher_prefer.unwrap_or(false),
            has_signature_algorithms: sec.signature_algorithms.is_some(),
            signature_algorithms: sec.signature_algorithms.clone().unwrap_or_default(),
            has_cipher_suite: sec.cipher_suite.is_some(),
            cipher_suite: sec.cipher_suite.clone().unwrap_or_default(),
            has_is_bidirectional_authentication: sec.is_bidirectional_authentication.is_some(),
            is_bidirectional_authentication: sec.is_bidirectional_authentication.unwrap_or(false),
        }
    }
}

impl From<&ffi::FFITlsSecureOptions> for bridge::TLSSecureOptions {
    fn from(sec: &ffi::FFITlsSecureOptions) -> Self {
        // 从 Vec<String> 转回 Option<UnionCaCert>，优先保留原始结构
        let ca = if sec.has_ca {
            match sec.ca.len() {
                0 => None,
                1 => Some(bridge::UnionCaCert::S(sec.ca[0].clone())),
                _ => Some(bridge::UnionCaCert::Array(sec.ca.clone())),
            }
        } else {
            None
        };
        let cert = if sec.has_cert {
            match sec.cert.len() {
                0 => None,
                1 => Some(bridge::UnionCaCert::S(sec.cert[0].clone())),
                _ => Some(bridge::UnionCaCert::Array(sec.cert.clone())),
            }
        } else {
            None
        };

        let protocols = if sec.has_protocols {
            match sec.protocols.len() {
                0 => None,
                1 => Some(bridge::UnionProtocol::S(match &sec.protocols[0] {
                    &ffi::FFIProtocol::TLSv12 => bridge::Protocol::TLSv12,
                    &ffi::FFIProtocol::TLSv13 => bridge::Protocol::TLSv13,
                    _ => unreachable!(),
                })),
                _ => {
                    let v: Vec<bridge::Protocol> = sec
                        .protocols
                        .iter()
                        .map(|p| match p {
                            &ffi::FFIProtocol::TLSv12 => bridge::Protocol::TLSv12,
                            &ffi::FFIProtocol::TLSv13 => bridge::Protocol::TLSv13,
                            _ => unreachable!(),
                        })
                        .collect();
                    Some(bridge::UnionProtocol::Array(v))
                }
            }
        } else {
            None
        };

        bridge::TLSSecureOptions {
            ca,
            cert,
            key: if sec.has_key { Some(sec.key.clone()) } else { None },
            password: if sec.has_password { Some(sec.password.clone()) } else { None },
            protocols,
            use_remote_cipher_prefer: if sec.has_use_remote_cipher_prefer { Some(sec.use_remote_cipher_prefer) } else { None },
            signature_algorithms: if sec.has_signature_algorithms { Some(sec.signature_algorithms.clone()) } else { None },
            cipher_suite: if sec.has_cipher_suite { Some(sec.cipher_suite.clone()) } else { None },
            is_bidirectional_authentication: if sec.has_is_bidirectional_authentication { Some(sec.is_bidirectional_authentication) } else { None },
        }
    }
}

impl From<&bridge::SocketRemoteInfo> for ffi::FFISocketRemoteInfo {
    fn from(info: &bridge::SocketRemoteInfo) -> Self {
        ffi::FFISocketRemoteInfo {
            address: info.address.clone(),
            family: info.family.clone(),
            port: info.port,
            size: info.size,
        }
    }
}

impl From<&ffi::FFISocketRemoteInfo> for bridge::SocketRemoteInfo {
    fn from(info: &ffi::FFISocketRemoteInfo) -> Self {
        bridge::SocketRemoteInfo {
            address: info.address.clone(),
            family: info.family.clone(),
            port: info.port,
            size: info.size,
        }
    }
}

impl From<&bridge::X509CertRawData> for ffi::FFIX509CertRawData {
    fn from(cert: &bridge::X509CertRawData) -> Self {
        ffi::FFIX509CertRawData {
            data: cert.data.to_vec(),
            encoding_format: match cert.encoding_format {
                bridge::EncodingFormat::FormatDer => ffi::FFIEncodingFormat::FORMAT_DER,
                bridge::EncodingFormat::FormatPem => ffi::FFIEncodingFormat::FORMAT_PEM,
                bridge::EncodingFormat::FormatPkcs7 => ffi::FFIEncodingFormat::FORMAT_PKCS7,
                _ => unreachable!("invalid EncodingFormat value"),
            },
        }
    }
}

impl From<&ffi::FFIX509CertRawData> for bridge::X509CertRawData {
    fn from(cert: &ffi::FFIX509CertRawData) -> Self {
        bridge::X509CertRawData {
            data: Uint8Array::new_with_vec(cert.data.clone()),
            encoding_format: match cert.encoding_format {
                ffi::FFIEncodingFormat::FORMAT_DER => bridge::EncodingFormat::FormatDer,
                ffi::FFIEncodingFormat::FORMAT_PEM => bridge::EncodingFormat::FormatPem,
                ffi::FFIEncodingFormat::FORMAT_PKCS7 => bridge::EncodingFormat::FormatPkcs7,
                _ => unreachable!("invalid FFIEncodingFormat value"),
            },
        }
    }
}

impl From<&bridge::SocketStateBase> for ffi::FFISocketStateBase {
    fn from(state: &bridge::SocketStateBase) -> Self {
        ffi::FFISocketStateBase {
            is_bound: state.is_bound,
            is_close: state.is_close,
            is_connected: state.is_connected,
        }
    }
}

impl From<&ffi::FFISocketStateBase> for bridge::SocketStateBase {
    fn from(state: &ffi::FFISocketStateBase) -> Self {
        bridge::SocketStateBase {
            is_bound: state.is_bound,
            is_close: state.is_close,
            is_connected: state.is_connected,
        }
    }
}

impl From<&bridge::LocalAddress> for ffi::FFILocalAddress {
    fn from(addr: &bridge::LocalAddress) -> Self {
        ffi::FFILocalAddress {
            address: addr.address.clone(),
        }
    }
}

impl From<&ffi::FFILocalAddress> for bridge::LocalAddress {
    fn from(addr: &ffi::FFILocalAddress) -> Self {
        bridge::LocalAddress {
            address: addr.address.clone(),
        }
    }
}

impl From<&bridge::LocalConnectOptions> for ffi::FFILocalConnectOptions {
    fn from(opts: &bridge::LocalConnectOptions) -> Self {
        ffi::FFILocalConnectOptions {
            address: ffi::FFILocalAddress::from(&opts.address),
            has_timeout: opts.timeout.is_some(),
            timeout: opts.timeout.unwrap_or(0),
        }
    }
}

impl From<&ffi::FFILocalConnectOptions> for bridge::LocalConnectOptions {
    fn from(opts: &ffi::FFILocalConnectOptions) -> Self {
        bridge::LocalConnectOptions {
            address: bridge::LocalAddress::from(&opts.address),
            timeout: if opts.has_timeout { Some(opts.timeout) } else { None },
        }
    }
}

impl From<&bridge::LocalSendOptions> for ffi::FFILocalSendOptions {
    fn from(opts: &bridge::LocalSendOptions) -> Self {
        let data = match &opts.data {
            bridge::UnionData::S(s) => s.as_bytes().to_vec(),
            bridge::UnionData::ArrayBuffer(buf) => buf.to_vec(),
        };
        ffi::FFILocalSendOptions {
            data,
            has_encoding: opts.encoding.is_some(),
            encoding: opts.encoding.clone().unwrap_or_default(),
        }
    }
}

impl From<&bridge::TCPSendOptions> for ffi::FFITcpSendOptions {
    fn from(opts: &bridge::TCPSendOptions) -> Self {
        let data = match &opts.data {
            bridge::UnionData::S(s) => s.as_bytes().to_vec(),
            bridge::UnionData::ArrayBuffer(buf) => buf.to_vec(),
        };
        ffi::FFITcpSendOptions {
            data,
            has_encoding: opts.encoding.is_some(),
            encoding: opts.encoding.clone().unwrap_or_default(),
        }
    }
}

impl From<&bridge::TCPConnectOptions> for ffi::FFITcpConnectOptions {
    fn from(opts: &bridge::TCPConnectOptions) -> Self {
        let (has_proxy, proxy) = match &opts.proxy {
            Some(p) => (true, ffi::FFIProxyOptions::from(p)),
            None    => (false, ffi::FFIProxyOptions::default()),
        };
        ffi::FFITcpConnectOptions {
            address: ffi::FFINetAddress::from(&opts.address),
            has_timeout: opts.timeout.is_some(),
            timeout: opts.timeout.unwrap_or(0),
            has_proxy,
            proxy,
        }
    }
}

impl From<&ffi::FFITcpConnectOptions> for bridge::TCPConnectOptions {
    fn from(opts: &ffi::FFITcpConnectOptions) -> Self {
        bridge::TCPConnectOptions {
            address: bridge::NetAddress::from(&opts.address),
            timeout: if opts.has_timeout { Some(opts.timeout) } else { None },
            proxy: if opts.has_proxy { Some(bridge::ProxyOptions::from(&opts.proxy)) } else { None },
        }
    }
}

impl From<&bridge::UDPSendOptions> for ffi::FFIUdpSendOptions {
    fn from(opts: &bridge::UDPSendOptions) -> Self {
        let data = match &opts.data {
            bridge::UnionData::S(s) => s.as_bytes().to_vec(),
            bridge::UnionData::ArrayBuffer(buf) => buf.to_vec(),
        };
        let (has_proxy, proxy) = match &opts.proxy {
            Some(p) => (true, ffi::FFIProxyOptions::from(p)),
            None    => (false, ffi::FFIProxyOptions::default()),
        };
        ffi::FFIUdpSendOptions {
            data,
            address: ffi::FFINetAddress::from(&opts.address),
            has_proxy,
            proxy,
        }
    }
}

impl From<&bridge::TLSConnectOptions> for ffi::FFITlsConnectOptions {
    fn from(opts: &bridge::TLSConnectOptions) -> Self {
        let (has_proxy, proxy) = match &opts.proxy {
            Some(p) => (true, ffi::FFIProxyOptions::from(p)),
            None    => (false, ffi::FFIProxyOptions::default()),
        };
        ffi::FFITlsConnectOptions {
            address: ffi::FFINetAddress::from(&opts.address),
            secure_options: ffi::FFITlsSecureOptions::from(&opts.secure_options),
            has_alpn_protocols: opts.alpn_protocols.is_some(),
            alpn_protocols: opts.alpn_protocols.clone().unwrap_or_default(),
            has_skip_remote_validation: opts.skip_remote_validation.is_some(),
            skip_remote_validation: opts.skip_remote_validation.unwrap_or(false),
            has_ssl_server_hostname_verification: opts.ssl_server_hostname_verification.is_some(),
            ssl_server_hostname_verification: opts.ssl_server_hostname_verification.unwrap_or(false),
            has_proxy,
            proxy,
            has_timeout: opts.timeout.is_some(),
            timeout: opts.timeout.unwrap_or(0),
        }
    }
}

impl From<&ffi::FFITlsConnectOptions> for bridge::TLSConnectOptions {
    fn from(opts: &ffi::FFITlsConnectOptions) -> Self {
        bridge::TLSConnectOptions {
            address: bridge::NetAddress::from(&opts.address),
            secure_options: bridge::TLSSecureOptions::from(&opts.secure_options),
            alpn_protocols: if opts.has_alpn_protocols { Some(opts.alpn_protocols.clone()) } else { None },
            skip_remote_validation: if opts.has_skip_remote_validation { Some(opts.skip_remote_validation) } else { None },
            ssl_server_hostname_verification: if opts.has_ssl_server_hostname_verification { Some(opts.ssl_server_hostname_verification) } else { None },
            proxy: if opts.has_proxy { Some(bridge::ProxyOptions::from(&opts.proxy)) } else { None },
            timeout: if opts.has_timeout { Some(opts.timeout) } else { None },
        }
    }
}