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

use ani_rs::typed_array::Uint8Array;
use ani_rs::typed_array::ArrayBuffer;
use serde::{Deserialize, Serialize};
use serde::de::{self, Visitor, Unexpected};
use std::fmt;

pub fn convert_to_business_error(mut code: i32) -> ani_rs::business_error::BusinessError {
    let error_msg = crate::wrapper::ffi::GetErrorCodeAndMessage(&mut code);
    ani_rs::business_error::BusinessError::new(code, error_msg)
}

#[derive(Deserialize, Serialize)]
pub enum UnionData {
    S(String),
    ArrayBuffer(ArrayBuffer),
}

#[derive(Deserialize, Serialize)]
pub enum UnionCaCert {
    S(String),
    Array(Vec<String>),
}

#[derive(Deserialize, Serialize)]
pub enum UnionProtocol {
    #[serde(rename = "@ohos.net.socket.socket.Protocol")]
    S(Protocol),
    Array(Vec<Protocol>),
}

#[ani_rs::ani(path = "@ohos.net.socket.socket.ProxyTypes")]
#[derive(Debug, Clone, Copy)]
pub enum ProxyTypes {
    NONE = 0,
    SOCKS5 = 1,
}

#[ani_rs::ani(path = "@ohos.net.socket.socket.Protocol")]
#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    TLSv12 = 1,
    TLSv13 = 2,
}

#[ani_rs::ani(path = "@ohos.security.cert.cert.EncodingFormat")]
pub enum EncodingFormat {
    FormatDer = 0,
    FormatPem = 1,
    FormatPkcs7 = 2,
}

#[ani_rs::ani(path = "@ohos.net.socket.socket.X509CertRawDataInner")]
pub struct X509CertRawData {
    pub data: Uint8Array,
    pub encoding_format: EncodingFormat,
}

#[ani_rs::ani(path = "@ohos.net.socket.socket.SocketStateBaseInner")]
pub struct SocketStateBase {
    pub is_bound: bool,
    pub is_close: bool,
    pub is_connected: bool,
}

#[ani_rs::ani(path = "@ohos.net.connection.connection.NetAddressInner")]
pub struct NetAddress {
    pub address: String,
    pub family: Option<i32>,
    pub port: Option<i32>,
}

#[ani_rs::ani(path = "@ohos.net.socket.socket.ExtraOptionsBaseInner")]
pub struct ExtraOptionsBase {
    pub receive_buffer_size: Option<i32>,
    pub send_buffer_size: Option<i32>,
    pub reuse_address: Option<bool>,
    pub socket_timeout: Option<i32>,
}

#[ani_rs::ani(path = "@ohos.net.socket.socket.UDPSendOptionsInner")]
pub struct UDPSendOptions {
    pub data: UnionData,
    pub address: NetAddress,
    pub proxy: Option<ProxyOptions>,
}

#[ani_rs::ani(path = "@ohos.net.socket.socket.ProxyOptionsInner")]
pub struct ProxyOptions {
    pub type_: ProxyTypes,
    pub address: NetAddress,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[ani_rs::ani(path = "@ohos.net.socket.socket.UDPExtraOptionsInner")]
pub struct UDPExtraOptions {
    pub receive_buffer_size: Option<i32>,
    pub send_buffer_size: Option<i32>,
    pub reuse_address: Option<bool>,
    pub socket_timeout: Option<i32>,
    pub broadcast: Option<bool>,
}

#[ani_rs::ani(path = "@ohos.net.socket.socket.SocketRemoteInfoInner")]
pub struct SocketRemoteInfo {
    pub address: String,
    pub family: String,
    pub port: i32,
    pub size: i32,
}

#[ani_rs::ani(path = "@ohos.net.socket.socket.LocalSocketMessageInfoInner")]
pub struct LocalSocketMessageInfo {
    pub message: ArrayBuffer,
    pub address: String,
    pub size: i32,
}

#[ani_rs::ani(path = "@ohos.net.socket.socket.LocalAddressInner")]
pub struct LocalAddress {
    pub address: String,
}

#[ani_rs::ani(path = "@ohos.net.socket.socket.LocalConnectOptionsInner")]
pub struct LocalConnectOptions {
    pub address: LocalAddress,
    pub timeout: Option<i32>,
}

#[ani_rs::ani(path = "@ohos.net.socket.socket.LocalSendOptionsInner")]
pub struct LocalSendOptions {
    pub data: UnionData,
    pub encoding: Option<String>,
}

#[ani_rs::ani(path = "@ohos.net.socket.socket.TCPConnectOptionsInner")]
pub struct TCPConnectOptions {
    pub address: NetAddress,
    pub timeout: Option<i32>,
    pub proxy: Option<ProxyOptions>,
}

#[ani_rs::ani(path = "@ohos.net.socket.socket.TCPSendOptionsInner")]
pub struct TCPSendOptions {
    pub data: UnionData,
    pub encoding: Option<String>,
}

#[ani_rs::ani(path = "@ohos.net.socket.socket.SocketLingerOptionsInner")]
pub struct SocketLingerOptions {
    pub on: Option<bool>,
    pub linger: Option<i32>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename = "@ohos.net.socket.socket.TCPExtraOptionsInner\0")]
pub struct TCPExtraOptions {
    #[serde(rename = "receiveBufferSize\0")]
    pub receive_buffer_size: Option<i32>,
    #[serde(rename = "sendBufferSize\0")]
    pub send_buffer_size: Option<i32>,
    #[serde(rename = "reuseAddress\0")]
    pub reuse_address: Option<bool>,
    #[serde(rename = "socketTimeout\0")]
    pub socket_timeout: Option<i32>,
    #[serde(rename = "keepAlive\0")]
    pub keep_alive: Option<bool>,
    #[serde(rename = "OOBInline\0")]
    pub oob_inline: Option<bool>,
    #[serde(rename = "TCPNoDelay\0")]
    pub tcp_no_delay: Option<bool>,
    #[serde(rename = "socketLinger\0")]
    pub socket_linger: Option<SocketLingerOptions>,
    #[serde(rename = "tcpFastOpen\0")]
    pub tcp_fast_open: Option<bool>,
}

#[ani_rs::ani(path = "@ohos.net.socket.socket.TLSSecureOptionsInner")]
pub struct TLSSecureOptions {
    pub ca: Option<UnionCaCert>,
    pub cert: Option<UnionCaCert>,
    pub key: Option<String>,
    pub password: Option<String>,
    pub protocols: Option<UnionProtocol>,
    pub use_remote_cipher_prefer: Option<bool>,
    pub signature_algorithms: Option<String>,
    pub cipher_suite: Option<String>,
    pub is_bidirectional_authentication: Option<bool>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename = "@ohos.net.socket.socket.TLSConnectOptionsInner\0")]
pub struct TLSConnectOptions {
    #[serde(rename = "address\0")]
    pub address: NetAddress,
    #[serde(rename = "secureOptions\0")]
    pub secure_options: TLSSecureOptions,
    #[serde(rename = "ALPNProtocols\0")]
    pub alpn_protocols: Option<Vec<String>>,
    #[serde(rename = "skipRemoteValidation\0")]
    pub skip_remote_validation: Option<bool>,
    #[serde(rename = "proxy\0")]
    pub proxy: Option<ProxyOptions>,
    #[serde(rename = "timeout\0")]
    pub timeout: Option<i32>,
}

#[ani_rs::ani(path = "@ohos.net.socket.socket.SocketMessageInfoInner")]
pub struct SocketMessageInfo {
    pub message: ArrayBuffer,
    pub remote_info: SocketRemoteInfo,
}

#[ani_rs::ani(path = "@ohos.net.socket.socket.UDPSocketInner")]
pub struct UDPSocketClient {
    pub native_ptr: i64,
    pub socket_fd: i32,
}

#[ani_rs::ani(path = "@ohos.net.socket.socket.MulticastSocketInner")]
pub struct MulticastSocketClient {
    pub native_ptr: i64,
}

#[ani_rs::ani(path = "@ohos.net.socket.socket.LocalSocketInner")]
pub struct LocalSocketClient {
    pub native_ptr: i64,
}

#[ani_rs::ani(path = "@ohos.net.socket.socket.LocalSocketConnectionInner")]
pub struct LocalSocketConnection {
    pub native_ptr: i64,
    pub client_id: i32,
}

#[ani_rs::ani(path = "@ohos.net.socket.socket.LocalSocketServerInner")]
pub struct LocalSocketServer {
    pub native_ptr: i64,
}

#[ani_rs::ani(path = "@ohos.net.socket.socket.TCPSocketInner")]
pub struct TCPSocketClient {
    pub native_ptr: i64,
    pub socket_fd: i32,
}

#[ani_rs::ani(path = "@ohos.net.socket.socket.TCPSocketConnectionInner")]
pub struct TCPSocketConnect {
    pub native_ptr: i64,
    pub client_id: i32,
}

#[ani_rs::ani(path = "@ohos.net.socket.socket.TCPSocketServerInner")]
pub struct TCPSocketServer {
    pub native_ptr: i64,
}

#[ani_rs::ani(path = "@ohos.net.socket.socket.TLSSocketInner")]
pub struct TLSSocketClient {
    pub native_ptr: i64,
}

#[ani_rs::ani(path = "@ohos.net.socket.socket.TLSSocketConnectionInner")]
pub struct TLSSocketConnect {
    pub native_ptr: i64,
    pub client_id: i32,
}

#[ani_rs::ani(path = "@ohos.net.socket.socket.TLSSocketServerInner")]
pub struct TLSSocketServer {
    pub native_ptr: i64,
}
