/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "socket_ani.h"
#include "wrapper.rs.h"
#include "socket_state_base.h"
#include "extra_options_base.h"
#include "tcp_connect_options.h"
#include "tcp_extra_options.h"
#include "tcp_send_options.h"
#include "udp_extra_options.h"
#include "net_address.h"
#include "proxy_options.h"
#include "socket_constant.h"
#include "socket_exec_error.h"
#include "udp_send_options.h"
#include "udp_socket_innerapi.h"
#include "local_socket_client_innerapi.h"
#include "local_socket_server_innerapi.h"
#include "tcp_socket_client_innerapi.h"
#include "tcp_socket_server_innerapi.h"
#include <string>

#include "socket_error.h"

namespace OHOS {
namespace NetStackAni {

using namespace NetStack;

rust::String GetErrorCodeAndMessage(int32_t &errorCode)
{
    if (errorCode == 0) {
        return rust::string("Success");
    }

    std::string msg = NetStack::Socket::GetSocketErrorMessage(errorCode);
    if (msg.empty()) {
        msg = "Unknown error";
    }
    return rust::string(msg);
}

std::vector<std::string> RustVecToStdVector(const rust::Vec<rust::String>& src)
{
    std::vector<std::string> dst;
    dst.reserve(src.size());
    for (const auto& s : src) {
        dst.push_back(std::string(s));
    }
    return dst;
}

Socket::ProxyType FFIProxyTypeToProxyType(FFIProxyTypes ffiType)
{
    switch (ffiType) {
        case FFIProxyTypes::SOCKS5: return Socket::ProxyType::SOCKS5;
        default:                    return Socket::ProxyType::NONE;
    }
}

std::string FFIProtocolToStdString(FFIProtocol proto)
{
    switch (proto) {
        case FFIProtocol::TLSv12: return "TLSv1.2";
        case FFIProtocol::TLSv13: return "TLSv1.3";
        default:                  return "";
    }
}

FFIEncodingFormat EncodingFormatToFFIEncodingFormat(TlsSocket::EncodingFormat fmt)
{
    return fmt == TlsSocket::EncodingFormat::PEM ? FFIEncodingFormat::FORMAT_PEM
                                      : FFIEncodingFormat::FORMAT_DER;
}

TlsSocket::VerifyMode FFIBidirectionalAuthToVerifyMode(bool isBidirectional)
{
    return isBidirectional ? TlsSocket::TWO_WAY_MODE : TlsSocket::ONE_WAY_MODE;
}

void FFINetAddressToNetAddress(const FFINetAddress& ffi, Socket::NetAddress& addr)
{
    if (ffi.has_family) {
        addr.SetFamilyByJsValue(static_cast<sa_family_t>(ffi.family));
    }
    if (ffi.has_port) {
        addr.SetPort(static_cast<uint16_t>(ffi.port));
    }
    addr.SetAddress(std::string(ffi.address));
}

void NetAddressToFFINetAddress(const Socket::NetAddress& addr, FFINetAddress& ffi)
{
    ffi.address = rust::String(addr.GetAddress());
    ffi.has_family = true;
    ffi.family = static_cast<int32_t>(addr.GetJsValueFamily());
    ffi.has_port = true;
    ffi.port = static_cast<int32_t>(addr.GetPort());
}


void FFITcpExtraOptionsToTCPExtraOptions(const FFITcpExtraOptions& ffi, Socket::TCPExtraOptions& opts)
{
    if (ffi.has_receive_buffer_size) {
        opts.SetReceiveBufferSize(static_cast<uint32_t>(ffi.receive_buffer_size));
        opts.SetRecvBufSizeFlag(true);
    }
    if (ffi.has_send_buffer_size) {
        opts.SetSendBufferSize(static_cast<uint32_t>(ffi.send_buffer_size));
        opts.SetSendBufSizeFlag(true);
    }
    if (ffi.has_reuse_address) {
        opts.SetReuseAddress(ffi.reuse_address);
        opts.SetReuseaddrFlag(true);
    }
    if (ffi.has_socket_timeout) {
        opts.SetSocketTimeout(static_cast<uint32_t>(ffi.socket_timeout));
        opts.SetTimeoutFlag(true);
    }
    if (ffi.has_keep_alive) {
        opts.SetKeepAlive(ffi.keep_alive);
        opts.SetKeepAliveFlag(true);
    }
    if (ffi.has_oob_inline) {
        opts.SetOOBInline(ffi.oob_inline);
        opts.SetOobInlineFlag(true);
    }
    if (ffi.has_tcp_no_delay) {
        opts.SetTCPNoDelay(ffi.tcp_no_delay);
        opts.SetTcpNoDelayFlag(true);
    }
    if (ffi.has_tcp_fast_open) {
        opts.SetTCPFastOpen(ffi.tcp_fast_open);
        opts.SetTcpFastOpenFlag(true);
    }
    if (ffi.has_socket_linger) {
        opts.socketLinger.SetOn(ffi.socket_linger_on);
        opts.socketLinger.SetLinger(static_cast<uint32_t>(ffi.socket_linger_linger));
        opts.SetLingerFlag(true);
    }
}

void FFITlsSecureOptionsToTLSSecureOptions(const FFITlsSecureOptions& ffi, TlsSocket::TLSSecureOptions& opts)
{
    if (ffi.has_ca) {
        opts.SetCaChain(RustVecToStdVector(ffi.ca));
    }
    if (ffi.has_cert) {
        opts.SetCertChain(RustVecToStdVector(ffi.cert));
    }
    if (ffi.has_key) {
        opts.SetKey(TlsSocket::SecureData(std::string(ffi.key)));
    }
    if (ffi.has_password) {
        opts.SetKeyPass(TlsSocket::SecureData(std::string(ffi.password)));
    }

    if (ffi.has_protocols) {
        std::vector<std::string> protocols;
        for (auto& p : ffi.protocols)
            protocols.push_back(FFIProtocolToStdString(static_cast<FFIProtocol>(p)));
        opts.SetProtocolChain(protocols);
    }
    if (ffi.has_use_remote_cipher_prefer) {
        opts.SetUseRemoteCipherPrefer(ffi.use_remote_cipher_prefer);
    }
    if (ffi.has_signature_algorithms) {
        opts.SetSignatureAlgorithms(std::string(ffi.signature_algorithms));
    }
    if (ffi.has_cipher_suite) {
        opts.SetCipherSuite(std::string(ffi.cipher_suite));
    }
    if (ffi.has_is_bidirectional_authentication) {
        opts.SetVerifyMode(FFIBidirectionalAuthToVerifyMode(ffi.is_bidirectional_authentication));
    }
}

void FFIProxyOptionsToProxyOptions(const FFIProxyOptions& ffi, Socket::ProxyOptions& opts)
{
    opts.type_ = FFIProxyTypeToProxyType(static_cast<FFIProxyTypes>(ffi.type_));
    if (opts.type_ != Socket::ProxyType::NONE) {
        FFINetAddressToNetAddress(ffi.address, opts.address_);
        if (ffi.has_username) {
            opts.username_ = TlsSocket::SecureData(std::string(ffi.username));
        }
        if (ffi.has_password) {
            opts.password_ = TlsSocket::SecureData(std::string(ffi.password));
        }
    }
}

void ApplyAddressAndSecure(const FFITlsConnectOptions& ffi, TlsSocket::TLSConnectOptions& opts)
{
    Socket::NetAddress addr;
    FFINetAddressToNetAddress(ffi.address, addr);
    opts.SetNetAddress(addr);
    opts.SetHostName(addr.GetAddress());

    TlsSocket::TLSSecureOptions secure;
    FFITlsSecureOptionsToTLSSecureOptions(ffi.secure_options, secure);
    opts.SetTlsSecureOptions(secure);
}

void ApplyTlsProxyOption(const FFITlsConnectOptions& ffi, TlsSocket::TLSConnectOptions& opts)
{
    if (ffi.has_proxy) {
        auto proxy = std::make_shared<Socket::ProxyOptions>();
        FFIProxyOptionsToProxyOptions(ffi.proxy, *proxy);
        opts.proxyOptions_ = proxy;
    }
}

void ApplyTlsOptionalFields(const FFITlsConnectOptions& ffi, TlsSocket::TLSConnectOptions& opts)
{
    if (ffi.has_alpn_protocols) { opts.SetAlpnProtocols(RustVecToStdVector(ffi.alpn_protocols)); }
    if (ffi.has_skip_remote_validation) { opts.SetSkipRemoteValidation(ffi.skip_remote_validation); }
    if (ffi.has_ssl_server_hostname_verification) {
        opts.SetSslServerHostnameVerification(ffi.ssl_server_hostname_verification);
    }
    if (ffi.has_timeout) { opts.SetTimeout(static_cast<uint32_t>(ffi.timeout)); }
    ApplyTlsProxyOption(ffi, opts);
}

void FFITlsConnectOptionsToTLSConnectOptions(const FFITlsConnectOptions& ffi, TlsSocket::TLSConnectOptions& opts)
{
    ApplyAddressAndSecure(ffi, opts);
    ApplyTlsOptionalFields(ffi, opts);
}

void FFITcpSendOptionsToTCPSendOptions(const FFITcpSendOptions& ffi, Socket::TCPSendOptions& opts)
{
    if (!ffi.data.empty()) {
        opts.SetData(std::string(ffi.data.begin(), ffi.data.end()));
    }
    if (ffi.has_encoding) {
        opts.SetEncoding(std::string(ffi.encoding));
    }
}

void SocketStateBaseToFFISocketStateBase(const Socket::SocketStateBase& state, FFISocketStateBase& ffi)
{
    ffi.is_bound = state.IsBound();
    ffi.is_close = state.IsClose();
    ffi.is_connected = state.IsConnected();
}

void X509CertRawDataToFFIX509CertRawData(const TlsSocket::X509CertRawData& cert, FFIX509CertRawData& ffi)
{
    const char* d = cert.data.Data();
    size_t len = cert.data.Length();
    ffi.data.clear();
    ffi.data.reserve(len);
    for (size_t i = 0; i < len; ++i) {
        ffi.data.push_back(static_cast<uint8_t>(d[i]));
    }
    ffi.encoding_format = EncodingFormatToFFIEncodingFormat(cert.encodingFormat);
}
} // namespace NetStackAni
} // namespace OHOS
