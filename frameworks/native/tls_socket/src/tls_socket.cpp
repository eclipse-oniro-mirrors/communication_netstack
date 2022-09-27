/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <chrono>
#include <netinet/tcp.h>
#include <thread>

#include "netstack_log.h"
#include "securec.h"

#include "tls_socket.h"

namespace OHOS {
namespace NetStack {

namespace {
constexpr int WAIT_MS = 10;
constexpr int TIMEOUT_MS = 10000;
}

TLSSecureOptions& TLSSecureOptions::operator=(const TLSSecureOptions &tlsSecureOptions)
{
    key_ = tlsSecureOptions.GetKey();
    caChain_ = tlsSecureOptions.GetCaChain();
    cert_ = tlsSecureOptions.GetCert();
    protocolChain_ = tlsSecureOptions.GetProtocolChain();
    crlChain_ = tlsSecureOptions.GetCrlChain();
    passwd_ = tlsSecureOptions.GetPasswd();
    signatureAlgorithms_ = tlsSecureOptions.GetSignatureAlgorithms();
    cipherSuite_ = tlsSecureOptions.GetCipherSuite();
    useRemoteCipherPrefer_ = tlsSecureOptions.UseRemoteCipherPrefer();
    return *this;
}

void TLSSecureOptions::SetCaChain(const std::vector<std::string> &caChain)
{
    caChain_ = caChain;
}

void TLSSecureOptions::SetCert(const std::string &cert)
{
    cert_ = cert;
}

void TLSSecureOptions::SetKey(const std::string &key)
{
    key_ = key;
}

void TLSSecureOptions::SetPassWd(const std::string &passwd)
{
    passwd_ = passwd;
}

void TLSSecureOptions::SetProtocolChain(const std::vector<std::string> &protocolChain)
{
    protocolChain_ = protocolChain;
}

void TLSSecureOptions::SetUseRemoteCipherPrefer(bool useRemoteCipherPrefer)
{
    useRemoteCipherPrefer_ = useRemoteCipherPrefer;
}

void TLSSecureOptions::SetSignatureAlgorithms(const std::string &signatureAlgorithms)
{
    signatureAlgorithms_ = signatureAlgorithms;
}

void TLSSecureOptions::SetCipherSuite(const std::string &cipherSuite)
{
    cipherSuite_ = cipherSuite;
}

void TLSSecureOptions::SetCrlChain(const std::vector<std::string> &crlChain)
{
    crlChain_ = crlChain;
}

const std::vector<std::string>& TLSSecureOptions::GetCaChain() const
{
    return caChain_;
}

const std::string& TLSSecureOptions::GetCert() const
{
    return cert_;
}

const std::string& TLSSecureOptions::GetKey() const
{
    return key_;
}

const std::string& TLSSecureOptions::GetPasswd() const
{
    return passwd_;
}

const std::vector<std::string>& TLSSecureOptions::GetProtocolChain() const
{
    return protocolChain_;
}

bool TLSSecureOptions::UseRemoteCipherPrefer() const
{
    return useRemoteCipherPrefer_;
}

const std::string& TLSSecureOptions::GetSignatureAlgorithms() const
{
    return signatureAlgorithms_;
}

const std::string& TLSSecureOptions::GetCipherSuite() const
{
    return cipherSuite_;
}

const std::vector<std::string>& TLSSecureOptions::GetCrlChain() const
{
    return crlChain_;
}

void TLSConnectOptions::SetNetAddress(const NetAddress &address)
{
    address_.SetAddress(address.GetAddress());
    address_.SetPort(address.GetPort());
    address_.SetFamilyBySaFamily(address.GetSaFamily());
}

void TLSConnectOptions::SetTlsSecureOptions(TLSSecureOptions &tlsSecureOptions)
{
    tlsSecureOptions_ = tlsSecureOptions;
}

void TLSConnectOptions::SetCheckServerIdentity(const CheckServerIdentity &checkServerIdentity)
{
    checkServerIdentity_ = checkServerIdentity;
}

void TLSConnectOptions::SetAlpnProtocols(const std::vector<std::string> &alpnProtocols)
{
    alpnProtocols_ = alpnProtocols;
}

NetAddress TLSConnectOptions::GetNetAddress() const
{
    return address_;
}

TLSSecureOptions TLSConnectOptions::GetTlsSecureOptions() const
{
    return tlsSecureOptions_;
}

CheckServerIdentity TLSConnectOptions::GetCheckServerIdentity() const
{
    return checkServerIdentity_;
}

const std::vector<std::string>& TLSConnectOptions::GetAlpnProtocols() const
{
    return alpnProtocols_;
}

std::string TLSSocket::MakeErrnoString()
{
    return strerror(errno);
}

std::string TLSSocket::MakeAddressString(sockaddr *addr)
{
    if (addr->sa_family == AF_INET) {
        auto *addr4 = reinterpret_cast<sockaddr_in *>(addr);
        const char *str = inet_ntoa(addr4->sin_addr);
        if (str == nullptr || strlen(str) == 0) {
            return {};
        }
        return str;
    } else if (addr->sa_family == AF_INET6) {
        auto *addr6 = reinterpret_cast<sockaddr_in6 *>(addr);
        char str[INET6_ADDRSTRLEN] = {0};
        if (inet_ntop(AF_INET6, &addr6->sin6_addr, str, INET6_ADDRSTRLEN) == nullptr || strlen(str) == 0) {
            return {};
        }
        return str;
    }
    return {};
}

void TLSSocket::GetAddr(const NetAddress &address,
                        sockaddr_in *addr4,
                        sockaddr_in6 *addr6,
                        sockaddr **addr,
                        socklen_t *len)
{
    sa_family_t family = address.GetSaFamily();
    if (family == AF_INET) {
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(address.GetPort());
        addr4->sin_addr.s_addr = inet_addr(address.GetAddress().c_str());
        *addr = reinterpret_cast<sockaddr *>(addr4);
        *len = sizeof(sockaddr_in);
    } else if (family == AF_INET6) {
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons(address.GetPort());
        inet_pton(AF_INET6, address.GetAddress().c_str(), &addr6->sin6_addr);
        *addr = reinterpret_cast<sockaddr *>(addr6);
        *len = sizeof(sockaddr_in6);
    }
}

void TLSSocket::MakeTcpSocket(sa_family_t family)
{
    if (family != AF_INET && family != AF_INET6) {
        return;
    }
    sockFd_ = socket(family, SOCK_STREAM, IPPROTO_TCP);
}

void TLSSocket::StartReadMessage()
{
    std::thread thread([this]() {
        isRunning_ = true;
        isRunOver_ = false;
        char buffer[MAX_BUFFER_SIZE];
        bzero(buffer, MAX_BUFFER_SIZE);
        while (isRunning_) {
            int len = openSslContext_.tlsSocketInternal_.GetRead(buffer, MAX_BUFFER_SIZE);
            if (!isRunning_) {
                break;
            }
            if (len < 0) {
                NETSTACK_LOGE("SSL_read errno is %{public}d %{public}s", errno, MakeErrnoString().c_str());
                CallOnErrorCallback(errno, MakeErrnoString());
                break;
            }

            if (len == 0) {
                continue;
            }

            SocketRemoteInfo remoteInfo;
            openSslContext_.tlsSocketInternal_.MakeRemoteInfo(remoteInfo);
            CallOnMessageCallback(buffer, remoteInfo);
        }
        isRunOver_ = true;
    });
    thread.detach();
}

TLSSocket::~TLSSocket()
{
    if (sockFd_ < 0) {
        CallOnErrorCallback(errno, MakeErrnoString());
        return;
    }

    int ret = close(sockFd_);
    if (ret < 0) {
        NETSTACK_LOGE("close errno is %{public}d %{public}s", errno, MakeErrnoString().c_str());
        CallOnErrorCallback(errno, MakeErrnoString());
        return;
    }

    CallOnCloseCallback();
}

void TLSSocket::CallOnMessageCallback(const std::string &data, const OHOS::NetStack::SocketRemoteInfo &remoteInfo)
{
    OnMessageCallback func = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (onMessageCallback_) {
            func = onMessageCallback_;
        }
    }

    if (func) {
        func(data, remoteInfo);
    }
}

void TLSSocket::CallOnConnectCallback()
{
    OnConnectCallback func = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (onConnectCallback_) {
            func = onConnectCallback_;
        }
    }

    if (func) {
        func();
    }
}

void TLSSocket::CallOnCloseCallback()
{
    OnCloseCallback func = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (onCloseCallback_) {
            func = onCloseCallback_;
        }
    }

    if (func) {
        func();
    }
}

void TLSSocket::CallOnErrorCallback(int32_t err, const std::string &errString)
{
    OnErrorCallback func = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (onErrorCallback_) {
            func = onErrorCallback_;
        }
    }

    if (func) {
        func(err, errString);
    }
}

void TLSSocket::CallBindCallback(bool ok, const BindCallback &callback)
{
    BindCallback func = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (bindCallback_) {
            func = bindCallback_;
        }
    }

    if (func) {
        func(ok);
    }
}

void TLSSocket::CallConnectCallback(bool ok, const ConnectCallback &callback)
{
    ConnectCallback func = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (connectCallback_) {
            func = connectCallback_;
        }
    }

    if (func) {
        func(ok);
    }
}

void TLSSocket::CallSendCallback(bool ok, const SendCallback &callback)
{
    SendCallback func = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (sendCallback_) {
            func = sendCallback_;
        }
    }

    if (func) {
        func(ok);
    }
}

void TLSSocket::CallCloseCallback(bool ok, const CloseCallback &callback)
{
    CloseCallback func = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (closeCallback_) {
            func = closeCallback_;
        }
    }

    if (func) {
        func(ok);
    }
}

void TLSSocket::CallGetRemoteAddressCallback(bool ok, const NetAddress &address,
                                             const GetRemoteAddressCallback &callback)
{
    GetRemoteAddressCallback func = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (getRemoteAddressCallback_) {
            func = getRemoteAddressCallback_;
        }
    }

    if (func) {
        func(ok, address);
    }
}

void TLSSocket::CallGetStateCallback(bool ok, const SocketStateBase &state,
                                     const GetStateCallback &callback)
{
    GetStateCallback func = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (getStateCallback_) {
            func = getStateCallback_;
        }
    }

    if (func) {
        func(ok, state);
    }
}

void TLSSocket::CallSetExtraOptionsCallback(bool ok, const SetExtraOptionsCallback &callback)
{
    SetExtraOptionsCallback func = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (setExtraOptionsCallback_) {
            func = setExtraOptionsCallback_;
        }
    }

    if (func) {
        func(ok);
    }
}

void TLSSocket::CallGetCertificateCallback(bool ok, const std::string &cert)
{
    GetCertificateCallback func = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (getCertificateCallback_) {
            func = getCertificateCallback_;
        }
    }

    if (func) {
        func(ok, cert);
    }
}

void TLSSocket::CallGetRemoteCertificateCallback(bool ok, const std::string &cert)
{
    GetRemoteCertificateCallback func = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (getRemoteCertificateCallback_) {
            func = getRemoteCertificateCallback_;
        }
    }

    if (func) {
        func(ok, cert);
    }
}

void TLSSocket::CallGetProtocolCallback(bool ok, const std::string &protocol)
{
    GetProtocolCallback func = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (getProtocolCallback_) {
            func = getProtocolCallback_;
        }
    }

    if (func) {
        func(ok, protocol);
    }
}

void TLSSocket::CallGetCipherSuiteCallback(bool ok, const std::vector<std::string> &suite)
{
    GetCipherSuiteCallback func = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (getCipherSuiteCallback_) {
            func = getCipherSuiteCallback_;
        }
    }

    if (func) {
        func(ok, suite);
    }
}

void TLSSocket::CallGetSignatureAlgorithmsCallback(bool ok,
                                                   const std::vector<std::string> &algorithms)
{
    GetSignatureAlgorithmsCallback func = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (getSignatureAlgorithmsCallback_) {
            func = getSignatureAlgorithmsCallback_;
        }
    }

    if (func) {
        func(ok, algorithms);
    }
}

void TLSSocket::Bind(const OHOS::NetStack::NetAddress &address,
                     const OHOS::NetStack::BindCallback &callback)
{
    if (sockFd_ >= 0) {
        CallBindCallback(true, callback);
        return;
    }

    MakeTcpSocket(address.GetSaFamily());
    if (sockFd_ < 0) {
        NETSTACK_LOGE("make tcp socket failed errno is %{public}d %{public}s", errno, MakeErrnoString().c_str());
        CallOnErrorCallback(errno, MakeErrnoString());
        CallBindCallback(false, callback);
        return;
    }

    sockaddr_in addr4 = {0};
    sockaddr_in6 addr6 = {0};
    sockaddr *addr = nullptr;
    socklen_t len;
    GetAddr(address, &addr4, &addr6, &addr, &len);
    if (addr == nullptr) {
        NETSTACK_LOGE("TLSSocket::Bind Address Is Invalid");
        CallOnErrorCallback(-1, "Address Is Invalid");
        CallBindCallback(false, callback);
        return;
    }

    if (bind(sockFd_, addr, len) < 0) {
        if (errno != EADDRINUSE) {
            NETSTACK_LOGE("TLSSocket::Bind bind error is %{public}s %{public}d", MakeErrnoString().c_str(), errno);
            CallOnErrorCallback(errno, MakeErrnoString());
            CallBindCallback(false, callback);
            return;
        }

        if (addr->sa_family == AF_INET) {
            addr4.sin_port = 0; /* distribute a random port */
        } else if (addr->sa_family == AF_INET6) {
            addr6.sin6_port = 0; /* distribute a random port */
        }

        if (bind(sockFd_, addr, len) < 0) {
            NETSTACK_LOGE("TLSSocket::Bind rebind error is %{public}s %{public}d", MakeErrnoString().c_str(), errno);
            CallOnErrorCallback(errno, MakeErrnoString());
            CallBindCallback(false, callback);
            return;
        }
    }

    CallBindCallback(true, callback);
}

void TLSSocket::Connect(OHOS::NetStack::TLSConnectOptions &tlsConnectOptions,
                        const OHOS::NetStack::ConnectCallback &callback)
{
    TlsConnectOptions options;
    TlsSecureOptions secureOptions;
    secureOptions.SetKey(tlsConnectOptions.GetTlsSecureOptions().GetKey());
    secureOptions.SetCa(tlsConnectOptions.GetTlsSecureOptions().GetCaChain());
    secureOptions.SetCert(tlsConnectOptions.GetTlsSecureOptions().GetCert());
    secureOptions.SetProtocol(tlsConnectOptions.GetTlsSecureOptions().GetProtocolChain());
    secureOptions.SetCrl(tlsConnectOptions.GetTlsSecureOptions().GetCrlChain());
    secureOptions.SetPasswd(tlsConnectOptions.GetTlsSecureOptions().GetPasswd());
    secureOptions.SetSignatureAlgorithms(tlsConnectOptions.GetTlsSecureOptions().GetSignatureAlgorithms());
    secureOptions.SetCipherSuite(tlsConnectOptions.GetTlsSecureOptions().GetCipherSuite());
    secureOptions.SetUseRemoteCipherPrefer(tlsConnectOptions.GetTlsSecureOptions().UseRemoteCipherPrefer());
    options.SetAddress(tlsConnectOptions.GetNetAddress());
    options.SetAlpnProtocols(tlsConnectOptions.GetAlpnProtocols());
    options.SetSecureOptions(secureOptions);

    auto res = openSslContext_.tlsSocketInternal_.TlsConnectToHost(options);
    if (!res) {
        CallOnErrorCallback(errno, MakeErrnoString());
        callback(false);
        return;
    }

    StartReadMessage();
    CallOnConnectCallback();
    callback(true);
}

void TLSSocket::Send(const OHOS::NetStack::TCPSendOptions &tcpSendOptions, const OHOS::NetStack::SendCallback &callback)
{
    (void)tcpSendOptions;

    auto res = openSslContext_.tlsSocketInternal_.Send(tcpSendOptions.GetData());
    if (!res) {
        CallOnErrorCallback(errno, MakeErrnoString());
        callback(false);
        return;
    }
    callback(true);
}

bool WaitConditionWithTimeout(bool *flag, int32_t timeoutMs)
{
    int MAX_WAIT_CNT = timeoutMs / WAIT_MS;
    int cnt = 0;
    while (!(*flag)) {
        if (cnt >= MAX_WAIT_CNT) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_MS));
        cnt++;
    }
    return true;
}

void TLSSocket::Close(const OHOS::NetStack::CloseCallback &callback)
{
    if (!WaitConditionWithTimeout(&isRunning_, TIMEOUT_MS)) {
        callback(false);
    }
    isRunning_ = false;
    if (!WaitConditionWithTimeout(&isRunOver_, TIMEOUT_MS)) {
        callback(false);
    }
    auto res = openSslContext_.tlsSocketInternal_.Close();
    if (!res) {
        CallOnErrorCallback(errno, MakeErrnoString());
        callback(false);
        return;
    }
    callback(true);
}

void TLSSocket::GetRemoteAddress(const OHOS::NetStack::GetRemoteAddressCallback &callback)
{
    sa_family_t family;
    socklen_t len = sizeof(family);
    int ret = getsockname(sockFd_, reinterpret_cast<sockaddr *>(&family), &len);
    if (ret < 0) {
        NETSTACK_LOGE("getsockname failed errno %{public}d", errno);
        CallOnErrorCallback(errno, MakeErrnoString());
        CallGetRemoteAddressCallback(false, {}, callback);
        return;
    }

    if (family == AF_INET) {
        GetIp4RemoteAddress(callback);
    } else if (family == AF_INET6) {
        GetIp6RemoteAddress(callback);
    }
}

void TLSSocket::GetIp4RemoteAddress(const OHOS::NetStack::GetRemoteAddressCallback &callback)
{
    sockaddr_in addr4 = {0};
    socklen_t len4 = sizeof(sockaddr_in);

    int ret = getpeername(sockFd_, reinterpret_cast<sockaddr *>(&addr4), &len4);
    if (ret < 0) {
        NETSTACK_LOGE("GetIp4RemoteAddress failed errno %{public}d", errno);
        CallOnErrorCallback(errno, MakeErrnoString());
        CallGetRemoteAddressCallback(false, {}, callback);
        return;
    }

    std::string address = MakeAddressString(reinterpret_cast<sockaddr *>(&addr4));
    if (address.empty()) {
        NETSTACK_LOGE("GetIp4RemoteAddress failed errno %{public}d", errno);
        CallOnErrorCallback(-1, "Address is invalid");
        CallGetRemoteAddressCallback(false, {}, callback);
        return;
    }
    NetAddress netAddress;
    netAddress.SetAddress(address);
    netAddress.SetFamilyBySaFamily(AF_INET);
    netAddress.SetPort(ntohs(addr4.sin_port));
    CallGetRemoteAddressCallback(true, netAddress, callback);
}

void TLSSocket::GetIp6RemoteAddress(const OHOS::NetStack::GetRemoteAddressCallback &callback)
{
    sockaddr_in6 addr6 = {0};
    socklen_t len6 = sizeof(sockaddr_in6);

    int ret = getpeername(sockFd_, reinterpret_cast<sockaddr *>(&addr6), &len6);
    if (ret < 0) {
        NETSTACK_LOGE("GetIp6RemoteAddress failed errno %{public}d", errno);
        CallOnErrorCallback(errno, MakeErrnoString());
        CallGetRemoteAddressCallback(false, {}, callback);
        return;
    }

    std::string address = MakeAddressString(reinterpret_cast<sockaddr *>(&addr6));
    if (address.empty()) {
        NETSTACK_LOGE("GetIp6RemoteAddress failed errno %{public}d", errno);
        CallOnErrorCallback(-1, "Address is invalid");
        CallGetRemoteAddressCallback(false, {}, callback);
        return;
    }
    NetAddress netAddress;
    netAddress.SetAddress(address);
    netAddress.SetFamilyBySaFamily(AF_INET6);
    netAddress.SetPort(ntohs(addr6.sin6_port));
    CallGetRemoteAddressCallback(true, netAddress, callback);
}

void TLSSocket::GetState(const OHOS::NetStack::GetStateCallback &callback)
{
    int opt;
    socklen_t optLen = sizeof(int);
    int r = getsockopt(sockFd_, SOL_SOCKET, SO_TYPE, &opt, &optLen);
    if (r < 0) {
        SocketStateBase state;
        state.SetIsClose(true);
        CallGetStateCallback(true, state, callback);
        return;
    }

    sa_family_t family;
    socklen_t len = sizeof(family);
    SocketStateBase state;
    int ret = getsockname(sockFd_, reinterpret_cast<sockaddr *>(&family), &len);
    state.SetIsBound(ret > 0);
    ret = getpeername(sockFd_, reinterpret_cast<sockaddr *>(&family), &len);
    state.SetIsConnected(ret > 0);

    CallGetStateCallback(true, state, callback);
}

bool TLSSocket::SetBaseOptions(const ExtraOptionsBase &option) const
{
    if (option.GetReceiveBufferSize() != 0) {
        int size = (int)option.GetReceiveBufferSize();
        if (setsockopt(sockFd_, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<void *>(&size), sizeof(size)) < 0) {
            return false;
        }
    }

    if (option.GetSendBufferSize() != 0) {
        int size = (int)option.GetSendBufferSize();
        if (setsockopt(sockFd_, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<void *>(&size), sizeof(size)) < 0) {
            return false;
        }
    }

    if (option.IsReuseAddress()) {
        int reuse = 1;
        if (setsockopt(sockFd_, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<void *>(&reuse), sizeof(reuse)) < 0) {
            return false;
        }
    }

    if (option.GetSocketTimeout() != 0) {
        timeval timeout = {(int)option.GetSocketTimeout(), 0};
        if (setsockopt(sockFd_, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<void *>(&timeout), sizeof(timeout)) < 0) {
            return false;
        }
        if (setsockopt(sockFd_, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<void *>(&timeout), sizeof(timeout)) < 0) {
            return false;
        }
    }

    return true;
}

bool TLSSocket::SetExtraOptions(const TCPExtraOptions &option) const
{
    if (option.IsKeepAlive()) {
        int keepalive = 1;
        if (setsockopt(sockFd_, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive)) < 0) {
            return false;
        }
    }

    if (option.IsOOBInline()) {
        int oobInline = 1;
        if (setsockopt(sockFd_, SOL_SOCKET, SO_OOBINLINE, &oobInline, sizeof(oobInline)) < 0) {
            return false;
        }
    }

    if (option.IsTCPNoDelay()) {
        int tcpNoDelay = 1;
        if (setsockopt(sockFd_, IPPROTO_TCP, TCP_NODELAY, &tcpNoDelay, sizeof(tcpNoDelay)) < 0) {
            return false;
        }
    }

    linger soLinger = {0};
    soLinger.l_onoff = option.socketLinger.IsOn();
    soLinger.l_linger = (int)option.socketLinger.GetLinger();
    if (setsockopt(sockFd_, SOL_SOCKET, SO_LINGER, &soLinger, sizeof(soLinger)) < 0) {
        return false;
    }

    return true;
}

void TLSSocket::SetExtraOptions(const OHOS::NetStack::TCPExtraOptions &tcpExtraOptions,
                                const OHOS::NetStack::SetExtraOptionsCallback &callback)
{
    if (!SetBaseOptions(tcpExtraOptions)) {
        NETSTACK_LOGE("SetExtraOptions errno %{public}d", errno);
        CallOnErrorCallback(errno, MakeErrnoString());
        CallSetExtraOptionsCallback(false, callback);
        return;
    }

    if (!SetExtraOptions(tcpExtraOptions)) {
        NETSTACK_LOGE("SetExtraOptions errno %{public}d", errno);
        CallOnErrorCallback(errno, MakeErrnoString());
        CallSetExtraOptionsCallback(false, callback);
        return;
    }

    CallSetExtraOptionsCallback(true, callback);
}

void TLSSocket::GetCertificate(const GetCertificateCallback &callback)
{
    std::string cert = openSslContext_.tlsSocketInternal_.GetCertificate();
    if (cert.empty()) {
        NETSTACK_LOGE("GetCertificate errno %{public}d, %{public}s", errno, strerror(errno));
        CallOnErrorCallback(errno, MakeErrnoString());
        callback(false, "");
        return;
    }
    callback(true, cert);
}

void TLSSocket::GetRemoteCertificate(const GetRemoteCertificateCallback &callback)
{
    std::string remoteCert = openSslContext_.tlsSocketInternal_.GetRemoteCertificate();
    if (remoteCert.empty()) {
        NETSTACK_LOGE("GetRemoteCertificate errno %{public}d", errno);
        CallOnErrorCallback(errno, MakeErrnoString());
        callback(false, "");
        return;
    }
    callback(true, remoteCert);
}

void TLSSocket::GetProtocol(const GetProtocolCallback &callback)
{
    std::string protocal = openSslContext_.tlsSocketInternal_.GetProtocol();
    if (protocal.empty()) {
        NETSTACK_LOGE("GetProtocol errno %{public}d", errno);
        CallOnErrorCallback(errno, MakeErrnoString());
        callback(false, "");
        return;
    }
    callback(true, protocal);
}

void TLSSocket::GetCipherSuite(const GetCipherSuiteCallback &callback)
{
    std::vector<std::string> cipherSuite = openSslContext_.tlsSocketInternal_.GetCipherSuite();
    if (cipherSuite.empty()) {
        NETSTACK_LOGE("GetCipherSuite errno %{public}d", errno);
        CallOnErrorCallback(errno, MakeErrnoString());
        callback(false, cipherSuite);
        return;
    }
    callback(true, cipherSuite);
}

void TLSSocket::GetSignatureAlgorithms(const GetSignatureAlgorithmsCallback &callback)
{
    std::vector signatureAlgorithms = openSslContext_.tlsSocketInternal_.GetSignatureAlgorithms();
    if (signatureAlgorithms.empty()) {
        NETSTACK_LOGE("GetSignatureAlgorithms errno %{public}d", errno);
        CallOnErrorCallback(errno, MakeErrnoString());
        callback(false, {});
        return;
    }
    callback(true, signatureAlgorithms);
}

void TLSSocket::OnMessage(const OHOS::NetStack::OnMessageCallback &onMessageCallback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    onMessageCallback_ = onMessageCallback;
}

void TLSSocket::OffMessage()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (onMessageCallback_) {
        onMessageCallback_ = nullptr;
    }
}

void TLSSocket::OnConnect(const OnConnectCallback &onConnectCallback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    onConnectCallback_ = onConnectCallback;
}

void TLSSocket::OffConnect()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (onConnectCallback_) {
        onConnectCallback_ = nullptr;
    }
}

void TLSSocket::OnClose(const OnCloseCallback &onCloseCallback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    onCloseCallback_ = onCloseCallback;
}

void TLSSocket::OffClose()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (onCloseCallback_) {
        onCloseCallback_ = nullptr;
    }
}

void TLSSocket::OnError(const OnErrorCallback &onErrorCallback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    onErrorCallback_ = onErrorCallback;
}

void TLSSocket::OffError()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (onErrorCallback_) {
        onErrorCallback_ = nullptr;
    }
}
} } // namespace OHOS::NetStack
