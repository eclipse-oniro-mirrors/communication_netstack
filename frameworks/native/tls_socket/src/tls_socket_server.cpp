/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "tls_socket_server.h"

#include <chrono>
#include <memory>
#include <netinet/tcp.h>
#include <numeric>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <regex>
#include <securec.h>
#include <sys/ioctl.h>
#include <thread>

#include "base_context.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"
#include "tls.h"

namespace OHOS {
namespace NetStack {
namespace TlsSocketServer {
namespace {
constexpr int SSL_ERROR_RETURN = -1;
constexpr const char *HOST_NAME = "hostname: ";
const std::regex JSON_STRING_PATTERN{R"(/^"(?:[^"\\\u0000-\u001f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"/)"};
const std::regex PATTERN{
    "((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|"
    "2[0-4][0-9]|[01]?[0-9][0-9]?)"};
} // namespace

void TLSServerSendOptions::SetSocket(const int &socketFd)
{
    socketFd_ = socketFd;
}

void TLSServerSendOptions::SetSendData(const std::string &data)
{
    data_ = data;
}

const int &TLSServerSendOptions::GetSocket() const
{
    return socketFd_;
}

const std::string &TLSServerSendOptions::GetSendData() const
{
    return data_;
}

void TLSSocketServer::Listen(const TlsSocket::TLSConnectOptions &tlsListenOptions, const ListenCallback &callback) {}

bool TLSSocketServer::ExecBind(const Socket::NetAddress &address, const ListenCallback &callback)
{
    return true;
}

void TLSSocketServer::ExecAccept(const TlsSocket::TLSConnectOptions &tlsAcceptOptions, const ListenCallback &callback)
{
}

bool TLSSocketServer::Send(const TLSServerSendOptions &data, const TlsSocket::SendCallback &callback)
{
    return true;
}

void TLSSocketServer::CallSendCallback(int32_t err, TlsSocket::SendCallback callback) {}

void TLSSocketServer::Close(const int socketFd, const TlsSocket::CloseCallback &callback) {}

void TLSSocketServer::Stop(const TlsSocket::CloseCallback &callback) {}

void TLSSocketServer::GetRemoteAddress(const int socketFd, const TlsSocket::GetRemoteAddressCallback &callback) {}

void TLSSocketServer::GetState(const TlsSocket::GetStateCallback &callback) {}

void TLSSocketServer::CallGetStateCallback(int32_t err, const Socket::SocketStateBase &state,
                                           TlsSocket::GetStateCallback callback)
{
}

bool TLSSocketServer::SetExtraOptions(const Socket::TCPExtraOptions &tcpExtraOptions,
                                      const TlsSocket::SetExtraOptionsCallback &callback)
{
    return true;
}

void TLSSocketServer::SetLocalTlsConfiguration(const TlsSocket::TLSConnectOptions &config) {}

void TLSSocketServer::GetCertificate(const TlsSocket::GetCertificateCallback &callback) {}

void TLSSocketServer::GetRemoteCertificate(const int socketFd, const TlsSocket::GetRemoteCertificateCallback &callback)
{
}

void TLSSocketServer::GetProtocol(const TlsSocket::GetProtocolCallback &callback)
{
    if (TLSServerConfiguration_.GetProtocol() == TlsSocket::TLS_V1_3) {
        callback(TlsSocket::TLSSOCKET_SUCCESS, TlsSocket::PROTOCOL_TLS_V13);
    }
    callback(TlsSocket::TLSSOCKET_SUCCESS, TlsSocket::PROTOCOL_TLS_V12);
}

void TLSSocketServer::GetCipherSuite(const int socketFd, const TlsSocket::GetCipherSuiteCallback &callback) {}

void TLSSocketServer::GetSignatureAlgorithms(const int socketFd,
                                             const TlsSocket::GetSignatureAlgorithmsCallback &callback)
{
}

void TLSSocketServer::Connection::OnMessage(const OnMessageCallback &onMessageCallback)
{
    onMessageCallback_ = onMessageCallback;
}

void TLSSocketServer::Connection::OnClose(const OnCloseCallback &onCloseCallback)
{
    onCloseCallback_ = onCloseCallback;
}

void TLSSocketServer::OnConnect(const OnConnectCallback &onConnectCallback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    onConnectCallback_ = onConnectCallback;
}

void TLSSocketServer::OnError(const TlsSocket::OnErrorCallback &onErrorCallback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    onErrorCallback_ = onErrorCallback;
}

void TLSSocketServer::Connection::OffMessage()
{
    if (onMessageCallback_) {
        onMessageCallback_ = nullptr;
    }
}

void TLSSocketServer::OffConnect()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (onConnectCallback_) {
        onConnectCallback_ = nullptr;
    }
}

void TLSSocketServer::Connection::OnError(const TlsSocket::OnErrorCallback &onErrorCallback)
{
    onErrorCallback_ = onErrorCallback;
}

void TLSSocketServer::Connection::OffClose()
{
    if (onCloseCallback_) {
        onCloseCallback_ = nullptr;
    }
}

void TLSSocketServer::Connection::OffError()
{
    onErrorCallback_ = nullptr;
}

void TLSSocketServer::Connection::CallOnErrorCallback(int32_t err, const std::string &errString) {}

void TLSSocketServer::OffError() {}

void TLSSocketServer::MakeIpSocket(sa_family_t family) {}

void TLSSocketServer::CallOnErrorCallback(int32_t err, const std::string &errString) {}

void TLSSocketServer::GetAddr(const Socket::NetAddress &address, sockaddr_in *addr4, sockaddr_in6 *addr6,
                              sockaddr **addr, socklen_t *len)
{
}

std::shared_ptr<TLSSocketServer::Connection> TLSSocketServer::GetConnectionByClientID(int clientid)
{
    return nullptr;
    ;
}

void TLSSocketServer::CallListenCallback(int32_t err, ListenCallback callback) {}

void TLSSocketServer::Connection::SetAddress(const Socket::NetAddress address)
{
    address_ = address;
}

const TlsSocket::X509CertRawData &TLSSocketServer::Connection::GetRemoteCertRawData() const
{
    return remoteRawData_;
}

bool TLSSocketServer::Connection::TlsAcceptToHost(int sock, const TlsSocket::TLSConnectOptions &options)
{
    return StartTlsAccept(options);
}

void TLSSocketServer::Connection::SetTlsConfiguration(const TlsSocket::TLSConnectOptions &config) {}

bool TLSSocketServer::Connection::Send(const std::string &data)
{
    return true;
}

int TLSSocketServer::Connection::Recv(char *buffer, int maxBufferSize)
{
    if (!ssl_) {
        NETSTACK_LOGE("ssl is null");
        return SSL_ERROR_RETURN;
    }
    return SSL_read(ssl_, buffer, maxBufferSize);
}

bool TLSSocketServer::Connection::Close()
{
    return true;
}

bool TLSSocketServer::Connection::SetAlpnProtocols(const std::vector<std::string> &alpnProtocols)
{
    return true;
}

void TLSSocketServer::Connection::MakeRemoteInfo(Socket::SocketRemoteInfo &remoteInfo) {}

TlsSocket::TLSConfiguration TLSSocketServer::Connection::GetTlsConfiguration() const
{
    return connectionConfiguration_;
}

std::vector<std::string> TLSSocketServer::Connection::GetCipherSuite() const
{
    if (!ssl_) {
        NETSTACK_LOGE("ssl in null");
        return {};
    }
    STACK_OF(SSL_CIPHER) *sk = SSL_get_ciphers(ssl_);
    if (!sk) {
        NETSTACK_LOGE("get ciphers failed");
        return {};
    }
    TlsSocket::CipherSuite cipherSuite;
    std::vector<std::string> cipherSuiteVec;
    for (int i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
        const SSL_CIPHER *c = sk_SSL_CIPHER_value(sk, i);
        cipherSuite.cipherName_ = SSL_CIPHER_get_name(c);
        cipherSuiteVec.push_back(cipherSuite.cipherName_);
    }
    return cipherSuiteVec;
}

std::string TLSSocketServer::Connection::GetRemoteCertificate() const
{
    return remoteCert_;
}

const TlsSocket::X509CertRawData &TLSSocketServer::Connection::GetCertificate() const
{
    return connectionConfiguration_.GetCertificate();
}

std::vector<std::string> TLSSocketServer::Connection::GetSignatureAlgorithms() const
{
    return signatureAlgorithms_;
}

std::string TLSSocketServer::Connection::GetProtocol() const
{
    return TlsSocket::PROTOCOL_TLS_V12;
}

bool TLSSocketServer::Connection::SetSharedSigals()
{
    return true;
}

ssl_st *TLSSocketServer::Connection::GetSSL() const
{
    return ssl_;
}

Socket::NetAddress TLSSocketServer::Connection::GetAddress() const
{
    return address_;
}

int TLSSocketServer::Connection::GetSocketFd() const
{
    return socketFd_;
}

std::shared_ptr<EventManager> TLSSocketServer::Connection::GetEventManager() const
{
    return eventManager_;
}

void TLSSocketServer::Connection::SetEventManager(std::shared_ptr<EventManager> eventManager)
{
    eventManager_ = eventManager;
}

void TLSSocketServer::Connection::SetClientID(int32_t clientID)
{
    clientID_ = clientID;
}

int TLSSocketServer::Connection::GetClientID()
{
    return clientID_;
}

bool TLSSocketServer::Connection::StartTlsAccept(const TlsSocket::TLSConnectOptions &options)
{
    return true;
}

bool TLSSocketServer::Connection::CreatTlsContext()
{
    return true;
}

bool TLSSocketServer::Connection::StartShakingHands(const TlsSocket::TLSConnectOptions &options)
{
    return true;
}

bool TLSSocketServer::Connection::GetRemoteCertificateFromPeer()
{
    return true;
}

bool TLSSocketServer::Connection::SetRemoteCertRawData()
{
    return true;
}

void CheckIpAndDnsName(const std::string &hostName, std::vector<std::string> dnsNames, std::vector<std::string> ips,
                       const X509 *x509Certificates, std::tuple<bool, std::string> &result)
{
}

std::string TLSSocketServer::Connection::CheckServerIdentityLegal(const std::string &hostName,
                                                                  const X509 *x509Certificates)
{
    std::string hostname = hostName;

    return HOST_NAME + hostname + ". is cert's CN";
}
void TLSSocketServer::RemoveConnect(int socketFd) {}
int TLSSocketServer::RecvRemoteInfo(int socketFd)
{
    return -1;
}
void TLSSocketServer::Connection::CallOnMessageCallback(int32_t socketFd, const std::string &data,
                                                        const Socket::SocketRemoteInfo &remoteInfo)
{
}
void TLSSocketServer::AddConnect(int socketFd, std::shared_ptr<Connection> connection) {}
void TLSSocketServer::Connection::CallOnCloseCallback(const int32_t socketFd) {}
void TLSSocketServer::CallOnConnectCallback(const int32_t socketFd, std::shared_ptr<EventManager> eventManager) {}
} // namespace TlsSocketServer
} // namespace NetStack
} // namespace OHOS
