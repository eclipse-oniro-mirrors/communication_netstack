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
#include "ffi_convert.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"

namespace OHOS {
namespace NetStackAni {

using namespace NetStack;

struct SyncCallbackContext {
    std::mutex mutex;
    std::condition_variable cv;
    bool completed = false;
    int32_t errorCode = 0;
};

std::unique_ptr<TlsClientContext> CreateTlsClientContext(int32_t &errCode)
{
    auto ctx = std::make_unique<TlsClientContext>();
    errCode = NetStack::Socket::SOCKET_ERROR_OK;
    return ctx;
}

std::unique_ptr<TlsClientContext> CreateTlsClientContextFromTcpClientContext(TcpSocketContext& client, int32_t &errCode)
{
    auto ctx = std::make_unique<TlsClientContext>();
    if (!ctx) {
        errCode = NetStack::Socket::SYSTEM_INTERNAL_ERROR;
        return nullptr;
    }
    int32_t tcpSockFd = 0;
    client.socket_->TransferFd(tcpSockFd, ctx->socks5Proxy_);

    if (tcpSockFd <= 0) {
        errCode = NetStack::TlsSocket::TLS_ERR_SOCK_INVALID_FD;
        return nullptr;
    }
    int optval;
    socklen_t optlen = sizeof(optval);
#if defined(IOS_PLATFORM)
    if (getsockopt(tcpSockFd, SOL_SOCKET, SO_TYPE, &optval, &optlen) != 0) {
        errCode = NetStack::TlsSocket::TLS_ERR_SOCK_INVALID_FD;
        return nullptr;
    }
    if (optval != SOCK_STREAM) {
        errCode = NetStack::TlsSocket::TLS_ERR_SOCK_INVALID_FD;
        return nullptr;
    }
#else
    if (getsockopt(tcpSockFd, SOL_SOCKET, SO_PROTOCOL, &optval, &optlen) != 0) {
        errCode = NetStack::TlsSocket::TLS_ERR_SOCK_INVALID_FD;
        return nullptr;
    }
    if (optval != IPPROTO_TCP) {
        errCode = NetStack::TlsSocket::TLS_ERR_SOCK_INVALID_FD;
        return nullptr;
    }
#endif
    sockaddr_storage addr{};
    socklen_t len = sizeof(addr);
    if (getpeername(tcpSockFd, reinterpret_cast<sockaddr *>(&addr), &len) != 0) {
        errCode = NetStack::TlsSocket::TLS_ERR_SOCK_NOT_CONNECT;
        return nullptr;
    }

    ctx->tlsSocketClient_ = std::make_shared<TlsSocket::TLSSocket>(tcpSockFd);
    if (!ctx->tlsSocketClient_) {
        errCode = NetStack::Socket::SYSTEM_INTERNAL_ERROR;
        return nullptr;
    }
    errCode = NetStack::Socket::SOCKET_ERROR_OK;
    return ctx;
}

void TlsClientSetMessageCallback(TlsClientContext &client)
{
    if (client.tlsSocketClient_ == nullptr) {
        return;
    }
    std::weak_ptr<rust::Box<TlsClientMessageBox>> messageBoxWeak = client.messageBoxHolder_;
    client.tlsSocketClient_->OnMessage([messageBoxWeak]
        (const std::string &data, const Socket::SocketRemoteInfo &remoteInfo) {
        if (auto messageBox = messageBoxWeak.lock()) {
            rust::Vec<uint8_t> vecData;
            for (const auto &byte : data) {
                vecData.push_back(static_cast<uint8_t>(byte));
            }
            rust::String address(remoteInfo.GetAddress());
            rust::String family(remoteInfo.GetFamily());
            int32_t port = static_cast<int32_t>(remoteInfo.GetPort());
            int32_t size = static_cast<int32_t>(remoteInfo.GetSize());
            (*messageBox)->on_message(vecData, address, family, port, size);
        }
    });
}

void TlsClientSetConnectCallback(TlsClientContext &client)
{
    if (client.tlsSocketClient_ != nullptr) {
        std::weak_ptr<rust::Box<TlsClientConnectBox>> connectBoxWeak = client.connectBoxHolder_;
        client.tlsSocketClient_->OnConnect([connectBoxWeak]() {
            if (auto connectBox = connectBoxWeak.lock()) {
                (*connectBox)->on_connect();
            }
        });
    }
}

void TlsClientSetCloseCallback(TlsClientContext &client)
{
    if (client.tlsSocketClient_ != nullptr) {
        std::weak_ptr<rust::Box<TlsClientCloseBox>> closeBoxWeak = client.closeBoxHolder_;
        client.tlsSocketClient_->OnClose([closeBoxWeak]() {
            if (auto closeBox = closeBoxWeak.lock()) {
                (*closeBox)->on_close();
            }
        });
    }
}

void TlsClientSetErrorCallback(TlsClientContext &client)
{
    if (client.tlsSocketClient_ != nullptr) {
        std::weak_ptr<rust::Box<TlsClientErrorBox>> errorBoxWeak = client.errorBoxHolder_;
        client.tlsSocketClient_->OnError([errorBoxWeak](int32_t err, const std::string &errString) {
            if (auto errorBox = errorBoxWeak.lock()) {
                rust::String errorString(errString);
                (*errorBox)->on_error(err, errorString);
            }
        });
    }
}

int32_t TlsClientBind(TlsClientContext &client, const FFINetAddress &addr)
{
    Socket::NetAddress netAddress;
    FFINetAddressToNetAddress(addr, netAddress);

    if (netAddress.GetAddress().empty()) {
        return NetStack::Socket::PARAM_ERROR_CODE;
    }

    if (client.tlsSocketClient_ != nullptr) {
        return NetStack::Socket::SOCKET_ERROR_OK;
    }

    client.tlsSocketClient_ = std::make_shared<TlsSocket::TLSSocket>();
    if (client.tlsSocketClient_ == nullptr) {
        return NetStack::Socket::SYSTEM_INTERNAL_ERROR;
    }

    TlsClientSetMessageCallback(client);
    TlsClientSetConnectCallback(client);
    TlsClientSetCloseCallback(client);
    TlsClientSetErrorCallback(client);

    auto context = std::make_shared<SyncCallbackContext>();
    client.tlsSocketClient_->Bind(netAddress, [context](int32_t errorNumber) {
        std::lock_guard<std::mutex> lock(context->mutex);
        context->errorCode = errorNumber;
        context->completed = true;
        context->cv.notify_one();
    });
    std::unique_lock<std::mutex> lock(context->mutex);
    context->cv.wait(lock, [&context] { return context->completed; });
    return context->errorCode;
}

int32_t TlsClientConnect(TlsClientContext &client, const FFITlsConnectOptions &opts)
{
    if (client.tlsSocketClient_ == nullptr) {
        return NetStack::TlsSocket::TLS_ERR_NO_BIND;
    }

    TlsSocket::TLSConnectOptions options;
    FFITlsConnectOptionsToTLSConnectOptions(opts, options);
    const auto alias = options.GetTlsSecureOptions().GetCertAlias();
    if (alias && !TlsSocket::IsValidCertAlias(*alias)) {
        return TlsSocket::TLS_ALIAS_INVALID;
    }

    if (!client.tlsSocketClient_->IsExtSock() && options.proxyOptions_ != nullptr &&
        options.proxyOptions_->type_ == Socket::ProxyType::SOCKS5) {
        if (client.socks5Proxy_ == nullptr) {
            const std::shared_ptr<Socks5::Socks5Option> sock5Opt = std::make_shared<Socks5::Socks5Option>();
            sock5Opt->username_ = options.proxyOptions_->username_;
            sock5Opt->password_ = options.proxyOptions_->password_;
            sock5Opt->proxyAddress_.netAddress_ = options.proxyOptions_->address_;
            socklen_t len;
            client.tlsSocketClient_->ExecTlsGetAddr(sock5Opt->proxyAddress_.netAddress_,
                                                    &sock5Opt->proxyAddress_.addrV4_,
                                                    &sock5Opt->proxyAddress_.addrV6_,
                                                    &sock5Opt->proxyAddress_.addr_, &len);
            if (sock5Opt->proxyAddress_.addr_ == nullptr) {
                return NetStack::Socket::SYSTEM_INTERNAL_ERROR;
            }
            client.socks5Proxy_ =
                std::make_shared<Socks5::Socks5TlsInstance>(client.tlsSocketClient_->GetSocketFd());
            client.socks5Proxy_->SetDestAddress(options.GetNetAddress());
            client.socks5Proxy_->SetSocks5Option(sock5Opt);
            client.socks5Proxy_->SetSocks5Instance(client.socks5Proxy_);
        }
        if (!client.socks5Proxy_->IsConnected() && !client.socks5Proxy_->Connect()) {
            return client.socks5Proxy_->GetErrorCode();
        }
        client.tlsSocketClient_->ExecTlsSetSockBlockFlag(client.tlsSocketClient_->GetSocketFd(), false);
    }

    auto context = std::make_shared<SyncCallbackContext>();
    client.tlsSocketClient_->Connect(options, [context](int32_t errorNumber) {
        std::lock_guard<std::mutex> lock(context->mutex);
        context->errorCode = errorNumber;
        context->completed = true;
        context->cv.notify_one();
    });
    std::unique_lock<std::mutex> lock(context->mutex);
    context->cv.wait(lock, [&context] { return context->completed; });
    return context->errorCode;
}

int32_t TlsClientSend(TlsClientContext &client, FFITcpSendOptions opts)
{
    if (client.tlsSocketClient_ == nullptr) {
        return NetStack::TlsSocket::TLS_ERR_NO_BIND;
    }

    Socket::TCPSendOptions options;
    FFITcpSendOptionsToTCPSendOptions(opts, options);

    if (options.GetData().empty()) {
        return NetStack::Socket::PARAM_ERROR_CODE;
    }

    auto context = std::make_shared<SyncCallbackContext>();
    client.tlsSocketClient_->Send(options, [context](int32_t errorNumber) {
        std::lock_guard<std::mutex> lock(context->mutex);
        context->errorCode = errorNumber;
        context->completed = true;
        context->cv.notify_one();
    });
    std::unique_lock<std::mutex> lock(context->mutex);
    context->cv.wait(lock, [&context] { return context->completed; });
    return context->errorCode;
}

int32_t TlsClientClose(TlsClientContext &client)
{
    if (client.tlsSocketClient_ == nullptr) {
        return NetStack::TlsSocket::TLS_ERR_NO_BIND;
    }

    auto context = std::make_shared<SyncCallbackContext>();
    client.tlsSocketClient_->Close([context](int32_t errorNumber) {
        std::lock_guard<std::mutex> lock(context->mutex);
        context->errorCode = errorNumber;
        context->completed = true;
        context->cv.notify_one();
    });
    std::unique_lock<std::mutex> lock(context->mutex);
    context->cv.wait(lock, [&context] { return context->completed; });
    client.tlsSocketClient_.reset();
    return context->errorCode;
}

int32_t TlsClientGetState(TlsClientContext &client, FFISocketStateBase &status)
{
    if (client.tlsSocketClient_ != nullptr) {
        auto context = std::make_shared<SyncCallbackContext>();
        Socket::SocketStateBase state;
        client.tlsSocketClient_->GetState([context, &state]
            (int32_t errorNumber, const Socket::SocketStateBase &stateBase) {
            std::lock_guard<std::mutex> lock(context->mutex);
            context->errorCode = errorNumber;
            state = stateBase;
            context->completed = true;
            context->cv.notify_one();
        });
        std::unique_lock<std::mutex> lock(context->mutex);
        context->cv.wait(lock, [&context] { return context->completed; });

        SocketStateBaseToFFISocketStateBase(state, status);
        return context->errorCode;
    }
    return NetStack::TlsSocket::TLSSOCKET_SUCCESS;
}

int32_t TlsClientGetRemoteAddress(TlsClientContext &client, FFINetAddress &addr)
{
    if (client.tlsSocketClient_ == nullptr) {
        return NetStack::TlsSocket::TLS_ERR_NO_BIND;
    }

    auto context = std::make_shared<SyncCallbackContext>();
    Socket::NetAddress remoteAddress;
    client.tlsSocketClient_->GetRemoteAddress([context, &remoteAddress]
        (int32_t errorNumber, const Socket::NetAddress &netAddress) {
        std::lock_guard<std::mutex> lock(context->mutex);
        context->errorCode = errorNumber;
        remoteAddress = netAddress;
        context->completed = true;
        context->cv.notify_one();
    });
    std::unique_lock<std::mutex> lock(context->mutex);
    context->cv.wait(lock, [&context] { return context->completed; });

    NetAddressToFFINetAddress(remoteAddress, addr);
    return context->errorCode;
}

int32_t TlsClientGetLocalAddress(TlsClientContext &client, FFINetAddress &addr)
{
    if (client.tlsSocketClient_ == nullptr) {
        return NetStack::TlsSocket::TLS_ERR_NO_BIND;
    }
    auto sockFd = client.tlsSocketClient_->GetSocketFd();
    struct sockaddr_storage addrStorage {};
    socklen_t addrLen = sizeof(addrStorage);
    if (getsockname(sockFd, reinterpret_cast<struct sockaddr*>(&addrStorage), &addrLen) == -1) {
        return NetStack::Socket::ConvertSocketClientErrno(errno);
    }

    char ipStr[INET6_ADDRSTRLEN] = {0};
    Socket::NetAddress localAddress;
    if (addrStorage.ss_family == AF_INET) {
        auto *addr_in = reinterpret_cast<struct sockaddr_in*>(&addrStorage);
        inet_ntop(AF_INET, &addr_in->sin_addr, ipStr, sizeof(ipStr));
        localAddress.SetFamilyBySaFamily(AF_INET);
        localAddress.SetRawAddress(ipStr);
        localAddress.SetPort(ntohs(addr_in->sin_port));
        client.tlsSocketClient_->SetLocalAddress(localAddress);
    } else if (addrStorage.ss_family == AF_INET6) {
        auto *addr_in6 = reinterpret_cast<struct sockaddr_in6*>(&addrStorage);
        inet_ntop(AF_INET6, &addr_in6->sin6_addr, ipStr, sizeof(ipStr));
        localAddress.SetFamilyBySaFamily(AF_INET6);
        localAddress.SetRawAddress(ipStr);
        localAddress.SetPort(ntohs(addr_in6->sin6_port));
        client.tlsSocketClient_->SetLocalAddress(localAddress);
    }

    NetAddressToFFINetAddress(localAddress, addr);
    return NetStack::TlsSocket::TLSSOCKET_SUCCESS;
}

int32_t TlsClientGetSocketFd(TlsClientContext &client, int32_t &fd)
{
    fd = client.tlsSocketClient_ != nullptr ? client.tlsSocketClient_->GetSocketFd() : -1;
    return NetStack::TlsSocket::TLSSOCKET_SUCCESS;
}

int32_t TlsClientGetCertificate(TlsClientContext &client, FFIX509CertRawData &cert)
{
    if (client.tlsSocketClient_ == nullptr) {
        return NetStack::TlsSocket::TLS_ERR_NO_BIND;
    }

    auto context = std::make_shared<SyncCallbackContext>();
    TlsSocket::X509CertRawData certData;
    client.tlsSocketClient_->GetCertificate([context, &certData]
        (int32_t errorNumber, const TlsSocket::X509CertRawData &c) {
        std::lock_guard<std::mutex> lock(context->mutex);
        context->errorCode = errorNumber;
        certData = c;
        context->completed = true;
        context->cv.notify_one();
    });
    std::unique_lock<std::mutex> lock(context->mutex);
    context->cv.wait(lock, [&context] { return context->completed; });

    X509CertRawDataToFFIX509CertRawData(certData, cert);
    return context->errorCode;
}


int32_t TlsClientGetRemoteCertificate(TlsClientContext &client, FFIX509CertRawData &cert)
{
    if (client.tlsSocketClient_ == nullptr) {
        return NetStack::TlsSocket::TLS_ERR_NO_BIND;
    }

    auto context = std::make_shared<SyncCallbackContext>();
    TlsSocket::X509CertRawData certData;

    client.tlsSocketClient_->GetRemoteCertificate([context, &certData]
        (int32_t errorNumber, const TlsSocket::X509CertRawData &data) {
        std::lock_guard<std::mutex> lock(context->mutex);
        context->errorCode = errorNumber;
        certData = data;
        context->completed = true;
        context->cv.notify_one();
    });

    std::unique_lock<std::mutex> lock(context->mutex);
    context->cv.wait(lock, [&context] { return context->completed; });

    X509CertRawDataToFFIX509CertRawData(certData, cert);
    return context->errorCode;
}

int32_t TlsClientGetProtocol(TlsClientContext &client, rust::String &protocol)
{
    if (client.tlsSocketClient_ == nullptr) {
        return NetStack::TlsSocket::TLS_ERR_NO_BIND;
    }

    auto context = std::make_shared<SyncCallbackContext>();
    std::string protocolStr;

    client.tlsSocketClient_->GetProtocol([context, &protocolStr]
        (int32_t errorNumber, const std::string &protocolName) {
        std::lock_guard<std::mutex> lock(context->mutex);
        context->errorCode = errorNumber;
        protocolStr = protocolName;
        context->completed = true;
        context->cv.notify_one();
    });

    std::unique_lock<std::mutex> lock(context->mutex);
    context->cv.wait(lock, [&context] { return context->completed; });

    protocol = rust::String(protocolStr);
    return context->errorCode;
}

int32_t TlsClientGetCipherSuite(TlsClientContext &client, rust::Vec<rust::String> &cipherSuite)
{
    if (client.tlsSocketClient_ == nullptr) {
        return NetStack::TlsSocket::TLS_ERR_NO_BIND;
    }

    auto context = std::make_shared<SyncCallbackContext>();
    std::vector<std::string> cipherSuiteVec;

    client.tlsSocketClient_->GetCipherSuite([context, &cipherSuiteVec]
        (int32_t errorNumber, const std::vector<std::string> &suite) {
        std::lock_guard<std::mutex> lock(context->mutex);
        context->errorCode = errorNumber;
        cipherSuiteVec = suite;
        context->completed = true;
        context->cv.notify_one();
    });

    std::unique_lock<std::mutex> lock(context->mutex);
    context->cv.wait(lock, [&context] { return context->completed; });

    cipherSuite.clear();
    for (const auto &item : cipherSuiteVec) {
        cipherSuite.push_back(rust::String(item));
    }

    return context->errorCode;
}

int32_t TlsClientGetSignatureAlgorithms(TlsClientContext &client, rust::Vec<rust::String> &signatureAlgorithms)
{
    if (client.tlsSocketClient_ == nullptr) {
        return NetStack::TlsSocket::TLS_ERR_NO_BIND;
    }

    auto context = std::make_shared<SyncCallbackContext>();
    std::vector<std::string> algorithmsVec;

    client.tlsSocketClient_->GetSignatureAlgorithms([context, &algorithmsVec]
        (int32_t errorNumber, const std::vector<std::string> &algorithms) {
        std::lock_guard<std::mutex> lock(context->mutex);
        context->errorCode = errorNumber;
        algorithmsVec = algorithms;
        context->completed = true;
        context->cv.notify_one();
    });

    std::unique_lock<std::mutex> lock(context->mutex);
    context->cv.wait(lock, [&context] { return context->completed; });

    for (const auto &item : algorithmsVec) {
        signatureAlgorithms.push_back(rust::String(item));
    }
    return context->errorCode;
}

int32_t TlsClientSetExtraOptions(TlsClientContext &client, const FFITcpExtraOptions &opts)
{
    if (client.tlsSocketClient_ == nullptr) {
        return NetStack::TlsSocket::TLS_ERR_NO_BIND;
    }

    Socket::TCPExtraOptions options;
    FFITcpExtraOptionsToTCPExtraOptions(opts, options);

    auto context = std::make_shared<SyncCallbackContext>();
    client.tlsSocketClient_->SetExtraOptions(options, [context](int32_t errorNumber) {
        std::lock_guard<std::mutex> lock(context->mutex);
        context->errorCode = errorNumber;
        context->completed = true;
        context->cv.notify_one();
    });
    std::unique_lock<std::mutex> lock(context->mutex);
    context->cv.wait(lock, [&context] { return context->completed; });
    return context->errorCode;
}

int32_t TlsClientOnMessage(TlsClientContext &client, rust::Box<TlsClientMessageBox> callbackBox)
{
    client.messageBoxHolder_ = std::make_shared<rust::Box<TlsClientMessageBox>>(std::move(callbackBox));
    TlsClientSetMessageCallback(client);
    return NetStack::TlsSocket::TLSSOCKET_SUCCESS;
}

int32_t TlsClientOnConnect(TlsClientContext &client, rust::Box<TlsClientConnectBox> callbackBox)
{
    client.connectBoxHolder_ = std::make_shared<rust::Box<TlsClientConnectBox>>(std::move(callbackBox));
    TlsClientSetConnectCallback(client);
    return NetStack::TlsSocket::TLSSOCKET_SUCCESS;
}

int32_t TlsClientOnClose(TlsClientContext &client, rust::Box<TlsClientCloseBox> callbackBox)
{
    client.closeBoxHolder_ = std::make_shared<rust::Box<TlsClientCloseBox>>(std::move(callbackBox));
    TlsClientSetCloseCallback(client);
    return NetStack::TlsSocket::TLSSOCKET_SUCCESS;
}

int32_t TlsClientOnError(TlsClientContext &client, rust::Box<TlsClientErrorBox> callbackBox)
{
    client.errorBoxHolder_ = std::make_shared<rust::Box<TlsClientErrorBox>>(std::move(callbackBox));
    TlsClientSetErrorCallback(client);
    return NetStack::TlsSocket::TLSSOCKET_SUCCESS;
}

int32_t TlsClientOffMessage(TlsClientContext &client)
{
    if (client.tlsSocketClient_ != nullptr) {
        client.tlsSocketClient_->OffMessage();
    }
    client.messageBoxHolder_ = nullptr;
    return NetStack::TlsSocket::TLSSOCKET_SUCCESS;
}

int32_t TlsClientOffConnect(TlsClientContext &client)
{
    if (client.tlsSocketClient_ != nullptr) {
        client.tlsSocketClient_->OffConnect();
    }
    client.connectBoxHolder_ = nullptr;
    return NetStack::TlsSocket::TLSSOCKET_SUCCESS;
}

int32_t TlsClientOffClose(TlsClientContext &client)
{
    if (client.tlsSocketClient_ != nullptr) {
        client.tlsSocketClient_->OffClose();
    }
    client.closeBoxHolder_ = nullptr;
    return NetStack::TlsSocket::TLSSOCKET_SUCCESS;
}

int32_t TlsClientOffError(TlsClientContext &client)
{
    if (client.tlsSocketClient_ != nullptr) {
        client.tlsSocketClient_->OffError();
    }
    client.errorBoxHolder_ = nullptr;
    return NetStack::TlsSocket::TLSSOCKET_SUCCESS;
}

std::unique_ptr<TlsServerContext> CreateTlsServerContext()
{
    return std::make_unique<TlsServerContext>();
}

void TlsServerSetConnectCallback(TlsServerContext &server)
{
    if (server.tlsSocketServer_ != nullptr) {
        std::weak_ptr<rust::Box<TlsServerConnectBox>> weakConnectBox = server.connectBoxHolder_;
        server.tlsSocketServer_->OnConnect([weakConnectBox](const int &socketFd) {
            if (auto connectBox = weakConnectBox.lock()) {
                (*connectBox)->on_connect(socketFd);
            }
        });
    }
}

void TlsServerSetErrorCallback(TlsServerContext &server)
{
    if (server.tlsSocketServer_ != nullptr) {
        std::weak_ptr<rust::Box<TlsServerErrorBox>> weakErrorBox = server.errorBoxHolder_;
        server.tlsSocketServer_->OnError([weakErrorBox](int32_t err, const std::string &errString) {
            if (auto errorBox = weakErrorBox.lock()) {
                (*errorBox)->on_error(err, rust::String(errString));
            }
        });
    }
}

int32_t TlsServerListen(TlsServerContext &server, const FFITlsConnectOptions &opts)
{
    if (server.tlsSocketServer_ == nullptr) {
        server.tlsSocketServer_ = std::make_shared<TlsSocketServer::TLSSocketServer>();
        TlsServerSetConnectCallback(server);
        TlsServerSetErrorCallback(server);
    }

    TlsSocket::TLSConnectOptions options;
    FFITlsConnectOptionsToTLSConnectOptions(opts, options);
    const auto alias = options.GetTlsSecureOptions().GetCertAlias();
    if (alias && !TlsSocket::IsValidCertAlias(*alias)) {
        return TlsSocket::TLS_ALIAS_INVALID;
    }

    auto context = std::make_shared<SyncCallbackContext>();
    server.tlsSocketServer_->Listen(options, [context](int32_t errorNumber) {
        std::lock_guard<std::mutex> lock(context->mutex);
        context->errorCode = errorNumber;
        context->completed = true;
        context->cv.notify_one();
    });
    std::unique_lock<std::mutex> lock(context->mutex);
    context->cv.wait(lock, [&context] { return context->completed; });
    return context->errorCode;
}

int32_t TlsServerGetState(TlsServerContext &server, FFISocketStateBase &status)
{
    if (server.tlsSocketServer_ != nullptr) {
        auto context = std::make_shared<SyncCallbackContext>();
        Socket::SocketStateBase state;
        server.tlsSocketServer_->GetState([context, &state]
            (int32_t errorNumber, const Socket::SocketStateBase &stateBase) {
            std::lock_guard<std::mutex> lock(context->mutex);
            context->errorCode = errorNumber;
            state = stateBase;
            context->completed = true;
            context->cv.notify_one();
        });
        std::unique_lock<std::mutex> lock(context->mutex);
        context->cv.wait(lock, [&context] { return context->completed; });

        SocketStateBaseToFFISocketStateBase(state, status);
        return context->errorCode;
    }
    return TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS;
}

int32_t TlsServerGetSocketFd(TlsServerContext &server, int32_t &fd)
{
    if (!CommonUtils::HasInternetPermission()) {
        return NetStack::Socket::PERMISSION_DENIED_CODE;
    }
    fd = server.tlsSocketServer_ != nullptr ? server.tlsSocketServer_->GetListenSocketFd() : -1;
    return TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS;
}

int32_t TlsServerClose(TlsServerContext &server)
{
    if (!CommonUtils::HasInternetPermission()) {
        return NetStack::Socket::PERMISSION_DENIED_CODE;
    }

    if (server.tlsSocketServer_ == nullptr) {
        return TlsSocket::TlsSocketError::TLS_ERR_NO_BIND;
    }

    auto context = std::make_shared<SyncCallbackContext>();
    server.tlsSocketServer_->Stop([context](int32_t errorNumber) {
        std::lock_guard<std::mutex> lock(context->mutex);
        context->errorCode = errorNumber;
        context->completed = true;
        context->cv.notify_one();
    });
    std::unique_lock<std::mutex> lock(context->mutex);
    context->cv.wait(lock, [&context] { return context->completed; });
    return context->errorCode;
}

int32_t TlsServerSetExtraOptions(TlsServerContext &server, const FFITcpExtraOptions &opts)
{
    if (server.tlsSocketServer_ == nullptr) {
        return TlsSocket::TlsSocketError::TLS_ERR_NO_BIND;
    }

    Socket::TCPExtraOptions options;
    FFITcpExtraOptionsToTCPExtraOptions(opts, options);

    auto context = std::make_shared<SyncCallbackContext>();
    server.tlsSocketServer_->SetExtraOptions(options, [context](int32_t errorNumber) {
        std::lock_guard<std::mutex> lock(context->mutex);
        context->errorCode = errorNumber;
        context->completed = true;
        context->cv.notify_one();
    });
    std::unique_lock<std::mutex> lock(context->mutex);
    context->cv.wait(lock, [&context] { return context->completed; });
    return context->errorCode;
}

int32_t TlsServerGetCertificate(TlsServerContext &server, FFIX509CertRawData &cert)
{
    if (server.tlsSocketServer_ == nullptr) {
        return TlsSocket::TlsSocketError::TLS_ERR_NO_BIND;
    }

    auto context = std::make_shared<SyncCallbackContext>();
    TlsSocket::X509CertRawData certData;
    server.tlsSocketServer_->GetCertificate([context, &certData]
        (int32_t errorNumber, const TlsSocket::X509CertRawData &c) {
        std::lock_guard<std::mutex> lock(context->mutex);
        context->errorCode = errorNumber;
        certData = c;
        context->completed = true;
        context->cv.notify_one();
    });
    std::unique_lock<std::mutex> lock(context->mutex);
    context->cv.wait(lock, [&context] { return context->completed; });
    X509CertRawDataToFFIX509CertRawData(certData, cert);
    return context->errorCode;
}

int32_t TlsServerGetProtocol(TlsServerContext &server, rust::String &protocol)
{
    if (server.tlsSocketServer_ == nullptr) {
        return TlsSocket::TlsSocketError::TLS_ERR_NO_BIND;
    }

    auto context = std::make_shared<SyncCallbackContext>();
    std::string protocolStr;
    server.tlsSocketServer_->GetProtocol([context, &protocolStr]
        (int32_t errorNumber, const std::string &protocolName) {
        std::lock_guard<std::mutex> lock(context->mutex);
        context->errorCode = errorNumber;
        protocolStr = protocolName;
        context->completed = true;
        context->cv.notify_one();
    });
    std::unique_lock<std::mutex> lock(context->mutex);
    context->cv.wait(lock, [&context] { return context->completed; });
    protocol = rust::String(protocolStr);
    return context->errorCode;
}

int32_t TlsServerGetLocalAddress(TlsServerContext &server, FFINetAddress &addr)
{
    if (server.tlsSocketServer_ == nullptr) {
        return TlsSocket::TlsSocketError::TLS_ERR_NO_BIND;
    }

    struct sockaddr_storage addrStorage{};
    socklen_t addrLen = sizeof(addrStorage);
    if (getsockname(server.tlsSocketServer_->GetListenSocketFd(),
        reinterpret_cast<struct sockaddr*>(&addrStorage), &addrLen) < 0) {
        return NetStack::Socket::ConvertSocketClientErrno(errno);
    }

    char ipStr[INET6_ADDRSTRLEN] = {0};
    Socket::NetAddress localAddress;
    if (addrStorage.ss_family == AF_INET) {
        auto *addr_in = reinterpret_cast<struct sockaddr_in*>(&addrStorage);
        inet_ntop(AF_INET, &addr_in->sin_addr, ipStr, sizeof(ipStr));
        localAddress.SetFamilyBySaFamily(AF_INET);
        localAddress.SetRawAddress(ipStr);
        localAddress.SetPort(ntohs(addr_in->sin_port));
        server.tlsSocketServer_->SetLocalAddress(localAddress);
    } else if (addrStorage.ss_family == AF_INET6) {
        auto *addr_in6 = reinterpret_cast<struct sockaddr_in6*>(&addrStorage);
        inet_ntop(AF_INET6, &addr_in6->sin6_addr, ipStr, sizeof(ipStr));
        localAddress.SetFamilyBySaFamily(AF_INET6);
        localAddress.SetRawAddress(ipStr);
        localAddress.SetPort(ntohs(addr_in6->sin6_port));
        server.tlsSocketServer_->SetLocalAddress(localAddress);
    }

    NetAddressToFFINetAddress(localAddress, addr);
    return TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS;
}

int32_t TlsServerOnConnect(TlsServerContext &server, rust::Box<TlsServerConnectBox> callbackBox)
{
    server.connectBoxHolder_ = std::make_shared<rust::Box<TlsServerConnectBox>>(std::move(callbackBox));
    TlsServerSetConnectCallback(server);
    return TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS;
}

int32_t TlsServerOnError(TlsServerContext &server, rust::Box<TlsServerErrorBox> callbackBox)
{
    server.errorBoxHolder_ = std::make_shared<rust::Box<TlsServerErrorBox>>(std::move(callbackBox));
    TlsServerSetErrorCallback(server);
    return TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS;
}

int32_t TlsServerOffConnect(TlsServerContext &server)
{
    if (server.tlsSocketServer_ != nullptr) {
        server.tlsSocketServer_->OffConnect();
    }
    server.connectBoxHolder_ = nullptr;
    return TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS;
}

int32_t TlsServerOffError(TlsServerContext &server)
{
    if (server.tlsSocketServer_ != nullptr) {
        server.tlsSocketServer_->OffError();
    }
    server.errorBoxHolder_ = nullptr;
    return TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS;
}

TlsConnectContext::~TlsConnectContext()
{
    if (auto server = tlsSocketServer_.lock()) {
        server->Close(clientId_, [this](int32_t errorNumber) {
            NETSTACK_LOGE("tls connect close %{public}d fail %{public}d", this->clientId_, errorNumber);
        });
    }
}

std::unique_ptr<TlsConnectContext> CreateTlsConnectContext(TlsServerContext &server, int32_t clientId)
{
    auto ctx = std::make_unique<TlsConnectContext>();

    if (server.tlsSocketServer_ != nullptr) {
        ctx->tlsSocketServer_ = server.tlsSocketServer_;
    }
    ctx->clientId_ = clientId;
    return ctx;
}

int32_t TlsConnectSend(TlsConnectContext &connect, FFITcpSendOptions opts)
{
    auto server = connect.tlsSocketServer_.lock();
    if (server == nullptr) {
        return TlsSocket::TlsSocketError::TLS_ERR_NO_BIND;
    }

    std::string sendData(reinterpret_cast<const char *>(opts.data.data()), opts.data.size());

    NetStack::TlsSocketServer::TLSServerSendOptions tlsServerSendOptions;
    tlsServerSendOptions.SetSocket(connect.clientId_);
    tlsServerSendOptions.SetSendData(sendData);

    auto context = std::make_shared<SyncCallbackContext>();
    server->Send(tlsServerSendOptions, [context](int32_t errorNumber) {
        std::lock_guard<std::mutex> lock(context->mutex);
        context->errorCode = errorNumber;
        context->completed = true;
        context->cv.notify_one();
    });
    std::unique_lock<std::mutex> lock(context->mutex);
    context->cv.wait(lock, [&context] { return context->completed; });
    return context->errorCode;
}

int32_t TlsConnectClose(TlsConnectContext &connect)
{
    auto server = connect.tlsSocketServer_.lock();
    if (server == nullptr) {
        return TlsSocket::TlsSocketError::TLS_ERR_NO_BIND;
    }

    auto context = std::make_shared<SyncCallbackContext>();
    server->Close(connect.clientId_, [context](int32_t errorNumber) {
        std::lock_guard<std::mutex> lock(context->mutex);
        context->errorCode = errorNumber;
        context->completed = true;
        context->cv.notify_one();
    });
    std::unique_lock<std::mutex> lock(context->mutex);
    context->cv.wait(lock, [&context] { return context->completed; });
    return context->errorCode;
}

int32_t TlsConnectGetRemoteAddress(TlsConnectContext &connect, FFINetAddress &addr)
{
    auto server = connect.tlsSocketServer_.lock();
    if (server == nullptr) {
        return TlsSocket::TlsSocketError::TLS_ERR_NO_BIND;
    }

    Socket::NetAddress remoteAddress;
    auto context = std::make_shared<SyncCallbackContext>();
    server->GetRemoteAddress(connect.clientId_,
        [context, &remoteAddress](int32_t errorNumber, Socket::NetAddress address) {
            std::lock_guard<std::mutex> lock(context->mutex);
            context->errorCode = errorNumber;
            remoteAddress = address;
            context->completed = true;
            context->cv.notify_one();
        });
    std::unique_lock<std::mutex> lock(context->mutex);
    context->cv.wait(lock, [&context] { return context->completed; });

    NetAddressToFFINetAddress(remoteAddress, addr);
    return context->errorCode;
}

int32_t TlsConnectGetLocalAddress(TlsConnectContext &connect, FFINetAddress &addr)
{
    auto server = connect.tlsSocketServer_.lock();
    if (server == nullptr) {
        return TlsSocket::TlsSocketError::TLS_ERR_NO_BIND;
    }

    Socket::NetAddress localAddress;
    auto context = std::make_shared<SyncCallbackContext>();
    server->GetLocalAddress(connect.clientId_,
        [context, &localAddress](int32_t errorNumber, Socket::NetAddress address) {
            std::lock_guard<std::mutex> lock(context->mutex);
            context->errorCode = errorNumber;
            localAddress = address;
            context->completed = true;
            context->cv.notify_one();
        });
    std::unique_lock<std::mutex> lock(context->mutex);
    context->cv.wait(lock, [&context] { return context->completed; });

    NetAddressToFFINetAddress(localAddress, addr);
    return context->errorCode;
}

int32_t TlsConnectGetRemoteCertificate(TlsConnectContext &connect, FFIX509CertRawData &cert)
{
    auto server = connect.tlsSocketServer_.lock();
    if (server == nullptr) {
        return TlsSocket::TlsSocketError::TLS_ERR_NO_BIND;
    }

    TlsSocket::X509CertRawData certRawData;
    auto context = std::make_shared<SyncCallbackContext>();
    server->GetRemoteCertificate(connect.clientId_,
        [context, &certRawData](int32_t errorNumber, const TlsSocket::X509CertRawData &cert) {
            std::lock_guard<std::mutex> lock(context->mutex);
            context->errorCode = errorNumber;
            certRawData = cert;
            context->completed = true;
            context->cv.notify_one();
        });
    std::unique_lock<std::mutex> lock(context->mutex);
    context->cv.wait(lock, [&context] { return context->completed; });

    X509CertRawDataToFFIX509CertRawData(certRawData, cert);
    return context->errorCode;
}

int32_t TlsConnectGetSocketFd(TlsConnectContext &connect, int &fd)
{
    if (!CommonUtils::HasInternetPermission()) {
        return NetStack::Socket::PERMISSION_DENIED_CODE;
    }

    auto server = connect.tlsSocketServer_.lock();
    if (server == nullptr) {
        return TlsSocket::TlsSocketError::TLS_ERR_NO_BIND;
    }

    fd = server->GetClientSocketFd(connect.clientId_);
    return TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS;
}

int32_t TlsConnectGetProtocol(TlsConnectContext &connect, rust::String &protocol)
{
    auto server = connect.tlsSocketServer_.lock();
    if (server == nullptr) {
        return TlsSocket::TlsSocketError::TLS_ERR_NO_BIND;
    }

    std::string protocolStr;
    auto context = std::make_shared<SyncCallbackContext>();
    server->GetProtocol([&context, &protocolStr](int32_t errorNumber, const std::string &protocol) {
        std::lock_guard<std::mutex> lock(context->mutex);
        context->errorCode = errorNumber;
        protocolStr = protocol;
        context->completed = true;
        context->cv.notify_one();
    });
    std::unique_lock<std::mutex> lock(context->mutex);
    context->cv.wait(lock, [&context] { return context->completed; });

    protocol = rust::String(protocolStr);
    return context->errorCode;
}

int32_t TlsConnectGetCipherSuites(TlsConnectContext &connect, rust::Vec<rust::String> &cipherSuites)
{
    auto server = connect.tlsSocketServer_.lock();
    if (server == nullptr) {
        return TlsSocket::TlsSocketError::TLS_ERR_NO_BIND;
    }

    std::vector<std::string> cipherSuiteVec;
    auto context = std::make_shared<SyncCallbackContext>();
    server->GetCipherSuite(connect.clientId_, [&context, &cipherSuiteVec]
        (int32_t errorNumber, const std::vector<std::string> &suite) {
        std::lock_guard<std::mutex> lock(context->mutex);
        context->errorCode = errorNumber;
        cipherSuiteVec = suite;
        context->completed = true;
        context->cv.notify_one();
    });
    std::unique_lock<std::mutex> lock(context->mutex);
    context->cv.wait(lock, [&context] { return context->completed; });

    cipherSuites.clear();
    for (const auto &item : cipherSuiteVec) {
        cipherSuites.push_back(rust::String(item));
    }
    return context->errorCode;
}

int32_t TlsConnectGetSignatureAlgorithms(TlsConnectContext &connect, rust::Vec<rust::String> &signatureAlgorithms)
{
    auto server = connect.tlsSocketServer_.lock();
    if (server == nullptr) {
        return TlsSocket::TlsSocketError::TLS_ERR_NO_BIND;
    }

    std::vector<std::string> algorithmsVec;
    auto context = std::make_shared<SyncCallbackContext>();
    server->GetSignatureAlgorithms(connect.clientId_, [&context, &algorithmsVec]
        (int32_t errorNumber, const std::vector<std::string> &algorithms) {
        std::lock_guard<std::mutex> lock(context->mutex);
        context->errorCode = errorNumber;
        algorithmsVec = algorithms;
        context->completed = true;
        context->cv.notify_one();
    });
    std::unique_lock<std::mutex> lock(context->mutex);
    context->cv.wait(lock, [&context] { return context->completed; });

    signatureAlgorithms.clear();
    for (const auto &item : algorithmsVec) {
        signatureAlgorithms.push_back(rust::String(item));
    }
    return context->errorCode;
}

int32_t TlsConnectOnMessage(TlsConnectContext &connect, rust::Box<TlsConnectMessageBox> callbackBox)
{
    connect.messageBoxHolder_ = std::make_shared<rust::Box<TlsConnectMessageBox>>(std::move(callbackBox));
    auto server = connect.tlsSocketServer_.lock();
    if (server == nullptr) {
        return TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS;
    }
    auto ptrConnection = server->GetConnectionByClientID(connect.clientId_);
    if (ptrConnection == nullptr) {
        return TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS;
    }
    std::weak_ptr<rust::Box<TlsConnectMessageBox>> weakMessageBox = connect.messageBoxHolder_;
    ptrConnection->OnMessage([weakMessageBox]
        (const int &socketFd, const std::string &data, const Socket::SocketRemoteInfo &remoteInfo) {
        if (auto messageBox = weakMessageBox.lock()) {
            rust::Vec<uint8_t> vecData;
            for (const auto &byte : data) {
                vecData.push_back(static_cast<uint8_t>(byte));
            }

            rust::String address(remoteInfo.GetAddress());
            rust::String family(remoteInfo.GetFamily());
            int32_t port = static_cast<int32_t>(remoteInfo.GetPort());
            int32_t size = static_cast<int32_t>(remoteInfo.GetSize());

            (*messageBox)->on_message(vecData, address, family, port, size);
        }
    });
    return TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS;
}

int32_t TlsConnectOnClose(TlsConnectContext &connection, rust::Box<TlsConnectCloseBox> callbackBox)
{
    connection.closeBoxHolder_ = std::make_shared<rust::Box<TlsConnectCloseBox>>(std::move(callbackBox));
    auto server = connection.tlsSocketServer_.lock();
    if (server == nullptr) {
        return TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS;
    }
    auto ptrConnection = server->GetConnectionByClientID(connection.clientId_);
    if (ptrConnection == nullptr) {
        return TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS;
    }
    std::weak_ptr<rust::Box<TlsConnectCloseBox>> weakCloseBox = connection.closeBoxHolder_;
    ptrConnection->OnClose([weakCloseBox](const int &socketFd) {
        if (auto closeBox = weakCloseBox.lock()) {
            (*closeBox)->on_close();
        }
    });
    return TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS;
}

int32_t TlsConnectOnError(TlsConnectContext &connection, rust::Box<TlsConnectErrorBox> callbackBox)
{
    connection.errorBoxHolder_ = std::make_shared<rust::Box<TlsConnectErrorBox>>(std::move(callbackBox));
    auto server = connection.tlsSocketServer_.lock();
    if (server == nullptr) {
        return TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS;
    }
    auto ptrConnection = server->GetConnectionByClientID(connection.clientId_);
    if (ptrConnection == nullptr) {
        return TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS;
    }
    std::weak_ptr<rust::Box<TlsConnectErrorBox>> weakErrorBox = connection.errorBoxHolder_;
    ptrConnection->OnError([weakErrorBox](int32_t errorNumber, const std::string &errorString) {
        if (auto errorBox = weakErrorBox.lock()) {
            (*errorBox)->on_error(errorNumber, rust::String(errorString));
        }
    });
    return TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS;
}

int32_t TlsConnectOffMessage(TlsConnectContext &connection)
{
    auto server = connection.tlsSocketServer_.lock();
    if (server != nullptr) {
        auto ptrConnection = server->GetConnectionByClientID(connection.clientId_);
        if (ptrConnection != nullptr) {
            ptrConnection->OffMessage();
        }
    }
    connection.messageBoxHolder_ = nullptr;
    return TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS;
}

int32_t TlsConnectOffClose(TlsConnectContext &connection)
{
    auto server = connection.tlsSocketServer_.lock();
    if (server != nullptr) {
        auto ptrConnection = server->GetConnectionByClientID(connection.clientId_);
        if (ptrConnection != nullptr) {
            ptrConnection->OffClose();
        }
    }
    connection.closeBoxHolder_ = nullptr;
    return TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS;
}

int32_t TlsConnectOffError(TlsConnectContext &connection)
{
    auto server = connection.tlsSocketServer_.lock();
    if (server != nullptr) {
        auto ptrConnection = server->GetConnectionByClientID(connection.clientId_);
        if (ptrConnection != nullptr) {
            ptrConnection->OffError();
        }
    }
    connection.errorBoxHolder_ = nullptr;
    return TlsSocket::TlsSocketError::TLSSOCKET_SUCCESS;
}

} // namespace NetStackAni
} // namespace OHOS
