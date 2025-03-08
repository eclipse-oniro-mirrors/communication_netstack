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

#include "tlssocket_exec.h"

#include <string>
#include <vector>

#include <napi/native_api.h>
#include <securec.h>

#include "context_key.h"
#include "event_list.h"
#include "napi_utils.h"
#include "netstack_log.h"
#include "socket_error.h"
#include "tls_socket.h"
#include "socket_exec_common.h"

#ifdef IOS_PLATFORM
#define SO_PROTOCOL 38
#endif

namespace OHOS {
namespace NetStack {
namespace TlsSocket {
namespace {
constexpr const char *CERTIFICATA_DATA = "data";
constexpr const char *CERTIFICATA_ENCODING_FORMAT = "encodingFormat";
} // namespace

static inline void TLSSocketThrowException(TLSInitContext *context, int32_t errorCode)
{
    context->SetNeedThrowException(true);
    context->SetError(errorCode, MakeErrorMessage(errorCode));
}

static inline bool IsTCPSocket(int sockFD)
{
    int optval;
    socklen_t optlen = sizeof(optval);

    if (getsockopt(sockFD, SOL_SOCKET, SO_PROTOCOL, &optval, &optlen) != 0) {
        return false;
    }
    return optval == IPPROTO_TCP;
}

static inline bool IsConnected(int sockFD)
{
    sockaddr_storage addr{};
    socklen_t len = sizeof(addr);
    return getpeername(sockFD, reinterpret_cast<sockaddr *>(&addr), &len) == 0;
}

bool TLSSocketExec::ExecInit(TLSInitContext *context)
{
    auto manager = context->GetManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        TLSSocketThrowException(context, SYSTEM_INTERNAL_ERROR);
        return false;
    }

    auto sockFd = static_cast<int>(reinterpret_cast<uint64_t>(context->extManager_->GetData()));
    if (sockFd <= 0 || !IsTCPSocket(sockFd)) {
        NETSTACK_LOGE("invalid tcp socket fd");
        TLSSocketThrowException(context, TLS_ERR_SOCK_INVALID_FD);
        return false;
    }

    if (!IsConnected(sockFd)) {
        NETSTACK_LOGE("tcp socket is not connected");
        TLSSocketThrowException(context, TLS_ERR_SOCK_NOT_CONNECT);
        return false;
    }

    auto tlsSocket = new TLSSocket(sockFd);
    if (tlsSocket == nullptr) {
        NETSTACK_LOGE("new TLSSocket failed, no enough memory");
        TLSSocketThrowException(context, SYSTEM_INTERNAL_ERROR);
        return false;
    }

    manager->SetData(tlsSocket);

    std::string events[] = {EVENT_MESSAGE, EVENT_ERROR, EVENT_CONNECT, EVENT_CLOSE};
    for (auto event : events) {
        context->extManager_->DeleteListener(event);
    }

    context->extManager_->SetData(reinterpret_cast<void *>(-1));
    context->extManager_->WaitForRcvThdExit();
    return true;
}

bool TLSSocketExec::ExecGetCertificate(GetCertificateContext *context)
{
    auto manager = context->GetManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    auto tlsSocket = reinterpret_cast<TLSSocket *>(manager->GetData());
    if (tlsSocket == nullptr) {
        NETSTACK_LOGE("ExecGetCertificate tlsSocket is null");
        context->SetError(TLS_ERR_NO_BIND, MakeErrorMessage(TLS_ERR_NO_BIND));
        return false;
    }
    tlsSocket->GetCertificate([&context](int32_t errorNumber, const X509CertRawData &cert) {
        context->localCert_ = cert;
        context->errorNumber_ = errorNumber;
        if (errorNumber != TLSSOCKET_SUCCESS) {
            context->SetError(errorNumber, MakeErrorMessage(errorNumber));
        }
    });
    return context->errorNumber_ == TLSSOCKET_SUCCESS;
}

bool TLSSocketExec::ExecConnect(TLSConnectContext *context)
{
    if (context) {
        context->connectOptions_.address_.SetRawAddress(ConvertAddressToIp(
            context->connectOptions_.address_.GetAddress(), context->connectOptions_.address_.GetSaFamily()));
    }
    auto manager = context->GetManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    auto tlsSocket = reinterpret_cast<TLSSocket *>(manager->GetData());
    if (tlsSocket == nullptr) {
        NETSTACK_LOGE("ExecConnect tlsSocket is null");
        context->SetError(TLS_ERR_NO_BIND, MakeErrorMessage(TLS_ERR_NO_BIND));
        return false;
    }
    tlsSocket->Connect(context->connectOptions_, [&context](int32_t errorNumber) {
        context->errorNumber_ = errorNumber;
        if (errorNumber != TLSSOCKET_SUCCESS) {
            context->SetError(errorNumber, MakeErrorMessage(errorNumber));
        }
    });
    return context->errorNumber_ == TLSSOCKET_SUCCESS;
}

bool TLSSocketExec::ExecGetCipherSuites(GetCipherSuitesContext *context)
{
    auto manager = context->GetManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    auto tlsSocket = reinterpret_cast<TLSSocket *>(manager->GetData());
    if (tlsSocket == nullptr) {
        NETSTACK_LOGE("ExecGetCipherSuites tlsSocket is null");
        context->SetError(TLS_ERR_NO_BIND, MakeErrorMessage(TLS_ERR_NO_BIND));
        return false;
    }
    tlsSocket->GetCipherSuite([&context](int32_t errorNumber, const std::vector<std::string> &suite) {
        context->cipherSuites_ = suite;
        context->errorNumber_ = errorNumber;
        if (errorNumber != TLSSOCKET_SUCCESS) {
            context->SetError(errorNumber, MakeErrorMessage(errorNumber));
        }
    });
    return context->errorNumber_ == TLSSOCKET_SUCCESS;
}

bool TLSSocketExec::ExecGetRemoteCertificate(GetRemoteCertificateContext *context)
{
    auto manager = context->GetManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    auto tlsSocket = reinterpret_cast<TLSSocket *>(manager->GetData());
    if (tlsSocket == nullptr) {
        NETSTACK_LOGE("ExecGetRemoteCertificate tlsSocket is null");
        context->SetError(TLS_ERR_NO_BIND, MakeErrorMessage(TLS_ERR_NO_BIND));
        return false;
    }
    tlsSocket->GetRemoteCertificate([&context](int32_t errorNumber, const X509CertRawData &cert) {
        context->remoteCert_ = cert;
        context->errorNumber_ = errorNumber;
        if (errorNumber != TLSSOCKET_SUCCESS) {
            context->SetError(errorNumber, MakeErrorMessage(errorNumber));
        }
    });
    return context->errorNumber_ == TLSSOCKET_SUCCESS;
}

bool TLSSocketExec::ExecGetProtocol(GetProtocolContext *context)
{
    auto manager = context->GetManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    auto tlsSocket = reinterpret_cast<TLSSocket *>(manager->GetData());
    if (tlsSocket == nullptr) {
        NETSTACK_LOGE("ExecGetProtocol tlsSocket is null");
        context->SetError(TLS_ERR_NO_BIND, MakeErrorMessage(TLS_ERR_NO_BIND));
        return false;
    }
    tlsSocket->GetProtocol([&context](int32_t errorNumber, const std::string &protocol) {
        context->protocol_ = protocol;
        context->errorNumber_ = errorNumber;
        if (errorNumber != TLSSOCKET_SUCCESS) {
            context->SetError(errorNumber, MakeErrorMessage(errorNumber));
        }
    });
    return context->errorNumber_ == TLSSOCKET_SUCCESS;
}

bool TLSSocketExec::ExecGetSignatureAlgorithms(GetSignatureAlgorithmsContext *context)
{
    auto manager = context->GetManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    auto tlsSocket = reinterpret_cast<TLSSocket *>(manager->GetData());
    if (tlsSocket == nullptr) {
        NETSTACK_LOGE("ExecGetSignatureAlgorithms tlsSocket is null");
        context->SetError(TLS_ERR_NO_BIND, MakeErrorMessage(TLS_ERR_NO_BIND));
        return false;
    }
    tlsSocket->GetSignatureAlgorithms([&context](int32_t errorNumber, const std::vector<std::string> &algorithms) {
        context->signatureAlgorithms_ = algorithms;
        context->errorNumber_ = errorNumber;
        if (errorNumber != TLSSOCKET_SUCCESS) {
            context->SetError(errorNumber, MakeErrorMessage(errorNumber));
        }
    });
    return context->errorNumber_ == TLSSOCKET_SUCCESS;
}

bool TLSSocketExec::ExecSend(TLSSendContext *context)
{
    auto manager = context->GetManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    auto tlsSocket = reinterpret_cast<TLSSocket *>(manager->GetData());
    if (tlsSocket == nullptr) {
        NETSTACK_LOGE("ExecSend tlsSocket is null");
        context->SetError(TLS_ERR_NO_BIND, MakeErrorMessage(TLS_ERR_NO_BIND));
        return false;
    }
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(context->data_);
    tlsSocket->Send(tcpSendOptions, [&context](int32_t errorNumber) {
        context->errorNumber_ = errorNumber;
        if (errorNumber != TLSSOCKET_SUCCESS) {
            context->SetError(errorNumber, MakeErrorMessage(errorNumber));
        }
    });
    return context->errorNumber_ == TLSSOCKET_SUCCESS;
}

bool TLSSocketExec::ExecClose(TLSNapiContext *context)
{
    auto manager = context->GetManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    auto tlsSocket = reinterpret_cast<TLSSocket *>(manager->GetData());
    if (tlsSocket == nullptr) {
        NETSTACK_LOGE("ExecClose tlsSocket is null");
        context->SetError(TLS_ERR_NO_BIND, MakeErrorMessage(TLS_ERR_NO_BIND));
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(tlsSocket->GetCloseLock());
        if (tlsSocket->GetCloseState()) {
            NETSTACK_LOGE("Socket is closing");
            return true;
        }
        tlsSocket->SetCloseState(true);
    }
    tlsSocket->Close([&context](int32_t errorNumber) {
        context->errorNumber_ = errorNumber;
        if (errorNumber != TLSSOCKET_SUCCESS) {
            context->SetError(errorNumber, MakeErrorMessage(errorNumber));
        }
    });
    delete tlsSocket;
    manager->SetData(nullptr);
    return context->errorNumber_ == TLSSOCKET_SUCCESS;
}

bool TLSSocketExec::ExecBind(TLSBindContext *context)
{
    auto manager = context->GetManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }

    auto tlsSocket = reinterpret_cast<TLSSocket *>(manager->GetData());
    if (tlsSocket != nullptr) {
        NETSTACK_LOGI("TLSSocket has been constructed");
        return true;
    }

    tlsSocket = new TLSSocket();
    if (tlsSocket == nullptr) {
        NETSTACK_LOGE("new TLSSocket failed, no enough memory");
        return false;
    }

    tlsSocket->Bind(context->address_, [&context](int32_t errorNumber) {
        context->errorNumber_ = errorNumber;
        if (errorNumber != TLSSOCKET_SUCCESS) {
            std::string errorString = MakeErrorMessage(errorNumber);
            context->SetError(errorNumber, errorString);
        }
    });
    manager->SetData(tlsSocket);
    return context->errorNumber_ == TLSSOCKET_SUCCESS;
}

bool TLSSocketExec::ExecGetRemoteAddress(TLSGetRemoteAddressContext *context)
{
    auto manager = context->GetManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    auto tlsSocket = reinterpret_cast<TLSSocket *>(manager->GetData());
    if (tlsSocket == nullptr) {
        NETSTACK_LOGE("ExecGetRemoteAddress tlsSocket is null");
        context->SetError(TLS_ERR_NO_BIND, MakeErrorMessage(TLS_ERR_NO_BIND));
        return false;
    }
    tlsSocket->GetRemoteAddress([&context](int32_t errorNumber, const Socket::NetAddress address) {
        context->address_ = address;
        context->errorNumber_ = errorNumber;
        if (errorNumber != TLSSOCKET_SUCCESS) {
            context->SetError(errorNumber, MakeErrorMessage(errorNumber));
        }
    });
    return context->errorNumber_ == TLSSOCKET_SUCCESS;
}

bool TLSSocketExec::ExecGetLocalAddress(TLSGetLocalAddressContext *context)
{
    if (context == nullptr) {
        NETSTACK_LOGE("context is nullptr");
        return false;
    }
    auto manager = context->GetManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        context->SetNeedThrowException(true);
        context->SetError(TlsSocket::TlsSocketError::TLS_ERR_NO_BIND,
                          TlsSocket::MakeErrorMessage(TlsSocket::TlsSocketError::TLS_ERR_NO_BIND));
        return false;
    }
    auto tlsSocket = reinterpret_cast<TLSSocket *>(manager->GetData());
    if (tlsSocket == nullptr) {
        NETSTACK_LOGE("get local address tlsSocketServer is null");
        context->SetError(TlsSocket::TlsSocketError::TLS_ERR_NO_BIND,
                          TlsSocket::MakeErrorMessage(TlsSocket::TlsSocketError::TLS_ERR_NO_BIND));
        return false;
    }
    auto listenSocketFD = tlsSocket->GetSocketFd();
    struct sockaddr_storage addr {};
    socklen_t addrLen = sizeof(addr);
    if (getsockname(listenSocketFD, (struct sockaddr *)&addr, &addrLen) == -1) {
        context->SetNeedThrowException(true);
        context->SetErrorCode(errno);
        return false;
    }

    char ipStr[INET6_ADDRSTRLEN] = {0};
    Socket::NetAddress localAddress;
    if (addr.ss_family == AF_INET) {
        auto *addr_in = (struct sockaddr_in *)&addr;
        inet_ntop(AF_INET, &addr_in->sin_addr, ipStr, sizeof(ipStr));
        localAddress.SetFamilyBySaFamily(AF_INET);
        localAddress.SetRawAddress(ipStr);
        localAddress.SetPort(ntohs(addr_in->sin_port));
        tlsSocket->SetLocalAddress(localAddress);
    } else if (addr.ss_family == AF_INET6) {
        auto *addr_in6 = (struct sockaddr_in6 *)&addr;
        inet_ntop(AF_INET6, &addr_in6->sin6_addr, ipStr, sizeof(ipStr));
        localAddress.SetFamilyBySaFamily(AF_INET6);
        localAddress.SetRawAddress(ipStr);
        localAddress.SetPort(ntohs(addr_in6->sin6_port));
        tlsSocket->SetLocalAddress(localAddress);
    }
    return true;
}

bool TLSSocketExec::ExecGetState(TLSGetStateContext *context)
{
    auto manager = context->GetManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        context->SetError(TLS_ERR_SYS_EINVAL, MakeErrorMessage(TLS_ERR_SYS_EINVAL));
        return false;
    }
    auto tlsSocket = reinterpret_cast<TLSSocket *>(manager->GetData());
    if (tlsSocket == nullptr) {
        NETSTACK_LOGE("ExecGetState tlsSocket is null");
        return true;
    }
    tlsSocket->GetState([&context](int32_t errorNumber, const Socket::SocketStateBase state) {
        context->state_ = state;
        context->errorNumber_ = errorNumber;
        if (errorNumber != TLSSOCKET_SUCCESS) {
            context->SetError(errorNumber, MakeErrorMessage(errorNumber));
        }
    });
    return context->errorNumber_ == TLSSOCKET_SUCCESS;
}

bool TLSSocketExec::ExecSetExtraOptions(TLSSetExtraOptionsContext *context)
{
    auto manager = context->GetManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    auto tlsSocket = reinterpret_cast<TLSSocket *>(manager->GetData());
    if (tlsSocket == nullptr) {
        NETSTACK_LOGE("ExecSetExtraOptions tlsSocket is null");
        context->SetError(TLS_ERR_NO_BIND, MakeErrorMessage(TLS_ERR_NO_BIND));
        return false;
    }
    tlsSocket->SetExtraOptions(context->options_, [&context](int32_t errorNumber) {
        context->errorNumber_ = errorNumber;
        if (errorNumber != TLSSOCKET_SUCCESS) {
            context->SetError(errorNumber, MakeErrorMessage(errorNumber));
        }
    });
    return context->errorNumber_ == TLSSOCKET_SUCCESS;
}

bool TLSSocketExec::ExecGetSocketFd(TLSGetSocketFdContext *context)
{
    auto manager = context->GetManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    auto tlsSocket = reinterpret_cast<std::shared_ptr<TLSSocket> *>(manager->GetData());
    if (tlsSocket == nullptr) {
        NETSTACK_LOGE("ExecGetSocketFd tlsSocket is null");
        context->sockFd_= -1;
        return true;
    }
    auto shared = *tlsSocket;
    if (!shared) {
        NETSTACK_LOGE("ExecGetSocketFd tlsSocket is null");
        context->sockFd_= -1;
        return true;
    }
    context->sockFd_= shared->GetSocketFd();
    return true;
}

napi_value TLSSocketExec::GetSocketFdCallback(TLSGetSocketFdContext *context)
{
    if (context->sockFd_ < 0) {
        return NapiUtils::GetUndefined(context->GetEnv());
    }
    return NapiUtils::CreateInt32(context->GetEnv(), context->sockFd_);
}

napi_value TLSSocketExec::GetCertificateCallback(GetCertificateContext *context)
{
    void *data = nullptr;
    napi_value arrayBuffer = NapiUtils::CreateArrayBuffer(context->GetEnv(), context->localCert_.data.Length(), &data);
    if (data != nullptr && arrayBuffer != nullptr) {
        if (memcpy_s(data, context->localCert_.data.Length(),
                     reinterpret_cast<const uint8_t *>(context->localCert_.data.Data()),
                     context->localCert_.data.Length()) != EOK) {
            NETSTACK_LOGE("memcpy_s failed!");
            return NapiUtils::GetUndefined(context->GetEnv());
        }
    }
    napi_value outData = nullptr;
    napi_create_typedarray(context->GetEnv(), napi_uint8_array, context->localCert_.data.Length(), arrayBuffer, 0,
                           &outData);
    napi_value obj = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), obj) != napi_object) {
        return NapiUtils::GetUndefined(context->GetEnv());
    }
    NapiUtils::SetNamedProperty(context->GetEnv(), obj, CERTIFICATA_DATA, outData);
    NapiUtils::SetInt32Property(context->GetEnv(), obj, CERTIFICATA_ENCODING_FORMAT,
                                context->localCert_.encodingFormat);
    return obj;
}

napi_value TLSSocketExec::ConnectCallback(TLSConnectContext *context)
{
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value TLSSocketExec::GetCipherSuitesCallback(GetCipherSuitesContext *context)
{
    napi_value cipherSuites = NapiUtils::CreateArray(context->GetEnv(), 0);
    int index = 0;
    for (const auto &cipher : context->cipherSuites_) {
        napi_value cipherSuite = NapiUtils::CreateStringUtf8(context->GetEnv(), cipher);
        NapiUtils::SetArrayElement(context->GetEnv(), cipherSuites, index++, cipherSuite);
    }
    return cipherSuites;
}

napi_value TLSSocketExec::GetRemoteCertificateCallback(GetRemoteCertificateContext *context)
{
    void *data = nullptr;
    napi_value arrayBuffer = NapiUtils::CreateArrayBuffer(context->GetEnv(), context->remoteCert_.data.Length(), &data);
    if (data != nullptr && arrayBuffer != nullptr) {
        if (memcpy_s(data, context->remoteCert_.data.Length(),
                     reinterpret_cast<const uint8_t *>(context->remoteCert_.data.Data()),
                     context->remoteCert_.data.Length()) != EOK) {
            NETSTACK_LOGE("memcpy_s failed!");
            return NapiUtils::GetUndefined(context->GetEnv());
        }
    }
    napi_value outData = nullptr;
    napi_create_typedarray(context->GetEnv(), napi_uint8_array, context->remoteCert_.data.Length(), arrayBuffer, 0,
                           &outData);
    napi_value obj = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), obj) != napi_object) {
        return NapiUtils::GetUndefined(context->GetEnv());
    }
    NapiUtils::SetNamedProperty(context->GetEnv(), obj, CERTIFICATA_DATA, outData);
    NapiUtils::SetInt32Property(context->GetEnv(), obj, CERTIFICATA_ENCODING_FORMAT,
                                context->remoteCert_.encodingFormat);
    return obj;
}

napi_value TLSSocketExec::GetProtocolCallback(GetProtocolContext *context)
{
    return NapiUtils::CreateStringUtf8(context->GetEnv(), context->protocol_);
}

napi_value TLSSocketExec::GetSignatureAlgorithmsCallback(GetSignatureAlgorithmsContext *context)
{
    napi_value signatureAlgorithms = NapiUtils::CreateArray(context->GetEnv(), 0);
    int index = 0;
    for (const auto &algorithm : context->signatureAlgorithms_) {
        napi_value signatureAlgorithm = NapiUtils::CreateStringUtf8(context->GetEnv(), algorithm);
        NapiUtils::SetArrayElement(context->GetEnv(), signatureAlgorithms, index++, signatureAlgorithm);
    }
    return signatureAlgorithms;
}

napi_value TLSSocketExec::SendCallback(TLSSendContext *context)
{
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value TLSSocketExec::CloseCallback(TLSNapiContext *context)
{
    auto manager = context->GetManager();
    if (manager != nullptr) {
        NETSTACK_LOGD("tls socket close, delete js ref");
        manager->DeleteEventReference(context->GetEnv());
    }
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value TLSSocketExec::BindCallback(TLSBindContext *context)
{
    context->Emit(EVENT_LISTENING, std::make_pair(NapiUtils::GetUndefined(context->GetEnv()),
                                                  NapiUtils::GetUndefined(context->GetEnv())));
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value TLSSocketExec::GetStateCallback(TLSGetStateContext *context)
{
    napi_value obj = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), obj) != napi_object) {
        return NapiUtils::GetUndefined(context->GetEnv());
    }
    NapiUtils::SetBooleanProperty(context->GetEnv(), obj, KEY_IS_BOUND, context->state_.IsBound());
    NapiUtils::SetBooleanProperty(context->GetEnv(), obj, KEY_IS_CLOSE, context->state_.IsClose());
    NapiUtils::SetBooleanProperty(context->GetEnv(), obj, KEY_IS_CONNECTED, context->state_.IsConnected());
    return obj;
}

napi_value TLSSocketExec::GetRemoteAddressCallback(TLSGetRemoteAddressContext *context)
{
    napi_value obj = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), obj) != napi_object) {
        return NapiUtils::GetUndefined(context->GetEnv());
    }
    NapiUtils::SetStringPropertyUtf8(context->GetEnv(), obj, KEY_ADDRESS, context->address_.GetAddress());
    NapiUtils::SetUint32Property(context->GetEnv(), obj, KEY_FAMILY, context->address_.GetJsValueFamily());
    NapiUtils::SetUint32Property(context->GetEnv(), obj, KEY_PORT, context->address_.GetPort());
    return obj;
}

napi_value TLSSocketExec::GetLocalAddressCallback(TLSGetLocalAddressContext *context)
{
    napi_value obj = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), obj) != napi_object) {
        return NapiUtils::GetUndefined(context->GetEnv());
    }
    auto manager = context->GetManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return obj;
    }
    auto tlsSocket = reinterpret_cast<TLSSocket *>(manager->GetData());
    if (tlsSocket == nullptr) {
        NETSTACK_LOGE("get localAddress callback tlsSocketServer is null");
        return obj;
    }
    auto env = context->GetEnv();
    NapiUtils::SetStringPropertyUtf8(env, obj, KEY_ADDRESS, tlsSocket->GetLocalAddress().GetAddress());
    NapiUtils::SetUint32Property(env, obj, KEY_FAMILY, tlsSocket->GetLocalAddress().GetJsValueFamily());
    NapiUtils::SetUint32Property(env, obj, KEY_PORT, tlsSocket->GetLocalAddress().GetPort());
    return obj;
}

napi_value TLSSocketExec::SetExtraOptionsCallback(TLSSetExtraOptionsContext *context)
{
    return NapiUtils::GetUndefined(context->GetEnv());
}

} // namespace TlsSocket
} // namespace NetStack
} // namespace OHOS
