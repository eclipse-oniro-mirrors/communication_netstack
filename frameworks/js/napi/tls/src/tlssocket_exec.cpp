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
#include <uv.h>

#include "context_key.h"
#include "event_list.h"
#include "napi_utils.h"
#include "netstack_log.h"
#include "tls_socket.h"

namespace OHOS {
namespace NetStack {
namespace {
constexpr int ARGN_LEN = 2;
constexpr int CALL_FUNCTION_NUM = 2;

void CheckServerIdentityCallback(uv_work_t *work, int status)
{
    NETSTACK_LOGD("checkServerIdentity callback");
    (void)status;
    if (work == nullptr) {
        NETSTACK_LOGE("work is nullptr");
        return;
    }
    auto context = reinterpret_cast<TLSConnectContext *>(work->data);
    if (context == nullptr) {
        NETSTACK_LOGE("context is nullptr");
        delete work;
        return;
    }
    napi_handle_scope scope = NapiUtils::OpenScope(context->GetEnv());
    napi_value hostName = NapiUtils::CreateStringUtf8(context->GetEnv(), context->hostName_);
    napi_value x509Certificate = NapiUtils::CreateArray(context->GetEnv(), context->x509Certificates_.size());
    uint32_t index = 0;
    for (const auto &cert : context->x509Certificates_) {
        napi_value x509Cert = NapiUtils::CreateStringUtf8(context->GetEnv(), cert);
        NapiUtils::SetArrayElement(context->GetEnv(), x509Certificate, index++, x509Cert);
    }
    napi_value argv[ARGN_LEN] = {hostName, x509Certificate};
    napi_value func = NapiUtils::GetReference(context->GetEnv(), context->checkCallback_);
    NapiUtils::CallFunction(context->GetEnv(), NapiUtils::GetUndefined(context->GetEnv()), func, CALL_FUNCTION_NUM,
                            argv);
    NapiUtils::CloseScope(context->GetEnv(), scope);
    delete work;
}
} // namespace

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
        return false;
    }
    tlsSocket->GetCertificate([&context](bool isOk, const std::string &cert) {
        context->isOk_ = isOk;
        context->cert_ = cert;
    });
    return context->isOk_;
}

bool TLSSocketExec::ExecConnect(TLSConnectContext *context)
{
    auto manager = context->GetManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    auto tlsSocket = reinterpret_cast<TLSSocket *>(manager->GetData());
    if (tlsSocket == nullptr) {
        NETSTACK_LOGE("ExecConnect tlsSocket is null");
        return false;
    }
    if (context->checkCallback_ != nullptr) {
        context->connectOptions_.SetCheckServerIdentity(
            [&context](const std::string &hostName, const std::vector<std::string> &x509Certificates) {
                context->hostName_ = hostName;
                context->x509Certificates_ = x509Certificates;
                NapiUtils::CreateUvQueueWork(context->GetEnv(), reinterpret_cast<void *>(context),
                                             CheckServerIdentityCallback);
            });
    }
    tlsSocket->Connect(context->connectOptions_, [&context](bool isOk) { context->isOk_ = isOk; });
    if (!context->isOk_) {
        NETSTACK_LOGE("ExecConnect result is false");
        return false;
    }
    return true;
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
        return false;
    }
    tlsSocket->GetCipherSuite([&context](bool isOk, const std::vector<std::string> &suite) {
        context->isOk_ = isOk;
        context->cipherSuites_ = suite;
    });
    return context->isOk_;
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
        return false;
    }
    tlsSocket->GetRemoteCertificate([&context](bool isOk, const std::string &cert) {
        context->isOk_ = isOk;
        context->remoteCert_ = cert;
    });
    return context->isOk_;
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
        return false;
    }
    tlsSocket->GetProtocol([&context](bool isOk, const std::string &protocol) {
        context->isOk_ = isOk;
        context->protocol_ = protocol;
    });
    return context->isOk_;
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
        return false;
    }
    tlsSocket->GetSignatureAlgorithms([&context](bool isOk, const std::vector<std::string> &algorithms) {
        context->isOk_ = isOk;
        context->signatureAlgorithms_ = algorithms;
    });
    return context->isOk_;
}

bool TLSSocketExec::ExecSend(SendContext *context)
{
    auto manager = context->GetManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    auto tlsSocket = reinterpret_cast<TLSSocket *>(manager->GetData());
    if (tlsSocket == nullptr) {
        NETSTACK_LOGE("ExecSend tlsSocket is null");
        return false;
    }
    TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(context->data_);
    tlsSocket->Send(tcpSendOptions, [](bool isOk) {
        if (!isOk) {
            NETSTACK_LOGE("send data is failed");
        }
    });
    return context->isOk_;
}

bool TLSSocketExec::ExecClose(TLSCloseContext *context)
{
    auto manager = context->GetManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    auto tlsSocket = reinterpret_cast<TLSSocket *>(manager->GetData());
    if (tlsSocket == nullptr) {
        NETSTACK_LOGE("ExecClose tlsSocket is null");
        return false;
    }
    tlsSocket->Close([&context](bool isOk) { context->isOk_ = isOk; });
    delete tlsSocket;
    manager->SetData(nullptr);
    return context->isOk_;
}

bool TLSSocketExec::ExecBind(BindContext *context)
{
    auto manager = context->GetManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    auto tlsSocket = new TLSSocket();
    tlsSocket->Bind(context->address, [&context](bool isOk) { context->isOk_ = isOk; });
    manager->SetData(tlsSocket);
    return context->isOk_;
}

bool TLSSocketExec::ExecGetRemoteAddress(GetRemoteAddressContext *context)
{
    auto manager = context->GetManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    auto tlsSocket = reinterpret_cast<TLSSocket *>(manager->GetData());
    if (tlsSocket == nullptr) {
        NETSTACK_LOGE("ExecGetRemoteAddress tlsSocket is null");
        return false;
    }
    tlsSocket->GetRemoteAddress([&context](bool isOk, const NetAddress address) {
        context->isOk_ = isOk;
        context->address = address;
    });
    return context->isOk_;
}

bool TLSSocketExec::ExecGetState(GetStateContext *context)
{
    auto manager = context->GetManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    auto tlsSocket = reinterpret_cast<TLSSocket *>(manager->GetData());
    if (tlsSocket == nullptr) {
        NETSTACK_LOGE("ExecGetState tlsSocket is null");
        return false;
    }
    tlsSocket->GetState([&context](bool isOk, const SocketStateBase state) {
        context->isOk_ = isOk;
        context->state = state;
    });
    return context->isOk_;
}

bool TLSSocketExec::ExecSetExtraOptions(TcpSetExtraOptionsContext *context)
{
    auto manager = context->GetManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    auto tlsSocket = reinterpret_cast<TLSSocket *>(manager->GetData());
    if (tlsSocket == nullptr) {
        NETSTACK_LOGE("ExecSetExtraOptions tlsSocket is null");
        return false;
    }
    tlsSocket->SetExtraOptions(context->options, [&context](bool isOk) { context->isOk_ = isOk; });
    return context->isOk_;
}

napi_value TLSSocketExec::GetCertificateCallback(GetCertificateContext *context)
{
    napi_value obj = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), obj) != napi_object) {
        return NapiUtils::GetUndefined(context->GetEnv());
    }
    napi_value x509CertRawData = NapiUtils::CreateArray(context->GetEnv(), context->cert_.size());
    NapiUtils::SetNamedProperty(context->GetEnv(), obj, "data", x509CertRawData);
    NapiUtils::SetInt32Property(context->GetEnv(), obj, "encodingFormat", 1);
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
    napi_value obj = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), obj) != napi_object) {
        return NapiUtils::GetUndefined(context->GetEnv());
    }
    napi_value x509CertRawData = NapiUtils::CreateArray(context->GetEnv(), context->remoteCert_.size());
    NapiUtils::SetNamedProperty(context->GetEnv(), obj, "data", x509CertRawData);
    NapiUtils::SetInt32Property(context->GetEnv(), obj, "encodingFormat", 1);
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

napi_value TLSSocketExec::SendCallback(SendContext *context)
{
    return NapiUtils::GetBoolean(context->GetEnv(), true);
}

napi_value TLSSocketExec::CloseCallback(TLSCloseContext *context)
{
    return NapiUtils::GetBoolean(context->GetEnv(), true);
}

napi_value TLSSocketExec::BindCallback(BindContext *context)
{
    context->Emit(EVENT_LISTENING, std::make_pair(NapiUtils::GetUndefined(context->GetEnv()),
                                                  NapiUtils::GetUndefined(context->GetEnv())));
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value TLSSocketExec::GetStateCallback(GetStateContext *context)
{
    napi_value obj = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), obj) != napi_object) {
        return NapiUtils::GetUndefined(context->GetEnv());
    }
    NapiUtils::SetBooleanProperty(context->GetEnv(), obj, KEY_IS_BOUND, context->state.IsBound());
    NapiUtils::SetBooleanProperty(context->GetEnv(), obj, KEY_IS_CLOSE, context->state.IsClose());
    NapiUtils::SetBooleanProperty(context->GetEnv(), obj, KEY_IS_CONNECTED, context->state.IsConnected());
    return obj;
}

napi_value TLSSocketExec::GetRemoteAddressCallback(GetRemoteAddressContext *context)
{
    napi_value obj = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), obj) != napi_object) {
        return NapiUtils::GetUndefined(context->GetEnv());
    }
    NapiUtils::SetStringPropertyUtf8(context->GetEnv(), obj, KEY_ADDRESS, context->address.GetAddress());
    NapiUtils::SetUint32Property(context->GetEnv(), obj, KEY_FAMILY, context->address.GetJsValueFamily());
    NapiUtils::SetUint32Property(context->GetEnv(), obj, KEY_PORT, context->address.GetPort());
    return obj;
}

napi_value TLSSocketExec::SetExtraOptionsCallback(TcpSetExtraOptionsContext *context)
{
    return NapiUtils::GetUndefined(context->GetEnv());
}

} // namespace NetStack
} // namespace OHOS
