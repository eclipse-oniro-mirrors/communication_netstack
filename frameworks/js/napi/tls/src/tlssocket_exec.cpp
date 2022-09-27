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

#include "napi_utils.h"
#include "netstack_log.h"
#include "tls_socket.h"

namespace OHOS {
namespace NetStack {
bool TlsSocketExec::ExecGetCertificate(GetCertificateContext *context)
{
    auto manager = context->GetManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    auto tlsSocket = reinterpret_cast<TLSSocket *>(manager->GetData());
    if (tlsSocket == nullptr) {
        NETSTACK_LOGE("TlsSocketExec::ExecGetCipherSuites tlsSocket is null");
        return false;
    }
    tlsSocket->GetCertificate([&context](bool ok, const std::string &cert) {
        context->ok_ = ok;
        context->cert_ = cert;
    });
    return context->ok_;
}

bool TlsSocketExec::ExecConnect(ConnectContext *context)
{
    auto manager = context->GetManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    if (manager->GetData() != nullptr) {
        NETSTACK_LOGE("tls tlsSocket is existed");
        return false;
    }
    auto tlsSocket = new TLSSocket();
    tlsSocket->Connect(context->connectOptions_, [&context](bool ok) { context->ok_ = ok; });
    if (!context->ok_) {
        NETSTACK_LOGE("TlsSocketExec::ExecConnect result is false");
        delete tlsSocket;
        tlsSocket = nullptr;
        return false;
    }
    manager->SetData(tlsSocket);
    return true;
}

bool TlsSocketExec::ExecGetCipherSuites(GetCipherSuitesContext *context)
{
    auto manager = context->GetManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    auto tlsSocket = reinterpret_cast<TLSSocket *>(manager->GetData());
    if (tlsSocket == nullptr) {
        NETSTACK_LOGE("TlsSocketExec::ExecGetCipherSuites tlsSocket is null");
        return false;
    }
    tlsSocket->GetCipherSuite([&context](bool ok, const std::vector<std::string> &suite) {
        context->ok_ = ok;
        context->cipherSuites_ = suite;
    });
    return context->ok_;
}

bool TlsSocketExec::ExecGetRemoteCertificate(GetRemoteCertificateContext *context)
{
    auto manager = context->GetManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    auto tlsSocket = reinterpret_cast<TLSSocket *>(manager->GetData());
    if (tlsSocket == nullptr) {
        NETSTACK_LOGE("TlsSocketExec::ExecGetRemoteCertificate tlsSocket is null");
        return false;
    }
    tlsSocket->GetRemoteCertificate([&context](bool ok, const std::string &cert) {
        context->ok_ = ok;
        context->remoteCert_ = cert;
    });
    return context->ok_;
}

bool TlsSocketExec::ExecGetProtocol(GetProtocolContext *context)
{
    auto manager = context->GetManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    auto tlsSocket = reinterpret_cast<TLSSocket *>(manager->GetData());
    if (tlsSocket == nullptr) {
        NETSTACK_LOGE("TlsSocketExec::ExecGetProtocol tlsSocket is null");
        return false;
    }
    tlsSocket->GetProtocol([&context](bool ok, const std::string &protocol) {
        context->ok_ = ok;
        context->protocol_ = protocol;
    });
    return context->ok_;
}

bool TlsSocketExec::ExecGetSignatureAlgorithms(GetSignatureAlgorithmsContext *context)
{
    auto manager = context->GetManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    auto tlsSocket = reinterpret_cast<TLSSocket *>(manager->GetData());
    if (tlsSocket == nullptr) {
        NETSTACK_LOGE("TlsSocketExec::ExecGetSignatureAlgorithms tlsSocket is null");
        return false;
    }
    tlsSocket->GetSignatureAlgorithms([&context](bool ok, const std::vector<std::string> &algorithms) {
        context->ok_ = ok;
        context->signatureAlgorithms_ = algorithms;
    });
    return context->ok_;
}

bool TlsSocketExec::ExecSend(SendContext *context)
{
    NETSTACK_LOGI("TlsSocketExec::ExecSend is start");
    auto manager = context->GetManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    auto tlsSocket = reinterpret_cast<TLSSocket*>(manager->GetData());
    if (tlsSocket == nullptr) {
        NETSTACK_LOGE("TlsSocketExec::ExecClose tlsSocket is null");
        return false;
    }
    TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(context->data_);
    tlsSocket->Send(tcpSendOptions, [](bool ok) {
        if (!ok) {
            NETSTACK_LOGE("send data is failed");
        }
    });
    NETSTACK_LOGI("TlsSocketExec::ExecSend is end");
    return context->ok_;
}

bool TlsSocketExec::ExecClose(CloseContext *context)
{
    auto manager = context->GetManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return false;
    }
    auto tlsSocket = reinterpret_cast<TLSSocket *>(manager->GetData());
    if (tlsSocket == nullptr) {
        NETSTACK_LOGE("TlsSocketExec::ExecClose tlsSocket is null");
        return false;
    }
    tlsSocket->Close([&context](bool ok) { context->ok_ = ok; });
    delete tlsSocket;
    manager->SetData(nullptr);
    return context->ok_;
}

napi_value TlsSocketExec::GetCertificateCallback(GetCertificateContext *context)
{
    return NapiUtils::CreateStringUtf8(context->GetEnv(), context->cert_);
}

napi_value TlsSocketExec::ConnectCallback(ConnectContext *context)
{
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value TlsSocketExec::GetCipherSuitesCallback(GetCipherSuitesContext *context)
{
    napi_value cipherSuites = NapiUtils::CreateArray(context->GetEnv(), 0);
    int index = 0;
    for (const auto &cipher : context->cipherSuites_) {
        napi_value cipherSuite = NapiUtils::CreateStringUtf8(context->GetEnv(), cipher);
        NapiUtils::SetArrayElement(context->GetEnv(), cipherSuites, index++, cipherSuite);
    }
    return cipherSuites;
}

napi_value TlsSocketExec::GetRemoteCertificateCallback(GetRemoteCertificateContext *context)
{
    return NapiUtils::CreateStringUtf8(context->GetEnv(), context->remoteCert_);
}

napi_value TlsSocketExec::GetProtocolCallback(GetProtocolContext *context)
{
    return NapiUtils::CreateStringUtf8(context->GetEnv(), context->protocol_);
}

napi_value TlsSocketExec::GetSignatureAlgorithmsCallback(GetSignatureAlgorithmsContext *context)
{
    napi_value signatureAlgorithms = NapiUtils::CreateArray(context->GetEnv(), 0);
    int index = 0;
    for (const auto &algorithm : context->signatureAlgorithms_) {
        napi_value signatureAlgorithm = NapiUtils::CreateStringUtf8(context->GetEnv(), algorithm);
        NapiUtils::SetArrayElement(context->GetEnv(), signatureAlgorithms, index++, signatureAlgorithm);
    }
    return signatureAlgorithms;
}

napi_value TlsSocketExec::SendCallback(SendContext *context)
{
    return NapiUtils::GetBoolean(context->GetEnv(), true);
}

napi_value TlsSocketExec::CloseCallback(CloseContext *context)
{
    return NapiUtils::GetBoolean(context->GetEnv(), true);
}
} // namespace NetStack
} // namespace OHOS
