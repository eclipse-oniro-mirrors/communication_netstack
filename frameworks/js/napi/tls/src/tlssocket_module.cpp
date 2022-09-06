/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "tlssocket_module.h"

#include <initializer_list>

#include <napi/native_api.h>
#include <napi/native_common.h>

#include "connect_context.h"
#include "close_context.h"
#include "event_manager.h"
#include "get_certificate_context.h"
#include "get_remote_certificate_context.h"
#include "get_signature_algorithms_context.h"
#include "get_cipher_suites_context.h"
#include "module_template.h"
#include "napi_utils.h"
#include "netstack_log.h"
#include "tlssocket_async_work.h"

namespace OHOS {
namespace NetStack {
namespace {
constexpr const char *TLS_SOCKET_MODULE_NAME = "net.tlssocket";
} // namespace

void Finalize(napi_env, void *data, void *)
{
    NETSTACK_LOGI("socket handle is finalized");
}

napi_value TLSSocketModuleExports::TLSSocket::GetCertificate(napi_env env , napi_callback_info info)
{
    return ModuleTemplate::Interface<GetCertificateContext>(env, info, FUNCTION_GET_CERTIFICATE, nullptr,
                                                            TlsSocketAsyncWork::ExecGetCertificate,
                                                            TlsSocketAsyncWork::GetCertificateCallback);
}

napi_value TLSSocketModuleExports::TLSSocket::GetProtocol(napi_env env , napi_callback_info info)
{
    return ModuleTemplate::Interface<GetCipherSuitesContext>(env, info, FUNCTION_GET_PROTOCOL, nullptr,
                                                            TlsSocketAsyncWork::ExecGetProtocol,
                                                            TlsSocketAsyncWork::GetProtocolCallback);
}

napi_value TLSSocketModuleExports::TLSSocket::Connect(napi_env env , napi_callback_info info)
{
    return ModuleTemplate::Interface<ConnectContext>(env, info, FUNCTION_CONNECT, nullptr,
                                                            TlsSocketAsyncWork::ExecConnect,
                                                            TlsSocketAsyncWork::ConnectCallback);
}

napi_value TLSSocketModuleExports::TLSSocket::GetCipherSuites(napi_env env , napi_callback_info info)
{
    return ModuleTemplate::Interface<GetCipherSuitesContext>(env, info, FUNCTION_GET_CIPHER_SUITES, nullptr,
                                                            TlsSocketAsyncWork::ExecGetCipherSuites,
                                                            TlsSocketAsyncWork::GetCipherSuitesCallback);
}

napi_value TLSSocketModuleExports::TLSSocket::GetRemoteCertificate(napi_env env , napi_callback_info info)
{
    return ModuleTemplate::Interface<GetRemoteCertificateContext>(env, info, FUNCTION_GET_REMOTE_CERTIFICATE, nullptr,
                                                            TlsSocketAsyncWork::ExecGetRemoteCertificate,
                                                            TlsSocketAsyncWork::GetRemoteCertificateCallback);
}

napi_value TLSSocketModuleExports::TLSSocket::GetSignatureAlgorithms(napi_env env , napi_callback_info info)
{
    return ModuleTemplate::Interface<GetSignatureAlgorithmsContext>(env, info, FUNCTION_GET_SIGNATURE_ALGORITHMS, nullptr,
                                                            TlsSocketAsyncWork::ExecGetSignatureAlgorithms,
                                                            TlsSocketAsyncWork::GetSignatureAlgorithmsCallback);
}

napi_value TLSSocketModuleExports::TLSSocket::Close(napi_env env , napi_callback_info info)
{
    return ModuleTemplate::Interface<CloseContext>(env, info, FUNCTION_CLOSE, nullptr,
                                                            TlsSocketAsyncWork::ExecClose,
                                                            TlsSocketAsyncWork::CloseCallback);
}

void TLSSocketModuleExports::DefineTLSSocketClass(napi_env env, napi_value exports)
{
    std::initializer_list<napi_property_descriptor> functions = {
        DECLARE_NAPI_FUNCTION(TLSSocket::FUNCTION_GET_CERTIFICATE, TLSSocket::GetCertificate),
        DECLARE_NAPI_FUNCTION(TLSSocket::FUNCTION_GET_REMOTE_CERTIFICATE, TLSSocket::GetRemoteCertificate),
        DECLARE_NAPI_FUNCTION(TLSSocket::FUNCTION_GET_SIGNATURE_ALGORITHMS, TLSSocket::GetSignatureAlgorithms),
        DECLARE_NAPI_FUNCTION(TLSSocket::FUNCTION_GET_PROTOCOL, TLSSocket::GetProtocol),
        DECLARE_NAPI_FUNCTION(TLSSocket::FUNCTION_CONNECT, TLSSocket::Connect),
        DECLARE_NAPI_FUNCTION(TLSSocket::FUNCTION_GET_CIPHER_SUITES, TLSSocket::GetCipherSuites),
        DECLARE_NAPI_FUNCTION(TLSSocket::FUNCTION_CLOSE, TLSSocket::Close),
    };
    ModuleTemplate::DefineClass(env, exports, functions, INTERFACE_TLS_SOCKET);
}

napi_value TLSSocketModuleExports::ConstructTLSSocketInstance(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::NewInstance(env, info, INTERFACE_TLS_SOCKET, Finalize);
}

void TLSSocketModuleExports::InitTLSSocketProperties(napi_env env, napi_value exports)
{
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_NAPI_FUNCTION(FUNCTION_CONSTRUCTOR_TLS_SOCKET_INSTANCE, ConstructTLSSocketInstance),
    };
    NapiUtils::DefineProperties(env, exports, properties);
}

napi_value TLSSocketModuleExports::InitTLSSocketModule(napi_env env, napi_value exports)
{
    DefineTLSSocketClass(env, exports);
    InitTLSSocketProperties(env, exports);
    return exports;
}

static napi_module g_tlssocketModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = TLSSocketModuleExports::InitTLSSocketModule,
    .nm_modname = TLS_SOCKET_MODULE_NAME,
    .nm_priv = nullptr,
    .reserved = {nullptr},
};

extern "C" __attribute__((constructor)) void RegisterTlsSocket(void)
{
    napi_module_register(&g_tlssocketModule);
}
} // namespace NetStack
} // namespace OHOS
