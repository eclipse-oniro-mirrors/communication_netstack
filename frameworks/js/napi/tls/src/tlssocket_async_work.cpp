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

#include "tlssocket_async_work.h"

#include "base_async_work.h"
#include "connect_context.h"
#include "close_context.h"
#include "get_certificate_context.h"
#include "get_cipher_suites_context.h"
#include "get_remote_certificate_context.h"
#include "tlssocket_exec.h"

namespace OHOS {
namespace NetStack {
void TlsSocketAsyncWork::ExecGetCertificate(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<GetCertificateContext, TlsSocketExec::ExecGetCertificate>(env, data);
}

void TlsSocketAsyncWork::ExecConnect(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<ConnectContext, TlsSocketExec::ExecConnect>(env, data);
}

void TlsSocketAsyncWork::ExecGetCipherSuites(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<GetCipherSuitesContext, TlsSocketExec::ExecGetCipherSuites>(env, data);
}

void TlsSocketAsyncWork::ExecGetRemoteCertificate(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<GetRemoteCertificateContext, TlsSocketExec::ExecGetRemoteCertificate>(env, data);
}

void TlsSocketAsyncWork::ExecGetProtocol(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<GetProtocolContext, TlsSocketExec::ExecGetProtocol>(env, data);
}

void TlsSocketAsyncWork::ExecGetSignatureAlgorithms(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<GetSignatureAlgorithmsContext, TlsSocketExec::ExecGetSignatureAlgorithms>(env, data);
}

void TlsSocketAsyncWork::ExecClose(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<CloseContext, TlsSocketExec::ExecClose>(env, data);
}

void TlsSocketAsyncWork::GetCertificateCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<GetCertificateContext, TlsSocketExec::GetCertificateCallback>(env, status, data);
}

void TlsSocketAsyncWork::ConnectCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<ConnectContext, TlsSocketExec::ConnectCallback>(env, status, data);
}

void TlsSocketAsyncWork::GetCipherSuitesCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<GetCipherSuitesContext, TlsSocketExec::GetCipherSuitesCallback>(env, status, data);
}

void TlsSocketAsyncWork::GetRemoteCertificateCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<GetRemoteCertificateContext, TlsSocketExec::GetRemoteCertificateCallback>(env, status, data);
}

void TlsSocketAsyncWork::GetProtocolCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<GetProtocolContext, TlsSocketExec::GetProtocolCallback>(env, status, data);
}

void TlsSocketAsyncWork::GetSignatureAlgorithmsCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<GetSignatureAlgorithmsContext, TlsSocketExec::GetSignatureAlgorithmsCallback>(env, status, data);
}

void TlsSocketAsyncWork::CloseCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<CloseContext, TlsSocketExec::CloseCallback>(env, status, data);
}
} // namespace NetStack
} // namespace OHOS
