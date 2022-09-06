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

#ifndef TLS_TLSSOCKET_EXEC_H
#define TLS_TLSSOCKET_EXEC_H

#include <napi/native_api.h>

#include "connect_context.h"
#include "close_context.h"
#include "get_certificate_context.h"
#include "get_cipher_suites_context.h"
#include "get_protocol_context.h"
#include "get_remote_certificate_context.h"
#include "get_signature_algorithms_context.h"

namespace OHOS {
namespace NetStack {
class TlsSocketExec final {
public:
    DISALLOW_COPY_AND_MOVE(TlsSocketExec);

    TlsSocketExec() = delete;
    ~TlsSocketExec() = delete;

    static bool ExecGetCertificate(GetCertificateContext *context);
    static bool ExecConnect(ConnectContext *context);
    static bool ExecGetCipherSuites(GetCipherSuitesContext *context);
    static bool ExecGetRemoteCertificate(GetRemoteCertificateContext *context);
    static bool ExecGetProtocol(GetProtocolContext *context);
    static bool ExecGetSignatureAlgorithms(GetSignatureAlgorithmsContext *context);
    static bool ExecClose(CloseContext *context);

    static napi_value GetCertificateCallback(GetCertificateContext *context);
    static napi_value ConnectCallback(ConnectContext *context);
    static napi_value GetCipherSuitesCallback(GetCipherSuitesContext *context);
    static napi_value GetRemoteCertificateCallback(GetRemoteCertificateContext *context);
    static napi_value GetProtocolCallback(GetProtocolContext *context);
    static napi_value GetSignatureAlgorithmsCallback(GetSignatureAlgorithmsContext *context);
    static napi_value CloseCallback(CloseContext *context);
};
} // namespace NetStack
} // namespace OHOS
#endif // TLS_TLSSOCKET_EXEC_H
