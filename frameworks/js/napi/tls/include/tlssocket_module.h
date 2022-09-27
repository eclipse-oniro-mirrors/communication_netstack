/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef TLS_TLSSOCKET_MODULE_H
#define TLS_TLSSOCKET_MODULE_H

#include "napi/native_api.h"

namespace OHOS {
namespace NetStack {
class TLSSocketModuleExports {
public:
    class TLSSocket {
    public:
        static constexpr const char *FUNCTION_GET_CERTIFICATE = "getCertificate";
        static constexpr const char *FUNCTION_GET_REMOTE_CERTIFICATE = "getRemoteCertificate";
        static constexpr const char *FUNCTION_GET_SIGNATURE_ALGORITHMS = "getSignatureAlgorithms";
        static constexpr const char *FUNCTION_GET_PROTOCOL ="getProtocol";
        static constexpr const char *FUNCTION_CONNECT ="connect";
        static constexpr const char *FUNCTION_GET_CIPHER_SUITES = "getCipherSuites";
        static constexpr const char *FUNCTION_CLOSE = "close";

        static napi_value GetCertificate(napi_env env, napi_callback_info info);
        static napi_value GetProtocol(napi_env env, napi_callback_info info);
        static napi_value Connect(napi_env env, napi_callback_info info);
        static napi_value GetCipherSuites(napi_env env, napi_callback_info info);
        static napi_value GetRemoteCertificate(napi_env env, napi_callback_info info);
        static napi_value GetSignatureAlgorithms(napi_env env, napi_callback_info info);
        static napi_value Close(napi_env env, napi_callback_info info);
    };

public:
    static constexpr const char *INTERFACE_TLS_SOCKET = "TLSSocket";
    static constexpr const char *FUNCTION_CONSTRUCTOR_TLS_SOCKET_INSTANCE = "constructTLSSocketInstance";

    static napi_value InitTLSSocketModule(napi_env env, napi_value exports);

private:
    static napi_value ConstructTLSSocketInstance(napi_env env, napi_callback_info info);
    static void DefineTLSSocketClass(napi_env env, napi_value exports);
    static void InitTLSSocketProperties(napi_env env, napi_value exports);
};
} // namespace NetStack
} // namespace OHOS
#endif // TLS_TLSSOCKET_MODULE_H
