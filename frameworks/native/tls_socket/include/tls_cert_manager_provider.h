/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef NETSTACK_TLS_CERT_MANAGER_PROVIDER_H
#define NETSTACK_TLS_CERT_MANAGER_PROVIDER_H

#include "tls_cert_alias.h"
#include <openssl/ssl.h>

namespace OHOS::NetStack::TlsSocket {
// Must outlive SSL and SSL_CTX. No process-wide provider or property changes.
class AliasProviderRuntime final {
public:
    AliasProviderRuntime();
    ~AliasProviderRuntime();
    AliasProviderRuntime(const AliasProviderRuntime &) = delete;
    AliasProviderRuntime &operator=(const AliasProviderRuntime &) = delete;
    bool Initialize(const std::shared_ptr<AliasCredential> &credential,
                    const std::shared_ptr<TlsConnectAttemptState> &state);
    SSL_CTX *CreateClientContext() const;
    EVP_PKEY *GetKey() const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace OHOS::NetStack::TlsSocket
#endif
