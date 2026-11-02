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

#ifndef NETSTACK_TLS_CERT_ALIAS_H
#define NETSTACK_TLS_CERT_ALIAS_H

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <utility>
#include <openssl/evp.h>
#include "socket_error.h"

namespace OHOS::NetStack::TlsSocket {
constexpr int32_t TLS_ALIAS_PERMISSION = 201;
constexpr int32_t TLS_ALIAS_INVALID = 401;
constexpr int32_t TLS_ALIAS_UNSUPPORTED = 801;
constexpr int32_t TLS_ALIAS_NOT_FOUND = TLS_ERR_CERT_ALIAS_NOT_FOUND;
constexpr int32_t TLS_ALIAS_UNAUTHORIZED = TLS_ERR_KEY_ACCESS_DENIED;
constexpr int32_t TLS_ALIAS_SERVICE_ERROR = TLS_ERR_CERT_MGR_SERVICE_ERROR;

bool IsValidCertAlias(const std::string &alias);
bool IsCertAliasError(int32_t error);
std::string CertAliasErrorMessage(int32_t error);

class TlsConnectAttemptState final {
public:
    void SetFirstError(int32_t error)
    {
        int32_t expected = 0;
        error_.compare_exchange_strong(expected, error);
    }
    int32_t GetError() const { return error_.load(); }
    void Cancel() { cancelled_.store(true); }
    bool IsCancelled() const { return cancelled_.load(); }
private:
    std::atomic<int32_t> error_{0};
    std::atomic<bool> cancelled_{false};
};

struct AliasSignatureSpec {
    std::string digest;
    // OpenSSL RSA padding constants; zero for EC.
    int padding = 0;
};

class CertManagerAdapter {
public:
    virtual ~CertManagerAdapter() = default;
    virtual int32_t Load(const std::string &alias, std::string &keyUri, std::string &pemChain,
                         uint32_t &certCount) = 0;
    // Input is the original message, not a precomputed digest.
    virtual int32_t Sign(const std::string &keyUri, const AliasSignatureSpec &spec,
                         const uint8_t *data, size_t size, std::vector<uint8_t> &signature) = 0;
};

struct AliasCredential {
    std::string keyUri;
    std::vector<std::string> certChain;
    std::shared_ptr<EVP_PKEY> publicKey;
    std::shared_ptr<CertManagerAdapter> adapter;
};

std::shared_ptr<CertManagerAdapter> CreateCertManagerAdapter();
int32_t PrepareAliasCredential(const std::string &alias, std::shared_ptr<AliasCredential> &credential,
    std::shared_ptr<CertManagerAdapter> adapter = nullptr);
} // namespace OHOS::NetStack::TlsSocket
#endif
