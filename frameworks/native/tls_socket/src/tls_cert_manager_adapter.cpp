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

#include "tls_cert_alias.h"

#include <cstring>
#include <openssl/rsa.h>
#if defined(__OHOS__)
#include "netstack_log.h"
#define TLS_ALIAS_LOGE(...) NETSTACK_LOGE(__VA_ARGS__)
#else
#define TLS_ALIAS_LOGE(...) ((void)0)
#endif
#if defined(NETSTACK_HAS_CERT_MANAGER) && NETSTACK_HAS_CERT_MANAGER
#include "cert_manager_api.h"
#include "cm_error_code.h"
// CmCallingGetAppCertList allocates credentialAbstract in the SDK; release it with its allocator.
extern "C" void CmFree(void *ptr);
#endif

namespace OHOS::NetStack::TlsSocket {
namespace {
#if defined(NETSTACK_HAS_CERT_MANAGER) && NETSTACK_HAS_CERT_MANAGER
int32_t MapError(int32_t error, bool signing)
{
    switch (error) {
        case CM_SUCCESS: return 0;
        case CMR_ERROR_PERMISSION_DENIED: return TLS_ALIAS_PERMISSION;
        case CMR_ERROR_AUTH_FAILED_MAC_FAILED:
        case CMR_ERROR_AUTH_FAILED_MAC_MISMATCH:
        case CMR_ERROR_AUTH_CHECK_FAILED:
        case CMR_ERROR_NOT_PERMITTED: return TLS_ALIAS_UNAUTHORIZED;
        case CMR_ERROR_NOT_SUPPORTED: return TLS_ALIAS_UNSUPPORTED;
        // Missing credentials at lookup/init differ from an expired signing session.
        case CMR_ERROR_INVALID_CERT_FORMAT: return TLS_ALIAS_NOT_FOUND;
        case CMR_ERROR_NOT_FOUND:
        case CMR_ERROR_NOT_EXIST: return signing ? TLS_ALIAS_SERVICE_ERROR : TLS_ALIAS_NOT_FOUND;
        default: return TLS_ALIAS_SERVICE_ERROR;
    }
}

CmBlob UriBlob(const std::string &uri)
{
    return {static_cast<uint32_t>(uri.size() + 1),
        reinterpret_cast<uint8_t *>(const_cast<char *>(uri.c_str()))};
}

int32_t ResolveKeyUri(const CredentialList &list, const std::string &alias, std::string &keyUri)
{
    if (list.credentialCount > MAX_COUNT_CERTIFICATE ||
        (list.credentialCount != 0 && list.credentialAbstract == nullptr)) {
        TLS_ALIAS_LOGE("certAlias list invalid: count=%{public}u, null=%{public}d",
            list.credentialCount, list.credentialAbstract == nullptr);
        return TLS_ALIAS_SERVICE_ERROR;
    }
    for (uint32_t i = 0; i < list.credentialCount; ++i) {
        const auto &entry = list.credentialAbstract[i];
        if (!memchr(entry.alias, '\0', sizeof(entry.alias)) ||
            !memchr(entry.keyUri, '\0', sizeof(entry.keyUri))) {
            TLS_ALIAS_LOGE("certAlias list entry invalid: index=%{public}u", i);
            return TLS_ALIAS_SERVICE_ERROR;
        }
        if (alias != entry.alias) {
            continue;
        }
        if (!keyUri.empty() || entry.keyUri[0] == '\0') {
            TLS_ALIAS_LOGE("certAlias matched entry invalid: index=%{public}u", i);
            return TLS_ALIAS_SERVICE_ERROR;
        }
        keyUri = entry.keyUri;
    }
    if (keyUri.empty()) {
        return TLS_ALIAS_NOT_FOUND;
    }
    return 0;
}

struct AbortGuard {
    CmBlob *handle;
    ~AbortGuard()
    {
        if (handle) {
            (void)CmAbort(handle);
        }
    }
};

class SystemCertManagerAdapter final : public CertManagerAdapter {
public:
    int32_t Load(const std::string &alias, std::string &keyUri, std::string &pem, uint32_t &count) override
    {
        keyUri.clear();
        pem.clear();
        count = 0;
        CredentialList list{0, nullptr};
        struct ListGuard {
            CredentialList &list;
            ~ListGuard() { CmFree(list.credentialAbstract); }
        } guard{list};
        int32_t error = CmCallingGetAppCertList(CM_PRI_CREDENTIAL_STORE, &list);
        if (error != CM_SUCCESS) {
            TLS_ALIAS_LOGE("certAlias list failed: cm=%{public}d, mapped=%{public}d",
                error, MapError(error, false));
            return MapError(error, false);
        }
        error = ResolveKeyUri(list, alias, keyUri);
        if (error != 0) {
            return error;
        }
        std::vector<uint8_t> data(MAX_LEN_CERTIFICATE_CHAIN);
        Credential result{};
        result.credData = {static_cast<uint32_t>(data.size()), data.data()};
        auto uri = UriBlob(keyUri);
        error = CmGetAppCert(&uri, CM_PRI_CREDENTIAL_STORE, &result);
        if (error != CM_SUCCESS) {
            TLS_ALIAS_LOGE("certAlias credential read failed: cm=%{public}d, mapped=%{public}d",
                error, MapError(error, false));
            return MapError(error, false);
        }
        if (!result.isExist) {
            return TLS_ALIAS_NOT_FOUND;
        }
        if (result.credData.size == 0 || result.certNum == 0) {
            return TLS_ALIAS_NOT_FOUND;
        }
        if (result.credData.size > data.size()) {
            TLS_ALIAS_LOGE("certAlias credential data invalid: size=%{public}u", result.credData.size);
            return TLS_ALIAS_SERVICE_ERROR;
        }
        pem.assign(reinterpret_cast<const char *>(data.data()), result.credData.size);
        count = result.certNum;
        return 0;
    }

    int32_t Sign(const std::string &keyUri, const AliasSignatureSpec &spec,
                 const uint8_t *data, size_t size, std::vector<uint8_t> &signature) override
    {
        uint32_t digest = spec.digest == "SHA256" ? CM_DIGEST_SHA256 :
            spec.digest == "SHA384" ? CM_DIGEST_SHA384 : spec.digest == "SHA512" ? CM_DIGEST_SHA512 : CM_DIGEST_NONE;
        if (digest == CM_DIGEST_NONE || !data || size == 0 || signature.empty() ||
            (spec.padding != 0 && spec.padding != RSA_PKCS1_PADDING && spec.padding != RSA_PKCS1_PSS_PADDING)) {
            return TLS_ERR_SSL_NULL;
        }
        uint32_t padding = spec.padding == RSA_PKCS1_PSS_PADDING ? CM_PADDING_PSS :
            spec.padding == RSA_PKCS1_PADDING ? CM_PADDING_PKCS1_V1_5 : CM_PADDING_NONE;
        CmSignatureSpec cmSpec{CM_KEY_PURPOSE_SIGN, padding, digest};
        uint64_t value = 0;
        CmBlob handle{sizeof(value), reinterpret_cast<uint8_t *>(&value)};
        auto uri = UriBlob(keyUri);
        auto error = CmInit(&uri, &cmSpec, &handle);
        if (error != CM_SUCCESS) {
            return MapError(error, false);
        }
        // Each signature owns its own operation, including all failure paths.
        AbortGuard guard{&handle};
        constexpr size_t CHUNK_SIZE = 16 * 1024;
        while (size > CHUNK_SIZE) {
            CmBlob input{CHUNK_SIZE, const_cast<uint8_t *>(data)};
            error = CmUpdate(&handle, &input);
            if (error != CM_SUCCESS) {
                return MapError(error, true);
            }
            data += CHUNK_SIZE;
            size -= CHUNK_SIZE;
        }
        CmBlob input{static_cast<uint32_t>(size), const_cast<uint8_t *>(data)};
        CmBlob output{static_cast<uint32_t>(signature.size()), signature.data()};
        error = CmFinish(&handle, &input, &output);
        if (error != CM_SUCCESS) {
            return MapError(error, true);
        }
        guard.handle = nullptr; // Finish consumed the service session.
        if (output.size == 0 || output.size > signature.size()) {
            return TLS_ALIAS_SERVICE_ERROR;
        }
        signature.resize(output.size);
        return 0;
    }
};
#else
class SystemCertManagerAdapter final : public CertManagerAdapter {
public:
    int32_t Load(const std::string &, std::string &, std::string &, uint32_t &) override
    {
        return TLS_ALIAS_UNSUPPORTED;
    }
    int32_t Sign(const std::string &, const AliasSignatureSpec &, const uint8_t *, size_t,
                 std::vector<uint8_t> &) override
    {
        return TLS_ALIAS_UNSUPPORTED;
    }
};
#endif
} // namespace
std::shared_ptr<CertManagerAdapter> CreateCertManagerAdapter()
{
    return std::make_shared<SystemCertManagerAdapter>();
}
} // namespace OHOS::NetStack::TlsSocket
