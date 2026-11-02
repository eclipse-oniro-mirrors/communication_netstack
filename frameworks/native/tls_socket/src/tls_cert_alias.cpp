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

#include <algorithm>
#include <climits>
#include <openssl/pem.h>

namespace OHOS::NetStack::TlsSocket {
namespace {
constexpr size_t MAX_ALIAS_LENGTH = 256;
constexpr unsigned char ASCII_SPACE = 0x20;
constexpr unsigned char ASCII_TILDE = 0x7e;

bool ParseAliasCertificateChain(std::string &pem, uint32_t count, AliasCredential &credential)
{
    // The SDK may include the terminating NUL in its output blob.
    if (!pem.empty() && pem.back() == '\0') {
        pem.pop_back();
    }
    size_t offset = 0;
    const std::string begin = "-----BEGIN CERTIFICATE-----";
    const std::string end = "-----END CERTIFICATE-----";
    while (offset < pem.size()) {
        offset = pem.find_first_not_of(" \r\n\t", offset);
        if (offset == std::string::npos) {
            break;
        }
        if (pem.compare(offset, begin.size(), begin) != 0) {
            return false;
        }
        auto last = pem.find(end, offset + begin.size());
        if (last == std::string::npos) {
            return false;
        }
        auto part = pem.substr(offset, last + end.size() - offset) + "\n";
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(part.data(), part.size()), BIO_free);
        std::unique_ptr<X509, decltype(&X509_free)> cert(
            bio ? PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr) : nullptr, X509_free);
        if (!cert) {
            return false;
        }
        if (credential.certChain.empty()) {
            credential.publicKey = std::shared_ptr<EVP_PKEY>(X509_get_pubkey(cert.get()), EVP_PKEY_free);
        }
        credential.certChain.push_back(std::move(part));
        offset = last + end.size();
    }
    return credential.certChain.size() == count && credential.publicKey;
}
} // namespace

bool IsValidCertAlias(const std::string &alias)
{
    return !alias.empty() && alias.size() <= MAX_ALIAS_LENGTH &&
        std::all_of(alias.begin(), alias.end(), [](unsigned char c) { return c >= ASCII_SPACE && c <= ASCII_TILDE; }) &&
        alias.find_first_not_of(' ') != std::string::npos;
}

bool IsCertAliasError(int32_t error)
{
    return error == TLS_ALIAS_PERMISSION || error == TLS_ALIAS_INVALID || error == TLS_ALIAS_UNSUPPORTED ||
        (error >= TLS_ALIAS_NOT_FOUND && error <= TLS_ALIAS_UNAUTHORIZED);
}

std::string CertAliasErrorMessage(int32_t error)
{
    return IsCertAliasError(error) ? MakeErrorMessage(error) : std::string{};
}

int32_t PrepareAliasCredential(const std::string &alias, std::shared_ptr<AliasCredential> &credential,
    std::shared_ptr<CertManagerAdapter> adapter)
{
    credential.reset();
    if (!IsValidCertAlias(alias)) {
        return TLS_ALIAS_INVALID;
    }
#if OPENSSL_VERSION_NUMBER < 0x30000000L || defined(OPENSSL_IS_BORINGSSL)
    return TLS_ALIAS_UNSUPPORTED;
#endif
    if (!adapter) {
        adapter = CreateCertManagerAdapter();
    }
    auto prepared = std::make_shared<AliasCredential>();
    prepared->adapter = std::move(adapter);
    std::string pem;
    uint32_t count = 0;
    auto error = prepared->adapter->Load(alias, prepared->keyUri, pem, count);
    if (error != 0) {
        return error;
    }
    if (prepared->keyUri.empty() || count == 0 || pem.size() > INT_MAX) {
        return TLS_ALIAS_NOT_FOUND;
    }
    if (!ParseAliasCertificateChain(pem, count, *prepared)) {
        return TLS_ALIAS_NOT_FOUND;
    }
    int type = EVP_PKEY_base_id(prepared->publicKey.get());
    if (type != EVP_PKEY_RSA && type != EVP_PKEY_EC) {
        return TLS_ALIAS_UNSUPPORTED;
    }
    credential = std::move(prepared);
    return 0;
}
} // namespace OHOS::NetStack::TlsSocket
