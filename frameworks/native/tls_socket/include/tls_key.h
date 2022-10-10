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

#ifndef COMMUNICATION_NETSTACK_TLS_KEY_H
#define COMMUNICATION_NETSTACK_TLS_KEY_H

#include <memory>
#include <string>

#include <openssl/bio.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "tls.h"

namespace OHOS {
namespace NetStack {
class TLSKey {
public:
    TLSKey() = default;
    ~TLSKey() = default;

    TLSKey(const std::string &data, KeyAlgorithm algorithm, const std::string &passPhrase);
    TLSKey(const std::string &fileName, KeyAlgorithm algorithm, EncodingFormat format = PEM, KeyType type = PRIVATE_KEY,
           const std::string &passPhrase = std::string());
    TLSKey &operator=(const TLSKey &other);

    [[nodiscard]] KeyAlgorithm Algorithm() const;
    [[nodiscard]] Handle handle() const;
    const std::string &GetKeyPass() const;

private:
    void DecodeData(const std::string &data, KeyAlgorithm algorithm, const std::string &passPhrase);
    void DecodeDer(KeyType type, KeyAlgorithm algorithm, const std::string &fileName, const std::string &passPhrase);
    void DecodePem(KeyType type, KeyAlgorithm algorithm, const std::string &fileName, const std::string &passPhrase);
    void Clear(bool deep);

private:
    EVP_PKEY *opaque_ = nullptr;
    RSA *rsa_ = nullptr;
    DSA *dsa_ = nullptr;
    DH *dh_ = nullptr;
    EC_KEY *ec_ = nullptr;
    EVP_PKEY *genericKey_ = nullptr;
    std::string keyPass_;
    bool keyIsNull_ = true;
    KeyType keyType_ = PUBLIC_KEY;
    KeyAlgorithm keyAlgorithm_ = OPAQUE;
};
} // namespace NetStack
} // namespace OHOS
#endif // COMMUNICATION_NETSTACK_TLS_KEY_H
