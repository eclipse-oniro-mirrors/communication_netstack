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

#include "tls_key.h"

#include "netstack_log.h"

namespace OHOS {
namespace NetStack {

namespace {
constexpr int FILE_READ_Key_LEN = 4096;
constexpr const char *FILE_OPEN_FLAG = "rb";
} // namespace

TLSKey::TLSKey(const std::string &fileName,
               KeyAlgorithm algorithm,
               EncodingFormat encoding,
               KeyType type,
               const std::string &passPhrase)
{
    if (encoding == DER) {
        DecodeDer(type, algorithm, fileName, passPhrase);
    } else {
        DecodePem(type, algorithm, fileName, passPhrase);
    }
}

TLSKey::TLSKey(const std::string &data, KeyAlgorithm algorithm, const std::string &passPhrase)
{
    if (data.empty()) {
        NETSTACK_LOGE("TlsKey::TlsKey(const std::string &data, const std::string &passPhrase) data is empty");
        return;
    }
    DecodeData(data, algorithm, passPhrase);
}

TLSKey &TLSKey::operator= (const TLSKey &other)
{
    if (other.rsa_ != nullptr) {
        rsa_ = RSA_new();
        rsa_ = other.rsa_;
    }
    if (other.dsa_ != nullptr) {
        dsa_ = DSA_new();
        dsa_ = other.dsa_;
    }
    if (other.dh_ != nullptr) {
        dh_ = DH_new();
        dh_ = other.dh_;
    }
    if (other.genericKey_ != nullptr) {
        genericKey_ = EVP_PKEY_new();
        genericKey_ = other.genericKey_;
    }
    keyIsNull_ = other.keyIsNull_;
    keyType_ = other.keyType_;
    keyAlgorithm_ = other.keyAlgorithm_;
    passwd_ = other.passwd_;
    return *this;
}

void TLSKey::DecodeData(const std::string &data, KeyAlgorithm algorithm, const std::string &passPhrase)
{
    if (data.empty()) {
        NETSTACK_LOGE("TlsKey::DecodeData data is empty");
        return;
    }
    keyAlgorithm_ = algorithm;
    passwd_ = passPhrase;
    BIO *bio = BIO_new_mem_buf(data.c_str(), -1);
    if (!bio) {
        NETSTACK_LOGE("TlsKey::DecodeData bio is null");
        return;
    }
    NETSTACK_LOGI("--- TlsKey::DecodeData rsa");
    RSA_print_fp(stdout,rsa_,11);
    rsa_ = PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);

    if (rsa_) {
        keyIsNull_ = false;
    }
}

void TLSKey::DecodeDer(KeyType type,
                       KeyAlgorithm algorithm,
                       const std::string &fileName,
                       const std::string &passPhrase)
{
    if (fileName.empty()) {
        NETSTACK_LOGI("TlsKey::DecodeDer filename is empty");
        return;
    }
    keyType_ = type;
    keyAlgorithm_ = algorithm;
    passwd_ = passPhrase;
    FILE *fp = nullptr;
    fp = fopen(static_cast<const char*>(fileName.c_str()), FILE_OPEN_FLAG);
    if (!fp) {
        NETSTACK_LOGE("TlsKey::DecodeDer: Couldn't open %{public}s file for reading", fileName.c_str());
        return;
    }
    char keyDer[FILE_READ_Key_LEN] = {};
    long keyLen = fread(keyDer, 1, FILE_READ_Key_LEN, fp);
    (void)fclose(fp);

    const unsigned char *key_data = reinterpret_cast<const unsigned char*>(keyDer);
    if (type == PUBLIC_KEY) {
        rsa_ = d2i_RSA_PUBKEY(nullptr, &key_data, keyLen);
    } else {
        rsa_ = d2i_RSAPrivateKey(nullptr, &key_data, keyLen);
    }
    if (!rsa_) {
        NETSTACK_LOGE("TlsKey::DecodeDer rsa_ is null");
        return;
    }
    keyIsNull_ = false;
}

void TLSKey::DecodePem(KeyType type,
                       KeyAlgorithm algorithm,
                       const std::string &fileName,
                       const std::string &passPhrase)
{
    if (fileName.empty()) {
        NETSTACK_LOGE("TlsKey::DecodePem filename is empty");
        return;
    }
    keyType_ = type;
    keyAlgorithm_ = algorithm;
    FILE *fp = nullptr;
    fp = fopen(static_cast<const char*>(fileName.c_str()), FILE_OPEN_FLAG);

    if (!fp) {
        NETSTACK_LOGE("TlsKey::DecodePem: Couldn't open %{public}s file for reading", fileName.c_str());
        return;
    }
    char privateKey[FILE_READ_Key_LEN] = {};
    if (!fread(privateKey, 1, FILE_READ_Key_LEN, fp)) {
        NETSTACK_LOGE("TlsKey::DecodePem file read false");
    }
    (void)fclose(fp);
    const char *privateKeyData = static_cast<const char*>(privateKey);
    BIO *bio = BIO_new_mem_buf(privateKeyData, -1);
    if (!bio) {
        NETSTACK_LOGE("TlsKey::DecodePem: bio is null");
        return;
    }
    passwd_ = passPhrase;
    switch (algorithm) {
        case ALGORITHM_RSA:
            rsa_ = (type == PUBLIC_KEY)
                ? PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr)
                : PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);
            if (rsa_) {
                keyIsNull_ = false;
            }
            break;
        case ALGORITHM_DSA:
            dsa_ = (type == PUBLIC_KEY)
                ? PEM_read_bio_DSA_PUBKEY(bio, nullptr, nullptr, nullptr)
                : PEM_read_bio_DSAPrivateKey(bio, nullptr, nullptr, nullptr);
            if (dsa_) {
                keyIsNull_ = false;
            }
            break;
        case ALGORITHM_DH: {
            EVP_PKEY *result = (type == PUBLIC_KEY)
                ? PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr)
                : PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
            if (result) {
                dh_ = EVP_PKEY_get1_DH(result);
            }
            if (dh_) {
                keyIsNull_ = false;
            }
            EVP_PKEY_free(result);
            break;
        }
        case ALGORITHM_EC:
            ec_ = (type == PUBLIC_KEY)
                ? PEM_read_bio_EC_PUBKEY(bio, nullptr, nullptr, nullptr)
                : PEM_read_bio_ECPrivateKey(bio, nullptr, nullptr, nullptr);
            if (ec_) {
                keyIsNull_ = false;
            }
            break;
        default:
            NETSTACK_LOGE("TlsKey::DecodePem algorithm = %{public}d", algorithm);
    }
    BIO_free(bio);
}

void TLSKey::Clear(bool deep)
{
    keyIsNull_ = true;
    const auto algo = Algorithm();
    if (algo == ALGORITHM_RSA && rsa_) {
        if (deep) {
            RSA_free(rsa_);
        }
        rsa_ = nullptr;
    }
    if (algo == ALGORITHM_DSA && dsa_) {
        if (deep) {
            DSA_free(dsa_);
        }
        dsa_ = nullptr;
    }
    if (algo == ALGORITHM_DH && dh_) {
        if (deep) {
            DH_free(dh_);
        }
        dh_ = nullptr;
    }
    if (algo == ALGORITHM_EC && ec_) {
        if (deep) {
            EC_KEY_free(ec_);
        }
        ec_ = nullptr;
    }
    if (algo == OPAQUE && opaque_) {
        if (deep) {
            EVP_PKEY_free(opaque_);
        }
        opaque_ = nullptr;
    }
}

KeyAlgorithm TLSKey::Algorithm() const
{
    return keyAlgorithm_;
}

Handle TLSKey::handle() const
{
    switch (keyAlgorithm_) {
        case OPAQUE:
            return Handle(OPAQUE);
        case ALGORITHM_RSA:
            return Handle(rsa_);
        case ALGORITHM_DSA:
            return Handle(dsa_);
        case ALGORITHM_DH:
            return Handle(dh_);
        case ALGORITHM_EC:
            return Handle(ec_);
        default:
            return Handle(nullptr);
    }
}

const std::string &TLSKey::GetPasswd() const
{
    return passwd_;
}
} } // namespace OHOS::NetStack
