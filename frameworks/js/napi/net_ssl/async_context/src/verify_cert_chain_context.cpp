/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "verify_cert_chain_context.h"

#include <map>
#include <node_api.h>
#include <openssl/ssl.h>

#include "napi_utils.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"
#include "net_ssl_verify_cert.h"
#if HAS_NETMANAGER_BASE
#include "net_conn_client.h"
#endif // HAS_NETMANAGER_BASE

static constexpr const int PARAM_CERT_ARRAY = 1;
static constexpr const int PARAM_CERT_ARRAY_AND_CA = 2;
static constexpr const int PARAM_CERT_ARRAY_CA_HOSTNAME = 3;

namespace OHOS::NetStack::Ssl {

static const std::map<int32_t, const char *> SSL_ERR_MAP_EXT = {
    {SslErrorCode::SSL_NONE_ERR, "Verify success."},
    {SslErrorCode::SSL_X509_V_ERR_UNSPECIFIED, "Unspecified error."},
    {SslErrorCode::SSL_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT, "Unable to get issuer certificate."},
    {SslErrorCode::SSL_X509_V_ERR_UNABLE_TO_GET_CRL, "Unable to get certificate revocation list (CRL)."},
    {SslErrorCode::SSL_X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE, "Unable to decrypt certificate signature."},
    {SslErrorCode::SSL_X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE, "Unable to decrypt CRL signature."},
    {SslErrorCode::SSL_X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY, "Unable to decode issuer public key."},
    {SslErrorCode::SSL_X509_V_ERR_CERT_SIGNATURE_FAILURE, "Certificate signature failure."},
    {SslErrorCode::SSL_X509_V_ERR_CRL_SIGNATURE_FAILURE, "CRL signature failure."},
    {SslErrorCode::SSL_X509_V_ERR_CERT_NOT_YET_VALID, "Certificate is not yet valid."},
    {SslErrorCode::SSL_X509_V_ERR_CERT_HAS_EXPIRED, "Certificate has expired."},
    {SslErrorCode::SSL_X509_V_ERR_CRL_NOT_YET_VALID, "CRL is not yet valid."},
    {SslErrorCode::SSL_X509_V_ERR_CRL_HAS_EXPIRED, "CRL has expired."},
    {SslErrorCode::SSL_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY, "Unable to get local issuer certificate."},
    {SslErrorCode::SSL_X509_V_ERR_CERT_REVOKED, "Certificate has been revoked."},
    {SslErrorCode::SSL_X509_V_ERR_INVALID_CA, "Invalid certificate authority (CA)."},
    {SslErrorCode::SSL_X509_V_ERR_CERT_UNTRUSTED, "Certificate is untrusted."},
    {SslErrorCode::SSL_X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT, "Self-signed certificate."},
    {SslErrorCode::SSL_X509_V_ERR_INVALID_CALL, "Invalid certificate verification context."},
    {SslErrorCode::SSL_X509_V_ERR_HOSTNAME_MISMATCH, "Hostname verification failed."}
};

VerifyCertChainContext::VerifyCertChainContext(napi_env env, const std::shared_ptr<EventManager> &manager)
    : BaseContext(env, manager),
      inputCerts_(nullptr),
      inputCertCount_(0),
      caCert_(nullptr),
      sortedChain_(nullptr),
      sortedChainCount_(0) {}

void VerifyCertChainContext::ParseParams(napi_value *params, size_t paramsCount)
{
    bool valid = CheckParamsType(params, paramsCount);
    if (valid) {
        if (paramsCount == PARAM_CERT_ARRAY) {
            // verifyCertChain([cert1, cert2])
            inputCerts_ = ParseCertBlobArray(GetEnv(), params[0], &inputCertCount_);
            SetParseOK(inputCerts_ != nullptr && inputCertCount_ > 0);
        } else if (paramsCount == PARAM_CERT_ARRAY_AND_CA) {
            // verifyCertChain([cert1, cert2], caCert)
            inputCerts_ = ParseCertBlobArray(GetEnv(), params[0], &inputCertCount_);

            // Check if second param is undefined/null (optional caCert)
            napi_valuetype valueType;
            napi_typeof(GetEnv(), params[1], &valueType);
            if (valueType != napi_undefined && valueType != napi_null) {
                caCert_ = ParseSingleCertBlob(GetEnv(), params[1]);
            }

            SetParseOK(inputCerts_ != nullptr && inputCertCount_ > 0);
        } else if (paramsCount == PARAM_CERT_ARRAY_CA_HOSTNAME) {
            // verifyCertChain([cert1, cert2], caCert, "example.com")
            inputCerts_ = ParseCertBlobArray(GetEnv(), params[0], &inputCertCount_);

            // Check if second param is undefined/null (optional caCert)
            napi_valuetype valueType;
            napi_typeof(GetEnv(), params[1], &valueType);
            if (valueType != napi_undefined && valueType != napi_null) {
                caCert_ = ParseSingleCertBlob(GetEnv(), params[1]);
            }

            // Check if third param is undefined/null (optional hostname)
            napi_typeof(GetEnv(), params[2], &valueType);
            if (valueType != napi_undefined && valueType != napi_null) {
                hostname_ = ParseHostname(GetEnv(), params[2]);
            }

            SetParseOK(inputCerts_ != nullptr && inputCertCount_ > 0);
        }
    } else {
        SetErrorCode(PARSE_ERROR_CODE);
    }
}

bool VerifyCertChainContext::CheckParamsType(napi_value *params, size_t paramsCount)
{
    if (paramsCount == PARAM_CERT_ARRAY) {
        bool isArray = false;
        napi_is_array(GetEnv(), params[0], &isArray);
        return isArray;
    } else if (paramsCount == PARAM_CERT_ARRAY_AND_CA) {
        bool isArray = false;
        napi_is_array(GetEnv(), params[0], &isArray);
        // Second param can be object or undefined/null
        napi_valuetype valueType;
        napi_typeof(GetEnv(), params[1], &valueType);
        return isArray && (valueType == napi_object || valueType == napi_undefined || valueType == napi_null);
    } else if (paramsCount == PARAM_CERT_ARRAY_CA_HOSTNAME) {
        bool isArray = false;
        napi_is_array(GetEnv(), params[0], &isArray);
        // Second param can be object or undefined/null
        napi_valuetype valueType1;
        napi_valuetype valueType2;
        napi_typeof(GetEnv(), params[1], &valueType1);
        napi_typeof(GetEnv(), params[2], &valueType2);
        return isArray &&
               (valueType1 == napi_object || valueType1 == napi_undefined || valueType1 == napi_null) &&
               (valueType2 == napi_string || valueType2 == napi_undefined || valueType2 == napi_null);
    }
    return false;
}

static void FreePartialCertArray(CertBlob *certArray, uint32_t count)
{
    for (uint32_t j = 0; j < count; j++) {
        if (certArray[j].data != nullptr) {
            delete[] certArray[j].data;
        }
    }
}

CertBlob *VerifyCertChainContext::ParseCertBlobArray(napi_env env, napi_value value, size_t *count)
{
    bool isArray = false;
    napi_is_array(env, value, &isArray);
    if (!isArray) {
        NETSTACK_LOGE("Input is not an array\n");
        SetErrorCode(PARSE_ERROR_CODE);
        return nullptr;
    }

    uint32_t arrayLength = 0;
    napi_get_array_length(env, value, &arrayLength);
    if (arrayLength == 0) {
        NETSTACK_LOGE("Empty certificate array\n");
        SetErrorCode(PARSE_ERROR_CODE);
        return nullptr;
    }

    CertBlob *certArray = new (std::nothrow) CertBlob[arrayLength];
    if (certArray == nullptr) {
        NETSTACK_LOGE("Failed to allocate cert array\n");
        SetErrorCode(PARSE_ERROR_CODE);
        return nullptr;
    }

    for (uint32_t i = 0; i < arrayLength; i++) {
        napi_value element;
        napi_get_element(env, value, i, &element);

        CertBlob *cert = ParseSingleCertBlob(env, element);
        if (cert == nullptr) {
            NETSTACK_LOGE("Failed to parse certificate at index %{public}u\n", i);
            FreePartialCertArray(certArray, i);
            delete[] certArray;
            SetErrorCode(PARSE_ERROR_CODE);
            return nullptr;
        }

        certArray[i] = *cert;
        delete cert;
    }

    *count = static_cast<size_t>(arrayLength);
    return certArray;
}

CertBlob *VerifyCertChainContext::ParseSingleCertBlob(napi_env env, napi_value value)
{
    napi_value typeValue = nullptr;
    napi_value dataValue = nullptr;
    napi_get_named_property(env, value, "type", &typeValue);
    napi_get_named_property(env, value, "data", &dataValue);

    if (typeValue == nullptr || dataValue == nullptr) {
        NETSTACK_LOGE("Missing type or data property\n");
        SetErrorCode(PARSE_ERROR_CODE);
        return new CertBlob{CERT_TYPE_MAX, 0, nullptr};
    }

    return ParseCertBlobFromData(env, value, typeValue, dataValue);
}

CertBlob *VerifyCertChainContext::ParseCertBlobFromData(
    napi_env env, napi_value value, napi_value typeValue, napi_value dataValue)
{
    size_t dataSize = 0;
    uint32_t type;
    uint32_t size = 0;
    uint8_t *data = nullptr;

    napi_get_value_uint32(env, typeValue, &type);
    CertType certType = static_cast<CertType>(type);

    if (certType == CERT_TYPE_PEM) {
        NETSTACK_LOGD("CERT_TYPE_PEM\n");
        napi_valuetype valueType;
        napi_typeof(env, dataValue, &valueType);
        if (valueType != napi_string) {
            NETSTACK_LOGE("PEM but not string\n");
            return new CertBlob{CERT_TYPE_MAX, 0, nullptr};
        }

        napi_get_value_string_utf8(env, dataValue, nullptr, 0, &dataSize);
        if (dataSize + 1 < SIZE_MAX / sizeof(uint8_t)) {
            data = new (std::nothrow) uint8_t[dataSize + 1];
            if (data == nullptr) {
                return new CertBlob{CERT_TYPE_MAX, 0, nullptr};
            }
            napi_get_value_string_utf8(env, dataValue, reinterpret_cast<char *>(data), dataSize + 1, &dataSize);
            size = static_cast<uint32_t>(dataSize);
        } else {
            return new CertBlob{CERT_TYPE_MAX, 0, nullptr};
        }
    } else if (certType == CERT_TYPE_DER) {
        NETSTACK_LOGD("CERT_TYPE_DER\n");
        bool isArrayBuffer = false;
        napi_is_arraybuffer(env, dataValue, &isArrayBuffer);
        if (!isArrayBuffer) {
            NETSTACK_LOGE("DER but not arraybuffer\n");
            return new CertBlob{CERT_TYPE_MAX, 0, nullptr};
        }

        void *dataArray = nullptr;
        napi_get_arraybuffer_info(env, dataValue, &dataArray, &dataSize);
        if (dataSize < SIZE_MAX / sizeof(uint8_t)) {
            data = new uint8_t[dataSize];
            std::copy(static_cast<uint8_t *>(dataArray), static_cast<uint8_t *>(dataArray) + dataSize, data);
            size = static_cast<uint32_t>(dataSize);
        } else {
            return new CertBlob{CERT_TYPE_MAX, 0, nullptr};
        }
    } else {
        return new CertBlob{CERT_TYPE_MAX, 0, nullptr};
    }

    return new CertBlob{static_cast<CertType>(type), static_cast<uint32_t>(size), static_cast<uint8_t *>(data)};
}

std::string VerifyCertChainContext::ParseHostname(napi_env env, napi_value value)
{
    napi_valuetype valueType;
    napi_typeof(env, value, &valueType);
    if (valueType != napi_string) {
        NETSTACK_LOGE("Hostname is not a string\n");
        return "";
    }

    size_t hostnameLen = 0;
    napi_get_value_string_utf8(env, value, nullptr, 0, &hostnameLen);
    if (hostnameLen == 0) {
        return "";
    }

    std::string hostname;
    hostname.resize(hostnameLen);
    napi_get_value_string_utf8(env, value, &hostname[0], hostnameLen + 1, &hostnameLen);

    return hostname;
}

void VerifyCertChainContext::SetSortedChain(CertBlob *chain, size_t count)
{
    sortedChain_ = chain;
    sortedChainCount_ = count;
}

int32_t VerifyCertChainContext::GetErrorCode() const
{
    auto errorCode = BaseContext::GetErrorCode();
    if (errorCode == PARSE_ERROR_CODE) {
        return PARSE_ERROR_CODE;
    }
    const auto &errorCodeSet = SslErrorCodeSetSinceAPI26;
    if (errorCodeSet.find(errorCode) == errorCodeSet.end()) {
        errorCode = SSL_X509_V_ERR_UNSPECIFIED;
    }
    return errorCode;
}

std::string VerifyCertChainContext::GetErrorMessage() const
{
    auto err = BaseContext::GetErrorCode();
    if (err == PARSE_ERROR_CODE) {
        return PARSE_ERROR_MSG;
    }

    auto pos = SSL_ERR_MAP_EXT.find(err);
    if (pos != SSL_ERR_MAP_EXT.end()) {
        return pos->second;
    }
    return SSL_ERR_MAP_EXT.at(SslErrorCode::SSL_X509_V_ERR_CERT_UNTRUSTED);
}

VerifyCertChainContext::~VerifyCertChainContext()
{
    if (inputCerts_ != nullptr) {
        for (size_t i = 0; i < inputCertCount_; i++) {
            if (inputCerts_[i].data != nullptr) {
                delete[] inputCerts_[i].data;
                inputCerts_[i].data = nullptr;
            }
        }
        delete[] inputCerts_;
        inputCerts_ = nullptr;
    }

    if (caCert_ != nullptr) {
        if (caCert_->data != nullptr) {
            delete[] caCert_->data;
            caCert_->data = nullptr;
        }
        delete caCert_;
        caCert_ = nullptr;
    }

    if (sortedChain_ != nullptr) {
        for (size_t i = 0; i < sortedChainCount_; i++) {
            if (sortedChain_[i].data != nullptr) {
                delete[] sortedChain_[i].data;
                sortedChain_[i].data = nullptr;
            }
        }
        delete[] sortedChain_;
        sortedChain_ = nullptr;
    }

    NETSTACK_LOGD("VerifyCertChainContext is destroyed by the destructor");
}

} // namespace OHOS::NetStack::Ssl
