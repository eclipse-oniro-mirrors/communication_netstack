/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <cstring>
#include <iostream>
#include <vector>
#include <string>

#include <openssl/ssl.h>

#include "net_ssl.h"
#include "net_ssl_c.h"
#include "net_ssl_c_type.h"
#include "securec.h"
#include "netstack_log.h"
#include "net_ssl_verify_cert.h"
#include "net_manager_constants.h"
#include "network_security_config.h"
#include "netmanager_base_permission.h"

struct OHOS::NetStack::Ssl::CertBlob SwitchToCertBlob(const struct NetStack_CertBlob cert)
{
    OHOS::NetStack::Ssl::CertBlob cb;
    switch (cert.type) {
        case NETSTACK_CERT_TYPE_PEM:
            cb.type = OHOS::NetStack::Ssl::CertType::CERT_TYPE_PEM;
            break;
        case NETSTACK_CERT_TYPE_DER:
            cb.type = OHOS::NetStack::Ssl::CertType::CERT_TYPE_DER;
            break;
        case NETSTACK_CERT_TYPE_INVALID:
            cb.type = OHOS::NetStack::Ssl::CertType::CERT_TYPE_MAX;
            break;
        default:
            break;
    }
    cb.size = cert.size;
    cb.data = cert.data;
    return cb;
}

uint32_t VerifyCert_With_RootCa(const struct NetStack_CertBlob *cert)
{
    uint32_t verifyResult = X509_V_ERR_UNSPECIFIED;
    OHOS::NetStack::Ssl::CertBlob cb = SwitchToCertBlob(*cert);
    verifyResult = OHOS::NetStack::Ssl::NetStackVerifyCertification(&cb);
    return verifyResult;
}

uint32_t VerifyCert_With_DesignatedCa(const struct NetStack_CertBlob *cert, const struct NetStack_CertBlob *caCert)
{
    uint32_t verifyResult = X509_V_ERR_UNSPECIFIED;
    OHOS::NetStack::Ssl::CertBlob cb = SwitchToCertBlob(*cert);
    OHOS::NetStack::Ssl::CertBlob caCb = SwitchToCertBlob(*caCert);
    verifyResult = OHOS::NetStack::Ssl::NetStackVerifyCertification(&cb, &caCb);
    return verifyResult;
}

uint32_t OH_NetStack_CertVerification(const struct NetStack_CertBlob *cert, const struct NetStack_CertBlob *caCert)
{
    if (cert == nullptr) {
        return X509_V_ERR_INVALID_CALL;
    }
    if (caCert == nullptr) {
        return VerifyCert_With_RootCa(cert);
    } else {
        return VerifyCert_With_DesignatedCa(cert, caCert);
    }
}

int32_t OH_NetStack_GetPinSetForHostName(const char *hostname, NetStack_CertificatePinning *pin)
{
    if (hostname == nullptr || pin == nullptr) {
        NETSTACK_LOGE("OH_NetStack_GetPinSetForHostName received invalid parameters");
        return OHOS::NetManagerStandard::NETMANAGER_ERR_PARAMETER_ERROR;
    }

    std::string innerHostname = std::string(hostname);
    std::string innerPins;

    int32_t ret = OHOS::NetManagerStandard::NetworkSecurityConfig::GetInstance().
        GetPinSetForHostName(innerHostname, innerPins);
    if (ret != OHOS::NetManagerStandard::NETMANAGER_SUCCESS) {
        return ret;
    }
    
    if (innerPins.length() <= 0) {
        pin->hashAlgorithm = NetStack_HashAlgorithm::SHA_256;
        pin->kind = NetStack_CertificatePinningKind::PUBLIC_KEY;
        pin->publicKeyHash = nullptr;
        return OHOS::NetManagerStandard::NETMANAGER_SUCCESS;
    }

    size_t size = innerPins.length() + 1;
    char *key = (char *)malloc(size);
    if (key == nullptr) {
        NETSTACK_LOGE("OH_NetStack_GetPinSetForHostName malloc failed");
        return OHOS::NetStack::Ssl::SslErrorCode::SSL_X509_V_ERR_OUT_OF_MEMORY;
    }

    if (strcpy_s(key, size, innerPins.c_str()) != 0) {
        free(key);
        NETSTACK_LOGE("OH_NetStack_GetPinSetForHostName string copy failed");
        return OHOS::NetStack::Ssl::SslErrorCode::SSL_X509_V_ERR_OUT_OF_MEMORY;
    }
    pin->hashAlgorithm = NetStack_HashAlgorithm::SHA_256;
    pin->kind = NetStack_CertificatePinningKind::PUBLIC_KEY;
    pin->publicKeyHash = key;

    return OHOS::NetManagerStandard::NETMANAGER_SUCCESS;
}

int32_t OH_NetStack_GetCertificatesForHostName(const char *hostname, NetStack_Certificates *certs)
{
    if (hostname == nullptr || certs == nullptr) {
        NETSTACK_LOGE("OH_NetStack_GetCertificatesForHostName received invalid parameters");
        return OHOS::NetManagerStandard::NETMANAGER_ERR_PARAMETER_ERROR;
    }

    std::string innerHostname = std::string(hostname);
    std::vector<std::string> innerCerts;

    int32_t ret = OHOS::NetManagerStandard::NetworkSecurityConfig::GetInstance()
                  .GetTrustAnchorsForHostName(innerHostname, innerCerts);
    if (ret != OHOS::NetManagerStandard::NETMANAGER_SUCCESS) {
        return ret;
    }

    size_t innerCertsLength = innerCerts.size();
    if (innerCertsLength <= 0) {
        certs->length = 0;
        certs->content = nullptr;
        return OHOS::NetManagerStandard::NETMANAGER_SUCCESS;
    }

    size_t contentPtrSize = innerCertsLength * sizeof(char *);
    size_t totalMallocSize = contentPtrSize;
    for (size_t i = 0; i < innerCertsLength; ++i) {
        totalMallocSize += innerCerts[i].size() + 1;
    }
    char *ptr = (char *)malloc(totalMallocSize);
    if (ptr == nullptr) {
        NETSTACK_LOGE("OH_NetStack_GetCertificatesForHostName malloc failed");
        return OHOS::NetStack::Ssl::SslErrorCode::SSL_X509_V_ERR_OUT_OF_MEMORY;
    }
    char **contentPtr = reinterpret_cast<char **>(ptr);
    char *certPtr = ptr + contentPtrSize;

    for (size_t i = 0; i < innerCertsLength; ++i) {
        size_t certLen = innerCerts[i].size() + 1;
        if (strcpy_s(certPtr, certLen, innerCerts[i].c_str()) != 0) {
            free(ptr);
            NETSTACK_LOGE("OH_NetStack_GetCertificatesForHostName string copy failed");
            return OHOS::NetStack::Ssl::SslErrorCode::SSL_X509_V_ERR_OUT_OF_MEMORY;
        }
        contentPtr[i] = certPtr;
        certPtr += certLen;
    }

    certs->length = innerCertsLength;
    certs->content = contentPtr;
    return OHOS::NetManagerStandard::NETMANAGER_SUCCESS;
}

void OH_Netstack_DestroyCertificatesContent(NetStack_Certificates *certs)
{
    if (certs == nullptr) {
        NETSTACK_LOGE("OH_Netstack_DestroyCertificatesContent received invalid parameters");
        return;
    }

    if (certs->content == nullptr) {
        return;
    }

    free(certs->content);
    certs->content = nullptr;
    certs->length = 0;
}

int32_t OH_Netstack_IsCleartextPermitted(bool *isCleartextPermitted)
{
    if (isCleartextPermitted == nullptr) {
        NETSTACK_LOGE("OH_Netstack_IsCleartextPermitted received invalid parameters");
        return OHOS::NetManagerStandard::NETMANAGER_ERR_PARAMETER_ERROR;
    }
    return OHOS::NetManagerStandard::NetworkSecurityConfig::GetInstance().IsCleartextPermitted(*isCleartextPermitted);
}

int32_t OH_Netstack_IsCleartextPermittedByHostName(const char *hostname, bool *isCleartextPermitted)
{
    if (hostname == nullptr || isCleartextPermitted == nullptr) {
        NETSTACK_LOGE("OH_Netstack_IsCleartextPermittedByHostName received invalid parameters");
        return OHOS::NetManagerStandard::NETMANAGER_ERR_PARAMETER_ERROR;
    }
    return OHOS::NetManagerStandard::NetworkSecurityConfig::GetInstance()
        .IsCleartextPermitted(std::string(hostname), *isCleartextPermitted);
}

int32_t OH_Netstack_IsCleartextCfgByComponent(const char *component, bool *componentCfg)
{
    if (component == nullptr || componentCfg == nullptr) {
        NETSTACK_LOGE("OH_Netstack_IsCleartextCfgByComponent received invalid parameters");
        return OHOS::NetManagerStandard::NETMANAGER_ERR_INVALID_PARAMETER;
    }
    return OHOS::NetManagerStandard::NetworkSecurityConfig::GetInstance()
        .IsCleartextCfgByComponent(std::string(component), *componentCfg);
}

static uint32_t ConvertOutputChain(
    OHOS::NetStack::Ssl::CertBlob *sortedChain, size_t sortedCount,
    struct NetStack_CertBlob **outSortedChain, size_t *outSortedCount)
{
    constexpr size_t maxCertChainSize = 10;
    if (sortedCount == 0 || sortedCount > maxCertChainSize) {
        NETSTACK_LOGE("Invalid cert chain size: %{public}zu", sortedCount);
        return OHOS::NetStack::Ssl::SSL_X509_V_ERR_INVALID_CALL;
    }

    struct NetStack_CertBlob *outputChain =
        (struct NetStack_CertBlob *)malloc(sortedCount * sizeof(struct NetStack_CertBlob));
    if (outputChain == nullptr) {
        NETSTACK_LOGE("Failed to allocate output chain");
        return OHOS::NetStack::Ssl::SSL_X509_V_ERR_OUT_OF_MEMORY;
    }

    for (size_t i = 0; i < sortedCount; i++) {
        outputChain[i].type = static_cast<enum NetStack_CertType>(sortedChain[i].type);
        outputChain[i].size = sortedChain[i].size;
        outputChain[i].data = (uint8_t *)malloc(sortedChain[i].size);
        if (outputChain[i].data == nullptr) {
            NETSTACK_LOGE("Failed to allocate cert data at index %{public}zu", i);
            for (size_t j = 0; j < i; j++) {
                free(outputChain[j].data);
            }
            free(outputChain);
            return OHOS::NetStack::Ssl::SSL_X509_V_ERR_OUT_OF_MEMORY;
        }
        memcpy_s(outputChain[i].data, sortedChain[i].size,
                 sortedChain[i].data, sortedChain[i].size);
    }

    *outSortedChain = outputChain;
    *outSortedCount = sortedCount;
    return 0;
}

uint32_t OH_NetStack_CreateAndVerifySortedCertChain(
    const struct NetStack_CertBlob *cert,
    size_t certCount,
    const struct NetStack_CertBlob *caCert,
    const char *hostname,
    struct NetStack_CertBlob **outSortedChain,
    size_t *outSortedCount)
{
    if (cert == nullptr || certCount == 0 || outSortedCount == nullptr) {
        NETSTACK_LOGE("OH_NetStack_CreateAndVerifySortedCertChain received invalid parameters");
        return OHOS::NetStack::Ssl::SSL_X509_V_ERR_INVALID_CALL;
    }

    std::vector<OHOS::NetStack::Ssl::CertBlob> internalCerts;
    for (size_t i = 0; i < certCount; i++) {
        internalCerts.push_back(SwitchToCertBlob(cert[i]));
    }

    OHOS::NetStack::Ssl::CertBlob *internalCaCert = nullptr;
    OHOS::NetStack::Ssl::CertBlob caCertBlob;
    if (caCert != nullptr) {
        caCertBlob = SwitchToCertBlob(*caCert);
        internalCaCert = &caCertBlob;
    }

    OHOS::NetStack::Ssl::CertBlob *sortedChain = nullptr;
    size_t sortedCount = 0;
    uint32_t result = OHOS::NetStack::Ssl::VerifyAndBuildCertChain(
        internalCerts.data(), certCount, internalCaCert, hostname, &sortedChain, &sortedCount);
    if (result != 0) {
        NETSTACK_LOGE("Certificate chain verification failed with error: %{public}u", result);
        *outSortedCount = 0;
        return result;
    }

    if (outSortedChain != nullptr && sortedChain != nullptr && sortedCount > 0) {
        result = ConvertOutputChain(sortedChain, sortedCount, outSortedChain, outSortedCount);
        OHOS::NetStack::Ssl::FreeCertChain(sortedChain, sortedCount);
    } else {
        *outSortedCount = sortedCount;
        if (sortedChain != nullptr) {
            OHOS::NetStack::Ssl::FreeCertChain(sortedChain, sortedCount);
        }
    }

    NETSTACK_LOGD("Certificate chain verification succeeded, chain length: %{public}zu", sortedCount);
    return result;
}

void OH_NetStack_FreeCertChain(struct NetStack_CertBlob *certChain, size_t certCount)
{
    if (certChain == nullptr || certCount == 0) {
        return;
    }

    for (size_t i = 0; i < certCount; i++) {
        if (certChain[i].data != nullptr) {
            free(certChain[i].data);
            certChain[i].data = nullptr;
        }
    }
    free(certChain);
}