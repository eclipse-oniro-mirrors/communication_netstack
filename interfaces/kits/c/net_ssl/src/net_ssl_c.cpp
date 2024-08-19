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
#include "net_manager_constants.h"
#include "net_conn_client.h"

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

    int32_t ret = OHOS::NetManagerStandard::NetConnClient::GetInstance().GetPinSetForHostName(innerHostname, innerPins);
    if (ret != OHOS::NetManagerStandard::NETMANAGER_SUCCESS) {
        return ret;
    }

    size_t size = innerPins.length() + 1;
    char *key = (char *)malloc(size);
    if (key == nullptr) {
        NETSTACK_LOGE("OH_NetStack_GetPinSetForHostName malloc failed");
        return OHOS::NetManagerStandard::NETMANAGER_ERR_INTERNAL;
    }

    if (strcpy_s(key, size, innerPins.c_str()) != 0) {
        NETSTACK_LOGE("OH_NetStack_GetPinSetForHostName string copy failed");
        return OHOS::NetManagerStandard::NETMANAGER_ERR_STRCPY_FAIL;
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

    int32_t ret = OHOS::NetManagerStandard::NetConnClient::GetInstance()
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
    char **contentPtr = (char **)malloc(innerCertsLength * sizeof(char *));
    if (contentPtr == nullptr) {
        NETSTACK_LOGE("OH_NetStack_GetCertificatesForHostName malloc failed");
        return OHOS::NetManagerStandard::NETMANAGER_ERR_INTERNAL;
    }

    for (size_t i = 0; i < innerCertsLength; ++i) {
        size_t certLen = innerCerts[i].size() + 1;
        char *certPtr = (char *)malloc(certLen);
        if (certPtr == nullptr) {
            NETSTACK_LOGE("OH_NetStack_GetCertificatesForHostName malloc failed");
            return OHOS::NetManagerStandard::NETMANAGER_ERR_INTERNAL;
        }
        if (strcpy_s(certPtr, certLen, innerCerts[i].c_str()) != 0) {
            NETSTACK_LOGE("OH_NetStack_GetCertificatesForHostName string copy failed");
            return OHOS::NetManagerStandard::NETMANAGER_ERR_STRCPY_FAIL;
        }
        contentPtr[i] = certPtr;
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

    for (size_t i = 0; i < certs->length; ++i) {
        free(certs->content[i]);
    }

    free((void *)certs->content);
    certs->content = nullptr;
    certs->length = 0;
}
