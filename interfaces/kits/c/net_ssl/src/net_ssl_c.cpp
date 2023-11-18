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

#include "net_ssl.h"
#include "net_ssl_c.h"
#include "net_ssl_c_type.h"

struct OHOS::NetStack::Ssl::CertBlob SwitchToCertBlob(const struct OH_NetStack_CertBlob cert)
{
    OHOS::NetStack::Ssl::CertBlob cb;
    switch (cert.type) {
        case OH_NetStack_CERT_TYPE_PEM:
            cb.type = OHOS::NetStack::Ssl::CertType::CERT_TYPE_PEM;
            break;
        case OH_NetStack_CERT_TYPE_DER:
            cb.type = OHOS::NetStack::Ssl::CertType::CERT_TYPE_DER;
            break;
        case OH_NetStack_CERT_TYPE_MAX:
            cb.type = OHOS::NetStack::Ssl::CertType::CERT_TYPE_MAX;
            break;
    }
    cb.size = cert.size;
    cb.data = cert.data;
    return cb;
}

uint32_t VerifyCert_With_RootCa(const struct OH_NetStack_CertBlob *cert)
{
    uint32_t verifyResult = X509_V_ERR_UNSPECIFIED;
    OHOS::NetStack::Ssl::CertBlob cb = SwitchToCertBlob(*cert);
    verifyResult = OHOS::NetStack::Ssl::NetStackVerifyCertification(&cb);
    return verifyResult;
}

uint32_t VerifyCert_With_DesignatedCa(const struct OH_NetStack_CertBlob *cert,
                                      const struct OH_NetStack_CertBlob *caCert)
{
    uint32_t verifyResult = X509_V_ERR_UNSPECIFIED;
    OHOS::NetStack::Ssl::CertBlob cb = SwitchToCertBlob(*cert);
    OHOS::NetStack::Ssl::CertBlob caCb = SwitchToCertBlob(*caCert);
    verifyResult = OHOS::NetStack::Ssl::NetStackVerifyCertification(&cb, &caCb);
    return verifyResult;
}

uint32_t OH_NetStack_VerifyCertification(const struct OH_NetStack_CertBlob *cert,
                                         const struct OH_NetStack_CertBlob *caCert)
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
