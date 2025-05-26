/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "network_security_ani.h"

#include "net_ssl.h"
#include "wrapper.rs.h"

namespace OHOS {
namespace NetStackAni {

uint32_t NetStackVerifyCertificationCa(const CertBlob &cert, const CertBlob &caCert)
{
    std::string a;
    NetStack::Ssl::CertBlob nativeCert{ .type = cert.cert_type,
        .size = cert.data.size(),
        .data = reinterpret_cast<uint8_t *>(const_cast<char *>(cert.data.data())) };

    NetStack::Ssl::CertBlob nativeCaCert{ .type = caCert.cert_type,
        .size = caCert.data.size(),
        .data = reinterpret_cast<uint8_t *>(const_cast<char *>(caCert.data.data())) };
    return NetStack::Ssl::NetStackVerifyCertification(&nativeCert, &nativeCaCert);
}

uint32_t NetStackVerifyCertification(const CertBlob &cert)
{
    NetStack::Ssl::CertBlob nativeCert{ .type = cert.cert_type,
        .size = cert.data.size(),
        .data = reinterpret_cast<uint8_t *>(const_cast<char *>(cert.data.data())) };
    return NetStack::Ssl::NetStackVerifyCertification(&nativeCert);
}

} // namespace NetStackAni
} // namespace OHOS
