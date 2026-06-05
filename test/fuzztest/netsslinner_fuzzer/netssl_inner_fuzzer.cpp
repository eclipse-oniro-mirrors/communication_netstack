/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <map>
#include <securec.h>
#include <string>
#include <vector>

#include "net_ssl.h"
#include "net_ssl_c.h"
#include "net_ssl_c_type.h"
#include "net_ssl_type.h"
#include "net_ssl_verify_cert.h"
#include "netstack_log.h"
#include "secure_char.h"

namespace OHOS {
namespace NetStack {
namespace Ssl {
namespace {

const uint8_t *g_baseFuzzData = nullptr;
size_t g_baseFuzzSize = 0;
size_t g_baseFuzzPos = 0;
[[maybe_unused]] constexpr size_t STR_LEN = 255;
} // namespace
template <class T> T GetData()
{
    T object{};
    size_t objectSize = sizeof(object);
    if (g_baseFuzzData == nullptr || g_baseFuzzSize <= g_baseFuzzPos || objectSize > g_baseFuzzSize - g_baseFuzzPos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, g_baseFuzzData + g_baseFuzzPos, objectSize);
    if (ret != EOK) {
        return object;
    }
    g_baseFuzzPos += objectSize;
    return object;
}

void SetGlobalFuzzData(const uint8_t *data, size_t size)
{
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
}

std::string GetStringFromData(int strlen)
{
    if (strlen < 1) {
        return "";
    }

    char cstr[strlen];
    cstr[strlen - 1] = '\0';
    for (int i = 0; i < strlen - 1; i++) {
        cstr[i] = GetData<char>();
    }
    std::string str(cstr);
    return str;
}

uint8_t *stringToUint8(const std::string &str)
{
    uint8_t *data = new uint8_t[str.size() + 1];
    for (size_t i = 0; i < str.size(); ++i) {
        data[i] = static_cast<uint8_t>(str[i]);
    }
    data[str.size()] = '\0';
    return data;
}

void SetNetStackVerifyCertificationTestOne(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    std::string str = GetStringFromData(STR_LEN);
    CertBlob certBlob;
    certBlob.type = CERT_TYPE_PEM;
    certBlob.size = str.size();
    certBlob.data = stringToUint8(str);
    NetStackVerifyCertification(&certBlob);
    delete[] certBlob.data;
    certBlob.data = nullptr;
}

void SetNetStackVerifyCertificationTestTwo(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    std::string str = GetStringFromData(STR_LEN);
    CertBlob certBlob;
    certBlob.type = CERT_TYPE_PEM;
    certBlob.size = str.size();
    certBlob.data = stringToUint8(str);
    NetStackVerifyCertification(&certBlob, &certBlob);
    delete[] certBlob.data;
    certBlob.data = nullptr;
}

void SetVerifyCertTestOne(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    std::string str = GetStringFromData(STR_LEN);
    CertBlob certBlob;
    certBlob.type = CERT_TYPE_PEM;
    certBlob.size = str.size();
    certBlob.data = stringToUint8(str);
    VerifyCert(&certBlob);
    delete[] certBlob.data;
    certBlob.data = nullptr;
}

void SetVerifyCertTestTwo(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    std::string str = GetStringFromData(STR_LEN);
    CertBlob certBlob;
    certBlob.type = CERT_TYPE_PEM;
    certBlob.size = str.size();
    certBlob.data = stringToUint8(str);
    VerifyCert(&certBlob, &certBlob);
    delete[] certBlob.data;
    certBlob.data = nullptr;
}

void SetFreeResourcesTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    std::string str = GetStringFromData(STR_LEN);
    CertBlob certBlob;
    certBlob.type = CERT_TYPE_PEM;
    certBlob.size = str.size();
    certBlob.data = stringToUint8(str);
    X509 *cert = PemToX509(certBlob.data, certBlob.size);
    X509_STORE *store = nullptr;
    X509_STORE_CTX *ctx = nullptr;
    FreeResources(&cert, &cert, &store, &ctx);
    delete[] certBlob.data;
    certBlob.data = nullptr;
}

void SetPemToX509Test(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    std::string str = GetStringFromData(STR_LEN);
    CertBlob certBlob;
    certBlob.type = CERT_TYPE_PEM;
    certBlob.size = str.size();
    certBlob.data = stringToUint8(str);
    PemToX509(data, size);
    delete[] certBlob.data;
    certBlob.data = nullptr;
}

void SetDerToX509Test(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    std::string str = GetStringFromData(STR_LEN);
    CertBlob certBlob;
    certBlob.type = CERT_TYPE_PEM;
    certBlob.size = str.size();
    certBlob.data = stringToUint8(str);
    DerToX509(data, size);
    delete[] certBlob.data;
    certBlob.data = nullptr;
}

void SetCertBlobToX509Test(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    std::string str = GetStringFromData(STR_LEN);
    CertBlob certBlob;
    certBlob.type = CERT_TYPE_PEM;
    certBlob.size = str.size();
    certBlob.data = stringToUint8(str);
    CertBlobToX509(&certBlob);
    delete[] certBlob.data;
    certBlob.data = nullptr;
}

void SetOHNetStackCertVerificationTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    std::string str = GetStringFromData(STR_LEN);
    CertBlob certBlob;
    certBlob.type = CERT_TYPE_PEM;
    certBlob.size = str.size();
    certBlob.data = stringToUint8(str);
    OH_NetStack_CertVerification((const struct NetStack_CertBlob *)&certBlob,
                                 (const struct NetStack_CertBlob *)&certBlob);
    delete[] certBlob.data;
    certBlob.data = nullptr;
}

void SetVerifyAndBuildCertChainTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);

    constexpr uint32_t certTypeModulo = 3;
    uint32_t certCount = GetData<uint32_t>() % 5 + 1;
    CertBlob *certs = new CertBlob[certCount];
    for (uint32_t i = 0; i < certCount; i++) {
        std::string str = GetStringFromData(STR_LEN);
        certs[i].type = (GetData<uint32_t>() % certTypeModulo == 0) ? CERT_TYPE_DER : CERT_TYPE_PEM;
        certs[i].size = static_cast<uint32_t>(str.size());
        certs[i].data = stringToUint8(str);
    }

    CertBlob *outChain = nullptr;
    size_t outCount = 0;
    VerifyAndBuildCertChain(certs, certCount, nullptr, nullptr, &outChain, &outCount);
    if (outChain != nullptr) {
        FreeCertChain(outChain, outCount);
    }

    for (uint32_t i = 0; i < certCount; i++) {
        delete[] certs[i].data;
    }
    delete[] certs;
}

void SetVerifyAndBuildCertChainWithCaTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);

    std::string leafStr = GetStringFromData(STR_LEN);
    CertBlob leafCert;
    leafCert.type = CERT_TYPE_PEM;
    leafCert.size = static_cast<uint32_t>(leafStr.size());
    leafCert.data = stringToUint8(leafStr);

    std::string caStr = GetStringFromData(STR_LEN);
    CertBlob caCert;
    caCert.type = CERT_TYPE_PEM;
    caCert.size = static_cast<uint32_t>(caStr.size());
    caCert.data = stringToUint8(caStr);

    CertBlob *outChain = nullptr;
    size_t outCount = 0;
    VerifyAndBuildCertChain(&leafCert, 1, &caCert, nullptr, &outChain, &outCount);
    if (outChain != nullptr) {
        FreeCertChain(outChain, outCount);
    }

    delete[] leafCert.data;
    delete[] caCert.data;
}

void SetVerifyAndBuildCertChainWithHostnameTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);

    std::string leafStr = GetStringFromData(STR_LEN);
    CertBlob leafCert;
    leafCert.type = CERT_TYPE_PEM;
    leafCert.size = static_cast<uint32_t>(leafStr.size());
    leafCert.data = stringToUint8(leafStr);

    std::string hostname = GetStringFromData(STR_LEN);

    CertBlob *outChain = nullptr;
    size_t outCount = 0;
    VerifyAndBuildCertChain(&leafCert, 1, nullptr, hostname.c_str(), &outChain, &outCount);
    if (outChain != nullptr) {
        FreeCertChain(outChain, outCount);
    }

    delete[] leafCert.data;
}

void SetVerifyHostnameTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);

    std::string certStr = GetStringFromData(STR_LEN);
    CertBlob certBlob;
    certBlob.type = CERT_TYPE_PEM;
    certBlob.size = static_cast<uint32_t>(certStr.size());
    certBlob.data = stringToUint8(certStr);

    X509 *cert = CertBlobToX509(&certBlob);
    if (cert != nullptr) {
        std::string hostname = GetStringFromData(STR_LEN);
        VerifyHostname(cert, hostname.c_str());
        X509_free(cert);
    }
    delete[] certBlob.data;
}

void SetX509ToCertBlobTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);

    std::string certStr = GetStringFromData(STR_LEN);
    CertBlob certBlob;
    certBlob.type = CERT_TYPE_PEM;
    certBlob.size = static_cast<uint32_t>(certStr.size());
    certBlob.data = stringToUint8(certStr);

    X509 *cert = CertBlobToX509(&certBlob);
    if (cert != nullptr) {
        CertType type = (GetData<uint32_t>() % 2 == 0) ? CERT_TYPE_PEM : CERT_TYPE_DER;
        CertBlob *blob = X509ToCertBlob(cert, type);
        if (blob != nullptr) {
            delete[] blob->data;
            delete blob;
        }
        X509_free(cert);
    }
    delete[] certBlob.data;
}

void SetFreeCertChainTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);

    uint32_t count = GetData<uint32_t>() % 5;
    CertBlob *chain = new CertBlob[count];
    for (uint32_t i = 0; i < count; i++) {
        std::string str = GetStringFromData(STR_LEN);
        chain[i].type = CERT_TYPE_PEM;
        chain[i].size = static_cast<uint32_t>(str.size());
        chain[i].data = stringToUint8(str);
    }
    FreeCertChain(chain, count);
    // FreeCertChain frees all memory, no cleanup needed
}

void SetOHNetStackCreateAndVerifySortedCertChainTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);

    uint32_t certCount = GetData<uint32_t>() % 5 + 1;
    struct NetStack_CertBlob *certs =
        (struct NetStack_CertBlob *)malloc(certCount * sizeof(struct NetStack_CertBlob));
    if (certs == nullptr) {
        return;
    }
    for (uint32_t i = 0; i < certCount; i++) {
        std::string str = GetStringFromData(STR_LEN);
        certs[i].type = NETSTACK_CERT_TYPE_PEM;
        certs[i].size = static_cast<uint32_t>(str.size());
        certs[i].data = (uint8_t *)malloc(certs[i].size);
        if (certs[i].data != nullptr) {
            if (memcpy_s(certs[i].data, certs[i].size, str.c_str(), certs[i].size) != EOK) {
                free(certs[i].data);
                certs[i].data = nullptr;
            }
        }
    }

    struct NetStack_CertBlob *outChain = nullptr;
    size_t outCount = 0;
    OH_NetStack_CreateAndVerifySortedCertChain(certs, certCount, nullptr, nullptr, &outChain, &outCount);
    if (outChain != nullptr) {
        OH_NetStack_FreeCertChain(outChain, outCount);
    }

    for (uint32_t i = 0; i < certCount; i++) {
        if (certs[i].data != nullptr) {
            free(certs[i].data);
        }
    }
    free(certs);
}

} // namespace Ssl
} // namespace NetStack
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::NetStack::Ssl::SetNetStackVerifyCertificationTestOne(data, size);
    OHOS::NetStack::Ssl::SetNetStackVerifyCertificationTestTwo(data, size);
    OHOS::NetStack::Ssl::SetVerifyCertTestOne(data, size);
    OHOS::NetStack::Ssl::SetVerifyCertTestTwo(data, size);
    OHOS::NetStack::Ssl::SetFreeResourcesTest(data, size);
    OHOS::NetStack::Ssl::SetPemToX509Test(data, size);
    OHOS::NetStack::Ssl::SetDerToX509Test(data, size);
    OHOS::NetStack::Ssl::SetCertBlobToX509Test(data, size);
    OHOS::NetStack::Ssl::SetOHNetStackCertVerificationTest(data, size);
    OHOS::NetStack::Ssl::SetVerifyAndBuildCertChainTest(data, size);
    OHOS::NetStack::Ssl::SetVerifyAndBuildCertChainWithCaTest(data, size);
    OHOS::NetStack::Ssl::SetVerifyAndBuildCertChainWithHostnameTest(data, size);
    OHOS::NetStack::Ssl::SetVerifyHostnameTest(data, size);
    OHOS::NetStack::Ssl::SetX509ToCertBlobTest(data, size);
    OHOS::NetStack::Ssl::SetFreeCertChainTest(data, size);
    OHOS::NetStack::Ssl::SetOHNetStackCreateAndVerifySortedCertChainTest(data, size);
    return 0;
}