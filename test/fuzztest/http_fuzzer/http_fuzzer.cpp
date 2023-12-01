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
#include <map>
#include <securec.h>
#include <string>
#include <vector>

#include "http_request_options.h"
#include "netstack_log.h"
#include "secure_char.h"

namespace OHOS {
namespace NetStack {
namespace Http {
namespace {
const uint8_t *g_baseFuzzData = nullptr;
size_t g_baseFuzzSize = 0;
size_t g_baseFuzzPos = 0;
constexpr size_t STR_LEN = 255;
} // namespace
template <class T> T GetData()
{
    T object{};
    size_t objectSize = sizeof(object);
    if (g_baseFuzzData == nullptr || g_baseFuzzSize <= g_baseFuzzPos || objectSize > g_baseFuzzSize - g_baseFuzzPos) {
        return object;
    }
    if (memcpy_s(&object, objectSize, g_baseFuzzData + g_baseFuzzPos, objectSize)) {
        return {};
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

void SetCaPathFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    std::string str = GetStringFromData(STR_LEN);

    HttpRequestOptions requestOptions;
    requestOptions.SetCaPath(str);
}

void SetUrlFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    HttpRequestOptions requestOptions;
    std::string str = GetStringFromData(STR_LEN);
    requestOptions.SetUrl(str);
}

void SetMethodFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    HttpRequestOptions requestOptions;
    std::string str = GetStringFromData(STR_LEN);
    requestOptions.SetMethod(str);
}

void SetHeaderFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    HttpRequestOptions requestOptions;
    std::string str = GetStringFromData(STR_LEN);
    requestOptions.SetHeader(str, str);
}

void SetReadTimeoutFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    HttpRequestOptions requestOptions;
    requestOptions.SetReadTimeout(size);
}

void SetConnectTimeoutFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    HttpRequestOptions requestOptions;
    requestOptions.SetConnectTimeout(size);
}

void SetUsingProtocolFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    HttpRequestOptions requestOptions;
}

void SetHttpDataTypeFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    HttpRequestOptions requestOptions;
    std::string str = GetStringFromData(STR_LEN);
    requestOptions.SetRequestTime(str);
}

void SetUsingHttpProxyTypeFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    HttpRequestOptions requestOptions;
    requestOptions.SetUsingHttpProxyType(UsingHttpProxyType::USE_SPECIFIED);
}

void SetSpecifiedHttpProxyFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    HttpRequestOptions requestOptions;
    std::string str = GetStringFromData(STR_LEN);
    requestOptions.SetSpecifiedHttpProxy(str, size, str);
}

void SetDnsServersFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    HttpRequestOptions requestOptions;
    std::string str = GetStringFromData(STR_LEN);
    std::vector<std::string> dnsServers = { GetStringFromData(STR_LEN), GetStringFromData(STR_LEN),
        GetStringFromData(STR_LEN) };
    requestOptions.SetDnsServers(dnsServers);
}

void SetDohUrlFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);

    HttpRequestOptions requestOptions;
    std::string str = GetStringFromData(STR_LEN);
    requestOptions.SetDohUrl(str);
}

void SetRangeNumberFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    HttpRequestOptions requestOptions;
    requestOptions.SetRangeNumber(size, size);
}

void SetClientCertFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);

    HttpRequestOptions requestOptions;
    std::string str = GetStringFromData(STR_LEN);
    Secure::SecureChar pwd(str);
    requestOptions.SetClientCert(str, str, str, pwd);
}

void AddMultiFormDataFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    HttpRequestOptions requestOptions;
    MultiFormData multiFormData;
    std::string str = GetStringFromData(STR_LEN);
    multiFormData.name = str;
    multiFormData.data = str;
    multiFormData.contentType = str;
    multiFormData.remoteFileName = str;
    multiFormData.filePath = str;
    requestOptions.AddMultiFormData(multiFormData);
}
} // namespace Http
} // namespace NetStack
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::NetStack::Http::SetCaPathFuzzTest(data, size);
    OHOS::NetStack::Http::SetUrlFuzzTest(data, size);
    OHOS::NetStack::Http::SetMethodFuzzTest(data, size);
    OHOS::NetStack::Http::SetHeaderFuzzTest(data, size);
    OHOS::NetStack::Http::SetReadTimeoutFuzzTest(data, size);
    OHOS::NetStack::Http::SetConnectTimeoutFuzzTest(data, size);
    OHOS::NetStack::Http::SetUsingProtocolFuzzTest(data, size);
    OHOS::NetStack::Http::SetHttpDataTypeFuzzTest(data, size);
    OHOS::NetStack::Http::SetUsingHttpProxyTypeFuzzTest(data, size);
    OHOS::NetStack::Http::SetSpecifiedHttpProxyFuzzTest(data, size);
    OHOS::NetStack::Http::SetDnsServersFuzzTest(data, size);
    OHOS::NetStack::Http::SetDohUrlFuzzTest(data, size);
    OHOS::NetStack::Http::SetRangeNumberFuzzTest(data, size);
    OHOS::NetStack::Http::SetClientCertFuzzTest(data, size);
    OHOS::NetStack::Http::AddMultiFormDataFuzzTest(data, size);
    return 0;
}