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

#include <csignal>
#include <cstring>
#include <functional>
#include <iostream>

#include "net_http.h"
#include "netstack_log.h"
#include "secure_char.h"

namespace OHOS {
namespace NetStack {
namespace HttpClient {
const uint8_t *g_baseFuzzData = nullptr;
size_t g_baseFuzzSize = 0;
size_t g_baseFuzzPos = 0;
constexpr size_t STR_LEN = 255;
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

void CreateRequestTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    std::string url = GetStringFromData(STR_LEN);
    Http_Request *request = OH_Http_CreateRequest(url.c_str());
    if (request == nullptr) {
        return;
    }
    request->requestId = 0;
    OH_Http_Destroy(&request);
}

void CreateHeadersTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    std::string keyStr = GetStringFromData(STR_LEN);
    std::string key1Str = GetStringFromData(STR_LEN);
    std::string valueStr = GetStringFromData(STR_LEN);
    std::string value1Str = GetStringFromData(STR_LEN);
    Http_Headers *headers = OH_Http_CreateHeaders();
    if (headers == nullptr) {
        return;
    }
    OH_Http_SetHeaderValue(headers, keyStr.c_str(), valueStr.c_str());
    OH_Http_SetHeaderValue(headers, key1Str.c_str(), value1Str.c_str());
    OH_Http_DestroyHeaders(&headers);
}

void GetHeaderValueTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    std::string keyStr = GetStringFromData(STR_LEN);
    std::string key1Str = GetStringFromData(STR_LEN);
    std::string valueStr = GetStringFromData(STR_LEN);
    std::string value1Str = GetStringFromData(STR_LEN);
    Http_Headers *headers = OH_Http_CreateHeaders();
    if (headers == nullptr) {
        return;
    }
    OH_Http_SetHeaderValue(headers, keyStr.c_str(), valueStr.c_str());
    OH_Http_SetHeaderValue(headers, key1Str.c_str(), value1Str.c_str());
    OH_Http_GetHeaderValue(headers, keyStr.c_str());
    OH_Http_DestroyHeaders(&headers);
}

void GetHeaderEntriesTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    std::string keyStr = GetStringFromData(STR_LEN);
    std::string key1Str = GetStringFromData(STR_LEN);
    std::string valueStr = GetStringFromData(STR_LEN);
    std::string value1Str = GetStringFromData(STR_LEN);
    Http_Headers *headers = OH_Http_CreateHeaders();
    if (headers == nullptr) {
        return;
    }
    OH_Http_SetHeaderValue(headers, keyStr.c_str(), valueStr.c_str());
    OH_Http_SetHeaderValue(headers, key1Str.c_str(), value1Str.c_str());
    Http_HeaderEntry *entries = OH_Http_GetHeaderEntries(headers);
    OH_Http_DestroyHeaderEntries(&entries);
    OH_Http_DestroyHeaders(&headers);
}

void HttpSampleResponseCallback(Http_Response *response, uint32_t errCode)
{
    if (response == nullptr) {
        return;
    }
    if (errCode != 0) {
        response->destroyResponse(&response);
        return;
    }
    response->destroyResponse(&response);
}

void HttpSampleOnDataReceiveCallback(const char *data, size_t length)
{
    if (data == nullptr || length == 0) {
        return;
    }
    return;
}

void HttpSampleOnUploadProgressCallback(uint64_t totalSize, uint64_t transferredSize)
{
}

void HttpSampleOnDownloadProgressCallback(uint64_t totalSize, uint64_t transferredSize)
{
}

void HttpSampleOnHeaderReceiveCallback(Http_Headers *headers)
{
    if (headers != nullptr) {
        Http_HeaderEntry *entries = OH_Http_GetHeaderEntries(headers);
        Http_HeaderValue *headerValue;
        Http_HeaderEntry *delEntries = entries;
        while (entries != nullptr) {
            headerValue = entries->value;
            while (headerValue != nullptr && entries->key != nullptr) {
                headerValue = headerValue->next;
            }
            entries = entries->next;
        }
        OH_Http_DestroyHeaderEntries(&delEntries);
        OH_Http_DestroyHeaders(&headers);
    }
}

void HttpSampleOnEndCallback()
{
}

void HttpSampleOnCancelCallback()
{
}

void HttpRequestTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    std::string url = GetStringFromData(STR_LEN);
    Http_Request *request = OH_Http_CreateRequest(url.c_str());
    if (request == nullptr) {
        return;
    }
    request->options = (Http_RequestOptions *)calloc(1, sizeof(Http_RequestOptions));
    if (request->options == nullptr) {
        OH_Http_Destroy(&request);
        return;
    }
    Http_Headers *headers = OH_Http_CreateHeaders();
    if (headers == nullptr) {
        free(request->options);
        OH_Http_Destroy(&request);
        return;
    }
    const char *key = "testKey";
    const char *value = "testValue";
    uint32_t ret = OH_Http_SetHeaderValue(headers, key, value);
    if (ret == 0) {
        OH_Http_DestroyHeaders(&headers);
        free(request->options);
        OH_Http_Destroy(&request);
        return;
    }
    request->options->headers = headers;
    Http_EventsHandler eventsHandler;
    eventsHandler.onDataReceive = HttpSampleOnDataReceiveCallback;
    eventsHandler.onCanceled = HttpSampleOnCancelCallback;
    eventsHandler.onDataEnd = HttpSampleOnEndCallback;
    eventsHandler.onDownloadProgress = HttpSampleOnDownloadProgressCallback;
    eventsHandler.onUploadProgress = HttpSampleOnUploadProgressCallback;
    eventsHandler.onHeadersReceive = HttpSampleOnHeaderReceiveCallback;
    ret = OH_Http_Request(request, HttpSampleResponseCallback, eventsHandler);
    if (ret != 0) {
        OH_Http_DestroyHeaders(&headers);
        free(request->options);
        OH_Http_Destroy(&request);
        return;
    }
    OH_Http_DestroyHeaders(&headers);
    free(request->options);
    OH_Http_Destroy(&request);
}

} // namespace HttpClient
} // namespace NetStack
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::NetStack::HttpClient::CreateRequestTest(data, size);
    OHOS::NetStack::HttpClient::CreateHeadersTest(data, size);
    OHOS::NetStack::HttpClient::GetHeaderValueTest(data, size);
    OHOS::NetStack::HttpClient::GetHeaderEntriesTest(data, size);
    OHOS::NetStack::HttpClient::HttpRequestTest(data, size);
    return 0;
}