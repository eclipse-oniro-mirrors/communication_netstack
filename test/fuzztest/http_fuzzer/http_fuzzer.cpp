/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#define private public
#include "http_client.h"
#include "http_client_request.h"
#undef private
#include "http_request_options.h"
#include "netstack_log.h"
#include "secure_char.h"

namespace OHOS {
namespace NetStack {
namespace Http {
namespace {
using namespace OHOS::NetStack::HttpClient;
const uint8_t *g_baseFuzzData = nullptr;
size_t g_baseFuzzSize = 0;
size_t g_baseFuzzPos = 0;
constexpr size_t STR_LEN = 255;
constexpr int32_t TEST_PORT = 8888;
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

HttpClientRequest CreateHttpClientRequest()
{
    HttpClientRequest httpReq;
    std::string url = "https://www.baidu.com";
    httpReq.SetURL(url);
    return httpReq;
}

HttpClientRequest CreateHttpClientRequest(const uint8_t *data, size_t size)
{
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    HttpClientRequest httpReq;
    std::string str = GetStringFromData(STR_LEN);
    httpReq.SetURL(str);
    return httpReq;
}

void HttpSessionCreateTaskFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    HttpClientRequest httpReq = CreateHttpClientRequest();
    auto testTask = HttpSession::GetInstance().CreateTask(httpReq);
    testTask->Start();

    httpReq = CreateHttpClientRequest(data, size);
    testTask = HttpSession::GetInstance().CreateTask(httpReq);
    testTask->Start();
}

void HttpClientTaskGetHttpVersionFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }

    HttpClientRequest httpReq = CreateHttpClientRequest();
    auto task = HttpSession::GetInstance().CreateTask(httpReq);
    HttpClient::HttpProtocol ptcl = HttpClient::HttpProtocol::HTTP1_1;
    HttpClientRequest request;
    request.SetHttpProtocol(ptcl);
    uint32_t timeout = GetData<uint32_t>();
    request.SetTimeout(timeout);
    std::string testData = GetStringFromData(STR_LEN);
    std::string result = request.GetBody();
    request.body_ = "";
    request.SetCaPath(testData);
    uint32_t priority = GetData<uint32_t>();
    request.SetPriority(priority);
    result = request.GetURL();
    result = request.GetMethod();
    uint32_t ret = request.GetTimeout();
    ret = request.GetConnectTimeout();
    ptcl = request.GetHttpProtocol();
    HttpClient::HttpProxyType proType = request.GetHttpProxyType();
    NETSTACK_LOGD("ptcl = %{private}d, proType = %{private}d", ptcl, proType);
    result = request.GetCaPath();
    ret = request.GetPriority();
    HttpProxy proxy = request.GetHttpProxy();
    request.SetRequestTime(testData);
    result = request.GetRequestTime();
    task->GetHttpVersion(ptcl);
}

void HttpClientTaskSetHttpProtocolFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }

    HttpClientRequest httpReq = CreateHttpClientRequest(data, size);
    auto task = HttpSession::GetInstance().CreateTask(httpReq);
    HttpClientRequest request;
    HttpClient::HttpProtocol ptcl = HttpClient::HttpProtocol::HTTP1_1;
    request.SetHttpProtocol(ptcl);
    HttpProxy proxy = request.GetHttpProxy();
    std::string testData = GetStringFromData(STR_LEN);
    request.SetCaPath(testData);
    request.SetRequestTime(testData);
    std::string result = request.GetRequestTime();
    result = request.GetBody();
    request.body_ = "";
    task->GetHttpVersion(ptcl);
    result = request.GetURL();
    result = request.GetMethod();
    result = request.GetCaPath();
    uint32_t timeout = GetData<uint32_t>();
    request.SetTimeout(timeout);
    uint32_t prio = GetData<uint32_t>();
    request.SetPriority(prio);
    uint32_t ret = request.GetTimeout();
    ret = request.GetConnectTimeout();
    ret = request.GetPriority();
    ptcl = request.GetHttpProtocol();
    HttpClient::HttpProxyType proType = request.GetHttpProxyType();
    NETSTACK_LOGD("ptcl = %{private}d, proType = %{private}d", ptcl, proType);
}

void HttpClientTaskSetOtherCurlOptionFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }

    HttpClientRequest request;
    std::string url = "http://www.httpbin.org/get";
    request.SetURL(url);
    request.SetHttpProxyType(NOT_USE);
    HttpProxy testProxy;
    testProxy.host = "192.168.147.60";
    testProxy.exclusions = "www.httpbin.org";
    testProxy.port = TEST_PORT;
    testProxy.tunnel = false;
    request.SetHttpProxy(testProxy);
    auto task = HttpSession::GetInstance().CreateTask(request);
    task->SetOtherCurlOption(task->curlHandle_);

    request = CreateHttpClientRequest(data, size);
    task = HttpSession::GetInstance().CreateTask(request);
    task->SetOtherCurlOption(task->curlHandle_);
}

void HttpClientTaskSetCurlOptionsFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }

    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/get";
    httpReq.SetURL(url);
    auto task = HttpSession::GetInstance().CreateTask(httpReq);
    task->request_.SetMethod(HttpConstant::HTTP_METHOD_HEAD);
    task->SetCurlOptions();

    httpReq = CreateHttpClientRequest(data, size);
    task = HttpSession::GetInstance().CreateTask(httpReq);
    task->request_.SetMethod(HttpConstant::HTTP_METHOD_HEAD);
    task->SetCurlOptions();
}

void HttpClientTaskGetTypeFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }

    HttpClientRequest httpReq = CreateHttpClientRequest();
    auto task = HttpSession::GetInstance().CreateTask(httpReq);
    TaskType type = task->GetType();
    std::string result = task->GetFilePath();
    int taskId = task->GetTaskId();
    TaskStatus status = static_cast<TaskStatus>(size % 2);
    task->SetStatus(status);
    status = task->GetStatus();
    NETSTACK_LOGD("type = %{private}d, result = %{private}s, taskId = %{private}d, status = %{private}d", type,
        result.c_str(), taskId, status);
    task->OnSuccess([task](const HttpClientRequest &request, const HttpClientResponse &response) {});
    task->OnCancel([](const HttpClientRequest &request, const HttpClientResponse &response) {});
    task->OnFail(
        [](const HttpClientRequest &request, const HttpClientResponse &response, const HttpClientError &error) {});
    task->OnDataReceive([](const HttpClientRequest &request, const uint8_t *data, size_t length) {});
    task->OnProgress(
        [](const HttpClientRequest &request, u_long dltotal, u_long dlnow, u_long ultotal, u_long ulnow) {});
    task->OnDataReceive([](const HttpClientRequest &request, const uint8_t *data, size_t length) {});
    httpReq = CreateHttpClientRequest(data, size);
    task = HttpSession::GetInstance().CreateTask(httpReq);
    type = task->GetType();
    result = task->GetFilePath();
    taskId = task->GetTaskId();
    status = task->GetStatus();
    task->SetStatus(status);
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
    OHOS::NetStack::Http::HttpSessionCreateTaskFuzzTest(data, size);
    OHOS::NetStack::Http::HttpClientTaskGetHttpVersionFuzzTest(data, size);
    OHOS::NetStack::Http::HttpClientTaskSetHttpProtocolFuzzTest(data, size);
    OHOS::NetStack::Http::HttpClientTaskSetOtherCurlOptionFuzzTest(data, size);
    OHOS::NetStack::Http::HttpClientTaskSetCurlOptionsFuzzTest(data, size);
    OHOS::NetStack::Http::HttpClientTaskGetTypeFuzzTest(data, size);
    return 0;
}