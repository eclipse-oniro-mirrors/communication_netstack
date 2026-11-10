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

#include <iostream>
#include <cstring>
#include <string>
#include <thread>
#include <vector>
#include <poll.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "openssl/ssl.h"
#include "openssl/pem.h"
#include "openssl/rsa.h"
#include "openssl/evp.h"
#include "openssl/x509v3.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "http_client_constant.h"
#include "netstack_log.h"
#include "netstack_common_utils.h"
#include "cJSON.h"

#define private public
#include "http_client_task.h"
#include "http_client.h"
#include "http_client_error.h"
#include <curl/curl.h>
#include "http_client_request.h"
#include "http_client_response.h"
#if HAS_NETMANAGER_BASE
#include "net_conn_client.h"
#include "network_security_config.h"
#endif
#ifdef HTTP_HANDOVER_FEATURE
#include "http_handover_info.h"
#endif
#if ENABLE_HTTP_GLOBAL_INTERCEPT
#include "http_interceptor_mgr.h"
#endif

using namespace OHOS::NetStack::HttpClient;
using namespace OHOS::NetStack::HttpInterceptor;
using namespace testing;
using namespace testing::ext;

class HttpClientTaskTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}

    void ProcesslTaskCb(std::shared_ptr<HttpClientTask> task);
};

namespace {
using namespace std;
using namespace testing::ext;

static void testCallbackconst(const HttpClientRequest &request, std::map<std::string,
    std::string> headerWithSetCookie)
{
    NETSTACK_LOGI("testCallbackconst function called!");
}

static OH_Interceptor_Result g_Interceptor_Result = OH_CONTINUE;
static bool g_IsModified = false;

OH_Interceptor_Result OH_Http_InterceptorHandler(
    OH_Http_Interceptor_Request *request, OH_Http_Interceptor_Response *response, int32_t *isModified)
{
    (void)request;
    (void)response;
    *isModified = g_IsModified ? 1 : 0;
    return g_Interceptor_Result;
}

OH_Http_Interceptor g_request_interceptor = {
    .groupId = 0,
    .stage = OH_STAGE_REQUEST,
    .type = OH_TYPE_MODIFY_NETWORK_KIT,
    .enabled = 1,
    .handler = OH_Http_InterceptorHandler,
};

OH_Http_Interceptor g_response_interceptor = {
    .groupId = 0,
    .stage = OH_STAGE_RESPONSE,
    .type = OH_TYPE_MODIFY_NETWORK_KIT,
    .enabled = 1,
    .handler = OH_Http_InterceptorHandler,
};

HWTEST_F(HttpClientTaskTest, GetHttpVersionTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "https://www.baidu.com";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    uint32_t httpVersionTest = task->GetHttpVersion(HttpProtocol::HTTP_NONE);
    EXPECT_EQ(httpVersionTest, CURL_HTTP_VERSION_NONE);
}

HWTEST_F(HttpClientTaskTest, GetHttpVersionTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "https://www.baidu.com";
    httpReq.SetURL(url);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    uint32_t httpVersionTest = task->GetHttpVersion(HttpProtocol::HTTP1_1);
    EXPECT_EQ(httpVersionTest, CURL_HTTP_VERSION_1_1);
}

HWTEST_F(HttpClientTaskTest, GetHttpVersionTest003, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "https://www.baidu.com";
    httpReq.SetURL(url);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    uint32_t httpVersionTest = task->GetHttpVersion(HttpProtocol::HTTP2);
    EXPECT_EQ(httpVersionTest, CURL_HTTP_VERSION_2_0);
    httpVersionTest = task->GetHttpVersion(HttpProtocol::HTTP3);
    EXPECT_EQ(httpVersionTest, CURL_HTTP_VERSION_3);
}

HWTEST_F(HttpClientTaskTest, SetOtherCurlOptionTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;

    std::string url = "http://www.httpbin.org/get";
    httpReq.SetURL(url);
    httpReq.SetHttpProxyType(NOT_USE);
    HttpProxy proxy;
    proxy.host = "192.168.147.60";
    proxy.port = 8888;
    proxy.exclusions = "www.httpbin.org";
    proxy.tunnel = false;
    httpReq.SetHttpProxy(proxy);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    bool result = task->SetOtherCurlOption(task->curlHandle_);
    EXPECT_TRUE(result);
}

HWTEST_F(HttpClientTaskTest, SetOtherCurlOptionTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;

    std::string url = "http://www.httpbin.org/get";
    httpReq.SetURL(url);
    httpReq.SetHttpProxyType(NOT_USE);
    HttpProxy proxy;
    proxy.host = "192.168.147.60";
    proxy.port = 8888;
    proxy.tunnel = false;
    httpReq.SetHttpProxy(proxy);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    EXPECT_TRUE(task->SetOtherCurlOption(task->curlHandle_));
}

HWTEST_F(HttpClientTaskTest, SetOtherCurlOptionTest003, TestSize.Level1)
{
    HttpClientRequest httpReq;

    std::string url = "http://www.httpbin.org/get";
    httpReq.SetURL(url);
    httpReq.SetHttpProxyType(NOT_USE);
    HttpProxy proxy;
    proxy.host = "192.168.147.60";
    proxy.port = 8888;
    proxy.tunnel = false;
    httpReq.SetHttpProxy(proxy);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    EXPECT_TRUE(task->SetOtherCurlOption(task->curlHandle_));
}

HWTEST_F(HttpClientTaskTest, SetOtherCurlOptionTest004, TestSize.Level1)
{
    HttpClientRequest httpReq;

    std::string url = "http://www.httpbin.org/get";
    httpReq.SetURL(url);
    httpReq.SetHttpProxyType(NOT_USE);
    HttpProxy proxy;
    proxy.host = "192.168.147.60";
    proxy.port = 8888;
    proxy.exclusions = "www.httpbin.org";
    proxy.tunnel = true;
    httpReq.SetHttpProxy(proxy);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    EXPECT_TRUE(task->SetOtherCurlOption(task->curlHandle_));
    curl_easy_cleanup(task->curlHandle_);
    task->curlHandle_ = nullptr;
}

HWTEST_F(HttpClientTaskTest, SetOtherCurlOptionTest005, TestSize.Level1)
{
    HttpClientRequest httpReq;

    std::string url = "http://www.httpbin.org/get";
    httpReq.SetURL(url);
    httpReq.SetHttpProxyType(USE_SPECIFIED);
    HttpProxy proxy;
    proxy.host = "192.168.147.60";
    proxy.port = 8888;
    proxy.exclusions = "www.test.org";
    proxy.tunnel = true;
    httpReq.SetHttpProxy(proxy);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    EXPECT_TRUE(task->SetOtherCurlOption(task->curlHandle_));
    curl_easy_cleanup(task->curlHandle_);
    task->curlHandle_ = nullptr;
}

HWTEST_F(HttpClientTaskTest, SetUploadOptionsTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/put";
    httpReq.SetURL(url);
    std::string method = "PUT";
    httpReq.SetMethod(method);

    HttpSession &session = HttpSession::GetInstance();
    std::string filePath = "/bin/who";
    auto task = session.CreateTask(httpReq, UPLOAD, filePath);

    EXPECT_TRUE(task->SetUploadOptions(task->curlHandle_));
}

HWTEST_F(HttpClientTaskTest, SetUploadOptionsTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/put";
    httpReq.SetURL(url);
    std::string method = "PUT";
    httpReq.SetMethod(method);

    HttpSession &session = HttpSession::GetInstance();
    std::string filePath = "";
    auto task = session.CreateTask(httpReq, UPLOAD, filePath);

    EXPECT_FALSE(task->SetUploadOptions(task->curlHandle_));
}

HWTEST_F(HttpClientTaskTest, SetUploadOptionsTest003, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/put";
    httpReq.SetURL(url);
    std::string method = "PUT";
    httpReq.SetMethod(method);

    HttpSession &session = HttpSession::GetInstance();
    std::string filePath = "unavailable";
    auto task = session.CreateTask(httpReq, UPLOAD, filePath);

    EXPECT_FALSE(task->SetUploadOptions(task->curlHandle_));
}

HWTEST_F(HttpClientTaskTest, SetCurlOptionsTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/get";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    EXPECT_TRUE(task->SetCurlOptions());
}

HWTEST_F(HttpClientTaskTest, SetCurlOptionsTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/get";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    task->request_.SetMethod(HttpConstant::HTTP_METHOD_HEAD);

    EXPECT_TRUE(task->SetCurlOptions());
}

HWTEST_F(HttpClientTaskTest, SetCurlOptionsTest003, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/put";
    httpReq.SetURL(url);
    std::string method = "PUT";
    httpReq.SetMethod(method);

    HttpSession &session = HttpSession::GetInstance();
    std::string filePath = "/bin/who";
    auto task = session.CreateTask(httpReq, UPLOAD, filePath);

    task->curlHandle_ = nullptr;
    EXPECT_FALSE(task->SetCurlOptions());
}

HWTEST_F(HttpClientTaskTest, SetCurlOptionsTest004, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/get";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    task->request_.SetMethod(HttpConstant::HTTP_METHOD_POST);

    EXPECT_TRUE(task->SetCurlOptions());
}

HWTEST_F(HttpClientTaskTest, SetCurlOptionsTest005, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/get";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    task->curlHandle_ = nullptr;

    EXPECT_FALSE(task->SetCurlOptions());
}

HWTEST_F(HttpClientTaskTest, SetCurlOptionsTest006, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/get";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    task->curlHandle_ = nullptr;
    task->curlHeaderList_ = nullptr;
    std::string headerStr = "Connection:keep-alive";
    task->curlHeaderList_ = curl_slist_append(task->curlHeaderList_, headerStr.c_str());

    EXPECT_FALSE(task->SetCurlOptions());
}

HWTEST_F(HttpClientTaskTest, SetCurlOptionsTest007, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/get";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    task->request_.SetMethod(HttpConstant::HTTP_METHOD_PUT);
    task->request_.SetResumeFrom(1000);

    EXPECT_FALSE(task->SetCurlOptions());
}

HWTEST_F(HttpClientTaskTest, SetCurlOptionsTest008, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/get";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    task->request_.SetMethod(HttpConstant::HTTP_METHOD_GET);
    task->request_.SetResumeFrom(1000);

    EXPECT_TRUE(task->SetCurlOptions());
}

HWTEST_F(HttpClientTaskTest, SetCurlOptionsTest009, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/get";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    task->request_.SetResumeFrom(1000);
    task->request_.SetResumeTo(100);

    EXPECT_TRUE(task->SetCurlOptions());
}

HWTEST_F(HttpClientTaskTest, GetType001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "https://www.baidu.com";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    EXPECT_EQ(TaskType::DEFAULT, task->GetType());
}

HWTEST_F(HttpClientTaskTest, GetFilePathTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/put";
    httpReq.SetURL(url);
    std::string method = "PUT";
    httpReq.SetMethod(method);

    HttpSession &session = HttpSession::GetInstance();
    std::string filePath = "/bin/who";
    auto task = session.CreateTask(httpReq, UPLOAD, filePath);

    EXPECT_EQ(task->GetFilePath(), "/bin/who");
}
HWTEST_F(HttpClientTaskTest, GetTaskIdTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/get";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    unsigned int taskId = task->GetTaskId();
    EXPECT_TRUE(taskId >= 0);
}

HWTEST_F(HttpClientTaskTest, OnSuccessTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/delete";
    std::string method = "DELETE";
    httpReq.SetURL(url);
    httpReq.SetMethod(method);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    task->OnSuccess([task](const HttpClientRequest &request, const HttpClientResponse &response) {});
    task->Start();

    char *curlMethod = nullptr;
    while (task->GetCurlHandle() == nullptr) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    curl_easy_getinfo(task->GetCurlHandle(), CURLINFO_EFFECTIVE_METHOD, &curlMethod);

    while (task->GetStatus() != TaskStatus::IDLE) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    if (task->GetResponse().GetResponseCode() == 200) {
        if (curlMethod == method) {
            NETSTACK_LOGI("TestMethod() = %{public}s OK!", curlMethod);
        }
        const std::map<std::string, std::string> &headers = task->GetResponse().GetHeaders();
        for (const auto &entry : headers) {
            NETSTACK_LOGI("TestMethod() HEAD = %{public}s : %{public}s", entry.first.c_str(),  entry.second.c_str());
        }
    } else if (task->GetResponse().GetResponseCode() == 405) {
        NETSTACK_LOGI("TestMethod() %{public}s don't support, response 405", curlMethod);
    } else {
        NETSTACK_LOGI("TestMethod() = failed %{public}s", curlMethod);
    }

    EXPECT_TRUE(task->onSucceeded_ != nullptr);
}

HWTEST_F(HttpClientTaskTest, OnSuccessTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/get";
    std::string method = "GET";
    httpReq.SetURL(url);
    httpReq.SetMethod(method);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    task->OnSuccess([task](const HttpClientRequest &request, const HttpClientResponse &response) {});
    task->Start();

    char *curlMethod = nullptr;
    while (task->GetCurlHandle() == nullptr) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    curl_easy_getinfo(task->GetCurlHandle(), CURLINFO_EFFECTIVE_METHOD, &curlMethod);

    while (task->GetStatus() != TaskStatus::IDLE) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    if (task->GetResponse().GetResponseCode() == 200) {
        if (curlMethod == method) {
            NETSTACK_LOGI("TestMethod() = %{public}s OK!", curlMethod);
        }
        const std::map<std::string, std::string> &headers = task->GetResponse().GetHeaders();
        for (const auto &entry : headers) {
            NETSTACK_LOGI("TestMethod() HEAD = %{public}s : %{public}s", entry.first.c_str(),  entry.second.c_str());
        }
    } else if (task->GetResponse().GetResponseCode() == 405) {
        NETSTACK_LOGI("TestMethod() %{public}s don't support, response 405", curlMethod);
    } else {
        NETSTACK_LOGI("TestMethod() = failed %{public}s", curlMethod);
    }

    EXPECT_TRUE(task->onSucceeded_ != nullptr);
}

HWTEST_F(HttpClientTaskTest, OnSuccessTest003, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/post";
    std::string method = "POST";
    httpReq.SetURL(url);
    httpReq.SetMethod(method);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    task->OnSuccess([task](const HttpClientRequest &request, const HttpClientResponse &response) {});
    task->Start();

    char *curlMethod = nullptr;
    while (task->GetCurlHandle() == nullptr) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    curl_easy_getinfo(task->GetCurlHandle(), CURLINFO_EFFECTIVE_METHOD, &curlMethod);

    while (task->GetStatus() != TaskStatus::IDLE) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    if (task->GetResponse().GetResponseCode() == 200) {
        if (curlMethod == method) {
            NETSTACK_LOGI("TestMethod() = %{public}s OK!", curlMethod);
        }
        const std::map<std::string, std::string> &headers = task->GetResponse().GetHeaders();
        for (const auto &entry : headers) {
            NETSTACK_LOGI("TestMethod() HEAD = %{public}s : %{public}s", entry.first.c_str(),  entry.second.c_str());
        }
    } else if (task->GetResponse().GetResponseCode() == 405) {
        NETSTACK_LOGI("TestMethod() %{public}s don't support, response 405", curlMethod);
    } else {
        NETSTACK_LOGI("TestMethod() = failed %{public}s", curlMethod);
    }

    EXPECT_TRUE(task->onSucceeded_ != nullptr);
}

HWTEST_F(HttpClientTaskTest, OnSuccessTest004, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/put";
    std::string method = "PUT";
    httpReq.SetURL(url);
    httpReq.SetMethod(method);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    task->OnSuccess([task](const HttpClientRequest &request, const HttpClientResponse &response) {});
    task->Start();

    char *curlMethod = nullptr;
    while (task->GetCurlHandle() == nullptr) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    curl_easy_getinfo(task->GetCurlHandle(), CURLINFO_EFFECTIVE_METHOD, &curlMethod);

    while (task->GetStatus() != TaskStatus::IDLE) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    if (task->GetResponse().GetResponseCode() == 200) {
        if (curlMethod == method) {
            NETSTACK_LOGI("TestMethod() = %{public}s OK!", curlMethod);
        }
        const std::map<std::string, std::string> &headers = task->GetResponse().GetHeaders();
        for (const auto &entry : headers) {
            NETSTACK_LOGI("TestMethod() HEAD = %{public}s : %{public}s", entry.first.c_str(),  entry.second.c_str());
        }
    } else if (task->GetResponse().GetResponseCode() == 405) {
        NETSTACK_LOGI("TestMethod() %{public}s don't support, response 405", curlMethod);
    } else {
        NETSTACK_LOGI("TestMethod() = failed %{public}s", curlMethod);
    }

    EXPECT_TRUE(task->onSucceeded_ != nullptr);
}

HWTEST_F(HttpClientTaskTest, OnCancelTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/get";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    task->OnCancel([](const HttpClientRequest &request, const HttpClientResponse &response) {});

    EXPECT_TRUE(task->onCanceled_ != nullptr);
}

HWTEST_F(HttpClientTaskTest, OnFailTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/get";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    task->OnFail(
        [](const HttpClientRequest &request, const HttpClientResponse &response, const HttpClientError &error) {});

    EXPECT_TRUE(task->onFailed_ != nullptr);
}

HWTEST_F(HttpClientTaskTest, OnDataReceiveTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/get";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    task->OnDataReceive([](const HttpClientRequest &request, const uint8_t *data, size_t length) {});

    EXPECT_TRUE(task->onDataReceive_ != nullptr);
}

HWTEST_F(HttpClientTaskTest, OnProgressTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/get";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    task->OnProgress(
        [](const HttpClientRequest &request, u_long dltotal, u_long dlnow, u_long ultotal, u_long ulnow) {});

    EXPECT_TRUE(task->onProgress_ != nullptr);
}

HWTEST_F(HttpClientTaskTest, DataReceiveCallbackTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "https://www.baidu.com";
    const char *data = "https://www.baidu.com";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    auto *userData = task.get();
    size_t size = 10;
    size_t memBytes = 1;

    task->OnDataReceive([](const HttpClientRequest &request, const uint8_t *data, size_t length) {});
    size_t result = task->DataReceiveCallback(data, size, memBytes, userData);

    EXPECT_EQ(result, size * memBytes);
}

HWTEST_F(HttpClientTaskTest, DataReceiveCallbackTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "https://www.baidu.com";
    const char *data = "https://www.baidu.com";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    auto *userData = task.get();
    size_t size = 10;
    size_t memBytes = 1;
    size_t result = task->DataReceiveCallback(data, size, memBytes, userData);

    EXPECT_EQ(result, size * memBytes);
}

HWTEST_F(HttpClientTaskTest, DataReceiveCallbackTest003, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/get";
    const char *data = "http://www.httpbin.org/get";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    auto *userData = task.get();
    size_t size = 10;
    size_t memBytes = 1;
    task->canceled_ = true;
    size_t result = task->DataReceiveCallback(data, size, memBytes, userData);

    EXPECT_EQ(result, 0);
    task->canceled_ = false;
}

HWTEST_F(HttpClientTaskTest, DataReceiveCallbackTest004, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/get";
    const char *data = "http://www.httpbin.org/get";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    auto *userData = task.get();
    size_t size = 10;
    size_t memBytes = 1;
    size_t result = task->DataReceiveCallback(data, size, memBytes, userData);

    EXPECT_EQ(result, size * memBytes);
}

HWTEST_F(HttpClientTaskTest, DataReceiveCallbackTest005, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/get";
    const char *data = "http://www.httpbin.org/get";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    auto *userData = task.get();
    size_t size = 10;
    size_t memBytes = 1;
    size_t result = task->DataReceiveCallback(data, size, memBytes, userData);

    EXPECT_EQ(result, size * memBytes);
}

HWTEST_F(HttpClientTaskTest, DataReceiveCallbackTest006, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/get";
    const char *data = "http://www.httpbin.org/get";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    HttpClientResponse resp;
    resp.result_ = "result1";
    task->SetResponse(resp);

    auto *userData = task.get();
    size_t size = 1;
    size_t memBytes = 1;
    size_t result = task->DataReceiveCallback(data, size, memBytes, userData);

    EXPECT_EQ(result, size * memBytes);
}

HWTEST_F(HttpClientTaskTest, ProgressCallbackTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "https://www.baidu.com";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    auto *userData = task.get();
    curl_off_t dltotal = 100;
    curl_off_t dlnow = 50;
    curl_off_t ultotal = 200;
    curl_off_t ulnow = 100;
    int result;

    result = task->ProgressCallback(userData, dltotal, dlnow, ultotal, ulnow);
    EXPECT_EQ(result, 0);
}

HWTEST_F(HttpClientTaskTest, ProgressCallbackTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "https://www.baidu.com";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    auto *userData = task.get();
    curl_off_t dltotal = 100;
    curl_off_t dlnow = 50;
    curl_off_t ultotal = 200;
    curl_off_t ulnow = 100;
    int result;

    task->Cancel();
    result = task->ProgressCallback(userData, dltotal, dlnow, ultotal, ulnow);
    EXPECT_EQ(result, CURLE_ABORTED_BY_CALLBACK);
}

HWTEST_F(HttpClientTaskTest, ProgressCallbackTest003, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "https://www.baidu.com";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    auto *userData = task.get();
    curl_off_t dltotal = 100;
    curl_off_t dlnow = 50;
    curl_off_t ultotal = 200;
    curl_off_t ulnow = 100;

    int result = task->ProgressCallback(userData, dltotal, dlnow, ultotal, ulnow);
    EXPECT_EQ(result, 0);
}

HWTEST_F(HttpClientTaskTest, HeaderReceiveCallbackTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "https://www.baidu.com";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    auto *userData = task.get();
    const char *data = "Test Header";
    size_t size = 5;
    size_t memBytes = 2;
    size_t result = task->HeaderReceiveCallback(data, size, memBytes, userData);
    EXPECT_EQ(result, size * memBytes);
}

HWTEST_F(HttpClientTaskTest, HeaderReceiveCallbackTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "https://www.baidu.com";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    auto *userData = task.get();

    const char *data = "Test Header";
    size_t size = HttpConstant::MAX_DATA_LIMIT + 1;
    size_t memBytes = 1;
    size_t result = task->HeaderReceiveCallback(data, size, memBytes, userData);
    EXPECT_EQ(result, 0);
}

HWTEST_F(HttpClientTaskTest, HeaderReceiveCallbackTest003, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/get";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    auto *userData = task.get();

    const char *data = "Test Header";
    size_t size = 5;
    size_t memBytes = 2;
    size_t result = task->HeaderReceiveCallback(data, size, memBytes, userData);
    EXPECT_EQ(result, size * memBytes);
}

HWTEST_F(HttpClientTaskTest, HeaderReceiveCallbackTest004, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/get";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    task->canceled_  = true;

    HttpClientResponse resp;
    const char *realHead = "test:data\r\n\r\n";
    resp.AppendHeader(realHead, strlen(realHead));
    task->SetResponse(resp);
    
    auto *userData = task.get();
    const char *data = "Test Header";
    size_t size = 5;
    size_t memBytes = 2;
    size_t result = task->HeaderReceiveCallback(data, size, memBytes, userData);
    EXPECT_TRUE(resp.headers_.empty());
    EXPECT_EQ(result, 0);
}

HWTEST_F(HttpClientTaskTest, HeaderReceiveCallbackTest005, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/get";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    task->onHeadersReceive_ = testCallbackconst;

    HttpClientResponse resp;
    const char *errorHead = "test:data\r\n";
    resp.AppendHeader(errorHead, strlen(errorHead));
    task->SetResponse(resp);
    
    auto *userData = task.get();
    const char *data = "Test Header";
    size_t size = 5;
    size_t memBytes = 2;
    size_t result = task->HeaderReceiveCallback(data, size, memBytes, userData);
    EXPECT_TRUE(resp.headers_.empty());
    EXPECT_EQ(result, size * memBytes);
}

HWTEST_F(HttpClientTaskTest, HeaderReceiveCallbackTest006, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/get";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    HttpClientResponse resp;
    const char *realHead = "test:data\r\n\r\n";
    resp.AppendHeader(realHead, strlen(realHead));
    task->SetResponse(resp);
    
    auto *userData = task.get();
    const char *data = "Test Header";
    size_t size = 5;
    size_t memBytes = 2;
    size_t result = task->HeaderReceiveCallback(data, size, memBytes, userData);
    EXPECT_TRUE(resp.headers_.empty());
    EXPECT_EQ(result, size * memBytes);
}

HWTEST_F(HttpClientTaskTest, ProcessResponseCodeTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "https://www.baidu.com";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    task->Start();

    while (task->GetStatus() != TaskStatus::IDLE) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    EXPECT_TRUE(task->ProcessResponseCode());
}

HWTEST_F(HttpClientTaskTest, ProcessResponseTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "https://www.baidu.com";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    CURLMsg msg;
    msg.data.result = CURLE_ABORTED_BY_CALLBACK;
    task->OnCancel([](const HttpClientRequest &request, const HttpClientResponse &response) {});
    task->ProcessResponse(&msg);
    EXPECT_TRUE(task->onCanceled_);

    AddressFamily famliy = task->ConvertSaFamily(AF_INET6);
    EXPECT_EQ(famliy, AddressFamily::FAMILY_IPV6);

    msg.data.result = CURLE_FAILED_INIT;
    task->OnFail(
        [](const HttpClientRequest &request, const HttpClientResponse &response, const HttpClientError &error) {});
    task->ProcessResponse(&msg);
    EXPECT_TRUE(task->onFailed_);

    msg.data.result = CURLE_OK;
    task->response_.SetResponseCode(ResponseCode::NOT_MODIFIED);
    task->OnSuccess([task](const HttpClientRequest &request, const HttpClientResponse &response) {});
    task->ProcessResponse(&msg);
    EXPECT_TRUE(task->onSucceeded_);

    task->curlHandle_ = nullptr;
    task->OnFail(
        [](const HttpClientRequest &request, const HttpClientResponse &response, const HttpClientError &error) {});
    task->ProcessResponse(&msg);
    EXPECT_TRUE(task->onFailed_);
}

HWTEST_F(HttpClientTaskTest, SetResponseTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "https://www.baidu.com";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    HttpClientResponse resp;
    resp.result_ = "result1";
    task->SetResponse(resp);

    EXPECT_EQ(task->response_.result_, "result1");
}

HWTEST_F(HttpClientTaskTest, GetHttpProxyInfoTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;

    std::string url = "http://www.httpbin.org/get";
    httpReq.SetURL(url);
    httpReq.SetHttpProxyType(USE_SPECIFIED);
    HttpProxy proxy;
    proxy.host = "192.168.147.60";
    proxy.port = 8888;
    proxy.exclusions = "www.httpbin.org";
    proxy.tunnel = false;
    httpReq.SetHttpProxy(proxy);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    std::string host;
    std::string exclusions;
    int32_t port = 0;
    bool tunnel = false;
    task->GetHttpProxyInfo(host, port, exclusions, tunnel);

    EXPECT_EQ(host, "192.168.147.60");
    EXPECT_EQ(port, 8888);
    EXPECT_EQ(exclusions, "www.httpbin.org");
    EXPECT_FALSE(tunnel);
}

HWTEST_F(HttpClientTaskTest, GetHttpProxyInfoTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;

    std::string url = "http://www.httpbin.org/get";
    httpReq.SetURL(url);
    httpReq.SetHttpProxyType(NOT_USE);
    HttpProxy proxy;
    proxy.host = "192.168.147.60";
    proxy.port = 8888;
    proxy.exclusions = "www.httpbin.org";
    proxy.tunnel = false;
    httpReq.SetHttpProxy(proxy);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    std::string host;
    std::string exclusions;
    int32_t port = 0;
    bool tunnel = false;
    task->GetHttpProxyInfo(host, port, exclusions, tunnel);

#if HAS_NETMANAGER_BASE
    OHOS::NetManagerStandard::HttpProxy defaultProxy;
    OHOS::NetManagerStandard::NetConnClient::GetInstance().GetDefaultHttpProxy(defaultProxy);
    EXPECT_EQ(host, defaultProxy.GetHost());
    EXPECT_EQ(port, static_cast<int32_t>(defaultProxy.GetPort()));
    EXPECT_EQ(exclusions, OHOS::NetStack::CommonUtils::ToString(defaultProxy.GetExclusionList()));
#else
    EXPECT_TRUE(host.empty());
    EXPECT_EQ(port, 0);
    EXPECT_TRUE(exclusions.empty());
#endif
    EXPECT_FALSE(tunnel);
}

HWTEST_F(HttpClientTaskTest, GetHttpProxyInfoTest003, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("https://www.httpbin.org/get");
    httpReq.SetHttpProxyType(USE_SPECIFIED);
    HttpProxy proxy;
    proxy.host = "192.168.147.60";
    proxy.port = 8888;
    proxy.exclusions = "www.test.org";
    proxy.tunnel = true;
    httpReq.SetHttpProxy(proxy);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    std::string host;
    std::string exclusions;
    int32_t port = 0;
    bool tunnel = false;
    task->GetHttpProxyInfo(host, port, exclusions, tunnel);

    EXPECT_EQ(host, proxy.host);
    EXPECT_EQ(port, proxy.port);
    EXPECT_EQ(exclusions, proxy.exclusions);
    EXPECT_TRUE(tunnel);
}

HWTEST_F(HttpClientTaskTest, GetHttpProxyInfoWithAuthTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    httpReq.SetHttpProxyType(USE_SPECIFIED);
    HttpProxy proxy;
    proxy.host = "192.168.147.60";
    proxy.port = 8888;
    proxy.exclusions = "www.test.org";
    proxy.username.assign("user");
    proxy.password.assign("pass");
    httpReq.SetHttpProxy(proxy);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    std::string host;
    std::string exclusions;
    SecureData username;
    SecureData password;
    int32_t port = 0;
    task->GetHttpProxyInfo(host, port, exclusions, username, password);

    EXPECT_EQ(host, proxy.host);
    EXPECT_EQ(port, proxy.port);
    EXPECT_EQ(exclusions, proxy.exclusions);
    EXPECT_EQ(username, proxy.username);
    EXPECT_EQ(password, proxy.password);
}

HWTEST_F(HttpClientTaskTest, GetHttpProxyInfoWithAuthTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    httpReq.SetHttpProxyType(NOT_USE);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    std::string host;
    std::string exclusions;
    SecureData username;
    SecureData password;
    int32_t port = 0;
    task->GetHttpProxyInfo(host, port, exclusions, username, password);

    std::string tunnelHost;
    std::string tunnelExclusions;
    int32_t tunnelPort = 0;
    bool tunnel = false;
    task->GetHttpProxyInfo(tunnelHost, tunnelPort, tunnelExclusions, tunnel);
    EXPECT_EQ(tunnelHost, host);
    EXPECT_EQ(tunnelPort, port);
    EXPECT_EQ(tunnelExclusions, exclusions);
}

HWTEST_F(HttpClientTaskTest, GetHttpProxyInfoWithAuthTest003, TestSize.Level2)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    httpReq.SetHttpProxyType(PROXY_TYPE_MAX);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    std::string host;
    std::string exclusions;
    SecureData username;
    SecureData password;
    int32_t port = -1;
    // PROXY_TYPE_MAX queries the system default proxy, the branch must not crash
    // even if no proxy is configured in the test environment.
    task->GetHttpProxyInfo(host, port, exclusions, username, password);
    EXPECT_GE(port, 0);
}

HWTEST_F(HttpClientTaskTest, GetHttpProxyInfoWithAuthTest004, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    httpReq.SetHttpProxyType(USE_SPECIFIED);
    HttpProxy proxy;
    proxy.host = "192.168.147.60";
    proxy.port = 8888;
    proxy.exclusions = "";
    proxy.tunnel = true;
    httpReq.SetHttpProxy(proxy);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    std::string host;
    std::string exclusions;
    SecureData username;
    SecureData password;
    int32_t port = 0;
    // a specified proxy without credentials yields empty username and password.
    task->GetHttpProxyInfo(host, port, exclusions, username, password);
    EXPECT_EQ(host, proxy.host);
    EXPECT_EQ(port, proxy.port);
    EXPECT_TRUE(exclusions.empty());
    EXPECT_TRUE(username.empty());
    EXPECT_TRUE(password.empty());
}

#if HAS_NETMANAGER_BASE
HWTEST_F(HttpClientTaskTest, GetHttpProxyInfoWithAuthTest005, TestSize.Level2)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    httpReq.SetHttpProxyType(PROXY_TYPE_MAX);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    OHOS::NetManagerStandard::HttpProxy defaultProxy;
    OHOS::NetManagerStandard::NetConnClient::GetInstance().GetDefaultHttpProxy(defaultProxy);

    std::string host;
    std::string exclusions;
    SecureData username;
    SecureData password;
    int32_t port = -1;
    task->GetHttpProxyInfo(host, port, exclusions, username, password);

    EXPECT_EQ(host, defaultProxy.GetHost());
    EXPECT_EQ(port, static_cast<int32_t>(defaultProxy.GetPort()));
    EXPECT_EQ(exclusions, OHOS::NetStack::CommonUtils::ToString(defaultProxy.GetExclusionList()));
    EXPECT_EQ(std::string(username), std::string(defaultProxy.GetUsername()));
    EXPECT_EQ(std::string(password), std::string(defaultProxy.GetPassword()));
}
#endif

HWTEST_F(HttpClientTaskTest, SslCtxFunctionTest001, TestSize.Level1)
{
    CURL *curl = nullptr;
    SSL_CTX *sslCtx = nullptr;
    HttpClientRequest httpReq;
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    EXPECT_EQ(task->SslCtxFunction(curl, sslCtx), CURLE_SSL_CERTPROBLEM);
}

HWTEST_F(HttpClientTaskTest, SslCtxFunctionTest002, TestSize.Level1)
{
    CURL *curl = nullptr;
    SSL_CTX *sslCtx = SSL_CTX_new(TLS_client_method());
    HttpClientRequest httpReq;
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    EXPECT_EQ(task->SslCtxFunction(curl, sslCtx), CURLE_OK);
    SSL_CTX_free(sslCtx);
}

HWTEST_F(HttpClientTaskTest, SslCtxFunctionSkipCertVerifyTest, TestSize.Level1)
{
    SSL_CTX *sslCtx = SSL_CTX_new(TLS_client_method());
    ASSERT_NE(sslCtx, nullptr);
    HttpClientRequest request;
    request.SetCanSkipCertVerifyFlag(true);
    auto task = HttpSession::GetInstance().CreateTask(request);
    ASSERT_NE(task, nullptr);
    EXPECT_EQ(task->SslCtxFunction(nullptr, sslCtx), CURLE_OK);
    SSL_CTX_free(sslCtx);
}

HWTEST_F(HttpClientTaskTest, SetStatus001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/get";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    task->SetStatus(RUNNING);
    EXPECT_EQ(RUNNING, task->GetStatus());
}

HWTEST_F(HttpClientTaskTest, GetStatusTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/get";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    EXPECT_EQ(IDLE, task->GetStatus());
}

HWTEST_F(HttpClientTaskTest, GetStatusTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "https://www.baidu.com";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    task->SetStatus(TaskStatus::RUNNING);

    EXPECT_EQ(task->GetStatus(), RUNNING);
}

HWTEST_F(HttpClientTaskTest, StartTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.baidu.com";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    task->SetStatus(TaskStatus::RUNNING);
    bool result = task->Start();
    EXPECT_FALSE(result);
}

HWTEST_F(HttpClientTaskTest, StartTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.baidu.com";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    task->error_.SetErrorCode(HttpErrorCode::HTTP_UNSUPPORTED_PROTOCOL);
    bool result = task->Start();
    EXPECT_FALSE(result);
}

HWTEST_F(HttpClientTaskTest, StartTest003, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.baidu.com";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    bool result = task->Start();
    EXPECT_TRUE(result);
}

HWTEST_F(HttpClientTaskTest, StartTest004, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "https://www.baidu.com";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    task->error_.SetErrorCode(HttpErrorCode::HTTP_UNSUPPORTED_PROTOCOL);
    bool result = task->Start();
    EXPECT_FALSE(result);
}

HWTEST_F(HttpClientTaskTest, ProcessCookieTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/cookies/set/name1/value1";
    httpReq.SetURL(url);
    httpReq.SetHeader("content-type", "text/plain");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    task->Start();

    while (task->GetStatus() != TaskStatus::IDLE) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    auto ret = task->GetResponse().GetResponseCode();
    EXPECT_GE(ret, 0);
}

HWTEST_F(HttpClientTaskTest, ProcessCookieTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    task->ProcessCookie(task->curlHandle_);
    EXPECT_NE(task->curlHandle_, nullptr);
}

HWTEST_F(HttpClientTaskTest, GetTimingFromCurlTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    task->curlHandle_ = nullptr;
    // CURLINFO info;
    auto ret = task->GetTimingFromCurl(task->curlHandle_, CURLINFO_TOTAL_TIME_T);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(HttpClientTaskTest, DumpHttpPerformanceTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    task->DumpHttpPerformance();
    EXPECT_NE(task->curlHandle_, nullptr);
}

HWTEST_F(HttpClientTaskTest, CancelTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "https://www.baidu.com";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    task->Cancel();
    EXPECT_TRUE(task->canceled_);
}

HWTEST_F(HttpClientTaskTest, SetServerSSLCertOption001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "https://www.baidu.com";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    bool result = task->SetServerSSLCertOption(task->curlHandle_);
    EXPECT_TRUE(result);
}

HWTEST_F(HttpClientTaskTest, SetServerSSLCertOption002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    bool result = task->SetServerSSLCertOption(task->curlHandle_);
    EXPECT_TRUE(result);
}

#if HAS_NETMANAGER_BASE
HWTEST_F(HttpClientTaskTest, SetServerSSLCertOption_ShouldReturnTrue_WhenGetPinSetForHostNameReturnsZeroAndPinsIsEmpty,
         TestSize.Level2)
{
    auto configInstance = OHOS::NetManagerStandard::NetworkSecurityConfig::GetInstance();
    OHOS::NetManagerStandard::DomainConfig config = {};
    OHOS::NetManagerStandard::Domain domain;
    domain.domainName_ = "https://www.example.com";
    domain.includeSubDomains_ = false;
    config.domains_.push_back(domain);
    OHOS::NetManagerStandard::Pin pin;
    pin.digestAlgorithm_ = "TEST";
    pin.digest_ = "TEST";
    config.pinSet_.pins_.push_back(pin);
    configInstance.domainConfigs_.push_back(config);
    HttpClientRequest httpReq;
    std::string url = "https://www.example.com";
    httpReq.SetURL(url);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    EXPECT_TRUE(task->SetServerSSLCertOption(task->curlHandle_));
}
#endif

class MockCurl {
public:
    MOCK_METHOD0(easy_init, CURL *());
};

HWTEST_F(HttpClientTaskTest, HttpClientTask_ShouldNotCreate_WhenCurlInitFails, TestSize.Level0)
{
    MockCurl mockCurl;
    ON_CALL(mockCurl, easy_init).WillByDefault(Return(nullptr));

    HttpClientRequest request;
    HttpClientTask httpClientTask(request);
    ASSERT_EQ(httpClientTask.GetStatus(), IDLE);
    ASSERT_EQ(httpClientTask.GetType(), DEFAULT);
    ASSERT_EQ(httpClientTask.canceled_, false);

    HttpSession &session = HttpSession::GetInstance();
    auto httpClientTask2 = session.CreateTask(request, UPLOAD, "testFakePath");
    ASSERT_EQ(httpClientTask2->GetType(), UPLOAD);
}

HWTEST_F(HttpClientTaskTest, ProcessRequestTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/get";
    httpReq.SetURL(url);
    httpReq.SetHeader("content-type", "application/json");
    
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    task->Start();

    while (task->GetStatus() != TaskStatus::IDLE) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    const HttpClientRequest &request = task->GetRequest();
    EXPECT_EQ(request.GetURL(), url);
}

HWTEST_F(HttpClientTaskTest, ProcessErrorTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://nonexistenturl:8080";
    httpReq.SetURL(url);
    httpReq.SetHeader("content-type", "text/plain");
    
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    task->Start();

    while (task->GetStatus() != TaskStatus::IDLE) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    const HttpClientError &error = task->GetError();
    EXPECT_NE(error.GetErrorCode(), 0);
    EXPECT_FALSE(error.GetErrorMessage().empty());
}

#ifdef HTTP_HANDOVER_FEATURE
HWTEST_F(HttpClientTaskTest, HandoverInfoTest, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://nonexistenturl:8080";
    httpReq.SetURL(url);
    httpReq.SetHeader("content-type", "text/plain");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    
    HttpHandoverInfo httpHandoverInfo;
    task->SetRequestHandoverInfo(httpHandoverInfo);
    std::string handoverInfo = task->GetRequestHandoverInfo();
 
    httpHandoverInfo.handOverReason = 1;
    httpHandoverInfo.readFlag = 1;
    task->SetRequestHandoverInfo(httpHandoverInfo);
    handoverInfo = task->GetRequestHandoverInfo();
 
    httpHandoverInfo.handOverReason = 2;
    httpHandoverInfo.readFlag = 2;
    task->SetRequestHandoverInfo(httpHandoverInfo);
    handoverInfo = task->GetRequestHandoverInfo();
 
    httpHandoverInfo.handOverReason = 3;
    task->SetRequestHandoverInfo(httpHandoverInfo);
    handoverInfo = task->GetRequestHandoverInfo();
    EXPECT_TRUE(task->Start());
}
#endif

HWTEST_F(HttpClientTaskTest, SetSslTypeAndClientEncCertTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "https://www.baidu.com";
    httpReq.SetURL(url);
    httpReq.SetSslType(SslType::TLS);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    bool result = task->SetSslTypeAndClientEncCert(task->curlHandle_);
    EXPECT_TRUE(result);
}

HWTEST_F(HttpClientTaskTest, SetSslTypeAndClientEncCertTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "https://www.baidu.com";
    httpReq.SetURL(url);
    httpReq.SetSslType(SslType::TLCP);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);

    bool result = task->SetSslTypeAndClientEncCert(task->curlHandle_);
    EXPECT_TRUE(result);
}

HWTEST_F(HttpClientTaskTest, SetIsHeadersOnce001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://nonexistenturl:8080";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_TRUE(task != nullptr);
    task->SetIsHeadersOnce(true);
    EXPECT_TRUE(task->IsHeadersOnce());
}

HWTEST_F(HttpClientTaskTest, SetIsHeaderOnce001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://nonexistenturl:8080";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_TRUE(task != nullptr);
    task->SetIsHeaderOnce(true);
    EXPECT_TRUE(task->IsHeaderOnce());
}

HWTEST_F(HttpClientTaskTest, SetIsRequestInStream001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://nonexistenturl:8080";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_TRUE(task != nullptr);
    task->SetIsRequestInStream(true);
    EXPECT_TRUE(task->IsRequestInStream());
}

HWTEST_F(HttpClientTaskTest, OnHeaderReceive001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://nonexistenturl:8080";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_TRUE(task != nullptr);
    task->OnHeaderReceive([](const HttpClientRequest &request, const std::string &) {});
    EXPECT_TRUE(task->onHeaderReceive_ != nullptr);
}

HWTEST_F(HttpClientTaskTest, OffHeaderReceive001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://nonexistenturl:8080";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_TRUE(task != nullptr);
    auto res = task->OffHeaderReceive();
    EXPECT_FALSE(res);
    task->OnHeaderReceive([](const HttpClientRequest &request, const std::string &) {});
    res = task->OffHeaderReceive();
    EXPECT_TRUE(task->onHeaderReceive_ == nullptr);
    EXPECT_TRUE(res);
}

HWTEST_F(HttpClientTaskTest, OffHeadersReceive001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://nonexistenturl:8080";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_TRUE(task != nullptr);
    auto res = task->OffHeadersReceive();
    EXPECT_FALSE(res);
    task->OnHeadersReceive(testCallbackconst);
    res = task->OffHeadersReceive();
    EXPECT_TRUE(task->onHeadersReceive_ == nullptr);
    EXPECT_TRUE(res);
}

HWTEST_F(HttpClientTaskTest, OffProgress001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://nonexistenturl:8080";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_TRUE(task != nullptr);
    auto res = task->OffProgress();
    EXPECT_FALSE(res);
    task->OnProgress(
        [](const HttpClientRequest &request, u_long dltotal, u_long dlnow, u_long ultotal, u_long ulnow) {});
    res = task->OffProgress();
    EXPECT_TRUE(task->onProgress_ == nullptr);
    EXPECT_TRUE(res);
}

HWTEST_F(HttpClientTaskTest, OffDataReceive001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://nonexistenturl:8080";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_TRUE(task != nullptr);
    auto res = task->OffDataReceive();
    EXPECT_FALSE(res);
    task->OnDataReceive([](const HttpClientRequest &request, const uint8_t *data, size_t length) {});
    res = task->OffDataReceive();
    EXPECT_TRUE(task->onDataReceive_ == nullptr);
    EXPECT_TRUE(res);
}

HWTEST_F(HttpClientTaskTest, IsBuiltWithOpenSSL001, TestSize.Level1)
{
    const auto data = curl_version_info(CURLVERSION_NOW);
    bool res = false;
    if (data == nullptr || data->ssl_version == nullptr) {
        res = HttpClientTask::IsBuiltWithOpenSSL();
        EXPECT_FALSE(res);
    } else {
        res = HttpClientTask::IsBuiltWithOpenSSL();
        EXPECT_TRUE(res);
    }
}

HWTEST_F(HttpClientTaskTest, ProcessUsingCache001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetUsingCache(true);
    std::string url = "http://nonexistenturl:8080";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_TRUE(task != nullptr);
    task->GetResponse().SetResponseCode(OK);
    task->WriteResopnseToCache(task->GetResponse());
    task->OnFail(
        [](const HttpClientRequest &request, const HttpClientResponse &response, const HttpClientError &error) {});
    auto res = task->ProcessUsingCache();
    EXPECT_FALSE(res);
}

HWTEST_F(HttpClientTaskTest, ProcessResponseExpectType001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetExpectDataType(HttpDataType::STRING);
    std::string url = "http://nonexistenturl:8080";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_TRUE(task != nullptr);
    task->ProcessResponseExpectType();
    EXPECT_TRUE(task->GetResponse().GetExpectDataType() == HttpDataType::STRING);
}

HWTEST_F(HttpClientTaskTest, ProcessResponseExpectType002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://nonexistenturl:8080";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_TRUE(task != nullptr);
    task->GetResponse().headers_[HttpConstant::HTTP_CONTENT_TYPE] = HttpConstant::HTTP_CONTENT_TYPE_OCTET_STREAM;
    task->ProcessResponseExpectType();
    EXPECT_TRUE(task->GetResponse().GetExpectDataType() == HttpDataType::ARRAY_BUFFER);
}

HWTEST_F(HttpClientTaskTest, ProcessResponseExpectType003, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://nonexistenturl:8080";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_TRUE(task != nullptr);
    task->GetResponse().headers_[HttpConstant::HTTP_CONTENT_TYPE] = HttpConstant::HTTP_CONTENT_TYPE_MULTIPART;
    task->ProcessResponseExpectType();
    EXPECT_TRUE(task->GetResponse().GetExpectDataType() == HttpDataType::STRING);
}

HWTEST_F(HttpClientTaskTest, GetRequestBody001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://nonexistenturl:8080";
    httpReq.SetURL(url);
    EscapedData extraData = { .dataType = HttpDataType::STRING, .data = "123" };
    httpReq.SetExtraData(extraData);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_TRUE(task != nullptr);
    auto res = task->GetRequestBody();
    EXPECT_TRUE(res);
}

HWTEST_F(HttpClientTaskTest, GetRequestBody002, TestSize.Level2)
{
    HttpClientRequest httpReq;
    std::string url = "http://nonexistenturl:8080";
    httpReq.SetURL(url);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_TRUE(task != nullptr);
    auto res = task->GetRequestBody();
    EXPECT_FALSE(res);
}

HWTEST_F(HttpClientTaskTest, HandleMethodForGet001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://nonexistenturl:8080?message";
    httpReq.SetURL(url);
    std::string extraParam = "username=admin&password=123456";
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_TRUE(task != nullptr);
    EscapedData extraData = { .dataType = HttpDataType::STRING, .data = extraParam };
    task->GetRequest().SetExtraData(extraData);
    task->HandleMethodForGet();
    auto fmtUrl = task->GetRequest().GetURL();
    EXPECT_STREQ(fmtUrl.c_str(), (url + HttpConstant::HTTP_URL_PARAM_SEPARATOR + extraParam).c_str());
}

HWTEST_F(HttpClientTaskTest, HandleMethodForGet002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://nonexistenturl:8080?message";
    httpReq.SetURL(url);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_TRUE(task != nullptr);

    cJSON *root = cJSON_CreateObject();
    ASSERT_TRUE(root != nullptr);
    cJSON_AddStringToObject(root, "letter", "test");
    cJSON_AddStringToObject(root, "characters", "UnitTest");
    cJSON_AddNumberToObject(root, "age", 25);
    cJSON_AddBoolToObject(root, "is_student", 1);
    cJSON_AddNullToObject(root, "optional_field");
    cJSON *array = cJSON_CreateArray();
    cJSON_AddItemToArray(array, cJSON_CreateString("element_1"));
    cJSON_AddItemToArray(array, cJSON_CreateString("element_2"));
    cJSON_AddItemToObject(root, "arrayElement", array);
    char *jsonObjStr = cJSON_Print(root);
    EscapedData extraData = { .dataType = HttpDataType::OBJECT, .data = jsonObjStr };
    free(jsonObjStr);
    cJSON_Delete(root);

    task->GetRequest().SetExtraData(extraData);
    task->HandleMethodForGet();
    auto fmtUrl = task->GetRequest().GetURL();
    EXPECT_FALSE(fmtUrl.empty());
}

HWTEST_F(HttpClientTaskTest, TraverseJson001, TestSize.Level2)
{
    HttpClientRequest httpReq;
    std::string url = "http://nonexistenturl:8080";
    httpReq.SetURL(url);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_TRUE(task != nullptr);

    std::string output;
    task->TraverseJson(nullptr, output);
    EXPECT_TRUE(output.empty());
}

HWTEST_F(HttpClientTaskTest, MakeUrl001, TestSize.Level2)
{
    HttpClientRequest httpReq;
    std::string url = "http://nonexistenturl:8080";
    httpReq.SetURL(url);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_TRUE(task != nullptr);

    std::string param;
    std::string extraParam = "username=admin&password=123456";
    auto res = task->MakeUrl(url, param, extraParam);
    EXPECT_FALSE(res.empty());
}

HWTEST_F(HttpClientTaskTest, IsUnReserved001, TestSize.Level2)
{
    HttpClientRequest httpReq;
    std::string url = "http://nonexistenturl:8080";
    httpReq.SetURL(url);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_TRUE(task != nullptr);
    EXPECT_FALSE(task->IsUnReserved('!'));
}

HWTEST_F(HttpClientTaskTest, SetDnsOption001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://nonexistenturl:8080";
    httpReq.SetURL(url);
    std::vector<std::string> dnsServers = { "http://dns.xtstest1.com/dns-query", "http://dns.xtstest2.com/dns-query" };
    httpReq.SetDNSServers(dnsServers);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_TRUE(task != nullptr);
    EXPECT_FALSE(task->GetRequest().GetDNSServers().empty());
}

HWTEST_F(HttpClientTaskTest, HeaderReceiveCallbackTest007, TestSize.Level2)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/get";
    httpReq.SetURL(url);

    const char *data = "Test Header";
    size_t size = 5;
    size_t memBytes = 2;
    auto result = HttpClientTask::HeaderReceiveCallback(data, size, memBytes, nullptr);
    EXPECT_EQ(result, 0);
}

HWTEST_F(HttpClientTaskTest, HeaderReceiveCallbackTest008, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/get";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_TRUE(task != nullptr);

    task->onHeaderReceive_ = [](const HttpClientRequest &request, const std::string &header) {};
    HttpClientResponse resp;
    std::string errorHead = "test:data";
    resp.SetRawHeader(errorHead);
    task->SetResponse(resp);

    auto *userData = task.get();
    const char *data = "Test Header";
    size_t size = 5;
    size_t memBytes = 2;
    size_t result = HttpClientTask::HeaderReceiveCallback(data, size, memBytes, userData);
    EXPECT_TRUE(resp.headers_.empty());
    EXPECT_EQ(result, size * memBytes);

    task->SetIsHeaderOnce(true);
    result = HttpClientTask::HeaderReceiveCallback(data, size, memBytes, userData);
    EXPECT_EQ(result, size * memBytes);
}

HWTEST_F(HttpClientTaskTest, HeaderReceiveCallbackTest009, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/get";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_TRUE(task != nullptr);
    task->onHeadersReceive_ = testCallbackconst;

    HttpClientResponse resp;
    const char *realHead = "test:data\r\n\r\n";
    resp.SetRawHeader(realHead);
    task->SetResponse(resp);
    
    auto *userData = task.get();
    const char *data = "Test Header";
    size_t size = 5;
    size_t memBytes = 2;
    auto result = HttpClientTask::HeaderReceiveCallback(data, size, memBytes, userData);
    EXPECT_EQ(result, size * memBytes);

    task->SetIsHeadersOnce(true);
    result = HttpClientTask::HeaderReceiveCallback(data, size, memBytes, userData);
    EXPECT_EQ(result, size * memBytes);
}

HWTEST_F(HttpClientTaskTest, DataReceiveCallbackTest007, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/get";
    const char *data = "http://www.httpbin.org/get";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_TRUE(task != nullptr);

    HttpClientResponse resp;
    resp.result_ = "result1";
    task->SetResponse(resp);
    task->SetIsRequestInStream(true);

    auto *userData = task.get();
    size_t size = 1;
    size_t memBytes = 1;
    auto result = HttpClientTask::DataReceiveCallback(data, size, memBytes, userData);

    EXPECT_EQ(result, size * memBytes);
}

HWTEST_F(HttpClientTaskTest, SetTlsOption001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/get";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();

    int32_t loopCount = 4;
    std::vector<TlsVersion> tlsVersionContainer = {
        TlsVersion::TLSv1_0,
        TlsVersion::TLSv1_1,
        TlsVersion::TLSv1_2,
        TlsVersion::TLSv1_3
    };
    for (int32_t i = 0; i < loopCount; ++i) {
        TlsOption option;
        option.tlsVersionMin = tlsVersionContainer.at(i);
        option.tlsVersionMax = tlsVersionContainer.at(i);
        httpReq.SetTLSOptions(option);
        auto task = session.CreateTask(httpReq);
        ASSERT_TRUE(task != nullptr);
    }
}

HWTEST_F(HttpClientTaskTest, SetTlsOption002, TestSize.Level2)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/get";
    httpReq.SetURL(url);
    TlsOption option;
    option.tlsVersionMin = TlsVersion::TLSv1_3;
    option.tlsVersionMax = TlsVersion::TLSv1_1;
    httpReq.SetTLSOptions(option);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_TRUE(task != nullptr);
}

HWTEST_F(HttpClientTaskTest, SetCertPinnerOption001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/get";
    httpReq.SetURL(url);
    SecureData certPIN;
    certPIN.append("Q6TCQAWqP4t+eq41xnKaUgJdrPWqyG5L+Ni2YzMhqdY=");
    httpReq.SetCertificatePinning(certPIN);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_TRUE(task != nullptr);
}

HWTEST_F(HttpClientTaskTest, LogResponseInfoTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.test.com");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    CURLcode code = CURLE_OK;
    task->LogResponseInfo(code);
    EXPECT_EQ(task->error_.GetErrorCode(), HTTP_NONE_ERR);
}

HWTEST_F(HttpClientTaskTest, LogResponseInfoTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    CURLcode code = CURLE_ABORTED_BY_CALLBACK;
    task->LogResponseInfo(code);
    EXPECT_NE(task->response_.GetResponseTime().empty(), true);
}

HWTEST_F(HttpClientTaskTest, HandleCancelCallbackTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    CURLcode code = CURLE_ABORTED_BY_CALLBACK;
    bool called = false;
    task->onCanceled_ = [&called](const HttpClientRequest &, const HttpClientResponse &) {
        called = true;
    };
    bool ret = task->HandleCancelCallback(code);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(called);
    EXPECT_FALSE(task->IsSuccess());
}

HWTEST_F(HttpClientTaskTest, HandleCancelCallbackTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    CURLcode code = CURLE_OK;
    bool ret = task->HandleCancelCallback(code);
    EXPECT_FALSE(ret);
}

HWTEST_F(HttpClientTaskTest, HandleCancelCallbackTest003, TestSize.Level1)
{
    HttpClientRequest httpReq;
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    CURLcode code = CURLE_ABORTED_BY_CALLBACK;
    bool ret = task->HandleCancelCallback(code);
    EXPECT_TRUE(ret);
    EXPECT_FALSE(task->IsSuccess());
}

HWTEST_F(HttpClientTaskTest, HandleErrorCallbackTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    CURLcode code = CURLE_FAILED_INIT;
    bool called = false;
    task->onFailed_ = [&called](const HttpClientRequest &, const HttpClientResponse &, const HttpClientError &) {
        called = true;
    };
    bool ret = task->HandleErrorCallback(code);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(called);
    EXPECT_FALSE(task->IsSuccess());
}

HWTEST_F(HttpClientTaskTest, HandleErrorCallbackTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    CURLcode code = CURLE_OK;
    bool ret = task->HandleErrorCallback(code);
    EXPECT_FALSE(ret);
}

HWTEST_F(HttpClientTaskTest, ProcessResponseCoreLogicTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    task->response_.SetResponseCode(ResponseCode::NOT_FOUND);
    bool ret = task->ProcessResponseCoreLogic();
    EXPECT_TRUE(ret);
}

HWTEST_F(HttpClientTaskTest, ProcessResponseCoreLogicTest003, TestSize.Level1)
{
    HttpClientRequest httpReq;
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    task->response_.SetResponseCode(ResponseCode::NOT_FOUND);
    HttpInterceptorMgr::GetInstance().AddInterceptor(&g_request_interceptor);
    g_Interceptor_Result = OH_ABORT;
    bool ret = task->ProcessResponseCoreLogic();
    task->networkProfilerUtils_.reset();
    task->HandleNetworkProfiling();
    HttpInterceptorMgr::GetInstance().DeleteInterceptor(&g_request_interceptor);
    g_Interceptor_Result = OH_CONTINUE;
    EXPECT_TRUE(ret);
}

HWTEST_F(HttpClientTaskTest, HandleResultCallbackTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    bool successCalled = false;
    task->onSucceeded_ = [&successCalled](const HttpClientRequest &, const HttpClientResponse &) {
        successCalled = true;
    };
    task->HandleResultCallback(true);
    EXPECT_TRUE(successCalled);
    EXPECT_TRUE(task->IsSuccess());
}

HWTEST_F(HttpClientTaskTest, HandleResultCallbackTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    bool failCalled = false;
    task->onFailed_ = [&failCalled](const HttpClientRequest &, const HttpClientResponse &, const HttpClientError &) {
        failCalled = true;
    };
    task->HandleResultCallback(false);
    EXPECT_TRUE(failCalled);
    EXPECT_FALSE(task->IsSuccess());
}

HWTEST_F(HttpClientTaskTest, ConvertRequestContextToInterceptorReqTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    std::shared_ptr<OH_Http_Interceptor_Request> ctx =
        OHOS::NetStack::HttpInterceptor::HttpInterceptorMgr::GetInstance().CreateHttpInterceptorRequest();
    bool ret = task->ConvertRequestContextToInterceptorReq(ctx);
    EXPECT_EQ(ret, true);
    ret = task->ConvertInterceptorReqToRequestContext(ctx);
    EXPECT_EQ(ret, true);
    task->request_.SetURL("http://test.com");
    task->request_.SetMethod("GET");
    std::string body = "111111";
    size_t len = body.length();
    task->request_.SetBody(body.c_str(), len);
    task->request_.SetHeader("aaa", "1111");
    task->request_.SetHeader("bbb", "");
    ret = task->ConvertRequestContextToInterceptorReq(ctx);
    EXPECT_EQ(ret, true);
    std::shared_ptr<OH_Http_Interceptor_Request> nullctx;
    ret = task->ConvertInterceptorReqToRequestContext(nullctx);
    EXPECT_EQ(ret, false);
    ret = task->ConvertRequestContextToInterceptorReq(nullctx);
    EXPECT_EQ(ret, false);
    ret = task->ConvertInterceptorReqToRequestContext(ctx);
    EXPECT_EQ(ret, true);
}

HWTEST_F(HttpClientTaskTest, GlobalRequestInterceptorCheckTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://test.com");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    bool ret = task->GlobalRequestInterceptorCheck();
    EXPECT_TRUE(ret);
}

HWTEST_F(HttpClientTaskTest, GlobalRequestInterceptorCheckTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/delete";
    std::string method = "DELETE";
    httpReq.SetURL(url);
    httpReq.SetMethod(method);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    HttpInterceptorMgr::GetInstance().AddInterceptor(&g_request_interceptor);
    g_Interceptor_Result = OH_ABORT;
    task->OnSuccess([task](const HttpClientRequest &request, const HttpClientResponse &response) {});
    auto ret = task->Start();
    HttpInterceptorMgr::GetInstance().DeleteInterceptor(&g_request_interceptor);
    g_Interceptor_Result = OH_CONTINUE;
    EXPECT_EQ(ret, false);
    EXPECT_EQ(task->GetError().GetErrorCode(), HttpErrorCode::HTTP_REQUEST_INTERCEPTED);
}

HWTEST_F(HttpClientTaskTest, GlobalRequestInterceptorCheckTest003, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/delete";
    std::string method = "DELETE";
    httpReq.SetURL(url);
    httpReq.SetMethod(method);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    HttpInterceptorMgr::GetInstance().AddInterceptor(&g_request_interceptor);
    g_IsModified = true;
    task->OnSuccess([task](const HttpClientRequest &request, const HttpClientResponse &response) {});
    auto ret = task->Start();
    HttpInterceptorMgr::GetInstance().DeleteInterceptor(&g_request_interceptor);
    g_IsModified = false;
    EXPECT_EQ(ret, true);
}

HWTEST_F(HttpClientTaskTest, ConvertResponseContextToInterceptorRespTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    std::shared_ptr<OH_Http_Interceptor_Response> ctx =
        OHOS::NetStack::HttpInterceptor::HttpInterceptorMgr::GetInstance().CreateHttpInterceptorResponse();
    auto ret = task->ConvertResponseContextToInterceptorResp(ctx);
    EXPECT_EQ(ret, true);
    ret = task->ConvertInterceptorRespToResponseContext(ctx);
    EXPECT_EQ(ret, true);
    task->response_.SetResult("aaaaaaaaa");
    task->response_.SetResponseCode(ResponseCode::OK);
    task->response_.SetRawHeader("aaa:111\r\nbbb\r\nset-cookie:data\r\n\r\n");
    task->response_.ParseHeaders();
    ret = task->ConvertResponseContextToInterceptorResp(ctx);
    EXPECT_EQ(ret, true);
    std::shared_ptr<OH_Http_Interceptor_Response> nullctx;
    ret = task->ConvertResponseContextToInterceptorResp(nullctx);
    EXPECT_EQ(ret, false);
    ret = task->ConvertInterceptorRespToResponseContext(nullctx);
    EXPECT_EQ(ret, false);
    ret = task->ConvertInterceptorRespToResponseContext(ctx);
    EXPECT_EQ(ret, true);
}

HWTEST_F(HttpClientTaskTest, GlobalResponseInterceptorCheckTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    bool ret = task->GlobalResponseInterceptorCheck();
    EXPECT_TRUE(ret);
}

HWTEST_F(HttpClientTaskTest, GlobalResponseInterceptorCheckTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.httpbin.org/delete";
    std::string method = "DELETE";
    httpReq.SetURL(url);
    httpReq.SetMethod(method);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    g_Interceptor_Result = OH_ABORT;
    g_IsModified = false;
    HttpInterceptorMgr::GetInstance().AddInterceptor(&g_response_interceptor);
    auto ret = task->GlobalResponseInterceptorCheck();
    EXPECT_EQ(ret, false);
    g_IsModified = true;
    g_Interceptor_Result = OH_CONTINUE;
    ret = task->GlobalResponseInterceptorCheck();
    (void)HttpInterceptorMgr::GetInstance().DeleteInterceptor(&g_response_interceptor);
    g_IsModified = false;
    EXPECT_EQ(ret, true);
}

HWTEST_F(HttpClientTaskTest, CreateCookieShareHandleTest001, TestSize.Level1)
{
    auto shareHandle = CreateCookieShareHandle();
    ASSERT_NE(shareHandle, nullptr);
    EXPECT_NE(shareHandle->Get(), nullptr);
    // the mutex used by the curl share lock callbacks must be accessible.
    (void)shareHandle->GetMutex();
    EXPECT_NE(shareHandle->Get(), nullptr);
}

HWTEST_F(HttpClientTaskTest, SetCookieShareHandleTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    auto shareHandle = CreateCookieShareHandle();
    ASSERT_NE(shareHandle, nullptr);

    task->SetCookieShareHandle(shareHandle);
    EXPECT_EQ(task->cookieShareHandle_, shareHandle);
    EXPECT_EQ(task->cookieShareHandle_->Get(), shareHandle->Get());
}

HWTEST_F(HttpClientTaskTest, SetCookieShareHandleTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    task->SetCookieShareHandle(nullptr);
    EXPECT_EQ(task->cookieShareHandle_, nullptr);
}

HWTEST_F(HttpClientTaskTest, SetCookieShareHandleTest003, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    auto shareHandle = CreateCookieShareHandle();
    ASSERT_NE(shareHandle, nullptr);
    curl_share_cleanup(shareHandle->handle_);
    shareHandle->handle_ = nullptr;

    task->SetCookieShareHandle(shareHandle);
    EXPECT_EQ(task->cookieShareHandle_, shareHandle);
}

#ifdef HTTP_ONLY_VERIFY_ROOT_CA_ENABLE
HWTEST_F(HttpClientTaskTest, RootCaVerifiedTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_FALSE(task->IsRootCaVerified());
    EXPECT_FALSE(task->IsRootCaVerifiedOk());

    task->SetRootCaVerified();
    EXPECT_TRUE(task->IsRootCaVerified());

    task->SetRootCaVerifiedOk(true);
    EXPECT_TRUE(task->IsRootCaVerifiedOk());

    task->SetRootCaVerifiedOk(false);
    EXPECT_FALSE(task->IsRootCaVerifiedOk());
}
#endif

#if defined(HTTP_MULTIPATH_CERT_ENABLE) || defined(HTTP_ONLY_VERIFY_ROOT_CA_ENABLE)
constexpr const char *TEST_TLS_HOST = "127.0.0.1";
constexpr const char *TEST_TLS_ROOT_CN = "Netstack Test Root CA";
constexpr int TEST_RSA_KEY_BITS = 2048;
constexpr long TEST_CERT_VALID_SECONDS = 24 * 60 * 60;
constexpr int TEST_SERVER_TIMEOUT_MS = 5000;
constexpr int TEST_SERVER_BACKLOG = 1;
constexpr const char *TEST_SERVER_RESPONSE =
    "HTTP/1.1 200 OK\r\nSet-Cookie: session=netstack; path=/\r\nContent-Length: 2\r\n"
    "Connection: close\r\n\r\nOK";
constexpr int HTTP2_FRAME_HEADER_LEN = 9;
constexpr uint8_t HTTP2_DATA_FRAME = 0x0;
constexpr uint8_t HTTP2_HEADERS_FRAME = 0x1;
constexpr uint8_t HTTP2_SETTINGS_FRAME = 0x4;
constexpr uint8_t HTTP2_FLAG_END_STREAM = 0x1;
constexpr uint8_t HTTP2_FLAG_END_HEADERS = 0x4;
constexpr uint8_t HTTP2_FLAG_ACK = 0x1;

EVP_PKEY *CreateTestKey()
{
    EVP_PKEY_CTX *pkeyCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (pkeyCtx == nullptr) {
        return nullptr;
    }
    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_keygen_init(pkeyCtx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(pkeyCtx, TEST_RSA_KEY_BITS) <= 0 ||
        EVP_PKEY_keygen(pkeyCtx, &pkey) <= 0) {
        pkey = nullptr;
    }
    EVP_PKEY_CTX_free(pkeyCtx);
    return pkey;
}

void AddTestCertExtension(X509 *cert, int nid, const char *value)
{
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(nullptr, nullptr, nid, const_cast<char *>(value));
    if (ext == nullptr) {
        return;
    }
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
}

X509 *CreateTestCert(EVP_PKEY *pkey, const char *commonName, X509 *issuerCert, EVP_PKEY *issuerKey)
{
    if (pkey == nullptr) {
        return nullptr;
    }
    X509 *cert = X509_new();
    if (cert == nullptr) {
        return nullptr;
    }
    X509_set_version(cert, X509_VERSION_3);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), TEST_CERT_VALID_SECONDS);
    X509_NAME *name = X509_get_subject_name(cert);
    bool ok = name != nullptr && X509_set_pubkey(cert, pkey) == 1 &&
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char *>(commonName), -1, -1, 0) == 1;
    if (issuerCert == nullptr) {
        ok = ok && X509_set_issuer_name(cert, name) == 1;
        AddTestCertExtension(cert, NID_basic_constraints, "critical,CA:TRUE");
    } else {
        ok = ok && X509_set_issuer_name(cert, X509_get_subject_name(issuerCert)) == 1;
        AddTestCertExtension(cert, NID_basic_constraints, "critical,CA:FALSE");
    }
    AddTestCertExtension(cert, NID_key_usage, "digitalSignature,keyEncipherment");
    if (!ok || X509_sign(cert, issuerCert == nullptr ? pkey : issuerKey, EVP_sha256()) <= 0) {
        X509_free(cert);
        return nullptr;
    }
    return cert;
}

std::string CertToPem(X509 *cert)
{
    if (cert == nullptr) {
        return {};
    }
    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == nullptr) {
        return {};
    }
    std::string pem;
    if (PEM_write_bio_X509(bio, cert) == 1) {
        char *data = nullptr;
        auto len = BIO_get_mem_data(bio, &data);
        if (data != nullptr && len > 0) {
            pem.assign(data, static_cast<size_t>(len));
        }
    }
    BIO_free(bio);
    return pem;
}

class HttpTlsTestServer {
public:
    HttpTlsTestServer() = default;
    ~HttpTlsTestServer()
    {
        Stop();
    }

    bool Start()
    {
        if (!InitCerts() || !InitSocket()) {
            Stop();
            return false;
        }
        thread_ = std::thread([this]() { Serve(); });
        return true;
    }

    uint16_t GetPort() const
    {
        return port_;
    }

    const std::string &GetRootCertPem() const
    {
        return rootCertPem_;
    }

    const std::string &GetServerCertPem() const
    {
        return serverCertPem_;
    }

    void SetResponse(const std::string &response)
    {
        response_ = response;
    }

    void SetHttp2(bool http2)
    {
        http2_ = http2;
    }

private:
    bool InitCerts()
    {
        EVP_PKEY *rootKey = CreateTestKey();
        X509 *rootCert = CreateTestCert(rootKey, TEST_TLS_ROOT_CN, nullptr, nullptr);
        EVP_PKEY *serverKey = CreateTestKey();
        X509 *serverCert = CreateTestCert(serverKey, TEST_TLS_HOST, rootCert, rootKey);
        bool ok = rootCert != nullptr && serverKey != nullptr && serverCert != nullptr;
        if (ok) {
            rootCertPem_ = CertToPem(rootCert);
            serverCertPem_ = CertToPem(serverCert);
            serverCtx_ = SSL_CTX_new(TLS_server_method());
            if (serverCtx_ != nullptr && http2_) {
                SSL_CTX_set_alpn_select_cb(serverCtx_, SelectAlpnH2, nullptr);
            }
            ok = serverCtx_ != nullptr && !rootCertPem_.empty() &&
                SSL_CTX_use_certificate(serverCtx_, serverCert) == 1 &&
                SSL_CTX_use_PrivateKey(serverCtx_, serverKey) == 1;
            if (ok && SSL_CTX_add_extra_chain_cert(serverCtx_, rootCert) == 1) {
                // ownership of the chain cert is transferred to the ssl ctx
                rootCert = nullptr;
            } else {
                ok = false;
            }
        }
        EVP_PKEY_free(rootKey);
        EVP_PKEY_free(serverKey);
        X509_free(rootCert);
        X509_free(serverCert);
        return ok;
    }

    bool InitSocket()
    {
        listenFd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (listenFd_ < 0) {
            return false;
        }
        struct sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (::bind(listenFd_, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) != 0 ||
            ::listen(listenFd_, TEST_SERVER_BACKLOG) != 0) {
            return false;
        }
        socklen_t len = sizeof(addr);
        if (::getsockname(listenFd_, reinterpret_cast<struct sockaddr *>(&addr), &len) != 0) {
            return false;
        }
        port_ = ntohs(addr.sin_port);
        return true;
    }

    void Serve()
    {
        if (listenFd_ < 0) {
            return;
        }
        struct pollfd pfd = { listenFd_, POLLIN, 0 };
        if (::poll(&pfd, 1, TEST_SERVER_TIMEOUT_MS) <= 0) {
            return;
        }
        int connFd = ::accept(listenFd_, nullptr, nullptr);
        if (connFd < 0) {
            return;
        }
        struct timeval timeout = { TEST_SERVER_TIMEOUT_MS / 1000, 0 };
        (void)::setsockopt(connFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        (void)::setsockopt(connFd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        SSL *ssl = SSL_new(serverCtx_);
        if (ssl != nullptr) {
            SSL_set_fd(ssl, connFd);
            if (SSL_accept(ssl) > 0) {
                if (http2_ && NegotiatedH2(ssl)) {
                    ServeHttp2(ssl);
                } else {
                    char buffer[1024] = {0};
                    (void)SSL_read(ssl, buffer, sizeof(buffer) - 1);
                    (void)SSL_write(ssl, response_.c_str(), static_cast<int>(response_.size()));
                    (void)SSL_shutdown(ssl);
                }
            }
            SSL_free(ssl);
        }
        ::close(connFd);
    }

    static int SelectAlpnH2(SSL *, const unsigned char **out, unsigned char *outLen, const unsigned char *in,
        unsigned int inLen, void *)
    {
        static const unsigned char h2[] = {2, 'h', '2'};
        if (SSL_select_next_proto(const_cast<unsigned char **>(out), outLen, in, inLen, h2, sizeof(h2)) ==
            OPENSSL_NPN_NEGOTIATED) {
            return SSL_TLSEXT_ERR_OK;
        }
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    bool NegotiatedH2(SSL *ssl)
    {
        const unsigned char *proto = nullptr;
        unsigned int protoLen = 0;
        SSL_get0_alpn_selected(ssl, &proto, &protoLen);
        return proto != nullptr && protoLen == strlen("h2") && memcmp(proto, "h2", protoLen) == 0;
    }

    static int ReadFull(SSL *ssl, void *buf, int len)
    {
        auto *p = static_cast<char *>(buf);
        int total = 0;
        while (total < len) {
            int n = SSL_read(ssl, p + total, len - total);
            if (n <= 0) {
                return -1;
            }
            total += n;
        }
        return total;
    }

    static int WriteFull(SSL *ssl, const void *buf, int len)
    {
        auto *p = static_cast<const char *>(buf);
        int total = 0;
        while (total < len) {
            int n = SSL_write(ssl, p + total, len - total);
            if (n <= 0) {
                return -1;
            }
            total += n;
        }
        return total;
    }

    static bool DiscardBytes(SSL *ssl, uint32_t len)
    {
        char buf[256];
        while (len > 0) {
            int chunk = len < sizeof(buf) ? static_cast<int>(len) : static_cast<int>(sizeof(buf));
            if (ReadFull(ssl, buf, chunk) < 0) {
                return false;
            }
            len -= static_cast<uint32_t>(chunk);
        }
        return true;
    }

    static uint32_t Http2FrameLength(const uint8_t header[HTTP2_FRAME_HEADER_LEN])
    {
        return (static_cast<uint32_t>(header[0]) << 16) | (static_cast<uint32_t>(header[1]) << 8) | header[2];
    }

    static bool WriteHttp2Frame(SSL *ssl, uint8_t type, uint8_t flags, uint32_t streamId,
        const std::string &payload)
    {
        uint32_t length = static_cast<uint32_t>(payload.size());
        uint8_t header[HTTP2_FRAME_HEADER_LEN] = {
            static_cast<uint8_t>((length >> 16) & 0xFF),
            static_cast<uint8_t>((length >> 8) & 0xFF),
            static_cast<uint8_t>(length & 0xFF),
            type,
            flags,
            0,
            0,
            0,
            static_cast<uint8_t>(streamId),
        };
        if (WriteFull(ssl, header, sizeof(header)) < 0) {
            return false;
        }
        return payload.empty() || WriteFull(ssl, payload.data(), static_cast<int>(payload.size())) >= 0;
    }

    void ServeHttp2(SSL *ssl)
    {
        char clientPreface[24] = {0};
        if (ReadFull(ssl, clientPreface, sizeof(clientPreface)) < 0 ||
            memcmp(clientPreface, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", sizeof(clientPreface)) != 0) {
            return;
        }
        if (!WriteHttp2Frame(ssl, HTTP2_SETTINGS_FRAME, 0, 0, "")) {
            return;
        }
        while (true) {
            uint8_t frameHeader[HTTP2_FRAME_HEADER_LEN] = {0};
            if (ReadFull(ssl, frameHeader, sizeof(frameHeader)) < 0) {
                return;
            }
            uint32_t length = Http2FrameLength(frameHeader);
            uint8_t type = frameHeader[3];
            uint8_t flags = frameHeader[4];
            if (type == HTTP2_SETTINGS_FRAME && (flags & HTTP2_FLAG_ACK) == 0) {
                if (!WriteHttp2Frame(ssl, HTTP2_SETTINGS_FRAME, HTTP2_FLAG_ACK, 0, "")) {
                    return;
                }
            }
            if (type == HTTP2_HEADERS_FRAME) {
                if (!DiscardBytes(ssl, length)) {
                    return;
                }
                break;
            }
            if (!DiscardBytes(ssl, length)) {
                return;
            }
        }

        std::string body = "OK";
        std::string hpack;
        hpack.push_back(static_cast<char>(0x88));
        hpack.push_back(0x00);
        const std::string name = "content-length";
        hpack.push_back(static_cast<char>(name.size()));
        hpack += name;
        std::string bodyLength = std::to_string(body.size());
        hpack.push_back(static_cast<char>(bodyLength.size()));
        hpack += bodyLength;
        if (!WriteHttp2Frame(ssl, HTTP2_HEADERS_FRAME, HTTP2_FLAG_END_HEADERS, 1, hpack)) {
            return;
        }
        (void)WriteHttp2Frame(ssl, HTTP2_DATA_FRAME, HTTP2_FLAG_END_STREAM, 1, body);
        (void)SSL_shutdown(ssl);
    }

    void Stop()
    {
        if (thread_.joinable()) {
            thread_.join();
        }
        if (listenFd_ >= 0) {
            ::close(listenFd_);
            listenFd_ = -1;
        }
        if (serverCtx_ != nullptr) {
            SSL_CTX_free(serverCtx_);
            serverCtx_ = nullptr;
        }
    }

    SSL_CTX *serverCtx_ = nullptr;
    std::thread thread_;
    std::string rootCertPem_;
    std::string serverCertPem_;
    std::string response_ = TEST_SERVER_RESPONSE;
    bool http2_ = false;
    uint16_t port_ = 0;
    int listenFd_ = -1;
};

std::string BuildLocalTlsUrl(uint16_t port)
{
    return std::string("https://") + TEST_TLS_HOST + ":" + std::to_string(port) + "/";
}

std::string ComputeSpkiPin(const std::string &certPem)
{
    BIO *bio = BIO_new_mem_buf(certPem.data(), static_cast<int>(certPem.size()));
    if (bio == nullptr) {
        return {};
    }
    X509 *cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (cert == nullptr) {
        return {};
    }
    unsigned char *spkiDer = nullptr;
    int spkiLen = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &spkiDer);
    X509_free(cert);
    if (spkiLen <= 0 || spkiDer == nullptr) {
        return {};
    }
    std::string digest;
    bool ok = OHOS::NetStack::CommonUtils::Sha256sum(spkiDer, static_cast<size_t>(spkiLen), digest);
    OPENSSL_free(spkiDer);
    if (!ok) {
        return {};
    }
    return std::string("sha256//") + digest;
}
#endif


HWTEST_F(HttpClientTaskTest, SetProxyOptionTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetProxyOption(task->curlHandle_));
}

HWTEST_F(HttpClientTaskTest, SetProxyOptionTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    Socks5Proxy socks5Proxy;
    socks5Proxy.host = "127.0.0.1";
    socks5Proxy.port = 1080;
    httpReq.SetSocks5Proxy(socks5Proxy);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetProxyOption(task->curlHandle_));
}

HWTEST_F(HttpClientTaskTest, SetHttpProxyOptionTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetHttpProxyOption(task->curlHandle_));
}

HWTEST_F(HttpClientTaskTest, SetHttpProxyOptionTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    httpReq.SetHttpProxyType(USE_SPECIFIED);
    HttpProxy proxy;
    proxy.host = "192.168.147.60";
    proxy.port = 8888;
    proxy.exclusions = "www.httpbin.org";
    httpReq.SetHttpProxy(proxy);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetHttpProxyOption(task->curlHandle_));
}

HWTEST_F(HttpClientTaskTest, SetHttpProxyOptionTest003, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("https://www.httpbin.org/get");
    httpReq.SetHttpProxyType(USE_SPECIFIED);
    HttpProxy proxy;
    proxy.host = "https://192.168.147.60";
    proxy.port = 8888;
    proxy.exclusions = "www.test.org";
    httpReq.SetHttpProxy(proxy);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetHttpProxyOption(task->curlHandle_));
}

HWTEST_F(HttpClientTaskTest, SetHttpProxyOptionTest004, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    httpReq.SetHttpProxyType(USE_SPECIFIED);
    HttpProxy proxy;
    proxy.host = "192.168.147.60";
    proxy.port = 8888;
    proxy.exclusions = "www.test.org";
    proxy.username.assign("user");
    proxy.password.assign("pass");
    httpReq.SetHttpProxy(proxy);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetHttpProxyOption(task->curlHandle_));
}

HWTEST_F(HttpClientTaskTest, SetSocks5ProxyOptionTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetSocks5ProxyOption(task->curlHandle_));
}

HWTEST_F(HttpClientTaskTest, SetSocks5ProxyOptionTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    Socks5Proxy socks5Proxy;
    socks5Proxy.host = "127.0.0.1";
    socks5Proxy.port = 1080;
    socks5Proxy.exclusionList = "www.httpbin.org";
    httpReq.SetSocks5Proxy(socks5Proxy);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetSocks5ProxyOption(task->curlHandle_));
}

HWTEST_F(HttpClientTaskTest, SetSocks5ProxyOptionTest003, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    Socks5Proxy socks5Proxy;
    socks5Proxy.host = "127.0.0.1";
    socks5Proxy.port = 1080;
    socks5Proxy.dnsStrategy = Socks5DnsStrategy::PROXY_MODE;
    httpReq.SetSocks5Proxy(socks5Proxy);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetSocks5ProxyOption(task->curlHandle_));
}

HWTEST_F(HttpClientTaskTest, SetSocks5ProxyOptionTest004, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    Socks5Proxy socks5Proxy;
    socks5Proxy.host = "127.0.0.1";
    socks5Proxy.port = 1080;
    socks5Proxy.dnsStrategy = Socks5DnsStrategy::SYSTEM_MODE;
    socks5Proxy.username.assign("user");
    socks5Proxy.password.assign("pass");
    httpReq.SetSocks5Proxy(socks5Proxy);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetSocks5ProxyOption(task->curlHandle_));
}

HWTEST_F(HttpClientTaskTest, SetSocks5ProxyOptionTest005, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    Socks5Proxy socks5Proxy;
    socks5Proxy.host = "127.0.0.1";
    socks5Proxy.port = 1080;
    socks5Proxy.dnsStrategy = Socks5DnsStrategy::UNSPECIFIED;
    httpReq.SetSocks5Proxy(socks5Proxy);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetSocks5ProxyOption(task->curlHandle_));
}

HWTEST_F(HttpClientTaskTest, SetSocks5ProxyOptionTest006, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    Socks5Proxy socks5Proxy;
    socks5Proxy.host = "socks5h://127.0.0.1";
    socks5Proxy.port = 1080;
    socks5Proxy.dnsStrategy = Socks5DnsStrategy::UNSPECIFIED;
    socks5Proxy.username.assign("user");
    socks5Proxy.password.assign("pass");
    httpReq.SetSocks5Proxy(socks5Proxy);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetSocks5ProxyOption(task->curlHandle_));
}

HWTEST_F(HttpClientTaskTest, SetExtraInfoOptionTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetExtraInfoOption(task->curlHandle_));
}

HWTEST_F(HttpClientTaskTest, SetOtherCurlOptionTest006, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("https://www.httpbin.org/get");
    Socks5Proxy socks5Proxy;
    socks5Proxy.host = "127.0.0.1";
    socks5Proxy.port = 1080;
    socks5Proxy.dnsStrategy = Socks5DnsStrategy::PROXY_MODE;
    httpReq.SetSocks5Proxy(socks5Proxy);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetOtherCurlOption(task->curlHandle_));
}

HWTEST_F(HttpClientTaskTest, SetIpResolveTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetIpResolve(task->curlHandle_));
}

HWTEST_F(HttpClientTaskTest, SetIpResolveTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    httpReq.SetAddressFamily("ONLY_V4");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetIpResolve(task->curlHandle_));
}

HWTEST_F(HttpClientTaskTest, SetIpResolveTest003, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    httpReq.SetAddressFamily("ONLY_V6");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetIpResolve(task->curlHandle_));
}

HWTEST_F(HttpClientTaskTest, SetIpResolveTest004, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    httpReq.SetAddressFamily("UNKNOWN_FAMILY");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetIpResolve(task->curlHandle_));
}

HWTEST_F(HttpClientTaskTest, MethodForPostPatchTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->MethodForPost(HttpConstant::HTTP_METHOD_PATCH));
    EXPECT_TRUE(task->MethodForPost(HttpConstant::HTTP_METHOD_POST));
    EXPECT_TRUE(task->MethodForPost(HttpConstant::HTTP_METHOD_PUT));
    EXPECT_TRUE(task->MethodForPost(HttpConstant::HTTP_METHOD_DELETE));
    EXPECT_FALSE(task->MethodForPost(""));
    EXPECT_FALSE(task->MethodForPost(HttpConstant::HTTP_METHOD_GET));
}

HWTEST_F(HttpClientTaskTest, GetSizeFromCurlPatchTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    httpReq.SetMethod(HttpConstant::HTTP_METHOD_PATCH);
    std::string body = "patch-body";
    httpReq.ReplaceBody(body.c_str(), body.size());
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_GE(task->GetSizeFromCurl(task->curlHandle_), 0);
}

HWTEST_F(HttpClientTaskTest, GetSizeFromCurlPatchTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    httpReq.SetMethod(HttpConstant::HTTP_METHOD_GET);
    std::string body = "get-body";
    httpReq.ReplaceBody(body.c_str(), body.size());
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_GE(task->GetSizeFromCurl(task->curlHandle_), 0);
}

HWTEST_F(HttpClientTaskTest, GetSizeFromCurlPatchTest003, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    httpReq.SetMethod(HttpConstant::HTTP_METHOD_PUT);
    std::string filePath = "/bin/who";
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq, UPLOAD, filePath);
    ASSERT_NE(task, nullptr);

    EXPECT_GE(task->GetSizeFromCurl(task->curlHandle_), 0);
}

HWTEST_F(HttpClientTaskTest, GetTlsVersionAndCipherSuiteTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("https://www.baidu.com");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    CURL *curlHandle = task->curlHandle_;
    task->curlHandle_ = nullptr;
    auto result = task->GetTlsVersionAndCipherSuite();
    task->curlHandle_ = curlHandle;
    ASSERT_NE(task->curlHandle_, nullptr);

    EXPECT_EQ(result.first, TlsVersion::DEFAULT);
    EXPECT_EQ(result.second, CipherSuite::INVALID);
}

HWTEST_F(HttpClientTaskTest, GetTlsVersionAndCipherSuiteTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("https://www.baidu.com");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    auto result = task->GetTlsVersionAndCipherSuite();
    EXPECT_EQ(result.first, TlsVersion::DEFAULT);
    EXPECT_EQ(result.second, CipherSuite::INVALID);
}

HWTEST_F(HttpClientTaskTest, ProcessConnectionExtraInfoTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    CURL *curlHandle = task->curlHandle_;
    task->curlHandle_ = nullptr;
    task->ProcessConnectionExtraInfo();
    task->curlHandle_ = curlHandle;
    ASSERT_NE(task->curlHandle_, nullptr);

    EXPECT_TRUE(task->GetResponse().GetExtraInfoItem(HttpConstant::PARAM_KEY_IS_CACHE_HIT, "").empty());
}

HWTEST_F(HttpClientTaskTest, ProcessConnectionExtraInfoTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    task->ProcessConnectionExtraInfo();
    EXPECT_EQ(task->GetResponse().GetExtraInfoItem(HttpConstant::PARAM_KEY_NETWORK_PROTOCOL_NAME, ""),
        "Unknown/Non-HTTP");
    EXPECT_EQ(task->GetResponse().GetExtraInfoItem(HttpConstant::PARAM_KEY_IS_CACHE_HIT, ""), "false");
    EXPECT_EQ(task->GetResponse().GetExtraInfoItem(HttpConstant::PARAM_KEY_IS_PROXY_CONNECTION, ""), "false");
    EXPECT_EQ(task->GetResponse().GetExtraInfoItem(HttpConstant::PARAM_KEY_IS_REUSED_CONNECTION, ""), "true");
    EXPECT_FALSE(task->GetResponse().GetExtraInfoItem(HttpConstant::PARAM_KEY_REDIRECT_COUNT, "").empty());
}

HWTEST_F(HttpClientTaskTest, SetDnsOptionTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetDnsOption(task->curlHandle_));
}

HWTEST_F(HttpClientTaskTest, SetDnsOptionTest003, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    std::vector<std::string> dnsServers = { "http://dns.xtstest1.com/dns-query", "" };
    httpReq.SetDNSServers(dnsServers);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetDnsOption(task->curlHandle_));
}

HWTEST_F(HttpClientTaskTest, SetDnsOptionTest004, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    std::vector<std::string> dnsServers = { "1.1.1.1", "8.8.8.8", "2.2.2.2", "3.3.3.3", "not-ip" };
    httpReq.SetDNSServers(dnsServers);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetDnsOption(task->curlHandle_));
}

HWTEST_F(HttpClientTaskTest, SetDnsOptionTest005, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    std::vector<std::string> dnsServers = { "::1", "8.8.8.8" };
    httpReq.SetDNSServers(dnsServers);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetDnsOption(task->curlHandle_));
}

HWTEST_F(HttpClientTaskTest, SetSslTypeAndClientEncCertTlcpTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("https://www.baidu.com");
    httpReq.SetSslType(SslType::TLCP);
    httpReq.SetCaPath("/etc/ssl/certs/ca.pem");
    HttpClientCert encCert;
    encCert.certPath = "/data/enc.pem";
    encCert.keyPath = "/data/enc.key";
    encCert.certType = "PEM";
    encCert.keyPassword.assign("password");
    httpReq.SetClientEncCert(encCert);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetSslTypeAndClientEncCert(task->curlHandle_));
}

HWTEST_F(HttpClientTaskTest, SetSslTypeAndClientEncCertTlcpTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("https://www.baidu.com");
    httpReq.SetSslType(SslType::TLCP);
    HttpClientCert encCert;
    encCert.certPath = "/data/enc.pem";
    httpReq.SetClientEncCert(encCert);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetSslTypeAndClientEncCert(task->curlHandle_));
}

constexpr const char *TEST_CA_CERT_PEM = R"pem(-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIUZqex0hG/EpGemxPP6DRu3By31NcwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQTmV0c3RhY2sgVGVzdCBDQTAeFw0yNjEwMTkwMjU1MjZa
Fw0zNjEwMTYwMjU1MjZaMBsxGTAXBgNVBAMMEE5ldHN0YWNrIFRlc3QgQ0EwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCrQlhJIwYcz+9BRQnSTLU7bbWg
Lhbji69KnzwPhYzJ7iZtBe0rWAQu83wPjNi2MFvN4iTCbtKpJSwrZyRui1gm/P1P
7JeMdJAoRfAfiBSktEMxzI3R4B1znFWCxWUyrS1rBlxVi6l5bWLI2sLb3KasPV9b
FFmCmduOqx1kE5ugV9P2PJwUMRkIFb8zZ6ZdPmiPT0L+XrM0Xc5f6g3snAuOPJ01
Q2X5+HigsvKDTcuXJkdX2IVvlRHSOpdNvaDyMki4ul2V4Vl0mciua6amJ2NtFjcY
/FViENv+5ZDsOODPwkNlLu5ewnlRsX1Omp7YPOg48sWDPlY0eoROsOqE1E+dAgMB
AAGjUzBRMB0GA1UdDgQWBBS52jrxHdwEz9u3jsQwRO+55InKqzAfBgNVHSMEGDAW
gBS52jrxHdwEz9u3jsQwRO+55InKqzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3
DQEBCwUAA4IBAQCh+QrvGp+DN1D9XqzLa1B4OUDBEeRxzt7N9oEa7/rOKwWRL3CI
Hc/WzJWJDRGlsypoe9b1ZZH8qtTiUxkuqSSfYSBomsT3n5qBJorD6zCe6K3TR55Q
fuTuPHjzDoyYEzb24h0Kvw7zUaExB58C5KFzRoqmR1MbzZiUIMihkskkxHCeJ6qq
n49TudxhTBqm8BDh5mPuJDC0LGDtti8ii2DDcnic42tQzPEOdRsY6NVq4WSPYWaf
4C0x87s8q9t3CPbNn1wN0SAFAuPVIb98TKWOiqdBn1ENaQAOxWwsKnE92LxvUmCv
TznV7u6wmf3e3OKHYxvm+3ZxjaQ96jy7v9/m
-----END CERTIFICATE-----
)pem";

constexpr const char *TEST_CA_CRL_PEM = R"pem(-----BEGIN X509 CRL-----
MIIBdDBeAgEBMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAMMEE5ldHN0YWNrIFRl
c3QgQ0EXDTI2MTAxOTAyNTUyNloXDTI2MTExODAyNTUyNlqgDzANMAsGA1UdFAQE
AgIQADANBgkqhkiG9w0BAQsFAAOCAQEAKPRmm7eOdp3pZVb6TpjPwj08/gfItbNI
gx9gj3Y/8z6tg6Ub8Qkh9QduW8/3sAKMOL5i2cFhWO2NNYWC8wNXcxX7fmNStGu8
mJtU2VpF+l2bD10lnttwMS2SRBg1c8GvAH6vBuT4v/tqqhSg18F40WXwFjWhYJ0o
VjYybXDAc8P5hxi0qj2pEXPjMl1DCyUmNkyRl+a1S0/lijb7usKFhZphdtAgH+94
Y+vG0uF8snc6Rqzr+FXypzfQcyimH1rVCYgkCt8kBjABPlp/MryPN72gofjdvQJh
0PYrtR5mTJIPzGuuQk1TmhJycIy0YvIyO6us4tniV5Jhk6DfocMskw==
-----END X509 CRL-----
)pem";

std::string BuildValidCaData()
{
    return std::string(TEST_CA_CERT_PEM) + TEST_CA_CRL_PEM;
}

HWTEST_F(HttpClientTaskTest, MultiPathSslCtxFunctionTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("https://www.baidu.com");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_EQ(task->MultiPathSslCtxFunction(nullptr, nullptr), CURLE_SSL_CERTPROBLEM);
}

HWTEST_F(HttpClientTaskTest, MultiPathSslCtxFunctionTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("https://www.baidu.com");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    SSL_CTX *sslCtx = SSL_CTX_new(TLS_client_method());
    ASSERT_NE(sslCtx, nullptr);
    EXPECT_EQ(task->MultiPathSslCtxFunction(nullptr, sslCtx), CURLE_OK);
    SSL_CTX_free(sslCtx);
}

HWTEST_F(HttpClientTaskTest, MultiPathSslCtxFunctionTest003, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("https://www.baidu.com");
    httpReq.SetCaData("not-a-valid-pem-certificate");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    SSL_CTX *sslCtx = SSL_CTX_new(TLS_client_method());
    ASSERT_NE(sslCtx, nullptr);
    EXPECT_EQ(task->MultiPathSslCtxFunction(nullptr, sslCtx), CURLE_SSL_CACERT_BADFILE);
    SSL_CTX_free(sslCtx);
}

HWTEST_F(HttpClientTaskTest, MultiPathSslCtxFunctionTest004, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("https://www.baidu.com");
    httpReq.SetCaData(BuildValidCaData());
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    SSL_CTX *sslCtx = SSL_CTX_new(TLS_client_method());
    ASSERT_NE(sslCtx, nullptr);
    EXPECT_EQ(task->MultiPathSslCtxFunction(nullptr, sslCtx), CURLE_OK);
    SSL_CTX_free(sslCtx);
}

HWTEST_F(HttpClientTaskTest, MultiPathSslCtxFunctionTest005, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("https://www.baidu.com");
    httpReq.SetCanSkipCertVerifyFlag(true);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    SSL_CTX *sslCtx = SSL_CTX_new(TLS_client_method());
    ASSERT_NE(sslCtx, nullptr);
    EXPECT_EQ(task->MultiPathSslCtxFunction(nullptr, sslCtx), CURLE_OK);
    SSL_CTX_free(sslCtx);
}

HWTEST_F(HttpClientTaskTest, SslCtxFunctionWithValidationTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("https://www.baidu.com");
    httpReq.SetValidationCallback([](const std::vector<std::string> &, const std::string &, const std::string &) {
        return true;
    });
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_EQ(task->SslCtxFunction(nullptr, nullptr), CURLE_SSL_CERTPROBLEM);

    SSL_CTX *sslCtx = SSL_CTX_new(TLS_client_method());
    ASSERT_NE(sslCtx, nullptr);
    EXPECT_EQ(task->SslCtxFunction(nullptr, sslCtx), CURLE_OK);
    SSL_CTX_free(sslCtx);
}

HWTEST_F(HttpClientTaskTest, SslCtxFunctionWithoutValidationTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("https://www.baidu.com");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_EQ(task->SslCtxFunction(nullptr, nullptr), CURLE_SSL_CERTPROBLEM);
}

HWTEST_F(HttpClientTaskTest, SslCtxFunctionTest003, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("https://www.baidu.com");
    std::string pin = std::string("sha256//") + std::string(44, 'A');
    httpReq.SetPinnedPubkey(pin);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    SSL_CTX *sslCtx = SSL_CTX_new(TLS_client_method());
    ASSERT_NE(sslCtx, nullptr);
    EXPECT_EQ(task->SslCtxFunction(nullptr, sslCtx), CURLE_OK);
    SSL_CTX_free(sslCtx);
}

HWTEST_F(HttpClientTaskTest, VerifyRootCaSslCtxFunctionTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("https://www.baidu.com");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_EQ(task->VerifyRootCaSslCtxFunction(nullptr, nullptr), CURLE_SSL_CERTPROBLEM);

    SSL_CTX *sslCtx = SSL_CTX_new(TLS_client_method());
    ASSERT_NE(sslCtx, nullptr);
    EXPECT_EQ(task->VerifyRootCaSslCtxFunction(nullptr, sslCtx), CURLE_OK);
    SSL_CTX_free(sslCtx);
}

HWTEST_F(HttpClientTaskTest, SetPinnedPubkeyOptionTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("https://www.baidu.com");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetPinnedPubkeyOption(task->curlHandle_, "www.baidu.com"));
}

#if HAS_NETMANAGER_BASE
HWTEST_F(HttpClientTaskTest, SetPinnedPubkeyOptionTest002, TestSize.Level2)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("https://www.pin-example.com");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    auto configInstance = OHOS::NetManagerStandard::NetworkSecurityConfig::GetInstance();
    OHOS::NetManagerStandard::DomainConfig config = {};
    OHOS::NetManagerStandard::Domain domain;
    domain.domainName_ = "www.pin-example.com";
    domain.includeSubDomains_ = false;
    config.domains_.push_back(domain);
    config.pinSet_.isOpenMode = true;
    config.pinSet_.shouldVerifyRootCa_ = true;
    OHOS::NetManagerStandard::Pin pin;
    pin.digestAlgorithm_ = "sha256";
    pin.digest_ = "TEST";
    config.pinSet_.pins_.push_back(pin);
    configInstance.domainConfigs_.push_back(config);

    EXPECT_TRUE(task->SetPinnedPubkeyOption(task->curlHandle_, "www.pin-example.com"));
    EXPECT_EQ(task->GetRequest().GetPinnedPubkey(), "sha256//TEST");
    configInstance.domainConfigs_.pop_back();
}
#endif

HWTEST_F(HttpClientTaskTest, SetSslCtxFunctionOptionTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("https://www.baidu.com");
    httpReq.SetSslType(SslType::TLS);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetSslCtxFunctionOption(task->curlHandle_));
}

HWTEST_F(HttpClientTaskTest, SetSslCtxFunctionOptionTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("https://www.baidu.com");
    httpReq.SetSslType(SslType::TLCP);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetSslCtxFunctionOption(task->curlHandle_));
}

HWTEST_F(HttpClientTaskTest, SetServerSSLCertOptionTest004, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("https://www.baidu.com");
    httpReq.SetCanSkipCertVerifyFlag(true);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetServerSSLCertOption(task->curlHandle_));
}

HWTEST_F(HttpClientTaskTest, SetServerSSLCertOptionTest005, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("https://www.baidu.com");
    httpReq.SetValidationCallback([](const std::vector<std::string> &, const std::string &, const std::string &) {
        return true;
    });
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetServerSSLCertOption(task->curlHandle_));
}

HWTEST_F(HttpClientTaskTest, SetServerSSLCertOptionTest006, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("https://www.baidu.com");
    httpReq.SetPartialChain(true);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetServerSSLCertOption(task->curlHandle_));
}

HWTEST_F(HttpClientTaskTest, SetServerSSLCertOptionTest007, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("https://www.baidu.com");
    httpReq.SetPartialChain(false);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_EQ(task->GetRequest().GetPartialChain(), 0);
    EXPECT_TRUE(task->SetServerSSLCertOption(task->curlHandle_));
}

HWTEST_F(HttpClientTaskTest, SetSSLCertOptionTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("https://www.baidu.com");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_FALSE(task->SetSSLCertOption(task->curlHandle_));
}

HWTEST_F(HttpClientTaskTest, SetSSLCertOptionTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("https://www.baidu.com");
    HttpClientCert clientCert;
    clientCert.certPath = "/etc/ssl/certs/client.pem";
    clientCert.keyPath = "/etc/ssl/private/client.key";
    clientCert.certType = "PEM";
    clientCert.keyPassword.assign("password");
    httpReq.SetClientCert(clientCert);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetSSLCertOption(task->curlHandle_));
}

HWTEST_F(HttpClientTaskTest, SetSSLCertOptionTest003, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("https://www.baidu.com");
    httpReq.SetCanSkipCertVerifyFlag(true);
    HttpClientCert clientCert;
    clientCert.certPath = "/etc/ssl/certs/client.pem";
    httpReq.SetClientCert(clientCert);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetSSLCertOption(task->curlHandle_));
}

#ifdef HTTP_ONLY_VERIFY_ROOT_CA_ENABLE
HWTEST_F(HttpClientTaskTest, SetSSLCertOptionTest004, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("https://www.baidu.com");
    httpReq.SetValidationCallback([](const std::vector<std::string> &, const std::string &, const std::string &) {
        return true;
    });
    HttpClientCert clientCert;
    clientCert.certPath = "/etc/ssl/certs/client.pem";
    httpReq.SetClientCert(clientCert);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetSSLCertOption(task->curlHandle_));
}
#endif

HWTEST_F(HttpClientTaskTest, SetCurlOptionsTest011, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    task->GetRequest().SetSniHostName("www.example.com");
    task->GetRequest().SetMaxRedirects(3);
    EXPECT_TRUE(task->SetCurlOptions());
}

HWTEST_F(HttpClientTaskTest, SetCurlOptionsTest012, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    task->GetRequest().SetReuseConnections(false);
    task->GetRequest().SetInactivityMs(5000);
    EXPECT_TRUE(task->SetCurlOptions());
}

HWTEST_F(HttpClientTaskTest, SetCurlOptionsTest013, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    task->GetRequest().SetPathPreference(PathPreference::primaryCellular);
    EXPECT_TRUE(task->SetCurlOptions());
}

HWTEST_F(HttpClientTaskTest, SetCurlOptionsTest014, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("https://www.baidu.com");
    httpReq.SetPartialChain(true);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetCurlOptions());
}

HWTEST_F(HttpClientTaskTest, SetCurlOptionsTest015, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    task->GetRequest().method_ = "UNSUPPORTED_METHOD";
    EXPECT_FALSE(task->SetCurlOptions());
}

HWTEST_F(HttpClientTaskTest, SetCurlMethodTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    httpReq.SetMethod(HttpConstant::HTTP_METHOD_POST);
    std::string body = "body-content";
    httpReq.ReplaceBody(body.c_str(), body.size());
    httpReq.SetBodyOrQueryConfigured(true);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetCurlMethod());
}

HWTEST_F(HttpClientTaskTest, SetCurlMethodTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    httpReq.SetMethod(HttpConstant::HTTP_METHOD_GET);
    std::string body = "get-body";
    httpReq.ReplaceBody(body.c_str(), body.size());
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetCurlMethod());
}

HWTEST_F(HttpClientTaskTest, SetCurlMethodTest003, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    httpReq.SetMethod(HttpConstant::HTTP_METHOD_HEAD);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetCurlMethod());
}

HWTEST_F(HttpClientTaskTest, SetCurlMethodTest004, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    std::string body = "empty-method-body";
    httpReq.ReplaceBody(body.c_str(), body.size());
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetCurlMethod());
}

HWTEST_F(HttpClientTaskTest, SetCurlMethodTest005, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    httpReq.SetMethod(HttpConstant::HTTP_METHOD_PATCH);
    std::string body = "patch-body";
    httpReq.ReplaceBody(body.c_str(), body.size());
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetCurlMethod());
}

HWTEST_F(HttpClientTaskTest, SetCurlMethodTest006, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/put");
    httpReq.SetMethod(HttpConstant::HTTP_METHOD_PUT);
    std::string filePath = "/bin/who";
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq, UPLOAD, filePath);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetCurlMethod());
}

HWTEST_F(HttpClientTaskTest, SetCurlMethodTest007, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    task->GetRequest().method_ = "UNSUPPORTED_METHOD";
    EXPECT_FALSE(task->SetCurlMethod());
}

HWTEST_F(HttpClientTaskTest, BuildUrlWithQueryParamsTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    std::string originUrl = task->GetRequest().GetURL();
    task->BuildUrlWithQueryParams();
    EXPECT_EQ(task->GetRequest().GetURL(), originUrl);
}

HWTEST_F(HttpClientTaskTest, BuildUrlWithQueryParamsTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EscapedData queryParams = { .dataType = HttpDataType::NO_DATA_TYPE, .data = "a=1" };
    task->GetRequest().SetQueryParams(queryParams);
    task->BuildUrlWithQueryParams();
    EXPECT_EQ(task->GetRequest().GetURL(), "http://www.httpbin.org/get");
}

HWTEST_F(HttpClientTaskTest, BuildUrlWithQueryParamsTest003, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get?existing=1");
    EscapedData queryParams = { .dataType = HttpDataType::STRING, .data = "a=1&b=2" };
    httpReq.SetQueryParams(queryParams);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    task->BuildUrlWithQueryParams();
    auto url = task->GetRequest().GetURL();
    EXPECT_NE(url.find("existing=1"), std::string::npos);
    EXPECT_NE(url.find("a=1&b=2"), std::string::npos);
}

HWTEST_F(HttpClientTaskTest, BuildUrlWithQueryParamsTest004, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    std::string json = R"({"name":"value","age":25,"is_student":true,"optional_field":null})";
    EscapedData queryParams = { .dataType = HttpDataType::OBJECT, .data = json };
    httpReq.SetQueryParams(queryParams);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    task->BuildUrlWithQueryParams();
    auto url = task->GetRequest().GetURL();
    EXPECT_NE(url.find("name=value"), std::string::npos);
    EXPECT_NE(url.find("age=25"), std::string::npos);
    EXPECT_NE(url.find("is_student=true"), std::string::npos);
    EXPECT_NE(url.find("optional_field"), std::string::npos);
}

HWTEST_F(HttpClientTaskTest, BuildUrlWithQueryParamsTest005, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    EscapedData queryParams = { .dataType = HttpDataType::OBJECT, .data = "not-a-json" };
    httpReq.SetQueryParams(queryParams);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    task->BuildUrlWithQueryParams();
    EXPECT_EQ(task->GetRequest().GetURL(), "http://www.httpbin.org/get");
}

HWTEST_F(HttpClientTaskTest, BuildUrlWithQueryParamsTest006, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    EscapedData queryParams = { .dataType = HttpDataType::OBJECT, .data = "" };
    httpReq.SetQueryParams(queryParams);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    task->BuildUrlWithQueryParams();
    EXPECT_EQ(task->GetRequest().GetURL(), "http://www.httpbin.org/get");
}

HWTEST_F(HttpClientTaskTest, ParseJsonValueToQueryParamsTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->ParseJsonValueToQueryParams("not-a-json").empty());
    EXPECT_TRUE(task->ParseJsonValueToQueryParams("[1,2,3]").empty());
}

HWTEST_F(HttpClientTaskTest, ParseJsonValueToQueryParamsTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    std::string json = R"({"tags":["a","b"],"count":3,"empty":[]})";
    std::string result = task->ParseJsonValueToQueryParams(json);
    EXPECT_NE(result.find("tags=a"), std::string::npos);
    EXPECT_NE(result.find("tags=b"), std::string::npos);
    EXPECT_NE(result.find("count=3"), std::string::npos);
}

HWTEST_F(HttpClientTaskTest, ParseJsonValueToQueryParamsTest003, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    std::string json = R"({"a b":"c d"})";
    std::string result = task->ParseJsonValueToQueryParams(json);
    EXPECT_FALSE(result.empty());
    EXPECT_TRUE(task->GetRequest().GetHeaders().count(HttpConstant::HTTP_CONTENT_TYPE) > 0);
}

HWTEST_F(HttpClientTaskTest, ProcessQueryParamValueTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    std::string params;
    cJSON *nullValue = cJSON_CreateNull();
    ASSERT_NE(nullValue, nullptr);
    task->ProcessQueryParamValue("nullField", false, nullValue, params);
    cJSON_Delete(nullValue);
    EXPECT_NE(params.find(std::string("nullField") + HttpConstant::HTTP_URL_PARAM_SEPARATOR), std::string::npos);

    params.clear();
    cJSON *trueValue = cJSON_CreateTrue();
    ASSERT_NE(trueValue, nullptr);
    task->ProcessQueryParamValue("trueField", false, trueValue, params);
    cJSON_Delete(trueValue);
    EXPECT_NE(params.find("trueField=true"), std::string::npos);

    params.clear();
    cJSON *falseValue = cJSON_CreateFalse();
    ASSERT_NE(falseValue, nullptr);
    task->ProcessQueryParamValue("falseField", false, falseValue, params);
    cJSON_Delete(falseValue);
    EXPECT_NE(params.find("falseField=false"), std::string::npos);

    params.clear();
    cJSON *numberValue = cJSON_CreateNumber(25);
    ASSERT_NE(numberValue, nullptr);
    task->ProcessQueryParamValue("numberField", false, numberValue, params);
    cJSON_Delete(numberValue);
    EXPECT_NE(params.find("numberField=25"), std::string::npos);

    params.clear();
    cJSON *stringValue = cJSON_CreateString("a b");
    ASSERT_NE(stringValue, nullptr);
    task->ProcessQueryParamValue("stringField", false, stringValue, params);
    cJSON_Delete(stringValue);
    EXPECT_TRUE(task->GetRequest().GetHeaders().count(HttpConstant::HTTP_CONTENT_TYPE) > 0);
}

HWTEST_F(HttpClientTaskTest, ProcessQueryParamValueTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    cJSON *objectValue = cJSON_CreateObject();
    ASSERT_NE(objectValue, nullptr);
    std::string params;
    task->ProcessQueryParamValue("objectField", false, objectValue, params);
    cJSON_Delete(objectValue);
    EXPECT_TRUE(params.empty());

    cJSON *stringValue = cJSON_CreateString("value");
    ASSERT_NE(stringValue, nullptr);
    task->ProcessQueryParamValue("a b", true, stringValue, params);
    cJSON_Delete(stringValue);
    EXPECT_FALSE(params.empty());
    EXPECT_TRUE(task->GetRequest().GetHeaders().count(HttpConstant::HTTP_CONTENT_TYPE) > 0);
}

HWTEST_F(HttpClientTaskTest, ReadResopnseFromCacheTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://nonexistenturl:8080");
    httpReq.SetUsingCache(true);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);
    EXPECT_FALSE(task->ReadResopnseFromCache());
}

HWTEST_F(HttpClientTaskTest, ProgressCallbackCanceledTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    bool progressCalled = false;
    task->OnProgress([&progressCalled](const HttpClientRequest &, u_long, u_long, u_long, u_long) {
        progressCalled = true;
    });
    task->Cancel();
    EXPECT_EQ(task->ProgressCallback(task.get(), 100, 10, 0, 0), 0);
    EXPECT_FALSE(progressCalled);
}

HWTEST_F(HttpClientTaskTest, ProgressCallbackCanceledTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    bool progressCalled = false;
    task->OnProgress([&progressCalled](const HttpClientRequest &, u_long, u_long, u_long, u_long) {
        progressCalled = true;
    });
    EXPECT_EQ(task->ProgressCallback(task.get(), 100, 10, 0, 0), 0);
    EXPECT_TRUE(progressCalled);
}

#if HAS_NETMANAGER_BASE
HWTEST_F(HttpClientTaskTest, GetInterfaceNameTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    std::string interfaceName;
    int32_t netId = 0;
    EXPECT_FALSE(task->GetInterfaceName(nullptr, interfaceName, netId));
}

HWTEST_F(HttpClientTaskTest, GetInterfaceNameTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    std::string interfaceName;
    int32_t netId = 0;
    EXPECT_FALSE(task->GetInterfaceName(task->curlHandle_, interfaceName, netId));
}

HWTEST_F(HttpClientTaskTest, SetInterfaceTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_FALSE(task->SetInterface(nullptr));
}

HWTEST_F(HttpClientTaskTest, SetInterfaceTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    httpReq.SetPathPreference(PathPreference::secondaryCellular);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    task->SetInterface(task->curlHandle_);
    EXPECT_EQ(task->GetRequest().GetPathPreference(), PathPreference::secondaryCellular);
}

HWTEST_F(HttpClientTaskTest, GetNetStatusTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    std::list<OHOS::sptr<OHOS::NetManagerStandard::NetHandle>> netList;
    std::list<OHOS::sptr<OHOS::NetManagerStandard::NetHandle>> cellularNetworks;
    uint8_t cellCount = 0;
    uint8_t wifiCount = 0;
    EXPECT_FALSE(task->GetNetStatus(netList, cellularNetworks, cellCount, wifiCount));
}

HWTEST_F(HttpClientTaskTest, GetNetStatusTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    std::list<OHOS::sptr<OHOS::NetManagerStandard::NetHandle>> netList;
    netList.push_back(nullptr);
    netList.push_back(nullptr);
    std::list<OHOS::sptr<OHOS::NetManagerStandard::NetHandle>> cellularNetworks;
    uint8_t cellCount = 0;
    uint8_t wifiCount = 0;
    EXPECT_TRUE(task->GetNetStatus(netList, cellularNetworks, cellCount, wifiCount));
    EXPECT_EQ(cellCount, 0);
    EXPECT_EQ(wifiCount, 0);
    EXPECT_TRUE(cellularNetworks.empty());
}

HWTEST_F(HttpClientTaskTest, GetPrimaryCellularInterfaceTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    std::list<OHOS::sptr<OHOS::NetManagerStandard::NetHandle>> netList;
    std::string interfaceName;
    int32_t netId = 0;
    EXPECT_FALSE(task->GetPrimaryCellularInterface(nullptr, netList, interfaceName, netId));
    EXPECT_FALSE(task->GetPrimaryCellularInterface(task->curlHandle_, netList, interfaceName, netId));
}

HWTEST_F(HttpClientTaskTest, GetPrimaryCellularInterfaceTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    std::list<OHOS::sptr<OHOS::NetManagerStandard::NetHandle>> netList;
    netList.push_back(nullptr);
    netList.push_back(nullptr);
    std::string interfaceName;
    int32_t netId = 0;
    EXPECT_FALSE(task->GetPrimaryCellularInterface(task->curlHandle_, netList, interfaceName, netId));
    EXPECT_TRUE(interfaceName.empty());
}

HWTEST_F(HttpClientTaskTest, GetSecondaryCellularInterfaceTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    std::list<OHOS::sptr<OHOS::NetManagerStandard::NetHandle>> netList;
    std::string interfaceName;
    int32_t netId = 0;
    EXPECT_FALSE(task->GetSecondaryCellularInterface(nullptr, netList, interfaceName, netId));
    EXPECT_FALSE(task->GetSecondaryCellularInterface(task->curlHandle_, netList, interfaceName, netId));
}

HWTEST_F(HttpClientTaskTest, GetSecondaryCellularInterfaceTest002, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    std::list<OHOS::sptr<OHOS::NetManagerStandard::NetHandle>> netList;
    netList.push_back(nullptr);
    netList.push_back(nullptr);
    std::string interfaceName;
    int32_t netId = 0;
    EXPECT_FALSE(task->GetSecondaryCellularInterface(task->curlHandle_, netList, interfaceName, netId));
    EXPECT_TRUE(interfaceName.empty());
}

HWTEST_F(HttpClientTaskTest, GetNetStatusTest003, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    std::list<OHOS::sptr<OHOS::NetManagerStandard::NetHandle>> netList;
    netList.push_back(new OHOS::NetManagerStandard::NetHandle());
    netList.push_back(new OHOS::NetManagerStandard::NetHandle());
    std::list<OHOS::sptr<OHOS::NetManagerStandard::NetHandle>> cellularNetworks;
    uint8_t cellCount = 0;
    uint8_t wifiCount = 0;
    EXPECT_TRUE(task->GetNetStatus(netList, cellularNetworks, cellCount, wifiCount));
    EXPECT_EQ(cellCount, 0);
    EXPECT_EQ(wifiCount, 0);
    EXPECT_TRUE(cellularNetworks.empty());
}

#endif

#if defined(HTTP_MULTIPATH_CERT_ENABLE) || defined(HTTP_ONLY_VERIFY_ROOT_CA_ENABLE)
HWTEST_F(HttpClientTaskTest, LocalTlsConnectionExtraInfoTest001, TestSize.Level1)
{
    HttpTlsTestServer server;
    ASSERT_TRUE(server.Start());
    HttpClientRequest httpReq;
    httpReq.SetURL(BuildLocalTlsUrl(server.GetPort()));
    httpReq.SetCanSkipCertVerifyFlag(true);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    auto shareHandle = CreateCookieShareHandle();
    ASSERT_NE(shareHandle, nullptr);
    task->SetCookieShareHandle(shareHandle);

    ASSERT_EQ(curl_easy_perform(task->GetCurlHandle()), CURLE_OK);
    task->ProcessConnectionExtraInfo();
    const HttpClientResponse &response = task->GetResponse();
    EXPECT_EQ(response.GetResult(), "OK");
    EXPECT_EQ(response.GetExtraInfoItem(HttpConstant::PARAM_KEY_NETWORK_PROTOCOL_NAME, ""), "HTTP/1.1");
    EXPECT_EQ(response.GetExtraInfoItem(HttpConstant::PARAM_KEY_REMOTE_ADDRESS, ""), TEST_TLS_HOST);
    EXPECT_EQ(response.GetExtraInfoItem(HttpConstant::PARAM_KEY_REMOTE_PORT, ""), std::to_string(server.GetPort()));
    EXPECT_FALSE(response.GetExtraInfoItem(HttpConstant::PARAM_KEY_LOCAL_ADDRESS, "").empty());
    EXPECT_FALSE(response.GetExtraInfoItem(HttpConstant::PARAM_KEY_LOCAL_PORT, "").empty());
    EXPECT_TRUE(response.GetExtraInfoItem(HttpConstant::PARAM_KEY_TLS_VERSION, "") == "TLS_V_1_3" ||
        response.GetExtraInfoItem(HttpConstant::PARAM_KEY_TLS_VERSION, "") == "TLS_V_1_2");
    EXPECT_FALSE(response.GetExtraInfoItem(HttpConstant::PARAM_KEY_CIPHER_SUITE, "").empty());
    EXPECT_EQ(response.GetExtraInfoItem(HttpConstant::PARAM_KEY_REDIRECT_COUNT, ""), "0");
    EXPECT_EQ(response.GetExtraInfoItem(HttpConstant::PARAM_KEY_IS_PROXY_CONNECTION, ""), "false");
    EXPECT_EQ(response.GetExtraInfoItem(HttpConstant::PARAM_KEY_IS_CACHE_HIT, ""), "false");
}

HWTEST_F(HttpClientTaskTest, CurlShareLockNullUserdataTest001, TestSize.Level1)
{
    HttpTlsTestServer server;
    ASSERT_TRUE(server.Start());
    HttpClientRequest httpReq;
    httpReq.SetURL(BuildLocalTlsUrl(server.GetPort()));
    httpReq.SetCanSkipCertVerifyFlag(true);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    auto shareHandle = CreateCookieShareHandle();
    ASSERT_NE(shareHandle, nullptr);
    ASSERT_EQ(curl_share_setopt(shareHandle->Get(), CURLSHOPT_USERDATA, nullptr), CURLSHE_OK);
    task->SetCookieShareHandle(shareHandle);

    ASSERT_EQ(curl_easy_perform(task->GetCurlHandle()), CURLE_OK);
    EXPECT_EQ(task->GetResponse().GetResult(), "OK");
}

HWTEST_F(HttpClientTaskTest, LocalTlsConnectionExtraInfoTest002, TestSize.Level1)
{
    HttpTlsTestServer server;
    ASSERT_TRUE(server.Start());
    HttpClientRequest httpReq;
    httpReq.SetURL(BuildLocalTlsUrl(server.GetPort()));
    httpReq.SetCanSkipCertVerifyFlag(true);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    ASSERT_EQ(curl_easy_setopt(task->GetCurlHandle(), CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2), CURLE_OK);
    ASSERT_EQ(curl_easy_perform(task->GetCurlHandle()), CURLE_OK);
    EXPECT_EQ(task->GetResponse().GetExtraInfoItem(HttpConstant::PARAM_KEY_TLS_VERSION, ""), "TLS_V_1_2");
}

HWTEST_F(HttpClientTaskTest, LocalHttpVersionExtraInfoTest001, TestSize.Level1)
{
    HttpTlsTestServer server;
    server.SetResponse("HTTP/1.0 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK");
    ASSERT_TRUE(server.Start());
    HttpClientRequest httpReq;
    httpReq.SetURL(BuildLocalTlsUrl(server.GetPort()));
    httpReq.SetCanSkipCertVerifyFlag(true);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    ASSERT_EQ(curl_easy_perform(task->GetCurlHandle()), CURLE_OK);
    task->ProcessConnectionExtraInfo();
    const HttpClientResponse &response = task->GetResponse();
    EXPECT_EQ(response.GetResult(), "OK");
    EXPECT_EQ(response.GetExtraInfoItem(HttpConstant::PARAM_KEY_NETWORK_PROTOCOL_NAME, ""), "HTTP/1.0");
}

HWTEST_F(HttpClientTaskTest, LocalHttp2VersionExtraInfoTest001, TestSize.Level1)
{
    if ((curl_version_info(CURLVERSION_NOW)->features & CURL_VERSION_HTTP2) == 0) {
        GTEST_SKIP() << "libcurl has no HTTP/2 support";
    }
    HttpTlsTestServer server;
    server.SetHttp2(true);
    ASSERT_TRUE(server.Start());
    HttpClientRequest httpReq;
    httpReq.SetURL(BuildLocalTlsUrl(server.GetPort()));
    httpReq.SetCanSkipCertVerifyFlag(true);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);
    ASSERT_EQ(curl_easy_setopt(task->GetCurlHandle(), CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0), CURLE_OK);

    ASSERT_EQ(curl_easy_perform(task->GetCurlHandle()), CURLE_OK);
    task->ProcessConnectionExtraInfo();
    EXPECT_EQ(task->GetResponse().GetExtraInfoItem(HttpConstant::PARAM_KEY_NETWORK_PROTOCOL_NAME, ""), "HTTP/2");
}
#endif

#ifdef HTTP_ONLY_VERIFY_ROOT_CA_ENABLE
HWTEST_F(HttpClientTaskTest, CustomValidationCallbackTest001, TestSize.Level1)
{
    HttpTlsTestServer server;
    ASSERT_TRUE(server.Start());
    std::vector<std::string> receivedCerts;
    std::string receivedHost;
    std::string receivedIp;
    HttpClientRequest httpReq;
    httpReq.SetURL(BuildLocalTlsUrl(server.GetPort()));
    httpReq.SetValidationCallback([&receivedCerts, &receivedHost, &receivedIp](const std::vector<std::string> &pemCerts,
        const std::string &host, const std::string &ip) {
        receivedCerts = pemCerts;
        receivedHost = host;
        receivedIp = ip;
        return true;
    });
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    ASSERT_EQ(curl_easy_perform(task->GetCurlHandle()), CURLE_OK);
    EXPECT_FALSE(receivedCerts.empty());
    EXPECT_NE(receivedCerts[0].find("BEGIN CERTIFICATE"), std::string::npos);
    EXPECT_EQ(receivedHost, TEST_TLS_HOST);
    EXPECT_FALSE(receivedIp.empty());
}

HWTEST_F(HttpClientTaskTest, CustomValidationCallbackTest002, TestSize.Level1)
{
    HttpTlsTestServer server;
    ASSERT_TRUE(server.Start());
    bool invoked = false;
    HttpClientRequest httpReq;
    httpReq.SetURL(BuildLocalTlsUrl(server.GetPort()));
    httpReq.SetValidationCallback([&invoked](const std::vector<std::string> &, const std::string &,
        const std::string &) {
        invoked = true;
        return false;
    });
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    CURLcode code = curl_easy_perform(task->GetCurlHandle());
    EXPECT_TRUE(code == CURLE_OK || code == CURLE_PEER_FAILED_VERIFICATION);
    EXPECT_TRUE(invoked);
}

HWTEST_F(HttpClientTaskTest, CustomValidationCallbackTest003, TestSize.Level1)
{
    HttpTlsTestServer server;
    ASSERT_TRUE(server.Start());
    HttpClientRequest httpReq;
    httpReq.SetURL(BuildLocalTlsUrl(server.GetPort()));
    httpReq.SetValidationCallback([](const std::vector<std::string> &, const std::string &, const std::string &) {
        return true;
    });
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    ValidationCallback emptyCallback;
    task->GetRequest().SetValidationCallback(emptyCallback);
    EXPECT_FALSE(task->GetRequest().GetValidationCallback());
    CURLcode code = curl_easy_perform(task->GetCurlHandle());
    EXPECT_TRUE(code == CURLE_OK || code == CURLE_PEER_FAILED_VERIFICATION);
}

HWTEST_F(HttpClientTaskTest, CustomValidationCallbackTest004, TestSize.Level1)
{
    HttpTlsTestServer server;
    ASSERT_TRUE(server.Start());
    std::thread::id callbackThreadId;
    std::thread::id performThreadId = std::this_thread::get_id();
    HttpClientRequest httpReq;
    httpReq.SetURL(BuildLocalTlsUrl(server.GetPort()));
    httpReq.SetValidationCallback([&callbackThreadId](const std::vector<std::string> &, const std::string &,
        const std::string &) {
        callbackThreadId = std::this_thread::get_id();
        return true;
    });
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    ASSERT_EQ(curl_easy_perform(task->GetCurlHandle()), CURLE_OK);
    EXPECT_EQ(callbackThreadId, performThreadId);
}

HWTEST_F(HttpClientTaskTest, VerifyRootCaCallbackTest001, TestSize.Level1)
{
    HttpTlsTestServer server;
    ASSERT_TRUE(server.Start());
    HttpClientRequest httpReq;
    httpReq.SetURL(BuildLocalTlsUrl(server.GetPort()));
    httpReq.SetCaData(server.GetRootCertPem());
    std::string pin = std::string("sha256//") + std::string(44, 'A');
    httpReq.SetPinnedPubkey(pin);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_NE(curl_easy_perform(task->GetCurlHandle()), CURLE_OK);
    EXPECT_TRUE(task->IsRootCaVerified());
    EXPECT_FALSE(task->IsRootCaVerifiedOk());
}

HWTEST_F(HttpClientTaskTest, VerifyRootCaCallbackTest002, TestSize.Level1)
{
    HttpTlsTestServer server;
    ASSERT_TRUE(server.Start());
    HttpClientRequest httpReq;
    httpReq.SetURL(BuildLocalTlsUrl(server.GetPort()));
    httpReq.SetCaData(server.GetRootCertPem());
    std::string pin = std::string("sha256//") + std::string(44, 'A');
    httpReq.SetPinnedPubkey(pin);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    task->SetRootCaVerifiedOk(true);
    CURLcode code = curl_easy_perform(task->GetCurlHandle());
    EXPECT_TRUE(code == CURLE_OK || code == CURLE_PEER_FAILED_VERIFICATION);
    EXPECT_TRUE(task->IsRootCaVerifiedOk());
    EXPECT_FALSE(task->IsRootCaVerified());
}

HWTEST_F(HttpClientTaskTest, VerifyRootCaCallbackTest003, TestSize.Level1)
{
    HttpTlsTestServer server;
    ASSERT_TRUE(server.Start());
    std::string correctPin = ComputeSpkiPin(server.GetServerCertPem());
    ASSERT_FALSE(correctPin.empty());
    std::string pin = std::string("sha256//") + std::string(44, 'B') + ";" + correctPin;

    HttpClientRequest httpReq;
    httpReq.SetURL(BuildLocalTlsUrl(server.GetPort()));
    httpReq.SetCaData(server.GetRootCertPem());
    httpReq.SetPinnedPubkey(pin);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_EQ(curl_easy_perform(task->GetCurlHandle()), CURLE_OK);
    EXPECT_TRUE(task->IsRootCaVerified());
    EXPECT_EQ(task->GetResponse().GetResult(), "OK");
}
#endif
} // namespace

#if HAS_NETMANAGER_BASE
namespace OHOS {
namespace NetManagerStandard {

static bool g_netConnSimEnabled = false;
static int32_t g_simDefaultNetId = 0; /* 0 => GetDefaultNet fails */
static std::list<int32_t> g_simAllNetIds;
static std::map<int32_t, std::set<NetBearType>> g_simBearerTypes;
static std::map<int32_t, std::string> g_simIfaceNames;

int32_t NetConnClient::GetNetCapabilities(const NetHandle &netHandle, NetAllCapabilities &netAllCap)
{
    if (!g_netConnSimEnabled) {
        return NETMANAGER_ERR_OPERATION_FAILED;
    }
    auto it = g_simBearerTypes.find(netHandle.GetNetId());
    if (it == g_simBearerTypes.end()) {
        return NETMANAGER_ERR_OPERATION_FAILED;
    }
    netAllCap.bearerTypes_.insert(it->second.begin(), it->second.end());
    return NETMANAGER_SUCCESS;
}

int32_t NetConnClient::GetDefaultNet(NetHandle &netHandle)
{
    if (!g_netConnSimEnabled || g_simDefaultNetId == 0) {
        return NETMANAGER_ERR_OPERATION_FAILED;
    }
    netHandle.SetNetId(g_simDefaultNetId);
    return NETMANAGER_SUCCESS;
}

int32_t NetConnClient::GetAllNets(std::list<sptr<NetHandle>> &netList)
{
    if (!g_netConnSimEnabled) {
        return NETMANAGER_ERR_OPERATION_FAILED;
    }
    for (auto id : g_simAllNetIds) {
        netList.push_back(new NetHandle(id));
    }
    return NETMANAGER_SUCCESS;
}

int32_t NetConnClient::GetConnectionProperties(const NetHandle &netHandle, NetLinkInfo &info)
{
    if (!g_netConnSimEnabled) {
        return NETMANAGER_ERR_OPERATION_FAILED;
    }
    auto it = g_simIfaceNames.find(netHandle.GetNetId());
    if (it == g_simIfaceNames.end()) {
        return NETMANAGER_ERR_OPERATION_FAILED;
    }
    info.ifaceName_ = it->second;
    return NETMANAGER_SUCCESS;
}
} // namespace NetManagerStandard
} // namespace OHOS

namespace NMS = OHOS::NetManagerStandard;

static void ResetNetConnSim()
{
    NMS::g_netConnSimEnabled = false;
    NMS::g_simDefaultNetId = 0;
    NMS::g_simAllNetIds.clear();
    NMS::g_simBearerTypes.clear();
    NMS::g_simIfaceNames.clear();
}

static std::list<OHOS::sptr<NMS::NetHandle>> MakeSimNetList(std::initializer_list<int32_t> ids)
{
    std::list<OHOS::sptr<NMS::NetHandle>> netList;
    for (auto id : ids) {
        netList.push_back(new NMS::NetHandle(id));
    }
    return netList;
}

HWTEST_F(HttpClientTaskTest, GetNetStatusBearerTypesTest001, TestSize.Level1)
{
    ResetNetConnSim();
    NMS::g_netConnSimEnabled = true;
    NMS::g_simBearerTypes[101] = {NMS::NetBearType::BEARER_CELLULAR};
    NMS::g_simBearerTypes[102] = {NMS::NetBearType::BEARER_WIFI};

    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    auto netList = MakeSimNetList({101, 102});
    std::list<OHOS::sptr<NMS::NetHandle>> cellularNetworks;
    uint8_t cellCount = 0;
    uint8_t wifiCount = 0;
    EXPECT_TRUE(task->GetNetStatus(netList, cellularNetworks, cellCount, wifiCount));
    EXPECT_EQ(cellCount, 1);
    EXPECT_EQ(wifiCount, 1);
    ASSERT_EQ(cellularNetworks.size(), 1);
    EXPECT_EQ(cellularNetworks.front()->GetNetId(), 101);
    ResetNetConnSim();
}

HWTEST_F(HttpClientTaskTest, GetPrimaryCellularInterfaceSimTest001, TestSize.Level1)
{
    ResetNetConnSim();
    NMS::g_netConnSimEnabled = true;
    NMS::g_simDefaultNetId = 105;
    NMS::g_simBearerTypes[105] = {NMS::NetBearType::BEARER_WIFI};
    NMS::g_simBearerTypes[101] = {NMS::NetBearType::BEARER_CELLULAR};
    NMS::g_simBearerTypes[102] = {NMS::NetBearType::BEARER_WIFI};
    NMS::g_simIfaceNames[101] = "ccmni0";

    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    auto netList = MakeSimNetList({101, 102});
    std::string interfaceName;
    int32_t netId = 0;
    EXPECT_TRUE(task->GetPrimaryCellularInterface(task->curlHandle_, netList, interfaceName, netId));
    EXPECT_EQ(interfaceName, "ccmni0");
    EXPECT_EQ(netId, 101);
    ResetNetConnSim();
}

HWTEST_F(HttpClientTaskTest, GetPrimaryCellularInterfaceDefaultCellularTest001, TestSize.Level1)
{
    ResetNetConnSim();
    NMS::g_netConnSimEnabled = true;
    NMS::g_simDefaultNetId = 105;
    NMS::g_simBearerTypes[105] = {NMS::NetBearType::BEARER_CELLULAR};
    NMS::g_simBearerTypes[101] = {NMS::NetBearType::BEARER_CELLULAR};
    NMS::g_simBearerTypes[102] = {NMS::NetBearType::BEARER_WIFI};
    NMS::g_simIfaceNames[101] = "ccmni0";

    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    auto netList = MakeSimNetList({101, 102});
    std::string interfaceName;
    int32_t netId = 0;
    EXPECT_FALSE(task->GetPrimaryCellularInterface(task->curlHandle_, netList, interfaceName, netId));
    ResetNetConnSim();
}

HWTEST_F(HttpClientTaskTest, GetSecondaryCellularInterfaceSimTest001, TestSize.Level1)
{
    ResetNetConnSim();
    NMS::g_netConnSimEnabled = true;
    NMS::g_simDefaultNetId = 101;
    NMS::g_simBearerTypes[101] = {NMS::NetBearType::BEARER_CELLULAR};
    NMS::g_simBearerTypes[102] = {NMS::NetBearType::BEARER_CELLULAR};
    NMS::g_simIfaceNames[102] = "ccmni1";

    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    auto netList = MakeSimNetList({101, 102});
    std::string interfaceName;
    int32_t netId = 0;
    EXPECT_TRUE(task->GetSecondaryCellularInterface(task->curlHandle_, netList, interfaceName, netId));
    EXPECT_EQ(interfaceName, "ccmni1");
    EXPECT_EQ(netId, 102);
    ResetNetConnSim();
}

HWTEST_F(HttpClientTaskTest, GetSecondaryCellularInterfaceSingleCellularTest001, TestSize.Level1)
{
    ResetNetConnSim();
    NMS::g_netConnSimEnabled = true;
    NMS::g_simBearerTypes[101] = {NMS::NetBearType::BEARER_CELLULAR};
    NMS::g_simBearerTypes[102] = {NMS::NetBearType::BEARER_WIFI};

    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    auto netList = MakeSimNetList({101, 102});
    std::string interfaceName;
    int32_t netId = 0;
    EXPECT_FALSE(task->GetSecondaryCellularInterface(task->curlHandle_, netList, interfaceName, netId));
    ResetNetConnSim();
}

HWTEST_F(HttpClientTaskTest, GetSecondaryCellularInterfaceNoDefaultTest001, TestSize.Level1)
{
    ResetNetConnSim();
    NMS::g_netConnSimEnabled = true;
    NMS::g_simBearerTypes[101] = {NMS::NetBearType::BEARER_CELLULAR};
    NMS::g_simBearerTypes[102] = {NMS::NetBearType::BEARER_CELLULAR};

    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    auto netList = MakeSimNetList({101, 102});
    std::string interfaceName;
    int32_t netId = 0;
    EXPECT_FALSE(task->GetSecondaryCellularInterface(task->curlHandle_, netList, interfaceName, netId));
    ResetNetConnSim();
}

HWTEST_F(HttpClientTaskTest, GetInterfaceNamePrimarySimTest001, TestSize.Level1)
{
    ResetNetConnSim();
    NMS::g_netConnSimEnabled = true;
    NMS::g_simAllNetIds = {99, 101, 102};
    NMS::g_simDefaultNetId = 105;
    NMS::g_simBearerTypes[105] = {NMS::NetBearType::BEARER_WIFI};
    NMS::g_simBearerTypes[101] = {NMS::NetBearType::BEARER_CELLULAR};
    NMS::g_simBearerTypes[102] = {NMS::NetBearType::BEARER_WIFI};
    NMS::g_simIfaceNames[101] = "ccmni0";

    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    httpReq.SetPathPreference(PathPreference::primaryCellular);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    std::string interfaceName;
    int32_t netId = 0;
    EXPECT_TRUE(task->GetInterfaceName(task->curlHandle_, interfaceName, netId));
    EXPECT_EQ(interfaceName, "ccmni0");
    EXPECT_EQ(netId, 101);
    ResetNetConnSim();
}

HWTEST_F(HttpClientTaskTest, GetInterfaceNameSecondarySimTest001, TestSize.Level1)
{
    ResetNetConnSim();
    NMS::g_netConnSimEnabled = true;
    NMS::g_simAllNetIds = {101, 102};
    NMS::g_simDefaultNetId = 101;
    NMS::g_simBearerTypes[101] = {NMS::NetBearType::BEARER_CELLULAR};
    NMS::g_simBearerTypes[102] = {NMS::NetBearType::BEARER_CELLULAR};
    NMS::g_simIfaceNames[102] = "ccmni1";

    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    httpReq.SetPathPreference(PathPreference::secondaryCellular);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    std::string interfaceName;
    int32_t netId = 0;
    EXPECT_TRUE(task->GetInterfaceName(task->curlHandle_, interfaceName, netId));
    EXPECT_EQ(interfaceName, "ccmni1");
    EXPECT_EQ(netId, 102);
    ResetNetConnSim();
}

HWTEST_F(HttpClientTaskTest, SetInterfaceSimTest001, TestSize.Level1)
{
    ResetNetConnSim();
    NMS::g_netConnSimEnabled = true;
    NMS::g_simAllNetIds = {101, 102};
    NMS::g_simDefaultNetId = 105;
    NMS::g_simBearerTypes[105] = {NMS::NetBearType::BEARER_WIFI};
    NMS::g_simBearerTypes[101] = {NMS::NetBearType::BEARER_CELLULAR};
    NMS::g_simBearerTypes[102] = {NMS::NetBearType::BEARER_WIFI};
    NMS::g_simIfaceNames[101] = "ccmni0";

    HttpClientRequest httpReq;
    httpReq.SetURL("http://www.httpbin.org/get");
    httpReq.SetPathPreference(PathPreference::primaryCellular);
    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    ASSERT_NE(task, nullptr);

    EXPECT_TRUE(task->SetInterface(task->curlHandle_));
    ResetNetConnSim();
}
#endif

namespace {
} // namespace
