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
#include "gtest/gtest.h"
#include "http_client_constant.h"
#include "netstack_log.h"
#include "netstack_common_utils.h"

#define private public
#include "http_client_task.h"
#include "http_client.h"
#include "http_client_error.h"
#include <curl/curl.h>
#include "http_client_request.h"
#include "http_client_response.h"

using namespace OHOS::NetStack::HttpClient;

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
    std::string url = "https://www.baidu.com";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    task->OnSuccess([task](const HttpClientRequest &request, const HttpClientResponse &response) {});

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
    std::string  exclusions;
    int32_t port = 0;
    bool tunnel = false;
    task->GetHttpProxyInfo(host, port, exclusions, tunnel);

    EXPECT_EQ(host, "");
    EXPECT_EQ(port, 0);
    EXPECT_EQ(exclusions, "");
    EXPECT_FALSE(tunnel);
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


} // namespace
