/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include "curl/curl.h"
#include "http_handover_handler.h"
#include "request_context.h"

namespace OHOS::NetStack::HttpOverCurl {
namespace {
using namespace testing::ext;
static constexpr const char *REQUEST_URL = "https://127.0.0.1";
static constexpr const long TIMEOUT_MS = 6000;
static constexpr const long TIMEOUT_IMMEDIATE = 0;
static constexpr const long TIMEOUT_STOP = -1;
static constexpr const FileDescriptor FILE_DESCRIPTOR = 222;

CURL *GetCurlHandle()
{
    CURL *handle = curl_easy_init();
    curl_easy_setopt(handle, CURLOPT_URL, REQUEST_URL);
    curl_easy_setopt(handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
    return handle;
}

RequestInfo *GetRequestInfo()
{
    CURL *handle = GetCurlHandle();
    RequestInfo *requestInfo = new RequestInfo();
    requestInfo->easyHandle = handle;
    static auto startCallback = +[](CURL *easyHandle, void *opaqueData) {};
    static auto responseCallback = +[](CURLMsg *curlMessage, void *opaqueData) {};
    static auto handoverInfoCallback = +[](void *opaqueData) {
        HttpHandoverStackInfo httpHandoverStackInfo;
        return httpHandoverStackInfo;
    };
    static auto setHandoverInfoCallback = +[](HttpHandoverInfo httpHandoverInfo, void *opaqueData) {};
    HttpOverCurl::TransferCallbacks callbacks = {
        .startedCallback = startCallback,
        .doneCallback = responseCallback,
        .handoverInfoCallback = handoverInfoCallback,
        .setHandoverInfoCallback = setHandoverInfoCallback,
    };
    requestInfo->callbacks = callbacks;
    requestInfo->opaqueData = static_cast<void *>(malloc(sizeof(Http::RequestContext)));
    return requestInfo;
}

void DeleteRequestInfo(RequestInfo *requestInfo)
{
    free(requestInfo->opaqueData);
    delete requestInfo;
}
}

class HttpHandoverHandlerTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

class SingletonHttpHandoverHandler {
public:
    SingletonHttpHandoverHandler(const SingletonHttpHandoverHandler&) = delete;
    SingletonHttpHandoverHandler& operator=(const SingletonHttpHandoverHandler&) = delete;
    static HttpHandoverHandler* GetInstance()
    {
        if (instance == nullptr) {
            instance = std::make_unique<HttpHandoverHandler>();
        }
        return instance;
    }

    ~SingletonHttpHandoverHandler()
    {
        instance.reset();
    }
private:
    static std::unique_ptr<HttpHandoverHandler> instance;
    SingletonHttpHandoverHandler() {}
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestSocketTime, TestSize.Level2)
{
    std::shared_ptr<HttpHandoverHandler> netHandoverHandler = std::make_shared<HttpHandoverHandler>();
    curl_socket_t fd = 0;
    EXPECT_TRUE(CheckSocketTime(netHandoverHandler.get(), fd));
    EXPECT_TRUE(CheckSocketTime(nullptr, fd));
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestOpenSocket, TestSize.Level2)
{
    std::shared_ptr<HttpHandoverHandler> netHandoverHandler = std::make_shared<HttpHandoverHandler>();
    curl_sockaddr addr = {AF_INET, SOCK_STREAM, 0};
    curlsocktype purpose = CURLSOCKTYPE_IPCXN;
    curl_socket_t sockfd = OpenSocket(netHandoverHandler.get(), purpose, &addr);
    EXPECT_GE(sockfd, 0);
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestCloseSocketCallback, TestSize.Level2)
{
    auto netHandoverHandler = std::make_shared<HttpHandoverHandler>();
    curl_socket_t fd = 0;
    int ret = CloseSocketCallback(netHandoverHandler.get(), fd);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestEvent, TestSize.Level2)
{
    std::shared_ptr<HttpHandoverHandler> netHandoverHandler = std::make_shared<HttpHandoverHandler>();
    netHandoverHandler->Initialize();
    netHandoverHandler->IsInitSuccess();

    Epoller poller;
    netHandoverHandler->RegisterForPolling(poller);
    netHandoverHandler->SetHandoverEvent();
    netHandoverHandler->SetHandoverTimeoutEvent(TIMEOUT_MS);
    netHandoverHandler->SetHandoverTimeoutEvent(TIMEOUT_IMMEDIATE);
    netHandoverHandler->SetHandoverTimeoutEvent(TIMEOUT_STOP);

    FileDescriptor descriptor = FILE_DESCRIPTOR;
    EXPECT_TRUE(!netHandoverHandler->IsItHandoverEvent(descriptor));
    EXPECT_TRUE(!netHandoverHandler->IsItHandoverTimeoutEvent(descriptor));
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestCallbackEvent, TestSize.Level2)
{
    std::shared_ptr<HttpHandoverHandler> netHandoverHandler = std::make_shared<HttpHandoverHandler>();
    HandoverCallback(static_cast<void*>(netHandoverHandler.get()));
    HandoverTimerCallback(static_cast<void*>(netHandoverHandler.get()), TIMEOUT_MS);
    HandoverCallback(nullptr);
    HandoverTimerCallback(nullptr, TIMEOUT_MS);
    netHandoverHandler->HandoverTimeoutCallback();

    RequestInfo *requestInfo = GetRequestInfo();
    netHandoverHandler->SetCallback(requestInfo);
    std::map<CURL *, RequestInfo *> ongoingRequests;
    CURLM *multi = curl_multi_init();
    netHandoverHandler->SetHandoverEvent();
    netHandoverHandler->HandoverRequestCallback(ongoingRequests, multi);
    DeleteRequestInfo(requestInfo);

    CURL *handle = GetCurlHandle();
    EXPECT_EQ(netHandoverHandler->IsRequestRead(handle), 0);
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestHandoverQuery, TestSize.Level2)
{
    std::shared_ptr<HttpHandoverHandler> netHandoverHandler = std::make_shared<HttpHandoverHandler>();
    netHandoverHandler->HandoverQuery();
    EXPECT_EQ(netHandoverHandler->GetStatus(), HttpHandoverHandler::INIT);
    EXPECT_EQ(netHandoverHandler->GetNetId(), 0);
    int32_t netId = 100;
    netHandoverHandler->SetNetId(netId);
    EXPECT_EQ(netHandoverHandler->GetNetId(), netId);
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestCheckSocket, TestSize.Level2)
{
    std::shared_ptr<HttpHandoverHandler> netHandoverHandler = std::make_shared<HttpHandoverHandler>();
    curl_socket_t fd = 0;
    netHandoverHandler->SetSocketOpenTime(fd);
    netHandoverHandler->EraseFd(fd);
    EXPECT_EQ(netHandoverHandler->CheckSocketOpentimeLessThanEndTime(fd), 0);
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestTryFlowControl, TestSize.Level2)
{
    std::shared_ptr<HttpHandoverHandler> netHandoverHandler = std::make_shared<HttpHandoverHandler>();
    RequestInfo *requestInfo = GetRequestInfo();
    netHandoverHandler->SetStatus(HttpHandoverHandler::INIT);
    EXPECT_FALSE(netHandoverHandler->TryFlowControl(requestInfo, HandoverRequestType::INCOMING));
    netHandoverHandler->SetStatus(HttpHandoverHandler::START);
    EXPECT_TRUE(netHandoverHandler->TryFlowControl(requestInfo, HandoverRequestType::INCOMING));
    EXPECT_TRUE(netHandoverHandler->TryFlowControl(requestInfo, HandoverRequestType::NETWORKERROR));
    EXPECT_TRUE(netHandoverHandler->TryFlowControl(requestInfo, HandoverRequestType::UNDONE));
    netHandoverHandler->SetStatus(HttpHandoverHandler::FATAL);
    EXPECT_FALSE(netHandoverHandler->TryFlowControl(requestInfo, HandoverRequestType::INCOMING));
    DeleteRequestInfo(requestInfo);
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestHandoverRequestCallback, TestSize.Level2)
{
    std::shared_ptr<HttpHandoverHandler> netHandoverHandler = std::make_shared<HttpHandoverHandler>();
    RequestInfo *requestInfo = GetRequestInfo();
    std::map<CURL *, RequestInfo *> ongoingRequests;
    ongoingRequests[requestInfo->easyHandle] = requestInfo;
    CURLM *multi = curl_multi_init();

    netHandoverHandler->SetHandoverEvent();
    netHandoverHandler->SetStatus(HttpHandoverHandler::START);
    netHandoverHandler->HandoverRequestCallback(ongoingRequests, multi);
    netHandoverHandler->SetHandoverEvent();
    netHandoverHandler->SetStatus(HttpHandoverHandler::END);
    netHandoverHandler->HandoverRequestCallback(ongoingRequests, multi);
    netHandoverHandler->SetHandoverEvent();
    netHandoverHandler->SetStatus(HttpHandoverHandler::TIMEOUT);
    netHandoverHandler->HandoverRequestCallback(ongoingRequests, multi);
    netHandoverHandler->SetHandoverEvent();
    netHandoverHandler->SetStatus(HttpHandoverHandler::FATAL);
    netHandoverHandler->HandoverRequestCallback(ongoingRequests, multi);
    EXPECT_EQ(netHandoverHandler->GetStatus(), HttpHandoverHandler::FATAL);
    DeleteRequestInfo(requestInfo);
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestRetransRequest, TestSize.Level2)
{
    std::shared_ptr<HttpHandoverHandler> netHandoverHandler = std::make_shared<HttpHandoverHandler>();
    std::map<CURL *, RequestInfo *> ongoingRequests;
    CURLM *multi = curl_multi_init();
    RequestInfo *requestInfo = GetRequestInfo();
    EXPECT_TRUE(netHandoverHandler->RetransRequest(ongoingRequests, multi, requestInfo));
    DeleteRequestInfo(requestInfo);
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestIsNetworkErrorTypeCorrect, TestSize.Level2)
{
    std::shared_ptr<HttpHandoverHandler> netHandoverHandler = std::make_shared<HttpHandoverHandler>();
    EXPECT_TRUE(netHandoverHandler->IsNetworkErrorTypeCorrect(CURLE_SEND_ERROR));
    EXPECT_TRUE(netHandoverHandler->IsNetworkErrorTypeCorrect(CURLE_RECV_ERROR));

    EXPECT_TRUE(netHandoverHandler->IsNetworkErrorTypeCorrect(CURLE_COULDNT_RESOLVE_HOST));
    EXPECT_TRUE(netHandoverHandler->IsNetworkErrorTypeCorrect(CURLE_COULDNT_CONNECT));
    EXPECT_TRUE(netHandoverHandler->IsNetworkErrorTypeCorrect(CURLE_SSL_CONNECT_ERROR));
    EXPECT_TRUE(netHandoverHandler->IsNetworkErrorTypeCorrect(CURLE_QUIC_CONNECT_ERROR));

    EXPECT_FALSE(netHandoverHandler->IsNetworkErrorTypeCorrect(CURLE_OK));
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestCheckRequestCanRetrans, TestSize.Level2)
{
    std::shared_ptr<HttpHandoverHandler> netHandoverHandler = std::make_shared<HttpHandoverHandler>();
    RequestInfo *requestInfo = GetRequestInfo();

    EXPECT_TRUE(netHandoverHandler->CheckRequestCanRetrans(
        requestInfo, HandoverRequestType::INCOMING, CURLE_SEND_ERROR));
    EXPECT_TRUE(netHandoverHandler->CheckRequestCanRetrans(
        requestInfo, HandoverRequestType::NETWORKERROR, CURLE_RECV_ERROR));
    EXPECT_TRUE(netHandoverHandler->CheckRequestCanRetrans(
        requestInfo, HandoverRequestType::OLD, CURLE_COULDNT_RESOLVE_HOST));
    EXPECT_TRUE(netHandoverHandler->CheckRequestCanRetrans(
        requestInfo, HandoverRequestType::UNDONE, CURLE_COULDNT_CONNECT));
    DeleteRequestInfo(requestInfo);
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestUndoneRequestHandle, TestSize.Level2)
{
    std::shared_ptr<HttpHandoverHandler> netHandoverHandler = std::make_shared<HttpHandoverHandler>();
    RequestInfo *requestInfo = GetRequestInfo();
    std::map<CURL *, RequestInfo *> ongoingRequests;
    ongoingRequests[requestInfo->easyHandle] = requestInfo;
    CURLM *multi = curl_multi_init();
    netHandoverHandler->UndoneRequestHandle(ongoingRequests, multi);
    DeleteRequestInfo(requestInfo);
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestProcessRequestErr, TestSize.Level2)
{
    std::shared_ptr<HttpHandoverHandler> netHandoverHandler = std::make_shared<HttpHandoverHandler>();
    std::map<CURL *, RequestInfo *> ongoingRequests;
    CURLM *multi = curl_multi_init();
    RequestInfo *requestInfo = GetRequestInfo();
    CURLMsg message;
    message.msg = CURLMSG_DONE;
    message.data.result = CURLE_SEND_ERROR;
    EXPECT_EQ(netHandoverHandler->ProcessRequestErr(ongoingRequests, multi, requestInfo, &message), 0);
    DeleteRequestInfo(requestInfo);
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestProcessRequestNetErrorErrorType, TestSize.Level2)
{
    std::shared_ptr<HttpHandoverHandler> netHandoverHandler = std::make_shared<HttpHandoverHandler>();
    std::map<CURL *, RequestInfo *> ongoingRequests;
    CURLM *multi = curl_multi_init();
    RequestInfo *requestInfo = GetRequestInfo();
    CURLMsg message;

    netHandoverHandler->SetHandoverEvent();
    netHandoverHandler->HandoverRequestCallback(ongoingRequests, multi);
    message.msg = CURLMSG_DONE;
    message.data.result = CURLE_SEND_ERROR;
    EXPECT_FALSE(netHandoverHandler->ProcessRequestNetError(ongoingRequests, multi, requestInfo, &message));
    DeleteRequestInfo(requestInfo);
}
}