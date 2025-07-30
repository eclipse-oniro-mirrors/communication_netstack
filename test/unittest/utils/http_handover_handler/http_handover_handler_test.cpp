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
static constexpr const int32_t INIT_NET_ID = -1;
static constexpr const FileDescriptor FILE_DESCRIPTOR = 222;

CURL *GetCurlHandle()
{
    CURL *handle = curl_easy_init();
    curl_easy_setopt(handle, CURLOPT_URL, REQUEST_URL);
    curl_easy_setopt(handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
    return handle;
}
}

class HttpHandoverHandlerTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

HWTEST_F(HttpHandoverHandlerTest, TestSocketTime, TestSize.Level2)
{
    auto mockHandler = std::make_shared<HttpHandoverHandler>();
    curl_socket_t fd = 0;
    EXPECT_EQ(CheckSocketTime(mockHandler.get(), fd), true);
}

HWTEST_F(HttpHandoverHandlerTest, TestOpenSocket, TestSize.Level2)
{
    auto mockHandler = std::make_shared<HttpHandoverHandler>();
    curl_sockaddr addr = {AF_INET, SOCK_STREAM, 0};
    curlsocktype purpose = CURLSOCKTYPE_IPCXN;
    curl_socket_t sockfd = OpenSocket(mockHandler.get(), purpose, &addr);
    EXPECT_GE(sockfd, 0);
}

HWTEST_F(HttpHandoverHandlerTest, TestCloseSocketCallback, TestSize.Level2)
{
    auto mockHandler = std::make_shared<HttpHandoverHandler>();
    curl_socket_t fd = 0;
    int ret = CloseSocketCallback(mockHandler.get(), fd);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestEvent, TestSize.Level2)
{
    std::shared_ptr<HttpHandoverHandler> netHandoverHandler;
    netHandoverHandler = std::make_shared<HttpHandoverHandler>();
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

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestTimeoutTimerEvent, TestSize.Level2)
{
    std::shared_ptr<HttpHandoverHandler> netHandoverHandler;
    netHandoverHandler = std::make_shared<HttpHandoverHandler>();
    
    HandoverCallback(static_cast<void*>(netHandoverHandler.get()));
    HandoverTimerCallback(static_cast<void*>(netHandoverHandler.get()), TIMEOUT_MS);
    HandoverCallback(nullptr);
    HandoverTimerCallback(nullptr, TIMEOUT_MS);
    netHandoverHandler->HandoverTimeoutCallback();
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestHandoverEvent, TestSize.Level2)
{
    std::shared_ptr<HttpHandoverHandler> netHandoverHandler;
    netHandoverHandler = std::make_shared<HttpHandoverHandler>();
    CURL *handle = GetCurlHandle();
    RequestInfo *requestInfo = new RequestInfo();
    requestInfo->easyHandle = handle;
    netHandoverHandler->SetCallback(requestInfo);
    std::map<CURL *, RequestInfo *> ongoingRequests;
    CURLM *multi = curl_multi_init();

    netHandoverHandler->SetHandoverEvent();
    netHandoverHandler->HandoverRequestCallback(ongoingRequests, multi);
    delete requestInfo;
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestHandoverQuery, TestSize.Level2)
{
    std::shared_ptr<HttpHandoverHandler> netHandoverHandler;
    netHandoverHandler = std::make_shared<HttpHandoverHandler>();
    int32_t status;
    int32_t netId;
    netHandoverHandler->HandoverQuery(status, netId);
    EXPECT_EQ(status, HttpHandoverHandler::INIT);
    EXPECT_EQ(netId, INIT_NET_ID);
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestCheckSocket, TestSize.Level2)
{
    std::shared_ptr<HttpHandoverHandler> netHandoverHandler;
    netHandoverHandler = std::make_shared<HttpHandoverHandler>();

    curl_socket_t fd = 0;
    netHandoverHandler->SetSocketOpenTime(fd);
    netHandoverHandler->EraseFd(fd);
    EXPECT_EQ(netHandoverHandler->CheckSocketOpentimeLessThanEndTime(fd), 0);
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestTryFlowControl, TestSize.Level2)
{
    std::shared_ptr<HttpHandoverHandler> netHandoverHandler;
    netHandoverHandler = std::make_shared<HttpHandoverHandler>();
    CURL *handle = GetCurlHandle();
    RequestInfo *requestInfo = new RequestInfo();
    requestInfo->easyHandle = handle;
    requestInfo->opaqueData = static_cast<void *>(malloc(sizeof(Http::RequestContext)));

    EXPECT_TRUE(!netHandoverHandler->TryFlowControl(requestInfo, HttpHandoverHandler::RequestType::OLD));
    free(requestInfo->opaqueData);
    delete requestInfo;
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestRetransRequest, TestSize.Level2)
{
    std::shared_ptr<HttpHandoverHandler> netHandoverHandler;
    netHandoverHandler = std::make_shared<HttpHandoverHandler>();
    std::map<CURL *, RequestInfo *> ongoingRequests;
    CURLM *multi = curl_multi_init();
    CURL *handle = GetCurlHandle();
    RequestInfo *requestInfo = new RequestInfo();
    requestInfo->easyHandle = handle;

    EXPECT_TRUE(netHandoverHandler->RetransRequest(ongoingRequests, multi, requestInfo));
    delete requestInfo;
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestCheckRequestCanRetrans, TestSize.Level2)
{
    std::shared_ptr<HttpHandoverHandler> netHandoverHandler;
    netHandoverHandler = std::make_shared<HttpHandoverHandler>();
    CURL *handle = GetCurlHandle();
    RequestInfo *requestInfo = new RequestInfo();
    requestInfo->easyHandle = handle;
    requestInfo->opaqueData = static_cast<void *>(malloc(sizeof(Http::RequestContext)));

    EXPECT_TRUE(netHandoverHandler->CheckRequestCanRetrans(requestInfo, HttpHandoverHandler::RequestType::INCOMING));
    EXPECT_TRUE(netHandoverHandler->CheckRequestCanRetrans(requestInfo,
        HttpHandoverHandler::RequestType::NETWORKERROR));
    EXPECT_TRUE(netHandoverHandler->CheckRequestCanRetrans(requestInfo, HttpHandoverHandler::RequestType::OLD));
    EXPECT_TRUE(netHandoverHandler->CheckRequestCanRetrans(requestInfo, HttpHandoverHandler::RequestType::UNDONE));
    free(requestInfo->opaqueData);
    delete requestInfo;
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestUndoneRequestHandle, TestSize.Level2)
{
    std::shared_ptr<HttpHandoverHandler> netHandoverHandler;
    netHandoverHandler = std::make_shared<HttpHandoverHandler>();
    CURL *handle = GetCurlHandle();
    RequestInfo *requestInfo = new RequestInfo();
    requestInfo->easyHandle = handle;
    requestInfo->opaqueData = static_cast<void *>(malloc(sizeof(Http::RequestContext)));
    std::map<CURL *, RequestInfo *> ongoingRequests;
    ongoingRequests[requestInfo->easyHandle] = requestInfo;
    CURLM *multi = curl_multi_init();

    netHandoverHandler->UndoneRequestHandle(ongoingRequests, multi);
    free(requestInfo->opaqueData);
    delete requestInfo;
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestProcessRequestErr, TestSize.Level2)
{
    std::shared_ptr<HttpHandoverHandler> netHandoverHandler;
    netHandoverHandler = std::make_shared<HttpHandoverHandler>();
    std::map<CURL *, RequestInfo *> ongoingRequests;
    CURLM *multi = curl_multi_init();
    CURL *handle = GetCurlHandle();
    RequestInfo *requestInfo = new RequestInfo();
    requestInfo->easyHandle = handle;
    requestInfo->opaqueData = static_cast<void *>(malloc(sizeof(Http::RequestContext)));
    CURLMsg message;
    message.msg = CURLMSG_DONE;
    message.data.result = CURLE_SEND_ERROR;

    EXPECT_EQ(netHandoverHandler->ProcessRequestErr(ongoingRequests, multi, requestInfo, &message), 0);
    free(requestInfo->opaqueData);
    delete requestInfo;
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestCheckRequestNetError, TestSize.Level2)
{
    std::shared_ptr<HttpHandoverHandler> netHandoverHandler;
    netHandoverHandler = std::make_shared<HttpHandoverHandler>();
    std::map<CURL *, RequestInfo *> ongoingRequests;
    CURLM *multi = curl_multi_init();
    CURL *handle = GetCurlHandle();
    RequestInfo *requestInfo = new RequestInfo();
    requestInfo->easyHandle = handle;
    requestInfo->opaqueData = static_cast<void *>(malloc(sizeof(Http::RequestContext)));
    ongoingRequests[requestInfo->easyHandle] = requestInfo;
    CURLMsg message;
    message.msg = CURLMSG_DONE;
    message.data.result = CURLE_SEND_ERROR;

    netHandoverHandler->SetHandoverEvent();
    netHandoverHandler->HandoverRequestCallback(ongoingRequests, multi);
    netHandoverHandler->CheckRequestNetError(ongoingRequests, multi, requestInfo, &message);
    free(requestInfo->opaqueData);
    delete requestInfo;
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestIsNetworkErrorTypeCorrect, TestSize.Level2)
{
    std::shared_ptr<HttpHandoverHandler> netHandoverHandler;
    netHandoverHandler = std::make_shared<HttpHandoverHandler>();
    
    EXPECT_TRUE(IsNetworkErrorTypeCorrect(CURLE_SEND_ERROR));
    EXPECT_TRUE(IsNetworkErrorTypeCorrect(CURLE_RECV_ERROR));
    EXPECT_TRUE(IsNetworkErrorTypeCorrect(CURLE_COULDNT_CONNECT));
    EXPECT_TRUE(IsNetworkErrorTypeCorrect(CURLE_COULDNT_RESOLVE_HOST));
    EXPECT_TRUE(!IsNetworkErrorTypeCorrect(CURLE_AUTH_ERROR));
}
}