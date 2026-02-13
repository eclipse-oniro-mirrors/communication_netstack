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

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestSocketTime, TestSize.Level2)
{
    HttpHandoverHandler handler;
    curl_socket_t fd = 0;
    EXPECT_TRUE(CheckSocketTime(&handler, fd));
    EXPECT_FALSE(CheckSocketTime(nullptr, fd));
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestOpenSocket, TestSize.Level2)
{
    HttpHandoverHandler handler;
    curl_sockaddr addr = {AF_INET, SOCK_STREAM, 0};
    curlsocktype purpose = CURLSOCKTYPE_IPCXN;
    curl_socket_t sockfd = OpenSocket(&handler, purpose, &addr);
    EXPECT_GE(sockfd, 0);
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestCloseSocketCallback, TestSize.Level2)
{
    HttpHandoverHandler handler;
    curl_socket_t fd = 0;
    int ret = CloseSocketCallback(&handler, fd);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestEvent, TestSize.Level2)
{
    HttpHandoverHandler handler;
    Epoller poller;
    handler.RegisterForPolling(poller);
    handler.SetHandoverEvent();
    handler.SetHandoverTimeoutEvent(TIMEOUT_MS);
    handler.SetHandoverTimeoutEvent(TIMEOUT_IMMEDIATE);
    handler.SetHandoverTimeoutEvent(TIMEOUT_STOP);

    FileDescriptor descriptor = FILE_DESCRIPTOR;
    EXPECT_FALSE(handler.IsItHandoverEvent(descriptor));
    EXPECT_FALSE(handler.IsItHandoverTimeoutEvent(descriptor));
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestCallbackEvent, TestSize.Level2)
{
    HttpHandoverHandler handler;
    HandoverCallback(static_cast<void*>(&handler));
    HandoverTimerCallback(static_cast<void*>(&handler), TIMEOUT_MS);
    HandoverCallback(nullptr);
    HandoverTimerCallback(nullptr, TIMEOUT_MS);
    handler.HandoverTimeoutCallback();

    RequestInfo *requestInfo = GetRequestInfo();
    handler.SetCallback(requestInfo);
    std::map<CURL *, RequestInfo *> ongoingRequests;
    CURLM *multi = curl_multi_init();
    handler.SetHandoverEvent();
    handler.HandoverRequestCallback(ongoingRequests, multi);
    DeleteRequestInfo(requestInfo);

    CURL *handle = GetCurlHandle();
    EXPECT_EQ(handler.IsRequestRead(handle), 0);
    EXPECT_EQ(handler.IsRequestInQueue(handle), 1);
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestHandoverQuery, TestSize.Level2)
{
    HttpHandoverHandler handler;
    EXPECT_EQ(handler.GetStatus(), HttpHandoverHandler::INIT);
    EXPECT_EQ(handler.GetNetId(), 0);
    int32_t netId = 100;
    handler.SetNetId(netId);
    EXPECT_EQ(handler.GetNetId(), netId);
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestCheckSocket, TestSize.Level2)
{
    HttpHandoverHandler handler;
    curl_socket_t fd = 0;
    handler.SetSocketOpenTime(fd);
    handler.EraseFd(fd);
    EXPECT_EQ(handler.CheckSocketOpentimeLessThanEndTime(fd), 0);
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestTryFlowControl, TestSize.Level2)
{
    HttpHandoverHandler handler;
    RequestInfo *requestInfo = GetRequestInfo();
    handler.SetStatus(HttpHandoverHandler::INIT);
    EXPECT_FALSE(handler.TryFlowControl(requestInfo, HandoverRequestType::INCOMING));

    handler.SetStatus(HttpHandoverHandler::START);
    EXPECT_EQ(handler.GetStatus(), HttpHandoverHandler::START);
    handler.TryFlowControl(requestInfo, HandoverRequestType::INCOMING);
    handler.TryFlowControl(requestInfo, HandoverRequestType::NETWORKERROR);
    handler.TryFlowControl(requestInfo, HandoverRequestType::UNDONE);

    handler.SetStatus(HttpHandoverHandler::FATAL);
    EXPECT_FALSE(handler.TryFlowControl(requestInfo, HandoverRequestType::INCOMING));
    DeleteRequestInfo(requestInfo);
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestRetransRequest, TestSize.Level2)
{
    HttpHandoverHandler handler;
    std::map<CURL *, RequestInfo *> ongoingRequests;
    CURLM *multi = curl_multi_init();
    RequestInfo *requestInfo = GetRequestInfo();
    EXPECT_TRUE(handler.RetransRequest(ongoingRequests, multi, requestInfo));
    DeleteRequestInfo(requestInfo);
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestIsNetworkErrorTypeCorrect, TestSize.Level2)
{
    HttpHandoverHandler handler;
    EXPECT_TRUE(handler.IsNetworkErrorTypeCorrect(CURLE_SEND_ERROR));
    EXPECT_TRUE(handler.IsNetworkErrorTypeCorrect(CURLE_RECV_ERROR));

    EXPECT_TRUE(handler.IsNetworkErrorTypeCorrect(CURLE_COULDNT_RESOLVE_HOST));
    EXPECT_TRUE(handler.IsNetworkErrorTypeCorrect(CURLE_COULDNT_CONNECT));
    EXPECT_TRUE(handler.IsNetworkErrorTypeCorrect(CURLE_SSL_CONNECT_ERROR));
    EXPECT_TRUE(handler.IsNetworkErrorTypeCorrect(CURLE_QUIC_CONNECT_ERROR));

    EXPECT_FALSE(handler.IsNetworkErrorTypeCorrect(CURLE_OK));
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestCheckRequestCanRetrans, TestSize.Level2)
{
    HttpHandoverHandler handler;
    RequestInfo *requestInfo = GetRequestInfo();

    EXPECT_TRUE(handler.CheckRequestCanRetrans(requestInfo, HandoverRequestType::INCOMING, CURLE_SEND_ERROR));
    EXPECT_TRUE(handler.CheckRequestCanRetrans(requestInfo, HandoverRequestType::NETWORKERROR, CURLE_RECV_ERROR));
    EXPECT_TRUE(handler.CheckRequestCanRetrans(requestInfo, HandoverRequestType::OLD, CURLE_COULDNT_RESOLVE_HOST));
    EXPECT_TRUE(handler.CheckRequestCanRetrans(requestInfo, HandoverRequestType::UNDONE, CURLE_COULDNT_CONNECT));
    DeleteRequestInfo(requestInfo);
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestUndoneRequestHandle, TestSize.Level2)
{
    HttpHandoverHandler handler;
    RequestInfo *requestInfo = GetRequestInfo();
    std::map<CURL *, RequestInfo *> ongoingRequests;
    ongoingRequests[requestInfo->easyHandle] = requestInfo;
    CURLM *multi = curl_multi_init();
    handler.UndoneRequestHandle(ongoingRequests, multi);
    DeleteRequestInfo(requestInfo);
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestProcessRequestErr, TestSize.Level2)
{
    HttpHandoverHandler handler;
    std::map<CURL *, RequestInfo *> ongoingRequests;
    CURLM *multi = curl_multi_init();
    RequestInfo *requestInfo = GetRequestInfo();
    CURLMsg message;
    message.msg = CURLMSG_DONE;
    message.data.result = CURLE_SEND_ERROR;
    EXPECT_FALSE(handler.ProcessRequestErr(ongoingRequests, nullptr, requestInfo, &message));
    EXPECT_FALSE(handler.ProcessRequestErr(ongoingRequests, multi, nullptr, &message));
    EXPECT_FALSE(handler.ProcessRequestErr(ongoingRequests, multi, requestInfo, nullptr));

    free(requestInfo->opaqueData);
    requestInfo->opaqueData = nullptr;
    handler.SetHandoverInfo(requestInfo);
    handler.SetHandoverInfo(nullptr);
    handler.DelRequest(requestInfo);
    delete requestInfo;
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestProcessRequestNetErrorErrorType, TestSize.Level2)
{
    HttpHandoverHandler handler;
    std::map<CURL *, RequestInfo *> ongoingRequests;
    CURLM *multi = curl_multi_init();
    RequestInfo *requestInfo = GetRequestInfo();
    CURLMsg message;

    handler.SetHandoverEvent();
    handler.HandoverRequestCallback(ongoingRequests, multi);
    message.msg = CURLMSG_DONE;
    message.data.result = CURLE_SEND_ERROR;
    EXPECT_FALSE(handler.ProcessRequestNetError(ongoingRequests, multi, requestInfo, &message));
    DeleteRequestInfo(requestInfo);
}
}