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

#include <gtest/gtest.h>
#include <iostream>

#include "curl/curl.h"
#include "want.h"
#include "http_handover_handler.h"
#include "request_context.h"

namespace OHOS::NetStack {
namespace {
using namespace testing::ext;
static constexpr const char *REQUEST_URL = "https://127.0.0.1";


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

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestInit, TestSize.Level2)
{
    std::shared_ptr<HttpOverCurl::HttpHandoverHandler> netHandoverHandler_;
    netHandoverHandler_ = std::make_shared<HttpOverCurl::HttpHandoverHandler>();
    EXPECT_EQ(netHandoverHandler_->InitSuccess(), 0);

    HttpOverCurl::Epoller poller;
    netHandoverHandler_->RegisterForPolling(poller);

    HttpOverCurl::FileDescriptor descriptor = 0;
    EXPECT_EQ(netHandoverHandler_->IsItYours(descriptor), 0);
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestCheckSocket, TestSize.Level2)
{
    std::shared_ptr<HttpOverCurl::HttpHandoverHandler> netHandoverHandler_;
    netHandoverHandler_ = std::make_shared<HttpOverCurl::HttpHandoverHandler>();
    EXPECT_EQ(netHandoverHandler_->InitSuccess(), 0);

    curl_socket_t fd = 0;
    EXPECT_EQ(netHandoverHandler_->CheckSocketOpentimeLessThanEndTime(fd), 0);

    netHandoverHandler_->SetSocketOpenTime(fd);

    EXPECT_EQ(netHandoverHandler_->CheckSocketOpentimeLessThanEndTime(fd), 0);

    netHandoverHandler_->EraseFd(fd);
}

HWTEST_F(HttpHandoverHandlerTest, HttpHandoverHandlerTestFlowControl, TestSize.Level2)
{
    std::shared_ptr<HttpOverCurl::HttpHandoverHandler> netHandoverHandler_;
    netHandoverHandler_ = std::make_shared<HttpOverCurl::HttpHandoverHandler>();
    EXPECT_EQ(netHandoverHandler_->InitSuccess(), 0);

    CURL *handle = GetCurlHandle();
    HttpOverCurl::RequestInfo request;
    request.easyHandle = handle;
    request.opaqueData = static_cast<void *>(malloc(sizeof(Http::RequestContext)));
    EXPECT_EQ(netHandoverHandler_->TryFlowControl(&request), 0);

    CURLM *multi = curl_multi_init();
    std::map<CURL *, HttpOverCurl::RequestInfo *> ongoingRequests;
    netHandoverHandler_->RetransRequest(ongoingRequests, multi, &request);
    netHandoverHandler_->UndoneRequestHandle(ongoingRequests, multi);

    netHandoverHandler_->Set();
    netHandoverHandler_->HandOverRequestCallback(ongoingRequests, multi);

    CURLMsg message;
    message.msg = CURLMSG_DONE;
    message.data.result = CURLE_SEND_ERROR;
    EXPECT_EQ(netHandoverHandler_->CheckRequestNetError(ongoingRequests, multi, &request, &message), 0);
    free(request.opaqueData);
}
}