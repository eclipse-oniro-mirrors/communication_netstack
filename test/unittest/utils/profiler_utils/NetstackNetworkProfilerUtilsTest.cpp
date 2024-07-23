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

#include "http_client_network_message.h"
#include "http_network_message.h"
#include "i_network_message.h"
#include "netstack_network_profiler.h"

namespace OHOS {
namespace NetStack {
namespace {
using namespace testing::ext;
static constexpr const char *REQUEST_ID = "123";
static constexpr const char *HTTP_VERSION_2 = "2";
static constexpr const char *REQUEST_URL = "https://127.0.0.1";
static constexpr const char *REQUEST_IP_ADDRESS = "127.0.0.1";
static constexpr const char *REQUEST_STRING = "unused";
static constexpr const char *REQUEST_HEADERS = "HTTP/1.1 200 OK\r\nk:v";
static constexpr const char *REQUEST_REASON_PARSE = "OK";
static constexpr const uint64_t REQUEST_BEGIN_TIME = 100;
static constexpr const double REQUEST_DNS_TIME = 10;

class MockNetworkMessage : public INetworkMessage {
public:
    MockNetworkMessage() = delete;

    MockNetworkMessage(std::string requestId, CURL *handle)
    {
        requestId_ = requestId;
        requestBeginTime_ = 0;
        handle_ = handle;
    }

    ~MockNetworkMessage() override;

    DfxMessage Parse() override;

private:
    CURL *handle_ = nullptr;
};

MockNetworkMessage::~MockNetworkMessage() = default;

DfxMessage MockNetworkMessage::Parse()
{
    DfxMessage msg{};
    msg.requestId_ = requestId_;
    msg.requestBeginTime_ = requestBeginTime_;
    uint32_t ret = 0;
    ret = GetIpAddressFromCurlHandle(msg.responseIpAddress_, handle_);
    if (ret == 0) {
        msg.responseIpAddress_ = REQUEST_IP_ADDRESS;
    }
    ret = GetEffectiveUrlFromCurlHandle(msg.responseEffectiveUrl_, handle_);
    if (ret != 0) {
        msg.responseEffectiveUrl_ = REQUEST_STRING;
    }
    ret = GetHttpVersionFromCurlHandle(msg.responseHttpVersion_, handle_);
    if (ret == 0) {
        msg.responseHttpVersion_ = HTTP_VERSION_2;
    }
    TimeInfo timeInfo{};
    ret = GetTimeInfoFromCurlHandle(timeInfo, handle_);
    if (ret == 0) {
        msg.dnsEndTime_ = REQUEST_DNS_TIME;
    }
    msg.responseReasonPhrase_ = GetReasonParse(REQUEST_HEADERS);
    return msg;
}

CURL *GetCurlHandle()
{
    CURL *handle = curl_easy_init();
    curl_easy_setopt(handle, CURLOPT_URL, REQUEST_URL);
    curl_easy_setopt(handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
    return handle;
}
}

class NetStackNetworkProfilerUtilsTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

HWTEST_F(NetStackNetworkProfilerUtilsTest, INetworkMessageTest001, TestSize.Level2) {
    MockNetworkMessage mockInstance(REQUEST_ID, GetCurlHandle());
    mockInstance.SetRequestBeginTime(REQUEST_BEGIN_TIME);
    DfxMessage msg = mockInstance.Parse();
    EXPECT_EQ(msg.requestId_, REQUEST_ID);
    EXPECT_EQ(msg.requestBeginTime_, REQUEST_BEGIN_TIME);
    EXPECT_EQ(msg.responseIpAddress_, REQUEST_IP_ADDRESS);
    EXPECT_EQ(msg.responseHttpVersion_, HTTP_VERSION_2);
    EXPECT_NE(msg.responseEffectiveUrl_, REQUEST_STRING);
    EXPECT_EQ(msg.dnsEndTime_, REQUEST_DNS_TIME);
    EXPECT_EQ(msg.responseReasonPhrase_, REQUEST_REASON_PARSE);
}

HWTEST_F(NetStackNetworkProfilerUtilsTest, HttpNetworkMessageTest001, TestSize.Level2) {
    Http::HttpRequestOptions request{};
    Http::HttpResponse response{};
    {
        HttpNetworkMessage httpMsg(REQUEST_ID, request, response, GetCurlHandle());
    }
}

HWTEST_F(NetStackNetworkProfilerUtilsTest, HttpNetworkMessageTest002, TestSize.Level2) {
    Http::HttpRequestOptions request{};
    Http::HttpResponse response{};
    HttpNetworkMessage httpMsg(REQUEST_ID, request, response, GetCurlHandle());
    DfxMessage dfxMsg = httpMsg.Parse();
    EXPECT_EQ(dfxMsg.requestId_, REQUEST_ID);
    EXPECT_EQ(dfxMsg.requestBeginTime_, 0);
}

HWTEST_F(NetStackNetworkProfilerUtilsTest, HttpClientNetworkMessageTest001, TestSize.Level2) {
    HttpClient::HttpClientRequest request{};
    HttpClient::HttpClientResponse response{};
    {
        HttpClientNetworkMessage httpClientMsg(REQUEST_ID, request, response, GetCurlHandle());
    }
}

HWTEST_F(NetStackNetworkProfilerUtilsTest, HttpClientNetworkMessageTest002, TestSize.Level2) {
    HttpClient::HttpClientRequest request{};
    HttpClient::HttpClientResponse response{};
    HttpClientNetworkMessage httpClientMsg(REQUEST_ID, request, response, GetCurlHandle());
    DfxMessage dfxMsg = httpClientMsg.Parse();
    EXPECT_EQ(dfxMsg.requestId_, REQUEST_ID);
    EXPECT_EQ(dfxMsg.requestBeginTime_, 0);
}
}
}
