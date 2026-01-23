/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"
#include <cstring>
#include <iostream>
#define private public
#include "http_interceptor_mgr.h"

class HttpInterceptorTest : public testing::Test {
public:
    static void SetUpTestCase() { }

    static void TearDownTestCase() { }

    virtual void SetUp() { }

    virtual void TearDown() { }
};

namespace {
using namespace testing::ext;
using namespace OHOS::NetStack::HttpInterceptor;

bool g_IsModified = false;
int32_t g_groupId = 0;
Interceptor_Result g_Interceptor_Result = CONTINUE;

char *MallocCString(const std::string &origin)
{
    if (origin.empty()) {
        return nullptr;
    }
    auto len = origin.length() + 1;
    char *res = static_cast<char *>(malloc(sizeof(char) * len));
    if (res == nullptr) {
        return nullptr;
    }
    return std::char_traits<char>::copy(res, origin.c_str(), len);
}

struct curl_slist *MakeHeaders(const std::vector<std::string> &vec)
{
    struct curl_slist *header = nullptr;
    for (const auto &s : vec) {
        header = curl_slist_append(header, s.c_str());
    }
    return header;
}

void InitHttpRequestData(std::shared_ptr<Http_Interceptor_Request> req)
{
    std::vector<std::string> headersList = { "'Content-Type': 'application/x-www-form-urlencoded'",
        "'AAAAA': '1111111'", "'BBBBBB': '222222'" };
    std::string url = "http://192.168.34.104:8080";
    req->url.buffer = MallocCString(url);
    req->url.length = url.length();
    std::string method = "GET";
    req->method.buffer = MallocCString(method);
    req->method.length = method.length();
    std::string body = "hello world!";
    req->body.buffer = MallocCString(body);
    req->body.length = body.length();
    req->headers = MakeHeaders(headersList);
}

void InitHttpResponseData(std::shared_ptr<Http_Interceptor_Response> resp)
{
    std::vector<std::string> headersList = { "'Content-Type': 'application/x-www-form-urlencoded'",
        "'AAAAA': '1111111'", "'BBBBBB': '222222'" };
    std::string body = "hello world!";
    resp->body.buffer = MallocCString(body);
    resp->body.length = body.length();
    resp->headers = MakeHeaders(headersList);
    resp->performanceTiming = {
        .dnsTiming = 11.11,
        .tcpTiming = 22.22,
        .tlsTiming = 33.33,
        .firstSendTiming = 44.44,
        .firstReceiveTiming = 55.55,
        .totalFinishTiming = 66.66,
        .redirectTiming = 77.77,
    };
}

Interceptor_Result OH_Http_InterceptorHandler(
    Http_Interceptor_Request *request, Http_Interceptor_Response *response, int32_t *isModified)
{
    (void)request;
    (void)response;
    if (isModified) {
        *isModified = g_IsModified ? 1 : 0;
    }
    return g_Interceptor_Result;
}

Http_Interceptor g_request_modify_interceptor = {
    .groupId = g_groupId,
    .stage = STAGE_REQUEST,
    .type = TYPE_MODIFY,
    .enabled = 0,
    .handler = OH_Http_InterceptorHandler,
};

Http_Interceptor g_request_modify_interceptor2 = {
    .groupId = g_groupId,
    .stage = STAGE_REQUEST,
    .type = TYPE_MODIFY,
    .enabled = 0,
    .handler = nullptr,
};

Http_Interceptor g_request_modify_interceptor3 = {
    .groupId = g_groupId,
    .stage = STAGE_REQUEST,
    .type = TYPE_MODIFY,
    .enabled = 0,
    .handler = OH_Http_InterceptorHandler,
};

Http_Interceptor g_request_readonly_interceptor = {
    .groupId = g_groupId,
    .stage = STAGE_REQUEST,
    .type = TYPE_READ_ONLY,
    .enabled = 0,
    .handler = OH_Http_InterceptorHandler,
};

Http_Interceptor g_request_readonly_interceptor2 = {
    .groupId = g_groupId,
    .stage = STAGE_REQUEST,
    .type = TYPE_READ_ONLY,
    .enabled = 0,
    .handler = nullptr,
};

Http_Interceptor g_request_readonly_interceptor3 = {
    .groupId = g_groupId,
    .stage = STAGE_REQUEST,
    .type = TYPE_READ_ONLY,
    .enabled = 0,
    .handler = OH_Http_InterceptorHandler,
};

Http_Interceptor g_response_modify_interceptor = {
    .groupId = g_groupId,
    .stage = STAGE_RESPONSE,
    .type = TYPE_MODIFY,
    .enabled = 0,
    .handler = OH_Http_InterceptorHandler,
};

Http_Interceptor g_response_modify_interceptor2 = {
    .groupId = g_groupId,
    .stage = STAGE_RESPONSE,
    .type = TYPE_MODIFY,
    .enabled = 0,
    .handler = nullptr,
};

Http_Interceptor g_response_modify_interceptor3 = {
    .groupId = g_groupId,
    .stage = STAGE_RESPONSE,
    .type = TYPE_MODIFY,
    .enabled = 0,
    .handler = OH_Http_InterceptorHandler,
};

Http_Interceptor g_response_readonly_interceptor = {
    .groupId = g_groupId,
    .stage = STAGE_RESPONSE,
    .type = TYPE_READ_ONLY,
    .enabled = 0,
    .handler = OH_Http_InterceptorHandler,
};

Http_Interceptor g_response_readonly_interceptor2 = {
    .groupId = g_groupId,
    .stage = STAGE_RESPONSE,
    .type = TYPE_READ_ONLY,
    .enabled = 0,
    .handler = nullptr,
};

Http_Interceptor g_response_readonly_interceptor3 = {
    .groupId = g_groupId,
    .stage = STAGE_RESPONSE,
    .type = TYPE_READ_ONLY,
    .enabled = 0,
    .handler = OH_Http_InterceptorHandler,
};

HWTEST_F(HttpInterceptorTest, SetAllInterceptorEnabledTest001, TestSize.Level1)
{
    HttpInterceptorMgr &mgr = HttpInterceptorMgr::GetInstance();
    mgr.AddInterceptor(&g_request_modify_interceptor);
    mgr.AddInterceptor(&g_request_readonly_interceptor);
    mgr.AddInterceptor(&g_response_modify_interceptor);
    mgr.AddInterceptor(&g_response_readonly_interceptor);
    auto ret = mgr.SetAllInterceptorEnabled(g_groupId, 0);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr.SetAllInterceptorEnabled(1, 0);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr.DeleteAllInterceptor(g_groupId);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
}

HWTEST_F(HttpInterceptorTest, DeleteAllInterceptorTest001, TestSize.Level1)
{
    HttpInterceptorMgr mgr;
    auto ret = mgr.SetAllInterceptorEnabled(g_groupId, 1);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr.AddInterceptor(&g_request_modify_interceptor);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    EXPECT_EQ(mgr.requestInterceptorList_.size(), 1);
    ret = mgr.DeleteAllInterceptor(g_groupId);
    EXPECT_EQ(mgr.requestInterceptorList_.size(), 0);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr.SetAllInterceptorEnabled(g_groupId, 0);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
}

HWTEST_F(HttpInterceptorTest, DeleteInterceptorTest001, TestSize.Level1)
{
    HttpInterceptorMgr mgr;
    auto ret = mgr.DeleteInterceptor(nullptr);
    EXPECT_EQ(ret, OH_HTTP_PARAMETER_ERROR);
}

HWTEST_F(HttpInterceptorTest, DeleteRequestInterceptorTest001, TestSize.Level1)
{
    HttpInterceptorMgr mgr;
    auto ret = mgr.AddInterceptor(nullptr);
    EXPECT_EQ(ret, OH_HTTP_PARAMETER_ERROR);
    ret = mgr.AddInterceptor(&g_request_modify_interceptor);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr.AddInterceptor(&g_request_modify_interceptor);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr.DeleteInterceptor(nullptr);
    EXPECT_EQ(ret, OH_HTTP_PARAMETER_ERROR);
    ret = mgr.DeleteInterceptor(&g_request_modify_interceptor);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr.DeleteInterceptor(&g_request_readonly_interceptor);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
}

HWTEST_F(HttpInterceptorTest, DeleteResponseInterceptorTest001, TestSize.Level1)
{
    HttpInterceptorMgr mgr;
    auto ret = mgr.AddInterceptor(nullptr);
    EXPECT_EQ(ret, OH_HTTP_PARAMETER_ERROR);
    ret = mgr.AddInterceptor(&g_response_modify_interceptor);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr.AddInterceptor(&g_response_modify_interceptor);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr.DeleteInterceptor(nullptr);
    EXPECT_EQ(ret, OH_HTTP_PARAMETER_ERROR);
    ret = mgr.DeleteInterceptor(&g_response_modify_interceptor);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr.DeleteInterceptor(&g_response_readonly_interceptor);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr.DeleteAllInterceptor(g_groupId);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
}

HWTEST_F(HttpInterceptorTest, IteratorRequestInterceptorTest001, TestSize.Level1)
{
    std::shared_ptr<HttpInterceptorMgr> mgr = std::make_shared<HttpInterceptorMgr>();
    auto ret = mgr->SetAllInterceptorEnabled(g_groupId, 0);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    bool isModified = false;
    std::shared_ptr<Http_Interceptor_Request> req = mgr->CreateHttpInterceptorRequest();
    InitHttpRequestData(req);
    ret = mgr->IteratorRequestInterceptor(req, isModified);
    EXPECT_EQ(ret, CONTINUE);
    std::shared_ptr<Http_Interceptor_Request> nullReq(nullptr);
    mgr->IteratorReadRequestInterceptor(nullReq);
    ret = mgr->IteratorRequestInterceptor(nullReq, isModified);
    EXPECT_EQ(ret, CONTINUE);
    ret = mgr->AddInterceptor(&g_request_modify_interceptor);
    ret = mgr->AddInterceptor(&g_request_modify_interceptor2);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr->AddInterceptor(&g_request_readonly_interceptor);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr->AddInterceptor(&g_request_readonly_interceptor2);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr->SetAllInterceptorEnabled(g_groupId, 1);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr->AddInterceptor(&g_request_modify_interceptor3);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr->AddInterceptor(&g_request_readonly_interceptor3);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr->IteratorRequestInterceptor(req, isModified);
    EXPECT_EQ(ret, CONTINUE);
    g_IsModified = true;
    g_Interceptor_Result = ABORT;
    ret = mgr->IteratorRequestInterceptor(req, isModified);
    EXPECT_EQ(isModified, true);
    EXPECT_EQ(ret, ABORT);
    g_IsModified = false;
    g_Interceptor_Result = CONTINUE;
    ret = mgr->SetAllInterceptorEnabled(g_groupId, 0);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
}

HWTEST_F(HttpInterceptorTest, IteratorRequestInterceptorTest002, TestSize.Level1)
{
    std::shared_ptr<HttpInterceptorMgr> mgr = std::make_shared<HttpInterceptorMgr>();
    auto ret = mgr->SetAllInterceptorEnabled(g_groupId, 0);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    bool isModified = false;
    std::shared_ptr<Http_Interceptor_Request> req = mgr->CreateHttpInterceptorRequest();
    InitHttpRequestData(req);
    ret = mgr->IteratorRequestInterceptor(req, isModified);
    EXPECT_EQ(ret, CONTINUE);
    std::shared_ptr<Http_Interceptor_Request> nullReq(nullptr);
    ret = mgr->IteratorRequestInterceptor(nullReq, isModified);
    mgr->CopyHttpInterceRequest(nullReq, req);
    mgr->CopyHttpInterceRequest(req, nullReq);
    EXPECT_EQ(ret, CONTINUE);
    ret = mgr->AddInterceptor(&g_request_modify_interceptor);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr->AddInterceptor(&g_request_readonly_interceptor);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr->SetAllInterceptorEnabled(g_groupId, 1);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr->IteratorRequestInterceptor(req, isModified);
    EXPECT_EQ(ret, CONTINUE);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    g_IsModified = true;
    g_Interceptor_Result = ABORT;
    ret = mgr->IteratorRequestInterceptor(req, isModified);
    EXPECT_EQ(isModified, true);
    EXPECT_EQ(ret, ABORT);
    g_IsModified = false;
    g_Interceptor_Result = CONTINUE;
    ret = mgr->SetAllInterceptorEnabled(g_groupId, 0);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
}

HWTEST_F(HttpInterceptorTest, IteratorResponseInterceptorTest001, TestSize.Level1)
{
    std::shared_ptr<HttpInterceptorMgr> mgr = std::make_shared<HttpInterceptorMgr>();
    auto ret = mgr->SetAllInterceptorEnabled(g_groupId, 0);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    std::shared_ptr<Http_Interceptor_Response> resp = mgr->CreateHttpInterceptorResponse();
    bool isModified = false;
    std::shared_ptr<Http_Interceptor_Response> nullResp(nullptr);
    ret = mgr->IteratorResponseInterceptor(nullResp, isModified);
    mgr->CopyHttpInterceResponse(nullResp, resp);
    mgr->CopyHttpInterceResponse(resp, nullResp);
    EXPECT_EQ(ret, CONTINUE);
    ret = mgr->AddInterceptor(&g_response_modify_interceptor);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr->AddInterceptor(&g_response_modify_interceptor2);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr->AddInterceptor(&g_response_readonly_interceptor);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr->AddInterceptor(&g_response_readonly_interceptor2);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr->SetAllInterceptorEnabled(g_groupId, 1);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr->AddInterceptor(&g_response_modify_interceptor3);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr->AddInterceptor(&g_response_readonly_interceptor3);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr->IteratorResponseInterceptor(resp, isModified);
    EXPECT_EQ(ret, CONTINUE);
    InitHttpResponseData(resp);
    ret = mgr->IteratorResponseInterceptor(resp, isModified);
    EXPECT_EQ(ret, CONTINUE);
    g_IsModified = true;
    g_Interceptor_Result = ABORT;
    ret = mgr->IteratorResponseInterceptor(resp, isModified);
    EXPECT_EQ(isModified, true);
    EXPECT_EQ(ret, ABORT);
    g_IsModified = false;
    g_Interceptor_Result = CONTINUE;
    ret = mgr->SetAllInterceptorEnabled(g_groupId, 0);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
}

HWTEST_F(HttpInterceptorTest, IteratorResponseInterceptorTest002, TestSize.Level1)
{
    std::shared_ptr<HttpInterceptorMgr> mgr = std::make_shared<HttpInterceptorMgr>();
    auto ret = mgr->SetAllInterceptorEnabled(g_groupId, 0);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    std::shared_ptr<Http_Interceptor_Response> resp = std::make_shared<Http_Interceptor_Response>();
    bool isModified = false;
    std::shared_ptr<Http_Interceptor_Response> nullResp(nullptr);
    mgr->IteratorReadResponseInterceptor(nullResp);
    ret = mgr->IteratorResponseInterceptor(nullResp, isModified);
    EXPECT_EQ(ret, CONTINUE);
    ret = mgr->AddInterceptor(&g_response_modify_interceptor);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr->AddInterceptor(&g_response_readonly_interceptor);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr->SetAllInterceptorEnabled(g_groupId, 1);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr->IteratorResponseInterceptor(resp, isModified);
    EXPECT_EQ(ret, CONTINUE);
    InitHttpResponseData(resp);
    ret = mgr->IteratorResponseInterceptor(resp, isModified);
    EXPECT_EQ(ret, CONTINUE);
    g_IsModified = true;
    g_Interceptor_Result = ABORT;
    ret = mgr->IteratorResponseInterceptor(resp, isModified);
    EXPECT_EQ(isModified, true);
    EXPECT_EQ(ret, ABORT);
    g_IsModified = false;
    g_Interceptor_Result = CONTINUE;
    std::this_thread::sleep_for(std::chrono::seconds(1));
    ret = mgr->SetAllInterceptorEnabled(g_groupId, 0);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
}

} // namespace
