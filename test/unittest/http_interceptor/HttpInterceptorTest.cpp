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
Interceptor_Result g_Interceptor_Result = CONTINUE;

Interceptor_Result OH_Http_InterceptorHandler(
    Http_Interceptor_Request *request, Http_Response *response, int32_t *isModified)
{
    (void)request;
    (void)response;
    if (isModified) {
        *isModified = g_IsModified ? 1 : 0;
    }
    return g_Interceptor_Result;
}

Http_Interceptor g_request_modify_interceptor = {
    .stage = STAGE_REQUEST,
    .type = TYPE_MODIFY,
    .context = nullptr,
    .handler = OH_Http_InterceptorHandler,
};

Http_Interceptor g_request_readonly_interceptor = {
    .stage = STAGE_REQUEST,
    .type = TYPE_READ_ONLY,
    .context = nullptr,
    .handler = OH_Http_InterceptorHandler,
};

Http_Interceptor g_response_modify_interceptor = {
    .stage = STAGE_RESPONSE,
    .type = TYPE_MODIFY,
    .context = nullptr,
    .handler = OH_Http_InterceptorHandler,
};

Http_Interceptor g_response_readonly_interceptor = {
    .stage = STAGE_RESPONSE,
    .type = TYPE_READ_ONLY,
    .context = nullptr,
    .handler = OH_Http_InterceptorHandler,
};

HWTEST_F(HttpInterceptorTest, StartAllInterceptorTest001, TestSize.Level1)
{
    HttpInterceptorMgr mgr;
    auto ret = mgr.StartAllInterceptor();
    EXPECT_EQ(mgr.isRunning_.load(), true);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
}

HWTEST_F(HttpInterceptorTest, StopAllInterceptorTest001, TestSize.Level1)
{
    HttpInterceptorMgr mgr;
    auto ret = mgr.StopAllInterceptor();
    EXPECT_EQ(mgr.GetInterceptorMgrStatus(), false);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
}

HWTEST_F(HttpInterceptorTest, DeleteAllInterceptorTest001, TestSize.Level1)
{
    HttpInterceptorMgr mgr;
    auto ret = mgr.StartAllInterceptor();
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr.AddInterceptor(&g_request_modify_interceptor);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    EXPECT_EQ(mgr.requestInterceptorList_.size(), 1);
    ret = mgr.DeleteAllInterceptor();
    EXPECT_EQ(mgr.requestInterceptorList_.size(), 0);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr.StopAllInterceptor();
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
    ret = mgr.DeleteAllInterceptor();
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
}

HWTEST_F(HttpInterceptorTest, IteratorRequestInterceptorTest001, TestSize.Level1)
{
    std::shared_ptr<HttpInterceptorMgr> mgr = std::make_shared<HttpInterceptorMgr>();
    auto ret = mgr->StopAllInterceptor();
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    bool isModified = false;
    std::shared_ptr<Http_Interceptor_Request> req = std::make_shared<Http_Interceptor_Request>();
    ret = mgr->IteratorRequestInterceptor(req, isModified);
    EXPECT_EQ(ret, CONTINUE);
    ret = mgr->StartAllInterceptor();
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr->IteratorRequestInterceptor(nullptr, isModified);
    EXPECT_EQ(ret, CONTINUE);
    ret = mgr->AddInterceptor(&g_request_modify_interceptor);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr->AddInterceptor(&g_request_readonly_interceptor);
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
    ret = mgr->StopAllInterceptor();
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
}

HWTEST_F(HttpInterceptorTest, IteratorRequestInterceptorTest002, TestSize.Level1)
{
    std::shared_ptr<HttpInterceptorMgr> mgr = std::make_shared<HttpInterceptorMgr>();
    auto ret = mgr->StopAllInterceptor();
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    bool isModified = false;
    std::shared_ptr<Http_Interceptor_Request> req = std::make_shared<Http_Interceptor_Request>();
    ret = mgr->IteratorRequestInterceptor(req, isModified);
    EXPECT_EQ(ret, CONTINUE);
    ret = mgr->StartAllInterceptor();
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr->IteratorRequestInterceptor(nullptr, isModified);
    EXPECT_EQ(ret, CONTINUE);
    ret = mgr->AddInterceptor(&g_request_modify_interceptor);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr->AddInterceptor(&g_request_readonly_interceptor);
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
    ret = mgr->StopAllInterceptor();
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
}

HWTEST_F(HttpInterceptorTest, IteratorResponseInterceptorTest001, TestSize.Level1)
{
    std::shared_ptr<HttpInterceptorMgr> mgr = std::make_shared<HttpInterceptorMgr>();
    auto ret = mgr->StopAllInterceptor();
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    std::shared_ptr<Http_Response> resp = std::make_shared<Http_Response>();
    bool isModified = false;
    ret = mgr->IteratorResponseInterceptor(resp, isModified);
    EXPECT_EQ(ret, CONTINUE);
    ret = mgr->StartAllInterceptor();
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr->IteratorResponseInterceptor(nullptr, isModified);
    EXPECT_EQ(ret, CONTINUE);
    ret = mgr->AddInterceptor(&g_response_modify_interceptor);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr->AddInterceptor(&g_response_readonly_interceptor);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr->IteratorResponseInterceptor(resp, isModified);
    EXPECT_EQ(ret, CONTINUE);
    g_IsModified = true;
    g_Interceptor_Result = ABORT;
    ret = mgr->IteratorResponseInterceptor(resp, isModified);
    EXPECT_EQ(isModified, true);
    EXPECT_EQ(ret, ABORT);
    g_IsModified = false;
    g_Interceptor_Result = CONTINUE;
    ret = mgr->StopAllInterceptor();
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
}

HWTEST_F(HttpInterceptorTest, IteratorResponseInterceptorTest002, TestSize.Level1)
{
    std::shared_ptr<HttpInterceptorMgr> mgr = std::make_shared<HttpInterceptorMgr>();
    auto ret = mgr->StopAllInterceptor();
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    std::shared_ptr<Http_Response> resp = std::make_shared<Http_Response>();
    bool isModified = false;
    ret = mgr->IteratorResponseInterceptor(resp, isModified);
    EXPECT_EQ(ret, CONTINUE);
    ret = mgr->StartAllInterceptor();
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr->IteratorResponseInterceptor(nullptr, isModified);
    EXPECT_EQ(ret, CONTINUE);
    ret = mgr->AddInterceptor(&g_response_modify_interceptor);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = mgr->AddInterceptor(&g_response_readonly_interceptor);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
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
    ret = mgr->StopAllInterceptor();
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
}

} // namespace
