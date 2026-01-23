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

#include "http_interceptor.h"
#include "gtest/gtest.h"
#include <cstring>
#include <iostream>

class HttpInterceptorInterfaceTest : public testing::Test {
public:
    static void SetUpTestCase() { }

    static void TearDownTestCase() { }

    virtual void SetUp() { }

    virtual void TearDown() { }
};

bool g_hasInternetPermission = true;
namespace OHOS::NetStack::CommonUtils {
bool HasInternetPermission()
{
    return g_hasInternetPermission;
}
} // namespace OHOS::NetStack::CommonUtils

namespace {
using namespace testing::ext;

bool g_isModified = false;
int32_t g_groupId = 0;
Interceptor_Result g_Interceptor_Result = CONTINUE;

Interceptor_Result OH_Http_InterceptorHandler(
    Http_Interceptor_Request *request, Http_Interceptor_Response *response, int32_t *isModified)
{
    (void)request;
    (void)response;
    if (isModified) {
        *isModified = g_isModified ? 1 : 0;
    }
    return g_Interceptor_Result;
}

Http_Interceptor g_response_readonly_interceptor = {
    .groupId = g_groupId,
    .stage = STAGE_RESPONSE,
    .type = TYPE_READ_ONLY,
    .enabled = 0,
    .handler = OH_Http_InterceptorHandler,
};

HWTEST_F(HttpInterceptorInterfaceTest, OH_Http_AddInterceptor001, TestSize.Level1)
{
    g_hasInternetPermission = false;
    auto ret = OH_Http_AddInterceptor(&g_response_readonly_interceptor);
    EXPECT_EQ(ret, OH_HTTP_PERMISSION_DENIED);
    g_hasInternetPermission = true;
    ret = OH_Http_AddInterceptor(&g_response_readonly_interceptor);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = OH_Http_AddInterceptor(nullptr);
    EXPECT_EQ(ret, OH_HTTP_PARAMETER_ERROR);
}

HWTEST_F(HttpInterceptorInterfaceTest, OH_Http_DeleteInterceptor001, TestSize.Level1)
{
    g_hasInternetPermission = false;
    auto ret = OH_Http_DeleteInterceptor(&g_response_readonly_interceptor);
    EXPECT_EQ(ret, OH_HTTP_PERMISSION_DENIED);
    g_hasInternetPermission = true;
    ret = OH_Http_DeleteInterceptor(&g_response_readonly_interceptor);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = OH_Http_DeleteInterceptor(nullptr);
    EXPECT_EQ(ret, OH_HTTP_PARAMETER_ERROR);
}

HWTEST_F(HttpInterceptorInterfaceTest, OH_Http_StartStopDeleteAllInterceptors001, TestSize.Level1)
{
    g_hasInternetPermission = false;
    auto ret = OH_Http_StartAllInterceptors(g_groupId);
    EXPECT_EQ(ret, OH_HTTP_PERMISSION_DENIED);
    ret = OH_Http_StopAllInterceptors(g_groupId);
    EXPECT_EQ(ret, OH_HTTP_PERMISSION_DENIED);
    ret = OH_Http_DeleteAllInterceptors(g_groupId);
    EXPECT_EQ(ret, OH_HTTP_PERMISSION_DENIED);
    g_hasInternetPermission = true;
    ret = OH_Http_StartAllInterceptors(g_groupId);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = OH_Http_StopAllInterceptors(g_groupId);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    ret = OH_Http_DeleteAllInterceptors(g_groupId);
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
}

} // namespace
