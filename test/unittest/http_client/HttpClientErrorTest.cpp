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

#define private public
#include "http_client_error.h"

using namespace OHOS::NetStack::HttpClient;

class HttpClientErrorTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

namespace {
using namespace std;
using namespace testing::ext;

HWTEST_F(HttpClientErrorTest, GetErrorCodeTest001, TestSize.Level1)
{
    HttpClientError req;

    int errorCode = req.GetErrorCode();
    EXPECT_EQ(errorCode, HttpErrorCode::HTTP_NONE_ERR);
}

HWTEST_F(HttpClientErrorTest, SetErrorCodeTest001, TestSize.Level1)
{
    HttpClientError req;

    req.SetErrorCode(HttpErrorCode::HTTP_PERMISSION_DENIED_CODE);
    int errorCode = req.GetErrorCode();
    EXPECT_EQ(errorCode, HttpErrorCode::HTTP_PERMISSION_DENIED_CODE);
}

HWTEST_F(HttpClientErrorTest, GetErrorMessageTest001, TestSize.Level1)
{
    HttpClientError req;

    string errorMsg = req.GetErrorMessage();
    EXPECT_EQ(errorMsg, "No errors occurred");
}

HWTEST_F(HttpClientErrorTest, GetErrorMessageTest002, TestSize.Level1)
{
    HttpClientError req;

    req.SetErrorCode(HttpErrorCode::HTTP_PERMISSION_DENIED_CODE);
    string errorMsg = req.GetErrorMessage();
    EXPECT_EQ(errorMsg, "Permission denied");
}

HWTEST_F(HttpClientErrorTest, SetCURLResultTest001, TestSize.Level1)
{
    HttpClientError req;

    req.SetCURLResult(CURLE_OK);
    int errorCode = req.GetErrorCode();
    EXPECT_EQ(errorCode, HttpErrorCode::HTTP_NONE_ERR);
}

HWTEST_F(HttpClientErrorTest, SetCURLResultTest002, TestSize.Level1)
{
    HttpClientError req;

    req.SetCURLResult(CURLE_UNSUPPORTED_PROTOCOL);
    int errorCode = req.GetErrorCode();
    EXPECT_EQ(errorCode, HttpErrorCode::HTTP_UNSUPPORTED_PROTOCOL);
}

HWTEST_F(HttpClientErrorTest, GetErrorMessageInvalidMaxAutoRedirTest001, TestSize.Level1)
{
    HttpClientError req;

    req.SetErrorCode(HttpErrorCode::HTTP_PARSE_ERROR_CODE);
    string errorMsg = req.GetErrorMessage();
    EXPECT_EQ(errorMsg, "Invalid number of maxRedirects");
}

HWTEST_F(HttpClientErrorTest, SetCURLResultTooManyRedirectsTest001, TestSize.Level1)
{
    HttpClientError req;

    req.SetCURLResult(CURLE_TOO_MANY_REDIRECTS);
    int errorCode = req.GetErrorCode();
    EXPECT_EQ(errorCode, HttpErrorCode::HTTP_TOO_MANY_REDIRECTS);
}

HWTEST_F(HttpClientErrorTest, GetErrorMessageTooManyRedirectsTest001, TestSize.Level1)
{
    HttpClientError req;

    req.SetCURLResult(CURLE_TOO_MANY_REDIRECTS);
    string errorMsg = req.GetErrorMessage();
    EXPECT_EQ(errorMsg, "The number of redirections reaches the maximum allowed");
}
} // namespace