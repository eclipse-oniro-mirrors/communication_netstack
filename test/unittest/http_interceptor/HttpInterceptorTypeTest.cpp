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

#include "http_interceptor_type.h"
#include "gtest/gtest.h"
#include <cstring>
#include <iostream>

class HttpInterceptorTypeTest : public testing::Test {
public:
    static void SetUpTestCase() { }

    static void TearDownTestCase() { }

    virtual void SetUp() { }

    virtual void TearDown() { }
};

namespace {
using namespace testing::ext;

HWTEST_F(HttpInterceptorTypeTest, InitHttpBuffer001, TestSize.Level1)
{
    Http_Buffer buf = { 0 };
    buf.length = 10;
    InitHttpBuffer(nullptr);
    DestroyHttpInterceptorRequest(nullptr);
    InitHttpBuffer(&buf);
    EXPECT_EQ(buf.length, 0);
}

HWTEST_F(HttpInterceptorTypeTest, DeepCopy001, TestSize.Level1)
{
    Http_Buffer dst = { 0 };
    char tmp[] = "aaa";
    Http_Buffer src = {
        .buffer = tmp,
        .length = 3,
    };
    DeepCopyBuffer(&dst, &src);
    DestroyHttpInterceptorResponse(nullptr);
    free(dst.buffer);
    dst.buffer = nullptr;
    EXPECT_EQ(dst.length, src.length);
    DeepCopyBuffer(nullptr, &src);
    DeepCopyBuffer(&dst, nullptr);
    src.length = 0;
    DeepCopyBuffer(&dst, &src);
    src.buffer = nullptr;
    DeepCopyBuffer(&dst, &src);
    const Http_Buffer *tmp2 = nullptr;
    DeepCopyBuffer(&dst, tmp2);
    EXPECT_EQ(dst.buffer, nullptr);
    auto ret = DeepCopyHeaders(nullptr);
    EXPECT_EQ(ret, nullptr);
    Http_Headers headsTmp = { 0 };
    ret = DeepCopyHeaders(&headsTmp);
    EXPECT_EQ(ret, nullptr);
}
} // namespace
