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

#include "gtest/gtest.h"
#include <cstring>
#include <iostream>
#ifdef GTEST_API_
#define private public
#endif

#include "http_interceptor.h"
#include "netstack_log.h"
#include "request_context.h"

using namespace OHOS::NetStack::Http;

class HttpInterceptorTest : public testing::Test {
public:
    static void SetUpTestCase() { }

    static void TearDownTestCase() { }

    virtual void SetUp() { }

    virtual void TearDown() { }
};

namespace {
using namespace std;
using namespace testing::ext;

class MockNapiEnvironment {
public:
    MockNapiEnvironment()
    {
        env_ = nullptr;
        global_ = nullptr;
    }

    ~MockNapiEnvironment() { }

    napi_env GetEnv()
    {
        return env_;
    }
    napi_value GetGlobal()
    {
        return global_;
    }

private:
    napi_env env_;
    napi_value global_;
};

HWTEST_F(HttpInterceptorTest, ConstructorTest001, TestSize.Level1)
{
    std::map<std::string, napi_ref> interceptorRefs;

    HttpInterceptor interceptor(interceptorRefs);

    EXPECT_FALSE(interceptor.IsInitialRequestInterceptor());
    EXPECT_FALSE(interceptor.IsRedirectionInterceptor());
    EXPECT_FALSE(interceptor.IsFinalResponseInterceptor());
    EXPECT_FALSE(interceptor.IsCacheCheckedInterceptor());
    EXPECT_FALSE(interceptor.IsConnectNetworkInterceptor());
}

HWTEST_F(HttpInterceptorTest, SetInterceptorRefsTest001, TestSize.Level1)
{
    std::map<std::string, napi_ref> interceptorRefs;
    napi_ref mockRef = reinterpret_cast<napi_ref>(1);
    interceptorRefs["INITIAL_REQUEST"] = mockRef;

    HttpInterceptor interceptor(interceptorRefs);

    EXPECT_TRUE(interceptor.IsInitialRequestInterceptor());
}

HWTEST_F(HttpInterceptorTest, SetConnectNetworkInterceptorTest001, TestSize.Level1)
{
    std::map<std::string, napi_ref> interceptorRefs;
    napi_ref mockRef = reinterpret_cast<napi_ref>(1);
    interceptorRefs["CONNECT_NETWORK"] = mockRef;

    HttpInterceptor interceptor(interceptorRefs);

    interceptor.SetConnectNetworkInterceptor();

    EXPECT_TRUE(interceptor.IsConnectNetworkInterceptor());
}

HWTEST_F(HttpInterceptorTest, GetConnectNetworkInterceptorCallbackTest001, TestSize.Level1)
{
    std::map<std::string, napi_ref> interceptorRefs;
    napi_ref mockRef = reinterpret_cast<napi_ref>(1);
    interceptorRefs["CONNECT_NETWORK"] = mockRef;

    HttpInterceptor interceptor(interceptorRefs);

    interceptor.SetConnectNetworkInterceptor();

    const RequestInterceptor &callback = interceptor.GetConnectNetworkInterceptorCallback();

    EXPECT_TRUE(callback != nullptr);
}

HWTEST_F(HttpInterceptorTest, MultipleInterceptorsTest001, TestSize.Level1)
{
    std::map<std::string, napi_ref> interceptorRefs;
    napi_ref mockRef1 = reinterpret_cast<napi_ref>(1);
    napi_ref mockRef2 = reinterpret_cast<napi_ref>(2);
    napi_ref mockRef3 = reinterpret_cast<napi_ref>(3);
    interceptorRefs["INITIAL_REQUEST"] = mockRef1;
    interceptorRefs["CONNECT_NETWORK"] = mockRef2;
    interceptorRefs["FINAL_RESPONSE"] = mockRef3;

    HttpInterceptor interceptor(interceptorRefs);

    interceptor.SetInitialRequestInterceptor();
    interceptor.SetConnectNetworkInterceptor();
    interceptor.SetFinalResponseInterceptor();

    EXPECT_TRUE(interceptor.IsInitialRequestInterceptor());
    EXPECT_TRUE(interceptor.IsConnectNetworkInterceptor());
    EXPECT_TRUE(interceptor.IsFinalResponseInterceptor());
}

HWTEST_F(HttpInterceptorTest, EmptyInterceptorRefsTest001, TestSize.Level1)
{
    std::map<std::string, napi_ref> interceptorRefs;

    HttpInterceptor interceptor(interceptorRefs);

    interceptor.SetInitialRequestInterceptor();
    interceptor.SetFinalResponseInterceptor();
    interceptor.SetRedirectionInterceptor();
    interceptor.SetCacheCheckedInterceptor();
    interceptor.SetConnectNetworkInterceptor();

    EXPECT_TRUE(interceptor.IsInitialRequestInterceptor());
    EXPECT_TRUE(interceptor.IsConnectNetworkInterceptor());
    EXPECT_TRUE(interceptor.IsFinalResponseInterceptor());
    EXPECT_TRUE(interceptor.IsRedirectionInterceptor());
    EXPECT_TRUE(interceptor.IsCacheCheckedInterceptor());
}

HWTEST_F(HttpInterceptorTest, InterceptorStateTransitionTest001, TestSize.Level1)
{
    std::map<std::string, napi_ref> interceptorRefs;
    napi_ref mockRef = reinterpret_cast<napi_ref>(1);

    HttpInterceptor interceptor1(interceptorRefs);
    EXPECT_FALSE(interceptor1.IsConnectNetworkInterceptor());

    interceptorRefs["CONNECT_NETWORK"] = mockRef;
    HttpInterceptor interceptor2(interceptorRefs);
    interceptor2.SetConnectNetworkInterceptor();
    EXPECT_TRUE(interceptor2.IsConnectNetworkInterceptor());
}

HWTEST_F(HttpInterceptorTest, InterceptorCallbackValidityTest001, TestSize.Level1)
{
    std::map<std::string, napi_ref> interceptorRefs;
    napi_ref mockRef1 = reinterpret_cast<napi_ref>(1);
    napi_ref mockRef2 = reinterpret_cast<napi_ref>(2);
    interceptorRefs["CONNECT_NETWORK"] = mockRef1;
    interceptorRefs["CACHE_CHECKED"] = mockRef2;

    HttpInterceptor interceptor(interceptorRefs);

    interceptor.SetConnectNetworkInterceptor();
    interceptor.SetCacheCheckedInterceptor();

    const RequestInterceptor &connectNetworkCallback = interceptor.GetConnectNetworkInterceptorCallback();
    const RequestInterceptor &cacheCheckedCallback = interceptor.GetCacheCheckedInterceptorCallback();

    EXPECT_TRUE(connectNetworkCallback != nullptr);
    EXPECT_TRUE(cacheCheckedCallback != nullptr);
    EXPECT_TRUE(&connectNetworkCallback != &cacheCheckedCallback);
}

HWTEST_F(HttpInterceptorTest, DestructorTest001, TestSize.Level1)
{
    std::map<std::string, napi_ref> interceptorRefs;
    napi_ref mockRef1 = reinterpret_cast<napi_ref>(1);
    napi_ref mockRef2 = reinterpret_cast<napi_ref>(2);
    interceptorRefs["CONNECT_NETWORK"] = mockRef1;
    interceptorRefs["INITIAL_REQUEST"] = mockRef2;

    {
        HttpInterceptor interceptor(interceptorRefs);
        interceptor.SetConnectNetworkInterceptor();
        interceptor.SetInitialRequestInterceptor();
        EXPECT_TRUE(interceptor.IsConnectNetworkInterceptor());
        EXPECT_TRUE(interceptor.IsInitialRequestInterceptor());
    }

    SUCCEED();
}
} // namespace