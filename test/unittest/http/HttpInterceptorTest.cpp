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
#include <memory>
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
HWTEST_F(HttpInterceptorTest, ApplyBodyToCurlHandleSurvivesLocalStringTest001, TestSize.Level1)
{
    auto manager = std::make_shared<OHOS::NetStack::EventManager>();
    RequestContext context(nullptr, manager);
    CURL *handle = curl_easy_init();
    ASSERT_NE(handle, nullptr);

    const char *storedAddr = nullptr;
    {
        std::string bodyStr = "{\"message\":\"probe string body\"}";
        context.options.ReplaceBody(bodyStr.data(), bodyStr.size());
        HttpInterceptor::ApplyBodyToCurlHandle(handle, &context);
        storedAddr = context.options.GetBody().data();
    }
    // 局部字符串已析构，curl 句柄指向的必须是 options 内部长期存储
    EXPECT_EQ(context.options.GetBody(), "{\"message\":\"probe string body\"}");
    EXPECT_EQ(context.options.GetBody().size(), static_cast<size_t>(31));
    EXPECT_EQ(storedAddr, context.options.GetBody().data());
    curl_easy_cleanup(handle);
}

HWTEST_F(HttpInterceptorTest, ApplyBodyToCurlHandleCopiesExternalBufferTest001, TestSize.Level1)
{
    auto manager = std::make_shared<OHOS::NetStack::EventManager>();
    RequestContext context(nullptr, manager);
    CURL *handle = curl_easy_init();
    ASSERT_NE(handle, nullptr);

    const size_t len = 64;
    char *external = new char[len];
    std::memset(external, 'A', len);
    context.options.ReplaceBody(external, len);
    HttpInterceptor::ApplyBodyToCurlHandle(handle, &context);
    // 模拟 JS 侧 ArrayBuffer 底层内存被回收
    delete[] external;

    EXPECT_EQ(context.options.GetBody().size(), len);
    EXPECT_EQ(context.options.GetBody(), std::string(len, 'A'));
    curl_easy_cleanup(handle);
}

HWTEST_F(HttpInterceptorTest, ApplyBodyToCurlHandleBinaryBodyTest001, TestSize.Level1)
{
    auto manager = std::make_shared<OHOS::NetStack::EventManager>();
    RequestContext context(nullptr, manager);
    CURL *handle = curl_easy_init();
    ASSERT_NE(handle, nullptr);

    const char binary[] = {'B', '\0', static_cast<char>(0xFF), 'C', '\x01', '\0', 'D'};
    context.options.ReplaceBody(binary, sizeof(binary));
    HttpInterceptor::ApplyBodyToCurlHandle(handle, &context);

    const std::string &stored = context.options.GetBody();
    ASSERT_EQ(stored.size(), sizeof(binary));
    EXPECT_EQ(std::memcmp(stored.data(), binary, sizeof(binary)), 0);
    curl_easy_cleanup(handle);
}

HWTEST_F(HttpInterceptorTest, ApplyBodyToCurlHandleEmptyBodyTest001, TestSize.Level1)
{
    auto manager = std::make_shared<OHOS::NetStack::EventManager>();
    RequestContext context(nullptr, manager);
    CURL *handle = curl_easy_init();
    ASSERT_NE(handle, nullptr);

    context.options.ReplaceBody("", 0);
    HttpInterceptor::ApplyBodyToCurlHandle(handle, &context);

    EXPECT_TRUE(context.options.GetBody().empty());
    EXPECT_EQ(context.options.GetBody().size(), static_cast<size_t>(0));
    curl_easy_cleanup(handle);
}

HWTEST_F(HttpInterceptorTest, ApplyBodyToCurlHandleNullArgumentsTest001, TestSize.Level1)
{
    auto manager = std::make_shared<OHOS::NetStack::EventManager>();
    RequestContext context(nullptr, manager);
    CURL *handle = curl_easy_init();
    ASSERT_NE(handle, nullptr);

    // 空句柄与空上下文都必须直接返回，不访问内部状态
    HttpInterceptor::ApplyBodyToCurlHandle(nullptr, &context);
    HttpInterceptor::ApplyBodyToCurlHandle(handle, nullptr);
    HttpInterceptor::ApplyBodyToCurlHandle(nullptr, nullptr);

    EXPECT_TRUE(context.options.GetBody().empty());
    curl_easy_cleanup(handle);
}

HWTEST_F(HttpInterceptorTest, BuildHeaderLineTest001, TestSize.Level1)
{
    // 空值用分号拼接，curl 才会发出空值头；冒号加空格会被 curl 当成删除该头
    EXPECT_EQ(HttpInterceptor::BuildHeaderLine("X-Empty", ""), "X-Empty;");
    EXPECT_EQ(HttpInterceptor::BuildHeaderLine("content-type", "application/json"),
        "content-type: application/json");
    EXPECT_EQ(HttpInterceptor::BuildHeaderLine("X-Number", "0"), "X-Number: 0");
}
} // namespace