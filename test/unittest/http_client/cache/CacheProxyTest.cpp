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

#include <chrono>
#include <map>
#include <thread>
#include "gtest/gtest.h"
#define private public
#include "cache_proxy.h"
#include "casche_constant.h"
#include "http_client_constant.h"
#include "http_client_request.h"
#include "http_client_response.h"
#include "lru_cache_disk_handler.h"

namespace OHOS::NetStack::HttpClient {
using namespace testing::ext;
extern std::atomic_bool g_cacheNeedRun;
extern std::atomic_bool g_cacheIsRunning;
extern std::condition_variable g_cacheThreadCondition;
extern std::condition_variable g_cacheNeedRunCondition;

class CacheProxyTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    void SetUp() {}

    void TearDown() {}
};

HWTEST_F(CacheProxyTest, CacheProxyTest001, TestSize.Level1)
{
    HttpClientRequest req;
    req.headers_[CACHE_CONTROL] = "CACHE_CONTROL";
    req.headers_[MIN_FRESH] = "MIN_FRESH";
    req.headers_[IF_NONE_MATCH] = "IF_NONE_MATCH";
    req.headers_[IF_MODIFIED_SINCE] = "IF_MODIFIED_SINCE";
    CacheProxy cache(req);
    EXPECT_EQ(cache.key_.empty(), false);
}

HWTEST_F(CacheProxyTest, CacheProxyReadResponseFromCacheTest001, TestSize.Level1)
{
    HttpClientRequest req;
    req.headers_[CACHE_CONTROL] = "CACHE_CONTROL";
    req.headers_[MIN_FRESH] = "MIN_FRESH";
    CacheProxy cache(req);
    g_cacheIsRunning.store(false);
    auto response = cache.ReadResponseFromCache();
    EXPECT_EQ(response, nullptr);
}

HWTEST_F(CacheProxyTest, CacheProxyReadResponseFromCacheTest002, TestSize.Level1)
{
    HttpClientRequest req;
    req.headers_[CACHE_CONTROL] = "CACHE_CONTROL";
    req.headers_[MIN_FRESH] = "MIN_FRESH";
    req.method_ = HttpConstant::HTTP_METHOD_GET;
    CacheProxy cache(req);
    g_cacheIsRunning.store(true);
    auto response = cache.ReadResponseFromCache();
    g_cacheIsRunning.store(false);
    EXPECT_EQ(response, nullptr);
}

HWTEST_F(CacheProxyTest, CacheProxyReadResponseFromCacheTest003, TestSize.Level1)
{
    HttpClientRequest req;
    req.headers_[CACHE_CONTROL] = "CACHE_CONTROL";
    req.headers_[MIN_FRESH] = "MIN_FRESH";
    req.method_ = HttpConstant::HTTP_METHOD_GET;
    CacheProxy cache(req);
    g_cacheIsRunning.store(true);
    HttpClientResponse response;
    response.rawHeader_ = "rawHeader_";
    response.cookies_ = "cookies_";
    response.responseTime_ = "2025-11-12 14:39:49";
    response.requestTime_ = "2025-11-12 14:20:49";
    response.responseCode_ = ResponseCode::OK;
    cache.strategy_.requestOptions_.method_ = HttpConstant::HTTP_METHOD_GET;
    cache.strategy_.cacheRequest_.noStore_ = false;
    cache.WriteResponseToCache(response);
    auto ret = cache.ReadResponseFromCache();
    g_cacheIsRunning.store(false);
    EXPECT_NE(ret, nullptr);
}

HWTEST_F(CacheProxyTest, CacheProxyReadResponseFromCacheTest004, TestSize.Level1)
{
    HttpClientRequest req;
    req.headers_[CACHE_CONTROL] = "CACHE_CONTROL";
    req.headers_[MIN_FRESH] = "MIN_FRESH";
    req.method_ = HttpConstant::HTTP_METHOD_GET;
    CacheProxy cache(req);
    g_cacheIsRunning.store(true);
    cache.strategy_.requestOptions_.method_ = HttpConstant::HTTP_METHOD_OPTIONS;
    HttpClientResponse response;
    cache.WriteResponseToCache(response);
    auto ret = cache.ReadResponseFromCache();
    g_cacheIsRunning.store(false);
    EXPECT_EQ(ret, nullptr);
}

HWTEST_F(CacheProxyTest, CacheProxyStopCacheAndDeleteTest001, TestSize.Level1)
{
    HttpClientRequest req;
    req.headers_[CACHE_CONTROL] = "CACHE_CONTROL";
    req.headers_[MIN_FRESH] = "MIN_FRESH";
    req.method_ = HttpConstant::HTTP_METHOD_GET;
    CacheProxy cache(req);
    g_cacheIsRunning.store(true);
    cache.FlushCache();
    g_cacheIsRunning.store(false);
    g_cacheNeedRun.store(true);
    cache.FlushCache();
    cache.StopCacheAndDelete();
    bool ret = g_cacheNeedRun == true;
    g_cacheNeedRun.store(false);
    EXPECT_EQ(ret, true);
}

HWTEST_F(CacheProxyTest, CacheProxyStopCacheAndDeleteTest002, TestSize.Level1)
{
    HttpClientRequest req;
    req.headers_[CACHE_CONTROL] = "CACHE_CONTROL";
    req.headers_[MIN_FRESH] = "MIN_FRESH";
    req.method_ = HttpConstant::HTTP_METHOD_GET;
    CacheProxy cache(req);
    g_cacheIsRunning.store(true);
    g_cacheNeedRun.store(true);
    std::thread([]() {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        g_cacheThreadCondition.notify_all();
        g_cacheIsRunning.store(false);
    }).detach();
    cache.StopCacheAndDelete();
    bool ret = g_cacheNeedRun == false;
    g_cacheNeedRun.store(false);
    EXPECT_EQ(ret, true);
}

HWTEST_F(CacheProxyTest, CacheProxyRunCacheTest001, TestSize.Level1)
{
    HttpClientRequest req;
    req.headers_[CACHE_CONTROL] = "CACHE_CONTROL";
    req.headers_[MIN_FRESH] = "MIN_FRESH";
    req.method_ = HttpConstant::HTTP_METHOD_GET;
    CacheProxy cache(req);
    g_cacheIsRunning.store(false);
    g_cacheNeedRun.store(false);
    std::thread([]() {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        g_cacheNeedRunCondition.notify_all();
    }).detach();
    cache.RunCache();
    auto ret = g_cacheNeedRun == true;
    g_cacheNeedRun.store(false);
    EXPECT_EQ(ret, true);
}

HWTEST_F(CacheProxyTest, CacheProxyRunCacheTest002, TestSize.Level1)
{
    HttpClientRequest req;
    CacheProxy cache(req);
    g_cacheIsRunning.store(true);
    g_cacheNeedRun.store(false);
    cache.RunCache();
    auto ret = g_cacheNeedRun == true;
    g_cacheIsRunning.store(false);
    EXPECT_EQ(ret, false);
}

HWTEST_F(CacheProxyTest, CacheProxyRunCacheTest003, TestSize.Level1)
{
    HttpClientRequest req;
    CacheProxy cache(req);
    g_cacheIsRunning.store(false);
    g_cacheNeedRun.store(false);
    std::thread([]() {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        g_cacheNeedRunCondition.notify_all();
        g_cacheNeedRun.store(false);
    }).detach();
    cache.RunCache();
    sleep(2);
    auto ret = g_cacheIsRunning == true;
    g_cacheIsRunning.store(false);
    EXPECT_EQ(ret, false);
}

HWTEST_F(CacheProxyTest, CacheProxyRunStrategyTest001, TestSize.Level1)
{
    HttpClientRequest req;
    req.headers_[CACHE_CONTROL] = "CACHE_CONTROL";
    req.headers_[MIN_FRESH] = "MIN_FRESH";
    req.method_ = HttpConstant::HTTP_METHOD_GET;
    CacheProxy cache(req);
    auto ret = cache.RunStrategy(nullptr);
    EXPECT_EQ(ret, CacheStatus::DENY);
}

HWTEST_F(CacheProxyTest, CacheProxyRunStrategyTest002, TestSize.Level1)
{
    HttpClientRequest req;
    req.headers_[CACHE_CONTROL] = "CACHE_CONTROL";
    req.headers_[MIN_FRESH] = "MIN_FRESH";
    req.method_ = HttpConstant::HTTP_METHOD_GET;
    CacheProxy cache(req);
    std::shared_ptr<HttpClientResponse> cachedResponse = std::make_shared<HttpClientResponse>();
    auto ret = cache.RunStrategy(cachedResponse);
    EXPECT_EQ(ret, CacheStatus::DENY);
}
} // namespace OHOS::NetStack::HttpClient
