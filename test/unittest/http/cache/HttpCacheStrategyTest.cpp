/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <algorithm>
#include <cstring>

#include "gtest/gtest.h"

#include "http_cache_request.h"
#include "http_cache_response.h"
#include "http_cache_strategy.h"
#include "netstack_log.h"

using namespace OHOS::NetStack;

class HttpCacheStrategyTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

namespace {
HWTEST_F(HttpCacheStrategyTest, cacheRequestNoCache, testing::ext::TestSize.Level1)
{
    HttpRequestOptions requestOptions;
    requestOptions.SetHeader("cache-control", "no-cache");
    requestOptions.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");

    HttpResponse response;
    response.SetResponseCode(200);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");
    auto &responseHeader = const_cast<std::map<std::string, std::string> &>(response.GetHeader());
    responseHeader["expires"] = "Sat, 04 Jun 2022 09:56:21 GMT";

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    NETSTACK_LOGI("status = %{public}d", status);

    EXPECT_EQ(status, 2);
}

HWTEST_F(HttpCacheStrategyTest, computeFreshnessLifetimeLastModifiedBranch, testing::ext::TestSize.Level1)
{
    HttpRequestOptions requestOptions;
    requestOptions.SetHeader("cache-control", "min-fresh=20");
    requestOptions.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");

    HttpResponse response;
    response.SetResponseCode(200);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");
    auto &responseHeader = const_cast<std::map<std::string, std::string> &>(response.GetHeader());
    responseHeader["Cache-Control"] = "public";
    responseHeader["last-modified"] = "Thu, 10 Feb 2022 10:55:14 GMT";
    responseHeader["date"] = "Fri, 20 May 2022 09:37:29 GMT";

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    NETSTACK_LOGI("status = %{public}d", status);

    EXPECT_EQ(status, STALE);
}

HWTEST_F(HttpCacheStrategyTest, cacheResponseNoCache, testing::ext::TestSize.Level1)
{
    HttpRequestOptions requestOptions;
    requestOptions.SetHeader("cache-control", "min-fresh=20");
    requestOptions.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");

    HttpResponse response;
    response.SetResponseCode(200);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");
    auto &responseHeader = const_cast<std::map<std::string, std::string> &>(response.GetHeader());
    responseHeader["Cache-Control"] = "no-cache";

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    NETSTACK_LOGI("status = %{public}d", status);

    EXPECT_EQ(status, 1);
}

HWTEST_F(HttpCacheStrategyTest, cacheRequestOnlyIfCached, testing::ext::TestSize.Level1)
{
    HttpRequestOptions requestOptions;
    requestOptions.SetHeader("cache-control", "only-if-cached");
    requestOptions.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");

    HttpResponse response;
    response.SetResponseCode(200);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");
    auto &responseHeader = const_cast<std::map<std::string, std::string> &>(response.GetHeader());
    responseHeader["Cache-Control"] = "max-age=70";

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    NETSTACK_LOGI("status = %{public}d", status);

    EXPECT_EQ(status, 0);
}

HWTEST_F(HttpCacheStrategyTest, isCacheable, testing::ext::TestSize.Level1)
{
    HttpRequestOptions requestOptions;
    requestOptions.SetHeader("cache-control", "min-fresh=20");
    requestOptions.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");

    HttpResponse response;
    response.SetResponseCode(303);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");
    auto &responseHeader = const_cast<std::map<std::string, std::string> &>(response.GetHeader());
    responseHeader["Cache-Control"] = "max-age=70";

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    NETSTACK_LOGI("status = %{public}d", status);

    EXPECT_EQ(status, 2);
}

HWTEST_F(HttpCacheStrategyTest, isCacheable_OK, testing::ext::TestSize.Level1)
{
    HttpRequestOptions requestOptions;
    requestOptions.SetHeader("cache-control", "min-fresh=20");
    requestOptions.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");

    HttpResponse response;
    response.SetResponseCode(200);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");
    auto &responseHeader = const_cast<std::map<std::string, std::string> &>(response.GetHeader());
    responseHeader["Cache-Control"] = "max-age=70";

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    NETSTACK_LOGI("status = %{public}d", status);

    EXPECT_EQ(status, STALE);
}

HWTEST_F(HttpCacheStrategyTest, requestIfModifiedSinceStr, testing::ext::TestSize.Level1)
{
    HttpRequestOptions requestOptions;
    requestOptions.SetHeader("if-modified-since", "Thu, 10 Feb 2022 10:55:14 GMT");
    requestOptions.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");

    HttpResponse response;
    response.SetResponseCode(200);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");
    auto &responseHeader = const_cast<std::map<std::string, std::string> &>(response.GetHeader());
    responseHeader["Cache-Control"] = "max-age=70";

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    NETSTACK_LOGI("status = %{public}d", status);

    EXPECT_EQ(status, 2);
}

HWTEST_F(HttpCacheStrategyTest, requestgetIfNoneMatch, testing::ext::TestSize.Level1)
{
    HttpRequestOptions requestOptions;
    requestOptions.SetHeader("if-none-match", "A6E52F1D544D9DAFB552163A1CF8AD10");
    requestOptions.SetHeader("if-modified-since", "Thu, 10 Feb 2022 10:55:14 GMT");
    requestOptions.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");

    HttpResponse response;
    response.SetResponseCode(200);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");
    auto &responseHeader = const_cast<std::map<std::string, std::string> &>(response.GetHeader());
    responseHeader["Cache-Control"] = "max-age=70";

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    NETSTACK_LOGI("status = %{public}d", status);

    EXPECT_EQ(status, 2);
}

HWTEST_F(HttpCacheStrategyTest, requestgetIfNoneMatchAndIfModifiedSinceStr, testing::ext::TestSize.Level1)
{
    HttpRequestOptions requestOptions;
    requestOptions.SetHeader("if-none-match", "A6E52F1D544D9DAFB552163A1CF8AD10");
    requestOptions.SetHeader("if-modified-since", "Thu, 10 Feb 2022 10:55:14 GMT");
    requestOptions.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");

    HttpResponse response;
    response.SetResponseCode(200);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");
    auto &responseHeader = const_cast<std::map<std::string, std::string> &>(response.GetHeader());
    responseHeader["Cache-Control"] = "max-age=70";

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    NETSTACK_LOGI("status = %{public}d", status);

    EXPECT_EQ(status, 2);
}

HWTEST_F(HttpCacheStrategyTest, strategyMaxAgeBranch, testing::ext::TestSize.Level1) // test
{
    HttpRequestOptions requestOptions;
    requestOptions.SetHeader("cache-control", "max-age=10");
    requestOptions.SetRequestTime("Fri, 20 May 2022 09:36:19 GMT");

    HttpResponse response;
    response.SetResponseCode(200);
    response.SetResponseTime("Fri,  20 May 2022 09:36:30 GMT");
    auto &responseHeader = const_cast<std::map<std::string, std::string> &>(response.GetHeader());
    responseHeader["Cache-Control"] = "max-age=70";

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    NETSTACK_LOGI("status = %{public}d", status);

    EXPECT_EQ(status, STALE);
}

HWTEST_F(HttpCacheStrategyTest, CompareNumber_1, testing::ext::TestSize.Level1)
{
    HttpRequestOptions requestOptions;
    requestOptions.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");

    HttpResponse response;
    response.SetResponseCode(200);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");
    auto &responseHeader = const_cast<std::map<std::string, std::string> &>(response.GetHeader());
    responseHeader["age"] = "33781";

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    NETSTACK_LOGI("status = %{public}d", status);

    EXPECT_EQ(status, 1);
}

HWTEST_F(HttpCacheStrategyTest, CompareNumber_1_2, testing::ext::TestSize.Level1)
{
    HttpRequestOptions requestOptions;
    requestOptions.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");

    HttpResponse response;
    response.SetResponseCode(200);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");
    auto &responseHeader = const_cast<std::map<std::string, std::string> &>(response.GetHeader());
    responseHeader["age"] = "33781";
    responseHeader["etag"] = "6f6741d197947f9f10943d36c4d8210e";

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    NETSTACK_LOGI("status = %{public}d", status);

    EXPECT_EQ(status, 1);
}

HWTEST_F(HttpCacheStrategyTest, CompareNumber_2, testing::ext::TestSize.Level1)
{
    HttpRequestOptions requestOptions;
    requestOptions.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");
    requestOptions.SetHeader("cache-control", "max-age=10");

    HttpResponse response;
    response.SetResponseCode(200);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");
    auto &responseHeader = const_cast<std::map<std::string, std::string> &>(response.GetHeader());
    responseHeader["age"] = "10";
    responseHeader["cache-control"] = "private";
    responseHeader["expires"] = "Mon, 16 May 2022 10:31:58 GMT";

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    NETSTACK_LOGI("status = %{public}d", status);

    EXPECT_EQ(status, 1);
}

HWTEST_F(HttpCacheStrategyTest, CompareNumber_3, testing::ext::TestSize.Level1)
{
    HttpRequestOptions requestOptions;
    requestOptions.SetRequestTime("Mon, 16 May 2022 09:32:59 GMT");
    requestOptions.SetHeader("cache-control", "no-cache");

    HttpResponse response;
    response.SetResponseCode(200);
    response.SetResponseTime("Mon, 16 May 2022 09:33:59 GMT");
    auto &responseHeader = const_cast<std::map<std::string, std::string> &>(response.GetHeader());
    responseHeader["age"] = "0";

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    NETSTACK_LOGI("status = %{public}d", status);

    EXPECT_EQ(status, 2);
}

HWTEST_F(HttpCacheStrategyTest, CompareNumber_4, testing::ext::TestSize.Level1)
{
    HttpRequestOptions requestOptions;
    requestOptions.SetRequestTime("Mon, 16 May 2022 09:32:59 GMT");
    requestOptions.SetHeader("if-modified-since", "Thu, 10 Feb 2022 10:55:14 GMT");

    HttpResponse response;
    response.SetResponseCode(200);
    response.SetResponseTime("Mon, 16 May 2022 09:33:59 GMT");
    auto &responseHeader = const_cast<std::map<std::string, std::string> &>(response.GetHeader());
    responseHeader["age"] = "33781";

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    NETSTACK_LOGI("status = %{public}d", status);

    EXPECT_EQ(status, 2);
}

HWTEST_F(HttpCacheStrategyTest, CompareNumber_5, testing::ext::TestSize.Level1)
{
    HttpRequestOptions requestOptions;
    requestOptions.SetRequestTime("Thu, 19 May 2022 08:19:59 GMT");
    requestOptions.SetHeader("cache-control", "min-fresh=20");

    HttpResponse response;
    response.SetResponseCode(200);
    response.SetResponseTime("Thu, 19 May 2022 08:21:59 GMT");
    auto &responseHeader = const_cast<std::map<std::string, std::string> &>(response.GetHeader());
    responseHeader["expires"] = "Thu, 19 May 2022 08:22:26 GMT";

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    NETSTACK_LOGI("status = %{public}d", status);

    EXPECT_EQ(status, STALE);
}

HWTEST_F(HttpCacheStrategyTest, CompareNumber_6, testing::ext::TestSize.Level1)
{
    HttpRequestOptions requestOptions;
    requestOptions.SetRequestTime("Thu, 20 May 2022 09:35:59 GMT");
    requestOptions.SetHeader("cache-control", "min-fresh=20");

    HttpResponse response;
    response.SetResponseCode(200);
    response.SetResponseTime("Thu, 20 May 2022 09:36:30 GMT");
    auto &responseHeader = const_cast<std::map<std::string, std::string> &>(response.GetHeader());
    responseHeader["expires"] = "Sat, 04 Jun 2022 09:56:21 GMT";
    responseHeader["date"] = "Fri, 20 May 2022 09:37:29 GMT";

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    NETSTACK_LOGI("status = %{public}d", status);

    EXPECT_EQ(status, STALE);
}

HWTEST_F(HttpCacheStrategyTest, CompareNumber_7, testing::ext::TestSize.Level1)
{
    HttpRequestOptions requestOptions;
    requestOptions.SetRequestTime("Thu, 20 May 2022 09:35:59 GMT");
    requestOptions.SetHeader("cache-control", "min-fresh=20");

    HttpResponse response;
    response.SetResponseCode(200);
    response.SetResponseTime("Thu, 20 May 2022 09:36:30 GMT");
    auto &responseHeader = const_cast<std::map<std::string, std::string> &>(response.GetHeader());
    responseHeader["expires"] = "Sat, 04 Jun 2022 09:56:21 GMT";
    responseHeader["last-modified"] = "Thu, 10 Feb 2022 10:55:14 GMT";
    responseHeader["date"] = "Fri, 20 May 2022 09:37:29 GMT";

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    NETSTACK_LOGI("status = %{public}d", status);

    EXPECT_EQ(status, STALE);
}

HWTEST_F(HttpCacheStrategyTest, CompareNumber_8, testing::ext::TestSize.Level1)
{
    HttpRequestOptions requestOptions;
    requestOptions.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");
    requestOptions.SetHeader("cache-control", "min-fresh=20");

    HttpResponse response;
    response.SetResponseCode(200);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");

    auto &responseHeader = const_cast<std::map<std::string, std::string> &>(response.GetHeader());
    responseHeader["expires"] = "Sat, 04 Jun 2022 09:56:21 GMT";
    responseHeader["last-modified"] = "Thu, 10 Feb 2022 10:55:14 GMT";
    responseHeader["etag"] = "6f6741d197947f9f10943d36c4d8210e";
    responseHeader["date"] = "Fri, 20 May 2022 09:37:29 GMT";

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    NETSTACK_LOGI("status = %{public}d", status);

    EXPECT_EQ(status, STALE);
}

HWTEST_F(HttpCacheStrategyTest, CompareNumber_9, testing::ext::TestSize.Level1)
{
    HttpRequestOptions requestOptions;
    requestOptions.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");
    requestOptions.SetHeader("cache-control", "min-fresh=20");

    HttpResponse response;
    response.SetResponseCode(200);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");

    auto &responseHeader = const_cast<std::map<std::string, std::string> &>(response.GetHeader());
    responseHeader["age"] = "60";

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    NETSTACK_LOGI("status = %{public}d", status);

    EXPECT_EQ(status, 1);
}

HWTEST_F(HttpCacheStrategyTest, computeFreshnessLifetimeLastModifiedNoDateBranch, testing::ext::TestSize.Level1)
{
    HttpRequestOptions requestOptions;
    requestOptions.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");
    requestOptions.SetHeader("cache-control", "min-fresh=20");

    HttpResponse response;
    response.SetResponseCode(200);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");

    auto &responseHeader = const_cast<std::map<std::string, std::string> &>(response.GetHeader());
    responseHeader["cache-control"] = "public";
    responseHeader["last-modified"] = "Thu, 10 Feb 2022 10:55:14 GMT";

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    NETSTACK_LOGI("status = %{public}d", status);

    EXPECT_EQ(status, 1);
}

HWTEST_F(HttpCacheStrategyTest, cache110WarningBranch, testing::ext::TestSize.Level1)
{
    HttpRequestOptions requestOptions;
    requestOptions.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");
    requestOptions.SetHeader("cache-control", "min-fresh=60, max-stale=2000");

    HttpResponse response;
    response.SetResponseCode(200);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");

    auto &responseHeader = const_cast<std::map<std::string, std::string> &>(response.GetHeader());
    responseHeader["cache-control"] = "max-age=60, max-stale=500000000";
    responseHeader["last-modified"] = "Thu, 10 Feb 2022 10:55:14 GMT";
    responseHeader["date"] = "Fri, 20 May 2022 09:50:29 GMT";

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    NETSTACK_LOGI("status = %{public}d", status);

    EXPECT_EQ(status, STALE);
}

CacheStatus switchTest(ResponseCode code)
{
    HttpRequestOptions requestOptions;
    requestOptions.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");
    requestOptions.SetHeader("cache-control", "min-fresh=60, max-stale=2000");

    HttpResponse response;
    response.SetResponseCode(static_cast<uint32_t>(code));
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");

    auto &responseHeader = const_cast<std::map<std::string, std::string> &>(response.GetHeader());
    responseHeader["cache-control"] = "max-age=60, max-stale=500000000";
    responseHeader["last-modified"] = "Thu, 10 Feb 2022 10:55:14 GMT";
    responseHeader["date"] = "Fri, 20 May 2022 09:50:29 GMT";

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    return status;
}

HWTEST_F(HttpCacheStrategyTest, cacheSwitchBranch, testing::ext::TestSize.Level1)
{
    CacheStatus result;
    std::vector<ResponseCode> respCode = {ResponseCode::OK,           ResponseCode::NOT_AUTHORITATIVE,
                                          ResponseCode::NO_CONTENT,   ResponseCode::MULT_CHOICE,
                                          ResponseCode::MOVED_PERM,   ResponseCode::NOT_FOUND,
                                          ResponseCode::BAD_METHOD,   ResponseCode::GONE,
                                          ResponseCode::REQ_TOO_LONG, ResponseCode::NOT_IMPLEMENTED};

    for (const auto &iterRespCode : respCode) {
        NETSTACK_LOGI("respCode:%d", iterRespCode);
    }

    for (const auto &iterRespCode : respCode) {
        result = switchTest(iterRespCode);
        EXPECT_EQ(result, STALE);
    }
}

HWTEST_F(HttpCacheStrategyTest, cache113WarningBranch, testing::ext::TestSize.Level1)
{
    HttpRequestOptions requestOptions;
    requestOptions.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");
    requestOptions.SetHeader("cache-control", "min-fresh=2, max-stale=9000000000");

    HttpResponse response;
    response.SetResponseCode(200);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");

    auto &responseHeader = const_cast<std::map<std::string, std::string> &>(response.GetHeader());
    responseHeader["cache-control"] = "max-stale=5000000000000000";
    responseHeader["last-modified"] = "Sat, 04 Jun 2022 09:56:21 GMT";
    responseHeader["date"] = "Mon, 20 Jun 2022 09:56:21 GMT";

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    NETSTACK_LOGI("status = %{public}d", status);

    EXPECT_EQ(status, FRESH);
}

HWTEST_F(HttpCacheStrategyTest, reqHeaderEtagBranch, testing::ext::TestSize.Level1)
{
    HttpRequestOptions requestOptions;
    requestOptions.SetRequestTime("Thu, 19 May 2022 08:19:59 GMT");
    requestOptions.SetHeader("cache-control", "min-fresh=20");

    HttpResponse response;
    response.SetResponseCode(200);
    response.SetResponseTime("Thu,  19 May 2022 08:21:59 GMT");

    auto &responseHeader = const_cast<std::map<std::string, std::string> &>(response.GetHeader());
    responseHeader["expires"] = "Thu, 19 May 2022 08:22:26 GMT";
    responseHeader["etag"] = "6f6741d197947f9f10943d36c4d8210e";

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    NETSTACK_LOGI("status = %{public}d", status);

    EXPECT_EQ(status, STALE);
}

HWTEST_F(HttpCacheStrategyTest, reqHeaderLastModifiedBranch, testing::ext::TestSize.Level1)
{
    HttpRequestOptions requestOptions;
    requestOptions.SetRequestTime("Thu, 19 May 2022 08:19:59 GMT");
    requestOptions.SetHeader("cache-control", "min-fresh=20");

    HttpResponse response;
    response.SetResponseCode(200);
    response.SetResponseTime("Thu,  19 May 2022 08:21:59 GMT");

    auto &responseHeader = const_cast<std::map<std::string, std::string> &>(response.GetHeader());
    responseHeader["expires"] = "Thu, 19 May 2022 08:22:26 GMT";
    responseHeader["last-modified"] = "Sat, 04 Jun 2022 09:56:21 GMT";

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    NETSTACK_LOGI("status = %{public}d", status);

    EXPECT_EQ(status, STALE);
}

HWTEST_F(HttpCacheStrategyTest, reqHeaderDateBranch, testing::ext::TestSize.Level1)
{
    HttpRequestOptions requestOptions;
    requestOptions.SetRequestTime("Thu, 19 May 2022 08:19:59 GMT");
    requestOptions.SetHeader("cache-control", "min-fresh=20");

    HttpResponse response;
    response.SetResponseCode(200);
    response.SetResponseTime("Thu,  19 May 2022 08:21:59 GMT");

    auto &responseHeader = const_cast<std::map<std::string, std::string> &>(response.GetHeader());
    responseHeader["expires"] = "Thu, 19 May 2022 08:22:26 GMT";
    responseHeader["date"] = "Sat, 04 Jun 2022 09:56:21 GMT";

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    NETSTACK_LOGI("status = %{public}d", status);

    EXPECT_EQ(status, STALE);
}

HWTEST_F(HttpCacheStrategyTest, headerNull, testing::ext::TestSize.Level1)
{
    HttpRequestOptions requestOptions;
    requestOptions.SetRequestTime("Thu, 19 May 2022 08:19:59 GMT");

    HttpResponse response;
    response.SetResponseCode(200);
    response.SetResponseTime("Thu,  19 May 2022 08:21:59 GMT");

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    NETSTACK_LOGI("status = %{public}d", status);

    EXPECT_EQ(status, STALE);
}

HWTEST_F(HttpCacheStrategyTest, requestTimeEmpty, testing::ext::TestSize.Level1)
{
    HttpRequestOptions requestOptions;

    HttpResponse response;
    response.SetResponseCode(200);
    response.SetResponseTime("Thu,  19 May 2022 08:21:59 GMT");

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    NETSTACK_LOGI("status = %{public}d", status);

    EXPECT_EQ(status, STALE);
}

HWTEST_F(HttpCacheStrategyTest, computeFreshnessLifetimeEnd, testing::ext::TestSize.Level1)
{
    HttpRequestOptions requestOptions;
    requestOptions.SetRequestTime("Thu, 19 May 2022 08:19:59 GMT");

    HttpResponse response;
    response.SetResponseCode(200);
    response.SetResponseTime("Thu,  19 May 2022 08:21:59 GMT");

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    NETSTACK_LOGI("status = %{public}d", status);

    EXPECT_EQ(status, STALE);
}

HWTEST_F(HttpCacheStrategyTest, isCacheableMovedTempIfCondition, testing::ext::TestSize.Level1)
{
    HttpRequestOptions requestOptions;
    requestOptions.SetRequestTime("Fri, 20 May 2022 09:35:59 GMT");
    requestOptions.SetHeader("cache-control", "min-fresh=20");

    HttpResponse response;
    response.SetResponseCode(static_cast<uint32_t>(ResponseCode::MOVED_TEMP));
    response.SetResponseTime("Fri, 20 May 2022 09:36:30 GMT");

    auto &responseHeader = const_cast<std::map<std::string, std::string> &>(response.GetHeader());
    responseHeader["cache-control"] = "private";
    responseHeader["last-modified"] = "Thu, 10 Feb 2022 10:55:14 GMT";

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    NETSTACK_LOGI("status = %{public}d", status);

    EXPECT_EQ(status, STALE);
}

HWTEST_F(HttpCacheStrategyTest, computeFreshnessLifetimeDelta, testing::ext::TestSize.Level1)
{
    HttpRequestOptions requestOptions;
    requestOptions.SetRequestTime("Fri, 20 May 2022 09:35:59 GMT");
    requestOptions.SetHeader("cache-control", "min-fresh=20");

    HttpResponse response;
    response.SetResponseCode(200);
    response.SetResponseTime("Fri, 20 May 2022 09:36:30 GMT");

    auto &responseHeader = const_cast<std::map<std::string, std::string> &>(response.GetHeader());
    responseHeader["last-modified"] = "Mon, 18 Jul 2022 10:55:14 GMT";

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    NETSTACK_LOGI("status = %{public}d", status);

    EXPECT_EQ(status, STALE);
}

HWTEST_F(HttpCacheStrategyTest, isCacheUsefulMaxStaleMillis, testing::ext::TestSize.Level1)
{
    HttpRequestOptions requestOptions;
    requestOptions.SetRequestTime("Fri, 20 May 2022 09:35:59 GMT");
    requestOptions.SetHeader("cache-control", "max-stale=20");

    HttpResponse response;
    response.SetResponseCode(200);
    response.SetResponseTime("Fri, 20 May 2022 09:36:30 GMT");

    auto &responseHeader = const_cast<std::map<std::string, std::string> &>(response.GetHeader());
    responseHeader["last-modified"] = "Thu, 10 Feb 2022 10:55:14 GMT";

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    NETSTACK_LOGI("status = %{public}d", status);

    EXPECT_EQ(status, STALE);
}

HWTEST_F(HttpCacheStrategyTest, isCacheableMovedTempIfCondition2, testing::ext::TestSize.Level1)
{
    HttpRequestOptions requestOptions;
    requestOptions.SetRequestTime("Fri, 20 May 2022 09:35:59 GMT");
    requestOptions.SetHeader("cache-control", "min-fresh=20, no-store");

    HttpResponse response;
    response.SetResponseCode(200);
    response.SetResponseTime("Fri, 20 May 2022 09:36:30 GMT");

    auto &responseHeader = const_cast<std::map<std::string, std::string> &>(response.GetHeader());
    responseHeader["cache-control"] = "private";
    responseHeader["last-modified"] = "Thu, 10 Feb 2022 10:55:14 GMT";

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    NETSTACK_LOGI("status = %{public}d", status);

    EXPECT_EQ(status, DENY);
}

HWTEST_F(HttpCacheStrategyTest, isCacheableMovedTempIfCondition3, testing::ext::TestSize.Level1)
{
    HttpRequestOptions requestOptions;
    requestOptions.SetRequestTime("Fri, 20 May 2022 09:35:59 GMT");
    requestOptions.SetHeader("cache-control", "min-fresh=20");

    HttpResponse response;
    response.SetResponseCode(200);
    response.SetResponseTime("Fri, 20 May 2022 09:36:30 GMT");

    auto &responseHeader = const_cast<std::map<std::string, std::string> &>(response.GetHeader());
    responseHeader["cache-control"] = "private, no-store";
    responseHeader["last-modified"] = "Thu, 10 Feb 2022 10:55:14 GMT";

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    NETSTACK_LOGI("status = %{public}d", status);

    EXPECT_EQ(status, DENY);
}

HWTEST_F(HttpCacheStrategyTest, isCacheableMovedTempIfCondition4, testing::ext::TestSize.Level1)
{
    HttpRequestOptions requestOptions;
    requestOptions.SetRequestTime("Fri, 20 May 2022 09:35:59 GMT");
    requestOptions.SetHeader("cache-control", "min-fresh=20");

    HttpResponse response;
    response.SetResponseCode(200);
    response.SetResponseTime("Fri, 20 May 2022 09:36:30 GMT");

    auto &responseHeader = const_cast<std::map<std::string, std::string> &>(response.GetHeader());
    responseHeader["cache-control"] = "private, must-revalidate";
    responseHeader["last-modified"] = "Thu, 10 Feb 2022 10:55:14 GMT";

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    NETSTACK_LOGI("status = %{public}d", status);

    EXPECT_EQ(status, STALE);
}

HWTEST_F(HttpCacheStrategyTest, CompareNumber_6_2, testing::ext::TestSize.Level1)
{
    HttpRequestOptions requestOptions;
    requestOptions.SetRequestTime("Fri, 20 May 2022 09:35:59 GMT");
    requestOptions.SetHeader("cache-control", "min-fresh=20");

    HttpResponse response;
    response.SetResponseCode(200);
    response.SetResponseTime("Fri, 20 May 2022 09:36:30 GMT");

    auto &responseHeader = const_cast<std::map<std::string, std::string> &>(response.GetHeader());
    responseHeader["cache-control"] = "no-cache";
    responseHeader["expires"] = "Sat, 04 Jun 2022 09:56:21 GMT";
    responseHeader["date"] = "Fri, 20 May 2022 09:37:29 GMT";

    HttpCacheStrategy cacheStrategy(requestOptions);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    NETSTACK_LOGI("status = %{public}d", status);

    EXPECT_EQ(status, STALE);
}
} // namespace