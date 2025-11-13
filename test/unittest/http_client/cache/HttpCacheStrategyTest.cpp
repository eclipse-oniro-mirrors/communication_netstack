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

#include <algorithm>
#include <cstring>

#include "gtest/gtest.h"

#define private public

#include "http_cache_request.h"
#include "http_cache_response.h"
#include "http_cache_strategy.h"

using namespace OHOS::NetStack::HttpClient;

class HttpClientCacheStrategyTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

namespace {
    using namespace std;
    using namespace testing::ext;

HWTEST_F(HttpClientCacheStrategyTest, cacheRequestNoCache, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetHeader("cache-control", "no-cache");
    httpReq.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");

    response.headers_["expires"] = "Sat, 04 Jun 2022 09:56:21 GMT";
    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, 2);
}

HWTEST_F(HttpClientCacheStrategyTest, computeFreshnessLifetimeLastModifiedBranch, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetHeader("cache-control", "min-fresh=20");
    httpReq.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");
    
    response.headers_["Cache-Control"] = "public";
    response.headers_["last-modified"] = "Thu, 10 Feb 2022 10:55:14 GMT";
    response.headers_["date"] = "Fri, 20 May 2022 09:37:29 GMT";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    EXPECT_EQ(status, STALE);
}

HWTEST_F(HttpClientCacheStrategyTest, cacheResponseNoCache, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetHeader("cache-control", "min-fresh=20");
    httpReq.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");
    response.headers_["Cache-Control"] = "no-cache";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, 1);
}

HWTEST_F(HttpClientCacheStrategyTest, cacheRequestOnlyIfCached, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetHeader("cache-control", "only-if-cached");
    httpReq.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");
    response.headers_["Cache-Control"] = "max-age=70";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, 0);
}

HWTEST_F(HttpClientCacheStrategyTest, isCacheable, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetHeader("cache-control", "min-fresh=20");
    httpReq.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::SEE_OTHER);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");
    response.headers_["Cache-Control"] = "max-age=70";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, 2);
}

HWTEST_F(HttpClientCacheStrategyTest, isCacheable_OK, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetHeader("cache-control", "min-fresh=20");
    httpReq.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");
    response.headers_["Cache-Control"] = "max-age=70";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, STALE);
}

HWTEST_F(HttpClientCacheStrategyTest, requestIfModifiedSinceStr, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetHeader("if-modified-since", "Thu, 10 Feb 2022 10:55:14 GMT");
    httpReq.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");
    response.headers_["Cache-Control"] = "max-age=70";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, 2);
}

HWTEST_F(HttpClientCacheStrategyTest, requestgetIfNoneMatch, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetHeader("if-none-match", "A6E52F1D544D9DAFB552163A1CF8AD10");
    httpReq.SetHeader("if-modified-since", "Thu, 10 Feb 2022 10:55:14 GMT");
    httpReq.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");
    response.headers_["Cache-Control"] = "max-age=70";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, 2);
}

HWTEST_F(HttpClientCacheStrategyTest, requestgetIfNoneMatchAndIfModifiedSinceStr, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetHeader("if-none-match", "A6E52F1D544D9DAFB552163A1CF8AD10");
    httpReq.SetHeader("if-modified-since", "Thu, 10 Feb 2022 10:55:14 GMT");
    httpReq.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");
    response.headers_["Cache-Control"] = "max-age=70";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, 2);
}

HWTEST_F(HttpClientCacheStrategyTest, strategyMaxAgeBranch, TestSize.Level1) // test
{
    HttpClientRequest httpReq;
    httpReq.SetHeader("cache-control", "max-age=10");
    httpReq.SetRequestTime("Fri, 20 May 2022 09:36:19 GMT");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Fri,  20 May 2022 09:36:30 GMT");
    response.headers_["Cache-Control"] = "max-age=70";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, STALE);
}

HWTEST_F(HttpClientCacheStrategyTest, CompareNumber_1, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");
    response.headers_["age"] = "33781";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, 1);
}

HWTEST_F(HttpClientCacheStrategyTest, CompareNumber_1_2, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");
    response.headers_["age"] = "33781";
    response.headers_["etag"] = "6f6741d197947f9f10943d36c4c4210e";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, 1);
}

HWTEST_F(HttpClientCacheStrategyTest, CompareNumber_2, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");
    httpReq.SetHeader("cache-control", "max-age=10");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");
    response.headers_["age"] = "10";
    response.headers_["cache-control"] = "private";
    response.headers_["expires"] = "Mon, 16 May 2022 10:31:58 GMT";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, 1);
}

HWTEST_F(HttpClientCacheStrategyTest, CompareNumber_3, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetRequestTime("Mon, 16 May 2022 09:32:59 GMT");
    httpReq.SetHeader("cache-control", "no-cache");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Mon, 16 May 2022 09:33:59 GMT");
    response.headers_["age"] = "0";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, 2);
}

HWTEST_F(HttpClientCacheStrategyTest, CompareNumber_4, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetRequestTime("Mon, 16 May 2022 09:32:59 GMT");
    httpReq.SetHeader("if-modified-since", "Thu, 10 Feb 2022 10:55:14 GMT");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Mon, 16 May 2022 09:33:59 GMT");
    response.headers_["age"] = "33781";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, 2);
}

HWTEST_F(HttpClientCacheStrategyTest, CompareNumber_5, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetRequestTime("Thu, 19 May 2022 08:19:59 GMT");
    httpReq.SetHeader("cache-control", "min-fresh=20");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Thu, 19 May 2022 08:21:59 GMT");
    response.headers_["expires"] = "Thu, 19 May 2022 08:22:26 GMT";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, STALE);
}

HWTEST_F(HttpClientCacheStrategyTest, CompareNumber_6, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetRequestTime("Thu, 20 May 2022 09:35:59 GMT");
    httpReq.SetHeader("cache-control", "min-fresh=20");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Thu, 20 May 2022 09:36:30 GMT");
    response.headers_["expires"] = "Sat, 04 Jun 2022 09:56:21 GMT";
    response.headers_["date"] = "Fri, 20 May 2022 09:37:29 GMT";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, STALE);
}

HWTEST_F(HttpClientCacheStrategyTest, CompareNumber_7, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetRequestTime("Thu, 20 May 2022 09:35:59 GMT");
    httpReq.SetHeader("cache-control", "min-fresh=20");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Thu, 20 May 2022 09:36:30 GMT");
    response.headers_["expires"] = "Sat, 04 Jun 2022 09:56:21 GMT";
    response.headers_["last-modified"] = "Thu, 10 Feb 2022 10:55:14 GMT";
    response.headers_["date"] = "Fri, 20 May 2022 09:37:29 GMT";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, STALE);
}

HWTEST_F(HttpClientCacheStrategyTest, CompareNumber_8, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");
    httpReq.SetHeader("cache-control", "min-fresh=20");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");
    response.headers_["expires"] = "Sat, 04 Jun 2022 09:56:21 GMT";
    response.headers_["last-modified"] = "Thu, 10 Feb 2022 10:55:14 GMT";
    response.headers_["etag"] = "6f6741d197947f9f10943d36c4c4210e";
    response.headers_["date"] = "Fri, 20 May 2022 09:37:29 GMT";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, STALE);
}

HWTEST_F(HttpClientCacheStrategyTest, CompareNumber_9, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");
    httpReq.SetHeader("cache-control", "min-fresh=20");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");
    response.headers_["age"] = "60";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, 1);
}

HWTEST_F(HttpClientCacheStrategyTest, computeFreshnessLifetimeLastModifiedNoDateBranch, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");
    httpReq.SetHeader("cache-control", "min-fresh=20");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");
    response.headers_["cache-control"] = "public";
    response.headers_["last-modified"] = "Thu, 10 Feb 2022 10:55:14 GMT";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, 1);
}

HWTEST_F(HttpClientCacheStrategyTest, cache110WarningBranch, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");
    httpReq.SetHeader("cache-control", "min-fresh=60, max-stale=2000");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");
    response.headers_["cache-control"] = "max-age=60, max-stale=500000000";
    response.headers_["last-modified"] = "Thu, 10 Feb 2022 10:55:14 GMT";
    response.headers_["date"] = "Fri, 20 May 2022 09:50:29 GMT";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, STALE);
}

CacheStatus switchTest(ResponseCode code)
{
    HttpClientRequest httpReq;
    httpReq.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");
    httpReq.SetHeader("cache-control", "min-fresh=60, max-stale=2000");

    HttpClientResponse response;
    response.SetResponseCode(code);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");
    response.headers_["cache-control"] = "max-age=60, max-stale=500000000";
    response.headers_["last-modified"] = "Thu, 10 Feb 2022 10:55:14 GMT";
    response.headers_["date"] = "Fri, 20 May 2022 09:50:29 GMT";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);
    return status;
}

HWTEST_F(HttpClientCacheStrategyTest, cacheSwitchBranch, TestSize.Level1)
{
    CacheStatus result;
    std::vector<ResponseCode> respCode = {ResponseCode::OK,           ResponseCode::NOT_AUTHORITATIVE,
                                          ResponseCode::NO_CONTENT,   ResponseCode::MULT_CHOICE,
                                          ResponseCode::MOVED_PERM,   ResponseCode::NOT_FOUND,
                                          ResponseCode::BAD_METHOD,   ResponseCode::GONE,
                                          ResponseCode::REQ_TOO_LONG, ResponseCode::NOT_IMPLEMENTED};

    for (const auto &iterRespCode : respCode) {
        result = switchTest(iterRespCode);
        EXPECT_EQ(result, STALE);
    }
}

HWTEST_F(HttpClientCacheStrategyTest, cache113WarningBranch, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");
    httpReq.SetHeader("cache-control", "min-fresh=2, max-stale=9000000000");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");
    response.headers_["cache-control"] = "max-stale=5000000000000000";
    response.headers_["last-modified"] = "Sat, 04 Jun 2022 09:56:21 GMT";
    response.headers_["date"] = "Mon, 20 Jun 2022 09:56:21 GMT";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, FRESH);
}

HWTEST_F(HttpClientCacheStrategyTest, reqHeaderEtagBranch, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetRequestTime("Thu, 19 May 2022 08:19:59 GMT");
    httpReq.SetHeader("cache-control", "min-fresh=20");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Thu,  19 May 2022 08:21:59 GMT");
    response.headers_["expires"] = "Thu, 19 May 2022 08:22:26 GMT";
    response.headers_["etag"] = "6f6741d197947f9f10943d36c4c4210e";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, STALE);
}

HWTEST_F(HttpClientCacheStrategyTest, reqHeaderLastModifiedBranch, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetRequestTime("Thu, 19 May 2022 08:19:59 GMT");
    httpReq.SetHeader("cache-control", "min-fresh=20");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Thu,  19 May 2022 08:21:59 GMT");
    response.headers_["expires"] = "Thu, 19 May 2022 08:22:26 GMT";
    response.headers_["last-modified"] = "Sat, 04 Jun 2022 09:56:21 GMT";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, STALE);
}

HWTEST_F(HttpClientCacheStrategyTest, reqHeaderDateBranch, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetRequestTime("Thu, 19 May 2022 08:19:59 GMT");
    httpReq.SetHeader("cache-control", "min-fresh=20");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Thu,  19 May 2022 08:21:59 GMT");
    response.headers_["expires"] = "Thu, 19 May 2022 08:22:26 GMT";
    response.headers_["date"] = "Sat, 04 Jun 2022 09:56:21 GMT";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, STALE);
}

HWTEST_F(HttpClientCacheStrategyTest, headerNull, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetRequestTime("Thu, 19 May 2022 08:19:59 GMT");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Thu,  19 May 2022 08:21:59 GMT");

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, STALE);
}

HWTEST_F(HttpClientCacheStrategyTest, requestTimeEmpty, TestSize.Level1)
{
    HttpClientRequest httpReq;

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Thu,  19 May 2022 08:21:59 GMT");

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, STALE);
}

HWTEST_F(HttpClientCacheStrategyTest, computeFreshnessLifetimeEnd, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetRequestTime("Thu, 19 May 2022 08:19:59 GMT");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Thu,  19 May 2022 08:21:59 GMT");

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, STALE);
}

HWTEST_F(HttpClientCacheStrategyTest, isCacheableMovedTempIfCondition, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetRequestTime("Fri, 20 May 2022 09:35:59 GMT");
    httpReq.SetHeader("cache-control", "min-fresh=20");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::MOVED_TEMP);
    response.SetResponseTime("Fri, 20 May 2022 09:36:30 GMT");

    response.headers_["cache-control"] = "private";
    response.headers_["last-modified"] = "Thu, 10 Feb 2022 10:55:14 GMT";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, STALE);
}

HWTEST_F(HttpClientCacheStrategyTest, computeFreshnessLifetimeDelta, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetRequestTime("Fri, 20 May 2022 09:35:59 GMT");
    httpReq.SetHeader("cache-control", "min-fresh=20");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Fri, 20 May 2022 09:36:30 GMT");
    response.headers_["last-modified"] = "Mon, 18 Jul 2022 10:55:14 GMT";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, STALE);
}

HWTEST_F(HttpClientCacheStrategyTest, isCacheUsefulMaxStaleMillis, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetRequestTime("Fri, 20 May 2022 09:35:59 GMT");
    httpReq.SetHeader("cache-control", "max-stale=20");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Fri, 20 May 2022 09:36:30 GMT");
    response.headers_["last-modified"] = "Thu, 10 Feb 2022 10:55:14 GMT";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, STALE);
}

HWTEST_F(HttpClientCacheStrategyTest, isCacheableMovedTempIfCondition2, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetRequestTime("Fri, 20 May 2022 09:35:59 GMT");
    httpReq.SetHeader("cache-control", "min-fresh=20, no-store");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Fri, 20 May 2022 09:36:30 GMT");
    response.headers_["cache-control"] = "private";
    response.headers_["last-modified"] = "Thu, 10 Feb 2022 10:55:14 GMT";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, DENY);
}

HWTEST_F(HttpClientCacheStrategyTest, isCacheableMovedTempIfCondition3, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetRequestTime("Fri, 20 May 2022 09:35:59 GMT");
    httpReq.SetHeader("cache-control", "min-fresh=20");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Fri, 20 May 2022 09:36:30 GMT");

    response.headers_["cache-control"] = "private, no-store";
    response.headers_["last-modified"] = "Thu, 10 Feb 2022 10:55:14 GMT";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, DENY);
}

HWTEST_F(HttpClientCacheStrategyTest, isCacheableMovedTempIfCondition4, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetRequestTime("Fri, 20 May 2022 09:35:59 GMT");
    httpReq.SetHeader("cache-control", "min-fresh=20");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Fri, 20 May 2022 09:36:30 GMT");
    response.headers_["cache-control"] = "private, must-revalidate";
    response.headers_["last-modified"] = "Thu, 10 Feb 2022 10:55:14 GMT";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, STALE);
}

HWTEST_F(HttpClientCacheStrategyTest, CompareNumber_6_2, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetRequestTime("Fri, 20 May 2022 09:35:59 GMT");
    httpReq.SetHeader("cache-control", "min-fresh=20");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Fri, 20 May 2022 09:36:30 GMT");
    response.headers_["cache-control"] = "no-cache";
    response.headers_["expires"] = "Sat, 04 Jun 2022 09:56:21 GMT";
    response.headers_["date"] = "Fri, 20 May 2022 09:37:29 GMT";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, STALE);
}

HWTEST_F(HttpClientCacheStrategyTest, SmaxageTest, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetHeader("cache-control", "only-if-cached");
    httpReq.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");
    response.headers_["Cache-Control"] = "s-maxage=70";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, 0);
}

HWTEST_F(HttpClientCacheStrategyTest, NoTransformTest, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetHeader("cache-control", "no-transform");
    httpReq.SetRequestTime("Fri, 20 May 2022 09:36:30 GMT");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Fri,  20 May 2022 09:36:59 GMT");
    response.headers_["Cache-Control"] = "s-maxage=70";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, STALE);
}


HWTEST_F(HttpClientCacheStrategyTest, MovedTempFailTest, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetRequestTime("Fri, 20 May 2022 09:35:59 GMT");
    httpReq.SetHeader("cache-control", "min-fresh=20");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::MOVED_TEMP);
    response.SetResponseTime("Fri, 20 May 2022 09:36:30 GMT");

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, DENY);
}

HWTEST_F(HttpClientCacheStrategyTest, CouldUseCacheWrongTest, TestSize.Level2)
{
    HttpClientRequest httpReq;
    httpReq.method_ = "";

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Fri, 20 May 2022 09:36:30 GMT");

    HttpCacheStrategy cacheStrategy(httpReq);
    bool status = cacheStrategy.IsCacheable(response);

    EXPECT_EQ(status, false);
}

HWTEST_F(HttpClientCacheStrategyTest, ProxyRevalidateTest, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetRequestTime("Fri, 20 May 2022 09:35:59 GMT");
    httpReq.SetHeader("cache-control", "min-fresh=20");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Fri, 20 May 2022 09:36:30 GMT");
    response.headers_["cache-control"] = "proxy-revalidate";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, STALE);
}

HWTEST_F(HttpClientCacheStrategyTest, ExpiresEmptyTest, TestSize.Level1)
{
    HttpClientRequest httpReq;
    httpReq.SetRequestTime("Fri, 20 May 2022 09:35:59 GMT");
    httpReq.SetHeader("expires", "");

    HttpClientResponse response;
    response.SetResponseCode(ResponseCode::OK);
    response.SetResponseTime("Fri, 20 May 2022 09:36:30 GMT");
    response.headers_["cache-control"] = "proxy-revalidate";

    HttpCacheStrategy cacheStrategy(httpReq);
    CacheStatus status = cacheStrategy.RunStrategy(response);

    EXPECT_EQ(status, STALE);
}

} // namespace