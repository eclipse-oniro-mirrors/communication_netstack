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

#include "casche_constant.h"
#include "constant.h"
#include "http_cache_request.h"
#include "http_cache_response.h"
#include "http_time.h"
#include "netstack_log.h"

#include "http_cache_strategy.h"

static constexpr const int64_t ONE_DAY_MILLISECONDS = 24 * 60 * 60 * 1000L;
static constexpr const int64_t CONVERT_TO_MILLISECONDS = 1000;
static constexpr const char *KEY_RANGE = "range";

// RFC 7234

namespace OHOS::NetStack {
HttpCacheStrategy::HttpCacheStrategy(HttpRequestOptions &requestOptions) : requestOptions_(requestOptions)
{
    cacheRequest_.ParseRequestHeader(requestOptions_.GetHeader());
    cacheRequest_.SetRequestTime(requestOptions_.GetRequestTime());
}

bool HttpCacheStrategy::CouldUseCache()
{
    return requestOptions_.GetMethod() == HttpConstant::HTTP_METHOD_GET ||
           requestOptions_.GetMethod() == HttpConstant::HTTP_METHOD_HEAD ||
           requestOptions_.GetHeader().find(KEY_RANGE) != requestOptions_.GetHeader().end();
}

CacheStatus HttpCacheStrategy::RunStrategy(HttpResponse &response)
{
    cacheResponse_.ParseCacheResponseHeader(response.GetHeader());
    cacheResponse_.SetRespCode(static_cast<ResponseCode>(response.GetResponseCode()));
    cacheResponse_.SetResponseTime(response.GetResponseTime());
    return RunStrategyInternal(response);
}

bool HttpCacheStrategy::IsCacheable(const HttpResponse &response)
{
    if (!CouldUseCache()) {
        return false;
    }
    HttpCacheResponse tempCacheResponse;
    tempCacheResponse.ParseCacheResponseHeader(response.GetHeader());
    tempCacheResponse.SetRespCode(static_cast<ResponseCode>(response.GetResponseCode()));
    return IsCacheable(tempCacheResponse);
}

int64_t HttpCacheStrategy::CacheResponseAgeMillis(int64_t sReqTime,
                                                  int64_t sRespTime,
                                                  int64_t nowTime,
                                                  int64_t sRespDate,
                                                  int64_t responseAge)
{
    int64_t apparentReceivedAge = 0;

    if (sRespDate != INVALID_TIME) {
        apparentReceivedAge = std::max<int64_t>(0, sRespTime - sRespDate);
    }

    int64_t receivedAge = apparentReceivedAge;
    if (responseAge != INVALID_TIME) {
        receivedAge = std::max(apparentReceivedAge, responseAge);
    }

    int64_t responseDuration = sRespTime - sReqTime;

    int64_t residentDuration = nowTime - sRespTime;

    return (receivedAge + responseDuration + residentDuration) * CONVERT_TO_MILLISECONDS;
}

int64_t HttpCacheStrategy::ComputeFreshnessLifetimeMillis()
{
    NETSTACK_LOGI("--- ComputeFreshnessLifetimeMillis start ---");

    int64_t maxAge = cacheResponse_.GetMaxAgeSeconds();
    int64_t sMaxAge = cacheResponse_.GetSMaxAgeSeconds();

    NETSTACK_LOGI("maxAge=%{public}lld", static_cast<long long>(maxAge));

    int64_t lifeTime = 0;

    if (sMaxAge != INVALID_TIME) {
        // If the cache is shared and the s-maxage response directive (Section 5.2.2.9) is present, use its value
        lifeTime = sMaxAge;
    } else if (maxAge != INVALID_TIME) {
        // If the max-age response directive (Section 5.2.2.8) is present, use its value
        NETSTACK_LOGI("--- ComputeFreshnessLifetimeMillis end ---");
        lifeTime = maxAge;
    } else if (cacheResponse_.GetExpires() != INVALID_TIME) {
        // If the Expires response header field (Section 5.3) is present, use its value minus the value of the Date
        // response header field
        int64_t servedMillis;
        if (cacheResponse_.GetDate() != INVALID_TIME) {
            servedMillis = cacheResponse_.GetDate();
        } else {
            servedMillis = cacheResponse_.GetResponseTime();
            NETSTACK_LOGI("servedMillis=%{public}lld", static_cast<long long>(servedMillis));
        }
        NETSTACK_LOGI("getExpiresSeconds=%{public}lld", static_cast<long long>(cacheResponse_.GetExpires()));
        int64_t delta = cacheResponse_.GetExpires() - servedMillis;

        NETSTACK_LOGI("delta=%{public}lld", static_cast<long long>(delta));

        NETSTACK_LOGI("--- ComputeFreshnessLifetimeMillis end ---");
        lifeTime = std::max<int64_t>(delta, 0);
    } else if (cacheResponse_.GetLastModified() != INVALID_TIME) {
        // 4.2.2. Calculating Heuristic Freshness
        int64_t servedMillis;
        if (cacheResponse_.GetDate() != INVALID_TIME) {
            servedMillis = cacheResponse_.GetDate();
        } else {
            servedMillis = cacheRequest_.GetRequestTime();
        }
        int64_t delta = servedMillis - cacheResponse_.GetLastModified();

        NETSTACK_LOGI("delta=%{public}lld", static_cast<long long>(delta));

        NETSTACK_LOGI("--- ComputeFreshnessLifetimeMillis end ---");
        lifeTime = std::max<int64_t>(delta / DECIMAL, 0);
    }

    int64_t reqMaxAge = cacheRequest_.GetMaxAgeSeconds();
    if (reqMaxAge != INVALID_TIME) {
        lifeTime = std::min(lifeTime, reqMaxAge);
    }
    NETSTACK_LOGI("lifeTime=%{public}lld", static_cast<long long>(lifeTime));

    NETSTACK_LOGI("--- ComputeFreshnessLifetimeMillis end ---");
    return lifeTime * CONVERT_TO_MILLISECONDS;
}

void HttpCacheStrategy::UpdateRequestHeader(const std::string &etag,
                                            const std::string &lastModified,
                                            const std::string &date)
{
    NETSTACK_LOGI("--- UpdateRequestHeader start ---");

    if (!etag.empty()) {
        requestOptions_.SetHeader(IF_NONE_MATCH, etag);
    } else if (!lastModified.empty()) {
        requestOptions_.SetHeader(IF_MODIFIED_SINCE, lastModified);
    } else if (!date.empty()) {
        requestOptions_.SetHeader(IF_MODIFIED_SINCE, date);
    }
}

bool HttpCacheStrategy::IsCacheable(const HttpCacheResponse &cacheResponse)
{
    switch (cacheResponse.GetRespCode()) {
        case ResponseCode::OK:
        case ResponseCode::NOT_AUTHORITATIVE:
        case ResponseCode::NO_CONTENT:
        case ResponseCode::MULT_CHOICE:
        case ResponseCode::MOVED_PERM:
        case ResponseCode::NOT_FOUND:
        case ResponseCode::BAD_METHOD:
        case ResponseCode::GONE:
        case ResponseCode::REQ_TOO_LONG:
        case ResponseCode::NOT_IMPLEMENTED:
            // These codes can be cached unless headers forbid it.
            break;

        case ResponseCode::MOVED_TEMP:
            if (cacheResponse.GetExpires() != INVALID_TIME || cacheResponse.GetMaxAgeSeconds() != INVALID_TIME ||
                cacheResponse.IsPublicCache() || cacheResponse.IsPrivateCache()) {
                break;
            }
            return false;

        default:
            return false;
    }

    return !cacheResponse.IsNoStore() && !cacheRequest_.IsNoStore();
}

std::tuple<int64_t, int64_t, int64_t, int64_t> HttpCacheStrategy::GetFreshness()
{
    int64_t ageMillis =
        CacheResponseAgeMillis(cacheRequest_.GetRequestTime(), cacheResponse_.GetResponseTime(),
                               HttpTime::GetNowTimeSeconds(), cacheResponse_.GetDate(), cacheResponse_.GetAgeSeconds());

    int64_t lifeTime = ComputeFreshnessLifetimeMillis();

    int64_t minFreshMillis = 0;
    minFreshMillis = cacheRequest_.GetMinFreshSeconds();
    if (minFreshMillis != INVALID_TIME) {
        minFreshMillis *= CONVERT_TO_MILLISECONDS;
    }
    int64_t maxStaleMillis = 0;
    if (!cacheResponse_.IsMustRevalidate()) {
        maxStaleMillis = cacheRequest_.GetMaxStaleSeconds();
    }
    if (maxStaleMillis != INVALID_TIME) {
        maxStaleMillis *= CONVERT_TO_MILLISECONDS;
    }
    NETSTACK_LOGI("%{public}lld, %{public}lld, %{public}lld, %{public}lld", static_cast<long long>(ageMillis),
                  static_cast<long long>(minFreshMillis), static_cast<long long>(lifeTime),
                  static_cast<long long>(maxStaleMillis));

    return {ageMillis, minFreshMillis, lifeTime, maxStaleMillis};
}

CacheStatus HttpCacheStrategy::RunStrategyInternal(HttpResponse &response)
{
    NETSTACK_LOGI("request nocache = %{public}d", cacheRequest_.IsNoCache());

    if (cacheRequest_.IsNoCache()) {
        NETSTACK_LOGI("return DENY");
        return DENY;
    }

    NETSTACK_LOGI("response nocache = %{public}d", cacheResponse_.IsNoCache());

    if (cacheResponse_.IsNoCache()) {
        NETSTACK_LOGI("return STALE");
        return STALE;
    }

    if (cacheRequest_.IsOnlyIfCached()) {
        NETSTACK_LOGI("return FRESH");
        return FRESH;
    }

    // T.B.D https and TLS handshake
    if (!IsCacheable(cacheResponse_)) {
        NETSTACK_LOGI("return DENY");
        return DENY;
    }

    if (cacheRequest_.GetIfModifiedSince() != INVALID_TIME || !cacheRequest_.GetIfNoneMatch().empty()) {
        NETSTACK_LOGI("return DENY");
        return DENY;
    }

    auto [ageMillis, minFreshMillis, lifeTime, maxStaleMillis] = GetFreshness();

    NETSTACK_LOGI("nocache:%{public}d", cacheResponse_.IsNoCache());
    if (ageMillis + minFreshMillis < lifeTime + maxStaleMillis) {
        if (ageMillis + minFreshMillis >= lifeTime) {
            NETSTACK_LOGI("110 HttpURLConnection");
            response.SetWarning("110 \"Response is STALE\"");
        }

        if (ageMillis > ONE_DAY_MILLISECONDS && cacheRequest_.GetMaxAgeSeconds() == INVALID_TIME &&
            cacheResponse_.GetExpires() == INVALID_TIME) {
            NETSTACK_LOGI("113 HttpURLConnection");
            response.SetWarning("113 \"Heuristic expiration\"");
        }
        NETSTACK_LOGI("return FRESH");
        return FRESH;
    }

    // The cache has expired and the request needs to be re-initialized
    UpdateRequestHeader(cacheResponse_.GetEtag(), cacheResponse_.GetLastModifiedStr(), cacheResponse_.GetDateStr());

    NETSTACK_LOGI("---IsCacheUseful end---");
    return STALE;
}
} // namespace OHOS::NetStack
