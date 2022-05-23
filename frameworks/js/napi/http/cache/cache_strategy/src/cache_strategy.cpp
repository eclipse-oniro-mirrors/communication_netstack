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

#include <chrono>

#include "constant.h"

#include "cache_strategy.h"

static constexpr const int MAX_TIME_LEN = 128;
static constexpr const char *KEY_RANGE = "range";

namespace OHOS::NetStack {
CacheStrategy::CacheStrategy(HttpRequestOptions &requestOptions) : requestOptions_(requestOptions) {}

CacheStatus CacheStrategy::GetCacheStatus(const HttpResponse &response)
{
    return CacheStatus::FRESH;
}

void CacheStrategy::SetHeaderForValidation(const HttpResponse &response) {}

bool CacheStrategy::CouldUseCache()
{
    return requestOptions_.GetMethod() == HttpConstant::HTTP_METHOD_GET ||
           requestOptions_.GetMethod() == HttpConstant::HTTP_METHOD_HEAD ||
           requestOptions_.GetHeader().find(KEY_RANGE) != requestOptions_.GetHeader().end();
}

bool CacheStrategy::CouldCache(const HttpResponse &response)
{
    return true;
}

std::string CacheStrategy::GetNowTimeGMT()
{
    auto now = std::chrono::system_clock::now();
    time_t timeSeconds = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    tm timeInfo = {0};
    if (gmtime_r(&timeSeconds, &timeInfo) == nullptr) {
        return {};
    }
    char s[MAX_TIME_LEN] = {0};
    if (strftime(s, sizeof(s), "%a, %d %b %Y %H:%M:%S GMT", &timeInfo) == 0) {
        return {};
    }
    return s;
}
} // namespace OHOS::NetStack