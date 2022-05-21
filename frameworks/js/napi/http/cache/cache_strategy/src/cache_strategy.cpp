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

#include "cache_strategy.h"

static constexpr const int MAX_TIME_LEN = 128;

namespace OHOS::NetStack {
CacheStatus CacheStrategy::GetCacheStatus(const HttpRequestOptions &request, const HttpResponse &response)
{
    return CacheStatus::FRESH;
}

void CacheStrategy::SetHeaderForValidation(HttpRequestOptions &request, const HttpResponse &response) {}

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