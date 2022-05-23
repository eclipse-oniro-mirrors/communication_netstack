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

#ifndef COMMUNICATIONNETSTACK_CACHE_STRATEGY_H
#define COMMUNICATIONNETSTACK_CACHE_STRATEGY_H

#include "http_request_options.h"
#include "http_response.h"

namespace OHOS::NetStack {
enum class CacheStatus {
    FRESH,
    STATE,
    TRANSPARENT [[maybe_unused]],
};

class CacheStrategy final {
    HttpRequestOptions &requestOptions_;

public:
    CacheStrategy() = delete;

    explicit CacheStrategy(HttpRequestOptions &requestOptions);

    CacheStatus GetCacheStatus(const HttpResponse &response);

    void SetHeaderForValidation(const HttpResponse &response);

    bool CouldCache(const HttpResponse &response);

    bool CouldUseCache();

    static std::string GetNowTimeGMT();
};
} // namespace OHOS::NetStack

#endif /* COMMUNICATIONNETSTACK_CACHE_STRATEGY_H */
