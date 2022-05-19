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

#ifndef COMMUNICATIONNETSTACK_LRU_CACHE_DISK_HANDLER_H
#define COMMUNICATIONNETSTACK_LRU_CACHE_DISK_HANDLER_H

#include "disk_handler.h"
#include "lru_cache.h"
#include "nocopyable.h"

namespace OHOS::NetStack {
class LRUCacheDiskHandler {
private:
    LRUCache &cache_;
    DiskHandler diskHandler_;
    size_t capacity_;

    Json::Value GetJsonValueFromFile();

public:
    LRUCacheDiskHandler() = delete;

    LRUCacheDiskHandler(std::string fileName, LRUCache &cache, size_t capacity);

    void WriteCacheToJsonFile();

    void ReadCacheFromJsonFile();
};
} // namespace OHOS::NetStack
#endif /* COMMUNICATIONNETSTACK_LRU_CACHE_DISK_HANDLER_H */
