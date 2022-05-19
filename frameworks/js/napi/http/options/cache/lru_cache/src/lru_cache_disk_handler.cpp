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
#include <fstream>

#include "lru_cache_disk_handler.h"
#include "netstack_log.h"

static constexpr const int MAX_DISK_CACHE_SIZE = 1024 * 1024 * 10;
static constexpr const uint64_t MIN_WRITE_INTERVAL_MILLISECOND = 60 * 1000;
static uint64_t LAST_WRITE_TIME_MILLISECOND = 0;

namespace OHOS::NetStack {
uint64_t GetNowTime()
{
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
}

LRUCacheDiskHandler::LRUCacheDiskHandler(std::string fileName, LRUCache &cache, size_t capacity)
    : cache_(cache), diskHandler_(std::move(fileName)), capacity_(std::min<size_t>(MAX_DISK_CACHE_SIZE, capacity))
{
}

Json::Value LRUCacheDiskHandler::GetJsonValueFromFile()
{
    std::string jsonStr = diskHandler_.Read();
    Json::Value root;
    JSONCPP_STRING err;
    Json::CharReaderBuilder builder;
    std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    if (!reader->parse(jsonStr.c_str(), jsonStr.c_str() + jsonStr.size(), &root, &err)) {
        NETSTACK_LOGE("parse json failed: %{public}s", err.c_str());
        return {};
    }
    return root;
}

void LRUCacheDiskHandler::WriteCacheToJsonFile()
{
    uint64_t now = GetNowTime();
    if (now < LAST_WRITE_TIME_MILLISECOND) {
        // 获取的系统时间比上一次记录的时间小，说明系统时间有问题，重新计算。
        LAST_WRITE_TIME_MILLISECOND = 0;
    }
    if (LAST_WRITE_TIME_MILLISECOND != 0 && now - LAST_WRITE_TIME_MILLISECOND < MIN_WRITE_INTERVAL_MILLISECOND) {
        NETSTACK_LOGI("write too often");
        return;
    }
    LAST_WRITE_TIME_MILLISECOND = now;

    LRUCache oldCache(capacity_);
    oldCache.ReadCacheFromJsonValue(GetJsonValueFromFile());
    oldCache.MergeOtherCache(cache_);

    Json::Value root = oldCache.WriteCacheToJsonValue();
    Json::StreamWriterBuilder builder;
    std::unique_ptr<Json::StreamWriter> writer(builder.newStreamWriter());
    std::stringstream s;
    int res = writer->write(root, &s);
    if (res != 0) {
        NETSTACK_LOGE("write json failed %{public}d", res);
        return;
    }
    diskHandler_.Write(s.str());
}

void LRUCacheDiskHandler::ReadCacheFromJsonFile()
{
    cache_.ReadCacheFromJsonValue(GetJsonValueFromFile());
}
} // namespace OHOS::NetStack
