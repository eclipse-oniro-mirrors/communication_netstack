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

#if USE_CACHE
#include <thread>
#endif

#include "netstack_log.h"

#include "lru_cache_disk_handler.h"

static constexpr const int WRITE_INTERVAL = 60 * 1000;

namespace OHOS::NetStack {
LRUCacheDiskHandler::LRUCacheDiskHandler(std::string fileName, size_t capacity)
    : diskHandler_(std::move(fileName)), capacity_(std::min<size_t>(MAX_DISK_CACHE_SIZE, capacity))
{
#if USE_CACHE
    // 从磁盘中读取缓存到内存里
    ReadCacheFromJsonFile();
    // 起线程每一分钟讲内存缓存持久化
    std::thread([this]() {
        while (true) {
            std::this_thread::sleep_for(std::chrono::milliseconds(WRITE_INTERVAL));
            WriteCacheToJsonFile();
        }
    }).detach();
#endif
}

Json::Value LRUCacheDiskHandler::ReadJsonValueFromFile()
{
    std::string jsonStr = diskHandler_.Read();
    Json::Value root;
    JSONCPP_STRING err;
    Json::CharReaderBuilder builder;
    std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    if (!reader->parse(jsonStr.c_str(), jsonStr.c_str() + jsonStr.size(), &root, &err)) {
        NETSTACK_LOGI("parse json not success, maybe file is broken: %{public}s", err.c_str());
        return {};
    }
    return root;
}

void LRUCacheDiskHandler::WriteJsonValueToFile(const Json::Value &root)
{
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

void LRUCacheDiskHandler::WriteCacheToJsonFile()
{
    LRUCache oldCache(capacity_);
    oldCache.ReadCacheFromJsonValue(ReadJsonValueFromFile());
    oldCache.MergeOtherCache(cache_);
    Json::Value root = oldCache.WriteCacheToJsonValue();
    WriteJsonValueToFile(root);
    cache_.Clear();
}

void LRUCacheDiskHandler::ReadCacheFromJsonFile()
{
    cache_.ReadCacheFromJsonValue(ReadJsonValueFromFile());
}

std::unordered_map<std::string, std::string> LRUCacheDiskHandler::Get(const std::string &key)
{
    auto valueFromMemory = cache_.Get(key);
    if (!valueFromMemory.empty()) {
        return valueFromMemory;
    }

    LRUCache diskCache(capacity_);
    diskCache.ReadCacheFromJsonValue(ReadJsonValueFromFile());
    auto valueFromDisk = diskCache.Get(key);
    cache_.Put(key, valueFromDisk);
    return valueFromDisk;
}

void LRUCacheDiskHandler::Put(const std::string &key, const std::unordered_map<std::string, std::string> &value)
{
    cache_.Put(key, value);
}
} // namespace OHOS::NetStack
