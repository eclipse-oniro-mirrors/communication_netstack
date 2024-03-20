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

#include "lru_cache_disk_handler.h"

#include <thread>

#include "netstack_log.h"

namespace OHOS::NetStack::Http {
LRUCacheDiskHandler::LRUCacheDiskHandler(std::string fileName, size_t capacity)
    : diskHandler_(std::move(fileName)),
      capacity_(std::max<size_t>(std::min<size_t>(MAX_DISK_CACHE_SIZE, capacity), MIN_DISK_CACHE_SIZE))
{
}

void LRUCacheDiskHandler::SetCapacity(size_t capacity)
{
    capacity_ = std::max<size_t>(std::min<size_t>(MAX_DISK_CACHE_SIZE, capacity), MIN_DISK_CACHE_SIZE);
    WriteCacheToJsonFile();
}

void LRUCacheDiskHandler::Delete()
{
    cache_.Clear();
    diskHandler_.Delete();
}

Json::Value LRUCacheDiskHandler::ReadJsonValueFromFile()
{
    std::string jsonStr = diskHandler_.Read();
    Json::Value root;
    JSONCPP_STRING err;
    Json::CharReaderBuilder builder;
    std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    if (!reader->parse(jsonStr.c_str(), jsonStr.c_str() + jsonStr.size(), &root, &err)) {
        NETSTACK_LOGE("parse json not success, maybe file is broken: %{public}s", err.c_str());
        return {};
    }

    Json::StyledWriter styledWriter;
    std::string json = styledWriter.write(root);
    NETSTACK_LOGE("ReadJsonValueFromFile : %{public}s", json.c_str());
    return root;
}

cJSON* LRUCacheDiskHandler::CjsonReadJsonValueFromFile()
{
    std::string jsonStr = diskHandler_.Read();
    cJSON *root = cJSON_Parse(jsonStr.c_str());
    NETSTACK_LOGE("CjsonReadJsonValueFromFile : %{public}s", cJSON_Print(root));
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

void LRUCacheDiskHandler::CjsonWriteJsonValueToFile(cJSON *root)
{
    char *s = cJSON_Print(root);
    free(s);
    cJSON_Delete(root);
}

void LRUCacheDiskHandler::WriteCacheToJsonFile()
{
    LRUCache oldCache(capacity_);
    oldCache.ReadCacheFromJsonValue(ReadJsonValueFromFile());
    oldCache.CjsonReadCacheFromJsonValue(CjsonReadJsonValueFromFile());
    oldCache.MergeOtherCache(cache_);
    Json::Value root = oldCache.WriteCacheToJsonValue();
    cJSON* json = oldCache.CjsonWriteCacheToJsonValue();
    WriteJsonValueToFile(root);
    CjsonWriteJsonValueToFile(json);
    cache_.Clear();
}

void LRUCacheDiskHandler::ReadCacheFromJsonFile()
{
    cache_.ReadCacheFromJsonValue(ReadJsonValueFromFile());
    cache_.CjsonReadCacheFromJsonValue(CjsonReadJsonValueFromFile());
}

std::unordered_map<std::string, std::string> LRUCacheDiskHandler::Get(const std::string &key)
{
    auto valueFromMemory = cache_.Get(key);
    if (!valueFromMemory.empty()) {
        return valueFromMemory;
    }

    LRUCache diskCache(capacity_);
    diskCache.ReadCacheFromJsonValue(ReadJsonValueFromFile());
    diskCache.CjsonReadCacheFromJsonValue(CjsonReadJsonValueFromFile());
    auto valueFromDisk = diskCache.Get(key);
    cache_.Put(key, valueFromDisk);
    return valueFromDisk;
}

void LRUCacheDiskHandler::Put(const std::string &key, const std::unordered_map<std::string, std::string> &value)
{
    cache_.Put(key, value);
}
} // namespace OHOS::NetStack::Http
