/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "lru_cache_disk_handler.h"

#include <fstream>
#include <sstream>
#include <algorithm>
#include "netstack_log.h"

namespace OHOS::NetStack::Http {

static size_t GetMapValueSize(const std::unordered_map<std::string, std::string> &m)
{
    size_t size = 0;
    for (const auto &p : m) {
        if (p.second.size() > MAX_SIZE) {
            return INVALID_SIZE;
        }
        if (size + p.second.size() > MAX_SIZE) {
            return INVALID_SIZE;
        }
        size += p.second.size();
    }
    if (size > MAX_SIZE || size == 0) {
        return INVALID_SIZE;
    }
    return size;
}

LRUCache::Node::Node(std::string key, std::unordered_map<std::string, std::string> value)
    : key(std::move(key)), value(std::move(value))
{
}

LRUCache::LRUCache() : capacity_(MAX_SIZE), size_(0) {}

LRUCache::LRUCache(size_t capacity) : capacity_(std::min<size_t>(MAX_SIZE, capacity)), size_(0) {}

void LRUCache::AddNode(const Node &node)
{
    nodeList_.emplace_front(node);
    cache_[node.key] = nodeList_.begin();
    size_ += GetMapValueSize(node.value);
}

void LRUCache::MoveNodeToHead(const std::list<Node>::iterator &it)
{
    std::string key = it->key;
    std::unordered_map<std::string, std::string> value = it->value;
    nodeList_.erase(it);
    nodeList_.emplace_front(key, value);
    cache_[key] = nodeList_.begin();
}

void LRUCache::EraseTailNode()
{
    if (nodeList_.empty()) {
        return;
    }
    Node node = nodeList_.back();
    nodeList_.pop_back();
    cache_.erase(node.key);
    size_ -= GetMapValueSize(node.value);
}

std::unordered_map<std::string, std::string> LRUCache::Get(const std::string &key)
{
    std::lock_guard<std::mutex> guard(mutex_);

    if (cache_.find(key) == cache_.end()) {
        return {};
    }
    auto it = cache_[key];
    auto value = it->value;
    MoveNodeToHead(it);
    return value;
}

void LRUCache::Put(const std::string &key, const std::unordered_map<std::string, std::string> &value)
{
    std::lock_guard<std::mutex> guard(mutex_);

    if (GetMapValueSize(value) == INVALID_SIZE) {
        NETSTACK_LOGE("value is invalid(0 or too long) can not insert to cache");
        return;
    }

    if (cache_.find(key) == cache_.end()) {
        AddNode(Node(key, value));
        while (size_ > capacity_) {
            EraseTailNode();
        }
        return;
    }

    auto it = cache_[key];

    size_ -= GetMapValueSize(it->value);
    it->value = value;
    size_ += GetMapValueSize(it->value);

    MoveNodeToHead(it);
    while (size_ > capacity_) {
        EraseTailNode();
    }
}

void LRUCache::MergeOtherCache(const LRUCache &other)
{
    std::list<Node> reverseList;
    {
        // set mutex in min scope
        std::lock_guard<std::mutex> guard(mutex_);
        if (other.nodeList_.empty()) {
            return;
        }
        reverseList = other.nodeList_;
    }
    reverseList.reverse();
    for (const auto &node : reverseList) {
        Put(node.key, node.value);
    }
}

Json::Value LRUCache::WriteCacheToJsonValue()
{
    Json::Value root;

    int index = 0;
    {
        // set mutex in min scope
        std::lock_guard<std::mutex> guard(mutex_);
        for (const auto &node : nodeList_) {
            root[node.key] = Json::Value();
            for (const auto &p : node.value) {
                root[node.key][p.first] = p.second;
            }
            root[node.key][LRU_INDEX] = std::to_string(index);
            ++index;
        }
    }
    return root;
}

void LRUCache::ReadCacheFromJsonValue(const Json::Value &root)
{
    std::vector<Node> nodeVec;
    for (auto it = root.begin(); it != root.end(); ++it) {
        if (!it.key().isString()) {
            continue;
        }
        Json::Value value = root[it.key().asString()];
        if (!value.isObject()) {
            continue;
        }

        std::unordered_map<std::string, std::string> m;
        for (auto innerIt = value.begin(); innerIt != value.end(); ++innerIt) {
            if (!innerIt.key().isString()) {
                continue;
            }
            Json::Value innerValue = root[it.key().asString()][innerIt.key().asString()];
            if (!innerValue.isString()) {
                continue;
            }

            m[innerIt.key().asString()] = innerValue.asString();
        }

        if (m.find(LRU_INDEX) != m.end()) {
            nodeVec.emplace_back(it.key().asString(), m);
        }
    }
    std::sort(nodeVec.begin(), nodeVec.end(), [](Node &a, Node &b) {
        return std::strtol(a.value[LRU_INDEX].c_str(), nullptr, DECIMAL_BASE) >
               std::strtol(b.value[LRU_INDEX].c_str(), nullptr, DECIMAL_BASE);
    });
    for (auto &node : nodeVec) {
        node.value.erase(LRU_INDEX);
        if (!node.value.empty()) {
            Put(node.key, node.value);
        }
    }
}

void LRUCache::Clear()
{
    std::lock_guard<std::mutex> guard(mutex_);
    cache_.clear();
    nodeList_.clear();
}

DiskHandler::DiskHandler(std::string fileName) : fileName_(std::move(fileName)) {}

void DiskHandler::Write(const std::string &str)
{
    std::lock_guard<std::mutex> guard(mutex_);
    std::ofstream w(fileName_);
    if (!w.is_open()) {
        return;
    }
    w << str;
    w.close();
}

std::string DiskHandler::Read()
{
    std::lock_guard<std::mutex> guard(mutex_);
    std::ifstream r(fileName_);
    if (!r.is_open()) {
        return {};
    }
    std::stringstream b;
    b << r.rdbuf();
    r.close();
    return b.str();
}

void DiskHandler::Delete()
{
    std::lock_guard<std::mutex> guard(mutex_);
    if (remove(fileName_.c_str()) < 0) {
        NETSTACK_LOGI("remove file error %{public}d", errno);
    }
}

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
} // namespace OHOS::NetStack::Http
