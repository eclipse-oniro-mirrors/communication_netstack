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
#include <fstream>
#include <filesystem>

#include "gtest/gtest.h"
#include "disk_handler.h"
#include "lru_cache.h"
#include "lru_cache_disk_handler.h"
#include "netstack_log.h"

using namespace OHOS::NetStack::HttpClient;

class HttpClientLruCacheTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

namespace {
using namespace std;
using namespace testing::ext;

std::vector<std::string> CreateTempFile(std::vector<std::string> files, std::vector<std::string> texts)
{
    std::vector<std::string> result = {};
    auto tempDir = testing::TempDir();
    for (size_t i = 0; i < files.size(); i++) {
        auto outPath = tempDir + files[i];
        std::ofstream outStream(outPath);
        if (outStream.fail()) {
            std::cerr << "Failed to open file: " << outPath << std::endl;
            return result;
        }
        outStream << texts[i];
        outStream.close();
        result.push_back(outPath);
    }
    return result;
}

bool DestroyFile(const std::string& path)
{
    std::error_code ec;
    return std::filesystem::remove(path, ec);
}

std::string getFileContent(const std::string& path)
{
    std::ifstream file;
    file.open(path);
    std::stringstream ss;
    ss << file.rdbuf();
    std::string infos = ss.str();
    file.close();
    return infos;
}

HWTEST_F(HttpClientLruCacheTest, WriteCacheToJsonFile001, TestSize.Level1)
{
    std::string fileName = "";
    size_t capacity = 0;
    LRUCacheDiskHandler handler(fileName, capacity);
    handler.WriteCacheToJsonFile();

    std::string fileContent = getFileContent(fileName);
    std::string file = "";
    EXPECT_EQ(fileContent, file);
    handler.Delete();
}

HWTEST_F(HttpClientLruCacheTest, WriteCacheToJsonFile002, TestSize.Level1)
{
    std::vector<std::string> fileNames = {"WriteCacheToJsonFile002.txt"};
    std::vector<std::string> fileContents = {R"(1111111111111)"};
    auto filePaths = CreateTempFile(fileNames, fileContents);
    int const expectedFileCount = 1;
    EXPECT_EQ(filePaths.size(), expectedFileCount);

    std::string fileName = filePaths.at(0);
    size_t capacity = 0;
    LRUCacheDiskHandler handler(fileName, capacity);
    handler.WriteCacheToJsonFile();

    std::string fileContent = getFileContent(fileName);
    EXPECT_NE(fileContent, fileContents.at(0));
    handler.Delete();
    DestroyFile(fileName);
}

HWTEST_F(HttpClientLruCacheTest, WriteCacheToJsonFile003, TestSize.Level1)
{
    std::vector<std::string> fileNames = {"WriteCacheToJsonFile003.txt"};
    std::vector<std::string> fileContents = {R"({
        "userInfo": {"name": "Alice", "age": "18"},
        "config": {"theme": "dark"}
    })"};
    auto filePaths = CreateTempFile(fileNames, fileContents);
    int const expectedFileCount = 1;
    EXPECT_EQ(filePaths.size(), expectedFileCount);

    std::string fileName = filePaths.at(0);
    size_t capacity = 0;
    LRUCacheDiskHandler handler(fileName, capacity);
    handler.WriteCacheToJsonFile();

    std::string fileContent = getFileContent(fileName);
    EXPECT_NE(fileContent, fileContents.at(0));
    handler.Delete();
    DestroyFile(fileName);
}

HWTEST_F(HttpClientLruCacheTest, WriteCacheToJsonFile004, TestSize.Level1)
{
    std::vector<std::string> fileNames = {"WriteCacheToJsonFile004.txt"};
    std::vector<std::string> fileContents = {R"({
        "userInfo": {"name": "Alice", "age": "18"},
        "config": {"theme": "dark"}
    })"};
    auto filePaths = CreateTempFile(fileNames, fileContents);
    int const expectedFileCount = 1;
    EXPECT_EQ(filePaths.size(), expectedFileCount);

    std::string fileName = filePaths.at(0);
    size_t capacity = 1024;
    LRUCacheDiskHandler handler(fileName, capacity);
    handler.WriteCacheToJsonFile();

    std::string fileContent = getFileContent(fileName);
    EXPECT_NE(fileContent, fileContents.at(0));
    handler.Delete();
    DestroyFile(fileName);
}

HWTEST_F(HttpClientLruCacheTest, ReadCacheFromJsonFile001, TestSize.Level1)
{
    std::string fileName = "";
    size_t capacity = 0;
    LRUCacheDiskHandler handler(fileName, capacity);
    handler.ReadCacheFromJsonFile();

    std::string fileContent = getFileContent(fileName);
    std::string file = "";
    EXPECT_EQ(fileContent, file);
    handler.Delete();
}

HWTEST_F(HttpClientLruCacheTest, ReadCacheFromJsonFile002, TestSize.Level1)
{
    std::vector<std::string> fileNames = {"ReadCacheFromJsonFile002.txt"};
    std::vector<std::string> fileContents = {R"({
        "userInfo": {"name": "Alice", "age": "18", "LRUIndex": "0"},
        "config": {"theme": "dark", "LRUIndex": "1"}
    })"};
    auto filePaths = CreateTempFile(fileNames, fileContents);
    int const expectedFileCount = 1;
    EXPECT_EQ(filePaths.size(), expectedFileCount);

    std::string fileName = filePaths.at(0);
    size_t capacity = 1024;
    LRUCacheDiskHandler handler(fileName, capacity);
    handler.ReadCacheFromJsonFile();

    std::string fileContent = getFileContent(fileName);
    EXPECT_EQ(fileContent, fileContents.at(0));
    handler.Delete();
    DestroyFile(fileName);
}

HWTEST_F(HttpClientLruCacheTest, SetCapacity001, TestSize.Level1)
{
    std::vector<std::string> fileNames = {"SetCapacity001.txt"};
    std::vector<std::string> fileContents = {R"({
        "userInfo": {"name": "Alice", "age": "18"},
        "config": {"theme": "dark"}
    })"};
    auto filePaths = CreateTempFile(fileNames, fileContents);
    int const expectedFileCount = 1;
    EXPECT_EQ(filePaths.size(), expectedFileCount);

    std::string fileName = filePaths.at(0);
    size_t capacity = 0;
    LRUCacheDiskHandler handler(fileName, capacity);
    size_t newCapacity = 1024;
    handler.SetCapacity(newCapacity);

    std::string fileContent = getFileContent(fileName);
    EXPECT_NE(fileContent, fileContents.at(0));
    handler.Delete();
    DestroyFile(fileName);
}

HWTEST_F(HttpClientLruCacheTest, Get001, TestSize.Level1)
{
    std::string fileName = "";
    size_t capacity = 0;
    LRUCacheDiskHandler handler(fileName, capacity);

    std::string key = "";
    std::unordered_map<std::string, std::string> value = handler.Get(key);
    EXPECT_TRUE(value.empty());
    handler.Delete();
}

HWTEST_F(HttpClientLruCacheTest, Get002, TestSize.Level1)
{
    LRUCache lruCache;
    std::string key = "userInfo";
    std::unordered_map<std::string, std::string> nodeValue = {{"name", "Alice"}, {"age", "18"}};
    lruCache.Put(key, nodeValue);
    std::unordered_map<std::string, std::string> value = lruCache.Get(key);
    EXPECT_TRUE(!value.empty());
}

HWTEST_F(HttpClientLruCacheTest, Put001, TestSize.Level1)
{
    std::string fileName = "";
    size_t capacity = 0;
    LRUCacheDiskHandler handler(fileName, capacity);

    std::string key = "";
    std::unordered_map<std::string, std::string> value;
    handler.Put(key, value);

    std::unordered_map<std::string, std::string> getValue = handler.Get(key);
    EXPECT_TRUE(getValue.empty());
    handler.Delete();
}

HWTEST_F(HttpClientLruCacheTest, Put002, TestSize.Level1)
{
    std::string fileName = "";
    size_t capacity = 0;
    LRUCacheDiskHandler handler(fileName, capacity);

    std::string key = "userInfo";
    std::unordered_map<std::string, std::string> nodeValue = {{"name", "Alice"}, {"age", "18"}};
    handler.Put(key, nodeValue);

    std::unordered_map<std::string, std::string> value = handler.Get(key);
    EXPECT_TRUE(!value.empty());
    handler.Delete();
}

HWTEST_F(HttpClientLruCacheTest, Put003, TestSize.Level1)
{
    LRUCache lruCache(5);
    std::string key = "userInfo";
    std::unordered_map<std::string, std::string> nodeValue = {{"name", "Alice"}, {"age", "18"}};
    lruCache.Put(key, nodeValue);

    std::unordered_map<std::string, std::string> value = lruCache.Get(key);
    EXPECT_TRUE(value.empty());
}

HWTEST_F(HttpClientLruCacheTest, Put004, TestSize.Level1)
{
    LRUCache lruCache(20);
    std::string key = "userInfo";
    std::unordered_map<std::string, std::string> nodeValue = {{"name", "Alice"}, {"age", "18"}};
    lruCache.Put(key, nodeValue);
    std::unordered_map<std::string, std::string> nodeValue1 = {{"name", "Tom1111111111111111111111111"}, {"age", "20"}};
    lruCache.Put(key, nodeValue1);

    std::unordered_map<std::string, std::string> value = lruCache.Get(key);
    EXPECT_TRUE(value.empty());
}

HWTEST_F(HttpClientLruCacheTest, Put005, TestSize.Level1)
{
    LRUCache lruCache(1024);
    std::string key = "userInfo";
    std::unordered_map<std::string, std::string> nodeValue = {{"name", "Alice"}, {"age", "18"}};
    lruCache.Put(key, nodeValue);
    std::unordered_map<std::string, std::string> nodeValue1 = {{"name", "Tom1111111111111111111111111"}, {"age", "20"}};
    lruCache.Put(key, nodeValue1);

    std::unordered_map<std::string, std::string> value = lruCache.Get(key);
    EXPECT_TRUE(!value.empty());
}
} // namespace
