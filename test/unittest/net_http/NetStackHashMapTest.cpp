/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstdio>
#include <cstring>
#include <cstdlib>

#include "netstack_hash_map.h"
#include "net_http_inner_types.h"
#include "netstack_log.h"
#include "gtest/gtest.h"

#define NETSTACK_HASH_FACTOR 31

class NetstackHashMapTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

namespace {
using namespace std;
using namespace testing::ext;

static void SimpleDestoryStub(void *value)
{
    NETSTACK_LOGE("SimpleDestoryStub");
}


HWTEST_F(NetstackHashMapTest, CreateMapTest001, TestSize.Level1)
{
    Netstack_HashMap *map = CreateMap();

    EXPECT_EQ(map->capacity, DEFAULT_MAP_CAPACITY);
    EXPECT_EQ(map->size, 0);
    Netstack_DestroyMap(map);
}

HWTEST_F(NetstackHashMapTest, NetstackInvalidMapTest001, TestSize.Level1)
{
    Netstack_HashMap *map = CreateMap();
    map = nullptr;
    const char *value = "value";
    uint32_t ret = Netstack_PutMapEntry(map, "key", (void *)value);
    EXPECT_EQ(ret, OH_HTTP_PARAMETER_ERROR);
    Netstack_DestroyMap(map);
}

HWTEST_F(NetstackHashMapTest, NetstackInvalidMapTest002, TestSize.Level1)
{
    Netstack_HashMap *map = CreateMap();
    map->entries = nullptr;
    char *value = strdup("value");
    uint32_t ret = Netstack_PutMapEntry(map, "key", value);
    EXPECT_EQ(ret, OH_HTTP_PARAMETER_ERROR);
    Netstack_DestroyMap(map);
}

HWTEST_F(NetstackHashMapTest, NetstackInvalidMapTest003, TestSize.Level1)
{
    Netstack_HashMap *map = CreateMap();
    map->capacity = DEFAULT_MAP_CAPACITY - 1;
    const char *value = "value";
    uint32_t ret = Netstack_PutMapEntry(map, "key", (void *)value);
    EXPECT_EQ(ret, OH_HTTP_PARAMETER_ERROR);
    Netstack_DestroyMap(map);
}

HWTEST_F(NetstackHashMapTest, NetstackInvalidMapTest004, TestSize.Level1)
{
    Netstack_HashMap *map = CreateMap();
    map->capacity = MAX_MAP_CAPACITY + 1;
    const char *value = "value";
    uint32_t ret = Netstack_PutMapEntry(map, "key", (void *)value);
    EXPECT_EQ(ret, OH_HTTP_PARAMETER_ERROR);
Netstack_DestroyMap(map);
}

HWTEST_F(NetstackHashMapTest, NetstackResizeMapTest001, TestSize.Level1)
{
    Netstack_HashMap *map = CreateMap();
    EXPECT_TRUE(map != nullptr);
    map->entries[0] = nullptr;
    const char *value = "value";
    Netstack_PutMapEntry(map, "key", (void *)value);
    Netstack_DestroyMap(map);
}

HWTEST_F(NetstackHashMapTest, NetstackResizeMapTest002, TestSize.Level1)
{
    Netstack_HashMap *map = CreateMap();
    EXPECT_TRUE(map != nullptr);
    map->entries[0] = (Netstack_HashMapEntry *)calloc(1, sizeof(Netstack_HashMapEntry));
    map->entries[0]->key = nullptr;
    const char *value = "value";
    Netstack_PutMapEntry(map, "key", (void *)value);
    Netstack_DestroyMap(map);
}

HWTEST_F(NetstackHashMapTest, NetstackPutMapEntryTest001, TestSize.Level1)
{
    Netstack_HashMap *map = CreateMap();
    EXPECT_TRUE(map != nullptr);
    char *key = nullptr;
    const char *value = "value";
    EXPECT_EQ(Netstack_PutMapEntry(map, key, (void *)value), OH_HTTP_PARAMETER_ERROR);
    Netstack_DestroyMap(map);
}

HWTEST_F(NetstackHashMapTest, NetstackPutMapEntryTest002, TestSize.Level1)
{
    Netstack_HashMap *map = CreateMap();
    map = nullptr;
    const char *key = "key";
    const char *value = "value";
    EXPECT_EQ(Netstack_PutMapEntry(map, key, (void *)value), OH_HTTP_PARAMETER_ERROR);
    Netstack_DestroyMap(map);
}

HWTEST_F(NetstackHashMapTest, NetstackPutMapEntryTest003, TestSize.Level1)
{
    Netstack_HashMap *map = CreateMap();
    map->size = DEFAULT_MAP_CAPACITY;
    map->capacity = DEFAULT_MAP_CAPACITY;
    const char *key = "key";
    const char *value  = "value";
    Netstack_PutMapEntry(map, key, (void *)value);
    EXPECT_EQ(map->capacity, DEFAULT_MAP_CAPACITY * 2);
    Netstack_DestroyMap(map);
}

HWTEST_F(NetstackHashMapTest, NetstackPutMapEntryTest004, TestSize.Level1)
{
    Netstack_HashMap *map = CreateMap();
    const char *key = "key";
    const char *value  = "value";
    EXPECT_EQ(Netstack_PutMapEntry(map, key, (void *)value), OH_HTTP_RESULT_OK);
    Netstack_DestroyMap(map);
}

HWTEST_F(NetstackHashMapTest, NetstackPutMapEntryTest005, TestSize.Level1)
{
    Netstack_HashMap *map = CreateMap();
    const char *key = "key";
    const char *value  = "value";
    const char *value2  = "value2";
    Netstack_PutMapEntry(map, key, (void *)value2);
    EXPECT_EQ(Netstack_PutMapEntry(map, key, (void *)value), OH_HTTP_RESULT_OK);
    EXPECT_EQ(Netstack_GetMapEntry(map, key), "value");
    Netstack_DestroyMap(map);
}

HWTEST_F(NetstackHashMapTest, NetstackGetMapEntryTest001, TestSize.Level1)
{
    Netstack_HashMap *map = CreateMap();
    const char *key = nullptr;
    EXPECT_EQ(Netstack_GetMapEntry(map, key), nullptr);
    Netstack_DestroyMap(map);
}

HWTEST_F(NetstackHashMapTest, NetstackGetMapEntryTest002, TestSize.Level1)
{
    Netstack_HashMap *map = CreateMap();
    const char *key = "a";
    const char *value  = "value";
    Netstack_PutMapEntry(map, key, (void *)value);
    EXPECT_EQ(Netstack_GetMapEntry(map, key), value);
    Netstack_DestroyMap(map);
}

HWTEST_F(NetstackHashMapTest, NetstackGetMapEntryTest003, TestSize.Level1)
{
    Netstack_HashMap *map = CreateMap();
    const char *key = "a";
    EXPECT_EQ(Netstack_GetMapEntry(map, key), nullptr);
    Netstack_DestroyMap(map);
}

HWTEST_F(NetstackHashMapTest, NetstackDeleteMapEntryTest001, TestSize.Level1)
{
    Netstack_HashMap *map = CreateMap();
    map->capacity = MAX_MAP_CAPACITY + 1;
    const char *key = "a";
    EXPECT_EQ(Netstack_DeleteMapEntry(map, key), OH_HTTP_PARAMETER_ERROR);
    Netstack_DestroyMap(map);
}

HWTEST_F(NetstackHashMapTest, NetstackDeleteMapEntryTest002, TestSize.Level1)
{
    Netstack_HashMap *map = CreateMap();
    char *key = nullptr;
    EXPECT_EQ(Netstack_DeleteMapEntry(map, key), OH_HTTP_PARAMETER_ERROR);
    Netstack_DestroyMap(map);
}

HWTEST_F(NetstackHashMapTest, NetstackDeleteMapEntryTest003, TestSize.Level1)
{
    Netstack_HashMap *map = CreateMap();
    const char *key = "a";
    const char *value  = "value";
    Netstack_PutMapEntry(map, key, (void *)value);
    int tempSize = map->size;
    EXPECT_EQ(Netstack_DeleteMapEntry(map, key), OH_HTTP_RESULT_OK);
    EXPECT_EQ(tempSize, map->size + 1);
    Netstack_DestroyMap(map);
}

//capacity=3
 HWTEST_F(NetstackHashMapTest, NetstackDeleteMapEntryTest004, TestSize.Level1)
 {
    Netstack_HashMap *map = CreateMap();
    const char *key1 = "da";
    const char *key2 = "eb";
    const char *key3 = "fc";
    const char *value  = "value";
    Netstack_PutMapEntry(map, key1, (void *)value);
    Netstack_PutMapEntry(map, key2, (void *)value);
    Netstack_PutMapEntry(map, key3, (void *)value);
    int tempSize = map->size;
    EXPECT_EQ(Netstack_DeleteMapEntry(map, key1), OH_HTTP_RESULT_OK);
    EXPECT_EQ(tempSize, map->size);
    Netstack_DestroyMap(map);
}

HWTEST_F(NetstackHashMapTest, NetstackDestroyMapWithValueTest001, TestSize.Level1)
{
    Netstack_HashMap *map = CreateMap();
    EXPECT_TRUE(map != nullptr);
    map->capacity = MAX_MAP_CAPACITY + 1;
    Netstack_DestroyMapWithValue(map, nullptr);
}

HWTEST_F(NetstackHashMapTest, NetstackDestroyMapWithValueTest002, TestSize.Level1)
{
    Netstack_HashMap *map = CreateMap();
    EXPECT_TRUE(map != nullptr);
    const char *key1 = "key1";
    const char *value1 = "123";
    Netstack_PutMapEntry(map, key1, (void *)value1);

    Netstack_DestroyMapWithValue(map, SimpleDestoryStub);
}

HWTEST_F(NetstackHashMapTest, NetstackCreateMapIteratorTest001, TestSize.Level1)
{
    Netstack_HashMap *map = CreateMap();
    map->capacity = MAX_MAP_CAPACITY + 1;
    Netstack_MapIterator *iterator = Netstack_CreateMapIterator(map);
    EXPECT_EQ(iterator, nullptr);
    Netstack_DestroyMap(map);
}

HWTEST_F(NetstackHashMapTest, NetstackCreateMapIteratorTest002, TestSize.Level1)
{
    Netstack_HashMap *map = CreateMap();
    const char *key1 = "da";
    const char *key2 = "eb";
    const char *key3 = "fc";
    const char *value  = "value";
    Netstack_PutMapEntry(map, key1, (void *)value);
    Netstack_PutMapEntry(map, key2, (void *)value);
    Netstack_PutMapEntry(map, key3, (void *)value);
    Netstack_MapIterator *iterator = Netstack_CreateMapIterator(map);
    EXPECT_FALSE(iterator == nullptr);
    Netstack_DestroyMapIterator(iterator);
    Netstack_DestroyMap(map);
}

HWTEST_F(NetstackHashMapTest, NetstackCreateMapIteratorTest003, TestSize.Level1)
{
    Netstack_HashMap *map = CreateMap();
    Netstack_MapIterator *iterator = Netstack_CreateMapIterator(map);
    EXPECT_EQ(iterator, nullptr);
    Netstack_DestroyMap(map);
}

HWTEST_F(NetstackHashMapTest, NetstackMapIterateNextTest001, TestSize.Level1)
{
    Netstack_MapIterateNext(nullptr);

    Netstack_HashMap *map = CreateMap();
    EXPECT_TRUE(map != nullptr);
    Netstack_MapIterator *iterator = Netstack_CreateMapIterator(map);
    Netstack_MapIterateNext(iterator);

    map->capacity = MAX_MAP_CAPACITY + 1;
    const char *key1 = "a";
    const char *key2 = "q";
    const char *value  = "value";
    Netstack_PutMapEntry(map, key1, (void *)value);
    Netstack_PutMapEntry(map, key2, (void *)value);
    iterator = Netstack_CreateMapIterator(map);
    Netstack_MapIterateNext(iterator);

    Netstack_DestroyMapIterator(iterator);
    Netstack_DestroyMap(map);
}

HWTEST_F(NetstackHashMapTest, NetstackMapIterateNextTest002, TestSize.Level1)
{
    Netstack_HashMap *map = CreateMap();
    Netstack_MapIterator *iterator = Netstack_CreateMapIterator(map);
    EXPECT_TRUE(iterator == nullptr);
    Netstack_DestroyMapIterator(iterator);
    Netstack_DestroyMap(map);
}

HWTEST_F(NetstackHashMapTest, NetstackMapIterateNextTest003, TestSize.Level1)
{
    Netstack_HashMap *map = CreateMap();
    EXPECT_TRUE(map != nullptr);
    const char *key1 = "da";
    const char *key2 = "eb";
    const char *key3 = "fc";
    const char *value  = "value";
    Netstack_PutMapEntry(map, key1, (void *)value);
    Netstack_PutMapEntry(map, key2, (void *)value);
    Netstack_PutMapEntry(map, key3, (void *)value);
    Netstack_MapIterator *iterator = Netstack_CreateMapIterator(map);
    Netstack_MapIterateNext(iterator);

    Netstack_DestroyMapIterator(iterator);
    Netstack_DestroyMap(map);
}

HWTEST_F(NetstackHashMapTest, NetstackMapIterateNextTest004, TestSize.Level1)
{
    Netstack_HashMap *map = CreateMap();
    EXPECT_TRUE(map != nullptr);
    const char *key1 = "a";
    const char *key2 = "q";
    const char *value  = "value";
    Netstack_PutMapEntry(map, key1, (void *)value);
    Netstack_PutMapEntry(map, key2, (void *)value);
    Netstack_MapIterator *iterator = Netstack_CreateMapIterator(map);
    Netstack_MapIterateNext(iterator);

    Netstack_DestroyMapIterator(iterator);
    Netstack_DestroyMap(map);
}
}