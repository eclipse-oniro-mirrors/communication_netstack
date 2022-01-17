/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef COMMUNICATIONNETSTACK_TEST_COMMON_H
#define COMMUNICATIONNETSTACK_TEST_COMMON_H

#include "native_engine/native_engine.h"
#include "native_value/quickjs_native_value.h"
#include "netstack_log.h"
#include "netstack_napi_utils.h"
#include "quickjs_native_engine.h"
#include "gtest/gtest.h"
#include <cstring>

static uint32_t g_testNum = 0;

static uint32_t testNumber = 1;

#define ASSERT_CHECK_CALL(call)   \
    do {                          \
        ASSERT_EQ(call, napi_ok); \
    } while (0)

#define ASSERT_CHECK_VALUE_TYPE(env, value, type)               \
    do {                                                        \
        napi_valuetype valueType = napi_undefined;              \
        ASSERT_TRUE((value) != nullptr);                        \
        ASSERT_CHECK_CALL(napi_typeof(env, value, &valueType)); \
        ASSERT_EQ(valueType, type);                             \
    } while (0)

#define ASSERT_VALUE_IS_PROMISE(env, value) \
    do {                                    \
        bool ret = false;                   \
        napi_is_promise(env, value, &ret);  \
        ASSERT_TRUE(ret);                   \
    } while (0)

class NativeEngineTest : public testing::Test {
public:
    NativeEngineTest();
    ~NativeEngineTest() override;
    void SetUp() override {}
    void TearDown() override {}

protected:
    NativeEngine *engine_;
};

static NativeEngine *g_nativeEngine = nullptr;

NativeEngineTest::NativeEngineTest() : engine_(g_nativeEngine) {}

NativeEngineTest::~NativeEngineTest() = default;

#endif /* COMMUNICATIONNETSTACK_TEST_COMMON_H */
