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

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "netstack_napi_utils.h"
#include "securec.h"
#include "test_common.h"

namespace OHOS::NetStack {
[[maybe_unused]] HWTEST_F(NativeEngineTest, TestGetValueType, testing::ext::TestSize.Level1) /* NOLINT */
{
    auto env = (napi_env)engine_;

    napi_value undefined = NapiUtils::GetUndefined(env);
    ASSERT_EQ(NapiUtils::GetValueType(env, undefined), napi_undefined);

    napi_value jsString = NapiUtils::CreateStringUtf8(env, "test-string");
    ASSERT_EQ(NapiUtils::GetValueType(env, jsString), napi_string);

    ASSERT_EQ(NapiUtils::GetValueType(env, nullptr), napi_undefined);
    ASSERT_EQ(NapiUtils::GetValueType(env, NapiUtils::CreateObject(env)), napi_object);
}

[[maybe_unused]] HWTEST_F(NativeEngineTest, TestHasNamedProperty, testing::ext::TestSize.Level1) /* NOLINT */
{
    auto env = (napi_env)engine_;

    napi_value obj = NapiUtils::CreateObject(env);
    ASSERT_FALSE(NapiUtils::HasNamedProperty(env, obj, "test"));

    NapiUtils::SetNamedProperty(env, obj, "test", NapiUtils::CreateObject(env));
    ASSERT_TRUE(NapiUtils::HasNamedProperty(env, obj, "test"));
}

[[maybe_unused]] HWTEST_F(NativeEngineTest, TestGetNamedProperty, testing::ext::TestSize.Level1) /* NOLINT */
{
    auto env = (napi_env)engine_;

    napi_value obj = NapiUtils::CreateObject(env);

    NapiUtils::SetNamedProperty(env, obj, "test", NapiUtils::CreateObject(env));
    napi_value innerObj = NapiUtils::GetNamedProperty(env, obj, "test");
    ASSERT_CHECK_VALUE_TYPE(env, innerObj, napi_object);
}

[[maybe_unused]] HWTEST_F(NativeEngineTest, TestSetNamedProperty, testing::ext::TestSize.Level1) /* NOLINT */
{
    auto env = (napi_env)engine_;

    napi_value obj = NapiUtils::CreateObject(env);

    NapiUtils::SetNamedProperty(env, obj, "test", NapiUtils::CreateObject(env));
    napi_value innerObj = NapiUtils::GetNamedProperty(env, obj, "test");
    ASSERT_CHECK_VALUE_TYPE(env, innerObj, napi_object);
}

[[maybe_unused]] HWTEST_F(NativeEngineTest, TestGetPropertyNames, testing::ext::TestSize.Level1) /* NOLINT */
{
    auto env = (napi_env)engine_;

    size_t num = 3;
    napi_value obj = NapiUtils::CreateObject(env);
    NapiUtils::SetNamedProperty(env, obj, "test1", NapiUtils::CreateObject(env));
    NapiUtils::SetNamedProperty(env, obj, "test2", NapiUtils::CreateObject(env));
    NapiUtils::SetNamedProperty(env, obj, "test3", NapiUtils::CreateObject(env));

    auto names = NapiUtils::GetPropertyNames(env, obj);
    ASSERT_EQ(names.size(), num);
}

[[maybe_unused]] HWTEST_F(NativeEngineTest, TestCreateUint32, testing::ext::TestSize.Level1) /* NOLINT */
{
    auto env = (napi_env)engine_;

    int num = 100;
    napi_value v = NapiUtils::CreateUint32(env, num);
    ASSERT_EQ(NapiUtils::GetUint32FromValue(env, v), num);
}

[[maybe_unused]] HWTEST_F(NativeEngineTest, TestGetUint32FromValue, testing::ext::TestSize.Level1) /* NOLINT */
{
    auto env = (napi_env)engine_;

    int num = 100;
    napi_value v = NapiUtils::CreateUint32(env, num);
    ASSERT_EQ(NapiUtils::GetUint32FromValue(env, v), num);
}

[[maybe_unused]] HWTEST_F(NativeEngineTest, TestGetUint32Property, testing::ext::TestSize.Level1) /* NOLINT */
{
    auto env = (napi_env)engine_;

    napi_value obj = NapiUtils::CreateObject(env);

    int num = 100;
    NapiUtils::SetUint32Property(env, obj, "test", num);
    ASSERT_EQ(NapiUtils::GetUint32Property(env, obj, "test"), num);
}

[[maybe_unused]] HWTEST_F(NativeEngineTest, TestSetUint32Property, testing::ext::TestSize.Level1) /* NOLINT */
{
    auto env = (napi_env)engine_;

    napi_value obj = NapiUtils::CreateObject(env);

    int num = 100;
    NapiUtils::SetUint32Property(env, obj, "test", num);
    ASSERT_EQ(NapiUtils::GetUint32Property(env, obj, "test"), num);
}

[[maybe_unused]] HWTEST_F(NativeEngineTest, TestCreateInt32, testing::ext::TestSize.Level1) /* NOLINT */
{
    auto env = (napi_env)engine_;

    int num = 100;
    napi_value v = NapiUtils::CreateInt32(env, num);
    ASSERT_EQ(NapiUtils::GetInt32FromValue(env, v), num);
}

[[maybe_unused]] HWTEST_F(NativeEngineTest, TestGetInt32FromValue, testing::ext::TestSize.Level1) /* NOLINT */
{
    auto env = (napi_env)engine_;

    int num = 100;
    napi_value v = NapiUtils::CreateInt32(env, num);
    ASSERT_EQ(NapiUtils::GetInt32FromValue(env, v), num);
}

[[maybe_unused]] HWTEST_F(NativeEngineTest, TestGetInt32Property, testing::ext::TestSize.Level1) /* NOLINT */
{
    auto env = (napi_env)engine_;

    napi_value obj = NapiUtils::CreateObject(env);

    int num = 100;
    NapiUtils::SetInt32Property(env, obj, "test", num);
    ASSERT_EQ(NapiUtils::GetInt32Property(env, obj, "test"), num);
}

[[maybe_unused]] HWTEST_F(NativeEngineTest, TestSetInt32Property, testing::ext::TestSize.Level1) /* NOLINT */
{
    auto env = (napi_env)engine_;

    napi_value obj = NapiUtils::CreateObject(env);

    int num = 100;
    NapiUtils::SetInt32Property(env, obj, "test", num);
    ASSERT_EQ(NapiUtils::GetInt32Property(env, obj, "test"), num);
}

[[maybe_unused]] HWTEST_F(NativeEngineTest, TestCreateStringUtf8, testing::ext::TestSize.Level1) /* NOLINT */
{
    auto env = (napi_env)engine_;

    std::string s = "test-string";
    napi_value v = NapiUtils::CreateStringUtf8(env, s);
    ASSERT_EQ(NapiUtils::GetStringFromValueUtf8(env, v), s);
}

[[maybe_unused]] HWTEST_F(NativeEngineTest, TestGetStringFromValueUtf8, testing::ext::TestSize.Level1) /* NOLINT */
{
    auto env = (napi_env)engine_;

    std::string s = "test-string";
    napi_value v = NapiUtils::CreateStringUtf8(env, s);
    ASSERT_EQ(NapiUtils::GetStringFromValueUtf8(env, v), s);
}

[[maybe_unused]] HWTEST_F(NativeEngineTest, TestGetStringPropertyUtf8, testing::ext::TestSize.Level1) /* NOLINT */
{
    auto env = (napi_env)engine_;

    napi_value obj = NapiUtils::CreateObject(env);

    std::string s = "test-string";
    NapiUtils::SetStringPropertyUtf8(env, obj, "test", s);
    ASSERT_EQ(NapiUtils::GetStringPropertyUtf8(env, obj, "test"), s);
}

[[maybe_unused]] HWTEST_F(NativeEngineTest, TestSetStringPropertyUtf8, testing::ext::TestSize.Level1) /* NOLINT */
{
    auto env = (napi_env)engine_;

    napi_value obj = NapiUtils::CreateObject(env);

    std::string s = "test-string";
    NapiUtils::SetStringPropertyUtf8(env, obj, "test", s);
    ASSERT_EQ(NapiUtils::GetStringPropertyUtf8(env, obj, "test"), s);
}

[[maybe_unused]] HWTEST_F(NativeEngineTest, TestValueIsArrayBuffer, testing::ext::TestSize.Level1) /* NOLINT */
{
    auto env = (napi_env)engine_;

    const char *s = "test-string";

    void *data = nullptr;
    size_t len = strlen(s);

    napi_value v = NapiUtils::CreateArrayBuffer(env, len, &data);
    ASSERT_TRUE(NapiUtils::ValueIsArrayBuffer(env, v));

    (void)memcpy_s(data, len, s, len);

    size_t tempLen = 0;
    void *temp = NapiUtils::GetInfoFromArrayBufferValue(env, v, &tempLen);
    ASSERT_EQ(tempLen, len);
    int ret = memcmp(data, temp, len);
    ASSERT_EQ(ret, 0);
}

[[maybe_unused]] HWTEST_F(NativeEngineTest, TestGetInfoFromArrayBufferValue, testing::ext::TestSize.Level1) /* NOLINT */
{
    auto env = (napi_env)engine_;

    const char *s = "test-string";

    void *data = nullptr;
    size_t len = strlen(s);

    napi_value v = NapiUtils::CreateArrayBuffer(env, len, &data);
    ASSERT_TRUE(NapiUtils::ValueIsArrayBuffer(env, v));

    (void)memcpy_s(data, len, s, len);

    size_t tempLen = 0;
    void *temp = NapiUtils::GetInfoFromArrayBufferValue(env, v, &tempLen);
    ASSERT_EQ(tempLen, len);
    int ret = memcmp(data, temp, len);
    ASSERT_EQ(ret, 0);
}

[[maybe_unused]] HWTEST_F(NativeEngineTest, TestCreateArrayBuffer, testing::ext::TestSize.Level1) /* NOLINT */
{
    auto env = (napi_env)engine_;

    const char *s = "test-string";

    void *data = nullptr;
    size_t len = strlen(s);

    napi_value v = NapiUtils::CreateArrayBuffer(env, len, &data);
    ASSERT_TRUE(NapiUtils::ValueIsArrayBuffer(env, v));

    (void)memcpy_s(data, len, s, len);

    size_t tempLen = 0;
    void *temp = NapiUtils::GetInfoFromArrayBufferValue(env, v, &tempLen);
    ASSERT_EQ(tempLen, len);
    int ret = memcmp(data, temp, len);
    ASSERT_EQ(ret, 0);
}

[[maybe_unused]] HWTEST_F(NativeEngineTest, TestCreateObject, testing::ext::TestSize.Level1) /* NOLINT */
{
    auto env = (napi_env)engine_;

    napi_value undefined = NapiUtils::GetUndefined(env);
    ASSERT_EQ(NapiUtils::GetValueType(env, undefined), napi_undefined);

    napi_value jsString = NapiUtils::CreateStringUtf8(env, "test-string");
    ASSERT_EQ(NapiUtils::GetValueType(env, jsString), napi_string);

    ASSERT_EQ(NapiUtils::GetValueType(env, nullptr), napi_undefined);
    ASSERT_EQ(NapiUtils::GetValueType(env, NapiUtils::CreateObject(env)), napi_object);
}

[[maybe_unused]] HWTEST_F(NativeEngineTest, TestGetUndefined, testing::ext::TestSize.Level1) /* NOLINT */
{
    auto env = (napi_env)engine_;

    napi_value undefined = NapiUtils::GetUndefined(env);
    ASSERT_EQ(NapiUtils::GetValueType(env, undefined), napi_undefined);

    napi_value jsString = NapiUtils::CreateStringUtf8(env, "test-string");
    ASSERT_EQ(NapiUtils::GetValueType(env, jsString), napi_string);

    ASSERT_EQ(NapiUtils::GetValueType(env, nullptr), napi_undefined);
    ASSERT_EQ(NapiUtils::GetValueType(env, NapiUtils::CreateObject(env)), napi_object);
}

[[maybe_unused]] HWTEST_F(NativeEngineTest, TestCallFunction, testing::ext::TestSize.Level1) /* NOLINT */
{
    auto env = (napi_env)engine_;

    auto func = [](napi_env env, napi_callback_info info) -> napi_value {
        return NapiUtils::CreateStringUtf8(env, "test-string");
    };

    napi_value jsFunc = NapiUtils::CreateFunction(env, "test_func", func, nullptr);
    napi_value ret = NapiUtils::CallFunction(env, nullptr, jsFunc, 0, nullptr);
    ASSERT_EQ(NapiUtils::GetStringFromValueUtf8(env, ret), "test-string");
}

[[maybe_unused]] HWTEST_F(NativeEngineTest, TestCreateFunction, testing::ext::TestSize.Level1) /* NOLINT */
{
    auto env = (napi_env)engine_;

    auto func = [](napi_env env, napi_callback_info info) -> napi_value {
        return NapiUtils::CreateStringUtf8(env, "test-string");
    };

    napi_value jsFunc = NapiUtils::CreateFunction(env, "test_func", func, nullptr);
    napi_value ret = NapiUtils::CallFunction(env, nullptr, jsFunc, 0, nullptr);
    ASSERT_EQ(NapiUtils::GetStringFromValueUtf8(env, ret), "test-string");
}

[[maybe_unused]] HWTEST_F(NativeEngineTest, TestCreateReference, testing::ext::TestSize.Level1) /* NOLINT */
{
    auto env = (napi_env)engine_;

    auto func = [](napi_env env, napi_callback_info info) -> napi_value {
        return NapiUtils::CreateStringUtf8(env, "test-string");
    };

    napi_value jsFunc = NapiUtils::CreateFunction(env, "test_func", func, nullptr);
    napi_ref ref = NapiUtils::CreateReference(env, jsFunc);
    ASSERT_NE(ref, nullptr);

    napi_value v = NapiUtils::GetReference(env, ref);
    ASSERT_NE(v, nullptr);

    NapiUtils::DeleteReference(env, ref);
}

[[maybe_unused]] HWTEST_F(NativeEngineTest, TestGetReference, testing::ext::TestSize.Level1) /* NOLINT */
{
    auto env = (napi_env)engine_;

    auto func = [](napi_env env, napi_callback_info info) -> napi_value {
        return NapiUtils::CreateStringUtf8(env, "test-string");
    };

    napi_value jsFunc = NapiUtils::CreateFunction(env, "test_func", func, nullptr);
    napi_ref ref = NapiUtils::CreateReference(env, jsFunc);
    ASSERT_NE(ref, nullptr);

    napi_value v = NapiUtils::GetReference(env, ref);
    ASSERT_NE(v, nullptr);

    NapiUtils::DeleteReference(env, ref);
}

[[maybe_unused]] HWTEST_F(NativeEngineTest, TestDeleteReference, testing::ext::TestSize.Level1) /* NOLINT */
{
    auto env = (napi_env)engine_;

    auto func = [](napi_env env, napi_callback_info info) -> napi_value {
        return NapiUtils::CreateStringUtf8(env, "test-string");
    };

    napi_value jsFunc = NapiUtils::CreateFunction(env, "test_func", func, nullptr);
    napi_ref ref = NapiUtils::CreateReference(env, jsFunc);
    ASSERT_NE(ref, nullptr);

    napi_value v = NapiUtils::GetReference(env, ref);
    ASSERT_NE(v, nullptr);

    NapiUtils::DeleteReference(env, ref);
}

[[maybe_unused]] HWTEST_F(NativeEngineTest, TestGetBooleanProperty, testing::ext::TestSize.Level1) /* NOLINT */
{
    auto env = (napi_env)engine_;

    napi_value obj = NapiUtils::CreateObject(env);

    bool s = true;
    NapiUtils::SetBooleanProperty(env, obj, "test", s);
    ASSERT_EQ(NapiUtils::GetBooleanProperty(env, obj, "test"), s);
}

[[maybe_unused]] HWTEST_F(NativeEngineTest, TestSetBooleanProperty, testing::ext::TestSize.Level1) /* NOLINT */
{
    auto env = (napi_env)engine_;

    napi_value obj = NapiUtils::CreateObject(env);

    bool s = true;
    NapiUtils::SetBooleanProperty(env, obj, "test", s);
    ASSERT_EQ(NapiUtils::GetBooleanProperty(env, obj, "test"), s);
}

[[maybe_unused]] HWTEST_F(NativeEngineTest, TestDefineProperties, testing::ext::TestSize.Level1) /* NOLINT */
{
    auto env = (napi_env)engine_;

    int num = 10;
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_NAPI_STATIC_PROPERTY("test1", NapiUtils::CreateUint32(env, num)),
        DECLARE_NAPI_STATIC_PROPERTY("test2", NapiUtils::CreateUint32(env, num)),
        DECLARE_NAPI_STATIC_PROPERTY("test3", NapiUtils::CreateUint32(env, num)),
    };

    napi_value obj = NapiUtils::CreateObject(env);
    NapiUtils::DefineProperties(env, obj, properties);

    ASSERT_EQ(NapiUtils::GetUint32Property(env, obj, "test1"), num);
    ASSERT_EQ(NapiUtils::GetUint32Property(env, obj, "test2"), num);
    ASSERT_EQ(NapiUtils::GetUint32Property(env, obj, "test3"), num);
}
} // namespace OHOS::NetStack

int main(int argc, char **argv)
{
    testing::GTEST_FLAG(output) = "xml:./";
    testing::InitGoogleTest(&argc, argv);

    JSRuntime *rt = JS_NewRuntime();

    if (rt == nullptr) {
        return 0;
    }

    JSContext *ctx = JS_NewContext(rt);
    if (ctx == nullptr) {
        return 0;
    }

    js_std_add_helpers(ctx, 0, nullptr);

    g_nativeEngine = new QuickJSNativeEngine(rt, ctx, nullptr); // default instance id 0

    napi_module_register(nullptr);
    int ret = RUN_ALL_TESTS();
    (void)ret;

    return 0;
}
