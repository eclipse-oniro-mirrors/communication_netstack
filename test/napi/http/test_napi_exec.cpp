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

#include "test_common.h"

#include "constant.h"
#include "event_list.h"
#include "http_module.h"
#include "securec.h"

#define COMMON_DECLARE1                                                                                                \
    auto env = (napi_env)engine_;                                                                                      \
                                                                                                                       \
    napi_value exports = NapiUtils::CreateObject(env);                                                                 \
                                                                                                                       \
    HttpModuleExports::InitHttpModule(env, exports);                                                                   \
    napi_value requestMethod = NapiUtils::GetNamedProperty(env, exports, HttpModuleExports::INTERFACE_REQUEST_METHOD); \
                                                                                                                       \
    std::string methodGet = NapiUtils::GetStringPropertyUtf8(env, requestMethod, HttpConstant::HTTP_METHOD_GET);       \
    ASSERT_EQ(methodGet, HttpConstant::HTTP_METHOD_GET);

#define COMMON_DECLARE2                                                                                              \
    napi_value responseCode = NapiUtils::GetNamedProperty(env, exports, HttpModuleExports::INTERFACE_RESPONSE_CODE); \
    uint32_t codeOK = NapiUtils::GetUint32Property(env, responseCode, "OK");                                         \
    ASSERT_EQ(codeOK, (uint32_t)HttpModuleExports::ResponseCode::OK);                                                \
                                                                                                                     \
    napi_value createHttpFunc = NapiUtils::GetNamedProperty(env, exports, HttpModuleExports::FUNCTION_CREATE_HTTP);  \
    ASSERT_CHECK_VALUE_TYPE(env, createHttpFunc, napi_function);

#define COMMON_DECLARE3                                                                                       \
    napi_value httpRequestValue = NapiUtils::CallFunction(env, exports, createHttpFunc, 0, nullptr);          \
    ASSERT_CHECK_VALUE_TYPE(env, httpRequestValue, napi_object);                                              \
                                                                                                              \
    napi_value requestFunc =                                                                                  \
        NapiUtils::GetNamedProperty(env, httpRequestValue, HttpModuleExports::HttpRequest::FUNCTION_REQUEST); \
    ASSERT_CHECK_VALUE_TYPE(env, requestFunc, napi_function);

#define DEFINE_TEST_BEGIN(name, ASSERT_CODE_OK)                                                                     \
    [[maybe_unused]] HWTEST_F(NativeEngineTest, /* NOLINT */                                                        \
                              name, testing::ext::TestSize.Level0)                                                  \
    {                                                                                                               \
        COMMON_DECLARE1                                                                                             \
        COMMON_DECLARE2                                                                                             \
        COMMON_DECLARE3                                                                                             \
        auto callbackOneParam = NapiUtils::CreateFunction(env, #name "CallbackOneParam",                            \
                                                          MAKE_CALLBACK_ONE_PARAM(#name, ASSERT_CODE_OK), nullptr); \
        auto callbackTwoParam = NapiUtils::CreateFunction(env, #name "CallbackTwoParam",                            \
                                                          MAKE_CALLBACK_TWO_PARAM(#name, ASSERT_CODE_OK), nullptr);

#define DEFINE_TEST_END }

#define MAKE_CALLBACK_ONE_PARAM(FUNC_NAME, ASSERT_CODE_OK)                                                          \
    [](napi_env env, napi_callback_info info) -> napi_value {                                                       \
        NETSTACK_LOGI("%s", FUNC_NAME);                                                                             \
                                                                                                                    \
        napi_value thisVal = nullptr;                                                                               \
        size_t paramsCount = 1;                                                                                     \
        napi_value params[1] = {nullptr};                                                                           \
        NAPI_CALL(env, napi_get_cb_info(env, info, &paramsCount, params, &thisVal, nullptr));                       \
                                                                                                                    \
        if (NapiUtils::GetValueType(env, params[0]) != napi_undefined) {                                            \
            if (NapiUtils::HasNamedProperty(env, params[0], HttpConstant::RESPONSE_KEY_RESPONSE_CODE)) {            \
                uint32_t code =                                                                                     \
                    NapiUtils::GetUint32Property(env, params[0], HttpConstant::RESPONSE_KEY_RESPONSE_CODE);         \
                                                                                                                    \
                assert((code == (uint32_t)HttpModuleExports::ResponseCode::OK) == (ASSERT_CODE_OK));                \
            }                                                                                                       \
                                                                                                                    \
            if (NapiUtils::HasNamedProperty(env, params[0], HttpConstant::RESPONSE_KEY_COOKIES)) {                  \
                std::string cookies =                                                                               \
                    NapiUtils::GetStringPropertyUtf8(env, params[0], HttpConstant::RESPONSE_KEY_COOKIES);           \
                                                                                                                    \
                NETSTACK_LOGI("cookies:\n%s", cookies.c_str());                                                     \
            }                                                                                                       \
                                                                                                                    \
            napi_value header;                                                                                      \
            if (NapiUtils::HasNamedProperty(env, params[0], HttpConstant::RESPONSE_KEY_HEADER)) {                   \
                header =                                                                                            \
                    OHOS::NetStack::NapiUtils::GetNamedProperty(env, params[0], HttpConstant::RESPONSE_KEY_HEADER); \
                auto names = OHOS::NetStack::NapiUtils::GetPropertyNames(env, header);                              \
                std::for_each(names.begin(), names.end(), [env, header](const std::string &name) {                  \
                    auto value = OHOS::NetStack::NapiUtils::GetStringPropertyUtf8(env, header, name);               \
                    NETSTACK_LOGI("name = %s; value = %s", name.c_str(), value.c_str());                            \
                });                                                                                                 \
            } else {                                                                                                \
                NETSTACK_LOGI("##### Once Header Receive");                                                         \
                header = params[0];                                                                                 \
                auto names = OHOS::NetStack::NapiUtils::GetPropertyNames(env, header);                              \
                NETSTACK_LOGI("names size = %zu", names.size());                                                    \
                std::for_each(names.begin(), names.end(), [env, header](const std::string &name) {                  \
                    auto value = OHOS::NetStack::NapiUtils::GetStringPropertyUtf8(env, header, name);               \
                    NETSTACK_LOGI("Once Header name = %s; value = %s", name.c_str(), value.c_str());                \
                });                                                                                                 \
            }                                                                                                       \
                                                                                                                    \
            if (NapiUtils::HasNamedProperty(env, params[0], HttpConstant::RESPONSE_KEY_RESULT)) {                   \
                napi_value result = NapiUtils::GetNamedProperty(env, params[0], HttpConstant::RESPONSE_KEY_RESULT); \
                                                                                                                    \
                if (NapiUtils::GetValueType(env, result) == napi_string) {                                          \
                    std::string data = OHOS::NetStack::NapiUtils::GetStringFromValueUtf8(env, result);              \
                    NETSTACK_LOGI("data:\n%s", data.c_str());                                                       \
                } else if (NapiUtils::ValueIsArrayBuffer(env, result)) {                                            \
                    size_t length = 0;                                                                              \
                    void *data = NapiUtils::GetInfoFromArrayBufferValue(env, result, &length);                      \
                    FILE *fp = fopen("mine.png", "wb");                                                             \
                    NETSTACK_LOGI("png size is is %zu", length);                                                    \
                    if (fp != nullptr) {                                                                            \
                        fwrite(data, 1, length, fp);                                                                \
                        fclose(fp);                                                                                 \
                    }                                                                                               \
                }                                                                                                   \
            }                                                                                                       \
        }                                                                                                           \
                                                                                                                    \
        NETSTACK_LOGI("\n\n\n");                                                                                    \
        return NapiUtils::GetUndefined(env);                                                                        \
    }

#define MAKE_CALLBACK_TWO_PARAM(FUNC_NAME, ASSERT_CODE_OK)                                                          \
    [](napi_env env, napi_callback_info info) -> napi_value {                                                       \
        NETSTACK_LOGI("%s", FUNC_NAME);                                                                             \
                                                                                                                    \
        napi_value thisVal = nullptr;                                                                               \
        size_t paramsCount = 2;                                                                                     \
        napi_value params[2] = {nullptr};                                                                           \
        NAPI_CALL(env, napi_get_cb_info(env, info, &paramsCount, params, &thisVal, nullptr));                       \
                                                                                                                    \
        bool typeRight = ((NapiUtils::GetValueType(env, params[0]) == napi_undefined &&                             \
                           NapiUtils::GetValueType(env, params[1]) != napi_undefined) ||                            \
                          (NapiUtils::GetValueType(env, params[0]) != napi_undefined &&                             \
                           NapiUtils::GetValueType(env, params[1]) == napi_undefined));                             \
        assert(typeRight);                                                                                          \
                                                                                                                    \
        if (NapiUtils::GetValueType(env, params[1]) != napi_undefined) {                                            \
            if (NapiUtils::HasNamedProperty(env, params[1], HttpConstant::RESPONSE_KEY_RESPONSE_CODE)) {            \
                uint32_t code =                                                                                     \
                    NapiUtils::GetUint32Property(env, params[1], HttpConstant::RESPONSE_KEY_RESPONSE_CODE);         \
                                                                                                                    \
                assert((code == (uint32_t)HttpModuleExports::ResponseCode::OK) == (ASSERT_CODE_OK));                \
            }                                                                                                       \
                                                                                                                    \
            if (NapiUtils::HasNamedProperty(env, params[1], HttpConstant::RESPONSE_KEY_COOKIES)) {                  \
                std::string cookies =                                                                               \
                    NapiUtils::GetStringPropertyUtf8(env, params[1], HttpConstant::RESPONSE_KEY_COOKIES);           \
                                                                                                                    \
                NETSTACK_LOGI("cookies:\n%s", cookies.c_str());                                                     \
            }                                                                                                       \
                                                                                                                    \
            napi_value header;                                                                                      \
            if (NapiUtils::HasNamedProperty(env, params[1], HttpConstant::RESPONSE_KEY_HEADER)) {                   \
                header =                                                                                            \
                    OHOS::NetStack::NapiUtils::GetNamedProperty(env, params[1], HttpConstant::RESPONSE_KEY_HEADER); \
                auto names = OHOS::NetStack::NapiUtils::GetPropertyNames(env, header);                              \
                std::for_each(names.begin(), names.end(), [env, header](const std::string &name) {                  \
                    auto value = OHOS::NetStack::NapiUtils::GetStringPropertyUtf8(env, header, name);               \
                    NETSTACK_LOGI("name = %s; value = %s", name.c_str(), value.c_str());                            \
                });                                                                                                 \
            } else {                                                                                                \
                NETSTACK_LOGI("##### On Header Receive");                                                           \
                header = params[1];                                                                                 \
                auto names = OHOS::NetStack::NapiUtils::GetPropertyNames(env, header);                              \
                NETSTACK_LOGI("names size = %zu", names.size());                                                    \
                std::for_each(names.begin(), names.end(), [env, header](const std::string &name) {                  \
                    auto value = OHOS::NetStack::NapiUtils::GetStringPropertyUtf8(env, header, name);               \
                    NETSTACK_LOGI("Header name = %s; value = %s", name.c_str(), value.c_str());                     \
                });                                                                                                 \
            }                                                                                                       \
                                                                                                                    \
            if (NapiUtils::HasNamedProperty(env, params[1], HttpConstant::RESPONSE_KEY_RESULT)) {                   \
                napi_value result = NapiUtils::GetNamedProperty(env, params[1], HttpConstant::RESPONSE_KEY_RESULT); \
                                                                                                                    \
                if (NapiUtils::GetValueType(env, result) == napi_string) {                                          \
                    std::string data = OHOS::NetStack::NapiUtils::GetStringFromValueUtf8(env, result);              \
                    NETSTACK_LOGI("data:\n%s", data.c_str());                                                       \
                } else if (NapiUtils::ValueIsArrayBuffer(env, result)) {                                            \
                    size_t length = 0;                                                                              \
                    void *data = NapiUtils::GetInfoFromArrayBufferValue(env, result, &length);                      \
                    FILE *fp = fopen("mine.png", "wb");                                                             \
                    NETSTACK_LOGI("png size is is %zu", length);                                                    \
                    if (fp != nullptr) {                                                                            \
                        fwrite(data, 1, length, fp);                                                                \
                        fclose(fp);                                                                                 \
                    }                                                                                               \
                }                                                                                                   \
            }                                                                                                       \
        } else if (NapiUtils::GetValueType(env, params[0]) != napi_undefined) {                                     \
            int32_t code = NapiUtils::GetInt32Property(env, params[0], "code");                                     \
            NETSTACK_LOGI("error code = %d\n", code);                                                               \
        } else {                                                                                                    \
            NETSTACK_LOGI("error is undefined");                                                                    \
        }                                                                                                           \
                                                                                                                    \
        NETSTACK_LOGI("\n\n\n");                                                                                    \
        return NapiUtils::GetUndefined(env);                                                                        \
    }

namespace OHOS::NetStack {
static constexpr const int PARAM_TWO = 2;

void CallOn(napi_env env, napi_value thisVal, napi_value callback)
{
    napi_value func = NapiUtils::GetNamedProperty(env, thisVal, HttpModuleExports::HttpRequest::FUNCTION_ON);

    napi_value argv[PARAM_TWO] = {NapiUtils::CreateStringUtf8(env, ON_HEADER_RECEIVE), callback};

    NapiUtils::CallFunction(env, thisVal, func, PARAM_TWO, argv);
}

void CallOnce(napi_env env, napi_value thisVal, napi_value callback)
{
    napi_value func = NapiUtils::GetNamedProperty(env, thisVal, HttpModuleExports::HttpRequest::FUNCTION_ONCE);

    napi_value argv[PARAM_TWO] = {NapiUtils::CreateStringUtf8(env, ON_HEADER_RECEIVE), callback};

    NapiUtils::CallFunction(env, thisVal, func, PARAM_TWO, argv);
}

void CallOff(napi_env env, napi_value thisVal, napi_value callback)
{
    napi_value func = NapiUtils::GetNamedProperty(env, thisVal, HttpModuleExports::HttpRequest::FUNCTION_OFF);

    napi_value argv[PARAM_TWO] = {NapiUtils::CreateStringUtf8(env, ON_HEADER_RECEIVE), callback};

    NapiUtils::CallFunction(env, thisVal, func, PARAM_TWO, argv);
}

void CallPromiseThenCatch(napi_env env, napi_value promise, napi_value callback)
{
    bool isPromise = false;
    napi_is_promise(env, promise, &isPromise);
    if (!isPromise) {
        return;
    }

    JSValue quickJsPromise = reinterpret_cast<QuickJSNativeValue *>(promise)->GetJsValue();

    JSContext *ctx = ((QuickJSNativeEngine *)g_nativeEngine)->GetContext();

    JSValue then = JS_GetPropertyStr(ctx, quickJsPromise, "then");
    JSValue callbackValue = reinterpret_cast<QuickJSNativeValue *>(callback)->GetJsValue();
    JS_Call(ctx, then, quickJsPromise, 1, &callbackValue);

    JSValue theCatch = JS_GetPropertyStr(ctx, quickJsPromise, "catch");
    JSValue callbackValueCatch = reinterpret_cast<QuickJSNativeValue *>(callback)->GetJsValue();
    JS_Call(ctx, theCatch, quickJsPromise, 1, &callbackValueCatch);
}

DEFINE_TEST_BEGIN(TestHttpModuleMethodGetExtraDataNameValue, true)
{
    napi_value urlValue = NapiUtils::CreateStringUtf8(env, "https://" SERVER_IP);

    napi_value options = NapiUtils::CreateObject(env);

    napi_value header = NapiUtils::CreateObject(env);
    NapiUtils::SetStringPropertyUtf8(env, header, "no-use", "no use header");
    NapiUtils::SetStringPropertyUtf8(env, header, "just-test", "just test header");

    napi_value extraData = NapiUtils::CreateObject(env);
    NapiUtils::SetStringPropertyUtf8(env, (napi_value)extraData, "南京", "首府");
    NapiUtils::SetStringPropertyUtf8(env, (napi_value)extraData, "天气", "北京");

    NapiUtils::SetNamedProperty(env, options, std::string(HttpConstant::PARAM_KEY_HEADER), header);
    NapiUtils::SetNamedProperty(env, options, std::string(HttpConstant::PARAM_KEY_EXTRA_DATA), extraData);

    napi_value args[3] = {urlValue, options, callbackTwoParam};

    napi_value retValue = NapiUtils::CallFunction(env, httpRequestValue, requestFunc, 3, args);
    ASSERT_CHECK_VALUE_TYPE(env, retValue, napi_undefined);

    retValue = NapiUtils::CallFunction(env, httpRequestValue, requestFunc, 2, args);
    ASSERT_VALUE_IS_PROMISE(env, retValue);
    CallPromiseThenCatch(env, retValue, callbackOneParam);
}
DEFINE_TEST_END

DEFINE_TEST_BEGIN(TestHttpModuleMethodGetExtraDataNameValueUrlHasPara, true)
{
    napi_value urlValue = NapiUtils::CreateStringUtf8(env, "https://" SERVER_IP "?name=Mao");

    napi_value options = NapiUtils::CreateObject(env);

    napi_value header = NapiUtils::CreateObject(env);
    NapiUtils::SetStringPropertyUtf8(env, header, "no-use", "no use header");
    NapiUtils::SetStringPropertyUtf8(env, header, "just-test", "just test header");

    napi_value extraData = NapiUtils::CreateObject(env);
    NapiUtils::SetStringPropertyUtf8(env, (napi_value)extraData, "南京", "首府");
    NapiUtils::SetStringPropertyUtf8(env, (napi_value)extraData, "天气", "北京");

    NapiUtils::SetNamedProperty(env, options, std::string(HttpConstant::PARAM_KEY_HEADER), header);
    NapiUtils::SetNamedProperty(env, options, std::string(HttpConstant::PARAM_KEY_EXTRA_DATA), extraData);

    napi_value args[3] = {urlValue, options, callbackTwoParam};

    napi_value retValue = NapiUtils::CallFunction(env, httpRequestValue, requestFunc, 3, args);
    ASSERT_CHECK_VALUE_TYPE(env, retValue, napi_undefined);

    retValue = NapiUtils::CallFunction(env, httpRequestValue, requestFunc, 2, args);
    ASSERT_VALUE_IS_PROMISE(env, retValue);
    CallPromiseThenCatch(env, retValue, callbackOneParam);
}
DEFINE_TEST_END

DEFINE_TEST_BEGIN(TestHttpModuleMethodGetExtraDataNameValueUrlHasParaNoEncode, true)
{
    napi_value urlValue = NapiUtils::CreateStringUtf8(env, "https://" SERVER_IP "?name=Mao");

    napi_value options = NapiUtils::CreateObject(env);

    napi_value header = NapiUtils::CreateObject(env);
    NapiUtils::SetStringPropertyUtf8(env, header, "no-use", "no use header");
    NapiUtils::SetStringPropertyUtf8(env, header, "just-test", "just test header");

    napi_value extraData = NapiUtils::CreateObject(env);
    NapiUtils::SetStringPropertyUtf8(env, (napi_value)extraData, "age", "199");
    NapiUtils::SetStringPropertyUtf8(env, (napi_value)extraData, "country", "China");

    NapiUtils::SetNamedProperty(env, options, std::string(HttpConstant::PARAM_KEY_HEADER), header);
    NapiUtils::SetNamedProperty(env, options, std::string(HttpConstant::PARAM_KEY_EXTRA_DATA), extraData);

    napi_value args[3] = {urlValue, options, callbackTwoParam};

    napi_value retValue = NapiUtils::CallFunction(env, httpRequestValue, requestFunc, 3, args);
    ASSERT_CHECK_VALUE_TYPE(env, retValue, napi_undefined);

    retValue = NapiUtils::CallFunction(env, httpRequestValue, requestFunc, 2, args);
    ASSERT_VALUE_IS_PROMISE(env, retValue);
    CallPromiseThenCatch(env, retValue, callbackOneParam);
}
DEFINE_TEST_END

DEFINE_TEST_BEGIN(TestHttpModuleMethodGetExtraDataString, true)
{
    napi_value urlValue = NapiUtils::CreateStringUtf8(env, "https://" SERVER_IP "?name=Mao");

    napi_value options = NapiUtils::CreateObject(env);

    napi_value header = NapiUtils::CreateObject(env);
    NapiUtils::SetStringPropertyUtf8(env, header, "no-use", "no use header");
    NapiUtils::SetStringPropertyUtf8(env, header, "just-test", "just test header");

    napi_value extraData = NapiUtils::CreateStringUtf8(env, "this-is-my-get-string=mao&this-test=age");

    NapiUtils::SetNamedProperty(env, options, std::string(HttpConstant::PARAM_KEY_HEADER), header);
    NapiUtils::SetNamedProperty(env, options, std::string(HttpConstant::PARAM_KEY_EXTRA_DATA), extraData);

    napi_value args[3] = {urlValue, options, callbackTwoParam};

    napi_value retValue = NapiUtils::CallFunction(env, httpRequestValue, requestFunc, 3, args);
    ASSERT_CHECK_VALUE_TYPE(env, retValue, napi_undefined);

    retValue = NapiUtils::CallFunction(env, httpRequestValue, requestFunc, 2, args);
    ASSERT_VALUE_IS_PROMISE(env, retValue);
    CallPromiseThenCatch(env, retValue, callbackOneParam);
}
DEFINE_TEST_END

DEFINE_TEST_BEGIN(TestHttpModuleMethodGetNoExtraData, true)
{
    napi_value urlValue = NapiUtils::CreateStringUtf8(env, "https://" SERVER_IP "?name=Mao");

    napi_value options = NapiUtils::CreateObject(env);

    napi_value header = NapiUtils::CreateObject(env);
    NapiUtils::SetStringPropertyUtf8(env, header, "no-use", "no use header");
    NapiUtils::SetStringPropertyUtf8(env, header, "just-test", "just test header");

    NapiUtils::SetNamedProperty(env, options, std::string(HttpConstant::PARAM_KEY_HEADER), header);

    napi_value args[3] = {urlValue, options, callbackTwoParam};

    napi_value retValue = NapiUtils::CallFunction(env, httpRequestValue, requestFunc, 3, args);
    ASSERT_CHECK_VALUE_TYPE(env, retValue, napi_undefined);

    retValue = NapiUtils::CallFunction(env, httpRequestValue, requestFunc, 2, args);
    ASSERT_VALUE_IS_PROMISE(env, retValue);
    CallPromiseThenCatch(env, retValue, callbackOneParam);
}
DEFINE_TEST_END

DEFINE_TEST_BEGIN(TestHttpModuleMethodGetExtraDataNullString, true)
{
    napi_value urlValue = NapiUtils::CreateStringUtf8(env, "https://" SERVER_IP "?name=Mao");

    napi_value options = NapiUtils::CreateObject(env);

    napi_value header = NapiUtils::CreateObject(env);
    NapiUtils::SetStringPropertyUtf8(env, header, "no-use", "no use header");
    NapiUtils::SetStringPropertyUtf8(env, header, "just-test", "just test header");

    napi_value extraData = NapiUtils::CreateStringUtf8(env, "");

    NapiUtils::SetNamedProperty(env, options, std::string(HttpConstant::PARAM_KEY_HEADER), header);
    NapiUtils::SetNamedProperty(env, options, std::string(HttpConstant::PARAM_KEY_EXTRA_DATA), extraData);

    napi_value args[3] = {urlValue, options, callbackTwoParam};

    napi_value retValue = NapiUtils::CallFunction(env, httpRequestValue, requestFunc, 3, args);
    ASSERT_CHECK_VALUE_TYPE(env, retValue, napi_undefined);

    retValue = NapiUtils::CallFunction(env, httpRequestValue, requestFunc, 2, args);
    ASSERT_VALUE_IS_PROMISE(env, retValue);
    CallPromiseThenCatch(env, retValue, callbackOneParam);
}
DEFINE_TEST_END

DEFINE_TEST_BEGIN(TestHttpModuleMethodAndHeaderByDefaultHasPara, true)
{
    napi_value urlValue = NapiUtils::CreateStringUtf8(env, "https://" SERVER_IP "?name=Mao");

    napi_value options = NapiUtils::CreateObject(env);

    napi_value extraData = NapiUtils::CreateObject(env);
    NapiUtils::SetStringPropertyUtf8(env, (napi_value)extraData, "age", "199");
    NapiUtils::SetStringPropertyUtf8(env, (napi_value)extraData, "country", "China");

    NapiUtils::SetNamedProperty(env, options, std::string(HttpConstant::PARAM_KEY_EXTRA_DATA), extraData);

    napi_value args[3] = {urlValue, options, callbackTwoParam};

    napi_value retValue = NapiUtils::CallFunction(env, httpRequestValue, requestFunc, 3, args);
    ASSERT_CHECK_VALUE_TYPE(env, retValue, napi_undefined);

    retValue = NapiUtils::CallFunction(env, httpRequestValue, requestFunc, 2, args);
    ASSERT_VALUE_IS_PROMISE(env, retValue);
    CallPromiseThenCatch(env, retValue, callbackOneParam);
}
DEFINE_TEST_END

DEFINE_TEST_BEGIN(TestHttpModuleMethodAndHeaderByDefault, true)
{
    napi_value urlValue = NapiUtils::CreateStringUtf8(env, "https://" SERVER_IP "?name=Mao");

    napi_value args[2] = {urlValue, callbackTwoParam};

    napi_value retValue = NapiUtils::CallFunction(env, httpRequestValue, requestFunc, 2, args);
    ASSERT_CHECK_VALUE_TYPE(env, retValue, napi_undefined);

    retValue = NapiUtils::CallFunction(env, httpRequestValue, requestFunc, 1, args);
    ASSERT_VALUE_IS_PROMISE(env, retValue);
    CallPromiseThenCatch(env, retValue, callbackOneParam);
}
DEFINE_TEST_END

DEFINE_TEST_BEGIN(TestHttpModuleMethodPostExtraDataString, true)
{
    napi_value urlValue = NapiUtils::CreateStringUtf8(env, "https://" SERVER_IP "?name=Mao");

    napi_value options = NapiUtils::CreateObject(env);

    napi_value header = NapiUtils::CreateObject(env);
    NapiUtils::SetStringPropertyUtf8(env, header, "no-use", "no use header");
    NapiUtils::SetStringPropertyUtf8(env, header, "just-test", "just test header");

    napi_value extraData = NapiUtils::CreateStringUtf8(env, "Linux Http Test String");

    NapiUtils::SetNamedProperty(env, options, std::string(HttpConstant::PARAM_KEY_HEADER), header);
    NapiUtils::SetNamedProperty(env, options, std::string(HttpConstant::PARAM_KEY_EXTRA_DATA), extraData);
    NapiUtils::SetStringPropertyUtf8(env, options, std::string(HttpConstant::PARAM_KEY_METHOD),
                                     std::string(HttpConstant::HTTP_METHOD_POST));

    napi_value args[3] = {urlValue, options, callbackTwoParam};

    napi_value retValue = NapiUtils::CallFunction(env, httpRequestValue, requestFunc, 3, args);
    ASSERT_CHECK_VALUE_TYPE(env, retValue, napi_undefined);

    retValue = NapiUtils::CallFunction(env, httpRequestValue, requestFunc, 2, args);
    ASSERT_VALUE_IS_PROMISE(env, retValue);
    CallPromiseThenCatch(env, retValue, callbackOneParam);
}
DEFINE_TEST_END

DEFINE_TEST_BEGIN(TestHttpModuleMethodAndHeaderFail, true)
{
    napi_value urlValue = NapiUtils::CreateStringUtf8(env, "https://" SERVER_IP
                                                           ":7878"
                                                           "?name=Mao");

    napi_value args[2] = {urlValue, callbackTwoParam};

    napi_value retValue = NapiUtils::CallFunction(env, httpRequestValue, requestFunc, 2, args);
    ASSERT_CHECK_VALUE_TYPE(env, retValue, napi_undefined);

    retValue = NapiUtils::CallFunction(env, httpRequestValue, requestFunc, 1, args);
    ASSERT_VALUE_IS_PROMISE(env, retValue);
    CallPromiseThenCatch(env, retValue, callbackOneParam);
}
DEFINE_TEST_END

DEFINE_TEST_BEGIN(TestHttpModuleMethodPostExtraDataArrayBuffer, true)
{
    napi_value urlValue = NapiUtils::CreateStringUtf8(env, "https://" SERVER_IP "?name=Mao");

    napi_value options = NapiUtils::CreateObject(env);

    napi_value header = NapiUtils::CreateObject(env);
    NapiUtils::SetStringPropertyUtf8(env, header, "no-use", "no use header");
    NapiUtils::SetStringPropertyUtf8(env, header, "just-test", "just test header");
    NapiUtils::SetStringPropertyUtf8(env, header, std::string(HttpConstant::HTTP_CONTENT_TYPE), "mine-png");

    FILE *fp = fopen("for-post.png", "rb");
    fseek(fp, 0L, SEEK_END);
    long size = ftell(fp);
    void *buffer = malloc(size);
    fseek(fp, 0, SEEK_SET);
    size_t readSize = fread((void *)buffer, 1, size, fp);
    NETSTACK_LOGI("file size = %ld read size = %zu", size, readSize);

    void *data = nullptr;
    napi_value extraData = NapiUtils::CreateArrayBuffer(env, readSize, &data);
    memcpy_s(data, readSize, buffer, readSize);

    NapiUtils::SetNamedProperty(env, options, std::string(HttpConstant::PARAM_KEY_HEADER), header);
    NapiUtils::SetNamedProperty(env, options, std::string(HttpConstant::PARAM_KEY_EXTRA_DATA), extraData);
    NapiUtils::SetStringPropertyUtf8(env, options, std::string(HttpConstant::PARAM_KEY_METHOD),
                                     std::string(HttpConstant::HTTP_METHOD_POST));

    napi_value args[3] = {urlValue, options, callbackTwoParam};

    napi_value retValue = NapiUtils::CallFunction(env, httpRequestValue, requestFunc, 3, args);
    ASSERT_CHECK_VALUE_TYPE(env, retValue, napi_undefined);

    retValue = NapiUtils::CallFunction(env, httpRequestValue, requestFunc, 2, args);
    ASSERT_VALUE_IS_PROMISE(env, retValue);
    CallPromiseThenCatch(env, retValue, callbackOneParam);
}
DEFINE_TEST_END

DEFINE_TEST_BEGIN(TestHttpModuleMethodGetExtraDataNameValueHeaderKeyMultiCase, true)
{
    napi_value urlValue = NapiUtils::CreateStringUtf8(env, "https://" SERVER_IP "?name=Mao");

    napi_value options = NapiUtils::CreateObject(env);

    napi_value header = NapiUtils::CreateObject(env);
    NapiUtils::SetStringPropertyUtf8(env, header, "no-use", "no use header");
    NapiUtils::SetStringPropertyUtf8(env, header, "NO-USE", "Thanks");
    NapiUtils::SetStringPropertyUtf8(env, header, "just-test", "just test header");

    NapiUtils::SetNamedProperty(env, options, std::string(HttpConstant::PARAM_KEY_HEADER), header);

    napi_value args[3] = {urlValue, options, callbackTwoParam};

    napi_value retValue = NapiUtils::CallFunction(env, httpRequestValue, requestFunc, 3, args);
    ASSERT_CHECK_VALUE_TYPE(env, retValue, napi_undefined);

    retValue = NapiUtils::CallFunction(env, httpRequestValue, requestFunc, 2, args);
    ASSERT_VALUE_IS_PROMISE(env, retValue);
    CallPromiseThenCatch(env, retValue, callbackOneParam);
}
DEFINE_TEST_END

DEFINE_TEST_BEGIN(TestHttpModuleMethodGetOnHeaderReceiveOnce, true)
{
    napi_value urlValue = NapiUtils::CreateStringUtf8(env, "https://" SERVER_IP "?name=Mao");

    napi_value args[2] = {urlValue, callbackTwoParam};

    CallOnce(env, httpRequestValue, callbackOneParam);

    napi_value retValue = NapiUtils::CallFunction(env, httpRequestValue, requestFunc, 2, args);
    ASSERT_CHECK_VALUE_TYPE(env, retValue, napi_undefined);

    retValue = NapiUtils::CallFunction(env, httpRequestValue, requestFunc, 1, args);
    ASSERT_VALUE_IS_PROMISE(env, retValue);
    CallPromiseThenCatch(env, retValue, callbackOneParam);
}
DEFINE_TEST_END

DEFINE_TEST_BEGIN(TestHttpModuleMethodGetOnHeaderReceiveOnOn, true)
{
    napi_value urlValue = NapiUtils::CreateStringUtf8(env, "https://" SERVER_IP "?name=Mao");

    napi_value args[2] = {urlValue, callbackTwoParam};

    CallOn(env, httpRequestValue, callbackTwoParam);

    napi_value retValue = NapiUtils::CallFunction(env, httpRequestValue, requestFunc, 2, args);
    ASSERT_CHECK_VALUE_TYPE(env, retValue, napi_undefined);

    retValue = NapiUtils::CallFunction(env, httpRequestValue, requestFunc, 1, args);
    ASSERT_VALUE_IS_PROMISE(env, retValue);
    CallPromiseThenCatch(env, retValue, callbackOneParam);
}
DEFINE_TEST_END

DEFINE_TEST_BEGIN(TestHttpModuleMethodGetOnHeaderReceiveOff, true)
{
    napi_value urlValue = NapiUtils::CreateStringUtf8(env, "https://" SERVER_IP "?name=Mao");

    napi_value args[2] = {urlValue, callbackTwoParam};

    CallOn(env, httpRequestValue, callbackTwoParam);
    CallOff(env, httpRequestValue, callbackTwoParam);

    napi_value retValue = NapiUtils::CallFunction(env, httpRequestValue, requestFunc, 2, args);
    ASSERT_CHECK_VALUE_TYPE(env, retValue, napi_undefined);

    retValue = NapiUtils::CallFunction(env, httpRequestValue, requestFunc, 1, args);
    ASSERT_VALUE_IS_PROMISE(env, retValue);
    CallPromiseThenCatch(env, retValue, callbackOneParam);
}
DEFINE_TEST_END
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

    int ret = RUN_ALL_TESTS();
    (void)ret;

    g_nativeEngine->Loop(LOOP_DEFAULT);

    return 0;
}