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

#include "test_common.h"

#include "constant.h"
#include "securec.h"
#include "websocket_module.h"

namespace OHOS::NetStack {
napi_value WEBSOCKET_HANDLE = nullptr;

int MESSAGE_NUM = 0;

napi_value ConnectCallback(napi_env env, napi_callback_info info)
{
    napi_value thisVal = nullptr;
    size_t paramsCount = 1;
    napi_value params[1] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &paramsCount, params, &thisVal, nullptr));

    bool connected = false;
    NAPI_CALL(env, napi_get_value_bool(env, params[0], &connected));
    NETSTACK_LOGI("connected: ? %{public}d", connected);
    return NapiUtils::GetUndefined(env);
}

napi_value SendCallback(napi_env env, napi_callback_info info)
{
    NETSTACK_LOGI("Send OK");
    return NapiUtils::GetUndefined(env);
}

napi_value OnOpen(napi_env env, napi_callback_info info)
{
    napi_value thisVal = nullptr;
    size_t paramsCount = 1;
    napi_value params[1] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &paramsCount, params, &thisVal, nullptr));

    NETSTACK_LOGI("status: %{public}u,", NapiUtils::GetUint32Property(env, params[0], "status"));
    NETSTACK_LOGI("message: %{public}s", NapiUtils::GetStringPropertyUtf8(env, params[0], "message").c_str());

    napi_value send = NapiUtils::GetNamedProperty(env, WEBSOCKET_HANDLE, WebSocketModule::WebSocket::FUNCTION_SEND);
    napi_value param[FUNCTION_PARAM_TWO] = {
        NapiUtils::CreateStringUtf8(env, "Hello World"),
        NapiUtils::CreateFunction(env, "SendCallback", SendCallback, nullptr),
    };
    NapiUtils::CallFunction(env, WEBSOCKET_HANDLE, send, FUNCTION_PARAM_TWO, param);
    return NapiUtils::GetUndefined(env);
}

static constexpr const int MAX_MESSAGE_NUM = 10;

napi_value OnMessage(napi_env env, napi_callback_info info)
{
    napi_value thisVal = nullptr;
    size_t paramsCount = 1;
    napi_value params[1] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &paramsCount, params, &thisVal, nullptr));

    ++MESSAGE_NUM;
    NETSTACK_LOGI("message: %{public}s", NapiUtils::GetStringFromValueUtf8(env, params[0]).c_str());

    if (MESSAGE_NUM <= MAX_MESSAGE_NUM) {
        napi_value send = NapiUtils::GetNamedProperty(env, WEBSOCKET_HANDLE, WebSocketModule::WebSocket::FUNCTION_SEND);
        napi_value param[FUNCTION_PARAM_TWO] = {
            NapiUtils::CreateStringUtf8(env, "Hello World"),
            NapiUtils::CreateFunction(env, "SendCallback", SendCallback, nullptr),
        };
        NapiUtils::CallFunction(env, WEBSOCKET_HANDLE, send, 1, param);
        return NapiUtils::GetUndefined(env);
    }

    napi_value close = NapiUtils::GetNamedProperty(env, WEBSOCKET_HANDLE, WebSocketModule::WebSocket::FUNCTION_CLOSE);
    napi_value options = NapiUtils::CreateObject(env);
    NapiUtils::SetUint32Property(env, options, "code", CLOSE_REASON_NORMAL_CLOSE);
    NapiUtils::SetStringPropertyUtf8(env, options, "reason", "CLOSE_NORMAL");
    napi_value param[1] = {options};
    NapiUtils::CallFunction(env, WEBSOCKET_HANDLE, close, 1, param);
    return NapiUtils::GetUndefined(env);
}

[[maybe_unused]] HWTEST_F(NativeEngineTest, name, testing::ext::TestSize.Level0)
{
    auto env = (napi_env)engine_;
    napi_value exports = NapiUtils::CreateObject(env);

    WebSocketModule::InitWebSocketModule(env, exports);
    napi_value createWebsocket = NapiUtils::GetNamedProperty(env, exports, WebSocketModule::FUNCTION_CREATE_WEB_SOCKET);

    if (WEBSOCKET_HANDLE == nullptr) {
        WEBSOCKET_HANDLE = NapiUtils::CallFunction(env, exports, createWebsocket, 0, nullptr);
    }

    ASSERT_TRUE(NapiUtils::GetValueType(env, WEBSOCKET_HANDLE) == napi_object);

    napi_value connect =
        NapiUtils::GetNamedProperty(env, WEBSOCKET_HANDLE, WebSocketModule::WebSocket::FUNCTION_CONNECT);
    napi_value header = NapiUtils::CreateObject(env);
    NapiUtils::SetStringPropertyUtf8(env, header, "Name1", "Value1");
    NapiUtils::SetStringPropertyUtf8(env, header, "Name2", "Value2");
    napi_value obj = NapiUtils::CreateObject(env);
    NapiUtils::SetNamedProperty(env, obj, "header", header);
    napi_value param[FUNCTION_PARAM_THREE] = {
        NapiUtils::CreateStringUtf8(env, "wss://x.x.x.x:443/socket"),
        obj,
        NapiUtils::CreateFunction(env, "ConnectCallback", ConnectCallback, nullptr),
    };
    NapiUtils::CallFunction(env, WEBSOCKET_HANDLE, connect, FUNCTION_PARAM_TWO, param);

    napi_value on = NapiUtils::GetNamedProperty(env, WEBSOCKET_HANDLE, WebSocketModule::WebSocket::FUNCTION_ON);
    napi_value onOpenParam[FUNCTION_PARAM_TWO] = {
        NapiUtils::CreateStringUtf8(env, "open"),
        NapiUtils::CreateFunction(env, "OnOpen", OnOpen, nullptr),
    };
    NapiUtils::CallFunction(env, WEBSOCKET_HANDLE, on, FUNCTION_PARAM_TWO, onOpenParam);

    napi_value onMessageParam[FUNCTION_PARAM_TWO] = {
        NapiUtils::CreateStringUtf8(env, "message"),
        NapiUtils::CreateFunction(env, "OnMessage", OnMessage, nullptr),
    };

    // call on("open") more times
    NapiUtils::CallFunction(env, WEBSOCKET_HANDLE, on, FUNCTION_PARAM_TWO, onOpenParam);
    NapiUtils::CallFunction(env, WEBSOCKET_HANDLE, on, FUNCTION_PARAM_TWO, onMessageParam);
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

    g_nativeEngine =
        reinterpret_cast<NativeEngine *>(new QuickJSNativeEngine(rt, ctx, nullptr)); // default instance id 0

    int ret = RUN_ALL_TESTS();
    (void)ret;

    g_nativeEngine->Loop(LOOP_DEFAULT);

    return 0;
}