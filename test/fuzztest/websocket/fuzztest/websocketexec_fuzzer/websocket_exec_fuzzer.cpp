/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "websocket_exec_fuzzer.h"
#include "netstack_log.h"
#include "securec.h"
#include "websocket_exec.h"
#include <cstdint>

namespace OHOS {
namespace NetStack {
namespace Websocket {
namespace {
const uint8_t *g_netstackFuzzData = nullptr;
size_t g_netstackFuzzSize = 0;
size_t g_netstackFuzzPos = 0;
constexpr size_t STR_LEN = 255;

template <class T> T GetData()
{
    T object{};
    size_t objectSize = sizeof(object);
    if (g_netstackFuzzData == nullptr || objectSize > g_netstackFuzzSize - g_netstackFuzzPos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, g_netstackFuzzData + g_netstackFuzzPos, objectSize);
    if (ret != EOK) {
        return object;
    }
    g_netstackFuzzPos += objectSize;
    return object;
}

inline void SetGlobalFuzzData(const uint8_t *data, size_t size)
{
    g_netstackFuzzData = data;
    g_netstackFuzzSize = size;
    g_netstackFuzzPos = 0;
}

std::string GetStringFromData(int strlen)
{
    if (strlen < 1) {
        return "";
    }

    char cstr[strlen];
    cstr[strlen - 1] = '\0';
    for (int i = 0; i < strlen - 1; i++) {
        cstr[i] = GetData<char>();
    }
    std::string str(cstr);
    return str;
}
} // namespace

void ExecConnectFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    ConnectContext context(env, nullptr);

    WebSocketExec::ExecConnect(&context);
}

void ExecSendFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    SendContext context(env, nullptr);

    WebSocketExec::ExecSend(&context);
}

void ExecCloseFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    CloseContext context(env, nullptr);

    WebSocketExec::ExecClose(&context);
}

void SetWebsocketProxyTypeFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager *manager(GetData<EventManager *>());
    ConnectContext context(env, manager);
    WebsocketProxyType proxyType(GetData<WebsocketProxyType>());
    context.SetWebsocketProxyType(proxyType);
}

void SetSpecifiedWebsocketProxyFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager *manager(GetData<EventManager *>());
    ConnectContext context(env, manager);
    std::string str = GetStringFromData(STR_LEN);
    context.SetSpecifiedWebsocketProxy(str, size, str);
}

void SetWebsocketProtocolFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager *manager(GetData<EventManager *>());
    ConnectContext context(env, manager);
    std::string str = GetStringFromData(STR_LEN);
    context.SetProtocol(str);
}
} // namespace Websocket
} // namespace NetStack
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::NetStack::Websocket::ExecConnectFuzzTest(data, size);
    OHOS::NetStack::Websocket::ExecSendFuzzTest(data, size);
    OHOS::NetStack::Websocket::ExecCloseFuzzTest(data, size);
    OHOS::NetStack::Websocket::SetWebsocketProxyTypeFuzzTest(data, size);
    OHOS::NetStack::Websocket::SetSpecifiedWebsocketProxyFuzzTest(data, size);
    OHOS::NetStack::Websocket::SetWebsocketProtocolFuzzTest(data, size);
    return 0;
}
