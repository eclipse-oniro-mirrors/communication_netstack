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

#include <cstdint>
#include "netstack_log.h"
#include "securec.h"
#include "socket_exec_fuzzer.h"
#include "socket_exec.h"

namespace OHOS {
namespace NetStack {
namespace Socket {
namespace {
const uint8_t *g_netstackFuzzData = nullptr;
size_t g_netstackFuzzSize = 0;
size_t g_netstackFuzzPos = 0;
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

inline void setGlobalFuzzData(const uint8_t *data, size_t size)
{
    g_netstackFuzzData = data;
    g_netstackFuzzSize = size;
    g_netstackFuzzPos = 0;
}
} // namespace

void MakeUdpSocketFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    setGlobalFuzzData(data, size);
    sa_family_t family(GetData<sa_family_t>());
    if (family == AF_INET || family == AF_INET6) {
        return;
    }
    SocketExec::MakeUdpSocket(family);
}

void MakeTcpSocketFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    setGlobalFuzzData(data, size);
    sa_family_t family(GetData<sa_family_t>());
    if (family == AF_INET || family == AF_INET6) {
        return;
    }
    SocketExec::MakeTcpSocket(family);
}

void ExecUdpBindFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    napi_env env = nullptr;
    EventManager eventManager;
    BindContext context(env, &eventManager);

    SocketExec::ExecUdpBind(&context);
}

void ExecTcpBindFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    napi_env env = nullptr;
    EventManager eventManager;
    BindContext context(env, &eventManager);

    SocketExec::ExecTcpBind(&context);
}

void ExecUdpSendFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    napi_env env = nullptr;
    EventManager eventManager;
    UdpSendContext context(env, &eventManager);

    SocketExec::ExecUdpSend(&context);
}

void ExecTcpSendFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    napi_env env = nullptr;
    EventManager eventManager;
    TcpSendContext context(env, &eventManager);

    SocketExec::ExecTcpSend(&context);
}

void ExecConnectFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    napi_env env = nullptr;
    EventManager eventManager;
    ConnectContext context(env, &eventManager);

    SocketExec::ExecConnect(&context);
}

void ExecCloseFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    napi_env env = nullptr;
    EventManager eventManager;
    CloseContext context(env, &eventManager);

    SocketExec::ExecClose(&context);
}

void ExecGetStateFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    napi_env env = nullptr;
    EventManager eventManager;
    GetStateContext context(env, &eventManager);

    SocketExec::ExecGetState(&context);
}

void ExecGetRemoteAddressFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    napi_env env = nullptr;
    EventManager eventManager;
    GetRemoteAddressContext context(env, &eventManager);

    SocketExec::ExecGetRemoteAddress(&context);
}

void ExecTcpSetExtraOptionsFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    napi_env env = nullptr;
    EventManager eventManager;
    TcpSetExtraOptionsContext context(env, &eventManager);

    SocketExec::ExecTcpSetExtraOptions(&context);
}

void ExecUdpSetExtraOptionsFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    napi_env env = nullptr;
    EventManager eventManager;
    UdpSetExtraOptionsContext context(env, &eventManager);

    SocketExec::ExecUdpSetExtraOptions(&context);
}
} //Socket
} // NetStack
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::NetStack::Socket::MakeUdpSocketFuzzTest(data, size);
    OHOS::NetStack::Socket::MakeTcpSocketFuzzTest(data, size);
    OHOS::NetStack::Socket::ExecUdpBindFuzzTest(data, size);
    OHOS::NetStack::Socket::ExecTcpBindFuzzTest(data, size);
    OHOS::NetStack::Socket::ExecUdpSendFuzzTest(data, size);
    OHOS::NetStack::Socket::ExecTcpSendFuzzTest(data, size);
    OHOS::NetStack::Socket::ExecConnectFuzzTest(data, size);
    OHOS::NetStack::Socket::ExecCloseFuzzTest(data, size);
    OHOS::NetStack::Socket::ExecGetStateFuzzTest(data, size);
    OHOS::NetStack::Socket::ExecGetRemoteAddressFuzzTest(data, size);
    OHOS::NetStack::Socket::ExecTcpSetExtraOptionsFuzzTest(data, size);
    OHOS::NetStack::Socket::ExecUdpSetExtraOptionsFuzzTest(data, size);
    return 0;
}
