/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "socket_exec_fuzzer.h"

#include "local_socket_exec.h"
#include "netstack_log.h"
#include "securec.h"
#include "socket_exec.h"
#include <cstdint>

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

inline void SetGlobalFuzzData(const uint8_t *data, size_t size)
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
    SetGlobalFuzzData(data, size);
    sa_family_t family(GetData<sa_family_t>());
    if (family == AF_INET || family == AF_INET6) {
        return;
    }
    int sockfd = SocketExec::MakeUdpSocket(family);
    close(sockfd);
}

void MakeTcpSocketFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    sa_family_t family(GetData<sa_family_t>());
    if (family == AF_INET || family == AF_INET6) {
        return;
    }
    int sockfd = SocketExec::MakeTcpSocket(family);
    close(sockfd);
}

void ExecUdpBindFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager eventManager;
    BindContext context(env, &eventManager);

    SocketExec::ExecUdpBind(&context);
}

void ExecTcpBindFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager eventManager;
    BindContext context(env, &eventManager);

    SocketExec::ExecTcpBind(&context);
}

void ExecUdpSendFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager eventManager;
    UdpSendContext context(env, &eventManager);

    SocketExec::ExecUdpSend(&context);
}

void ExecTcpSendFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager eventManager;
    TcpSendContext context(env, &eventManager);

    SocketExec::ExecTcpSend(&context);
}

void ExecConnectFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager eventManager;
    ConnectContext context(env, &eventManager);

    SocketExec::ExecConnect(&context);
}

void ExecCloseFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager eventManager;
    CloseContext context(env, &eventManager);

    SocketExec::ExecClose(&context);
}

void ExecGetStateFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager eventManager;
    GetStateContext context(env, &eventManager);

    SocketExec::ExecGetState(&context);
}

void ExecGetRemoteAddressFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager eventManager;
    GetRemoteAddressContext context(env, &eventManager);

    SocketExec::ExecGetRemoteAddress(&context);
}

void ExecTcpSetExtraOptionsFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager eventManager;
    TcpSetExtraOptionsContext context(env, &eventManager);

    SocketExec::ExecTcpSetExtraOptions(&context);
}

void ExecUdpSetExtraOptionsFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager eventManager;
    UdpSetExtraOptionsContext context(env, &eventManager);

    SocketExec::ExecUdpSetExtraOptions(&context);
}

void ExecTcpServerListenFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager eventManager;
    TcpServerListenContext context(env, &eventManager);

    SocketExec::ExecTcpServerListen(&context);
}

void ExecTcpServerSetExtraOptionsFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager eventManager;
    TcpServerSetExtraOptionsContext context(env, &eventManager);

    SocketExec::ExecTcpServerSetExtraOptions(&context);
}

void ExecTcpServerGetStateFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager eventManager;
    TcpServerGetStateContext context(env, &eventManager);

    SocketExec::ExecTcpServerGetState(&context);
}

void ExecTcpConnectionSendFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager eventManager;
    TcpServerSendContext context(env, &eventManager);

    SocketExec::ExecTcpConnectionSend(&context);
}

void ExecTcpConnectionGetRemoteAddressFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager eventManager;
    TcpServerGetRemoteAddressContext context(env, &eventManager);

    SocketExec::ExecTcpConnectionGetRemoteAddress(&context);
}

void ExecTcpConnectionCloseFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager eventManager;
    TcpServerCloseContext context(env, &eventManager);

    SocketExec::ExecTcpConnectionClose(&context);
}

void ExecUdpAddMembershipFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager eventManager;
    MulticastMembershipContext context(env, &eventManager);

    SocketExec::ExecUdpAddMembership(&context);
}

void ExecUdpDropMembershipFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager eventManager;
    MulticastMembershipContext context(env, &eventManager);

    SocketExec::ExecUdpDropMembership(&context);
}

void ExecSetMulticastTTLFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager eventManager;
    MulticastSetTTLContext context(env, &eventManager);

    SocketExec::ExecSetMulticastTTL(&context);
}

void ExecGetMulticastTTLFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager eventManager;
    MulticastGetTTLContext context(env, &eventManager);

    SocketExec::ExecGetMulticastTTL(&context);
}

void ExecSetLoopbackModeFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager eventManager;
    MulticastSetLoopbackContext context(env, &eventManager);

    SocketExec::ExecSetLoopbackMode(&context);
}

void ExecGetLoopbackModeFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager eventManager;
    MulticastGetLoopbackContext context(env, &eventManager);

    SocketExec::ExecGetLoopbackMode(&context);
}

void MakeLocalSocketFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    int sockfd = LocalSocketExec::MakeLocalSocket(SOCK_STREAM);
    close(sockfd);
}

void ExecLocalSocketBindFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager eventManager;
    LocalSocketBindContext context(env, &eventManager);

    LocalSocketExec::ExecLocalSocketBind(&context);
}

void ExecLocalSocketConnectFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager eventManager;
    LocalSocketConnectContext context(env, &eventManager);

    LocalSocketExec::ExecLocalSocketConnect(&context);
}

void ExecLocalSocketSendFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager eventManager;
    LocalSocketSendContext context(env, &eventManager);

    LocalSocketExec::ExecLocalSocketSend(&context);
}

void ExecLocalSocketCloseFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager eventManager;
    LocalSocketCloseContext context(env, &eventManager);

    LocalSocketExec::ExecLocalSocketClose(&context);
}

void ExecLocalSocketGetStateFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager eventManager;
    LocalSocketGetStateContext context(env, &eventManager);

    LocalSocketExec::ExecLocalSocketGetState(&context);
}

void ExecLocalSocketGetSocketFdFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager eventManager;
    LocalSocketGetSocketFdContext context(env, &eventManager);

    LocalSocketExec::ExecLocalSocketGetSocketFd(&context);
}

void ExecLocalSocketSetExtraOptionsFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager eventManager;
    LocalSocketSetExtraOptionsContext context(env, &eventManager);

    LocalSocketExec::ExecLocalSocketSetExtraOptions(&context);
}

void ExecLocalSocketGetExtraOptionsFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager eventManager;
    LocalSocketGetExtraOptionsContext context(env, &eventManager);

    LocalSocketExec::ExecLocalSocketGetExtraOptions(&context);
}

void ExecLocalSocketServerListenFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager eventManager;
    LocalSocketServerListenContext context(env, &eventManager);

    LocalSocketExec::ExecLocalSocketServerListen(&context);
}

void ExecLocalSocketServerGetStateFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager eventManager;
    LocalSocketServerGetStateContext context(env, &eventManager);

    LocalSocketExec::ExecLocalSocketServerGetState(&context);
}

void ExecLocalSocketServerSetExtraOptionsFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager eventManager;
    LocalSocketServerSetExtraOptionsContext context(env, &eventManager);

    LocalSocketExec::ExecLocalSocketServerSetExtraOptions(&context);
}

void ExecLocalSocketServerGetExtraOptionsFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager eventManager;
    LocalSocketServerGetExtraOptionsContext context(env, &eventManager);

    LocalSocketExec::ExecLocalSocketServerGetExtraOptions(&context);
}

void ExecLocalSocketConnectionSendFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager eventManager;
    LocalSocketServerSendContext context(env, &eventManager);

    LocalSocketExec::ExecLocalSocketConnectionSend(&context);
}

void ExecLocalSocketConnectionCloseFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    EventManager eventManager;
    LocalSocketServerCloseContext context(env, &eventManager);

    LocalSocketExec::ExecLocalSocketConnectionClose(&context);
}
} // namespace Socket
} // namespace NetStack
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
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
    OHOS::NetStack::Socket::ExecTcpServerListenFuzzTest(data, size);
    OHOS::NetStack::Socket::ExecTcpServerSetExtraOptionsFuzzTest(data, size);
    OHOS::NetStack::Socket::ExecTcpServerGetStateFuzzTest(data, size);
    OHOS::NetStack::Socket::ExecTcpConnectionSendFuzzTest(data, size);
    OHOS::NetStack::Socket::ExecTcpConnectionGetRemoteAddressFuzzTest(data, size);
    OHOS::NetStack::Socket::ExecTcpConnectionCloseFuzzTest(data, size);
    OHOS::NetStack::Socket::ExecUdpAddMembershipFuzzTest(data, size);
    OHOS::NetStack::Socket::ExecUdpDropMembershipFuzzTest(data, size);
    OHOS::NetStack::Socket::ExecSetMulticastTTLFuzzTest(data, size);
    OHOS::NetStack::Socket::ExecGetMulticastTTLFuzzTest(data, size);
    OHOS::NetStack::Socket::ExecSetLoopbackModeFuzzTest(data, size);
    OHOS::NetStack::Socket::ExecGetLoopbackModeFuzzTest(data, size);
    OHOS::NetStack::Socket::MakeLocalSocketFuzzTest(data, size);
    OHOS::NetStack::Socket::ExecLocalSocketBindFuzzTest(data, size);
    OHOS::NetStack::Socket::ExecLocalSocketConnectFuzzTest(data, size);
    OHOS::NetStack::Socket::ExecLocalSocketSendFuzzTest(data, size);
    OHOS::NetStack::Socket::ExecLocalSocketCloseFuzzTest(data, size);
    OHOS::NetStack::Socket::ExecLocalSocketGetStateFuzzTest(data, size);
    OHOS::NetStack::Socket::ExecLocalSocketGetSocketFdFuzzTest(data, size);
    OHOS::NetStack::Socket::ExecLocalSocketSetExtraOptionsFuzzTest(data, size);
    OHOS::NetStack::Socket::ExecLocalSocketGetExtraOptionsFuzzTest(data, size);
    OHOS::NetStack::Socket::ExecLocalSocketServerListenFuzzTest(data, size);
    OHOS::NetStack::Socket::ExecLocalSocketServerGetStateFuzzTest(data, size);
    OHOS::NetStack::Socket::ExecLocalSocketServerSetExtraOptionsFuzzTest(data, size);
    OHOS::NetStack::Socket::ExecLocalSocketServerGetExtraOptionsFuzzTest(data, size);
    OHOS::NetStack::Socket::ExecLocalSocketConnectionSendFuzzTest(data, size);
    OHOS::NetStack::Socket::ExecLocalSocketConnectionCloseFuzzTest(data, size);
    return 0;
}
