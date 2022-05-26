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

#include "socket_exec_fuzzer.h"
#include "socket_exec.h"

namespace OHOS {
namespace NetStack {
void MakeUdpSocketFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= 0)) {
        return;
    }

    sa_family_t family = *(reinterpret_cast<const sa_family_t*>(data));

    SocketExec::MakeUdpSocket(family);
}

void MakeTcpSocketFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= 0)) {
        return;
    }

    sa_family_t family = *(reinterpret_cast<const sa_family_t*>(data));

    SocketExec::MakeTcpSocket(family);
}

void ExecUdpBindFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= 0)) {
        return;
    }

    napi_env env = *(reinterpret_cast<const napi_env*>(data));
    EventManager eventManager;
    eventManager.SetData((void*)(data));
    BindContext context(env, &eventManager);

    SocketExec::ExecUdpBind(&context);
}

void ExecTcpBindFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= 0)) {
        return;
    }

    napi_env env = *(reinterpret_cast<const napi_env*>(data));
    EventManager eventManager;
    eventManager.SetData((void*)(data));
    BindContext context(env, &eventManager);

    SocketExec::ExecTcpBind(&context);
}

void ExecUdpSendFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= 0)) {
        return;
    }

    napi_env env = *(reinterpret_cast<const napi_env*>(data));
    EventManager eventManager;
    eventManager.SetData((void*)(data));
    UdpSendContext context(env, &eventManager);

    SocketExec::ExecUdpSend(&context);
}

void ExecTcpSendFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= 0)) {
        return;
    }

    napi_env env = *(reinterpret_cast<const napi_env*>(data));
    EventManager eventManager;
    eventManager.SetData((void*)(data));
    TcpSendContext context(env, &eventManager);

    SocketExec::ExecTcpSend(&context);
}

void ExecConnectFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= 0)) {
        return;
    }

    napi_env env = *(reinterpret_cast<const napi_env*>(data));
    EventManager eventManager;
    eventManager.SetData((void*)(data));
    ConnectContext context(env, &eventManager);

    SocketExec::ExecConnect(&context);
}

void ExecCloseFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= 0)) {
        return;
    }

    napi_env env = *(reinterpret_cast<const napi_env*>(data));
    EventManager eventManager;
    eventManager.SetData((void*)(data));
    CloseContext context(env, &eventManager);

    SocketExec::ExecClose(&context);
}

void ExecGetStateFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= 0)) {
        return;
    }

    napi_env env = *(reinterpret_cast<const napi_env*>(data));
    EventManager eventManager;
    eventManager.SetData((void*)(data));
    GetStateContext context(env, &eventManager);

    SocketExec::ExecGetState(&context);
}

void ExecGetRemoteAddressFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= 0)) {
        return;
    }

    napi_env env = *(reinterpret_cast<const napi_env*>(data));
    EventManager eventManager;
    eventManager.SetData((void*)(data));
    GetRemoteAddressContext context(env, &eventManager);

    SocketExec::ExecGetRemoteAddress(&context);
}

void ExecTcpSetExtraOptionsFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= 0)) {
        return;
    }

    napi_env env = *(reinterpret_cast<const napi_env*>(data));
    EventManager eventManager;
    eventManager.SetData((void*)(data));
    TcpSetExtraOptionsContext context(env, &eventManager);

    SocketExec::ExecTcpSetExtraOptions(&context);
}

void ExecUdpSetExtraOptionsFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= 0)) {
        return;
    }

    napi_env env = *(reinterpret_cast<const napi_env*>(data));
    EventManager eventManager;
    eventManager.SetData((void*)(data));
    UdpSetExtraOptionsContext context(env, &eventManager);

    SocketExec::ExecUdpSetExtraOptions(&context);
}
} // NetStack
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::NetStack::MakeUdpSocketFuzzTest(data, size);
    OHOS::NetStack::MakeTcpSocketFuzzTest(data, size);
    OHOS::NetStack::ExecUdpBindFuzzTest(data, size);
    OHOS::NetStack::ExecTcpBindFuzzTest(data, size);
    OHOS::NetStack::ExecUdpSendFuzzTest(data, size);
    OHOS::NetStack::ExecTcpSendFuzzTest(data, size);
    OHOS::NetStack::ExecConnectFuzzTest(data, size);
    OHOS::NetStack::ExecCloseFuzzTest(data, size);
    OHOS::NetStack::ExecGetStateFuzzTest(data, size);
    OHOS::NetStack::ExecGetRemoteAddressFuzzTest(data, size);
    OHOS::NetStack::ExecTcpSetExtraOptionsFuzzTest(data, size);
    OHOS::NetStack::ExecUdpSetExtraOptionsFuzzTest(data, size);

    return 0;
}