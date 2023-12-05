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

#ifndef NETSTACK_LOCAL_SOCKET_EXEC_H
#define NETSTACK_LOCAL_SOCKET_EXEC_H

#include "local_socket_context.h"
#include "local_socket_server_context.h"

namespace OHOS::NetStack::Socket::LocalSocketExec {
int MakeLocalSocket(int socketType, bool needNonblock = true);

/* async work execute */
bool ExecLocalSocketBind(LocalSocketBindContext *context);

bool ExecLocalSocketConnect(LocalSocketConnectContext *context);

bool ExecLocalSocketSend(LocalSocketSendContext *context);

bool ExecLocalSocketClose(LocalSocketCloseContext *context);

bool ExecLocalSocketGetState(LocalSocketGetStateContext *context);

bool ExecLocalSocketGetSocketFd(LocalSocketGetSocketFdContext *context);

bool ExecLocalSocketSetExtraOptions(LocalSocketSetExtraOptionsContext *context);

bool ExecLocalSocketGetExtraOptions(LocalSocketGetExtraOptionsContext *context);

bool ExecLocalSocketServerListen(LocalSocketServerListenContext *context);

bool ExecLocalSocketServerGetState(LocalSocketServerGetStateContext *context);

bool ExecLocalSocketServerSetExtraOptions(LocalSocketServerSetExtraOptionsContext *context);

bool ExecLocalSocketServerGetExtraOptions(LocalSocketServerGetExtraOptionsContext *context);

bool ExecLocalSocketConnectionSend(LocalSocketServerSendContext *context);

bool ExecLocalSocketConnectionClose(LocalSocketServerCloseContext *context);

/* async work callback */
napi_value LocalSocketBindCallback(LocalSocketBindContext *context);

napi_value LocalSocketConnectCallback(LocalSocketConnectContext *context);

napi_value LocalSocketSendCallback(LocalSocketSendContext *context);

napi_value LocalSocketCloseCallback(LocalSocketCloseContext *context);

napi_value LocalSocketGetStateCallback(LocalSocketGetStateContext *context);

napi_value LocalSocketGetSocketFdCallback(LocalSocketGetSocketFdContext *context);

napi_value LocalSocketSetExtraOptionsCallback(LocalSocketSetExtraOptionsContext *context);

napi_value LocalSocketGetExtraOptionsCallback(LocalSocketGetExtraOptionsContext *context);

napi_value LocalSocketServerListenCallback(LocalSocketServerListenContext *context);

napi_value LocalSocketServerGetStateCallback(LocalSocketServerGetStateContext *context);

napi_value LocalSocketServerSetExtraOptionsCallback(LocalSocketServerSetExtraOptionsContext *context);

napi_value LocalSocketServerGetExtraOptionsCallback(LocalSocketServerGetExtraOptionsContext *context);

napi_value LocalSocketConnectionSendCallback(LocalSocketServerSendContext *context);

napi_value LocalSocketConnectionCloseCallback(LocalSocketServerCloseContext *context);

struct LocalSocketConnectionData {
    LocalSocketConnectionData(int32_t clientId, LocalSocketServerManager *serverManager)
        : clientId_(clientId), serverManager_(serverManager)
    {
    }
    ~LocalSocketConnectionData() = default;
    int32_t clientId_ = 0;
    LocalSocketServerManager *serverManager_ = nullptr;
} __attribute__((packed));
} // namespace OHOS::NetStack::Socket::LocalSocketExec
#endif /* NETSTACK_LOCAL_SOCKET_EXEC_H */