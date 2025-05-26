/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef NET_WEB_SOCKET_ANI_H
#define NET_WEB_SOCKET_ANI_H

#include <cstdint>
#include <memory>
#include <string>

#include "cxx.h"
#include "websocket_client_innerapi.h"

namespace OHOS {
namespace NetStackAni {
struct ConnectOptions;
struct CloseOption;

std::unique_ptr<NetStack::WebSocketClient::WebSocketClient> CreateWebSocket();

int32_t Connect(NetStack::WebSocketClient::WebSocketClient &client, const rust::str url, ConnectOptions options);
int32_t Send(NetStack::WebSocketClient::WebSocketClient &client, const rust::str data);
int32_t Close(NetStack::WebSocketClient::WebSocketClient &client, CloseOption options);

} // namespace NetStackAni
} // namespace OHOS

#endif