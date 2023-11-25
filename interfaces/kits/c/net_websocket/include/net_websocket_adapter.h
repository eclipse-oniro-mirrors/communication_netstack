/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef NATIVE_WEBSOCKET_ADAPTER_H
#define NATIVE_WEBSOCKET_ADAPTER_H

#include "net_websocket.h"
#include "websocket_client_innerapi.h"

namespace OHOS::NetStack::WebsocketClient {

extern std::map<OH_NetStack_WebsocketClient *, WebsocketClient *> g_clientMap;

WebsocketClient *GetInnerClientAdapter(OH_NetStack_WebsocketClient *key);
OH_NetStack_WebsocketClient *GetNdkClientAdapter(WebsocketClient *websocketClient);

int32_t Conv2RequestOptions(struct OpenOptions *openOptions,
                            struct OH_NetStack_WebsocketClient_RequestOptions requestOptions);
int32_t Conv2CloseOptions(struct CloseOption *closeOption,
                          struct OH_NetStack_WebsocketClient_CloseOption requestOptions);
int32_t Conv2CloseResult(struct CloseResult closeResult,
                         struct OH_NetStack_WebsocketClient_CloseResult *OH_CloseResult);
int32_t Conv2ErrorResult(struct ErrorResult error, struct OH_NetStack_WebsocketClient_ErrorResult *OH_ErrorResult);
int32_t Conv2OpenResult(struct OpenResult openResult, struct OH_NetStack_WebsocketClient_OpenResult *OH_OpenResult);

} // namespace OHOS::NetStack::WebsocketClient
#endif /* NATIVE_WEBSOCKET_ADAPTER_H */