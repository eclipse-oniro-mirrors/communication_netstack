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

#include "net_websocket.h"
#include "websocket_client_innerapi.h"
#include <iostream>

namespace OHOS::NetStack::WebsocketClient {

std::map<OH_NetStack_WebsocketClient *, WebsocketClient *> g_clientMap;
std::map<std::string, std::string> globalheaders;

WebsocketClient *GetInnerClientAdapter(OH_NetStack_WebsocketClient *key)
{
    auto it = g_clientMap.find(key);
    if (it != g_clientMap.end()) {
        return it->second;
    } else {
        return nullptr;
    }
}

OH_NetStack_WebsocketClient *GetNdkClientAdapter(WebsocketClient *websocketClient)
{
    for (const auto &pair : g_clientMap) {
        if (pair.second == websocketClient) {
            return pair.first;
        }
    }
    return nullptr;
}

int32_t Conv2RequestOptions(struct OpenOptions *openOptions,
                            struct OH_NetStack_WebsocketClient_RequestOptions requestOptions)
{
    if (openOptions == nullptr) {
        return -1;
    }

    struct OH_NetStack_WebsocketClient_Slist *currentHeader = requestOptions.headers;

    while (currentHeader != nullptr) {
        std::string fieldName(currentHeader->fieldName);
        std::string fieldValue(currentHeader->fieldValue);
        openOptions->headers[fieldName] = fieldValue;
        currentHeader = currentHeader->next;
    }

    return 0;
}

int32_t Conv2CloseOptions(struct CloseOption *closeOption,
                          struct OH_NetStack_WebsocketClient_CloseOption requestOptions)
{
    closeOption->code = requestOptions.code;
    closeOption->reason = requestOptions.reason;
    return 0;
}

int32_t Conv2CloseResult(struct CloseResult closeResult, struct OH_NetStack_WebsocketClient_CloseResult *OH_CloseResult)
{
    OH_CloseResult->code = closeResult.code;
    OH_CloseResult->reason = closeResult.reason;
    return 0;
}

int32_t Conv2ErrorResult(struct ErrorResult error, struct OH_NetStack_WebsocketClient_ErrorResult *OH_ErrorResult)
{
    OH_ErrorResult->errorCode = error.errorCode;
    OH_ErrorResult->errorMessage = error.errorMessage;
    return 0;
}

int32_t Conv2OpenResult(struct OpenResult openResult, struct OH_NetStack_WebsocketClient_OpenResult *OH_OpenResult)
{
    OH_OpenResult->code = openResult.status;
    OH_OpenResult->reason = openResult.Message;

    return 0;
}

} // namespace OHOS::NetStack::WebsocketClient