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

[[maybe_unused]] const int MAX_SIZE = 10;
std::map<OH_NetStack_WebsocketClient *, WebsocketClient *> globalMap;
std::map<std::string, std::string> globalheaders;

WebsocketClient *GetInnerClientAdapter(OH_NetStack_WebsocketClient *key)
{
    auto it = globalMap.find(key);
    if (it != globalMap.end()) {
        return it->second;
    } else {
        return nullptr;
    }
}

OH_NetStack_WebsocketClient *GetNdkClientAdapter(WebsocketClient *websocketClient)
{
    for (const auto &pair : globalMap) {
        if (pair.second == websocketClient) {
            return pair.first;
        }
    }
    return nullptr;
}

bool IsNull(void *ptr)
{
    return (ptr == nullptr);
}

int32_t Conv2RequestOptions(struct OpenOptions *openOptions,
                            struct OH_NetStack_WebsocketClient_RequestOptions RequestOptions)
{
    if (openOptions == nullptr) {
        return -1;
    }

    if (IsNull(&RequestOptions)) {
        printf("RequestOptions is empty (NULL).\n");
    } else {
        printf("RequestOptions is not empty.\n");
    }

    struct OH_NetStack_WebsocketClient_Slist *currentHeader = RequestOptions.headers;

    while (currentHeader != nullptr) {
        std::string fieldName(currentHeader->FieldName);
        std::string fieldValue(currentHeader->FieldValue);
        openOptions->headers[fieldName] = fieldValue;
        currentHeader = currentHeader->next;
    }

    return 0;
}

int32_t Conv2CloseOptions(struct CloseOption *closeOption,
                          struct OH_NetStack_WebsocketClient_CloseOption RequestOptions)
{
    closeOption->code = RequestOptions.code;
    closeOption->reason = RequestOptions.reason;
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