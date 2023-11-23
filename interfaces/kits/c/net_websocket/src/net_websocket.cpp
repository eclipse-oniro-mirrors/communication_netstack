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
#include <cstring>
#include <iostream>

#include "net_websocket.h"
#include "net_websocket_adapter.h"
#include "netstack_log.h"
#include "websocket_client_innerapi.h"

using namespace OHOS::NetStack::WebsocketClient;

const int MAX_CLIENT_SIZE = 100;

void OH_NetStack_OnMessageCallback(WebsocketClient *ptrInner, const std::string &data, size_t length)
{
    NETSTACK_LOGD("websocket CAPI Message Callback");
    char *data1 = const_cast<char *>(data.c_str());
    OH_NetStack_WebsocketClient *OH_client = GetNdkClientAdapter(ptrInner);
    OH_client->onMessage(OH_client, data1, length);
}

void OH_NetStack_OnCloseCallback(WebsocketClient *ptrInner, CloseResult closeResult)
{
    NETSTACK_LOGD("websocket CAPI Close Callback");
    struct OH_NetStack_WebsocketClient_CloseResult OH_CloseResult;
    Conv2CloseResult(closeResult, &OH_CloseResult);
    OH_NetStack_WebsocketClient *OH_client = GetNdkClientAdapter(ptrInner);
    OH_client->onClose(OH_client, OH_CloseResult);
}

void OH_NetStack_OnErrorCallback(WebsocketClient *ptrInner, ErrorResult error)
{
    NETSTACK_LOGD("websocket CAPI Error Callback");
    struct OH_NetStack_WebsocketClient_ErrorResult OH_ErrorResult;
    Conv2ErrorResult(error, &OH_ErrorResult);
    OH_NetStack_WebsocketClient *OH_client = GetNdkClientAdapter(ptrInner);
    OH_client->onError(OH_client, OH_ErrorResult);
}

void OH_NetStack_OnOpenCallback(WebsocketClient *ptrInner, OpenResult openResult)
{
    NETSTACK_LOGD("websocket CAPI Open Callback");
    struct OH_NetStack_WebsocketClient_OpenResult OH_OpenResult;
    Conv2OpenResult(openResult, &OH_OpenResult);
    OH_NetStack_WebsocketClient *OH_client = GetNdkClientAdapter(ptrInner);
    OH_client->onOpen(OH_client, OH_OpenResult);
}

struct OH_NetStack_WebsocketClient *OH_NetStack_WebsocketClient_Construct(
    OH_NetStack_WebsocketClient_OnOpenCallback onOpen, OH_NetStack_WebsocketClient_OnMessageCallback onMessage,
    OH_NetStack_WebsocketClient_OnErrorCallback onError, OH_NetStack_WebsocketClient_OnCloseCallback onclose)
{
    OH_NetStack_WebsocketClient *OH_client = new OH_NetStack_WebsocketClient;
    WebsocketClient *websocketClient = new WebsocketClient();
    OH_client->onMessage = onMessage;
    OH_client->onClose = onclose;
    OH_client->onError = onError;
    OH_client->onOpen = onOpen;
    websocketClient->Registcallback(OH_NetStack_OnOpenCallback, OH_NetStack_OnMessageCallback,
                                    OH_NetStack_OnErrorCallback, OH_NetStack_OnCloseCallback);
    if (g_clientMap.size() == MAX_CLIENT_SIZE) {
        OH_client = nullptr;
        return OH_client;
    }

    OH_client->requestOptions.headers = nullptr;
    g_clientMap[OH_client] = websocketClient;
    return OH_client;
}

int OH_NetStack_WebSocketClient_AddHeader(struct OH_NetStack_WebsocketClient *client,
                                          struct OH_NetStack_WebsocketClient_Slist header)
{
    NETSTACK_LOGD("websocket CAPI AddHeader");
    if (client == nullptr) {
        return WebsocketErrorCode::WEBSOCKET_CLIENT_IS_NULL;
    }

    struct OH_NetStack_WebsocketClient_Slist *newHeader =
        (struct OH_NetStack_WebsocketClient_Slist *)malloc(sizeof(struct OH_NetStack_WebsocketClient_Slist));

    if (newHeader == nullptr) {
        return WebsocketErrorCode::WEBSOCKET_CONNECTION_ERROR;
    } else {
        newHeader->fieldName = header.fieldName;
        newHeader->fieldValue = header.fieldValue;
        newHeader->next = NULL;
        struct OH_NetStack_WebsocketClient_Slist *currentHeader = client->requestOptions.headers;
        if (currentHeader == nullptr) {
            client->requestOptions.headers = newHeader;
        } else {
            while (currentHeader->next != NULL) {
                currentHeader = currentHeader->next;
            }
            currentHeader->next = newHeader;
        }
        return 0;
    }
}

int OH_NetStack_WebSocketClient_Send(struct OH_NetStack_WebsocketClient *client, char *data, size_t length)
{
    int ret;
    if (client == nullptr) {
        return WebsocketErrorCode::WEBSOCKET_CLIENT_IS_NULL;
    }
    WebsocketClient *websocketClient = GetInnerClientAdapter(client);

    if (websocketClient == NULL) {
        return WebsocketErrorCode::WEBSOCKET_CLIENT_IS_NOT_CREAT;
    }

    ret = websocketClient->Send(data, length);
    return ret;
}

int OH_NetStack_WebSocketClient_Connect(struct OH_NetStack_WebsocketClient *client, const char *url,
                                        struct OH_NetStack_WebsocketClient_RequestOptions options)
{
    NETSTACK_LOGI("websocket CAPI Connect");
    int ret = 0;
    if (client == nullptr) {
        return WebsocketErrorCode::WEBSOCKET_CLIENT_IS_NULL;
    }

    struct OpenOptions openOptions;
    openOptions.headers = {};

    if (options.headers != nullptr) {
        Conv2RequestOptions(&openOptions, options);
    }

    WebsocketClient *websocketClient = GetInnerClientAdapter(client);

    if (websocketClient == NULL) {
        return WebsocketErrorCode::WEBSOCKET_CLIENT_IS_NOT_CREAT;
    }

    std::string connectUrl = std::string(url);
    ret = websocketClient->Connect(connectUrl, openOptions);
    NETSTACK_LOGD("websocket CAPI Connect,ret=%{public}d", ret);
    return ret;
}

int OH_NetStack_WebSocketClient_Close(struct OH_NetStack_WebsocketClient *client,
                                      struct OH_NetStack_WebsocketClient_CloseOption options)
{
    int ret = 0;

    if (client == nullptr) {
        return WebsocketErrorCode::WEBSOCKET_CLIENT_IS_NULL;
    }

    WebsocketClient *websocketClient = GetInnerClientAdapter(client);
    if (websocketClient == NULL) {
        return WebsocketErrorCode::WEBSOCKET_CLIENT_IS_NOT_CREAT;
    }

    struct CloseOption closeOption;
    Conv2CloseOptions(&closeOption, options);
    ret = websocketClient->Close(closeOption);
    return ret;
}

void OH_NetStack_WebsocketClient_FreeHeader(struct OH_NetStack_WebsocketClient_Slist *header)
{
    if (header == nullptr) {
        return;
    }
    OH_NetStack_WebsocketClient_FreeHeader(header->next);
    free(header);
}

int OH_NetStack_WebsocketClient_Destroy(struct OH_NetStack_WebsocketClient *client)
{
    NETSTACK_LOGI("websocket CAPI Destroy");
    int ret = 0;
    if (client == nullptr) {
        return WebsocketErrorCode::WEBSOCKET_CLIENT_IS_NULL;
    }
    WebsocketClient *websocketClient = GetInnerClientAdapter(client);
    if (websocketClient == NULL) {
        return WebsocketErrorCode::WEBSOCKET_CLIENT_IS_NOT_CREAT;
    }
    ret = websocketClient->Destroy();

    OH_NetStack_WebsocketClient_FreeHeader(client->requestOptions.headers);

    delete client;
    g_clientMap.erase(client);
    return ret;
}