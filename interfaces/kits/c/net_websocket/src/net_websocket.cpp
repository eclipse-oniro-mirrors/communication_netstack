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

using namespace std;

using namespace OHOS::NetStack::WebsocketClient;

void OH_NetStack_OnMessageCallback(WebsocketClient *ptrInner, const std::string &data, size_t length)
{
    NETSTACK_LOGI("OH_NetStack_OnMessageCallback at:  %{public}d", __LINE__);
    char *data1 = const_cast<char *>(data.c_str());
    OH_NetStack_WebsocketClient *OH_client = GetNdkClientAdapter(ptrInner);
    OH_client->onMessage(OH_client, data1, length);
}

void OH_NetStack_OnCloseCallback(WebsocketClient *ptrInner, CloseResult closeResult)
{
    NETSTACK_LOGI("OH_NetStack_OnCloseCallback at:  %{public}d", __LINE__);
    struct OH_NetStack_WebsocketClient_CloseResult OH_CloseResult;
    Conv2CloseResult(closeResult, &OH_CloseResult);
    OH_NetStack_WebsocketClient *OH_client = GetNdkClientAdapter(ptrInner);
    OH_client->onClose(OH_client, OH_CloseResult);
}

void OH_NetStack_OnErrorCallback(WebsocketClient *ptrInner, ErrorResult error)
{
    NETSTACK_LOGI("OH_NetStack_OnErrorCallback at:  %{public}d", __LINE__);
    struct OH_NetStack_WebsocketClient_ErrorResult OH_ErrorResult;
    Conv2ErrorResult(error, &OH_ErrorResult);
    OH_NetStack_WebsocketClient *OH_client = GetNdkClientAdapter(ptrInner);
    OH_client->onError(OH_client, OH_ErrorResult);
}

void OH_NetStack_OnOpenCallback(WebsocketClient *ptrInner, OpenResult openResult)
{
    NETSTACK_LOGI("OH_NetStack_OnOpenCallback at:  %{public}d", __LINE__);
    struct OH_NetStack_WebsocketClient_OpenResult OH_OpenResult;
    Conv2OpenResult(openResult, &OH_OpenResult);
    OH_NetStack_WebsocketClient *OH_client = GetNdkClientAdapter(ptrInner);
    OH_client->onOpen(OH_client, OH_OpenResult);
}

struct OH_NetStack_WebsocketClient *OH_NetStack_WebsocketClient_Construct(
    OH_NetStack_WebsocketClient_OnOpenCallback OnOpen, OH_NetStack_WebsocketClient_OnMessageCallback onMessage,
    OH_NetStack_WebsocketClient_OnErrorCallback OnError, OH_NetStack_WebsocketClient_OnCloseCallback onclose)
{
    OH_NetStack_WebsocketClient *OH_client = new OH_NetStack_WebsocketClient;
    WebsocketClient *websocketClient = new WebsocketClient();
    OH_client->onMessage = onMessage;
    OH_client->onClose = onclose;
    OH_client->onError = OnError;
    OH_client->onOpen = OnOpen;
    websocketClient->registcallback(OH_NetStack_OnOpenCallback, OH_NetStack_OnMessageCallback,
                                    OH_NetStack_OnErrorCallback, OH_NetStack_OnCloseCallback);
    if (globalMap.size() == 100) {
        OH_client = nullptr;
        return OH_client;
    }

    OH_client->RequestOptions.headers = nullptr;
    globalMap[OH_client] = websocketClient;
    return OH_client;
}

int OH_NetStack_WebSocketClient_AddHeader(struct OH_NetStack_WebsocketClient *client,
                                          struct OH_NetStack_WebsocketClient_Slist header)
{
    NETSTACK_LOGI("OH_NetStack_WebSocketClient_AddHeader at:  %{public}d", __LINE__);
    if (client == nullptr)
        return WebsocketErrorCode::WEBSOCKET_CLIENT_IS_NULL;
    NETSTACK_LOGI("OH_NetStack_WebSocketClient_AddHeader at:  %{public}d", __LINE__);
    struct OH_NetStack_WebsocketClient_Slist *newHeader =
        (struct OH_NetStack_WebsocketClient_Slist *)malloc(sizeof(struct OH_NetStack_WebsocketClient_Slist));
    newHeader->FieldName = header.FieldName;
    newHeader->FieldValue = header.FieldValue;
    newHeader->next = NULL;
    struct OH_NetStack_WebsocketClient_Slist *currentHeader = client->RequestOptions.headers;
    if (currentHeader == NULL) {
        client->RequestOptions.headers = newHeader;
    } else {
        while (currentHeader->next != NULL) {
            currentHeader = currentHeader->next;
        }
        currentHeader->next = newHeader;
    }

    return 0;
}

int OH_NetStack_WebSocketClient_Send(struct OH_NetStack_WebsocketClient *client, char *data, size_t length)
{
    int ret;
    if (client == nullptr)
        return WebsocketErrorCode::WEBSOCKET_CLIENT_IS_NULL;
    WebsocketClient *websocketClient = GetInnerClientAdapter(client);

    if (websocketClient == NULL)
        return WebsocketErrorCode::WEBSOCKET_CLIENT_IS_NOT_CREAT;

    ret = websocketClient->Send(data, length);
    return ret;
}

int OH_NetStack_WebSocketClient_Connect(struct OH_NetStack_WebsocketClient *client, const char *url,
                                        struct OH_NetStack_WebsocketClient_RequestOptions options)
{
    NETSTACK_LOGI("OH_NetStack_WebSocketClient_Connect at:  %{public}d", __LINE__);
    int ret = 0;
    [[maybe_unused]] int32_t retConv;
    if (client == nullptr)
        return WebsocketErrorCode::WEBSOCKET_CLIENT_IS_NULL;

    struct OpenOptions openOptions;
    openOptions.headers = {};

    if (options.headers != nullptr)
        retConv = Conv2RequestOptions(&openOptions, options);

    WebsocketClient *websocketClient = GetInnerClientAdapter(client);

    if (websocketClient == NULL)
        return WebsocketErrorCode::WEBSOCKET_CLIENT_IS_NOT_CREAT;

    std::string URL = std::string(url);
    ret = websocketClient->Connect(URL, openOptions);
    NETSTACK_LOGI("function at:  %{public}d,ret=%{public}d", __LINE__, ret);
    return ret;
}

int OH_NetStack_WebSocketClient_Close(struct OH_NetStack_WebsocketClient *client,
                                      struct OH_NetStack_WebsocketClient_CloseOption options)
{
    int ret = 0;

    if (client == nullptr)
        return WebsocketErrorCode::WEBSOCKET_CLIENT_IS_NULL;

    WebsocketClient *websocketClient = GetInnerClientAdapter(client);
    if (websocketClient == NULL)
        return WebsocketErrorCode::WEBSOCKET_CLIENT_IS_NOT_CREAT;

    struct CloseOption closeOption;
    Conv2CloseOptions(&closeOption, options);
    ret = websocketClient->Close(closeOption);
    return ret;
}

void OH_NetStack_WebsocketClient_FreeHeader(struct OH_NetStack_WebsocketClient_Slist *header)
{
    if (header == NULL) {
        return;
    }
    OH_NetStack_WebsocketClient_FreeHeader(header->next);
    free(header);
}

int OH_NetStack_WebsocketClient_Destroy(struct OH_NetStack_WebsocketClient *client)
{
    int ret = 0;
    if (client == nullptr)
        return WebsocketErrorCode::WEBSOCKET_CLIENT_IS_NULL;
    WebsocketClient *websocketClient = GetInnerClientAdapter(client);
    if (websocketClient == NULL)
        return WebsocketErrorCode::WEBSOCKET_CLIENT_IS_NOT_CREAT;
    ret = websocketClient->Destroy();

    OH_NetStack_WebsocketClient_FreeHeader(client->RequestOptions.headers);

    delete client;
    globalMap.erase(client);
    return ret;
}
