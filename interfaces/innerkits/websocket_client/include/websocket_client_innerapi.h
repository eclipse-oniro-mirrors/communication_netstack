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

#ifndef COMMUNICATIONNETSTACK_WEBSOCKET_CLIENT_H
#define COMMUNICATIONNETSTACK_WEBSOCKET_CLIENT_H

#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <signal.h>
#include <string.h>
#include <string>
#include <thread>
#include <libwebsockets.h>

#include "client_context.h"
#include "websocket_client_error.h"

namespace OHOS {
namespace NetStack {
namespace WebsocketClient {

struct CloseResult {
    unsigned int code;
    const char *reason;
};

struct CloseOption {
    unsigned int code;
    const char *reason;
};

struct ErrorResult {
    unsigned int errorCode;
    const char *errorMessage;
};

struct OpenResult {
    unsigned int status;
    const char *message;
};

struct OpenOptions {
    std::map<std::string, std::string> headers;
};

class WebsocketClient {
public:
    WebsocketClient();
    ~WebsocketClient();
    typedef void (*OnMessageCallback)(WebsocketClient *client, const std::string &data, size_t length);
    typedef void (*OnCloseCallback)(WebsocketClient *client, CloseResult closeResult);
    typedef void (*OnErrorCallback)(WebsocketClient *client, ErrorResult error);
    typedef void (*OnOpenCallback)(WebsocketClient *client, OpenResult openResult);

    int Connect(std::string URL, OpenOptions Options);
    int Send(char *data, size_t length);
    int Close(CloseOption options);
    int Registcallback(OnOpenCallback OnOpen, OnMessageCallback onMessage, OnErrorCallback OnError,
                       OnCloseCallback onclose);
    int Destroy();

    OnMessageCallback onMessageCallback_;
    OnCloseCallback onCloseCallback_;
    OnErrorCallback onErrorCallback_;
    OnOpenCallback onOpenCallback_;
    ClientContext *GetClientContext() const;

private:
    ClientContext *clientContext;
    
};
} // namespace WebsocketClient
} // namespace NetStack
} // namespace OHOS

#endif // COMMUNICATIONNETSTACK_WEBSOCKET_CLIENT_H