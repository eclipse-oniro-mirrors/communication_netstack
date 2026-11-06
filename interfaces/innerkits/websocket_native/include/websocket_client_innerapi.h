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

#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>

#include "websocket_client_error.h"
#include "atomic_callback.h"

namespace OHOS {
namespace NetStack {
namespace WebSocketClient {
class ClientContext;

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

struct OpenInfo {
    unsigned int status;
    const char *message;
    const char *protocol;
};

struct OpenOptions {
    std::map<std::string, std::string> headers;
    bool supportOriginPort = false;
    std::string serverName;
};

class WebSocketClient : public std::enable_shared_from_this<WebSocketClient> {
public:
    WebSocketClient();
    ~WebSocketClient();
    using OnMessageCallback = std::function<void(WebSocketClient *client, const std::string &data, size_t length)>;
    using OnCloseCallback = std::function<void(WebSocketClient *client, CloseResult closeResult)>;
    using OnErrorCallback = std::function<void(WebSocketClient *client, ErrorResult error)>;
    using OnOpenCallback = std::function<void(WebSocketClient *client, OpenResult openResult)>;
    using OnOpenInfoCallback = std::function<void(WebSocketClient *client, OpenInfo openInfo)>;
    using OnHeaderReceiveCallback =
        std::function<void(WebSocketClient *client, const std::map<std::string, std::string> &headers)>;
    using OnDataEndCallback = std::function<void(WebSocketClient *client)>;

    int Connect(std::string URL, OpenOptions Options);
    int ConnectEx(std::string URL, OpenOptions Options);
    int Send(const char *data, size_t length);
    int SendEx(const char *data, size_t length);
    int Close(CloseOption options);
    int CloseEx(CloseOption options);
    int Registcallback(OnOpenCallback OnOpen, OnMessageCallback onMessage, OnErrorCallback OnError,
                        OnCloseCallback onclose);
    int Destroy();
    int AppendData(void *data, size_t length);
    const std::string &GetData();
    void ClearData();

    AtomicCallback<OnMessageCallback> onMessageCallback_;
    AtomicCallback<OnCloseCallback> onCloseCallback_;
    AtomicCallback<OnErrorCallback> onErrorCallback_;
    AtomicCallback<OnOpenCallback> onOpenCallback_;
    AtomicCallback<OnOpenInfoCallback> onOpenInfoCallback_;
    AtomicCallback<OnHeaderReceiveCallback> onHeaderReceiveCallback_;
    AtomicCallback<OnDataEndCallback> onDataEndCallback_;
    ClientContext *GetClientContext() const;
    std::shared_ptr<ClientContext> GetClientContextShared() const;

private:
    void RunLwsThread();
    std::shared_ptr<ClientContext> clientContext_;
    std::string data_;
    std::thread serviceThread_;
    std::mutex operationMutex_;
};
} // namespace WebSocketClient
} // namespace NetStack
} // namespace OHOS

#endif // COMMUNICATIONNETSTACK_WEBSOCKET_CLIENT_H
