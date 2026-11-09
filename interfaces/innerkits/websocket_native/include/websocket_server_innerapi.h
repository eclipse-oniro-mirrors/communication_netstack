/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef COMMUNICATIONNETSTACK_WEBSOCKET_SERVER_H
#define COMMUNICATIONNETSTACK_WEBSOCKET_SERVER_H

#include <atomic>
#include <libwebsockets.h>
#include <mutex>
#include <thread>
#include "server_context.h"
#include "atomic_callback.h"

namespace OHOS {
namespace NetStack {
namespace WebSocketServer {

class WebSocketServer {
public:
    WebSocketServer();
    ~WebSocketServer();
    using OnErrorCallback = std::function<void(WebSocketServer *server, ErrorResult)>;
    using OnConnectCallback = std::function<void(WebSocketServer *server, SocketConnection)>;
    using OnCloseCallback = std::function<void(WebSocketServer *server, CloseResult, SocketConnection)>;
    using OnMessageReceiveCallback =
        std::function<void(WebSocketServer *server, const std::string &, size_t, SocketConnection)>;

    int Start(const ServerConfig &config);
    int Stop();
    int Close(const SocketConnection &connection, const CloseOption &option);
    int Send(const char *data, int length, const SocketConnection &connection);
    int ListAllConnections(std::vector<SocketConnection> &connections) const;
    int Destroy();

    ServerContext *GetServerContext() const;

    int Registcallback(OnErrorCallback onError, OnConnectCallback onConnect,
        OnCloseCallback onClose, OnMessageReceiveCallback onMessageReceive);

    AtomicCallback<OnErrorCallback> onErrorCallback_;
    AtomicCallback<OnConnectCallback> onConnectCallback_;
    AtomicCallback<OnCloseCallback> onCloseCallback_;
    AtomicCallback<OnMessageReceiveCallback> onMessageReceiveCallback_;

private:
    ServerContext *serverContext_ = nullptr;
    std::thread serviceThread_;
    std::mutex destroyMutex_;

    void DestroyContext(lws_context *context);

    friend void RunServerService(WebSocketServer *server);
};
} // namespace WebSocketServer
} // namespace NetStack
} // namespace OHOS

#endif // COMMUNICATIONNETSTACK_WEBSOCKET_SERVER_H