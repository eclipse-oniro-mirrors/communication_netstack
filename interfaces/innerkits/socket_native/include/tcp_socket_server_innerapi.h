/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#ifndef COMMUNICATIONNETSTACK_SOCKET_SERVER_H
#define COMMUNICATIONNETSTACK_SOCKET_SERVER_H

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "net_address.h"
#include "tcp_socket_config.h"
#include "socket_constant.h"
#include "socket_remote_info.h"
#include "socket_state_base.h"
#include "tcp_extra_options.h"
#include "tcp_send_options.h"

namespace OHOS {
namespace NetStack {
namespace Socket {

using TCPSocketServerOnConnectCallback =  std::function<void(const int &clientId)>;
using TCPSocketServerOnErrorCallback = std::function<void(const int32_t errorNumber, const std::string &errorString)>;

using TCPSocketConnectionOnMessageCallback = std::function<void(const std::string &data,
    const SocketRemoteInfo &remoteInfo)>;
using TCPSocketConnectionOnCloseCallback = std::function<void(void)>;
using TCPSocketConnectionOnErrorCallback = std::function<void(const int32_t errorNumber,
    const std::string &errorString)>;

class TCPSocketConnection : public std::enable_shared_from_this<TCPSocketConnection> {
public:
    explicit TCPSocketConnection(int32_t clientId);
    ~TCPSocketConnection();

    int Send(const TCPSendOptions &options);
    int Close();
    int GetRemoteAddress(NetAddress &address);
    int GetLocalAddress(NetAddress &address);
    int GetSocketFd(int32_t &fd) const;

    void OnMessage(const TCPSocketConnectionOnMessageCallback &messageCallback);
    void OnClose(const TCPSocketConnectionOnCloseCallback &closeCallback);
    void OnError(const TCPSocketConnectionOnErrorCallback &OnErrorCallback);
    void OffMessage();
    void OffClose();
    void OffError();

    void SetSocketFd(const int32_t sockFd) { socketFd_ = sockFd; }
    int32_t GetClientId() const { return clientId_; }
    bool WaitForMessageCallback();

private:
    void CallOnMessageCallback(const std::string &data, const SocketRemoteInfo &remoteInfo);
    void CallOnCloseCallback();
    void CallOnErrorCallback(const int32_t err, const std::string &errMsg);
    bool IsRemoteConnect();

    std::mutex mutex_;
    TCPSocketConnectionOnMessageCallback onMessageCallback_ = nullptr;
    TCPSocketConnectionOnCloseCallback onCloseCallback_ = nullptr;
    TCPSocketConnectionOnErrorCallback onErrorCallback_ = nullptr;
    std::condition_variable messageCallbackCv_;
    std::atomic<bool> messageCallbackRegistered_{false};

    int32_t clientId_;
    int socketFd_ = -1;

    friend class TCPSocketServer;
};

class TCPSocketServer : public std::enable_shared_from_this<TCPSocketServer> {
public:
    TCPSocketServer();
    ~TCPSocketServer();

    int Listen(const NetAddress &address);
    int Close();
    int GetState(SocketStateBase &state);
    int SetExtraOptions(const TCPExtraOptions &options);
    int GetLocalAddress(NetAddress &address);
    int GetSocketFd(int32_t &fd) const;

    void OnConnect(const TCPSocketServerOnConnectCallback &connectCallback);
    void OnError(const TCPSocketServerOnErrorCallback &OnErrorCallback);
    void OffConnect();
    void OffError();

    std::shared_ptr<TCPSocketConnection> GetConnectionByClientID(const int32_t clientId);

private:
    std::shared_ptr<TCPSocketConnection> AddConnection(int32_t clientId);
    void RemoveConnection(int32_t clientId);
    int GenerateClientId() { return ++userCounter_; }
    std::shared_ptr<SocketConfig> GetSocketConfig() { return socketConfig_; }

    void RunAcceptThread();
    void DoAcceptLoop();
    bool AcceptNewClient(int &connectFD);
    bool InitNewClient(int connectFD, int &clientId);
    void ClientHandler(int32_t clientId);
    void CleanupClientConnection(int32_t clientId);
    bool PollAndRecvData(int connectFD, char *buffer, uint32_t recvBufferSize, int &recvSize);
    bool ServerBind(const NetAddress &address);
    bool SocketSetTcpExtraOptions(int sockfd, const TCPExtraOptions &option);
    void NotifyAcceptThdExit();
    void WaitForAcceptThdExit();

    void CallOnConnectCallback(const int32_t clientId);
    void CallOnErrorCallback(const int32_t err, const std::string &errMsg);

    std::mutex callbackMutex_;
    std::mutex acceptThdMutex_;
    std::condition_variable acceptThdCoVar_;
    TCPSocketServerOnConnectCallback onConnectCallback_ = nullptr;
    TCPSocketServerOnErrorCallback onErrorCallback_ = nullptr;

    int listenFd_ = -1;
    bool reuseAddr_ = true; // means enable reuseaddr feature
    std::atomic_int userCounter_ = 0;
    std::atomic<bool> isRunning_{false};
    std::atomic<bool> isClosed_{false};
    std::atomic<bool> isAcceptExit_{true};
    mutable std::shared_mutex connMapMutex_;
    std::unordered_map<int32_t, std::shared_ptr<TCPSocketConnection>> connectionMap_;
    std::shared_ptr<SocketConfig> socketConfig_ = nullptr;
};

} // namespace Socket
} // namespace NetStack
} // namespace OHOS

#endif /* COMMUNICATIONNETSTACK_SOCKET_SERVER_H */
