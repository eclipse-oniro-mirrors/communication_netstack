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

#include "tcp_socket_server_innerapi.h"

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include "securec.h"

#include "netstack_log.h"
#include "socket_exec_common.h"
#include "netstack_common_utils.h"
#include "socket_exec_error.h"
#include "socket_constant.h"

namespace OHOS {
namespace NetStack {
namespace Socket {
constexpr int USER_LIMIT = 511;
static constexpr int WAIT_MESSAGE_CALLBACK_TIMEOUT_SECONDS = 30;
static constexpr const char *TCP_SERVER_ACCEPT_RECV_DATA = "OS_NET_SockRD";
static constexpr const char *TCP_SERVER_HANDLE_CLIENT = "OS_NET_SockAcc";

bool TCPSocketServer::ServerBind(const NetAddress &address)
{
    sockaddr_in addr4 = {0};
    sockaddr_in6 addr6 = {0};
    sockaddr *addr = nullptr;
    socklen_t len;
    ExecCommonUtils::GetSocketAddr(&address, &addr4, &addr6, &addr, &len);
    if (addr == nullptr) {
        NETSTACK_LOGE("addr family error, address invalid");
        errno = EINVAL;
        return false;
    }

    if (bind(listenFd_, addr, len) < 0) {
        if (errno != EADDRINUSE) {
            NETSTACK_LOGE("bind failed, socket is %{public}d, errno is %{public}d", listenFd_, errno);
            return false;
        }
        if (addr->sa_family == AF_INET) {
            NETSTACK_LOGI("distribute a random port");
            addr4.sin_port = 0;
        } else if (addr->sa_family == AF_INET6) {
            NETSTACK_LOGI("distribute a random port");
            addr6.sin6_port = 0;
        }
        if (bind(listenFd_, addr, len) < 0) {
            NETSTACK_LOGE("rebind failed, socket is %{public}d, errno is %{public}d", listenFd_, errno);
            return false;
        }
        NETSTACK_LOGI("rebind success");
    }
    NETSTACK_LOGI("bind success");

    return true;
}

bool TCPSocketServer::SocketSetTcpExtraOptions(int sockfd, const TCPExtraOptions& option)
{
    if (!ExecCommonUtils::SetExtraOptionsBase(sockfd, static_cast<const ExtraOptionsBase &>(option))) {
        return false;
    }
    if (option.AlreadySetKeepAlive()) {
        int alive = static_cast<int>(option.IsKeepAlive());
        if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<void*>(&alive), sizeof(alive)) < 0) {
            NETSTACK_LOGE("set SO_KEEPALIVE failed, fd: %{public}d", sockfd);
            return false;
        }
    }
    if (option.AlreadySetOobInline()) {
        int oob = static_cast<int>(option.IsOOBInline());
        if (setsockopt(sockfd, SOL_SOCKET, SO_OOBINLINE, reinterpret_cast<void*>(&oob), sizeof(oob)) < 0) {
            NETSTACK_LOGE("set SO_OOBINLINE failed, fd: %{public}d", sockfd);
            return false;
        }
    }
    if (option.AlreadySetTcpNoDelay()) {
        int noDelay = static_cast<int>(option.IsTCPNoDelay());
        if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<void*>(&noDelay), sizeof(noDelay)) < 0) {
            NETSTACK_LOGE("set TCP_NODELAY failed, fd: %{public}d", sockfd);
            return false;
        }
    }
#if !defined(IOS_PLATFORM)
    if (option.IsTCPFastOpen()) {
        int fastOpen = 1;
        if (setsockopt(sockfd, SOL_TCP, TCP_FASTOPEN_CONNECT, &fastOpen, sizeof(fastOpen)) < 0) {
            NETSTACK_LOGE("set SOL_TCP TFO failed! fd=%{public}d, errno=%{public}d", sockfd, errno);
            return false;
        }
    }
#endif
    if (option.AlreadySetLinger()) {
        linger soLinger = {.l_onoff = option.socketLinger.IsOn(),
                           .l_linger = static_cast<int>(option.socketLinger.GetLinger())};
        if (setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &soLinger, sizeof(soLinger)) < 0) {
            NETSTACK_LOGE("set SO_LINGER failed, fd: %{public}d", sockfd);
            return false;
        }
    }
    return true;
}

bool TCPSocketConnection::IsRemoteConnect()
{
    sockaddr_storage sockAddr = {};
    socklen_t len = sizeof(sockaddr_storage);
    if (getsockname(socketFd_, reinterpret_cast<sockaddr *>(&sockAddr), &len) < 0) {
        NETSTACK_LOGE("get sock name failed, address invalid");
        return false;
    }
    if (sockAddr.ss_family == AF_INET) {
        sockaddr_in addr4 = {0};
        socklen_t len4 = sizeof(addr4);
        int ret = getpeername(socketFd_, reinterpret_cast<sockaddr *>(&addr4), &len4);
        return ret >= 0 && addr4.sin_port != 0;
    } else if (sockAddr.ss_family == AF_INET6) {
        sockaddr_in6 addr6 = {0};
        socklen_t len6 = sizeof(addr6);
        int ret = getpeername(socketFd_, reinterpret_cast<sockaddr *>(&addr6), &len6);
        return ret >= 0 && addr6.sin6_port != 0;
    }
    NETSTACK_LOGE("sock is not connect to remote, socket:%{public}d, errno:%{public}d", socketFd_, errno);
    return false;
}

TCPSocketConnection::TCPSocketConnection(int32_t clientId) : clientId_(clientId)
{
}

TCPSocketConnection::~TCPSocketConnection()
{
    Close();
}

int TCPSocketConnection::Send(const TCPSendOptions &options)
{
    if (!CommonUtils::HasInternetPermission()) {
        NETSTACK_LOGE("INTERNET permission denied.");
        return PERMISSION_DENIED_CODE;
    }
    auto data = options.GetData();
    if (data.empty()) {
        NETSTACK_LOGE("TCPSendOptions data string is empty.");
        return PARAM_ERROR_CODE;
    }

    if (socketFd_ < 0) {
        NETSTACK_LOGE("fd is invalid or close");
        return SYSTEM_INTERNAL_ERROR;
    }

    if (!IsRemoteConnect()) {
        return SYSTEM_INTERNAL_ERROR;
    }

    if (!ExecCommonUtils::PollSendData(socketFd_, data.c_str(), data.size(), nullptr, 0)) {
        NETSTACK_LOGE("send failed, socket is %{public}d, errno is %{public}d", socketFd_, errno);
        return SYSTEM_INTERNAL_ERROR;
    }
    return SOCKET_ERROR_OK;
}

int TCPSocketConnection::Close()
{
    if (!CommonUtils::HasInternetPermission()) {
        NETSTACK_LOGE("INTERNET permission denied.");
        return PERMISSION_DENIED_CODE;
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (socketFd_ >= 0) {
            shutdown(socketFd_, SHUT_RDWR);
            close(socketFd_);
            socketFd_ = -1;
        }
        messageCallbackCv_.notify_all();
    }

    CallOnCloseCallback();
    return SOCKET_ERROR_OK;
}

int TCPSocketConnection::GetRemoteAddress(NetAddress &address)
{
    if (!CommonUtils::HasInternetPermission()) {
        NETSTACK_LOGE("INTERNET permission denied.");
        return PERMISSION_DENIED_CODE;
    }
    if (socketFd_ < 0) {
        NETSTACK_LOGE("fd is invalid or close");
        return SYSTEM_INTERNAL_ERROR;
    }
    if (!ExecCommonUtils::FillRemoteAddress(socketFd_, address)) {
        NETSTACK_LOGE("FillRemoteAddress failed.");
        return ConvertSocketServerErrno(errno);
    }
    return SOCKET_ERROR_OK;
}

int TCPSocketConnection::GetLocalAddress(NetAddress &address)
{
    if (!CommonUtils::HasInternetPermission()) {
        NETSTACK_LOGE("INTERNET permission denied.");
        return PERMISSION_DENIED_CODE;
    }
    if (socketFd_ < 0) {
        NETSTACK_LOGE("fd is invalid or close");
        return SYSTEM_INTERNAL_ERROR;
    }
    if (!ExecCommonUtils::FillLocalAddress(socketFd_, address)) {
        NETSTACK_LOGE("FillLocalAddress failed.");
        return ConvertSocketServerErrno(errno);
    }
    return SOCKET_ERROR_OK;
}

int TCPSocketConnection::GetSocketFd(int32_t &fd) const
{
    if (!CommonUtils::HasInternetPermission()) {
        NETSTACK_LOGE("INTERNET permission denied.");
        return PERMISSION_DENIED_CODE;
    }
    if (socketFd_ < 0) {
        NETSTACK_LOGE("fd is invalid or close");
        return SYSTEM_INTERNAL_ERROR;
    }
    fd = socketFd_;
    return SOCKET_ERROR_OK;
}

void TCPSocketConnection::CallOnMessageCallback(const std::string &data, const SocketRemoteInfo &remoteInfo)
{
    TCPSocketConnectionOnMessageCallback callback = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (onMessageCallback_) {
            callback = onMessageCallback_;
        }
    }
    if (callback) {
        callback(data, remoteInfo);
    }
}

void TCPSocketConnection::CallOnCloseCallback()
{
    TCPSocketConnectionOnCloseCallback callback = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (onCloseCallback_) {
            callback = onCloseCallback_;
        }
    }
    if (callback) {
        callback();
    }
}

void TCPSocketConnection::CallOnErrorCallback(const int32_t err, const std::string &errMsg)
{
    TCPSocketConnectionOnErrorCallback callback = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (onErrorCallback_) {
            callback = onErrorCallback_;
        }
    }
    if (callback) {
        callback(err, errMsg);
    }
}

bool TCPSocketConnection::WaitForMessageCallback()
{
    std::unique_lock<std::mutex> lock(mutex_);
    bool registered = messageCallbackCv_.wait_for(lock, std::chrono::seconds(WAIT_MESSAGE_CALLBACK_TIMEOUT_SECONDS),
        [this]() {
            return messageCallbackRegistered_ || socketFd_ < 0;
        });
    if (!registered) {
        NETSTACK_LOGE("WaitForMessageCallback timed out waiting for message listener registration");
        return false;
    }

    return messageCallbackRegistered_ && socketFd_ >= 0;
}

void TCPSocketConnection::OnMessage(const TCPSocketConnectionOnMessageCallback &messageCallback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    onMessageCallback_ = messageCallback;
    messageCallbackRegistered_.store(true);
    messageCallbackCv_.notify_all();
}

void TCPSocketConnection::OnClose(const TCPSocketConnectionOnCloseCallback &closeCallback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    onCloseCallback_ = closeCallback;
}

void TCPSocketConnection::OnError(const TCPSocketConnectionOnErrorCallback &onErrorCallback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    onErrorCallback_ = onErrorCallback;
}

void TCPSocketConnection::OffMessage()
{
    std::lock_guard<std::mutex> lock(mutex_);
    onMessageCallback_ = nullptr;
}

void TCPSocketConnection::OffClose()
{
    std::lock_guard<std::mutex> lock(mutex_);
    onCloseCallback_ = nullptr;
}

void TCPSocketConnection::OffError()
{
    std::lock_guard<std::mutex> lock(mutex_);
    onErrorCallback_ = nullptr;
}

TCPSocketServer::TCPSocketServer() {}

TCPSocketServer::~TCPSocketServer()
{
    Close();
}

void TCPSocketServer::CleanupClientConnection(int32_t clientId)
{
    auto conn = GetConnectionByClientID(clientId);
    int connectFd = -1;
    if (conn != nullptr) {
        conn->GetSocketFd(connectFd);
        conn->Close();
    }
    RemoveConnection(clientId);
    auto config = GetSocketConfig();
    if (config != nullptr && connectFd >= 0) {
        config->RemoveAcceptSocket(connectFd);
    }
}

bool TCPSocketServer::PollAndRecvData(int connectFD, char *buffer, uint32_t recvBufferSize, int &recvSize)
{
    pollfd fds[1] = {{connectFD, POLLIN, 0}};
    int ret = poll(fds, 1, DEFAULT_POLL_TIMEOUT);
    if (ret < 0) {
        if (errno == EINTR) {
            return true;
        }
        NETSTACK_LOGE("Poll failed, fd: %{public}d, errno: %{public}d", connectFD, errno);
        return false;
    }
    if (ret == 0) {
        return true;
    }

    recvSize = recv(connectFD, buffer, recvBufferSize, 0);
    if (fcntl(connectFD, F_GETFL, 0) == -1) {
        NETSTACK_LOGE("Socket check failed, fd: %{public}d, errno: %{public}d", connectFD, errno);
        return false;
    }

    if (recvSize <= 0) {
        if (recvSize == 0 || (errno != EAGAIN && errno != EINTR)) {
            NETSTACK_LOGI("Connection closed, fd: %{public}d, errno: %{public}d", connectFD, errno);
            return false;
        }
    }

    return true;
}

void TCPSocketServer::ClientHandler(int32_t clientId)
{
    uint32_t recvBufferSize = DEFAULT_BUFFER_SIZE;
    auto config = GetSocketConfig();
    auto conn = GetConnectionByClientID(clientId);
    if (conn == nullptr || config == nullptr) {
        NETSTACK_LOGE("connnection or config is nullptr.");
        return;
    }
    if (!conn->WaitForMessageCallback()) {
        NETSTACK_LOGI("clientId %{public}d aborted before message listener registered", clientId);
        CleanupClientConnection(clientId);
        return;
    }
    auto connectFd = -1;
    conn->GetSocketFd(connectFd);
    TCPExtraOptions option;
    if (config->GetTcpExtraOptions(listenFd_, option)) {
        if (option.GetReceiveBufferSize() != 0) {
            recvBufferSize = option.GetReceiveBufferSize();
        }
    }
    auto buffer = std::make_unique<char[]>(recvBufferSize);
    if (buffer == nullptr) {
        NETSTACK_LOGE("Failed to allocate buffer, clientId: %{public}d, fd: %{public}d", clientId, connectFd);
        CleanupClientConnection(clientId);
        return;
    }
    while (isRunning_.load()) {
        if (memset_s(buffer.get(), recvBufferSize, 0, recvBufferSize) != EOK) {
            NETSTACK_LOGE("Buffer clear failed, clientId: %{public}d, fd: %{public}d", clientId, connectFd);
            CleanupClientConnection(clientId);
            break;
        }

        int recvSize = 0;
        if (!PollAndRecvData(connectFd, buffer.get(), recvBufferSize, recvSize)) {
            CleanupClientConnection(clientId);
            break;
        }

        if (recvSize > 0) {
            SocketRemoteInfo remoteInfo;
            remoteInfo.SetSize(static_cast<size_t>(recvSize));
            std::string bufContent(buffer.get(), recvSize);
            conn->CallOnMessageCallback(bufContent, remoteInfo);
        }
    }
}

bool TCPSocketServer::AcceptNewClient(int &connectFD)
{
    sockaddr_in clientAddress = {0};
    socklen_t clientAddrLength = sizeof(clientAddress);
    connectFD = accept(listenFd_, reinterpret_cast<sockaddr *>(&clientAddress), &clientAddrLength);
    if (connectFD >= 0) {
        return true;
    }
    if (errno == EINTR) {
        NETSTACK_LOGI("accept interrupted, continue");
        return true;
    }
    NETSTACK_LOGE("accept fail, listenFd: %{public}d, errno: %{public}d", listenFd_, errno);
    return false;
}

bool TCPSocketServer::InitNewClient(int connectFD, int &clientId)
{
    clientId = GenerateClientId();
    auto conn = AddConnection(clientId);
    if (conn == nullptr) {
        NETSTACK_LOGE("AddConnection failed, fd: %{public}d", connectFD);
        shutdown(connectFD, SHUT_RDWR);
        close(connectFD);
        return false;
    }
    NETSTACK_LOGI("New client accepted, fd: %{public}d, clientId: %{public}d", connectFD, clientId);
    conn->SetSocketFd(connectFD);

    auto config = GetSocketConfig();
    if (config != nullptr) {
        config->AddNewAcceptSocket(listenFd_, connectFD);
        if (TCPExtraOptions option; config->GetTcpExtraOptions(listenFd_, option)) {
            SocketSetTcpExtraOptions(connectFD, option);
        }
    }
    return true;
}

void TCPSocketServer::DoAcceptLoop()
{
    std::vector<std::shared_ptr<std::thread>> clientThreads;
    auto config = GetSocketConfig();
    if (config == nullptr) {
        NETSTACK_LOGE("socketConfig is null");
        return;
    }
    isRunning_ = true;
    isAcceptExit_ = false;
    while (isRunning_.load()) {
        int connectFD = -1;
        if (!AcceptNewClient(connectFD)) {
            config->RemoveServerSocket(listenFd_);
            break;
        }
        if (connectFD < 0) {
            continue;
        }
        int clientId = -1;
        if (!InitNewClient(connectFD, clientId)) {
            continue;
        }
        CallOnConnectCallback(clientId);
        auto self = shared_from_this();
        auto handlerThread = std::make_shared<std::thread>([self, clientId]() {
            self->ClientHandler(clientId);
        });
#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
        pthread_setname_np(TCP_SERVER_HANDLE_CLIENT);
#else
        pthread_setname_np(handlerThread->native_handle(), TCP_SERVER_HANDLE_CLIENT);
#endif
        clientThreads.push_back(handlerThread);
    }
    for (auto handlerThread : clientThreads) {
        handlerThread->join();
    }
    NotifyAcceptThdExit();
}

int TCPSocketServer::Listen(const NetAddress &address)
{
    if (!CommonUtils::HasInternetPermission()) {
        NETSTACK_LOGE("INTERNET permission denied.");
        return PERMISSION_DENIED_CODE;
    }
    if (!ExecCommonUtils::ValidateAddress(address)) {
        return PARAM_ERROR_CODE;
    }
    int sock = ExecCommonUtils::MakeTcpSocket(address.GetSaFamily(), false);
    if (sock <= 0) {
        NETSTACK_LOGE("make tcp socket failed");
        return ConvertSocketServerErrno(errno);
    }
    int reuse = reuseAddr_ ? 1 : 0;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<void *>(&reuse), sizeof(reuse)) < 0) {
        NETSTACK_LOGE("failed to set tcp server listen socket reuseaddr on, sockfd: %{public}d", sock);
    }
    listenFd_ = sock;
    if (!ServerBind(address)) {
        close(listenFd_);
        listenFd_ = -1;
        return ConvertSocketServerErrno(errno);
    }
    if (listen(listenFd_, USER_LIMIT) < 0) {
        NETSTACK_LOGE("tcp server listen error");
        close(listenFd_);
        listenFd_ = -1;
        return ConvertSocketServerErrno(errno);
    }
    if (!socketConfig_) {
        socketConfig_ = std::make_shared<SocketConfig>();
    }
    socketConfig_->AddNewListenSocket(listenFd_);
    isClosed_ = false;
    NETSTACK_LOGI("listen success");
    RunAcceptThread();
    return SOCKET_ERROR_OK;
}

int TCPSocketServer::Close()
{
    if (!CommonUtils::HasInternetPermission()) {
        NETSTACK_LOGE("INTERNET permission denied.");
        return PERMISSION_DENIED_CODE;
    }
    if (isClosed_.load() || listenFd_ < 0) {
        NETSTACK_LOGI("TCPServer socket is invalid or closed");
        isClosed_ = true;
        return SOCKET_ERROR_OK;
    }
    isRunning_ = false;
    if (listenFd_ >= 0) {
        shutdown(listenFd_, SHUT_RDWR);
        close(listenFd_);
        listenFd_ = -1;
        NETSTACK_LOGI("close all listenfd");
        isClosed_ = true;
    }
    {
        std::unique_lock<std::shared_mutex> lock(connMapMutex_);
        for (auto &pair : connectionMap_) {
            pair.second->Close();
        }
    }
    WaitForAcceptThdExit();
    return SOCKET_ERROR_OK;
}

int TCPSocketServer::GetState(SocketStateBase &state)
{
    if (!CommonUtils::HasInternetPermission()) {
        NETSTACK_LOGE("INTERNET permission denied.");
        return PERMISSION_DENIED_CODE;
    }
    if (listenFd_ < 0) {
        NETSTACK_LOGI("TCPServer socket is invalid or closed");
        state.SetIsClose(isClosed_.load());
        return SOCKET_ERROR_OK;
    }

    int opt;
    socklen_t optLen = sizeof(int);
    if (getsockopt(listenFd_, SOL_SOCKET, SO_TYPE, &opt, &optLen) < 0) {
        NETSTACK_LOGI("getsockopt failed, errno=%{public}d", errno);
        state.SetIsClose(true);
        return SOCKET_ERROR_OK;
    }

    struct sockaddr_storage addr{};
    socklen_t addrLen = sizeof(addr);
    if (getsockname(listenFd_, reinterpret_cast<struct sockaddr *>(&addr), &addrLen) < 0) {
        NETSTACK_LOGE("getsockname failed, errno=%{public}d", errno);
        state.SetIsClose(true);
        return ConvertSocketServerErrno(errno);
    }
    if (addr.ss_family == AF_INET) {
        auto *addr4 = reinterpret_cast<sockaddr_in *>(&addr);
        state.SetIsBound(ntohs(addr4->sin_port) != 0);
    } else if (addr.ss_family == AF_INET6) {
        auto *addr6 = reinterpret_cast<sockaddr_in6 *>(&addr);
        state.SetIsBound(ntohs(addr6->sin6_port) != 0);
    }

    if (opt != SOCK_STREAM) {
        return SOCKET_ERROR_OK;
    }
    state.SetIsConnected(!connectionMap_.empty());
    return SOCKET_ERROR_OK;
}

int TCPSocketServer::SetExtraOptions(const TCPExtraOptions &options)
{
    if (!CommonUtils::HasInternetPermission()) {
        NETSTACK_LOGE("INTERNET permission denied.");
        return PERMISSION_DENIED_CODE;
    }
    if (listenFd_ < 0) {
        NETSTACK_LOGI("TCPServer socket is invalid or closed");
        return ConvertSocketServerErrno(ERRNO_BAD_FD);
    }
    if (!SocketSetTcpExtraOptions(listenFd_, options)) {
        NETSTACK_LOGE("SocketSetTcpExtraOptions failed, errno=%{public}d", errno);
        return ConvertSocketServerErrno(errno);
    }
    if (socketConfig_ == nullptr) {
        NETSTACK_LOGE("socketConfig_ is null.");
        return SYSTEM_INTERNAL_ERROR;
    }
    auto clients = socketConfig_->GetClients(listenFd_);
    for (int clientFd : clients) {
        if (!SocketSetTcpExtraOptions(clientFd, options)) {
            NETSTACK_LOGE("SocketSetTcpExtraOptions failed for client, fd=%{public}d, errno=%{public}d",
                          clientFd, errno);
            return ConvertSocketServerErrno(errno);
        }
    }
    socketConfig_->SetTcpExtraOptions(listenFd_, options);
    return SOCKET_ERROR_OK;
}

int TCPSocketServer::GetLocalAddress(NetAddress &address)
{
    if (!CommonUtils::HasInternetPermission()) {
        NETSTACK_LOGE("INTERNET permission denied.");
        return PERMISSION_DENIED_CODE;
    }
    if (listenFd_ < 0) {
        NETSTACK_LOGI("TCPServer socket is invalid or closed");
        return SYSTEM_INTERNAL_ERROR;
    }
    if (!ExecCommonUtils::FillLocalAddress(listenFd_, address)) {
        NETSTACK_LOGE("FillLocalAddress failed, errno=%{public}d", errno);
        return ConvertSocketServerErrno(errno);
    }
    return SOCKET_ERROR_OK;
}

int TCPSocketServer::GetSocketFd(int32_t &fd) const
{
    if (!CommonUtils::HasInternetPermission()) {
        NETSTACK_LOGE("INTERNET permission denied.");
        return PERMISSION_DENIED_CODE;
    }
    fd = listenFd_;
    return SOCKET_ERROR_OK;
}

std::shared_ptr<TCPSocketConnection> TCPSocketServer::GetConnectionByClientID(const int32_t clientId)
{
    std::shared_ptr<TCPSocketConnection> ptrConnection = nullptr;
    std::shared_lock<std::shared_mutex> lock(connMapMutex_);
    auto it = connectionMap_.find(clientId);
    if (it != connectionMap_.end()) {
        ptrConnection = it->second;
    }
    return ptrConnection;
}

std::shared_ptr<TCPSocketConnection> TCPSocketServer::AddConnection(int32_t clientId)
{
    auto conn = std::make_shared<TCPSocketConnection>(clientId);
    std::unique_lock<std::shared_mutex> lock(connMapMutex_);
    connectionMap_[clientId] = conn;
    return conn;
}

void TCPSocketServer::RemoveConnection(int32_t clientId)
{
    std::shared_ptr<TCPSocketConnection> conn;
    {
        std::unique_lock<std::shared_mutex> lock(connMapMutex_);
        auto it = connectionMap_.find(clientId);
        if (it != connectionMap_.end()) {
            conn = it->second;
            connectionMap_.erase(it);
        }
    }
    if (conn != nullptr) {
        conn->Close();
    }
}

void TCPSocketServer::RunAcceptThread()
{
    std::weak_ptr<TCPSocketServer> weak = shared_from_this();
    std::thread acceptThread([weak]() {
        auto server = weak.lock();
        if (server == nullptr) {
            return;
        }
        int listenFd = -1;
        server->GetSocketFd(listenFd);
        if (listenFd < 0) {
            NETSTACK_LOGE("Invalid listen fd");
            return;
        }
        server->DoAcceptLoop();
    });
#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
    pthread_setname_np(TCP_SERVER_ACCEPT_RECV_DATA);
#else
    pthread_setname_np(acceptThread.native_handle(), TCP_SERVER_ACCEPT_RECV_DATA);
#endif
    acceptThread.detach();
}

void TCPSocketServer::CallOnConnectCallback(int32_t clientId)
{
    TCPSocketServerOnConnectCallback callback = nullptr;
    {
        std::lock_guard<std::mutex> lock(callbackMutex_);
        if (onConnectCallback_) {
            callback = onConnectCallback_;
        }
    }
    if (callback) {
        callback(clientId);
    }
}

void TCPSocketServer::CallOnErrorCallback(const int32_t err, const std::string &errMsg)
{
    TCPSocketServerOnErrorCallback callback = nullptr;
    {
        std::lock_guard<std::mutex> lock(callbackMutex_);
        if (onErrorCallback_) {
            callback = onErrorCallback_;
        }
    }
    if (callback) {
        callback(err, errMsg);
    }
}

void TCPSocketServer::OnConnect(const TCPSocketServerOnConnectCallback &connectCallback)
{
    std::lock_guard<std::mutex> lock(callbackMutex_);
    onConnectCallback_ = connectCallback;
}

void TCPSocketServer::OnError(const TCPSocketServerOnErrorCallback &onErrorCallback)
{
    std::lock_guard<std::mutex> lock(callbackMutex_);
    onErrorCallback_ = onErrorCallback;
}

void TCPSocketServer::OffConnect()
{
    std::lock_guard<std::mutex> lock(callbackMutex_);
    onConnectCallback_ = nullptr;
}

void TCPSocketServer::OffError()
{
    std::lock_guard<std::mutex> lock(callbackMutex_);
    onErrorCallback_ = nullptr;
}

void TCPSocketServer::NotifyAcceptThdExit()
{
    std::unique_lock<std::mutex> lock(acceptThdMutex_);
    isAcceptExit_ = true;
    acceptThdCoVar_.notify_one();
}

void TCPSocketServer::WaitForAcceptThdExit()
{
    std::unique_lock<std::mutex> lock(acceptThdMutex_);
    acceptThdCoVar_.wait(lock, [this]() { return isAcceptExit_.load(); });
}

} // namespace Socket
} // namespace NetStack
} // namespace OHOS
