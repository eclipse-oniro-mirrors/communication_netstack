/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "local_socket_exec.h"

#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>

#include "context_key.h"
#include "napi_utils.h"
#include "netstack_log.h"
#include "securec.h"
#include "socket_async_work.h"
#include "socket_module.h"

#ifndef EPOLLIN
#define EPOLLIN 0x001
#endif

namespace {
constexpr int BACKLOG = 32;

constexpr int DEFAULT_BUFFER_SIZE = 8192;

constexpr int MAX_SOCKET_BUFFER_SIZE = 262144;

constexpr int DEFAULT_POLL_TIMEOUT_MS = 500;

constexpr int UNKNOW_ERROR = -1;

constexpr int NO_MEMORY = -2;

constexpr int ERRNO_BAD_FD = 9;

constexpr int DEFAULT_TIMEOUT_MS = 20000;

constexpr int UNIT_CONVERSION_1000 = 1000; // multiples of conversion between units

constexpr char LOCAL_SOCKET_CONNECTION[] = "LocalSocketConnection";

constexpr char LOCAL_SOCKET_SERVER_HANDLE_CLIENT[] = "OS_NET_LSAcc";

constexpr char LOCAL_SOCKET_SERVER_ACCEPT_RECV_DATA[] = "OS_NET_LSAccRD";

constexpr char LOCAL_SOCKET_CONNECT[] = "OS_NET_LSCon";
} // namespace

namespace OHOS::NetStack::Socket::LocalSocketExec {
struct MsgWithLocalRemoteInfo {
    MsgWithLocalRemoteInfo() = delete;
    MsgWithLocalRemoteInfo(void *d, size_t length, const std::string &path) : data(d), len(length)
    {
        remoteInfo.SetAddress(path);
    }
    ~MsgWithLocalRemoteInfo()
    {
        if (data) {
            free(data);
        }
    }
    void *data = nullptr;
    size_t len = 0;
    LocalSocketRemoteInfo remoteInfo;
};

void LocalSocketServerConnectionFinalize(napi_env, void *data, void *)
{
    NETSTACK_LOGI("localsocket connection is finalized");
    EventManager *manager = reinterpret_cast<EventManager *>(data);
    if (manager != nullptr) {
        LocalSocketConnectionData *connectData = reinterpret_cast<LocalSocketConnectionData *>(manager->GetData());
        if (connectData != nullptr) {
            connectData->serverManager_->RemoveEventManager(connectData->clientId_);
            connectData->serverManager_->RemoveAccept(connectData->clientId_);
            delete connectData;
        }
    }
}

napi_value NewInstanceWithConstructor(napi_env env, napi_callback_info info, napi_value jsConstructor,
                                      LocalSocketConnectionData *data)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_new_instance(env, jsConstructor, 0, nullptr, &result));

    EventManager *manager = new (std::nothrow) EventManager();
    if (manager == nullptr) {
        return result;
    }
    manager->SetData(reinterpret_cast<void *>(data));
    EventManager::SetValid(manager);
    data->serverManager_->AddEventManager(data->clientId_, manager);
    napi_wrap(env, result, reinterpret_cast<void *>(manager), LocalSocketServerConnectionFinalize, nullptr, nullptr);
    return result;
}

napi_value ConstructLocalSocketConnection(napi_env env, napi_callback_info info, LocalSocketConnectionData *data)
{
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_NAPI_FUNCTION(SocketModuleExports::LocalSocketConnection::FUNCTION_SEND,
                              SocketModuleExports::LocalSocketConnection::Send),
        DECLARE_NAPI_FUNCTION(SocketModuleExports::LocalSocketConnection::FUNCTION_CLOSE,
                              SocketModuleExports::LocalSocketConnection::Close),
        DECLARE_NAPI_FUNCTION(SocketModuleExports::LocalSocketConnection::FUNCTION_ON,
                              SocketModuleExports::LocalSocketConnection::On),
        DECLARE_NAPI_FUNCTION(SocketModuleExports::LocalSocketConnection::FUNCTION_OFF,
                              SocketModuleExports::LocalSocketConnection::Off),
    };

    auto constructor = [](napi_env env, napi_callback_info info) -> napi_value {
        napi_value thisVal = nullptr;
        NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisVal, nullptr));
        return thisVal;
    };

    napi_property_descriptor descriptors[properties.size()];
    std::copy(properties.begin(), properties.end(), descriptors);

    napi_value jsConstructor = nullptr;
    NAPI_CALL_BASE(env,
                   napi_define_class(env, LOCAL_SOCKET_CONNECTION, NAPI_AUTO_LENGTH, constructor, nullptr,
                                     properties.size(), descriptors, &jsConstructor),
                   NapiUtils::GetUndefined(env));

    if (jsConstructor != nullptr) {
        napi_value result = NewInstanceWithConstructor(env, info, jsConstructor, data);
        NapiUtils::SetInt32Property(env, result, SocketModuleExports::LocalSocketConnection::PROPERTY_CLIENT_ID,
                                    data->clientId_);
        return result;
    }
    return NapiUtils::GetUndefined(env);
}

static napi_value MakeLocalSocketConnectionMessage(napi_env env, void *para)
{
    auto pData = reinterpret_cast<LocalSocketConnectionData *>(para);
    napi_callback_info info = nullptr;
    return ConstructLocalSocketConnection(env, info, pData);
}

static napi_value MakeJsLocalSocketMessageParam(napi_env env, napi_value msgBuffer, MsgWithLocalRemoteInfo *msg)
{
    napi_value obj = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, obj) != napi_object) {
        return nullptr;
    }
    if (NapiUtils::ValueIsArrayBuffer(env, msgBuffer)) {
        NapiUtils::SetNamedProperty(env, obj, KEY_MESSAGE, msgBuffer);
    }
    NapiUtils::SetStringPropertyUtf8(env, obj, KEY_ADDRESS, msg->remoteInfo.GetAddress());
    NapiUtils::SetUint32Property(env, obj, KEY_SIZE, msg->len);
    return obj;
}

static napi_value MakeLocalSocketMessage(napi_env env, void *param)
{
    auto *manager = reinterpret_cast<EventManager *>(param);
    auto *msg = reinterpret_cast<MsgWithLocalRemoteInfo *>(manager->GetQueueData());
    auto deleter = [](const MsgWithLocalRemoteInfo *p) { delete p; };
    std::unique_ptr<MsgWithLocalRemoteInfo, decltype(deleter)> handler(msg, deleter);
    if (msg == nullptr || msg->data == nullptr || msg->len == 0) {
        NETSTACK_LOGE("msg or msg->data or msg->len is invalid");
        return NapiUtils::GetUndefined(env);
    }
    void *dataHandle = nullptr;
    napi_value msgBuffer = NapiUtils::CreateArrayBuffer(env, msg->len, &dataHandle);
    if (dataHandle == nullptr || !NapiUtils::ValueIsArrayBuffer(env, msgBuffer)) {
        return NapiUtils::GetUndefined(env);
    }
    int result = memcpy_s(dataHandle, msg->len, msg->data, msg->len);
    if (result != EOK) {
        NETSTACK_LOGE("memcpy err, res: %{public}d, msg: %{public}s, len: %{public}zu", result,
                      reinterpret_cast<char *>(msg->data), msg->len);
        return NapiUtils::GetUndefined(env);
    }
    return MakeJsLocalSocketMessageParam(env, msgBuffer, msg);
}

template <napi_value (*MakeJsValue)(napi_env, void *)> static void CallbackTemplate(uv_work_t *work, int status)
{
    (void)status;

    auto workWrapper = static_cast<UvWorkWrapper *>(work->data);
    napi_env env = workWrapper->env;
    auto closeScope = [env](napi_handle_scope scope) { NapiUtils::CloseScope(env, scope); };
    std::unique_ptr<napi_handle_scope__, decltype(closeScope)> scope(NapiUtils::OpenScope(env), closeScope);

    napi_value obj = MakeJsValue(env, workWrapper->data);

    std::pair<napi_value, napi_value> arg = {NapiUtils::GetUndefined(workWrapper->env), obj};
    workWrapper->manager->Emit(workWrapper->type, arg);

    delete workWrapper;
    delete work;
}

static bool OnRecvLocalSocketMessage(EventManager *manager, void *data, size_t len, const std::string &path)
{
    if (manager == nullptr || data == nullptr || len == 0) {
        NETSTACK_LOGE("manager or data or len is invalid");
        return false;
    }
    MsgWithLocalRemoteInfo *msg = new (std::nothrow) MsgWithLocalRemoteInfo(data, len, path);
    if (msg == nullptr) {
        NETSTACK_LOGE("MsgWithLocalRemoteInfo construct error");
        return false;
    }
    manager->SetQueueData(reinterpret_cast<void *>(msg));
    manager->EmitByUv(EVENT_MESSAGE, manager, CallbackTemplate<MakeLocalSocketMessage>);
    return true;
}

static bool PollFd(pollfd *fds, nfds_t num, int timeout)
{
    int ret = poll(fds, num, timeout);
    if (ret == -1) {
        NETSTACK_LOGE("poll to send failed, socket is %{public}d, errno is %{public}d", fds->fd, errno);
        return false;
    }
    if (ret == 0) {
        NETSTACK_LOGE("poll to send timeout, socket is %{public}d, timeout is %{public}d", fds->fd, timeout);
        return false;
    }
    return true;
}

static int ConfirmSocketTimeoutMs(int sock, int type, int defaultValue)
{
    timeval timeout;
    socklen_t optlen = sizeof(timeout);
    if (getsockopt(sock, SOL_SOCKET, type, reinterpret_cast<void *>(&timeout), &optlen) < 0) {
        NETSTACK_LOGE("get timeout failed, type: %{public}d, sock: %{public}d, errno: %{public}d", type, sock, errno);
        return defaultValue;
    }
    auto socketTimeoutMs = timeout.tv_sec * UNIT_CONVERSION_1000 + timeout.tv_usec / UNIT_CONVERSION_1000;
    return socketTimeoutMs == 0 ? defaultValue : socketTimeoutMs;
}

static bool PollSendData(int sock, const char *data, size_t size, sockaddr *addr, socklen_t addrLen)
{
    int bufferSize = DEFAULT_BUFFER_SIZE;
    int opt = 0;
    socklen_t optLen = sizeof(opt);
    if (getsockopt(sock, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<void *>(&opt), &optLen) >= 0 && opt > 0) {
        bufferSize = opt;
    }
    int sockType = 0;
    optLen = sizeof(sockType);
    if (getsockopt(sock, SOL_SOCKET, SO_TYPE, reinterpret_cast<void *>(&sockType), &optLen) < 0) {
        NETSTACK_LOGI("get sock opt sock type failed, socket is %{public}d, errno is %{public}d", sock, errno);
        return false;
    }

    auto curPos = data;
    size_t leftSize = size;
    nfds_t num = 1;
    pollfd fds[1] = {{0}};
    fds[0].fd = sock;
    fds[0].events = static_cast<short>(POLLOUT);

    int sendTimeoutMs = ConfirmSocketTimeoutMs(sock, SO_SNDTIMEO, DEFAULT_TIMEOUT_MS);
    while (leftSize > 0) {
        if (!PollFd(fds, num, sendTimeoutMs)) {
            return false;
        }
        size_t sendSize = (sockType == SOCK_STREAM ? leftSize : std::min<size_t>(leftSize, bufferSize));
        auto sendLen = sendto(sock, curPos, sendSize, 0, addr, addrLen);
        if (sendLen < 0) {
            if (errno == EAGAIN) {
                continue;
            }
            NETSTACK_LOGE("send failed, socket is %{public}d, errno is %{public}d", sock, errno);
            return false;
        }
        if (sendLen == 0) {
            break;
        }
        curPos += sendLen;
        leftSize -= sendLen;
    }

    if (leftSize != 0) {
        NETSTACK_LOGE("send not complete, socket is %{public}d, errno is %{public}d", sock, errno);
        return false;
    }
    return true;
}

static bool LocalSocketSendEvent(LocalSocketSendContext *context)
{
    if (context == nullptr) {
        return false;
    }
    if (!PollSendData(context->GetSocketFd(), context->GetOptionsRef().GetBufferRef().c_str(),
                      context->GetOptionsRef().GetBufferRef().size(), nullptr, 0)) {
        NETSTACK_LOGE("send failed, socket is %{public}d, errno is %{public}d", context->GetSocketFd(), errno);
        context->SetErrorCode(errno);
        return false;
    }
    return true;
}

static bool MakeNonBlock(int sock)
{
    int flags = fcntl(sock, F_GETFL, 0);
    while (flags == -1 && errno == EINTR) {
        flags = fcntl(sock, F_GETFL, 0);
    }
    if (flags == -1) {
        NETSTACK_LOGE("make non block failed, socket is %{public}d, errno is %{public}d", sock, errno);
        return false;
    }
    int ret = fcntl(sock, F_SETFL, static_cast<size_t>(flags) | static_cast<size_t>(O_NONBLOCK));
    while (ret == -1 && errno == EINTR) {
        ret = fcntl(sock, F_SETFL, static_cast<size_t>(flags) | static_cast<size_t>(O_NONBLOCK));
    }
    if (ret == -1) {
        NETSTACK_LOGE("make non block failed, socket is %{public}d, errno is %{public}d", sock, errno);
        return false;
    }
    return true;
}

int MakeLocalSocket(int socketType, bool needNonblock)
{
    int sock = socket(AF_UNIX, socketType, 0);
    NETSTACK_LOGI("new local socket is %{public}d", sock);
    if (sock < 0) {
        NETSTACK_LOGE("make local socket failed, errno is %{public}d", errno);
        return -1;
    }
    if (needNonblock && !MakeNonBlock(sock)) {
        close(sock);
        return -1;
    }
    return sock;
}

static napi_value MakeError(napi_env env, void *errCode)
{
    auto code = reinterpret_cast<int32_t *>(errCode);
    auto deleter = [](const int32_t *p) { delete p; };
    std::unique_ptr<int32_t, decltype(deleter)> handler(code, deleter);

    napi_value err = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, err) != napi_object) {
        return NapiUtils::GetUndefined(env);
    }
    NapiUtils::SetInt32Property(env, err, KEY_ERROR_CODE, *code);
    return err;
}

static napi_value MakeClose(napi_env env, void *data)
{
    (void)data;
    napi_value obj = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, obj) != napi_object) {
        return NapiUtils::GetUndefined(env);
    }

    return obj;
}

class LocalSocketMessageCallback {
public:
    LocalSocketMessageCallback() = delete;

    ~LocalSocketMessageCallback() = default;

    explicit LocalSocketMessageCallback(EventManager *manager, const std::string &path = "")
        : manager_(manager), socketPath_(path)
    {
    }

    void OnError(int err) const
    {
        manager_->EmitByUv(EVENT_ERROR, new int(err), CallbackTemplate<MakeError>);
    }

    void OnCloseMessage(EventManager *manager = nullptr) const
    {
        if (manager == nullptr) {
            manager_->EmitByUv(EVENT_CLOSE, nullptr, CallbackTemplate<MakeClose>);
        } else {
            manager->EmitByUv(EVENT_CLOSE, nullptr, CallbackTemplate<MakeClose>);
        }
    }

    bool OnMessage(void *data, size_t dataLen) const
    {
        return OnRecvLocalSocketMessage(manager_, data, dataLen, socketPath_);
    }

    bool OnMessage(EventManager *manager, void *data, size_t len) const
    {
        return OnRecvLocalSocketMessage(manager, data, len, socketPath_);
    }

    void OnLocalSocketConnectionMessage(int clientId, LocalSocketServerManager *serverManager) const
    {
        LocalSocketConnectionData *data = new (std::nothrow) LocalSocketConnectionData(clientId, serverManager);
        if (data != nullptr) {
            manager_->EmitByUv(EVENT_CONNECT, data, CallbackTemplate<MakeLocalSocketConnectionMessage>);
        }
    }
    EventManager *GetEventManager() const
    {
        return manager_;
    }

    EventManager *manager_;

private:
    std::string socketPath_;
};

static bool SetSocketBufferSize(int sockfd, int type, uint32_t size)
{
    if (size > MAX_SOCKET_BUFFER_SIZE) {
        NETSTACK_LOGE("invalid socket buffer size: %{public}u", size);
        return false;
    }
    if (setsockopt(sockfd, SOL_SOCKET, type, reinterpret_cast<void *>(&size), sizeof(size)) < 0) {
        NETSTACK_LOGE("localsocket set sock size failed, sock: %{public}d, type: %{public}d, size: %{public}u, size",
                      sockfd, type, size);
        return false;
    }
    return true;
}

static bool SetLocalSocketOptions(int sockfd, const LocalExtraOptions &options)
{
    if (options.AlreadySetRecvBufSize()) {
        uint32_t recvBufSize = options.GetReceiveBufferSize();
        if (!SetSocketBufferSize(sockfd, SO_RCVBUF, recvBufSize)) {
            return false;
        }
    }
    if (options.AlreadySetSendBufSize()) {
        uint32_t sendBufSize = options.GetSendBufferSize();
        if (!SetSocketBufferSize(sockfd, SO_SNDBUF, sendBufSize)) {
            return false;
        }
    }
    if (options.AlreadySetTimeout()) {
        uint32_t timeMs = options.GetSocketTimeout();
        timeval timeout = {timeMs / UNIT_CONVERSION_1000, (timeMs % UNIT_CONVERSION_1000) * UNIT_CONVERSION_1000};
        if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<void *>(&timeout), sizeof(timeout)) < 0) {
            NETSTACK_LOGE("localsocket setsockopt error, SO_RCVTIMEO, fd: %{public}d", sockfd);
            return false;
        }
        if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<void *>(&timeout), sizeof(timeout)) < 0) {
            NETSTACK_LOGE("localsocket setsockopt error, SO_SNDTIMEO, fd: %{public}d", sockfd);
            return false;
        }
    }
    return true;
}

static void SetSocketDefaultBufferSize(int sockfd, LocalSocketServerManager *mgr)
{
    uint32_t recvSize = DEFAULT_BUFFER_SIZE;
    if (mgr->alreadySetExtraOptions_ && mgr->extraOptions_.AlreadySetRecvBufSize()) {
        recvSize = mgr->extraOptions_.GetReceiveBufferSize();
    }
    SetSocketBufferSize(sockfd, SO_RCVBUF, recvSize);
    uint32_t sendSize = DEFAULT_BUFFER_SIZE;
    if (mgr->alreadySetExtraOptions_ && mgr->extraOptions_.AlreadySetSendBufSize()) {
        sendSize = mgr->extraOptions_.GetSendBufferSize();
    }
    SetSocketBufferSize(sockfd, SO_SNDBUF, sendSize);
}

static int ConfirmBufferSize(int sock)
{
    int bufferSize = DEFAULT_BUFFER_SIZE;
    int opt = 0;
    socklen_t optLen = sizeof(opt);
    if (getsockopt(sock, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<void *>(&opt), &optLen) >= 0 && opt > 0) {
        bufferSize = opt;
    }
    return bufferSize;
}

static inline void RecvInErrorCondition(int reason, int clientId, const LocalSocketMessageCallback &callback,
                                        LocalSocketServerManager *serverManager)
{
    callback.OnError(reason);
    serverManager->RemoveAccept(clientId);
}

static void RecvHandler(int connectFd, const LocalSocketMessageCallback &callback, LocalSocketServerManager *mgr)
{
    int clientId = mgr->GetClientId(connectFd);
    EventManager *eventManager = mgr->GetManager(clientId);
    if (eventManager == nullptr) {
        NETSTACK_LOGI("manager is null");
        callback.OnError(UNKNOW_ERROR);
        return;
    }
    int sockRecvSize = ConfirmBufferSize(connectFd);
    auto buffer = std::make_unique<char[]>(sockRecvSize);
    if (buffer == nullptr) {
        NETSTACK_LOGE("failed to malloc, connectFd: %{public}d, malloc size: %{public}d", connectFd, sockRecvSize);
        RecvInErrorCondition(NO_MEMORY, clientId, callback, mgr);
        return;
    }
    int32_t recvSize = recv(connectFd, buffer.get(), sockRecvSize, 0);
    if (recvSize == 0) {
        NETSTACK_LOGI("session closed, errno:%{public}d,fd:%{public}d,id:%{public}d", errno, connectFd, clientId);
        callback.OnCloseMessage(eventManager);
        mgr->RemoveAccept(clientId);
    } else if (recvSize < 0) {
        if (errno != EINTR && errno != EAGAIN) {
            if (mgr->GetAcceptFd(clientId) < 0) {
                callback.OnCloseMessage(eventManager);
                return;
            }
            NETSTACK_LOGE("recv error, errno:%{public}d,fd:%{public}d,id:%{public}d", errno, connectFd, clientId);
            RecvInErrorCondition(errno, clientId, callback, mgr);
        }
    } else {
        NETSTACK_LOGI("recv, fd:%{public}d, size:%{public}d, buf:%{public}s", connectFd, recvSize, buffer.get());
        void *data = malloc(recvSize);
        if (data == nullptr) {
            RecvInErrorCondition(NO_MEMORY, clientId, callback, mgr);
            return;
        }
        if (memcpy_s(data, recvSize, buffer.get(), recvSize) != EOK ||
            !callback.OnMessage(eventManager, data, recvSize)) {
            free(data);
        }
    }
}

static void AcceptHandler(int fd, LocalSocketServerManager *mgr, const LocalSocketMessageCallback &callback)
{
#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
    pthread_setname_np(LOCAL_SOCKET_SERVER_HANDLE_CLIENT);
#else
    pthread_setname_np(pthread_self(), LOCAL_SOCKET_SERVER_HANDLE_CLIENT);
#endif
    if (fd < 0) {
        NETSTACK_LOGE("accept a invalid fd");
        return;
    }
    int clientId = mgr->AddAccept(fd);
    if (clientId < 0) {
        NETSTACK_LOGE("add connect fd err, fd:%{public}d", fd);
        callback.OnError(UNKNOW_ERROR);
        close(fd);
        return;
    }
    callback.OnLocalSocketConnectionMessage(clientId, mgr);
    mgr->WaitRegisteringEvent(clientId);
    if (mgr->RegisterEpollEvent(fd, EPOLLIN) == -1) {
        NETSTACK_LOGE("new connection register err, fd:%{public}d, errno:%{public}d", fd, errno);
        callback.OnError(errno);
        close(fd);
        return;
    }
    SetSocketDefaultBufferSize(fd, mgr);
    if (mgr->alreadySetExtraOptions_) {
        SetLocalSocketOptions(fd, mgr->extraOptions_);
    }
}

static void LocalSocketServerAccept(LocalSocketServerManager *mgr, const LocalSocketMessageCallback &callback)
{
#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
    pthread_setname_np(LOCAL_SOCKET_SERVER_ACCEPT_RECV_DATA);
#else
    pthread_setname_np(pthread_self(), LOCAL_SOCKET_SERVER_ACCEPT_RECV_DATA);

    struct sockaddr_un clientAddress;
    socklen_t clientAddrLength = sizeof(clientAddress);
    if (mgr->RegisterEpollEvent(mgr->sockfd_, EPOLLIN) == -1) {
        NETSTACK_LOGE("register listen fd err, fd:%{public}d, errno:%{public}d", mgr->sockfd_, errno);
        callback.OnError(errno);
        return;
    }
    mgr->SetServerDestructStatus(false);
    while (true) {
        int eventNum = mgr->EpollWait();
        if (eventNum == -1) {
            if (errno == EINTR) {
                continue;
            }
            NETSTACK_LOGE("epoll wait err, fd:%{public}d, errno:%{public}d", mgr->sockfd_, errno);
            callback.OnError(errno);
            break;
        }
        if (mgr->GetServerDestructStatus()) {
            NETSTACK_LOGI("server object destruct, exit the loop");
            break;
        }
        for (int i = 0; i < eventNum; ++i) {
            if ((mgr->events_[i].data.fd == mgr->sockfd_) && (mgr->events_[i].events & EPOLLIN)) {
                int connectFd = accept(mgr->sockfd_, reinterpret_cast<sockaddr *>(&clientAddress), &clientAddrLength);
                std::thread th(AcceptHandler, connectFd, mgr, callback);
                th.detach();
            } else if ((mgr->events_[i].data.fd != mgr->sockfd_) && (mgr->events_[i].events & EPOLLIN)) {
                RecvHandler(mgr->events_[i].data.fd, callback, mgr);
            }
        }
    }
    mgr->NotifyLoopFinished();
#endif
}

static int UpdateRecvBuffer(int sock, int &bufferSize, std::unique_ptr<char[]> &buf,
                            const LocalSocketMessageCallback &callback)
{
    if (int currentRecvBufferSize = ConfirmBufferSize(sock); currentRecvBufferSize != bufferSize) {
        bufferSize = currentRecvBufferSize;
        if (bufferSize <= 0 || bufferSize > MAX_SOCKET_BUFFER_SIZE) {
            NETSTACK_LOGE("buffer size is out of range, size: %{public}d", bufferSize);
            bufferSize = DEFAULT_BUFFER_SIZE;
        }
        buf.reset(new (std::nothrow) char[bufferSize]);
        if (buf == nullptr) {
            callback.OnError(NO_MEMORY);
            return NO_MEMORY;
        }
    }
    return 0;
}

static void PollRecvData(int sock, const LocalSocketMessageCallback &callback)
{
    int bufferSize = ConfirmBufferSize(sock);
    auto buf = std::make_unique<char[]>(bufferSize);
    if (buf == nullptr) {
        callback.OnError(NO_MEMORY);
        return;
    }
    nfds_t num = 1;
    pollfd fds[1] = {{.fd = sock, .events = POLLIN}};
    int recvTimeoutMs = ConfirmSocketTimeoutMs(sock, SO_RCVTIMEO, DEFAULT_POLL_TIMEOUT_MS);
    while (true) {
        int ret = poll(fds, num, recvTimeoutMs);
        if (ret < 0) {
            NETSTACK_LOGE("poll to recv failed, socket is %{public}d, errno is %{public}d", sock, errno);
            callback.OnError(errno);
            return;
        } else if (ret == 0) {
            continue;
        }
        if (memset_s(buf.get(), bufferSize, 0, bufferSize) != EOK) {
            NETSTACK_LOGE("memset_s failed, client fd: %{public}d, bufferSize: %{public}d", sock, bufferSize);
            continue;
        }
        if (UpdateRecvBuffer(sock, bufferSize, buf, callback) < 0) {
            return;
        }
        auto recvLen = recv(sock, buf.get(), bufferSize, 0);
        if (recvLen < 0) {
            if (errno == EAGAIN || errno == EINTR) {
                continue;
            }
            NETSTACK_LOGE("recv failed, socket is %{public}d, errno is %{public}d", sock, errno);
            if (auto mgr = reinterpret_cast<LocalSocketManager *>(callback.manager_->GetData()); mgr != nullptr) {
                mgr->GetSocketCloseStatus() ? callback.OnCloseMessage() : callback.OnError(errno);
            }
            return;
        } else if (recvLen == 0) {
            callback.OnCloseMessage();
            break;
        }
        void *data = malloc(recvLen);
        if (data == nullptr) {
            callback.OnError(NO_MEMORY);
            return;
        }
        if (memcpy_s(data, recvLen, buf.get(), recvLen) != EOK || !callback.OnMessage(data, recvLen)) {
            free(data);
        }
    }
}

bool ExecLocalSocketBind(LocalSocketBindContext *context)
{
    if (context == nullptr) {
        return false;
    }
    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    if (strcpy_s(addr.sun_path, sizeof(addr.sun_path) - 1, context->GetSocketPath().c_str()) != 0) {
        NETSTACK_LOGE("failed to copy socket path, sockfd: %{public}d", context->GetSocketFd());
        context->SetErrorCode(UNKNOW_ERROR);
        return false;
    }
    if (bind(context->GetSocketFd(), reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) == -1) {
        NETSTACK_LOGE("failed to bind local socket, errno: %{public}d", errno);
        context->SetErrorCode(errno);
        return false;
    }
    return true;
}

static bool NonBlockConnect(int sock, sockaddr *addr, socklen_t addrLen, uint32_t timeoutMSec)
{
    if (connect(sock, addr, addrLen) == -1) {
        pollfd fds[1] = {{.fd = sock, .events = POLLOUT}};
        if (errno != EINPROGRESS) {
            NETSTACK_LOGE("connect error, fd: %{public}d, errno: %{public}d", sock, errno);
            return false;
        }
        int pollResult = poll(fds, 1, timeoutMSec);
        if (pollResult == 0) {
            NETSTACK_LOGE("connection timeout, fd: %{public}d, timeout: %{public}d", sock, timeoutMSec);
            return false;
        } else if (pollResult == -1) {
            NETSTACK_LOGE("poll connect error, fd: %{public}d, errno: %{public}d", sock, errno);
            return false;
        }
        int error = 0;
        socklen_t errorLen = sizeof(error);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &errorLen) < 0 || error != 0) {
            NETSTACK_LOGE("failed to get socket so_error, fd: %{public}d, errno: %{public}d", sock, errno);
            return false;
        }
    }
    return true;
}

bool ExecLocalSocketConnect(LocalSocketConnectContext *context)
{
    if (context == nullptr) {
        return false;
    }
    struct sockaddr_un addr;
    memset_s(&addr, sizeof(addr), 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    int sockfd = context->GetSocketFd();
    SetSocketBufferSize(sockfd, SO_RCVBUF, DEFAULT_BUFFER_SIZE);
    if (strcpy_s(addr.sun_path, sizeof(addr.sun_path) - 1, context->GetSocketPath().c_str()) != 0) {
        NETSTACK_LOGE("failed to copy local socket path, sockfd: %{public}d", sockfd);
        context->SetErrorCode(UNKNOW_ERROR);
        return false;
    }
    NETSTACK_LOGI("local socket client fd: %{public}d, path: %{public}s", context->GetSocketFd(), addr.sun_path);
    if (!NonBlockConnect(sockfd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr), context->GetTimeoutMs())) {
        NETSTACK_LOGE("failed to connect local socket, errno: %{public}d, %{public}s", errno, strerror(errno));
        context->SetErrorCode(errno);
        return false;
    }
    if (auto pMgr = reinterpret_cast<LocalSocketManager *>(context->GetManager()->GetData()); pMgr != nullptr) {
        pMgr->isConnected_ = true;
    }
    std::thread serviceThread(PollRecvData, sockfd, LocalSocketMessageCallback(context->GetManager(), context->
                              GetSocketPath()));
#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
    pthread_setname_np(LOCAL_SOCKET_CONNECT);
#else
    pthread_setname_np(serviceThread.native_handle(), LOCAL_SOCKET_CONNECT);
#endif
    serviceThread.detach();
    return true;
}

bool ExecLocalSocketSend(LocalSocketSendContext *context)
{
    if (context == nullptr) {
        return false;
    }
#ifdef FUZZ_TEST
    return true;
#endif
    if (context->GetSocketFd() < 0) {
        context->SetErrorCode(EBADF);
    }
    bool result = LocalSocketSendEvent(context);
    NapiUtils::CreateUvQueueWorkEnhanced(context->GetEnv(), context, SocketAsyncWork::LocalSocketSendCallback);
    return result;
}

bool ExecLocalSocketClose(LocalSocketCloseContext *context)
{
    if (context == nullptr) {
        return false;
    }
    if (close(context->GetSocketFd()) < 0) {
        NETSTACK_LOGE("failed to closed localsock, fd: %{public}d, errno: %{public}d", context->GetSocketFd(), errno);
        context->SetErrorCode(errno);
        return false;
    }
    context->SetSocketFd(-1);
    if (auto pMgr = reinterpret_cast<LocalSocketManager *>(context->GetManager()->GetData()); pMgr != nullptr) {
        pMgr->isConnected_ = false;
        pMgr->SetSocketCloseStatus(true);
    }
    return true;
}

bool ExecLocalSocketGetState(LocalSocketGetStateContext *context)
{
    if (context == nullptr) {
        return false;
    }
    struct sockaddr_un unAddr = {0};
    socklen_t len = sizeof(unAddr);
    SocketStateBase &state = context->GetStateRef();
    if (getsockname(context->GetSocketFd(), reinterpret_cast<struct sockaddr *>(&unAddr), &len) < 0) {
        NETSTACK_LOGI("localsocket do not bind or socket has closed");
        state.SetIsBound(false);
    } else {
        state.SetIsBound(strlen(unAddr.sun_path) > 0);
    }
    if (auto pMgr = reinterpret_cast<LocalSocketManager *>(context->GetManager()->GetData()); pMgr != nullptr) {
        state.SetIsConnected(pMgr->isConnected_);
    }
    return true;
}

bool ExecLocalSocketGetSocketFd(LocalSocketGetSocketFdContext *context)
{
    if (context == nullptr) {
        return false;
    }
    return true;
}

bool ExecLocalSocketSetExtraOptions(LocalSocketSetExtraOptionsContext *context)
{
    if (context == nullptr) {
        return false;
    }
    if (SetLocalSocketOptions(context->GetSocketFd(), context->GetOptionsRef())) {
        return true;
    }
    context->SetErrorCode(errno);
    return false;
}

static bool GetLocalSocketOptions(int sockfd, LocalExtraOptions &optionsRef)
{
    int result = 0;
    socklen_t len = sizeof(result);
    if (getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &result, &len) == -1) {
        NETSTACK_LOGE("getsockopt error, SO_RCVBUF");
        return false;
    }
    optionsRef.SetReceiveBufferSize(result);
    if (getsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &result, &len) == -1) {
        NETSTACK_LOGE("getsockopt error, SO_SNDBUF");
        return false;
    }
    optionsRef.SetSendBufferSize(result);
    timeval timeout;
    socklen_t timeLen = sizeof(timeout);
    if (getsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, &timeLen) == -1) {
        NETSTACK_LOGE("getsockopt error, SO_SNDTIMEO");
        return false;
    }
    optionsRef.SetSocketTimeout(timeout.tv_sec * UNIT_CONVERSION_1000 + timeout.tv_usec / UNIT_CONVERSION_1000);
    return true;
}

bool ExecLocalSocketGetExtraOptions(LocalSocketGetExtraOptionsContext *context)
{
    if (context == nullptr) {
        return false;
    }
    LocalExtraOptions &optionsRef = context->GetOptionsRef();
    if (!GetLocalSocketOptions(context->GetSocketFd(), optionsRef)) {
        context->SetErrorCode(errno);
        return false;
    }
    return true;
}

static bool LocalSocketServerBind(LocalSocketServerListenContext *context)
{
    unlink(context->GetSocketPath().c_str());
    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    if (int err = strcpy_s(addr.sun_path, sizeof(addr.sun_path) - 1, context->GetSocketPath().c_str()); err != 0) {
        NETSTACK_LOGE("failed to copy socket path");
        context->SetErrorCode(err);
        return false;
    }
    if (bind(context->GetSocketFd(), reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) == -1) {
        NETSTACK_LOGE("failed to bind local socket, fd: %{public}d, errno: %{public}d", context->GetSocketFd(), errno);
        context->SetErrorCode(errno);
        return false;
    }
    NETSTACK_LOGI("local socket server bind success: %{public}s", addr.sun_path);
    return true;
}

bool ExecLocalSocketServerListen(LocalSocketServerListenContext *context)
{
    if (context == nullptr) {
        return false;
    }
    if (!LocalSocketServerBind(context)) {
        return false;
    }
    if (listen(context->GetSocketFd(), BACKLOG) < 0) {
        NETSTACK_LOGE("local socket server listen error, fd: %{public}d", context->GetSocketFd());
        context->SetErrorCode(errno);
        return false;
    }
    NETSTACK_LOGI("local socket server listen success");
    LocalSocketServerManager *mgr = reinterpret_cast<LocalSocketServerManager *>(context->GetManager()->GetData());
    if (mgr == nullptr) {
        NETSTACK_LOGE("LocalSocketServerManager reinterpret cast failed");
        context->SetErrorCode(UNKNOW_ERROR);
        return false;
    }
    std::thread serviceThread(LocalSocketServerAccept, mgr, LocalSocketMessageCallback(context->GetManager(),
                                                                                       context->GetSocketPath()));
    serviceThread.detach();
    return true;
}

bool ExecLocalSocketServerGetState(LocalSocketServerGetStateContext *context)
{
    if (context == nullptr) {
        return false;
    }
    struct sockaddr_un unAddr = {0};
    socklen_t len = sizeof(unAddr);
    SocketStateBase &state = context->GetStateRef();
    if (getsockname(context->GetSocketFd(), reinterpret_cast<struct sockaddr *>(&unAddr), &len) == 0) {
        state.SetIsBound(true);
    }
    auto pMgr = reinterpret_cast<LocalSocketServerManager *>(context->GetManager()->GetData());
    if (pMgr != nullptr) {
        state.SetIsConnected(pMgr->GetClientCounts() > 0);
    }
    return true;
}

bool ExecLocalSocketServerSetExtraOptions(LocalSocketServerSetExtraOptionsContext *context)
{
    if (context == nullptr) {
        return false;
    }
    auto serverManager = reinterpret_cast<LocalSocketServerManager *>(context->GetManager()->GetData());
    if (serverManager == nullptr) {
        return false;
    }
    for (const auto &[id, fd] : serverManager->acceptFds_) {
        if (!SetLocalSocketOptions(fd, context->GetOptionsRef())) {
            context->SetErrorCode(errno);
            return false;
        }
    }
    serverManager->extraOptions_ = context->GetOptionsRef();
    serverManager->alreadySetExtraOptions_ = true;
    return true;
}

bool ExecLocalSocketServerGetExtraOptions(LocalSocketServerGetExtraOptionsContext *context)
{
    if (context == nullptr) {
        return false;
    }
    if (auto pMgr = reinterpret_cast<LocalSocketServerManager *>(context->GetManager()->GetData()); pMgr != nullptr) {
        LocalExtraOptions &options = context->GetOptionsRef();
        if (pMgr->alreadySetExtraOptions_) {
            options = pMgr->extraOptions_;
        } else {
            if (!GetLocalSocketOptions(context->GetSocketFd(), options)) {
                context->SetErrorCode(errno);
                return false;
            }
            options.SetReceiveBufferSize(DEFAULT_BUFFER_SIZE);
            options.SetSendBufferSize(DEFAULT_BUFFER_SIZE);
        }
        return true;
    }
    context->SetErrorCode(UNKNOW_ERROR);
    return false;
}

bool ExecLocalSocketConnectionSend(LocalSocketServerSendContext *context)
{
    if (context == nullptr) {
        return false;
    }
    int clientId = context->GetClientId();
    auto data = reinterpret_cast<LocalSocketConnectionData *>(context->GetManager()->GetData());
    if (data == nullptr || data->serverManager_ == nullptr) {
        NETSTACK_LOGE("localsocket connection send, data or manager is nullptr, id: %{public}d", clientId);
        return false;
    }
    int acceptFd = data->serverManager_->GetAcceptFd(clientId);
    if (acceptFd <= 0) {
        NETSTACK_LOGE("accept fd is invalid, id: %{public}d, fd: %{public}d", clientId, acceptFd);
        context->SetErrorCode(ERRNO_BAD_FD);
        return false;
    }

    if (!PollSendData(acceptFd, context->GetOptionsRef().GetBufferRef().c_str(),
                      context->GetOptionsRef().GetBufferRef().size(), nullptr, 0)) {
        NETSTACK_LOGE("localsocket connection send failed, fd: %{public}d, errno: %{public}d", acceptFd, errno);
        context->SetErrorCode(errno);
        return false;
    }
    return true;
}

bool ExecLocalSocketConnectionClose(LocalSocketServerCloseContext *context)
{
    if (context == nullptr) {
        return false;
    }
    if (auto data = reinterpret_cast<LocalSocketConnectionData *>(context->GetManager()->GetData()); data != nullptr) {
        if (data->serverManager_ != nullptr) {
            if (data->serverManager_->GetAcceptFd(context->GetClientId()) > 0) {
                return true;
            }
        }
    }
    NETSTACK_LOGE("invalid serverManager or socket has closed");
    context->SetErrorCode(EBADF);
    return false;
}

napi_value LocalSocketBindCallback(LocalSocketBindContext *context)
{
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value LocalSocketConnectCallback(LocalSocketConnectContext *context)
{
    context->Emit(EVENT_CONNECT, std::make_pair(NapiUtils::GetUndefined(context->GetEnv()),
                                                NapiUtils::GetUndefined(context->GetEnv())));
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value LocalSocketSendCallback(LocalSocketSendContext *context)
{
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value LocalSocketCloseCallback(LocalSocketCloseContext *context)
{
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value LocalSocketGetStateCallback(LocalSocketGetStateContext *context)
{
    napi_value obj = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), obj) != napi_object) {
        return NapiUtils::GetUndefined(context->GetEnv());
    }
    NapiUtils::SetBooleanProperty(context->GetEnv(), obj, KEY_IS_BOUND, context->GetStateRef().IsBound());
    NapiUtils::SetBooleanProperty(context->GetEnv(), obj, KEY_IS_CLOSE, context->GetStateRef().IsClose());
    NapiUtils::SetBooleanProperty(context->GetEnv(), obj, KEY_IS_CONNECTED, context->GetStateRef().IsConnected());
    return obj;
}

napi_value LocalSocketGetSocketFdCallback(LocalSocketGetSocketFdContext *context)
{
    int sockFd = context->GetSocketFd();
    if (sockFd <= 0) {
        return NapiUtils::GetUndefined(context->GetEnv());
    }
    return NapiUtils::CreateUint32(context->GetEnv(), sockFd);
}

napi_value LocalSocketSetExtraOptionsCallback(LocalSocketSetExtraOptionsContext *context)
{
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value LocalSocketGetExtraOptionsCallback(LocalSocketGetExtraOptionsContext *context)
{
    napi_value obj = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), obj) != napi_object) {
        return NapiUtils::GetUndefined(context->GetEnv());
    }
    NapiUtils::SetBooleanProperty(context->GetEnv(), obj, KEY_REUSE_ADDRESS, false);
    NapiUtils::SetInt32Property(context->GetEnv(), obj, KEY_RECEIVE_BUFFER_SIZE,
                                context->GetOptionsRef().GetReceiveBufferSize());
    NapiUtils::SetInt32Property(context->GetEnv(), obj, KEY_SEND_BUFFER_SIZE,
                                context->GetOptionsRef().GetSendBufferSize());
    NapiUtils::SetInt32Property(context->GetEnv(), obj, KEY_TIMEOUT, context->GetOptionsRef().GetSocketTimeout());
    return obj;
}

napi_value LocalSocketServerListenCallback(LocalSocketServerListenContext *context)
{
    context->Emit(EVENT_LISTENING, std::make_pair(NapiUtils::GetUndefined(context->GetEnv()),
                                                  NapiUtils::GetUndefined(context->GetEnv())));
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value LocalSocketServerGetStateCallback(LocalSocketServerGetStateContext *context)
{
    napi_value obj = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), obj) != napi_object) {
        return NapiUtils::GetUndefined(context->GetEnv());
    }
    NapiUtils::SetBooleanProperty(context->GetEnv(), obj, KEY_IS_BOUND, context->GetStateRef().IsBound());
    NapiUtils::SetBooleanProperty(context->GetEnv(), obj, KEY_IS_CLOSE, context->GetStateRef().IsClose());
    NapiUtils::SetBooleanProperty(context->GetEnv(), obj, KEY_IS_CONNECTED, context->GetStateRef().IsConnected());
    return obj;
}

napi_value LocalSocketServerSetExtraOptionsCallback(LocalSocketServerSetExtraOptionsContext *context)
{
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value LocalSocketServerGetExtraOptionsCallback(LocalSocketServerGetExtraOptionsContext *context)
{
    napi_value obj = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), obj) != napi_object) {
        return NapiUtils::GetUndefined(context->GetEnv());
    }
    NapiUtils::SetBooleanProperty(context->GetEnv(), obj, KEY_REUSE_ADDRESS, false);
    NapiUtils::SetInt32Property(context->GetEnv(), obj, KEY_RECEIVE_BUFFER_SIZE,
                                context->GetOptionsRef().GetReceiveBufferSize());
    NapiUtils::SetInt32Property(context->GetEnv(), obj, KEY_SEND_BUFFER_SIZE,
                                context->GetOptionsRef().GetSendBufferSize());
    NapiUtils::SetInt32Property(context->GetEnv(), obj, KEY_TIMEOUT, context->GetOptionsRef().GetSocketTimeout());
    return obj;
}

napi_value LocalSocketConnectionSendCallback(LocalSocketServerSendContext *context)
{
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value LocalSocketConnectionCloseCallback(LocalSocketServerCloseContext *context)
{
    auto data = reinterpret_cast<LocalSocketConnectionData *>(context->GetManager()->GetData());
    if (data == nullptr || data->serverManager_ == nullptr) {
        NETSTACK_LOGE("connection close callback reinterpret cast failed");
        return NapiUtils::GetUndefined(context->GetEnv());
    }
    int acceptFd = data->serverManager_->GetAcceptFd(context->GetClientId());
    if (acceptFd <= 0) {
        NETSTACK_LOGE("socket invalid, fd: %{public}d", acceptFd);
        return NapiUtils::GetUndefined(context->GetEnv());
    }

    if (shutdown(acceptFd, SHUT_RDWR) != 0) {
        NETSTACK_LOGE("socket shutdown failed, socket is %{public}d, errno is %{public}d", acceptFd, errno);
    }
    int ret = close(acceptFd);
    if (ret < 0) {
        NETSTACK_LOGE("sock closed failed, socket is %{public}d, errno is %{public}d", acceptFd, errno);
    } else {
        NETSTACK_LOGI("sock %{public}d closed success", acceptFd);
        data->serverManager_->RemoveAccept(context->GetClientId());
    }

    return NapiUtils::GetUndefined(context->GetEnv());
}
} // namespace OHOS::NetStack::Socket::LocalSocketExec
