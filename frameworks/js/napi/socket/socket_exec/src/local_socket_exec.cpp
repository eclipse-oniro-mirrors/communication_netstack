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

namespace {
constexpr int BACKLOG = 32;

constexpr int DEFAULT_BUFFER_SIZE = 8192;

constexpr int DEFAULT_POLL_TIMEOUT_MS = 500;

constexpr int UNKNOW_ERROR = -1;

constexpr int NO_MEMORY = -2;

constexpr int MAX_CLIENTS = 1024;

constexpr int ERRNO_BAD_FD = 9;

constexpr char LOCAL_SOCKET_CONNECTION[] = "LocalSocketConnection";

constexpr char LOCAL_SOCKET_SERVER_HANDLE_CLIENT[] = "LocalSocketServerHandleClient";

constexpr char LOCAL_SOCKET_SERVER_ACCEPT_RECV_DATA[] = "LocalSocketServerAcceptRecvData";
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
        LocalSocketConnectionData *data = reinterpret_cast<LocalSocketConnectionData *>(manager->GetData());
        if (data != nullptr) {
            data->serverManager_->RemoveEventManager(data->clientId_);
            data->serverManager_->RemoveAccept(data->clientId_);
            delete data;
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
    napi_value jsRemoteInfo = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, jsRemoteInfo) != napi_object) {
        return nullptr;
    }
    NapiUtils::SetStringPropertyUtf8(env, jsRemoteInfo, KEY_ADDRESS, msg->remoteInfo.GetAddress());
    NapiUtils::SetUint32Property(env, jsRemoteInfo, KEY_SIZE, msg->len);
    NapiUtils::SetNamedProperty(env, obj, KEY_REMOTE_INFO, jsRemoteInfo);
    return obj;
}

static napi_value MakeLocalSocketMessage(napi_env env, void *param)
{
    EventManager *manager = reinterpret_cast<EventManager *>(param);
    MsgWithLocalRemoteInfo *msg = reinterpret_cast<MsgWithLocalRemoteInfo *>(manager->GetQueueData());
    manager->PopQueueData();
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
        NETSTACK_LOGE("memcpy err, res: %{public}d, msg: %{public}s, len: %{public}u", result,
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
        NETSTACK_LOGE("poll to send timeout, socket is %{public}d, errno is %{public}d", fds->fd, errno);
        return false;
    }
    return true;
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
    auto leftSize = size;
    nfds_t num = 1;
    pollfd fds[1] = {{0}};
    fds[0].fd = sock;
    fds[0].events = 0;
    fds[0].events |= POLLOUT;

    while (leftSize > 0) {
        if (!PollFd(fds, num, DEFAULT_BUFFER_SIZE)) {
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
    int ret = fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    while (ret == -1 && errno == EINTR) {
        ret = fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    }
    if (ret == -1) {
        NETSTACK_LOGE("make non block failed, socket is %{public}d, errno is %{public}d", sock, errno);
        return false;
    }
    return true;
}

int MakeLocalSocket(int socketType)
{
    int sock = socket(AF_UNIX, socketType, 0);
    NETSTACK_LOGI("new local socket is %{public}d", sock);
    if (sock < 0) {
        NETSTACK_LOGE("make local socket failed, errno is %{public}d", errno);
        return -1;
    }
    if (!MakeNonBlock(sock)) {
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

    void OnCloseMessage(EventManager *manager) const
    {
        manager->EmitByUv(EVENT_CLOSE, nullptr, CallbackTemplate<MakeClose>);
    }

    bool OnMessage(void *data, size_t dataLen, [[maybe_unused]] sockaddr *addr) const
    {
        return OnRecvLocalSocketMessage(manager_, data, dataLen, socketPath_);
    }

    bool OnMessage(EventManager *manager, void *data, size_t len, const std::string &path) const
    {
        return OnRecvLocalSocketMessage(manager, data, len, path);
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

protected:
    EventManager *manager_;

private:
    std::string socketPath_;
};

static bool SetLocalSocketOptions(int sockfd, const LocalExtraOptions &options)
{
    if (options.AlreadySetRecvBufSize()) {
        uint32_t recvBufSize = options.GetReceiveBufferSize();
        if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<void *>(&recvBufSize), sizeof(recvBufSize)) <
            0) {
            NETSTACK_LOGE("localsocket setsockopt error, SO_RCVBUF, fd: %{public}d", sockfd);
            return false;
        }
    }
    if (options.AlreadySetSendBufSize()) {
        uint32_t sendBufSize = options.GetSendBufferSize();
        if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<void *>(&sendBufSize), sizeof(sendBufSize)) <
            0) {
            NETSTACK_LOGE("localsocket setsockopt error, SO_SNDBUF, fd: %{public}d", sockfd);
            return false;
        }
    }
    if (options.AlreadySetTimeout()) {
        uint32_t timeout = options.GetSocketTimeout();
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

static void LocalSocketServerRecvHandler(int connectFd, LocalSocketServerManager *serverManager,
                                         const LocalSocketMessageCallback &callback, const std::string &path)
{
    int clientId = serverManager->AddAccept(connectFd);
    if (serverManager->alreadySetExtraOptions_) {
        SetLocalSocketOptions(connectFd, serverManager->extraOptions_);
    }
    NETSTACK_LOGI("local socket server accept new, fd: %{public}d, id: %{public}d", connectFd, clientId);
    callback.OnLocalSocketConnectionMessage(clientId, serverManager);
    EventManager *eventManager = serverManager->WaitForManager(clientId);
    char buffer[DEFAULT_BUFFER_SIZE];
    while (true) {
        if (memset_s(buffer, sizeof(buffer), 0, sizeof(buffer)) != EOK) {
            NETSTACK_LOGE("memset_s failed, connectFd: %{public}d, clientId: %{public}d", connectFd, clientId);
            break;
        }
        int32_t recvSize = recv(connectFd, buffer, sizeof(buffer), 0);
        if (recvSize <= 0) {
            if (errno != EAGAIN) {
                NETSTACK_LOGE("conntion close, recvSize:%{public}d, errno:%{public}d, fd:%{public}d, id:%{public}d",
                    recvSize, errno, connectFd, clientId);
                callback.OnCloseMessage(eventManager);
                serverManager->RemoveAccept(clientId);
                break;
            }
        } else {
            NETSTACK_LOGD("localsocket recv: fd: %{public}d, size: %{public}d, buf: %{public}s", connectFd, recvSize,
                          buffer);
            void *data = malloc(recvSize);
            if (data == nullptr) {
                callback.OnError(NO_MEMORY);
                break;
            }
            if (memcpy_s(data, recvSize, buffer, recvSize) != EOK ||
                !callback.OnMessage(eventManager, data, recvSize, path)) {
                free(data);
            }
        }
    }
}

static void LocalSocketServerAccept(LocalSocketServerManager *mgr, const LocalSocketMessageCallback &callback,
                                    const std::string &path)
{
    while (true) {
        struct sockaddr_un clientAddress;
        socklen_t clientAddrLength = sizeof(clientAddress);
        int connectFd = accept(mgr->sockfd_, reinterpret_cast<sockaddr *>(&clientAddress), &clientAddrLength);
        if (connectFd < 0) {
            continue;
        }
        if (mgr->GetClientCounts() >= MAX_CLIENTS) {
            NETSTACK_LOGE("local socket server max number of clients reached, sockfd: %{public}d", mgr->sockfd_);
            close(connectFd);
            continue;
        }

        std::thread handlerThread(LocalSocketServerRecvHandler, connectFd, mgr, std::ref(callback), std::ref(path));
#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
        pthread_setname_np(LOCAL_SOCKET_SERVER_HANDLE_CLIENT);
#else
        pthread_setname_np(handlerThread.native_handle(), LOCAL_SOCKET_SERVER_HANDLE_CLIENT);
#endif
        handlerThread.detach();
    }
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

static void PollRecvData(int sock, sockaddr *addr, socklen_t addrLen, const LocalSocketMessageCallback &callback)
{
    int bufferSize = ConfirmBufferSize(sock);
    auto deleter = [](char *s) { free(reinterpret_cast<void *>(s)); };
    std::unique_ptr<char, decltype(deleter)> buf(reinterpret_cast<char *>(malloc(bufferSize)), deleter);
    if (buf == nullptr) {
        callback.OnError(NO_MEMORY);
        return;
    }
    auto addrDeleter = [](sockaddr *a) { free(reinterpret_cast<void *>(a)); };
    std::unique_ptr<sockaddr, decltype(addrDeleter)> pAddr(addr, addrDeleter);
    nfds_t num = 1;
    pollfd fds[1] = {{.fd = sock, .events = 0}};
    fds[0].events |= POLLIN;
    while (true) {
        int ret = poll(fds, num, DEFAULT_POLL_TIMEOUT_MS);
        if (ret < 0) {
            NETSTACK_LOGE("poll to recv failed, socket is %{public}d, errno is %{public}d", sock, errno);
            callback.OnError(errno);
            return;
        }
        if (ret == 0) {
            continue;
        }
        if (static_cast<int>(reinterpret_cast<uint64_t>(callback.GetEventManager()->GetData())) == 0) {
            return;
        }
        (void)memset_s(buf.get(), bufferSize, 0, bufferSize);
        socklen_t tempAddrLen = addrLen;
        auto recvLen = recvfrom(sock, buf.get(), bufferSize, 0, addr, &tempAddrLen);
        if (recvLen < 0) {
            if (errno == EAGAIN) {
                continue;
            }
            NETSTACK_LOGE("recv failed, socket is %{public}d, errno is %{public}d", sock, errno);
            callback.OnError(errno);
            return;
        }
        if (recvLen == 0) {
            continue;
        }
        void *data = malloc(recvLen);
        if (data == nullptr) {
            callback.OnError(NO_MEMORY);
            return;
        }
        if (memcpy_s(data, recvLen, buf.get(), recvLen) != EOK || !callback.OnMessage(data, recvLen, addr)) {
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

bool ExecLocalSocketConnect(LocalSocketConnectContext *context)
{
    if (context == nullptr) {
        return false;
    }
    struct sockaddr_un addr;
    memset_s(&addr, sizeof(addr), 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strcpy_s(addr.sun_path, sizeof(addr.sun_path) - 1, context->GetSocketPath().c_str()) != 0) {
        NETSTACK_LOGE("failed to copy local socket path, sockfd: %{public}d", context->GetSocketFd());
        context->SetErrorCode(UNKNOW_ERROR);
        return false;
    }
    NETSTACK_LOGI("local socket client fd: %{public}d, path: %{public}s", context->GetSocketFd(), addr.sun_path);
    if (connect(context->GetSocketFd(), reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) == -1) {
        NETSTACK_LOGE("failed to connect local socket, errno: %{public}d, %{public}s", errno, strerror(errno));
        context->SetErrorCode(errno);
        return false;
    }
    if (auto pMgr = reinterpret_cast<LocalSocketManager*>(context->GetManager()->GetData()); pMgr != nullptr) {
        pMgr->isConnected_ = true;
    }
    std::thread serviceThread(PollRecvData, context->GetSocketFd(), nullptr, 0,
                              LocalSocketMessageCallback(context->GetManager(), context->GetSocketPath()));
    serviceThread.detach();
    return true;
}

bool ExecLocalSocketSend(LocalSocketSendContext *context)
{
    if (context == nullptr) {
        return false;
    }
    bool result = true;
#ifdef ENABLE_EVENT_HANDLER
    auto manager = context->GetManager();
    auto eventHandler = manager->GetNetstackEventHandler();
    if (!eventHandler) {
        NETSTACK_LOGE("netstack eventHandler is nullptr");
        return false;
    }
    eventHandler->PostSyncTask([&result, context]() { result = LocalSocketSendEvent(context); });
    NapiUtils::CreateUvQueueWorkEnhanced(context->GetEnv(), context, SocketAsyncWork::LocalSocketSendCallback);
#endif
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
    context->SetSocketFd(0);
    if (auto pMgr = reinterpret_cast<LocalSocketManager *>(context->GetManager()->GetData()); pMgr != nullptr) {
        pMgr->isConnected_ = false;
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
    if (getsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &result, &len) == -1) {
        NETSTACK_LOGE("getsockopt error, SO_SNDTIMEO");
        return false;
    }
    optionsRef.SetSocketTimeout(result);
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
} // namespace OHOS::NetStack::Socket::LocalSocketExec