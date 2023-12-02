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
} // namespace OHOS::NetStack::Socket::LocalSocketExec
