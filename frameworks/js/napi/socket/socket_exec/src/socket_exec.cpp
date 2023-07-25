/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "socket_exec.h"

#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <condition_variable>
#include <fcntl.h>
#include <map>
#include <memory>
#include <mutex>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

#include "context_key.h"
#include "event_list.h"
#include "napi_utils.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"
#include "securec.h"
#include "socket_module.h"

static constexpr const int DEFAULT_BUFFER_SIZE = 8192;

static constexpr const int DEFAULT_POLL_TIMEOUT = 500; // 0.5 Seconds

static constexpr const int ADDRESS_INVALID = 99;

static constexpr const int NO_MEMORY = -2;

static constexpr const int MSEC_TO_USEC = 1000;

static constexpr const int MAX_SEC = 999999999;

static constexpr const int USER_LIMIT = 511;

static constexpr const int ERR_SYS_BASE = 2303100;

static constexpr const int MAX_CLIENTS = 1024;

static constexpr const char *TCP_SOCKET_CONNECTION = "TCPSocketConnection";

static constexpr const char *TCP_SERVER_ACCEPT_RECV_DATA = "TCPServerAcceptRecvData";

static constexpr const char *TCP_SERVER_HANDLE_CLIENT = "TCPServerHandleClient";
namespace OHOS::NetStack::Socket::SocketExec {
std::map<int32_t, int32_t> g_clientFDs;
std::map<int32_t, std::shared_ptr<EventManager>> g_clientEventManagers;
std::condition_variable g_cv;
std::mutex g_mutex;
std::atomic_int g_userCounter = 0;

struct MessageData {
    MessageData() = delete;
    MessageData(void *d, size_t l, const SocketRemoteInfo &info) : data(d), len(l), remoteInfo(info) {}
    ~MessageData()
    {
        if (data) {
            free(data);
        }
    }

    void *data;
    size_t len;
    SocketRemoteInfo remoteInfo;
};

struct TcpConnection {
    TcpConnection() = delete;
    explicit TcpConnection(int32_t clientid) : clientId(clientid) {}
    ~TcpConnection() = default;

    int32_t clientId;
};

static void SetIsBound(sa_family_t family, GetStateContext *context, const sockaddr_in *addr4,
                       const sockaddr_in6 *addr6)
{
    if (family == AF_INET) {
        context->state_.SetIsBound(ntohs(addr4->sin_port) != 0);
    } else if (family == AF_INET6) {
        context->state_.SetIsBound(ntohs(addr6->sin6_port) != 0);
    }
}

static void SetIsConnected(sa_family_t family, GetStateContext *context, const sockaddr_in *addr4,
                           const sockaddr_in6 *addr6)
{
    if (family == AF_INET) {
        context->state_.SetIsConnected(ntohs(addr4->sin_port) != 0);
    } else if (family == AF_INET6) {
        context->state_.SetIsConnected(ntohs(addr6->sin6_port) != 0);
    }
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

napi_value NewInstanceWithConstructor(napi_env env, napi_callback_info info, napi_value jsConstructor, int32_t counter)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_new_instance(env, jsConstructor, 0, nullptr, &result));

    std::shared_ptr<EventManager> manager = std::make_shared<EventManager>();
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_clientEventManagers.insert(std::pair<int32_t, std::shared_ptr<EventManager>>(counter, manager));
        g_cv.notify_one();
    }

    napi_wrap(
        env, result, reinterpret_cast<void *>(manager.get()),
        [](napi_env, void *data, void *) {
            NETSTACK_LOGI("socket handle is finalized");
            auto manager = static_cast<EventManager *>(data);
            if (manager != nullptr) {
                EventManager::SetInvalid(manager);
                int sock = static_cast<int>(reinterpret_cast<uint64_t>(manager->GetData()));
                if (sock != 0) {
                    close(sock);
                }
            }
        },
        nullptr, nullptr);

    return result;
}

napi_value ConstructTCPSocketConnection(napi_env env, napi_callback_info info, int32_t counter)
{
    napi_value jsConstructor = nullptr;
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_NAPI_FUNCTION(SocketModuleExports::TCPConnection::FUNCTION_SEND,
                              SocketModuleExports::TCPConnection::Send),
        DECLARE_NAPI_FUNCTION(SocketModuleExports::TCPConnection::FUNCTION_CLOSE,
                              SocketModuleExports::TCPConnection::Close),
        DECLARE_NAPI_FUNCTION(SocketModuleExports::TCPConnection::FUNCTION_GET_REMOTE_ADDRESS,
                              SocketModuleExports::TCPConnection::GetRemoteAddress),
        DECLARE_NAPI_FUNCTION(SocketModuleExports::TCPConnection::FUNCTION_ON, SocketModuleExports::TCPConnection::On),
        DECLARE_NAPI_FUNCTION(SocketModuleExports::TCPConnection::FUNCTION_OFF,
                              SocketModuleExports::TCPConnection::Off),
    };

    auto constructor = [](napi_env env, napi_callback_info info) -> napi_value {
        napi_value thisVal = nullptr;
        NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisVal, nullptr));

        return thisVal;
    };

    napi_property_descriptor descriptors[properties.size()];
    std::copy(properties.begin(), properties.end(), descriptors);

    NAPI_CALL_BASE(env,
                   napi_define_class(env, TCP_SOCKET_CONNECTION, NAPI_AUTO_LENGTH, constructor, nullptr,
                                     properties.size(), descriptors, &jsConstructor),
                   NapiUtils::GetUndefined(env));

    if (jsConstructor != nullptr) {
        napi_value result = NewInstanceWithConstructor(env, info, jsConstructor, counter);
        NapiUtils::SetInt32Property(env, result, SocketModuleExports::TCPConnection::PROPERTY_CLIENT_ID, counter);
        return result;
    }
    return NapiUtils::GetUndefined(env);
}

static napi_value MakeTcpConnectionMessage(napi_env env, void *para)
{
    auto netConnection = reinterpret_cast<TcpConnection *>(para);
    auto deleter = [](const TcpConnection *p) { delete p; };
    std::unique_ptr<TcpConnection, decltype(deleter)> handler(netConnection, deleter);

    napi_callback_info info = nullptr;
    return ConstructTCPSocketConnection(env, info, netConnection->clientId);
}

static std::string MakeAddressString(sockaddr *addr)
{
    if (addr->sa_family == AF_INET) {
        auto *addr4 = reinterpret_cast<sockaddr_in *>(addr);
        const char *str = inet_ntoa(addr4->sin_addr);
        if (str == nullptr || strlen(str) == 0) {
            return {};
        }
        return str;
    } else if (addr->sa_family == AF_INET6) {
        auto *addr6 = reinterpret_cast<sockaddr_in6 *>(addr);
        char str[INET6_ADDRSTRLEN] = {0};
        if (inet_ntop(AF_INET6, &addr6->sin6_addr, str, INET6_ADDRSTRLEN) == nullptr || strlen(str) == 0) {
            return {};
        }
        return str;
    }
    return {};
}

static napi_value MakeJsMessageParam(napi_env env, napi_value msgBuffer, SocketRemoteInfo *remoteInfo)
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
    NapiUtils::SetStringPropertyUtf8(env, jsRemoteInfo, KEY_ADDRESS, remoteInfo->GetAddress());
    NapiUtils::SetStringPropertyUtf8(env, jsRemoteInfo, KEY_FAMILY, remoteInfo->GetFamily());
    NapiUtils::SetUint32Property(env, jsRemoteInfo, KEY_PORT, remoteInfo->GetPort());
    NapiUtils::SetUint32Property(env, jsRemoteInfo, KEY_SIZE, remoteInfo->GetSize());

    NapiUtils::SetNamedProperty(env, obj, KEY_REMOTE_INFO, jsRemoteInfo);
    return obj;
}

static napi_value MakeMessage(napi_env env, void *para)
{
    auto messageData = reinterpret_cast<MessageData *>(para);
    auto deleter = [](const MessageData *p) { delete p; };
    std::unique_ptr<MessageData, decltype(deleter)> handler(messageData, deleter);

    if (messageData->data == nullptr || messageData->len == 0) {
        return MakeJsMessageParam(env, NapiUtils::GetUndefined(env), &messageData->remoteInfo);
    }

    void *dataHandle = nullptr;
    napi_value msgBuffer = NapiUtils::CreateArrayBuffer(env, messageData->len, &dataHandle);
    if (dataHandle == nullptr || !NapiUtils::ValueIsArrayBuffer(env, msgBuffer)) {
        return MakeJsMessageParam(env, NapiUtils::GetUndefined(env), &messageData->remoteInfo);
    }

    int result = memcpy_s(dataHandle, messageData->len, messageData->data, messageData->len);
    if (result != EOK) {
        NETSTACK_LOGI("copy ret %{public}d", result);
        return NapiUtils::GetUndefined(env);
    }

    return MakeJsMessageParam(env, msgBuffer, &messageData->remoteInfo);
}

static bool OnRecvMessage(EventManager *manager, void *data, size_t len, sockaddr *addr)
{
    if (data == nullptr || len == 0) {
        return false;
    }

    SocketRemoteInfo remoteInfo;
    std::string address = MakeAddressString(addr);
    if (address.empty()) {
        manager->EmitByUv(EVENT_ERROR, new int32_t(ADDRESS_INVALID), CallbackTemplate<MakeError>);
        return false;
    }
    remoteInfo.SetAddress(address);
    remoteInfo.SetFamily(addr->sa_family);
    if (addr->sa_family == AF_INET) {
        auto *addr4 = reinterpret_cast<sockaddr_in *>(addr);
        remoteInfo.SetPort(ntohs(addr4->sin_port));
    } else if (addr->sa_family == AF_INET6) {
        auto *addr6 = reinterpret_cast<sockaddr_in6 *>(addr);
        remoteInfo.SetPort(ntohs(addr6->sin6_port));
    }
    remoteInfo.SetSize(len);

    manager->EmitByUv(EVENT_MESSAGE, new MessageData(data, len, remoteInfo), CallbackTemplate<MakeMessage>);
    return true;
}

class MessageCallback {
public:
    MessageCallback() = delete;

    virtual ~MessageCallback() = default;

    explicit MessageCallback(EventManager *manager) : manager_(manager) {}

    virtual void OnError(int err) const = 0;

    virtual bool OnMessage(int sock, void *data, size_t dataLen, sockaddr *addr) const = 0;

    virtual bool OnMessage(int sock, void *data, size_t dataLen, sockaddr *addr,
                           std::shared_ptr<EventManager> manager) const = 0;

    virtual void OnTcpConnectionMessage(int32_t id) const = 0;

protected:
    EventManager *manager_;
};

class TcpMessageCallback final : public MessageCallback {
public:
    TcpMessageCallback() = delete;

    ~TcpMessageCallback() override = default;

    explicit TcpMessageCallback(EventManager *manager) : MessageCallback(manager) {}

    void OnError(int err) const override
    {
        manager_->EmitByUv(EVENT_ERROR, new int(err), CallbackTemplate<MakeError>);
    }

    bool OnMessage(int sock, void *data, size_t dataLen, sockaddr *addr) const override
    {
        (void)addr;

        sockaddr sockAddr = {0};
        socklen_t len = sizeof(sockaddr);
        int ret = getsockname(sock, &sockAddr, &len);
        if (ret < 0) {
            return false;
        }

        if (sockAddr.sa_family == AF_INET) {
            sockaddr_in addr4 = {0};
            socklen_t len4 = sizeof(sockaddr_in);

            ret = getpeername(sock, reinterpret_cast<sockaddr *>(&addr4), &len4);
            if (ret < 0) {
                return false;
            }
            return OnRecvMessage(manager_, data, dataLen, reinterpret_cast<sockaddr *>(&addr4));
        } else if (sockAddr.sa_family == AF_INET6) {
            sockaddr_in6 addr6 = {0};
            socklen_t len6 = sizeof(sockaddr_in6);

            ret = getpeername(sock, reinterpret_cast<sockaddr *>(&addr6), &len6);
            if (ret < 0) {
                return false;
            }
            return OnRecvMessage(manager_, data, dataLen, reinterpret_cast<sockaddr *>(&addr6));
        }
        return false;
    }

    bool OnMessage(int sock, void *data, size_t dataLen, sockaddr *addr,
                   std::shared_ptr<EventManager> manager) const override
    {
        (void)addr;
        sockaddr sockAddr = {0};
        socklen_t len = sizeof(sockaddr);
        int ret = getsockname(sock, &sockAddr, &len);
        if (ret < 0) {
            return false;
        }

        if (sockAddr.sa_family == AF_INET) {
            sockaddr_in addr4 = {0};
            socklen_t len4 = sizeof(sockaddr_in);

            ret = getpeername(sock, reinterpret_cast<sockaddr *>(&addr4), &len4);
            if (ret < 0) {
                return false;
            }
            return OnRecvMessage(manager.get(), data, dataLen, reinterpret_cast<sockaddr *>(&addr4));
        } else if (sockAddr.sa_family == AF_INET6) {
            sockaddr_in6 addr6 = {0};
            socklen_t len6 = sizeof(sockaddr_in6);

            ret = getpeername(sock, reinterpret_cast<sockaddr *>(&addr6), &len6);
            if (ret < 0) {
                return false;
            }
            return OnRecvMessage(manager.get(), data, dataLen, reinterpret_cast<sockaddr *>(&addr6));
        }
        return false;
    }

    void OnTcpConnectionMessage(int32_t id) const override
    {
        manager_->EmitByUv(EVENT_CONNECT, new TcpConnection(id), CallbackTemplate<MakeTcpConnectionMessage>);
    }
};

class UdpMessageCallback final : public MessageCallback {
public:
    UdpMessageCallback() = delete;

    ~UdpMessageCallback() override = default;

    explicit UdpMessageCallback(EventManager *manager) : MessageCallback(manager) {}

    void OnError(int err) const override
    {
        manager_->EmitByUv(EVENT_ERROR, new int(err), CallbackTemplate<MakeError>);
    }

    bool OnMessage(int sock, void *data, size_t dataLen, sockaddr *addr) const override
    {
        return OnRecvMessage(manager_, data, dataLen, addr);
    }

    bool OnMessage(int sock, void *data, size_t dataLen, sockaddr *addr,
                   std::shared_ptr<EventManager> manager) const override
    {
        return true;
    }

    void OnTcpConnectionMessage(int32_t id) const override {}
};

static bool MakeNonBlock(int sock)
{
    int flags = fcntl(sock, F_GETFL, 0);
    while (flags == -1 && errno == EINTR) {
        flags = fcntl(sock, F_GETFL, 0);
    }
    if (flags == -1) {
        NETSTACK_LOGE("make non block failed %{public}s", strerror(errno));
        return false;
    }
    int ret = fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    while (ret == -1 && errno == EINTR) {
        ret = fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    }
    if (ret == -1) {
        NETSTACK_LOGE("make non block failed %{public}s", strerror(errno));
        return false;
    }
    return true;
}

static bool PollFd(pollfd *fds, nfds_t num, int timeout)
{
    int ret = poll(fds, num, timeout);
    if (ret == -1) {
        NETSTACK_LOGE("poll to send failed %{public}s", strerror(errno));
        return false;
    }
    if (ret == 0) {
        NETSTACK_LOGE("poll to send timeout");
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
        NETSTACK_LOGI("get sock opt sock type failed = %{public}s", strerror(errno));
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
            NETSTACK_LOGE("send failed %{public}s", strerror(errno));
            return false;
        }
        if (sendLen == 0) {
            break;
        }
        curPos += sendLen;
        leftSize -= sendLen;
    }

    if (leftSize != 0) {
        NETSTACK_LOGE("send not complete");
        return false;
    }
    return true;
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

static void PollRecvData(int sock, sockaddr *addr, socklen_t addrLen, const MessageCallback &callback)
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
    pollfd fds[1] = {{0}};
    fds[0].fd = sock;
    fds[0].events = 0;
    fds[0].events |= POLLIN;

    while (true) {
        int ret = poll(fds, num, DEFAULT_POLL_TIMEOUT);
        if (ret < 0) {
            NETSTACK_LOGE("poll to recv failed errno is: %{public}d %{public}s", errno, strerror(errno));
            callback.OnError(errno);
            return;
        }
        if (ret == 0) {
            continue;
        }
        (void)memset_s(buf.get(), bufferSize, 0, bufferSize);
        socklen_t tempAddrLen = addrLen;
        auto recvLen = recvfrom(sock, buf.get(), bufferSize, 0, addr, &tempAddrLen);
        if (recvLen < 0) {
            if (errno == EAGAIN) {
                continue;
            }
            NETSTACK_LOGE("recv failed errno is: %{public}d %{public}s", errno, strerror(errno));
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
        if (memcpy_s(data, recvLen, buf.get(), recvLen) != EOK || !callback.OnMessage(sock, data, recvLen, addr)) {
            free(data);
        }
    }
}

static bool NonBlockConnect(int sock, sockaddr *addr, socklen_t addrLen, uint32_t timeoutMSec)
{
    int ret = connect(sock, addr, addrLen);
    if (ret >= 0) {
        return true;
    }
    if (errno != EINPROGRESS) {
        return false;
    }

    fd_set set = {0};
    FD_ZERO(&set);
    FD_SET(sock, &set);
    if (timeoutMSec == 0) {
        timeoutMSec = DEFAULT_CONNECT_TIMEOUT;
    }

    timeval timeout = {
        .tv_sec = (timeoutMSec / MSEC_TO_USEC) % MAX_SEC,
        .tv_usec = (timeoutMSec % MSEC_TO_USEC) * MSEC_TO_USEC,
    };

    ret = select(sock + 1, nullptr, &set, nullptr, &timeout);
    if (ret < 0) {
        NETSTACK_LOGE("select error: %{public}s\n", strerror(errno));
        return false;
    } else if (ret == 0) {
        NETSTACK_LOGE("timeout!");
        return false;
    }

    int err = 0;
    socklen_t optLen = sizeof(err);
    ret = getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<void *>(&err), &optLen);
    if (ret < 0) {
        return false;
    }
    if (err != 0) {
        NETSTACK_LOGE("NonBlockConnect err number: %{public}d, message: %{public}s", err, strerror(err));
        return false;
    }
    return true;
}

static void GetAddr(NetAddress *address, sockaddr_in *addr4, sockaddr_in6 *addr6, sockaddr **addr, socklen_t *len)
{
    sa_family_t family = address->GetSaFamily();
    if (family == AF_INET) {
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(address->GetPort());
        addr4->sin_addr.s_addr = inet_addr(address->GetAddress().c_str());
        *addr = reinterpret_cast<sockaddr *>(addr4);
        *len = sizeof(sockaddr_in);
    } else if (family == AF_INET6) {
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons(address->GetPort());
        inet_pton(AF_INET6, address->GetAddress().c_str(), &addr6->sin6_addr);
        *addr = reinterpret_cast<sockaddr *>(addr6);
        *len = sizeof(sockaddr_in6);
    }
}

static bool SetBaseOptions(int sock, ExtraOptionsBase *option)
{
    if (option->GetReceiveBufferSize() != 0) {
        int size = (int)option->GetReceiveBufferSize();
        if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<void *>(&size), sizeof(size)) < 0) {
            return false;
        }
    }

    if (option->GetSendBufferSize() != 0) {
        int size = (int)option->GetSendBufferSize();
        if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<void *>(&size), sizeof(size)) < 0) {
            return false;
        }
    }

    if (option->IsReuseAddress()) {
        int reuse = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<void *>(&reuse), sizeof(reuse)) < 0) {
            return false;
        }
    }

    if (option->GetSocketTimeout() != 0) {
        timeval timeout = {(int)option->GetSocketTimeout(), 0};
        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<void *>(&timeout), sizeof(timeout)) < 0) {
            return false;
        }
        if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<void *>(&timeout), sizeof(timeout)) < 0) {
            return false;
        }
    }

    return true;
}

int MakeTcpSocket(sa_family_t family)
{
    if (family != AF_INET && family != AF_INET6) {
        return -1;
    }
    int sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
    NETSTACK_LOGI("new tcp socket is %{public}d", sock);
    if (sock < 0) {
        NETSTACK_LOGE("make tcp socket failed errno is %{public}d %{public}s", errno, strerror(errno));
        return -1;
    }
    if (!MakeNonBlock(sock)) {
        close(sock);
        return -1;
    }
    return sock;
}

int MakeUdpSocket(sa_family_t family)
{
    if (family != AF_INET && family != AF_INET6) {
        return -1;
    }
    int sock = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    NETSTACK_LOGI("new udp socket is %{public}d", sock);
    if (sock < 0) {
        NETSTACK_LOGE("make udp socket failed errno is %{public}d %{public}s", errno, strerror(errno));
        return -1;
    }
    if (!MakeNonBlock(sock)) {
        close(sock);
        return -1;
    }
    return sock;
}

bool ExecBind(BindContext *context)
{
    sockaddr_in addr4 = {0};
    sockaddr_in6 addr6 = {0};
    sockaddr *addr = nullptr;
    socklen_t len;
    GetAddr(&context->address_, &addr4, &addr6, &addr, &len);
    if (addr == nullptr) {
        NETSTACK_LOGE("addr family error, address invalid");
        context->SetErrorCode(ADDRESS_INVALID);
        return false;
    }

    if (bind(context->GetSocketFd(), addr, len) < 0) {
        if (errno != EADDRINUSE) {
            NETSTACK_LOGE("bind error is %{public}s %{public}d", strerror(errno), errno);
            context->SetErrorCode(errno);
            return false;
        }
        if (addr->sa_family == AF_INET) {
            NETSTACK_LOGI("distribute a random port");
            addr4.sin_port = 0; /* distribute a random port */
        } else if (addr->sa_family == AF_INET6) {
            NETSTACK_LOGI("distribute a random port");
            addr6.sin6_port = 0; /* distribute a random port */
        }
        if (bind(context->GetSocketFd(), addr, len) < 0) {
            NETSTACK_LOGE("rebind error is %{public}s %{public}d", strerror(errno), errno);
            context->SetErrorCode(errno);
            return false;
        }
        NETSTACK_LOGI("rebind success");
    }
    NETSTACK_LOGI("bind success");

    return true;
}

bool ExecUdpBind(BindContext *context)
{
    if (!ExecBind(context)) {
        return false;
    }

    sockaddr_in addr4 = {0};
    sockaddr_in6 addr6 = {0};
    sockaddr *addr = nullptr;
    socklen_t len;
    GetAddr(&context->address_, &addr4, &addr6, &addr, &len);
    if (addr == nullptr) {
        NETSTACK_LOGE("addr family error, address invalid");
        context->SetErrorCode(ADDRESS_INVALID);
        return false;
    }

    if (addr->sa_family == AF_INET) {
        auto pAddr4 = reinterpret_cast<sockaddr *>(malloc(sizeof(addr4)));
        if (pAddr4 == nullptr) {
            NETSTACK_LOGE("no memory!");
            return false;
        }
        NETSTACK_LOGI("copy ret = %{public}d", memcpy_s(pAddr4, sizeof(addr4), &addr4, sizeof(addr4)));
        std::thread serviceThread(PollRecvData, context->GetSocketFd(), pAddr4, sizeof(addr4),
                                  UdpMessageCallback(context->GetManager()));
        serviceThread.detach();
    } else if (addr->sa_family == AF_INET6) {
        void *pTmpAddr = malloc(len);
        auto pAddr6 = reinterpret_cast<sockaddr *>(pTmpAddr);
        if (pAddr6 == nullptr) {
            NETSTACK_LOGE("no memory!");
            return false;
        }
        NETSTACK_LOGI("copy ret = %{public}d", memcpy_s(pAddr6, sizeof(addr6), &addr6, sizeof(addr6)));
        std::thread serviceThread(PollRecvData, context->GetSocketFd(), pAddr6, sizeof(addr6),
                                  UdpMessageCallback(context->GetManager()));
        serviceThread.detach();
    }

    return true;
}

bool ExecUdpSend(UdpSendContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }

    sockaddr_in addr4 = {0};
    sockaddr_in6 addr6 = {0};
    sockaddr *addr = nullptr;
    socklen_t len;
    GetAddr(&context->options.address, &addr4, &addr6, &addr, &len);
    if (addr == nullptr) {
        NETSTACK_LOGE("addr family error, address invalid");
        context->SetErrorCode(ADDRESS_INVALID);
        return false;
    }

    if (!PollSendData(context->GetSocketFd(), context->options.GetData().c_str(), context->options.GetData().size(),
                      addr, len)) {
        context->SetErrorCode(errno);
        return false;
    }
    return true;
}

bool ExecTcpBind(BindContext *context)
{
    return ExecBind(context);
}

bool ExecConnect(ConnectContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }

    sockaddr_in addr4 = {0};
    sockaddr_in6 addr6 = {0};
    sockaddr *addr = nullptr;
    socklen_t len;
    GetAddr(&context->options.address, &addr4, &addr6, &addr, &len);
    if (addr == nullptr) {
        NETSTACK_LOGE("addr family error, address invalid");
        context->SetErrorCode(ADDRESS_INVALID);
        return false;
    }

    if (!NonBlockConnect(context->GetSocketFd(), addr, len, context->options.GetTimeout())) {
        NETSTACK_LOGE("connect errno %{public}d %{public}s", errno, strerror(errno));
        context->SetErrorCode(errno);
        return false;
    }

    NETSTACK_LOGI("connect success");
    std::thread serviceThread(PollRecvData, context->GetSocketFd(), nullptr, 0,
                              TcpMessageCallback(context->GetManager()));
    serviceThread.detach();
    return true;
}

bool ExecTcpSend(TcpSendContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }

    std::string encoding = context->options.GetEncoding();
    (void)encoding;
    /* no use for now */

    sockaddr sockAddr = {0};
    socklen_t len = sizeof(sockaddr);
    if (getsockname(context->GetSocketFd(), &sockAddr, &len) < 0) {
        NETSTACK_LOGE("get sock name failed, address invalid");
        context->SetErrorCode(ADDRESS_INVALID);
        return false;
    }
    bool connected = false;
    if (sockAddr.sa_family == AF_INET) {
        sockaddr_in addr4 = {0};
        socklen_t len4 = sizeof(addr4);
        int ret = getpeername(context->GetSocketFd(), reinterpret_cast<sockaddr *>(&addr4), &len4);
        if (ret >= 0 && addr4.sin_port != 0) {
            connected = true;
        }
    } else if (sockAddr.sa_family == AF_INET6) {
        sockaddr_in6 addr6 = {0};
        socklen_t len6 = sizeof(addr6);
        int ret = getpeername(context->GetSocketFd(), reinterpret_cast<sockaddr *>(&addr6), &len6);
        if (ret >= 0 && addr6.sin6_port != 0) {
            connected = true;
        }
    }

    if (!connected) {
        NETSTACK_LOGE("sock is not connect to remote %{public}s", strerror(errno));
        context->SetErrorCode(errno);
        return false;
    }

    if (!PollSendData(context->GetSocketFd(), context->options.GetData().c_str(), context->options.GetData().size(),
                      nullptr, 0)) {
        NETSTACK_LOGE("send errno %{public}d %{public}s", errno, strerror(errno));
        context->SetErrorCode(errno);
        return false;
    }
    return true;
}

bool ExecClose(CloseContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }

    int ret = close(context->GetSocketFd());
    if (ret < 0) {
        NETSTACK_LOGE("sock closed error %{public}s sock = %{public}d, ret = %{public}d", strerror(errno),
                      context->GetSocketFd(), ret);
        return false;
    }
    NETSTACK_LOGI("sock %{public}d closed success", context->GetSocketFd());

    context->SetSocketFd(0);

    return true;
}

static bool CheckClosed(GetStateContext *context, int &opt)
{
    socklen_t optLen = sizeof(int);
    int r = getsockopt(context->GetSocketFd(), SOL_SOCKET, SO_TYPE, &opt, &optLen);
    if (r < 0) {
        context->state_.SetIsClose(true);
        return true;
    }
    return false;
}

static bool CheckSocketFd(GetStateContext *context, sockaddr &sockAddr)
{
    socklen_t len = sizeof(sockaddr);
    int ret = getsockname(context->GetSocketFd(), &sockAddr, &len);
    if (ret < 0) {
        context->SetErrorCode(errno);
        return false;
    }
    return true;
}

bool ExecGetState(GetStateContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }

    int opt;
    if (CheckClosed(context, opt)) {
        return true;
    }

    sockaddr sockAddr = {0};
    if (!CheckSocketFd(context, sockAddr)) {
        return false;
    }

    sockaddr_in addr4 = {0};
    sockaddr_in6 addr6 = {0};
    sockaddr *addr = nullptr;
    socklen_t addrLen;
    if (sockAddr.sa_family == AF_INET) {
        addr = reinterpret_cast<sockaddr *>(&addr4);
        addrLen = sizeof(addr4);
    } else if (sockAddr.sa_family == AF_INET6) {
        addr = reinterpret_cast<sockaddr *>(&addr6);
        addrLen = sizeof(addr6);
    }

    if (addr == nullptr) {
        NETSTACK_LOGE("addr family error, address invalid");
        context->SetErrorCode(ADDRESS_INVALID);
        return false;
    }

    (void)memset_s(addr, addrLen, 0, addrLen);
    socklen_t len = addrLen;
    int ret = getsockname(context->GetSocketFd(), addr, &len);
    if (ret < 0) {
        context->SetErrorCode(errno);
        return false;
    }

    SetIsBound(sockAddr.sa_family, context, &addr4, &addr6);

    if (opt != SOCK_STREAM) {
        return true;
    }

    (void)memset_s(addr, addrLen, 0, addrLen);
    len = addrLen;
    (void)getpeername(context->GetSocketFd(), addr, &len);
    SetIsConnected(sockAddr.sa_family, context, &addr4, &addr6);
    return true;
}

bool ExecGetRemoteAddress(GetRemoteAddressContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }

    sockaddr sockAddr = {0};
    socklen_t len = sizeof(sockaddr);
    int ret = getsockname(context->GetSocketFd(), &sockAddr, &len);
    if (ret < 0) {
        context->SetErrorCode(errno);
        return false;
    }

    if (sockAddr.sa_family == AF_INET) {
        sockaddr_in addr4 = {0};
        socklen_t len4 = sizeof(sockaddr_in);

        ret = getpeername(context->GetSocketFd(), reinterpret_cast<sockaddr *>(&addr4), &len4);
        if (ret < 0) {
            context->SetErrorCode(errno);
            return false;
        }

        std::string address = MakeAddressString(reinterpret_cast<sockaddr *>(&addr4));
        if (address.empty()) {
            NETSTACK_LOGE("addr family error, address invalid");
            context->SetErrorCode(ADDRESS_INVALID);
            return false;
        }
        context->address_.SetAddress(address);
        context->address_.SetFamilyBySaFamily(sockAddr.sa_family);
        context->address_.SetPort(ntohs(addr4.sin_port));
        return true;
    } else if (sockAddr.sa_family == AF_INET6) {
        sockaddr_in6 addr6 = {0};
        socklen_t len6 = sizeof(sockaddr_in6);

        ret = getpeername(context->GetSocketFd(), reinterpret_cast<sockaddr *>(&addr6), &len6);
        if (ret < 0) {
            context->SetErrorCode(errno);
            return false;
        }

        std::string address = MakeAddressString(reinterpret_cast<sockaddr *>(&addr6));
        if (address.empty()) {
            NETSTACK_LOGE("addr family error, address invalid");
            context->SetErrorCode(ADDRESS_INVALID);
            return false;
        }
        context->address_.SetAddress(address);
        context->address_.SetFamilyBySaFamily(sockAddr.sa_family);
        context->address_.SetPort(ntohs(addr6.sin6_port));
        return true;
    }

    return false;
}

bool ExecTcpSetExtraOptions(TcpSetExtraOptionsContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }

    if (!SetBaseOptions(context->GetSocketFd(), &context->options_)) {
        context->SetErrorCode(errno);
        return false;
    }

    if (context->options_.IsKeepAlive()) {
        int keepalive = 1;
        if (setsockopt(context->GetSocketFd(), SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive)) < 0) {
            context->SetErrorCode(errno);
            return false;
        }
    }

    if (context->options_.IsOOBInline()) {
        int oobInline = 1;
        if (setsockopt(context->GetSocketFd(), SOL_SOCKET, SO_OOBINLINE, &oobInline, sizeof(oobInline)) < 0) {
            context->SetErrorCode(errno);
            return false;
        }
    }

    if (context->options_.IsTCPNoDelay()) {
        int tcpNoDelay = 1;
        if (setsockopt(context->GetSocketFd(), IPPROTO_TCP, TCP_NODELAY, &tcpNoDelay, sizeof(tcpNoDelay)) < 0) {
            context->SetErrorCode(errno);
            return false;
        }
    }

    linger soLinger = {0};
    soLinger.l_onoff = context->options_.socketLinger.IsOn();
    soLinger.l_linger = (int)context->options_.socketLinger.GetLinger();
    if (setsockopt(context->GetSocketFd(), SOL_SOCKET, SO_LINGER, &soLinger, sizeof(soLinger)) < 0) {
        context->SetErrorCode(errno);
        return false;
    }

    return true;
}

bool ExecUdpSetExtraOptions(UdpSetExtraOptionsContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }

    if (!SetBaseOptions(context->GetSocketFd(), &context->options)) {
        context->SetErrorCode(errno);
        return false;
    }

    if (context->options.IsBroadcast()) {
        int broadcast = 1;
        if (setsockopt(context->GetSocketFd(), SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) < 0) {
            context->SetErrorCode(errno);
            return false;
        }
    }

    return true;
}

bool ExecTcpGetSocketFd(GetSocketFdContext *context)
{
    return true;
}

bool ExecUdpGetSocketFd(GetSocketFdContext *context)
{
    return true;
}

static bool GetIPv4Address(TcpConnectionGetRemoteAddressContext *context, int32_t fd, sockaddr sockAddr)
{
    sockaddr_in addr4 = {0};
    socklen_t len4 = sizeof(sockaddr_in);

    int ret = getpeername(fd, reinterpret_cast<sockaddr *>(&addr4), &len4);
    if (ret < 0) {
        context->SetErrorCode(errno);
        return false;
    }

    std::string address = MakeAddressString(reinterpret_cast<sockaddr *>(&addr4));
    if (address.empty()) {
        NETSTACK_LOGE("addr family error, address invalid");
        context->SetErrorCode(ADDRESS_INVALID);
        return false;
    }
    context->address_.SetAddress(address);
    context->address_.SetFamilyBySaFamily(sockAddr.sa_family);
    context->address_.SetPort(ntohs(addr4.sin_port));
    return true;
}

static bool GetIPv6Address(TcpConnectionGetRemoteAddressContext *context, int32_t fd, sockaddr sockAddr)
{
    sockaddr_in6 addr6 = {0};
    socklen_t len6 = sizeof(sockaddr_in6);

    int ret = getpeername(fd, reinterpret_cast<sockaddr *>(&addr6), &len6);
    if (ret < 0) {
        context->SetErrorCode(errno);
        return false;
    }

    std::string address = MakeAddressString(reinterpret_cast<sockaddr *>(&addr6));
    if (address.empty()) {
        NETSTACK_LOGE("addr family error, address invalid");
        context->SetErrorCode(ADDRESS_INVALID);
        return false;
    }
    context->address_.SetAddress(address);
    context->address_.SetFamilyBySaFamily(sockAddr.sa_family);
    context->address_.SetPort(ntohs(addr6.sin6_port));
    return true;
}

bool ExecTcpConnectionGetRemoteAddress(TcpConnectionGetRemoteAddressContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }

    int32_t clientFd = -1;
    bool fdValid = false;

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto iter = g_clientFDs.find(context->clientId_);
        if (iter != g_clientFDs.end()) {
            fdValid = true;
            clientFd = iter->second;
        } else {
            NETSTACK_LOGE("not find clientId");
        }
    }

    if (!fdValid) {
        NETSTACK_LOGE("client fd is invalid");
        context->SetErrorCode(ERR_SYS_BASE + errno);
        return false;
    }

    sockaddr sockAddr = {0};
    socklen_t len = sizeof(sockaddr);
    int ret = getsockname(clientFd, &sockAddr, &len);
    if (ret < 0) {
        context->SetErrorCode(ERR_SYS_BASE + errno);
        return false;
    }

    if (sockAddr.sa_family == AF_INET) {
        return GetIPv4Address(context, clientFd, sockAddr);
    } else if (sockAddr.sa_family == AF_INET6) {
        return GetIPv6Address(context, clientFd, sockAddr);
    }

    return false;
}

static bool IsRemoteConnect(TcpSendContext *context, int32_t clientFd)
{
    sockaddr sockAddr = {0};
    socklen_t len = sizeof(sockaddr);
    if (getsockname(clientFd, &sockAddr, &len) < 0) {
        NETSTACK_LOGE("get sock name failed, address invalid");
        context->SetErrorCode(ADDRESS_INVALID);
        return false;
    }
    bool connected = false;
    if (sockAddr.sa_family == AF_INET) {
        sockaddr_in addr4 = {0};
        socklen_t len4 = sizeof(addr4);
        int ret = getpeername(clientFd, reinterpret_cast<sockaddr *>(&addr4), &len4);
        if (ret >= 0 && addr4.sin_port != 0) {
            connected = true;
        }
    } else if (sockAddr.sa_family == AF_INET6) {
        sockaddr_in6 addr6 = {0};
        socklen_t len6 = sizeof(addr6);
        int ret = getpeername(clientFd, reinterpret_cast<sockaddr *>(&addr6), &len6);
        if (ret >= 0 && addr6.sin6_port != 0) {
            connected = true;
        }
    }

    if (!connected) {
        NETSTACK_LOGE("sock is not connect to remote %{public}s", strerror(errno));
        context->SetErrorCode(errno);
        return false;
    }
    return true;
}

bool ExecTcpConnectionSend(TcpSendContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }

    int32_t clientFd = -1;
    bool fdValid = false;

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto iter = g_clientFDs.find(context->clientId_);
        if (iter != g_clientFDs.end()) {
            fdValid = true;
            clientFd = iter->second;
        } else {
            NETSTACK_LOGE("not find clientId");
        }
    }

    if (!fdValid) {
        NETSTACK_LOGE("client fd is invalid");
        context->SetErrorCode(ERR_SYS_BASE + errno);
        return false;
    }

    std::string encoding = context->options.GetEncoding();
    (void)encoding;
    /* no use for now */

    if (!IsRemoteConnect(context, clientFd)) {
        return false;
    }

    if (!PollSendData(clientFd, context->options.GetData().c_str(), context->options.GetData().size(), nullptr, 0)) {
        NETSTACK_LOGE("send errno %{public}d %{public}s", errno, strerror(errno));
        context->SetErrorCode(ERR_SYS_BASE + errno);
        return false;
    }
    return true;
}

bool ExecTcpConnectionClose(CloseContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    bool fdValid = false;

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto iter = g_clientFDs.find(context->clientId_);
        if (iter != g_clientFDs.end()) {
            fdValid = true;
        } else {
            NETSTACK_LOGE("not find clientId");
        }
    }

    if (!fdValid) {
        NETSTACK_LOGE("client fd is invalid");
        context->SetErrorCode(ERR_SYS_BASE + errno);
        return false;
    }

    return true;
}

static bool ServerBind(BindContext *context)
{
    sockaddr_in addr4 = {0};
    sockaddr_in6 addr6 = {0};
    sockaddr *addr = nullptr;
    socklen_t len;
    GetAddr(&context->address_, &addr4, &addr6, &addr, &len);
    if (addr == nullptr) {
        NETSTACK_LOGE("addr family error, address invalid");
        context->SetErrorCode(ADDRESS_INVALID);
        return false;
    }

    if (bind(context->GetSocketFd(), addr, len) < 0) {
        if (errno != EADDRINUSE) {
            NETSTACK_LOGE("bind error is %{public}s %{public}d", strerror(errno), errno);
            context->SetErrorCode(ERR_SYS_BASE + errno);
            return false;
        }
        if (addr->sa_family == AF_INET) {
            NETSTACK_LOGI("distribute a random port");
            addr4.sin_port = 0; /* distribute a random port */
        } else if (addr->sa_family == AF_INET6) {
            NETSTACK_LOGI("distribute a random port");
            addr6.sin6_port = 0; /* distribute a random port */
        }
        if (bind(context->GetSocketFd(), addr, len) < 0) {
            NETSTACK_LOGE("rebind error is %{public}s %{public}d", strerror(errno), errno);
            context->SetErrorCode(ERR_SYS_BASE + errno);
            return false;
        }
        NETSTACK_LOGI("rebind success");
    }
    NETSTACK_LOGI("bind success");

    return true;
}

static void RemoveClientConnection(int32_t clientFd)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    for (auto it = g_clientFDs.begin(); it != g_clientFDs.end(); ++it) {
        if (it->second == clientFd) {
            g_clientFDs.erase(it->first);
            g_clientEventManagers.erase(it->first);
            break;
        }
    }
}

static bool IsClientFdClosed(int32_t clientFd)
{
    return (fcntl(clientFd, F_GETFL) == -1 && errno == EBADF);
}

static void ClientHandler(int32_t connectFD, sockaddr *addr, socklen_t addrLen, const TcpMessageCallback &callback)
{
    char buffer[DEFAULT_BUFFER_SIZE];

    std::shared_ptr<EventManager> manager = nullptr;
    {
        std::unique_lock<std::mutex> lock(g_mutex);
        g_cv.wait(lock, [&manager]() {
            auto iter = g_clientEventManagers.find(g_userCounter);
            if (iter != g_clientEventManagers.end()) {
                manager = iter->second;
                return true;
            } else {
                return false;
            }
        });
    }
    while (true) {
        if (memset_s(buffer, sizeof(buffer), 0, sizeof(buffer)) != EOK) {
            NETSTACK_LOGE("memset_s failed!");
            break;
        }
        int32_t recvSize = recv(connectFD, buffer, sizeof(buffer), 0);
        NETSTACK_LOGI("ClientRecv: fd is %{public}d, buf is %{public}s, size is %{public}d bytes", connectFD, buffer,
                      recvSize);
        if (recvSize <= 0) {
            NETSTACK_LOGE("close ClientHandler: recvSize is %{public}d, errno is %{public}d", recvSize, errno);
            if (IsClientFdClosed(connectFD)) {
                NETSTACK_LOGE("connectFD has been closed");
                break;
            }
            if (errno != EAGAIN) {
                shutdown(connectFD, SHUT_RDWR);
                close(connectFD);
                manager->Emit(EVENT_CLOSE, std::make_pair(nullptr, nullptr));
                RemoveClientConnection(connectFD);
                break;
            }
        } else {
            void *data = malloc(recvSize);
            if (data == nullptr) {
                callback.OnError(NO_MEMORY);
                break;
            }
            if (memcpy_s(data, recvSize, buffer, recvSize) != EOK ||
                !callback.OnMessage(connectFD, data, recvSize, addr, manager)) {
                free(data);
            }
        }
    }
}

static void AcceptRecvData(int sock, sockaddr *addr, socklen_t addrLen, const TcpMessageCallback &callback)
{
    while (true) {
        sockaddr_in clientAddress;
        socklen_t clientAddrLength = sizeof(clientAddress);
        int32_t connectFD = accept(sock, reinterpret_cast<sockaddr *>(&clientAddress), &clientAddrLength);
        if (connectFD < 0) {
            continue;
        }
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_clientFDs.size() >= MAX_CLIENTS) {
                NETSTACK_LOGE("Maximum number of clients reached, connection rejected");
                close(connectFD);
                continue;
            }
            NETSTACK_LOGI("Server accept new client SUCCESS, fd = %{public}d", connectFD);
            g_userCounter++;
            g_clientFDs[g_userCounter] = connectFD;
        }
        callback.OnTcpConnectionMessage(g_userCounter);
        std::thread handlerThread(ClientHandler, connectFD, nullptr, 0, callback);
#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
        pthread_setname_np(TCP_SERVER_HANDLE_CLIENT);
#else
        pthread_setname_np(handlerThread.native_handle(), TCP_SERVER_HANDLE_CLIENT);
#endif
        handlerThread.detach();
    }
}

bool ExecTcpServerListen(BindContext *context)
{
    int ret = 0;
    if (!ServerBind(context)) {
        return false;
    }

    ret = listen(context->GetSocketFd(), USER_LIMIT);
    if (ret < 0) {
        NETSTACK_LOGE("tcp server listen error");
        return false;
    }

    NETSTACK_LOGI("listen success");
    std::thread serviceThread(AcceptRecvData, context->GetSocketFd(), nullptr, 0,
                              TcpMessageCallback(context->GetManager()));
#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
    pthread_setname_np(TCP_SERVER_ACCEPT_RECV_DATA);
#else
    pthread_setname_np(serviceThread.native_handle(), TCP_SERVER_ACCEPT_RECV_DATA);
#endif
    serviceThread.detach();
    return true;
}

bool ExecTcpServerSetExtraOptions(TcpSetExtraOptionsContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }

    if (!SetBaseOptions(context->GetSocketFd(), &context->options_)) {
        context->SetErrorCode(ERR_SYS_BASE + errno);
        return false;
    }

    if (context->options_.IsKeepAlive()) {
        int keepalive = 1;
        if (setsockopt(context->GetSocketFd(), SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive)) < 0) {
            context->SetErrorCode(ERR_SYS_BASE + errno);
            return false;
        }
    }

    if (context->options_.IsOOBInline()) {
        int oobInline = 1;
        if (setsockopt(context->GetSocketFd(), SOL_SOCKET, SO_OOBINLINE, &oobInline, sizeof(oobInline)) < 0) {
            context->SetErrorCode(ERR_SYS_BASE + errno);
            return false;
        }
    }

    if (context->options_.IsTCPNoDelay()) {
        int tcpNoDelay = 1;
        if (setsockopt(context->GetSocketFd(), IPPROTO_TCP, TCP_NODELAY, &tcpNoDelay, sizeof(tcpNoDelay)) < 0) {
            context->SetErrorCode(ERR_SYS_BASE + errno);
            return false;
        }
    }

    linger soLinger = {0};
    soLinger.l_onoff = context->options_.socketLinger.IsOn();
    soLinger.l_linger = (int)context->options_.socketLinger.GetLinger();
    if (setsockopt(context->GetSocketFd(), SOL_SOCKET, SO_LINGER, &soLinger, sizeof(soLinger)) < 0) {
        context->SetErrorCode(ERR_SYS_BASE + errno);
        return false;
    }

    return true;
}

static void SetIsConnected(GetStateContext *context)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_clientFDs.empty()) {
        context->state_.SetIsConnected(false);
    } else {
        context->state_.SetIsConnected(true);
    }
}

bool ExecTcpServerGetState(GetStateContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }

    int opt;
    socklen_t optLen = sizeof(int);
    if (getsockopt(context->GetSocketFd(), SOL_SOCKET, SO_TYPE, &opt, &optLen) < 0) {
        context->state_.SetIsClose(true);
        return true;
    }

    sockaddr sockAddr = {0};
    socklen_t len = sizeof(sockaddr);
    if (getsockname(context->GetSocketFd(), &sockAddr, &len) < 0) {
        context->SetErrorCode(ERR_SYS_BASE + errno);
        return false;
    }

    sockaddr_in addr4 = {0};
    sockaddr_in6 addr6 = {0};
    sockaddr *addr = nullptr;
    socklen_t addrLen;
    if (sockAddr.sa_family == AF_INET) {
        addr = reinterpret_cast<sockaddr *>(&addr4);
        addrLen = sizeof(addr4);
    } else if (sockAddr.sa_family == AF_INET6) {
        addr = reinterpret_cast<sockaddr *>(&addr6);
        addrLen = sizeof(addr6);
    }

    if (addr == nullptr) {
        NETSTACK_LOGE("addr family error, address invalid");
        context->SetErrorCode(ADDRESS_INVALID);
        return false;
    }

    if (memset_s(addr, addrLen, 0, addrLen) != EOK) {
        NETSTACK_LOGE("memset_s failed!");
        return false;
    }
    len = addrLen;
    if (getsockname(context->GetSocketFd(), addr, &len) < 0) {
        context->SetErrorCode(ERR_SYS_BASE + errno);
        return false;
    }

    SetIsBound(sockAddr.sa_family, context, &addr4, &addr6);

    if (opt != SOCK_STREAM) {
        return true;
    }
    SetIsConnected(context);
    return true;
}

napi_value BindCallback(BindContext *context)
{
    context->Emit(EVENT_LISTENING, std::make_pair(NapiUtils::GetUndefined(context->GetEnv()),
                                                  NapiUtils::GetUndefined(context->GetEnv())));
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value UdpSendCallback(UdpSendContext *context)
{
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value ConnectCallback(ConnectContext *context)
{
    context->Emit(EVENT_CONNECT, std::make_pair(NapiUtils::GetUndefined(context->GetEnv()),
                                                NapiUtils::GetUndefined(context->GetEnv())));
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value TcpSendCallback(TcpSendContext *context)
{
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value CloseCallback(CloseContext *context)
{
    context->Emit(EVENT_CLOSE, std::make_pair(NapiUtils::GetUndefined(context->GetEnv()),
                                              NapiUtils::GetUndefined(context->GetEnv())));
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value GetStateCallback(GetStateContext *context)
{
    napi_value obj = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), obj) != napi_object) {
        return NapiUtils::GetUndefined(context->GetEnv());
    }

    NapiUtils::SetBooleanProperty(context->GetEnv(), obj, KEY_IS_BOUND, context->state_.IsBound());
    NapiUtils::SetBooleanProperty(context->GetEnv(), obj, KEY_IS_CLOSE, context->state_.IsClose());
    NapiUtils::SetBooleanProperty(context->GetEnv(), obj, KEY_IS_CONNECTED, context->state_.IsConnected());

    return obj;
}

napi_value GetRemoteAddressCallback(GetRemoteAddressContext *context)
{
    napi_value obj = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), obj) != napi_object) {
        return NapiUtils::GetUndefined(context->GetEnv());
    }

    NapiUtils::SetStringPropertyUtf8(context->GetEnv(), obj, KEY_ADDRESS, context->address_.GetAddress());
    NapiUtils::SetUint32Property(context->GetEnv(), obj, KEY_FAMILY, context->address_.GetJsValueFamily());
    NapiUtils::SetUint32Property(context->GetEnv(), obj, KEY_PORT, context->address_.GetPort());

    return obj;
}

napi_value TcpSetExtraOptionsCallback(TcpSetExtraOptionsContext *context)
{
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value UdpSetExtraOptionsCallback(UdpSetExtraOptionsContext *context)
{
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value TcpGetSocketFdCallback(GetSocketFdContext *context)
{
    int sockFd = context->GetSocketFd();
    if (sockFd == -1) {
        return NapiUtils::GetUndefined(context->GetEnv());
    }
    return NapiUtils::CreateUint32(context->GetEnv(), sockFd);
}

napi_value UdpGetSocketFdCallback(GetSocketFdContext *context)
{
    int sockFd = context->GetSocketFd();
    if (sockFd == -1) {
        return NapiUtils::GetUndefined(context->GetEnv());
    }
    return NapiUtils::CreateUint32(context->GetEnv(), sockFd);
}

napi_value TcpConnectionSendCallback(TcpSendContext *context)
{
    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value TcpConnectionCloseCallback(CloseContext *context)
{
    int32_t clientFd = -1;

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto iter = g_clientFDs.find(context->clientId_);
        if (iter != g_clientFDs.end()) {
            clientFd = iter->second;
        } else {
            NETSTACK_LOGE("not find clientId");
        }
    }

    if (shutdown(clientFd, SHUT_RDWR) != 0) {
        NETSTACK_LOGE("socket shutdown error %{public}s", strerror(errno));
    }
    int ret = close(clientFd);
    if (ret < 0) {
        NETSTACK_LOGE("sock closed error %{public}s sock = %{public}d, ret = %{public}d", strerror(errno),
                      context->GetSocketFd(), ret);
    } else {
        NETSTACK_LOGI("sock %{public}d closed success", clientFd);
        RemoveClientConnection(clientFd);
        context->Emit(EVENT_CLOSE, std::make_pair(NapiUtils::GetUndefined(context->GetEnv()),
                                                  NapiUtils::GetUndefined(context->GetEnv())));
    }

    return NapiUtils::GetUndefined(context->GetEnv());
}

napi_value TcpConnectionGetRemoteAddressCallback(TcpConnectionGetRemoteAddressContext *context)
{
    napi_value obj = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), obj) != napi_object) {
        return NapiUtils::GetUndefined(context->GetEnv());
    }

    NapiUtils::SetStringPropertyUtf8(context->GetEnv(), obj, KEY_ADDRESS, context->address_.GetAddress());
    NapiUtils::SetUint32Property(context->GetEnv(), obj, KEY_FAMILY, context->address_.GetJsValueFamily());
    NapiUtils::SetUint32Property(context->GetEnv(), obj, KEY_PORT, context->address_.GetPort());

    return obj;
}

napi_value ListenCallback(BindContext *context)
{
    return NapiUtils::GetUndefined(context->GetEnv());
}
} // namespace OHOS::NetStack::Socket::SocketExec
