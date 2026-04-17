/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "net_socket_impl.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cinttypes>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "securec.h"
#include "netstack_log.h"
#include "netstack_common_utils.h"
#include "cj_connect_monitor.h"
#include "ffi_remote_data.h"

namespace OHOS::NetStack::Socket {

CJTcpSocketProxy::CJTcpSocketProxy() {}

CJTcpSocketProxy::~CJTcpSocketProxy()
{
    if (sockFd_ >= 0) {
        CjConnectMonitor::GetInstance().Unregister(sockFd_);
    }
    StopRecvThread();
    if (sockFd_ >= 0) {
        close(sockFd_);
        sockFd_ = -1;
    }
}

int CJTcpSocketProxy::GetSocketFd() const
{
    return sockFd_;
}

void CJTcpSocketProxy::SetSocketFd(int fd)
{
    sockFd_ = fd;
}

sa_family_t CJTcpSocketProxy::GetFamily() const
{
    return family_;
}

void CJTcpSocketProxy::SetFamily(sa_family_t family)
{
    family_ = family;
}

bool CJTcpSocketProxy::GetReuseAddr() const
{
    return reuseAddr_;
}

void CJTcpSocketProxy::SetReuseAddr(bool reuseAddr)
{
    reuseAddr_ = reuseAddr;
}

bool CJTcpSocketProxy::IsAsyncConnecting() const
{
    return asyncConnecting_;
}

void CJTcpSocketProxy::SetAsyncConnecting(bool asyncConnecting)
{
    asyncConnecting_ = asyncConnecting;
}

bool CJTcpSocketProxy::IsClosed() const
{
    return closed_.load();
}

void CJTcpSocketProxy::AddCallback2Map(int32_t type, SocketCallback callback)
{
    std::lock_guard<std::mutex> lock(eventMutex_);
    eventMap_[type] = callback;
}

void CJTcpSocketProxy::DelCallback(int32_t type)
{
    std::lock_guard<std::mutex> lock(eventMutex_);
    eventMap_.erase(type);
}

std::optional<SocketCallback> CJTcpSocketProxy::FindCallback(int32_t type)
{
    std::lock_guard<std::mutex> lock(eventMutex_);
    auto iter = eventMap_.find(type);
    if (iter != eventMap_.end()) {
        return iter->second;
    }
    return std::nullopt;
}

void CJTcpSocketProxy::SetConnectCallback(ConnectCallback callback)
{
    std::lock_guard<std::mutex> lock(connectMutex_);
    connectCallback_ = callback;
}

ConnectCallback CJTcpSocketProxy::GetConnectCallback()
{
    std::lock_guard<std::mutex> lock(connectMutex_);
    return connectCallback_;
}

void CJTcpSocketProxy::StartRecvThread()
{
    std::lock_guard<std::mutex> lock(recvMutex_);
    if (recvThread_.joinable()) {
        return;
    }
    closed_.store(false);
    recvThread_ = std::thread(&CJTcpSocketProxy::RecvLoop, this);
    pthread_setname_np(recvThread_.native_handle(), "TcpSocketRecv");
}

void CJTcpSocketProxy::StopRecvThread()
{
    closed_.store(true);
    std::lock_guard<std::mutex> lock(recvMutex_);
    if (recvThread_.joinable()) {
        recvThread_.join();
    }
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

int CJTcpSocketProxy::WaitForPollEvent(pollfd &fd)
{
    fd.fd = sockFd_;
    fd.events = POLLIN;
    int ret = poll(&fd, 1, DEFAULT_POLL_TIMEOUT);
    if (ret < 0) {
        if (errno == EINTR) {
            return 0;
        }
        EmitErrorEvent(errno);
        return -1;
    }
    if (ret == 0) {
        return 0;
    }
    if ((fd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
        EmitCloseEvent();
        return -1;
    }
    if ((fd.revents & POLLIN) == 0) {
        return 0;
    }
    return 1;
}

void CJTcpSocketProxy::RecvLoop()
{
    int bufferSize = ConfirmBufferSize(sockFd_);
    auto buf = std::make_unique<char[]>(bufferSize);
    sockaddr_in addr4 = {0};
    sockaddr_in6 addr6 = {0};
    sockaddr *addr = nullptr;
    socklen_t addrLen = 0;
    if (family_ == AF_INET) {
        addr = reinterpret_cast<sockaddr *>(&addr4);
        addrLen = sizeof(addr4);
    } else {
        addr = reinterpret_cast<sockaddr *>(&addr6);
        addrLen = sizeof(addr6);
    }
    while (!closed_.load()) {
        pollfd fds[1] = {};
        int ret = WaitForPollEvent(fds[0]);
        if (ret < 0) {
            break;
        }
        if (ret == 0) {
            continue;
        }
        socklen_t tempAddrLen = addrLen;
        ssize_t recvLen = recvfrom(sockFd_, buf.get(), bufferSize, 0, addr, &tempAddrLen);
        if (recvLen < 0) {
            int errsv = errno;
            if (errsv == EAGAIN || errsv == EINTR) {
                continue;
            }
            EmitErrorEvent(errsv);
            break;
        }
        if (recvLen == 0) {
            EmitCloseEvent();
            break;
        }
        EmitMessageEvent(buf.get(), static_cast<size_t>(recvLen), addr);
    }
}

void CJTcpSocketProxy::EmitMessageEvent(void *data, size_t dataLen, sockaddr *addr)
{
    auto callback = FindCallback(EVENT_TYPE_MESSAGE);
    if (!callback.has_value()) {
        return;
    }
    CCallbackData cbData = {};
    cbData.typeId = EVENT_TYPE_MESSAGE;
    cbData.code = 0;
    if (dataLen <= 0) {
        return;
    }
    cbData.data.head = static_cast<uint8_t *>(malloc(dataLen));
    if (cbData.data.head != nullptr) {
        memcpy_s(cbData.data.head, dataLen, data, dataLen);
        cbData.data.size = static_cast<int64_t>(dataLen);
    }
    std::string address = MakeAddressString(addr);
    cbData.remoteInfo.address = MallocCString(address);
    if (addr->sa_family == AF_INET) {
        auto *addr4 = reinterpret_cast<sockaddr_in *>(addr);
        cbData.remoteInfo.port = ntohs(addr4->sin_port);
        cbData.remoteInfo.family = MallocCString("IPv4");
    } else if (addr->sa_family == AF_INET6) {
        auto *addr6 = reinterpret_cast<sockaddr_in6 *>(addr);
        cbData.remoteInfo.port = ntohs(addr6->sin6_port);
        cbData.remoteInfo.family = MallocCString("IPv6");
    }
    cbData.remoteInfo.size = static_cast<uint32_t>(dataLen);
    callback.value()(&cbData);
}

void CJTcpSocketProxy::EmitErrorEvent(int err)
{
    auto callback = FindCallback(EVENT_TYPE_ERROR);
    if (!callback.has_value()) {
        return;
    }
    CCallbackData cbData = {};
    cbData.typeId = EVENT_TYPE_ERROR;
    cbData.code = ConvertErrCode(err);
    callback.value()(&cbData);
}

void CJTcpSocketProxy::EmitCloseEvent()
{
    auto callback = FindCallback(EVENT_TYPE_CLOSE);
    if (!callback.has_value()) {
        return;
    }
    CCallbackData cbData = {};
    cbData.typeId = EVENT_TYPE_CLOSE;
    cbData.code = 0;
    callback.value()(&cbData);
}

void CJTcpSocketProxy::EmitConnectEvent()
{
    auto callback = FindCallback(EVENT_TYPE_CONNECT);
    if (!callback.has_value()) {
        return;
    }
    CCallbackData cbData = {};
    cbData.typeId = EVENT_TYPE_CONNECT;
    cbData.code = 0;
    callback.value()(&cbData);
}

int32_t CJTcpSocketImpl::Bind(CJTcpSocketProxy *proxy, const CNetAddress &cAddr)
{
    if (proxy == nullptr) {
        return ERR_INVALID_INSTANCE_CODE;
    }
    if (!CommonUtils::HasInternetPermission()) {
        NETSTACK_LOGE("INTERNET permission denied");
        return PERMISSION_DENIED_CODE;
    }
    NetAddress address;
    ParseCNetAddress(cAddr, address);
    int sockFd = proxy->GetSocketFd();
    if (sockFd < 0) {
        sockFd = MakeTcpSocket(address.GetSaFamily(), true);
        if (sockFd < 0) {
            return ConvertErrCode(errno);
        }
        proxy->SetSocketFd(sockFd);
        proxy->SetFamily(address.GetSaFamily());
        if (!ExecTcpBind(sockFd, address, proxy->GetReuseAddr())) {
            return ConvertErrCode(errno);
        }
    }
    return ERR_OK;
}

void CJTcpSocketImpl::OnConnectResult(int64_t proxyId, int32_t resultErrCode)
{
    auto proxy = OHOS::FFI::FFIData::GetData<CJTcpSocketProxy>(proxyId);
    if (proxy == nullptr) {
        NETSTACK_LOGE("Connect callback: proxy is null, id=%{public}" PRId64, proxyId);
        return;
    }
    proxy->SetAsyncConnecting(false);
    if (resultErrCode == 0) {
        proxy->StartRecvThread();
    }
    auto callback = proxy->GetConnectCallback();
    if (callback) {
        callback(resultErrCode);
    }
    if (resultErrCode == 0) {
        proxy->EmitConnectEvent();
    }
}

int32_t CJTcpSocketImpl::Connect(CJTcpSocketProxy *proxy, const CTcpConnectOptions &cOptions,
    int64_t callbackId)
{
    if (proxy == nullptr) {
        return ERR_INVALID_INSTANCE_CODE;
    }
    if (!CommonUtils::HasInternetPermission()) {
        NETSTACK_LOGE("INTERNET permission denied");
        return PERMISSION_DENIED_CODE;
    }
    NetAddress address;
    ParseCNetAddress(cOptions.address, address);
    TcpConnectOptions options;
    options.SetAddress(address);
    options.SetTimeout(cOptions.timeout);
    int sockFd = proxy->GetSocketFd();
    if (sockFd < 0) {
        sockFd = MakeTcpSocket(address.GetSaFamily(), true);
        if (sockFd < 0) {
            return ConvertErrCode(errno);
        }
        proxy->SetSocketFd(sockFd);
        proxy->SetFamily(address.GetSaFamily());
    }
    bool asyncConnecting = false;
    int errCode = 0;
    if (!ExecConnect(sockFd, options, nullptr, asyncConnecting, errCode)) {
        return ConvertErrCode(errCode);
    }
    proxy->SetAsyncConnecting(asyncConnecting);
    auto connectCallback = CJLambda::Create(reinterpret_cast<void (*)(int32_t)>(callbackId));
    if (asyncConnecting) {
        if (connectCallback) {
            proxy->SetConnectCallback(connectCallback);
        }
        int64_t proxyId = proxy->GetID();
        CjConnectMonitor::GetInstance().Register(sockFd, cOptions.timeout,
            [proxyId](int32_t resultErrCode) { OnConnectResult(proxyId, resultErrCode); });
        return ERR_OK;
    }
    proxy->StartRecvThread();
    if (connectCallback) {
        connectCallback(ERR_OK);
    }
    return ERR_OK;
}

int32_t CJTcpSocketImpl::Send(CJTcpSocketProxy *proxy, const CTcpSendOptions &cOptions)
{
    if (proxy == nullptr) {
        return ERR_INVALID_INSTANCE_CODE;
    }
    int sockFd = proxy->GetSocketFd();
    if (sockFd <= 0) {
        return ConvertErrCode(ERRNO_BAD_FD);
    }
    TcpSendOptions options;
    if (cOptions.data.head != nullptr && cOptions.data.size > 0) {
        options.SetData(cOptions.data.head, static_cast<size_t>(cOptions.data.size));
    }
    if (cOptions.encoding != nullptr) {
        options.SetEncoding(std::string(cOptions.encoding));
    }
    if (!ExecTcpSend(sockFd, options)) {
        return ConvertErrCode(errno);
    }
    return ERR_OK;
}

int32_t CJTcpSocketImpl::Close(CJTcpSocketProxy *proxy)
{
    if (proxy == nullptr) {
        return ERR_INVALID_INSTANCE_CODE;
    }
    int sockFd = proxy->GetSocketFd();
    if (sockFd < 0) {
        return ERR_OK;
    }
    CjConnectMonitor::GetInstance().Unregister(sockFd);
    proxy->StopRecvThread();
    if (!ExecClose(sockFd)) {
        return ConvertErrCode(errno);
    }
    proxy->SetSocketFd(-1);
    return ERR_OK;
}

CGetStateResult CJTcpSocketImpl::GetState(CJTcpSocketProxy *proxy)
{
    CGetStateResult result = {};
    if (proxy == nullptr) {
        result.code = ERR_INVALID_INSTANCE_CODE;
        return result;
    }
    int sockFd = proxy->GetSocketFd();
    if (sockFd < 0) {
        result.state.isClose = true;
        result.code = ERR_OK;
        return result;
    }
    SocketStateBase state;
    if (!ExecGetState(sockFd, state)) {
        result.code = ConvertErrCode(errno);
        return result;
    }
    result.code = ERR_OK;
    result.state.isBound = state.IsBound();
    result.state.isClose = state.IsClose();
    result.state.isConnected = state.IsConnected();
    return result;
}

CGetAddressResult CJTcpSocketImpl::GetRemoteAddress(CJTcpSocketProxy *proxy)
{
    CGetAddressResult result = {};
    if (proxy == nullptr) {
        result.code = ERR_INVALID_INSTANCE_CODE;
        return result;
    }
    int sockFd = proxy->GetSocketFd();
    if (sockFd < 0) {
        result.code = ConvertErrCode(ERRNO_BAD_FD);
        return result;
    }
    NetAddress address;
    if (!ExecGetRemoteAddress(sockFd, address)) {
        result.code = ConvertErrCode(errno);
        return result;
    }
    result.code = ERR_OK;
    result.address.address = MallocCString(address.GetAddress());
    result.address.family = address.GetJsValueFamily();
    result.address.port = address.GetPort();
    return result;
}

CGetAddressResult CJTcpSocketImpl::GetLocalAddress(CJTcpSocketProxy *proxy)
{
    CGetAddressResult result = {};
    if (proxy == nullptr) {
        result.code = ERR_INVALID_INSTANCE_CODE;
        return result;
    }
    int sockFd = proxy->GetSocketFd();
    if (sockFd < 0) {
        result.code = ConvertErrCode(ERRNO_BAD_FD);
        return result;
    }
    NetAddress address;
    if (!ExecGetLocalAddress(sockFd, address)) {
        result.code = ConvertErrCode(errno);
        return result;
    }
    result.code = ERR_OK;
    result.address.address = MallocCString(address.GetAddress());
    result.address.family = address.GetJsValueFamily();
    result.address.port = address.GetPort();
    return result;
}

CGetSocketFdResult CJTcpSocketImpl::GetSocketFd(CJTcpSocketProxy *proxy)
{
    CGetSocketFdResult result = {};
    if (proxy == nullptr) {
        result.code = ERR_INVALID_INSTANCE_CODE;
        return result;
    }
    result.code = ERR_OK;
    result.fd = proxy->GetSocketFd();
    return result;
}

int32_t CJTcpSocketImpl::SetExtraOptions(CJTcpSocketProxy *proxy, const CTcpExtraOptions &cOptions)
{
    if (proxy == nullptr) {
        return ERR_INVALID_INSTANCE_CODE;
    }
    int sockFd = proxy->GetSocketFd();
    if (sockFd <= 0) {
        return ConvertErrCode(ERRNO_BAD_FD);
    }
    TCPExtraOptions options;
    ParseCTcpExtraOptions(cOptions, options);
    if (cOptions.hasReuseAddress) {
        proxy->SetReuseAddr(cOptions.reuseAddress);
    }
    if (!ExecTcpSetExtraOptions(sockFd, options)) {
        return ConvertErrCode(errno);
    }
    return ERR_OK;
}

int32_t CJTcpSocketImpl::OnController(CJTcpSocketProxy *proxy, int32_t typeId,
    SocketCallback callback)
{
    if (proxy == nullptr) {
        return ERR_INVALID_INSTANCE_CODE;
    }
    proxy->AddCallback2Map(typeId, callback);
    return ERR_OK;
}

int32_t CJTcpSocketImpl::OffController(CJTcpSocketProxy *proxy, int32_t typeId)
{
    if (proxy == nullptr) {
        return ERR_INVALID_INSTANCE_CODE;
    }
    proxy->DelCallback(typeId);
    return ERR_OK;
}

}
