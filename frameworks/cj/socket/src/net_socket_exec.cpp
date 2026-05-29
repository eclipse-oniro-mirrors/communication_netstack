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

#include "net_socket_exec.h"

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "netstack_log.h"
#include "securec.h"

namespace OHOS::NetStack::Socket {

NetAddress::NetAddress() : family_(Family::IPv4), port_(0) {}

void NetAddress::SetRawAddress(const std::string &address)
{
    address_ = address;
}

void NetAddress::SetIpAddress(const std::string &address)
{
    SetIpAddressInner(address);
}

void NetAddress::SetIpAddressInner(const std::string &address)
{
    if (address.empty()) {
        return;
    }
    if (address == "localhost" || address == "127.0.0.1") {
        address_ = "127.0.0.1";
        family_ = Family::IPv4;
        return;
    }
    in_addr ipv4;
    if (inet_pton(AF_INET, address.c_str(), &ipv4) > 0) {
        address_ = address;
        family_ = Family::IPv4;
        return;
    }
    in6_addr ipv6;
    if (inet_pton(AF_INET6, address.c_str(), &ipv6) > 0) {
        address_ = address;
        family_ = Family::IPv6;
        return;
    }
    address_ = address;
}

void NetAddress::SetAddress(const std::string &address)
{
    SetIpAddress(address);
}

void NetAddress::SetFamilyByJsValue(uint32_t family)
{
    if (family == static_cast<uint32_t>(Family::IPv4)) {
        family_ = Family::IPv4;
    } else if (family == static_cast<uint32_t>(Family::IPv6)) {
        family_ = Family::IPv6;
    } else if (family == static_cast<uint32_t>(Family::DOMAIN_NAME)) {
        family_ = Family::DOMAIN_NAME;
    }
}

void NetAddress::SetFamilyBySaFamily(sa_family_t family)
{
    if (family == AF_INET6) {
        family_ = Family::IPv6;
    } else {
        family_ = Family::IPv4;
    }
}

void NetAddress::SetPort(uint16_t port)
{
    port_ = port;
}

const std::string &NetAddress::GetAddress() const
{
    return address_;
}

uint32_t NetAddress::GetJsValueFamily() const
{
    return static_cast<uint32_t>(family_);
}

sa_family_t NetAddress::GetSaFamily() const
{
    if (family_ == Family::IPv6) {
        return AF_INET6;
    }
    return AF_INET;
}

uint16_t NetAddress::GetPort() const
{
    return port_;
}

NetAddress::Family NetAddress::GetFamily() const
{
    return family_;
}

NetAddress &NetAddress::operator=(const NetAddress &other)
{
    if (this != &other) {
        address_ = other.address_;
        family_ = other.family_;
        port_ = other.port_;
    }
    return *this;
}

SocketStateBase::SocketStateBase() : isBound_(false), isClose_(false), isConnected_(false) {}

void SocketStateBase::SetIsBound(bool isBound)
{
    isBound_ = isBound;
}

void SocketStateBase::SetIsClose(bool isClose)
{
    isClose_ = isClose;
}

void SocketStateBase::SetIsConnected(bool isConnected)
{
    isConnected_ = isConnected;
}

bool SocketStateBase::IsBound() const
{
    return isBound_;
}

bool SocketStateBase::IsClose() const
{
    return isClose_;
}

bool SocketStateBase::IsConnected() const
{
    return isConnected_;
}

SocketRemoteInfo::SocketRemoteInfo() : port_(0), size_(0) {}

void SocketRemoteInfo::SetAddress(const std::string &address)
{
    address_ = address;
}

void SocketRemoteInfo::SetFamily(sa_family_t family)
{
    if (family == AF_INET) {
        family_ = "IPv4";
    } else if (family == AF_INET6) {
        family_ = "IPv6";
    } else {
        family_ = "Others";
    }
}

void SocketRemoteInfo::SetPort(uint16_t port)
{
    port_ = port;
}

void SocketRemoteInfo::SetSize(uint32_t size)
{
    size_ = size;
}

void SocketRemoteInfo::SetFamilyByStr(const std::string family)
{
    family_ = family;
}

const std::string &SocketRemoteInfo::GetAddress() const
{
    return address_;
}

const std::string &SocketRemoteInfo::GetFamily() const
{
    return family_;
}

uint16_t SocketRemoteInfo::GetPort() const
{
    return port_;
}

uint32_t SocketRemoteInfo::GetSize() const
{
    return size_;
}

ExtraOptionsBase::ExtraOptionsBase()
    : receiveBufferSize_(0), sendBufferSize_(0), reuseAddress_(false), socketTimeout_(0) {}

void ExtraOptionsBase::SetReceiveBufferSize(uint32_t receiveBufferSize)
{
    receiveBufferSize_ = receiveBufferSize;
}

void ExtraOptionsBase::SetSendBufferSize(uint32_t sendBufferSize)
{
    sendBufferSize_ = sendBufferSize;
}

void ExtraOptionsBase::SetReuseAddress(bool reuseAddress)
{
    reuseAddress_ = reuseAddress;
}

void ExtraOptionsBase::SetSocketTimeout(uint32_t socketTimeout)
{
    socketTimeout_ = socketTimeout;
}

uint32_t ExtraOptionsBase::GetReceiveBufferSize() const
{
    return receiveBufferSize_;
}

uint32_t ExtraOptionsBase::GetSendBufferSize() const
{
    return sendBufferSize_;
}

bool ExtraOptionsBase::IsReuseAddress() const
{
    return reuseAddress_;
}

uint32_t ExtraOptionsBase::GetSocketTimeout() const
{
    return socketTimeout_;
}

bool ExtraOptionsBase::AlreadySetRecvBufSize() const
{
    return recvBufSizeFlag_;
}

void ExtraOptionsBase::SetRecvBufSizeFlag(bool flag)
{
    recvBufSizeFlag_ = flag;
}

bool ExtraOptionsBase::AlreadySetSendBufSize() const
{
    return sendBufSizeFlag_;
}

void ExtraOptionsBase::SetSendBufSizeFlag(bool flag)
{
    sendBufSizeFlag_ = flag;
}

bool ExtraOptionsBase::AlreadySetTimeout() const
{
    return timeoutFlag_;
}

void ExtraOptionsBase::SetTimeoutFlag(bool flag)
{
    timeoutFlag_ = flag;
}

bool ExtraOptionsBase::AlreadySetReuseAddr() const
{
    return reuseAddrFlag_;
}

void ExtraOptionsBase::SetReuseaddrFlag(bool flag)
{
    reuseAddrFlag_ = flag;
}

SocketLinger::SocketLinger() : on_(false), linger_(0) {}

void SocketLinger::SetOn(bool on)
{
    on_ = on;
}

void SocketLinger::SetLinger(uint32_t linger)
{
    linger_ = linger;
}

bool SocketLinger::IsOn() const
{
    return on_;
}

uint32_t SocketLinger::GetLinger() const
{
    return linger_;
}

TCPExtraOptions::TCPExtraOptions()
    : keepAlive_(false), OOBInline_(false), TCPNoDelay_(false), TCPFastOpen_(false) {}

void TCPExtraOptions::SetKeepAlive(bool keepAlive)
{
    keepAlive_ = keepAlive;
}

void TCPExtraOptions::SetOOBInline(bool OOBInline)
{
    OOBInline_ = OOBInline;
}

void TCPExtraOptions::SetTCPNoDelay(bool TCPNoDelay)
{
    TCPNoDelay_ = TCPNoDelay;
}

void TCPExtraOptions::SetTCPFastOpen(bool TCPFastOpen)
{
    TCPFastOpen_ = TCPFastOpen;
}

bool TCPExtraOptions::IsKeepAlive() const
{
    return keepAlive_;
}

bool TCPExtraOptions::IsOOBInline() const
{
    return OOBInline_;
}

bool TCPExtraOptions::IsTCPNoDelay() const
{
    return TCPNoDelay_;
}

bool TCPExtraOptions::IsTCPFastOpen() const
{
    return TCPFastOpen_;
}

bool TCPExtraOptions::AlreadySetKeepAlive() const
{
    return keepAliveFlag_;
}

void TCPExtraOptions::SetKeepAliveFlag(bool flag)
{
    keepAliveFlag_ = flag;
}

bool TCPExtraOptions::AlreadySetOobInline() const
{
    return oobInlineFlag_;
}

void TCPExtraOptions::SetOobInlineFlag(bool flag)
{
    oobInlineFlag_ = flag;
}

bool TCPExtraOptions::AlreadySetTcpNoDelay() const
{
    return tcpNoDelayFlag_;
}

void TCPExtraOptions::SetTcpNoDelayFlag(bool flag)
{
    tcpNoDelayFlag_ = flag;
}

bool TCPExtraOptions::AlreadySetTCPFastOpen() const
{
    return tcpFastOpenFlag_;
}

void TCPExtraOptions::SetTcpFastOpenFlag(bool flag)
{
    tcpFastOpenFlag_ = flag;
}

bool TCPExtraOptions::AlreadySetLinger() const
{
    return lingerFlag_;
}

void TCPExtraOptions::SetLingerFlag(bool flag)
{
    lingerFlag_ = flag;
}

TcpConnectOptions::TcpConnectOptions() : timeout_(DEFAULT_CONNECT_TIMEOUT) {}

void TcpConnectOptions::SetAddress(const NetAddress &address)
{
    address_ = address;
}

void TcpConnectOptions::SetTimeout(uint32_t timeout)
{
    timeout_ = timeout;
}

NetAddress &TcpConnectOptions::GetMutableAddress()
{
    return address_;
}

const NetAddress &TcpConnectOptions::GetAddress() const
{
    return address_;
}

uint32_t TcpConnectOptions::GetTimeout() const
{
    return timeout_;
}

TcpSendOptions::TcpSendOptions() {}

void TcpSendOptions::SetData(const std::string &data)
{
    data_ = data;
}

void TcpSendOptions::SetData(void *data, size_t size)
{
    if (data != nullptr && size > 0) {
        data_.append(reinterpret_cast<char *>(data), size);
    }
}

void TcpSendOptions::SetEncoding(const std::string &encoding)
{
    encoding_ = encoding;
}

const std::string &TcpSendOptions::GetData() const
{
    return data_;
}

const std::string &TcpSendOptions::GetEncoding() const
{
    return encoding_;
}

ProxyOptions::ProxyOptions() {}

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

static bool IsTfoEnabled(int sock)
{
    int tfoEnabled = 0;
    socklen_t tfoLen = sizeof(tfoEnabled);
    if (getsockopt(sock, SOL_TCP, TCP_FASTOPEN_CONNECT, &tfoEnabled, &tfoLen) != 0) {
        NETSTACK_LOGE("get TFO failed, fd=%{public}d, errno=%{public}d", sock, errno);
        tfoEnabled = 0;
    }
    return tfoEnabled != 0;
}

static bool SetBaseOptions(int sock, ExtraOptionsBase *option)
{
    if (option->AlreadySetRecvBufSize()) {
        int size = static_cast<int>(option->GetReceiveBufferSize());
        if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<void *>(&size), sizeof(size)) < 0) {
            NETSTACK_LOGE("set SO_RCVBUF failed, fd: %{public}d", sock);
            return false;
        }
    }
    if (option->AlreadySetSendBufSize()) {
        int size = static_cast<int>(option->GetSendBufferSize());
        if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<void *>(&size), sizeof(size)) < 0) {
            NETSTACK_LOGE("set SO_SNDBUF failed, fd: %{public}d", sock);
            return false;
        }
    }
    if (option->AlreadySetReuseAddr()) {
        int reuse = static_cast<int>(option->IsReuseAddress());
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<void *>(&reuse), sizeof(reuse)) < 0) {
            NETSTACK_LOGE("set SO_REUSEADDR failed, fd: %{public}d", sock);
            return false;
        }
    }
    if (option->AlreadySetTimeout()) {
        int value = static_cast<int>(option->GetSocketTimeout());
        timeval timeout = {value / UNIT_CONVERSION_1000, (value % UNIT_CONVERSION_1000) * UNIT_CONVERSION_1000};
        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<void *>(&timeout), sizeof(timeout)) < 0) {
            NETSTACK_LOGE("set SO_RCVTIMEO failed, fd: %{public}d", sock);
            return false;
        }
        if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<void *>(&timeout), sizeof(timeout)) < 0) {
            NETSTACK_LOGE("set SO_SNDTIMEO failed, fd: %{public}d", sock);
            return false;
        }
    }
    return true;
}

static bool SocketSetTcpExtraOptions(int sockfd, TCPExtraOptions &option)
{
    if (!SetBaseOptions(sockfd, &option)) {
        return false;
    }
    if (option.AlreadySetKeepAlive()) {
        int alive = static_cast<int>(option.IsKeepAlive());
        if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<void *>(&alive), sizeof(alive)) < 0) {
            NETSTACK_LOGE("set SO_KEEPALIVE failed, fd: %{public}d", sockfd);
            return false;
        }
    }
    if (option.AlreadySetOobInline()) {
        int oob = static_cast<int>(option.IsOOBInline());
        if (setsockopt(sockfd, SOL_SOCKET, SO_OOBINLINE, reinterpret_cast<void *>(&oob), sizeof(oob)) < 0) {
            NETSTACK_LOGE("set SO_OOBINLINE failed, fd: %{public}d", sockfd);
            return false;
        }
    }
    if (option.AlreadySetTcpNoDelay()) {
        int noDelay = static_cast<int>(option.IsTCPNoDelay());
        if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<void *>(&noDelay), sizeof(noDelay)) < 0) {
            NETSTACK_LOGE("set TCP_NODELAY failed, fd: %{public}d", sockfd);
            return false;
        }
    }
    if (option.IsTCPFastOpen()) {
        int fastOpen = 1;
        if (setsockopt(sockfd, SOL_TCP, TCP_FASTOPEN_CONNECT, &fastOpen, sizeof(fastOpen)) < 0) {
            NETSTACK_LOGE("set SOL_TCP TFO failed! fd=%{public}d, errno=%{public}d", sockfd, errno);
            return false;
        }
    }
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

bool MakeNonBlock(int sock)
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

int MakeTcpSocket(sa_family_t family, bool needNonblock)
{
    if (family != AF_INET && family != AF_INET6) {
        return -1;
    }
    int sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
    NETSTACK_LOGI("new tcp socket is %{public}d", sock);
    if (sock < 0) {
        NETSTACK_LOGE("make tcp socket failed, errno is %{public}d", errno);
        return -1;
    }
    if (needNonblock && !MakeNonBlock(sock)) {
        close(sock);
        return -1;
    }
    return sock;
}

std::string ConvertAddressToIp(const std::string &address, sa_family_t family)
{
    if (address.empty()) {
        return {};
    }
    addrinfo hints{};
    hints.ai_family = family;
    char ipStr[INET6_ADDRSTRLEN] = {0};
    addrinfo *res = nullptr;
    auto status = getaddrinfo(address.c_str(), nullptr, &hints, &res);
    if (status != 0 || res == nullptr) {
        return {};
    }
    std::string ip;
    if (res->ai_family == AF_INET) {
        auto *ipv4 = reinterpret_cast<struct sockaddr_in *>(res->ai_addr);
        auto addr = &(ipv4->sin_addr);
        inet_ntop(res->ai_family, addr, ipStr, sizeof(ipStr));
        ip = ipStr;
    } else {
        auto *ipv6 = reinterpret_cast<struct sockaddr_in6 *>(res->ai_addr);
        auto addr = &(ipv6->sin6_addr);
        inet_ntop(res->ai_family, addr, ipStr, sizeof(ipStr));
        ip = ipStr;
    }
    freeaddrinfo(res);
    return ip;
}

bool IpMatchFamily(const std::string &address, sa_family_t family)
{
    if (family == AF_INET6) {
        in_addr ipv4{};
        if (inet_pton(AF_INET, address.c_str(), &(ipv4.s_addr)) > 0) {
            return false;
        }
    } else if (family == AF_INET) {
        in6_addr ipv6{};
        if (inet_pton(AF_INET6, address.c_str(), &ipv6) > 0) {
            return false;
        }
    }
    return true;
}

static bool HandlePollEvent(struct pollfd *fds)
{
    if (fds == nullptr) {
        return false;
    }
    if (static_cast<uint16_t>(fds[0].revents) & (POLLNVAL | POLLHUP | POLLERR)) {
        NETSTACK_LOGE("NonBlockConnect poll failed, socket is %{public}d, revents is %{public}x",
            fds[0].fd, fds[0].revents);
        return false;
    }
    int err = 0;
    socklen_t optLen = sizeof(err);
    int ret = getsockopt(fds[0].fd, SOL_SOCKET, SO_ERROR, reinterpret_cast<void *>(&err), &optLen);
    if (ret < 0) {
        return false;
    }
    if (err != 0) {
        NETSTACK_LOGE("NonBlockConnect exec failed, socket is %{public}d, err is %{public}d", fds[0].fd, err);
        return false;
    }
    return true;
}

bool NonBlockConnect(int sock, sockaddr *addr, socklen_t addrLen, uint32_t timeoutMSec)
{
    int ret = connect(sock, addr, addrLen);
    if (ret >= 0) {
        return true;
    }
    if (errno != EINPROGRESS) {
        return false;
    }
    struct pollfd fds[1] = {{.fd = sock, .events = POLLOUT}};
    int timeoutMs = (timeoutMSec == 0) ? DEFAULT_CONNECT_TIMEOUT : timeoutMSec;
    while (true) {
        auto startTime = std::chrono::steady_clock::now();
        ret = poll(fds, 1, timeoutMs);
        if (ret > 0) {
            break;
        } else if (ret == 0) {
            NETSTACK_LOGE("connect poll timeout, socket is %{public}d", sock);
            return false;
        }
        if (errno == EINTR) {
            auto endTime = std::chrono::steady_clock::now();
            auto intervalMs = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
            timeoutMs -= static_cast<int>(intervalMs.count());
            if (timeoutMs <= 0) {
                NETSTACK_LOGE("invalid timeout");
                return false;
            }
            continue;
        }
        NETSTACK_LOGE("connect poll failed, socket is %{public}d, errno is %{public}d", sock, errno);
        return false;
    }
    return HandlePollEvent(fds);
}

static bool GetSendBufferSize(int sock, int &bufferSize, int &sockType)
{
    int opt = 0;
    socklen_t optLen = sizeof(opt);
    bufferSize = DEFAULT_BUFFER_SIZE;
    if (getsockopt(sock, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<void *>(&opt), &optLen) >= 0 && opt > 0) {
        bufferSize = opt;
    }
    sockType = 0;
    optLen = sizeof(sockType);
    if (getsockopt(sock, SOL_SOCKET, SO_TYPE, reinterpret_cast<void *>(&sockType), &optLen) < 0) {
        return false;
    }
    return true;
}

bool PollSendData(int sock, const char *data, size_t size, sockaddr *addr, socklen_t addrLen)
{
    NETSTACK_LOGD("js send RawSize: %{public}zu", size);
    int bufferSize = DEFAULT_BUFFER_SIZE;
    int sockType = 0;
    if (!GetSendBufferSize(sock, bufferSize, sockType)) {
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
    int sendTimeoutMs = ConfirmSocketTimeoutMs(sock, SO_SNDTIMEO, DEFAULT_TIMEOUT_MS);
    if (sendTimeoutMs < 0) {
        return false;
    }
    bool tfoEnabled = IsTfoEnabled(sock);
    while (leftSize > 0) {
        if (!PollFd(fds, num, sendTimeoutMs)) {
            if (errno != EINTR) {
                return false;
            }
        }
        size_t sendSize = (sockType == SOCK_STREAM ? leftSize : std::min<size_t>(leftSize, bufferSize));
        ssize_t sendLen = tfoEnabled ? send(sock, curPos, sendSize, 0)
            : sendto(sock, curPos, sendSize, 0, addr, addrLen);
        NETSTACK_LOGD("socketFD: %{public}d, send len: %{public}zu", sock, sendLen);
        if (sendLen < 0) {
            if (errno == EAGAIN || errno == EINTR) {
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

int ConfirmSocketTimeoutMs(int sock, int type, int defaultValue)
{
    timeval timeout;
    socklen_t optlen = sizeof(timeout);
    if (getsockopt(sock, SOL_SOCKET, type, reinterpret_cast<void *>(&timeout), &optlen) < 0) {
        NETSTACK_LOGE("get timeout failed, type: %{public}d, sock: %{public}d, errno: %{public}d", type, sock, errno);
        if (errno == ENOTSOCK && type == SO_RCVTIMEO) {
            return -1;
        }
        return defaultValue;
    }
    auto socketTimeoutMs = timeout.tv_sec * UNIT_CONVERSION_1000 + timeout.tv_usec / UNIT_CONVERSION_1000;
    return socketTimeoutMs == 0 ? defaultValue : socketTimeoutMs;
}

int ConfirmBufferSize(int sock)
{
    int bufferSize = DEFAULT_BUFFER_SIZE;
    int opt = 0;
    socklen_t optLen = sizeof(opt);
    if (getsockopt(sock, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<void *>(&opt), &optLen) >= 0 && opt > 0) {
        bufferSize = opt;
    }
    return bufferSize;
}

void ParseCNetAddress(const CNetAddress &cAddr, NetAddress &addr)
{
    if (cAddr.address != nullptr) {
        addr.SetIpAddress(std::string(cAddr.address));
    }
    addr.SetFamilyByJsValue(cAddr.family);
    addr.SetPort(cAddr.port);
}

void ParseCProxyOptions(const CProxyOptions &cProxy, ProxyOptions &proxy)
{
    ParseCNetAddress(cProxy.address, proxy.address_);
    proxy.type_ = cProxy.type;
    if (cProxy.username != nullptr) {
        proxy.username_ = std::string(cProxy.username);
    }
    if (cProxy.password != nullptr) {
        proxy.password_ = std::string(cProxy.password);
    }
}

void ParseCTcpExtraOptions(const CTcpExtraOptions &cOpts, TCPExtraOptions &opts)
{
    if (cOpts.hasReceiveBufferSize) {
        opts.SetRecvBufSizeFlag(true);
        opts.SetReceiveBufferSize(cOpts.receiveBufferSize);
    }
    if (cOpts.hasSendBufferSize) {
        opts.SetSendBufSizeFlag(true);
        opts.SetSendBufferSize(cOpts.sendBufferSize);
    }
    if (cOpts.hasReuseAddress) {
        opts.SetReuseaddrFlag(true);
        opts.SetReuseAddress(cOpts.reuseAddress);
    }
    if (cOpts.hasSocketTimeout) {
        opts.SetTimeoutFlag(true);
        opts.SetSocketTimeout(cOpts.socketTimeout);
    }
    if (cOpts.hasKeepAlive) {
        opts.SetKeepAliveFlag(true);
        opts.SetKeepAlive(cOpts.keepAlive);
    }
    if (cOpts.hasOOBInline) {
        opts.SetOobInlineFlag(true);
        opts.SetOOBInline(cOpts.OOBInline);
    }
    if (cOpts.hasTCPNoDelay) {
        opts.SetTcpNoDelayFlag(true);
        opts.SetTCPNoDelay(cOpts.TCPNoDelay);
    }
    if (cOpts.hasTCPFastOpen) {
        opts.SetTcpFastOpenFlag(true);
        opts.SetTCPFastOpen(cOpts.TCPFastOpen);
    }
    if (cOpts.hasLinger) {
        opts.SetLingerFlag(true);
        opts.socketLinger.SetOn(cOpts.linger.on);
        opts.socketLinger.SetLinger(cOpts.linger.linger);
    }
}

static bool HandleNonProxyConnection(int sockFd, const TcpConnectOptions &options, bool &asyncConnecting, int &errCode)
{
    sockaddr_in addr4 = {0};
    sockaddr_in6 addr6 = {0};
    sockaddr *addr = nullptr;
    socklen_t len;
    NetAddress targetAddr = options.GetAddress();
    GetAddr(&targetAddr, &addr4, &addr6, &addr, &len);
    if (addr == nullptr) {
        NETSTACK_LOGE("addr family error, address invalid");
        errCode = ADDRESS_INVALID;
        return false;
    }
    int ret = connect(sockFd, addr, len);
    if (ret == 0) {
        asyncConnecting = false;
        errCode = 0;
        return true;
    }
    int savedErrno = errno;
    if (savedErrno == EINPROGRESS || savedErrno == EALREADY) {
        asyncConnecting = true;
        errCode = 0;
        return true;
    }
    NETSTACK_LOGE("connect errno %{public}d", savedErrno);
    errCode = savedErrno;
    return false;
}

static bool TcpSendEvent(int sockFd, const TcpSendOptions &options)
{
    bool tfoEnabled = IsTfoEnabled(sockFd);
    sockaddr sockAddr = {0};
    socklen_t len = sizeof(sockaddr);
    if (getsockname(sockFd, &sockAddr, &len) < 0) {
        NETSTACK_LOGE("getsockname failed, sock:%{public}d, errno:%{public}d", sockFd, errno);
        return false;
    }
    bool connected = false;
    if (sockAddr.sa_family == AF_INET) {
        sockaddr_in addr4 = {0};
        socklen_t len4 = sizeof(addr4);
        int ret = getpeername(sockFd, reinterpret_cast<sockaddr *>(&addr4), &len4);
        if (ret >= 0 && addr4.sin_port != 0) {
            connected = true;
        }
    } else if (sockAddr.sa_family == AF_INET6) {
        sockaddr_in6 addr6 = {0};
        socklen_t len6 = sizeof(addr6);
        int ret = getpeername(sockFd, reinterpret_cast<sockaddr *>(&addr6), &len6);
        if (ret >= 0 && addr6.sin6_port != 0) {
            connected = true;
        }
    }
    if (!connected && !tfoEnabled) {
        NETSTACK_LOGE("sock is not connect to remote, socket is %{public}d, errno is %{public}d", sockFd, errno);
        return false;
    }
    if (!PollSendData(sockFd, options.GetData().c_str(), options.GetData().size(), nullptr, 0)) {
        NETSTACK_LOGE("send failed, socket is %{public}d, errno is %{public}d", sockFd, errno);
        return false;
    }
    return true;
}

static void SetIsBound(sa_family_t family, SocketStateBase &state, const sockaddr_in *addr4,
                       const sockaddr_in6 *addr6)
{
    if (family == AF_INET) {
        state.SetIsBound(ntohs(addr4->sin_port) != 0);
    } else if (family == AF_INET6) {
        state.SetIsBound(ntohs(addr6->sin6_port) != 0);
    }
}

static void SetIsConnected(sa_family_t family, SocketStateBase &state, const sockaddr_in *addr4,
                           const sockaddr_in6 *addr6)
{
    if (family == AF_INET) {
        state.SetIsConnected(ntohs(addr4->sin_port) != 0);
    } else if (family == AF_INET6) {
        state.SetIsConnected(ntohs(addr6->sin6_port) != 0);
    }
}

bool ExecTcpBind(int sockFd, const NetAddress &address, bool reuseAddr)
{
    sockaddr_in addr4 = {0};
    sockaddr_in6 addr6 = {0};
    sockaddr *addr = nullptr;
    socklen_t len;
    NetAddress bindAddr = address;
    GetAddr(&bindAddr, &addr4, &addr6, &addr, &len);
    if (addr == nullptr) {
        NETSTACK_LOGE("addr family error, address invalid");
        return false;
    }
    if (sockFd < 0) {
        NETSTACK_LOGE("fd is nullptr or closed");
        return false;
    }
    int reuse = static_cast<int>(reuseAddr);
    if (setsockopt(sockFd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<void *>(&reuse), sizeof(reuse)) < 0) {
        NETSTACK_LOGE("set SO_REUSEADDR failed, fd: %{public}d", sockFd);
        return false;
    }
    if (bind(sockFd, addr, len) < 0) {
        if (errno != EADDRINUSE) {
            NETSTACK_LOGE("bind failed, socket:%{public}d, errno:%{public}d", sockFd, errno);
            return false;
        }
        if (addr->sa_family == AF_INET) {
            NETSTACK_LOGI("distribute a random port");
            addr4.sin_port = 0;
        } else if (addr->sa_family == AF_INET6) {
            NETSTACK_LOGI("distribute a random port");
            addr6.sin6_port = 0;
        }
        if (bind(sockFd, addr, len) < 0) {
            NETSTACK_LOGE("rebind failed, socket:%{public}d, errno:%{public}d", sockFd, errno);
            return false;
        }
        NETSTACK_LOGI("rebind success");
    }
    NETSTACK_LOGI("bind success, sock:%{public}d", sockFd);
    return true;
}

bool ExecConnect(int sockFd, const TcpConnectOptions &options, const ProxyOptions *proxy,
    bool &asyncConnecting, int &errCode)
{
    TcpConnectOptions resolvedOptions = options;
    resolvedOptions.GetMutableAddress().SetRawAddress(
        ConvertAddressToIp(options.GetAddress().GetAddress(), options.GetAddress().GetSaFamily()));

    if (proxy == nullptr) {
        return HandleNonProxyConnection(sockFd, resolvedOptions, asyncConnecting, errCode);
    }
    NETSTACK_LOGI("proxy connect not fully supported in CFFI layer, falling back to direct connect");
    return HandleNonProxyConnection(sockFd, resolvedOptions, asyncConnecting, errCode);
}

bool ExecTcpSend(int sockFd, const TcpSendOptions &options)
{
    if (sockFd <= 0) {
        NETSTACK_LOGE("bad fd, socket is %{public}d", sockFd);
        return false;
    }
    return TcpSendEvent(sockFd, options);
}

bool ExecClose(int sockFd)
{
    if (sockFd < 0) {
        NETSTACK_LOGE("sock %{public}d is previous closed", sockFd);
        return false;
    }
    int ret = close(sockFd);
    if (ret < 0) {
        NETSTACK_LOGE("sock closed failed, socket is %{public}d, errno is %{public}d", sockFd, errno);
        return false;
    }
    NETSTACK_LOGI("sock closed success");
    return true;
}

bool ExecGetState(int sockFd, SocketStateBase &state)
{
    if (sockFd < 0) {
        NETSTACK_LOGE("fd is nullptr or closed");
        state.SetIsClose(true);
        return true;
    }
    int opt;
    socklen_t optLen = sizeof(int);
    int r = getsockopt(sockFd, SOL_SOCKET, SO_TYPE, &opt, &optLen);
    if (r < 0) {
        state.SetIsClose(true);
        return true;
    }
    sockaddr sockAddr = {0};
    socklen_t len = sizeof(sockaddr);
    int ret = getsockname(sockFd, &sockAddr, &len);
    if (ret < 0) {
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
        return false;
    }
    (void)memset_s(addr, addrLen, 0, addrLen);
    socklen_t nameLen = addrLen;
    ret = getsockname(sockFd, addr, &nameLen);
    if (ret < 0) {
        return false;
    }
    SetIsBound(sockAddr.sa_family, state, &addr4, &addr6);
    if (opt != SOCK_STREAM) {
        return true;
    }
    (void)memset_s(addr, addrLen, 0, addrLen);
    nameLen = addrLen;
    (void)getpeername(sockFd, addr, &nameLen);
    SetIsConnected(sockAddr.sa_family, state, &addr4, &addr6);
    return true;
}

bool ExecGetRemoteAddress(int sockFd, NetAddress &address)
{
    sockaddr sockAddr = {0};
    socklen_t len = sizeof(sockaddr);
    int ret = getsockname(sockFd, &sockAddr, &len);
    if (ret < 0) {
        return false;
    }
    if (sockAddr.sa_family == AF_INET) {
        sockaddr_in addr4 = {0};
        socklen_t len4 = sizeof(sockaddr_in);
        ret = getpeername(sockFd, reinterpret_cast<sockaddr *>(&addr4), &len4);
        std::string addrStr = MakeAddressString(reinterpret_cast<sockaddr *>(&addr4));
        if (ret < 0 || addrStr.empty()) {
            return false;
        }
        address.SetRawAddress(addrStr);
        address.SetFamilyBySaFamily(sockAddr.sa_family);
        address.SetPort(ntohs(addr4.sin_port));
        return true;
    } else if (sockAddr.sa_family == AF_INET6) {
        sockaddr_in6 addr6 = {0};
        socklen_t len6 = sizeof(sockaddr_in6);
        ret = getpeername(sockFd, reinterpret_cast<sockaddr *>(&addr6), &len6);
        std::string addrStr = MakeAddressString(reinterpret_cast<sockaddr *>(&addr6));
        if (ret < 0 || addrStr.empty()) {
            return false;
        }
        address.SetRawAddress(addrStr);
        address.SetFamilyBySaFamily(sockAddr.sa_family);
        address.SetPort(ntohs(addr6.sin6_port));
        return true;
    }
    return false;
}

bool ExecGetLocalAddress(int sockFd, NetAddress &address)
{
    struct sockaddr_storage addr{};
    socklen_t addrLen = sizeof(addr);
    if (getsockname(sockFd, reinterpret_cast<struct sockaddr *>(&addr), &addrLen) < 0) {
        return false;
    }
    char ipStr[INET6_ADDRSTRLEN] = {0};
    if (addr.ss_family == AF_INET) {
        auto *addrIn = reinterpret_cast<struct sockaddr_in *>(&addr);
        inet_ntop(AF_INET, &addrIn->sin_addr, ipStr, sizeof(ipStr));
        address.SetFamilyBySaFamily(AF_INET);
        address.SetRawAddress(ipStr);
        address.SetPort(ntohs(addrIn->sin_port));
    } else if (addr.ss_family == AF_INET6) {
        auto *addrIn6 = reinterpret_cast<struct sockaddr_in6 *>(&addr);
        inet_ntop(AF_INET6, &addrIn6->sin6_addr, ipStr, sizeof(ipStr));
        address.SetFamilyBySaFamily(AF_INET6);
        address.SetRawAddress(ipStr);
        address.SetPort(ntohs(addrIn6->sin6_port));
    }
    return true;
}

bool ExecTcpSetExtraOptions(int sockFd, const TCPExtraOptions &options)
{
    if (sockFd <= 0) {
        NETSTACK_LOGE("bad fd, socket is %{public}d", sockFd);
        return false;
    }
    TCPExtraOptions opts = options;
    if (!SocketSetTcpExtraOptions(sockFd, opts)) {
        return false;
    }
    return true;
}

char *MallocCString(const std::string &origin)
{
    if (origin.empty()) {
        return nullptr;
    }
    auto len = origin.length() + 1;
    char *res = static_cast<char *>(malloc(sizeof(char) * len));
    if (res == nullptr) {
        return nullptr;
    }
    return std::char_traits<char>::copy(res, origin.c_str(), len);
}

}
