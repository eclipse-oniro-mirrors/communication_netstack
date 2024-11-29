/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "socks5_instance.h"

#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/tcp.h>

#include "netstack_log.h"
#include "socket_exec.h"
#include "socket_exec_common.h"
#include "socks5_none_method.h"
#include "socks5_passwd_method.h"
#include "socks5_package.h"
#include "socks5_utils.h"
#include "securec.h"

static constexpr const int INET_SOCKS5_UDP_HEADER_LEN = 10;

static constexpr const int INET6_SOCKS5_UDP_HEADER_LEN = 22;

static constexpr const int SOCKS5_DO_CONNECT_COUNT_MAX = 3;

namespace OHOS {
namespace NetStack {
namespace Socks5 {

void Socks5Instance::SetSocks5Option(const std::shared_ptr<Socks5Option> &opt)
{
    options_ = opt;
}

void Socks5Instance::SetDestAddress(const Socket::NetAddress &dest)
{
    this->dest_ = dest;
}

bool Socks5Instance::IsConnected() const
{
    return state_ == Socks5AuthState::SUCCESS;
}

bool Socks5Instance::DoConnect(Socks5Command command)
{
    if (doConnectCount_++ > SOCKS5_DO_CONNECT_COUNT_MAX) {
        NETSTACK_LOGE("socks5 instance connect count over %{public}d times socket:%{public}d",
                      SOCKS5_DO_CONNECT_COUNT_MAX, socketId_);
        return false;
    }

    if (!RequestMethod(SOCKS5_METHODS)) {
        NETSTACK_LOGE("socks5 instance fail to request method socket:%{public}d", socketId_);
        return false;
    }
    if (method_ == nullptr) {
        NETSTACK_LOGE("socks5 instance method is null socket:%{public}d", socketId_);
        Socks5Utils::UpdateErrorInfo(Socks5Status::SOCKS5_METHOD_ERROR);
        return false;
    }
    if (!method_->RequestAuth(socketId_, options_->username, options_->password, options_->proxyAddress)) {
        NETSTACK_LOGE("socks5 instance fail to auth socket:%{public}d", socketId_);
        return false;
    }
    const std::pair<bool, Socks5ProxyResponse> result{method_->RequestProxy(socketId_, command, dest_,
        options_->proxyAddress)};
    if (!result.first) {
        NETSTACK_LOGE("socks5 instance fail to request proxy socket:%{public}d", socketId_);
        return false;
    }
    proxyBindAddr_.SetAddress(result.second.destAddr, false);
    proxyBindAddr_.SetPort(result.second.destPort);
    if (result.second.addrType == Socks5AddrType::IPV4) {
        proxyBindAddr_.SetFamilyByJsValue(static_cast<uint32_t>(Socket::NetAddress::Family::IPv4));
    } else if (result.second.addrType == Socks5AddrType::IPV6) {
        proxyBindAddr_.SetFamilyByJsValue(static_cast<uint32_t>(Socket::NetAddress::Family::IPv6));
    } else if (result.second.addrType == Socks5AddrType::DOMAIN) {
        proxyBindAddr_.SetFamilyByJsValue(static_cast<uint32_t>(Socket::NetAddress::Family::DOMAIN));
    } else {
        NETSTACK_LOGE("socks5 instance get unknow addrType:%{public}d socket:%{public}d",
            static_cast<uint32_t>(result.second.addrType), socketId_);
    }
    state_ = Socks5AuthState::SUCCESS;
    return true;
}

int32_t Socks5Instance::GetErrorCode() const
{
    return Socks5Utils::errorCode;
}

std::string Socks5Instance::GetErrorMessage() const
{
    return Socks5Utils::errorMessage;
}

void Socks5Instance::OnSocks5TcpError()
{
    NETSTACK_LOGE("socks5 instance tcp error socket:%{public}d", socketId_);
    std::lock_guard<std::mutex> lock{mutex_};
    state_ = Socks5AuthState::FAIL;
}

Socket::NetAddress Socks5Instance::GetProxyBindAddress() const
{
    return proxyBindAddr_;
}

bool Socks5Instance::RequestMethod(const std::vector<Socks5MethodType> &methods)
{
    Socks5MethodRequest request{};
    request.version = SOCKS5_VERSION;
    request.methods = methods;

    const socklen_t addrLen{Socks5Utils::GetAddressLen(options_->proxyAddress.netAddress)};
    const std::pair<sockaddr *, socklen_t> addrInfo{options_->proxyAddress.addr, addrLen};
    Socks5MethodResponse response{};
    if (!Socks5Utils::RequestProxyServer(socketId_, addrInfo, &request, &response, "RequestMethod")) {
        return false;
    }
    Socks5MethodType methodType{static_cast<Socks5MethodType>(response.method)};
    method_ = CreateSocks5MethodByType(methodType);
    return true;
}

std::shared_ptr<Socks5Method> Socks5Instance::CreateSocks5MethodByType(Socks5MethodType type) const
{
    if (type == Socks5MethodType::NO_AUTH) {
        return std::make_shared<Socks5NoneMethod>();
    } else if (type == Socks5MethodType::PASSWORD) {
        return std::make_shared<Socks5PasswdMethod>();
    } else if (type == Socks5MethodType::GSSAPI) {
        NETSTACK_LOGE("socks5 instance not support GSSAPI now");
        return nullptr;
    } else {
        NETSTACK_LOGE("socks5 instance no method type:%{public}d", static_cast<int32_t>(type));
        return nullptr;
    }
}

Socks5TcpInstance::Socks5TcpInstance(int32_t socketId)
{
    socketId_ = socketId;
}

bool Socks5TcpInstance::Connect()
{
    NETSTACK_LOGD("socks5 tcp instance auth socket:%{public}d", socketId_);
    Socks5Utils::UpdateErrorInfo(0, "");
    std::lock_guard<std::mutex> lock{mutex_};
    if (state_ == Socks5AuthState::SUCCESS) {
        NETSTACK_LOGD("socks5 tcp instance auth already socket:%{public}d", socketId_);
        return true;
    }
    if (DoConnect(Socks5Command::TCP_CONNECTION)) {
        NETSTACK_LOGI("socks5 tcp instance auth successfully socket:%{public}d", socketId_);
        return true;
    } else {
        return false;
    }
}

bool Socks5TcpInstance::RemoveHeader(void *data, size_t &len, int af)
{
    return false;
}

void Socks5TcpInstance::AddHeader()
{
}

std::string Socks5TcpInstance::GetHeader()
{
    return std::string();
}

void Socks5TcpInstance::SetHeader(std::string header)
{
}

Socks5UdpInstance::~Socks5UdpInstance()
{
    CloseSocket();
}

void Socks5UdpInstance::CloseSocket()
{
    if (socketId_ != SOCKS5_INVALID_SOCKET_FD) {
        NETSTACK_LOGI("socks5 udp instance close socket:%{public}d", socketId_);
        static_cast<void>(::close(socketId_));
        socketId_ = SOCKS5_INVALID_SOCKET_FD;
    }
}

bool Socks5UdpInstance::Connect()
{
    NETSTACK_LOGD("socks5 udp instance auth");
    Socks5Utils::UpdateErrorInfo(0, "");

    std::lock_guard<std::mutex> lock{mutex_};
    if (state_ == Socks5AuthState::SUCCESS) {
        NETSTACK_LOGD("socks5 udp instance auth already");
        return true;
    }
    if (!CreateSocket()) {
        return false;
    }
    if (!ConnectProxy()) {
        CloseSocket();
        return false;
    }
    if (!DoConnect(Socks5Command::UDP_ASSOCIATE)) {
        CloseSocket();
        return false;
    }
    const socklen_t addrLen{Socks5Utils::GetAddressLen(options_->proxyAddress.netAddress)};
    const std::shared_ptr<Socks5UdpInstance> ptr = std::make_shared<Socks5UdpInstance>();
    const std::weak_ptr<Socks5UdpInstance> wp{ptr};
    std::thread serviceThread(Socks5Utils::TcpKeepAliveThread, socketId_, options_->proxyAddress.addr,
        addrLen, wp);
#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
    pthread_setname_np(SOCKS5_TCP_KEEP_ALIVE_THREAD_NAME);
#else
    pthread_setname_np(serviceThread.native_handle(), SOCKS5_TCP_KEEP_ALIVE_THREAD_NAME);
#endif
    serviceThread.detach();
    NETSTACK_LOGI("socks5 udp instance auth successfully socket:%{public}d", socketId_);
    return true;
}

bool Socks5UdpInstance::CreateSocket()
{
    socketId_ = Socket::ExecCommonUtils::MakeTcpSocket(options_->proxyAddress.netAddress.GetSaFamily());
    if (socketId_ == SOCKS5_INVALID_SOCKET_FD) {
        NETSTACK_LOGE("socks5 udp instance fail to make tcp socket");
        Socks5Utils::UpdateErrorInfo(Socks5Status::SOCKS5_MAKE_SOCKET_ERROR);
        return false;
    }

    int keepalive = 1;
    if (setsockopt(socketId_, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive)) < 0) {
        NETSTACK_LOGE("socks5 udp instance fail to set keepalive");
        return false;
    }

    return true;
}

bool Socks5UdpInstance::ConnectProxy()
{
    const socklen_t addrLen{Socks5Utils::GetAddressLen(options_->proxyAddress.netAddress)};
    // use default value
    const uint32_t timeoutMSec{0U};
    if (!NonBlockConnect(socketId_, options_->proxyAddress.addr, addrLen, timeoutMSec)) {
        NETSTACK_LOGE("socks5 udp instance fail to connect proxy");
        Socks5Utils::UpdateErrorInfo(Socks5Status::SOCKS5_FAIL_TO_CONNECT_PROXY);
        return false;
    }
    return true;
}

bool Socks5UdpInstance::RemoveHeader(void *data, size_t &len, int af)
{
    size_t headerLen = af == AF_INET ? INET_SOCKS5_UDP_HEADER_LEN : INET6_SOCKS5_UDP_HEADER_LEN;
    Socks5UdpHeader header{};

    if (data == nullptr || !header.Deserialize(data, len)) {
        NETSTACK_LOGE("not a valid socks5 udp header");
        return false;
    }

    if (len < headerLen) {
        NETSTACK_LOGE("fail to remove udp header");
        return false;
    }

    len -= headerLen;

    if (memmove_s(data, len, static_cast<uint8_t *>(data) + headerLen, len) != EOK) {
        NETSTACK_LOGE("memory copy failed");
        return false;
    }

    return true;
}

void Socks5UdpInstance::AddHeader()
{
    const Socket::NetAddress::Family family{dest_.GetFamily()};
    Socks5::Socks5AddrType addrType;

    if (family == Socket::NetAddress::Family::IPv4) {
        addrType = Socks5::Socks5AddrType::IPV4;
    } else if (family == Socket::NetAddress::Family::IPv6) {
        addrType = Socks5::Socks5AddrType::IPV6;
    } else if (family == Socket::NetAddress::Family::DOMAIN) {
        addrType = Socks5::Socks5AddrType::DOMAIN;
    } else {
        NETSTACK_LOGE("socks5 udp protocol address type error");
        return ;
    }

    Socks5::Socks5UdpHeader header{};
    header.addrType = addrType;
    header.destAddr = dest_.GetAddress();
    header.dstPort = dest_.GetPort();

    SetHeader(header.Serialize());
}

void Socks5UdpInstance::SetHeader(std::string header)
{
    header_ = header;
}

std::string Socks5UdpInstance::GetHeader()
{
    return header_;
}

} // Socks5
} // NetStack
} // OHOS
