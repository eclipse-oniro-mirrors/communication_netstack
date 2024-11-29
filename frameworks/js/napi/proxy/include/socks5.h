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

#ifndef COMMUNICATION_NETSTACK_SOCKS5_H
#define COMMUNICATION_NETSTACK_SOCKS5_H

#include <sys/types.h>
#include <sys/socket.h>
#include <map>
#include <string>

#include "net_address.h"

namespace OHOS {
namespace NetStack {
namespace Socks5 {
enum class Socks5Command : uint8_t {
    TCP_CONNECTION = 0x01,
    TCP_BIND = 0x02,
    UDP_ASSOCIATE = 0x03
};

enum class Socks5MethodType : uint8_t {
    NO_AUTH = 0x00,
    GSSAPI = 0x01,
    PASSWORD = 0x02,
    NO_METHODS = 0xFF
};

enum class Socks5AddrType : uint8_t {
    IPV4 = 0x01,
    DOMAIN = 0x03,
    IPV6 = 0x04
};

enum class Socks5AuthState : uint32_t {
    INIT = 0x00,
    FAIL = 0x01,
    SUCCESS = 0x02
};

enum class Socks5Status : uint8_t {
    SUCCESS = 0x00,
    FAIL = 0x01,
    CONNECTION_NOT_ALLOWED = 0x02,
    NETWORK_UNREACHABLE = 0x03,
    HOST_UNREACHABLE = 0x04,
    CONNECTION_REFUSED_BY_HOST = 0x05,
    TTL_EXPIRED = 0x06,
    COMMAND_NOT_SUPPORTED = 0x07,
    ADDRESS_TYPE_NOT_SUPPORTED = 0x08,
    SOCKS5_NOT_ACTIVE = 0xA1,
    SOCKS5_METHOD_ERROR = 0xA2,
    SOCKS5_MAKE_SOCKET_ERROR = 0xA3,
    SOCKS5_FAIL_TO_CONNECT_PROXY = 0xA4,
    SOCKS5_FAIL_TO_SEND_MSG = 0xA5,
    SOCKS5_FAIL_TO_RECV_MSG = 0xA6,
    SOCKS5_SERIALIZE_ERROR = 0xA7,
    SOCKS5_DESERIALIZE_ERROR = 0xA8,
    SOCKS5_USER_PASS_INVALID,
    SOCKS5_FAIL_TO_CONNECT_REMOTE,
    OTHER_STATUS
};

static constexpr const char *SOCKS5_TCP_KEEP_ALIVE_THREAD_NAME = "OS_NET_SOCKS5_TCP_KEEP_ALIVE";
static constexpr uint8_t SOCKS5_VERSION{5U};
static constexpr uint8_t SOCKS5_SUBVERSION(1U);
static constexpr int32_t SOCKS5_INVALID_SOCKET_FD{-1};
static const std::vector<Socks5MethodType> SOCKS5_METHODS{Socks5MethodType::NO_AUTH, Socks5MethodType::PASSWORD};
static const std::map<Socks5Status, std::string> g_errStatusMap = {
    {Socks5Status::SUCCESS, "Success"},
    {Socks5Status::FAIL, "Socks5 general socks server failure"},
    {Socks5Status::CONNECTION_NOT_ALLOWED, "Socks5 connection not allowed by ruleset"},
    {Socks5Status::NETWORK_UNREACHABLE, "Socks5 network unreachable"},
    {Socks5Status::HOST_UNREACHABLE, "Socks5 host unreachable"},
    {Socks5Status::CONNECTION_REFUSED_BY_HOST, "Socks5 connection refused by host"},
    {Socks5Status::TTL_EXPIRED, "Socks5 ttl expired"},
    {Socks5Status::COMMAND_NOT_SUPPORTED, "Socks5 command not supported"},
    {Socks5Status::ADDRESS_TYPE_NOT_SUPPORTED, "Socks5 address type not supported"},
    {Socks5Status::SOCKS5_NOT_ACTIVE, "Socks5 is not active"},
    {Socks5Status::SOCKS5_METHOD_ERROR, "Socks5 method request error"},
    {Socks5Status::SOCKS5_MAKE_SOCKET_ERROR, "Socks5 make tcp socket error"},
    {Socks5Status::SOCKS5_FAIL_TO_CONNECT_PROXY, "Socks5 fail to connect proxy server"},
    {Socks5Status::SOCKS5_FAIL_TO_SEND_MSG, "Socks5 fail to send message"},
    {Socks5Status::SOCKS5_FAIL_TO_RECV_MSG, "Socks5 fail to recv message"},
    {Socks5Status::SOCKS5_SERIALIZE_ERROR, "Socks5 serialize error"},
    {Socks5Status::SOCKS5_DESERIALIZE_ERROR, "Socks5 deserialize error"},
    {Socks5Status::SOCKS5_USER_PASS_INVALID, "Socks5 username or password invalid"},
    {Socks5Status::SOCKS5_FAIL_TO_CONNECT_REMOTE, "Socks5 fail to connect remote server"},
    {Socks5Status::OTHER_STATUS, "Socks5 unassigned status"}
};

using Socks5Buffer = std::string;
class Socks5ProxyAddress {
public:
    Socket::NetAddress netAddress{};
    sockaddr_in addrV4{};
    sockaddr_in6 addrV6{};
    sockaddr* addr{nullptr};
};

class Socks5Option {
public:
    Socks5ProxyAddress proxyAddress{};
    std::string username{};
    std::string password{};
};
} // Socks5
} // NetStack
} // OHOS
#endif // COMMUNICATION_NETSTACK_SOCKS5_H
