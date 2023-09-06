/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include <netdb.h>
#include "net_address.h"
#include "netstack_log.h"

namespace OHOS::NetStack::Socket {

NetAddress::NetAddress() : family_(Family::IPv4), port_(0) {}

void NetAddress::SetAddress(const std::string &address)
{
    struct addrinfo hints;
    sa_family_t saFamily = GetSaFamily();
    memset(&hints, 0, sizeof hints);
    hints.ai_family = saFamily;
    char ipStr[INET6_ADDRSTRLEN];
    struct addrinfo *res = nullptr;
    int status = getaddrinfo(address.c_str(), nullptr, &hints, &res);
    if (status != 0 || res == nullptr) {
        NETSTACK_LOGE("getaddrinfo status is %{public}d, error is %{public}s", status, gai_strerror(status));
        return;
    }

    void *addr = nullptr;
    if (res->ai_family == AF_INET) {
        auto *ipv4 = (struct sockaddr_in *)res->ai_addr;
        addr = &(ipv4->sin_addr);
    } else {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)res->ai_addr;
        addr = &(ipv6->sin6_addr);
    }
    inet_ntop(res->ai_family, addr, ipStr, sizeof ipStr);
    address_ = ipStr;
    freeaddrinfo(res);
}

void NetAddress::SetFamilyByJsValue(uint32_t family)
{
    if (static_cast<Family>(family) == Family::IPv6) {
        family_ = Family::IPv6;
    }
}

void NetAddress::SetFamilyBySaFamily(sa_family_t family)
{
    if (family == AF_INET6) {
        family_ = Family::IPv6;
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

sa_family_t NetAddress::GetSaFamily() const
{
    if (family_ == Family::IPv6) {
        return AF_INET6;
    }
    return AF_INET;
}

uint32_t NetAddress::GetJsValueFamily() const
{
    return static_cast<uint32_t>(family_);
}

uint16_t NetAddress::GetPort() const
{
    return port_;
}
} // namespace OHOS::NetStack::Socket
