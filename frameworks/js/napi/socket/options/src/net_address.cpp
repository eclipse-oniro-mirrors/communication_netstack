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

#include "net_address.h"

namespace OHOS::NetStack::Socket {

static constexpr int INET_PTON_SUCCESS = 1;

NetAddress::NetAddress() : family_(Family::IPv4), port_(0) {}

void NetAddress::SetAddress(const std::string &address)
{
    address_ = address;
}

bool NetAddress::IsValidAddress(const std::string &address)
{
    if (address.empty()) {
        return false;
    }
    struct in_addr addrIPv4;
    struct in6_addr addrIPv6;
    if (inet_pton(AF_INET, address.c_str(), reinterpret_cast<void *>(&addrIPv4)) == INET_PTON_SUCCESS ||
        inet_pton(AF_INET6, address.c_str(), reinterpret_cast<void *>(&addrIPv6)) == INET_PTON_SUCCESS) {
        return true;
    }
    return false;
}

void NetAddress::SetFamilyByJsValue(const std::string &address)
{
    if (address.empty()) {
        return;
    }
    struct in_addr addrIPv4;
    if (inet_pton(AF_INET, address.c_str(), reinterpret_cast<void *>(&addrIPv4)) != INET_PTON_SUCCESS) {
        family_ = Family::IPv6;
        return;
    }
    family_ = Family::IPv4;
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
