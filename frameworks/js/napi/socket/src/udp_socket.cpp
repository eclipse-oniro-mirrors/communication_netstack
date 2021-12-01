/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "udp_socket.h"
#include "napi_util.h"
#include "netmgr_log_wrapper.h"
#include "node_api_types.h"

namespace OHOS {
namespace NetManagerStandard {
UDPSocket::UDPSocket(Baseinfo remInfo)
{
    this->remInfo = remInfo;
}

UDPSocket::~UDPSocket()
{
    UdpClose(this->remInfo.socketfd);
}

void UDPSocket::GetJSParameter(napi_env &env, napi_value *parameters, Baseinfo*&asyncContext)
{
    napi_value addressvalue = NapiUtil::GetNamedProperty(env, parameters[0], "address");
    if (addressvalue != nullptr) {
        asyncContext->ipAddress = NapiUtil::GetStringFromValue(env, addressvalue);
    }
    napi_value familyValue = NapiUtil::GetNamedProperty(env, parameters[0], "family");
    if (familyValue != nullptr) {
        napi_get_value_int32(env, familyValue, &asyncContext->family);
    }
    napi_value portValue = NapiUtil::GetNamedProperty(env, parameters[0], "port");
    if (portValue != nullptr) {
        napi_get_value_int32(env, portValue, &asyncContext->port);
    }
    napi_value dataValue = NapiUtil::GetNamedProperty(env, parameters[0], "data");
    if (dataValue != nullptr) {
        asyncContext->data = NapiUtil::GetStringFromValue(env, dataValue);
    }
}

void UDPSocket::GetSocketInfo(struct sockaddr_in &addr, Baseinfo *&asyncContext)
{
    addr.sin_addr.s_addr = inet_addr(asyncContext->ipAddress.c_str());
    if (asyncContext->family == IPV6) {
        addr.sin_family = AF_INET6;
    } else {
        addr.sin_family = AF_INET;
    }
    addr.sin_port = htons(asyncContext->port);
}

int UDPSocket::UdpSocket(int domain, int type, int protocol)
{
    this->remInfo.socketfd = socket(domain, type, protocol);
    return this->remInfo.socketfd;
}

int UDPSocket::UdpBind(int fd, const struct sockaddr *addr, socklen_t len)
{
    if (fd != this->remInfo.socketfd) {
        return -1;
    }
    return bind(fd, addr, len);
}

int UDPSocket::UdpConnect(int fd, const struct sockaddr *addr, socklen_t len)
{
    if (fd != this->remInfo.socketfd) {
        return -1;
    }
    return connect(fd, addr, len);
}

int UDPSocket::UdpSend(int fd, const void *buf, size_t len, int flags)
{
    if (fd != this->remInfo.socketfd) {
        return -1;
    }
    return send(fd, buf, len, flags);
}

int UDPSocket::UdpClose(int fd)
{
    if (fd != this->remInfo.socketfd) {
        return -1;
    }
    return close(fd);
}
} // namespace NetManagerStandard
} // namespace OHOS