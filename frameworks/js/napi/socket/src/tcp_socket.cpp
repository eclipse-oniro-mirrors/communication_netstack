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

#include "tcp_socket.h"

#include "napi_util.h"
#include "netmgr_log_wrapper.h"
#include "node_api_types.h"

namespace OHOS {
namespace NetManagerStandard {
TCPSocket::TCPSocket(TcpBaseContext remInfo)
{
    this->tcpbaseContext_ = remInfo;
}

TCPSocket::~TCPSocket()
{
    TcpClose(this->tcpbaseContext_.socketfd_);
    NETMGR_LOGD("~TCPSocket");
}

void TCPSocket::GetJSParameter(napi_env &env, napi_value *parameters, TcpBaseContext*&asyncContext)
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

void TCPSocket::GetSocketInfo(struct sockaddr_in &addr, TcpBaseContext *&asyncContext)
{
    addr.sin_addr.s_addr = inet_addr(asyncContext->ipAddress.c_str());
    if (asyncContext->family == IPV6) {
        addr.sin_family = AF_INET6;
    } else {
        addr.sin_family = AF_INET;
    }
    addr.sin_port = htons(asyncContext->port);
}

int TCPSocket::TcpSocket(int domain, int type, int protocol)
{
    this->tcpbaseContext_.socketfd_ = socket(domain, type, protocol);
    return this->tcpbaseContext_.socketfd_;
}

int TCPSocket::TcpBind(int fd, const struct sockaddr *addr, socklen_t len)
{
    if (fd != this->tcpbaseContext_.socketfd_) {
        return -1;
    }
    return bind(fd, addr, len);
}

int TCPSocket::TcpConnect(int fd, const struct sockaddr *addr, socklen_t len)
{
    if (fd != this->tcpbaseContext_.socketfd_) {
        return -1;
    }
    return connect(fd, addr, len);
}

int TCPSocket::TcpSend(int fd, const void *buf, size_t len, int flags)
{
    if (fd != this->tcpbaseContext_.socketfd_) {
        return -1;
    }
    return send(fd, buf, len, flags);
}

int TCPSocket::TcpClose(int fd)
{
    if (fd != this->tcpbaseContext_.socketfd_) {
        return -1;
    }
    return close(fd);
}

int TCPSocket::TcpSetSockopt(int fd, int level, int optname, const void *optval, socklen_t optlen)
{
    if (fd != this->tcpbaseContext_.socketfd_) {
        return -1;
    }
    return setsockopt(fd, level, optname, optval, optlen);
}

void TCPSocket::GetExOpGetJSParameter(napi_env &env, napi_value *parameters, TcpBaseContext*&asyncContext)
{
    bool value = false;
    napi_value keepAliveValue = NapiUtil::GetNamedProperty(env, parameters[0], "keepAlive");
    if (keepAliveValue != nullptr) {
        napi_get_value_bool(env, keepAliveValue, &value);
    }
    asyncContext->tcpExtraOptions_.SetKeepAlive(value);

    napi_value OOBInlineValue = NapiUtil::GetNamedProperty(env, parameters[0], "OOBInline");
    if (OOBInlineValue != nullptr) {
        napi_get_value_bool(env, OOBInlineValue, &value);
    }
    asyncContext->tcpExtraOptions_.SetOOBInline(value);

    napi_value TCPNoDelayValue = NapiUtil::GetNamedProperty(env, parameters[0], "TCPNoDelay");
    if (TCPNoDelayValue != nullptr) {
        napi_get_value_bool(env, TCPNoDelayValue, &value);
    }
    asyncContext->tcpExtraOptions_.SetTCPNoDelay(value);

    napi_value socketLingerValue = NapiUtil::GetNamedProperty(env, parameters[0], "socketLinger");
    if (socketLingerValue != nullptr) {
        napi_value socktLingerOnValue = NapiUtil::GetNamedProperty(env, socketLingerValue, "on");
        if (socktLingerOnValue != nullptr) {
            napi_get_value_bool(env, socktLingerOnValue, &value);
        }
        asyncContext->tcpExtraOptions_.SetSocketLingerOn(value);

        int32_t intValue = 0;
        napi_value socktLingerLingerValue = NapiUtil::GetNamedProperty(env, socketLingerValue, "linger");
        if (socktLingerLingerValue != nullptr) {
            napi_get_value_int32(env, socktLingerLingerValue, &intValue);
        }
        asyncContext->tcpExtraOptions_.SetSocketLingerLinger(value);
    }
}
} // namespace NetManagerStandard
} // namespace OHOS