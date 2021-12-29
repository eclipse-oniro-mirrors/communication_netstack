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
#ifndef TCP_SOCKET_H
#define TCP_SOCKET_H

#include "sys/socket.h"
#include "unistd.h"
#include "sys/socket.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "netaddress.h"
#include "socket_napi.h"
#include "tcp_extra_options.h"

#include <arpa/inet.h>
#include <map>
#include <netdb.h>
#include <sys/types.h>

namespace OHOS {
namespace NetManagerStandard {
class TCPSocket;
struct TcpBaseContext : NetAddress {
    napi_async_work work_ = nullptr;
    napi_deferred deferred_ = nullptr;
    napi_ref callbackRef_ = nullptr;
    bool resolved_ = false;
    int32_t errorCode_ = 0;
    int32_t socketfd_ = -1;
    std::string data = "";
    std::string errorString_ = "";
    bool isBound = false;
    bool isClose = true;
    bool isConnected = false;
    bool broadcast = false;
    int type = 0;
    TCPExtraOptions tcpExtraOptions_;
    TCPSocket *tcpSocket_;
};

class TCPSocket {
public:
    TCPSocket(TcpBaseContext remInfo);
    ~TCPSocket();

    int TcpSocket(int domain, int type, int protocol);
    int TcpBind(int fd, const struct sockaddr *addr, socklen_t len);
    int TcpConnect(int fd, const struct sockaddr *addr, socklen_t len);
    int TcpSend(int fd, const void *buf, size_t len, int flags);
    int TcpClose(int fd);
    int TcpSetSockopt(int fd, int level, int optname, const void *optval, socklen_t optlen);
    void GetJSParameter(napi_env &env, napi_value *parameters, TcpBaseContext *&asyncContext);
    void GetSocketInfo(struct sockaddr_in &addr, TcpBaseContext *&asyncContext);
    void GetExOpGetJSParameter(napi_env &env, napi_value *parameters, TcpBaseContext *&asyncContext);
    TcpBaseContext tcpbaseContext_;
};
} // namespace NetManagerStandard
} // namespace OHOS
#endif  // TCP_SOCKET_H