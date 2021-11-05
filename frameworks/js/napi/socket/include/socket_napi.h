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

#ifndef SOCKET_NAPI_H
#define SOCKET_NAPI_H

#include "musl/include/sys/socket.h"
#include "musl/porting/liteos_m/kernel/include/unistd.h"
#include "musl/porting/liteos_m/kernel/include/sys/socket.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "tcp_event_list.h"
#include "udp_event_list.h"

#include <arpa/inet.h>
#include <list>
#include <map>
#include <netdb.h>
#include <sys/types.h>

namespace OHOS {
namespace NetManagerStandard {
    const int32_t ERROR_NONE = 0;
    const int32_t ERROR_SERVICE_UNAVAILABLE = -2;
    const int32_t ERROR_PARAMETER_VALUE_INVALID = -3;
    const int32_t ERROR_NATIVE_API_EXECUTE_FAIL = -4;
    const int32_t NORMAL_STRING_SIZE = 64;
    constexpr int32_t PARAMS_COUNT = 2;

    static const std::int32_t STR_MAX_SIZE = 64;
    static const std::int32_t PORT_MIN_SIZE = 0;
    static const std::int32_t PORT_MAX_SIZE = 65535;
    static const std::int32_t defaultValue = -1;

    static std::list<UdpEventListener> g_udpEventListenerList;
    static std::list<TcpEventListener> g_tcpEventListenerList;

    // UDP extern interface
    napi_value CreateUDPSocket(napi_env env, napi_callback_info info);
    napi_value UdpBind(napi_env env, napi_callback_info info);
    napi_value UdpConnect(napi_env env, napi_callback_info info);
    napi_value UdpSend(napi_env env, napi_callback_info info);
    napi_value UdpClose(napi_env env, napi_callback_info info);
    napi_value UdpGetState(napi_env env, napi_callback_info info);
    napi_value UdpSetExtraOptions(napi_env env, napi_callback_info info);
    napi_value UdpOn(napi_env env, napi_callback_info info);
    napi_value UdpOff(napi_env env, napi_callback_info info);
    // TCP extern interface
    napi_value CreateTCPSocket(napi_env env, napi_callback_info info);
    napi_value TcpBind(napi_env env, napi_callback_info info);
    napi_value TcpConnect(napi_env env, napi_callback_info info);
    napi_value TcpSend(napi_env env, napi_callback_info info);
    napi_value TcpClose(napi_env env, napi_callback_info info);
    napi_value TcpGetRemoteAddress(napi_env env, napi_callback_info info);
    napi_value TcpGetState(napi_env env, napi_callback_info info);
    napi_value TcpSetExtraOptions(napi_env env, napi_callback_info info);
    napi_value TcpOn(napi_env env, napi_callback_info info);
    napi_value TcpOff(napi_env env, napi_callback_info info);
} // namespace NetManagerStandard
} // namespace OHOS
#endif // SOCKET_NAPI_H