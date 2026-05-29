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

#ifndef NET_SOCKET_FFI_STRUCTS_H
#define NET_SOCKET_FFI_STRUCTS_H

#include <cstdint>

#include "cj_ffi/cj_common_ffi.h"

#ifdef __cplusplus
#define EXTERN_C_START extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_START
#define EXTERN_C_END
#endif

EXTERN_C_START
    struct CNetAddress {
        char* address;
        uint32_t family;
        uint16_t port;
    };

    struct CProxyOptions {
        CNetAddress address;
        uint32_t type;
        char* username;
        char* password;
    };

    struct CTcpConnectOptions {
        CNetAddress address;
        uint32_t timeout;
        CProxyOptions* proxy;
    };

    struct CTcpSendOptions {
        CArrUI8 data;
        char* encoding;
    };

    struct CSocketLinger {
        bool on;
        uint32_t linger;
    };

    struct CTcpExtraOptions {
        bool hasReceiveBufferSize;
        uint32_t receiveBufferSize;
        bool hasSendBufferSize;
        uint32_t sendBufferSize;
        bool hasReuseAddress;
        bool reuseAddress;
        bool hasSocketTimeout;
        uint32_t socketTimeout;
        bool hasKeepAlive;
        bool keepAlive;
        bool hasOOBInline;
        bool OOBInline;
        bool hasTCPNoDelay;
        bool TCPNoDelay;
        bool hasTCPFastOpen;
        bool TCPFastOpen;
        bool hasLinger;
        CSocketLinger linger;
    };

    struct CSocketStateBase {
        bool isBound;
        bool isClose;
        bool isConnected;
    };

    struct CSocketRemoteInfo {
        char* address;
        char* family;
        uint16_t port;
        uint32_t size;
    };

    struct CCallbackData {
        int32_t typeId;
        int32_t code;
        CArrUI8 data;
        CSocketRemoteInfo remoteInfo;
    };

    struct CGetStateResult {
        int32_t code;
        CSocketStateBase state;
    };

    struct CGetAddressResult {
        int32_t code;
        CNetAddress address;
    };

    struct CGetSocketFdResult {
        int32_t code;
        int32_t fd;
    };
EXTERN_C_END

#endif
