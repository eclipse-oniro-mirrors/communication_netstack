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

#ifndef NET_SOCKET_IMPL_H
#define NET_SOCKET_IMPL_H

#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <atomic>
#include <poll.h>

#include "ffi_remote_data.h"
#include "ffi_structs.h"
#include "net_socket_exec.h"
#include "cj_lambda.h"
#include "constant.h"

namespace OHOS::NetStack::Socket {

using SocketCallback = std::function<void(CCallbackData *)>;
using ConnectCallback = std::function<void(int32_t errCode)>;

class CJTcpSocketProxy : public OHOS::FFI::FFIData {
    DECL_TYPE(CJTcpSocketProxy, OHOS::FFI::FFIData);

public:
    CJTcpSocketProxy();
    ~CJTcpSocketProxy() override;

    int GetSocketFd() const;
    void SetSocketFd(int fd);
    sa_family_t GetFamily() const;
    void SetFamily(sa_family_t family);
    bool GetReuseAddr() const;
    void SetReuseAddr(bool reuseAddr);
    bool IsAsyncConnecting() const;
    void SetAsyncConnecting(bool asyncConnecting);
    bool IsClosed() const;
    bool IsEverOpened() const;

    void AddCallback2Map(int32_t type, SocketCallback callback);
    void DelCallback(int32_t type);
    std::optional<SocketCallback> FindCallback(int32_t type);

    void SetConnectCallback(ConnectCallback callback);
    ConnectCallback GetConnectCallback();

    void StartRecvThread();
    void StopRecvThread();

    void EmitMessageEvent(void *data, size_t dataLen, sockaddr *addr);
    void EmitErrorEvent(int err);
    void EmitCloseEvent();
    void EmitConnectEvent();

private:
    int WaitForPollEvent(pollfd &fd);
    void RecvLoop();

    int sockFd_ = -1;
    sa_family_t family_ = AF_INET;
    bool reuseAddr_ = false;
    bool asyncConnecting_ = false;
    bool everOpened_ = false;
    std::atomic<bool> closed_ = {false};

    std::map<int32_t, SocketCallback> eventMap_;
    std::mutex eventMutex_;

    ConnectCallback connectCallback_;
    std::mutex connectMutex_;

    std::thread recvThread_;
    std::mutex recvMutex_;
};

class CJTcpSocketImpl {
public:
    static void OnConnectResult(int64_t proxyId, int32_t resultErrCode);
    static int32_t Bind(CJTcpSocketProxy *proxy, const CNetAddress &cAddr);
    static int32_t Connect(CJTcpSocketProxy *proxy, const CTcpConnectOptions &cOptions,
        int64_t callback);
    static int32_t Send(CJTcpSocketProxy *proxy, const CTcpSendOptions &cOptions);
    static int32_t Close(CJTcpSocketProxy *proxy);
    static CGetStateResult GetState(CJTcpSocketProxy *proxy);
    static CGetAddressResult GetRemoteAddress(CJTcpSocketProxy *proxy);
    static CGetAddressResult GetLocalAddress(CJTcpSocketProxy *proxy);
    static CGetSocketFdResult GetSocketFd(CJTcpSocketProxy *proxy);
    static int32_t SetExtraOptions(CJTcpSocketProxy *proxy, const CTcpExtraOptions &cOptions);

    static int32_t OnController(CJTcpSocketProxy *proxy, int32_t typeId,
        SocketCallback callback);
    static int32_t OffController(CJTcpSocketProxy *proxy, int32_t typeId);
};

}
#endif
