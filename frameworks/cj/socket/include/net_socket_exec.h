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

#ifndef NET_SOCKET_EXEC_H
#define NET_SOCKET_EXEC_H

#include <arpa/inet.h>
#include <cstdint>
#include <mutex>
#include <string>

#include "constant.h"
#include "ffi_structs.h"

namespace OHOS::NetStack::Socket {

class NetAddress {
public:
    enum class Family : uint32_t {
        IPv4 = 1,
        IPv6 = 2,
        DOMAIN_NAME = 3,
    };

    NetAddress();
    ~NetAddress() = default;

    void SetRawAddress(const std::string &address);
    void SetIpAddress(const std::string &address);
    void SetAddress(const std::string &address);
    void SetFamilyByJsValue(uint32_t family);
    void SetFamilyBySaFamily(sa_family_t family);
    void SetPort(uint16_t port);

    const std::string &GetAddress() const;
    uint32_t GetJsValueFamily() const;
    sa_family_t GetSaFamily() const;
    uint16_t GetPort() const;
    Family GetFamily() const;

    NetAddress &operator=(const NetAddress &other);

private:
    void SetIpAddressInner(const std::string &address);
    std::string address_;
    Family family_;
    uint16_t port_;
};

class SocketStateBase {
public:
    SocketStateBase();
    ~SocketStateBase() = default;

    void SetIsBound(bool isBound);
    void SetIsClose(bool isClose);
    void SetIsConnected(bool isConnected);

    bool IsBound() const;
    bool IsClose() const;
    bool IsConnected() const;

private:
    bool isBound_;
    bool isClose_;
    bool isConnected_;
};

class SocketRemoteInfo {
public:
    SocketRemoteInfo();
    ~SocketRemoteInfo() = default;

    void SetAddress(const std::string &address);
    void SetFamily(sa_family_t family);
    void SetPort(uint16_t port);
    void SetSize(uint32_t size);
    void SetFamilyByStr(const std::string family);

    const std::string &GetAddress() const;
    const std::string &GetFamily() const;
    uint16_t GetPort() const;
    uint32_t GetSize() const;

private:
    std::string address_;
    std::string family_;
    uint16_t port_;
    uint32_t size_;
};

class ExtraOptionsBase {
public:
    ExtraOptionsBase();
    ~ExtraOptionsBase() = default;

    void SetReceiveBufferSize(uint32_t receiveBufferSize);
    void SetSendBufferSize(uint32_t sendBufferSize);
    void SetReuseAddress(bool reuseAddress);
    void SetSocketTimeout(uint32_t socketTimeout);

    uint32_t GetReceiveBufferSize() const;
    uint32_t GetSendBufferSize() const;
    bool IsReuseAddress() const;
    uint32_t GetSocketTimeout() const;

    bool AlreadySetRecvBufSize() const;
    void SetRecvBufSizeFlag(bool flag);
    bool AlreadySetSendBufSize() const;
    void SetSendBufSizeFlag(bool flag);
    bool AlreadySetTimeout() const;
    void SetTimeoutFlag(bool flag);
    bool AlreadySetReuseAddr() const;
    void SetReuseaddrFlag(bool flag);

private:
    uint32_t receiveBufferSize_;
    uint32_t sendBufferSize_;
    bool reuseAddress_;
    uint32_t socketTimeout_;
    bool recvBufSizeFlag_ = false;
    bool sendBufSizeFlag_ = false;
    bool timeoutFlag_ = false;
    bool reuseAddrFlag_ = false;
};

class SocketLinger {
public:
    SocketLinger();
    ~SocketLinger() = default;

    void SetOn(bool on);
    void SetLinger(uint32_t linger);
    bool IsOn() const;
    uint32_t GetLinger() const;

private:
    bool on_;
    uint32_t linger_;
};

class TCPExtraOptions final : public ExtraOptionsBase {
public:
    TCPExtraOptions();
    ~TCPExtraOptions() = default;

    void SetKeepAlive(bool keepAlive);
    void SetOOBInline(bool OOBInline);
    void SetTCPNoDelay(bool TCPNoDelay);
    void SetTCPFastOpen(bool TCPFastOpen);

    bool IsKeepAlive() const;
    bool IsOOBInline() const;
    bool IsTCPNoDelay() const;
    bool IsTCPFastOpen() const;

    bool AlreadySetKeepAlive() const;
    void SetKeepAliveFlag(bool flag);
    bool AlreadySetOobInline() const;
    void SetOobInlineFlag(bool flag);
    bool AlreadySetTcpNoDelay() const;
    void SetTcpNoDelayFlag(bool flag);
    bool AlreadySetTCPFastOpen() const;
    void SetTcpFastOpenFlag(bool flag);
    bool AlreadySetLinger() const;
    void SetLingerFlag(bool flag);

    SocketLinger socketLinger;

private:
    bool keepAlive_;
    bool OOBInline_;
    bool TCPNoDelay_;
    bool TCPFastOpen_;
    bool keepAliveFlag_ = false;
    bool oobInlineFlag_ = false;
    bool tcpNoDelayFlag_ = false;
    bool tcpFastOpenFlag_ = false;
    bool lingerFlag_ = false;
};

class TcpConnectOptions {
public:
    TcpConnectOptions();
    ~TcpConnectOptions() = default;

    void SetAddress(const NetAddress &address);
    void SetTimeout(uint32_t timeout);
    NetAddress &GetMutableAddress();
    const NetAddress &GetAddress() const;
    uint32_t GetTimeout() const;

private:
    NetAddress address_;
    uint32_t timeout_;
};

class TcpSendOptions {
public:
    TcpSendOptions();
    ~TcpSendOptions() = default;

    void SetData(const std::string &data);
    void SetData(void *data, size_t size);
    void SetEncoding(const std::string &encoding);
    const std::string &GetData() const;
    const std::string &GetEncoding() const;

private:
    std::string data_;
    std::string encoding_;
};

class ProxyOptions {
public:
    ProxyOptions();
    ~ProxyOptions() = default;

    NetAddress address_;
    uint32_t type_ = 0;
    std::string username_;
    std::string password_;
};

std::string ConvertAddressToIp(const std::string &address, sa_family_t family);
bool IpMatchFamily(const std::string &address, sa_family_t family);
bool NonBlockConnect(int sock, sockaddr *addr, socklen_t addrLen, uint32_t timeoutMSec);
bool PollSendData(int sock, const char *data, size_t size, sockaddr *addr, socklen_t addrLen);
int ConfirmSocketTimeoutMs(int sock, int type, int defaultValue);
int ConfirmBufferSize(int sock);

bool MakeNonBlock(int sock);
int MakeTcpSocket(sa_family_t family, bool needNonblock = true);

void ParseCNetAddress(const CNetAddress &cAddr, NetAddress &addr);
void ParseCProxyOptions(const CProxyOptions &cProxy, ProxyOptions &proxy);
void ParseCTcpExtraOptions(const CTcpExtraOptions &cOpts, TCPExtraOptions &opts);

bool ExecTcpBind(int sockFd, const NetAddress &address, bool reuseAddr);
bool ExecConnect(int sockFd, const TcpConnectOptions &options, const ProxyOptions *proxy,
    bool &asyncConnecting, int &errCode);
bool ExecTcpSend(int sockFd, const TcpSendOptions &options);
bool ExecClose(int sockFd);
bool ExecGetState(int sockFd, SocketStateBase &state);
bool ExecGetRemoteAddress(int sockFd, NetAddress &address);
bool ExecGetLocalAddress(int sockFd, NetAddress &address);
bool ExecTcpSetExtraOptions(int sockFd, const TCPExtraOptions &options);

char *MallocCString(const std::string &origin);

}
#endif
