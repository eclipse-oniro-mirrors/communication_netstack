/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"

#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "net_address.h"
#include "socks5.h"
#define protected public
#include "socks5_instance.h"
#undef protected
#include "socks5_none_method.h"
#include "socks5_passwd_method.h"
#include "socks5_package.h"
#include "socks5_utils.h"
#include "socket_exec_common.h"

namespace OHOS {
namespace NetStack {
namespace Socks5 {

using testing::ext::TestSize;

class Socks5Test : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}

    virtual void SetUp() {}
    virtual void TearDown() {}
};

HWTEST_F(Socks5Test, SetSocks5OptionTest001, TestSize.Level1)
{
    int32_t socketId = -1;
    std::shared_ptr<Socks5Instance> socks5Inst = std::make_shared<Socks5TcpInstance>(socketId);
    std::shared_ptr<Socks5Option> opt = std::make_shared<Socks5Option>();
    socks5Inst->SetSocks5Option(opt);
    EXPECT_NE(socks5Inst->options_, nullptr);
}

HWTEST_F(Socks5Test, SetSocks5InstanceTest001, TestSize.Level1)
{
    int32_t socketId = -1;
    std::shared_ptr<Socks5Instance> socks5Inst = std::make_shared<Socks5TcpInstance>(socketId);
    /* SetSocks5Instance stores a weak-like ref via the base class mechanism */
    socks5Inst->SetSocks5Instance(socks5Inst);
    /* No crash is the expected behavior */
    EXPECT_TRUE(true);
}

HWTEST_F(Socks5Test, DoConnectTest001, TestSize.Level1)
{
    int32_t socketId = -1;
    std::shared_ptr<Socks5Instance> socks5Inst = std::make_shared<Socks5TcpInstance>(socketId);
    socks5Inst->options_ = std::make_shared<Socks5Option>();
    socks5Inst->SetSocks5Instance(socks5Inst);
    /* DoConnect with no real proxy should return false */
    auto ret = socks5Inst->DoConnect(Socks5Command::TCP_CONNECTION);
    EXPECT_FALSE(ret);
    EXPECT_FALSE(socks5Inst->IsConnected());
}

HWTEST_F(Socks5Test, RequestMethodTest001, TestSize.Level1)
{
    int32_t socketId = -1;
    std::vector<Socks5MethodType> methods = {Socks5MethodType::NO_AUTH, Socks5MethodType::PASSWORD};
    std::shared_ptr<Socks5Instance> socks5Inst = std::make_shared<Socks5TcpInstance>(socketId);
    socks5Inst->options_ = std::make_shared<Socks5Option>();
    socks5Inst->SetSocks5Instance(socks5Inst);
    /* RequestMethod with no real proxy should return false */
    auto ret = socks5Inst->RequestMethod(methods);
    EXPECT_FALSE(ret);
}

HWTEST_F(Socks5Test, CreateSocks5MethodByTypeTest001, TestSize.Level1)
{
    int32_t socketId = -1;
    std::shared_ptr<Socks5Instance> socks5Inst = std::make_shared<Socks5TcpInstance>(socketId);
    socks5Inst->SetSocks5Instance(socks5Inst);

    auto ret = socks5Inst->CreateSocks5MethodByType(Socks5MethodType::NO_AUTH);
    EXPECT_NE(ret, nullptr);

    ret = socks5Inst->CreateSocks5MethodByType(Socks5MethodType::PASSWORD);
    EXPECT_NE(ret, nullptr);

    ret = socks5Inst->CreateSocks5MethodByType(Socks5MethodType::GSSAPI);
    EXPECT_EQ(ret, nullptr);

    ret = socks5Inst->CreateSocks5MethodByType(Socks5MethodType::NO_METHODS);
    EXPECT_EQ(ret, nullptr);
}

HWTEST_F(Socks5Test, ConnectTcpTest001, TestSize.Level1)
{
    int32_t socketId = -1;
    auto socks5TcpInst = std::make_shared<Socks5TcpInstance>(socketId);
    socks5TcpInst->SetSocks5Instance(socks5TcpInst);
    socks5TcpInst->options_ = std::make_shared<Socks5Option>();
    socks5TcpInst->state_ = Socks5AuthState::SUCCESS;
    EXPECT_TRUE(socks5TcpInst->Connect());
    socks5TcpInst->state_ = Socks5AuthState::INIT;
    EXPECT_FALSE(socks5TcpInst->Connect());
}

HWTEST_F(Socks5Test, ConnectUdpTest001, TestSize.Level1)
{
    auto socks5UdpInst = std::make_shared<Socks5UdpInstance>();
    socks5UdpInst->SetSocks5Instance(socks5UdpInst);
    socks5UdpInst->options_ = std::make_shared<Socks5Option>();
    socks5UdpInst->state_ = Socks5AuthState::SUCCESS;
    EXPECT_TRUE(socks5UdpInst->Connect());
    socks5UdpInst->state_ = Socks5AuthState::INIT;
    EXPECT_FALSE(socks5UdpInst->Connect());
}

HWTEST_F(Socks5Test, ConnectProxyTest001, TestSize.Level1)
{
    auto socks5UdpInst = std::make_shared<Socks5UdpInstance>();
    socks5UdpInst->SetSocks5Instance(socks5UdpInst);
    socks5UdpInst->options_ = std::make_shared<Socks5Option>();
    EXPECT_FALSE(socks5UdpInst->ConnectProxy());
}

HWTEST_F(Socks5Test, RemoveHeaderTest001, TestSize.Level1)
{
    auto socks5UdpInst = std::make_shared<Socks5UdpInstance>();
    socks5UdpInst->SetSocks5Instance(socks5UdpInst);
    void *data = nullptr;
    size_t len = 2;
    int af = AF_INET;
    EXPECT_FALSE(socks5UdpInst->RemoveHeader(data, len, af));
}

HWTEST_F(Socks5Test, AddHeaderIPv4Test001, TestSize.Level1)
{
    auto socks5UdpInst = std::make_shared<Socks5UdpInstance>();
    socks5UdpInst->SetSocks5Instance(socks5UdpInst);
    Socket::NetAddress dest;
    dest.SetAddress("192.168.1.10");
    dest.SetFamilyBySaFamily(AF_INET);
    socks5UdpInst->SetDestAddress(dest);
    socks5UdpInst->AddHeader();
    EXPECT_EQ(socks5UdpInst->dest_.GetFamily(), Socket::NetAddress::Family::IPv4);
}

HWTEST_F(Socks5Test, AddHeaderIPv6Test001, TestSize.Level1)
{
    auto socks5UdpInst = std::make_shared<Socks5UdpInstance>();
    socks5UdpInst->SetSocks5Instance(socks5UdpInst);
    Socket::NetAddress dest;
    dest.SetAddress("fe80::100");
    dest.SetFamilyBySaFamily(AF_INET6);
    socks5UdpInst->SetDestAddress(dest);
    socks5UdpInst->AddHeader();
    EXPECT_EQ(socks5UdpInst->dest_.GetFamily(), Socket::NetAddress::Family::IPv6);
}

HWTEST_F(Socks5Test, GetSetHeaderTest001, TestSize.Level1)
{
    auto socks5UdpInst = std::make_shared<Socks5UdpInstance>();
    std::string testHeader = "\x00\x00\x00\x01\x01\xc0\xa8\x01\x0a\x00\x50";
    socks5UdpInst->SetHeader(testHeader);
    std::string retrieved = socks5UdpInst->GetHeader();
    EXPECT_EQ(retrieved, testHeader);
}

HWTEST_F(Socks5Test, UpdateErrorInfoTest001, TestSize.Level1)
{
    int32_t socketId = -1;
    std::shared_ptr<Socks5Instance> socks5Inst = std::make_shared<Socks5TcpInstance>(socketId);
    socks5Inst->UpdateErrorInfo(Socks5Status::SUCCESS);
    EXPECT_EQ(socks5Inst->GetErrorCode(), 0);

    socks5Inst->UpdateErrorInfo(100, "test error");
    EXPECT_EQ(socks5Inst->GetErrorCode(), 100);
    EXPECT_EQ(socks5Inst->GetErrorMessage(), "test error");
}

HWTEST_F(Socks5Test, IsConnectedTest001, TestSize.Level1)
{
    int32_t socketId = -1;
    std::shared_ptr<Socks5Instance> socks5Inst = std::make_shared<Socks5TcpInstance>(socketId);
    /* Not connected by default */
    EXPECT_FALSE(socks5Inst->IsConnected());

    /* After setting state to SUCCESS, IsConnected returns true
     * (it only checks state_ == SUCCESS, not socketId validity) */
    socks5Inst->state_ = Socks5AuthState::SUCCESS;
    EXPECT_TRUE(socks5Inst->IsConnected());
}

HWTEST_F(Socks5Test, GetSocketIdTest001, TestSize.Level1)
{
    int32_t socketId = 42;
    std::shared_ptr<Socks5Instance> socks5Inst = std::make_shared<Socks5TcpInstance>(socketId);
    EXPECT_EQ(socks5Inst->GetSocketId(), socketId);
}

HWTEST_F(Socks5Test, GetProxyBindAddressTest001, TestSize.Level1)
{
    int32_t socketId = -1;
    std::shared_ptr<Socks5Instance> socks5Inst = std::make_shared<Socks5TcpInstance>(socketId);
    auto bindAddr = socks5Inst->GetProxyBindAddress();
    /* Should return default-constructed address */
    (void)bindAddr;
    EXPECT_TRUE(true);
}

HWTEST_F(Socks5Test, CloseSocketTest001, TestSize.Level1)
{
    int32_t socketId = -1;
    std::shared_ptr<Socks5Instance> socks5Inst = std::make_shared<Socks5TcpInstance>(socketId);
    socks5Inst->CloseSocket();
    /* CloseSocket is a no-op for invalid fd, socketId remains unchanged */
    EXPECT_EQ(socks5Inst->GetSocketId(), socketId);
}

HWTEST_F(Socks5Test, TlsInstanceTest001, TestSize.Level1)
{
    int32_t socketId = -1;
    auto socks5TlsInst = std::make_shared<Socks5TlsInstance>(socketId);
    socks5TlsInst->options_ = std::make_shared<Socks5Option>();
    socks5TlsInst->SetSocks5Instance(socks5TlsInst);
    socks5TlsInst->state_ = Socks5AuthState::SUCCESS;
    EXPECT_TRUE(socks5TlsInst->Connect());
    socks5TlsInst->state_ = Socks5AuthState::INIT;
    EXPECT_FALSE(socks5TlsInst->Connect());
}

/* ==================== Socks5Package Serialization Tests ==================== */

HWTEST_F(Socks5Test, Socks5MethodPkgTest001, TestSize.Level1)
{
    Socks5MethodRequest request;
    Socks5MethodResponse response;

    request.version_ = 1;
    std::string serialized = request.Serialize();
    EXPECT_NE(serialized, "");

    EXPECT_FALSE(response.Deserialize(reinterpret_cast<const uint8_t *>(serialized.c_str()), 1));
    EXPECT_TRUE(response.Deserialize(reinterpret_cast<const uint8_t *>(serialized.c_str()), serialized.size()));
}

HWTEST_F(Socks5Test, Socks5AuthPkgTest001, TestSize.Level1)
{
    Socks5AuthRequest request;
    Socks5AuthResponse response;

    EXPECT_EQ(request.Serialize(), "");

    request.version_ = 1;
    request.username_ = TlsSocket::SecureData("user");
    request.password_ = TlsSocket::SecureData("pass");
    std::string serialized = request.Serialize();
    EXPECT_NE(serialized, "");

    EXPECT_FALSE(response.Deserialize(reinterpret_cast<const uint8_t *>(serialized.c_str()), 1));
    EXPECT_TRUE(response.Deserialize(reinterpret_cast<const uint8_t *>(serialized.c_str()), serialized.size()));
}

HWTEST_F(Socks5Test, Socks5ProxyPkgTest001, TestSize.Level1)
{
    Socks5ProxyRequest request;
    Socks5ProxyResponse response;

    EXPECT_EQ(request.Serialize(), "");

    request.version_ = 1;
    request.cmd_ = Socks5Command::TCP_CONNECTION;
    request.reserved_ = 1;
    request.destPort_ = 1;

    /* IPv4 */
    request.destAddr_ = "192.168.1.10";
    request.addrType_ = Socks5AddrType::IPV4;
    std::string serialized = request.Serialize();
    EXPECT_NE(serialized, "");
    EXPECT_FALSE(response.Deserialize(reinterpret_cast<const uint8_t *>(serialized.c_str()), 1));
    EXPECT_TRUE(response.Deserialize(reinterpret_cast<const uint8_t *>(serialized.c_str()), serialized.size()));

    /* DOMAIN_NAME */
    request.destAddr_ = "www.example.com";
    request.addrType_ = Socks5AddrType::DOMAIN_NAME;
    std::string serialized2 = request.Serialize();
    EXPECT_NE(serialized2, "");
    EXPECT_TRUE(response.Deserialize(reinterpret_cast<const uint8_t *>(serialized2.c_str()), serialized2.size()));

    /* IPv6 */
    request.destAddr_ = "fe80::100";
    request.addrType_ = Socks5AddrType::IPV6;
    std::string serialized3 = request.Serialize();
    EXPECT_NE(serialized3, "");
    EXPECT_TRUE(response.Deserialize(reinterpret_cast<const uint8_t *>(serialized3.c_str()), serialized3.size()));
}

HWTEST_F(Socks5Test, Socks5UdpHeaderPkgTest001, TestSize.Level1)
{
    Socks5UdpHeader header;

    EXPECT_EQ(header.Serialize(), "");

    header.reserved_ = 0;
    header.frag_ = 0;
    header.dstPort_ = 1;

    /* IPv4 */
    header.destAddr_ = "192.168.1.10";
    header.addrType_ = Socks5AddrType::IPV4;
    std::string serialized = header.Serialize();
    EXPECT_NE(serialized, "");
    EXPECT_FALSE(header.Deserialize(reinterpret_cast<const uint8_t *>(serialized.c_str()), 1));
    EXPECT_TRUE(header.Deserialize(reinterpret_cast<const uint8_t *>(serialized.c_str()), serialized.size()));

    /* DOMAIN_NAME */
    header.destAddr_ = "www.example.com";
    header.addrType_ = Socks5AddrType::DOMAIN_NAME;
    std::string serialized2 = header.Serialize();
    EXPECT_NE(serialized2, "");
    EXPECT_TRUE(header.Deserialize(reinterpret_cast<const uint8_t *>(serialized2.c_str()), serialized2.size()));

    /* IPv6 */
    header.destAddr_ = "fe80::100";
    header.addrType_ = Socks5AddrType::IPV6;
    std::string serialized3 = header.Serialize();
    EXPECT_NE(serialized3, "");
    EXPECT_TRUE(header.Deserialize(reinterpret_cast<const uint8_t *>(serialized3.c_str()), serialized3.size()));
}

/* ==================== Socks5Utils Tests ==================== */

HWTEST_F(Socks5Test, GetAddressLenTest001, TestSize.Level1)
{
    Socket::NetAddress addr;
    /* Default family is IPv4 */
    EXPECT_EQ(Socks5Utils::GetAddressLen(addr), sizeof(sockaddr_in));

    addr.SetFamilyBySaFamily(AF_INET6);
    EXPECT_EQ(Socks5Utils::GetAddressLen(addr), sizeof(sockaddr_in6));

    /* SetFamilyBySaFamily only updates family for AF_INET6.
     * For AF_UNSPEC/AF_INET, it does nothing — family stays unchanged.
     * To test a non-IP family, use SetFamilyByJsValue with DOMAIN_NAME. */
    Socket::NetAddress addr2;
    addr2.SetFamilyByJsValue(static_cast<uint32_t>(Socket::NetAddress::Family::DOMAIN_NAME));
    EXPECT_EQ(Socks5Utils::GetAddressLen(addr2), 0u);
}

HWTEST_F(Socks5Test, GetStatusMessageTest001, TestSize.Level1)
{
    std::string msg = Socks5Utils::GetStatusMessage(Socks5Status::SUCCESS);
    EXPECT_EQ(msg, "Success");

    msg = Socks5Utils::GetStatusMessage(Socks5Status::SOCKS5_NOT_ACTIVE);
    EXPECT_EQ(msg, "Socks5 is not active");

    /* Unknown status should return "Socks5 unassigned status" */
    msg = Socks5Utils::GetStatusMessage(Socks5Status::OTHER_STATUS);
    EXPECT_EQ(msg, "Socks5 unassigned status");
}

HWTEST_F(Socks5Test, RecvOnInvalidSocketTest001, TestSize.Level1)
{
    /* Recv on closed socket should fail gracefully.
     * Using fd=-1 causes poll to timeout forever (poll ignores negative fd and returns 0),
     * so we use a real socket that we immediately close. poll on a closed fd returns EBADF. */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_NE(sock, -1);
    close(sock);
    auto result = Socks5Utils::Recv(sock, nullptr, 0);
    EXPECT_FALSE(result.first);
    EXPECT_EQ(result.second, "");
}

HWTEST_F(Socks5Test, SendOnInvalidSocketTest001, TestSize.Level1)
{
    /* Send on invalid socket should fail gracefully */
    bool ret = Socks5Utils::Send(-1, "test", 4, nullptr, 0);
    EXPECT_FALSE(ret);
}

HWTEST_F(Socks5Test, PrintRecvErrMsgTest001, TestSize.Level1)
{
    /* PrintRecvErrMsg should not crash on any input */
    Socks5Utils::PrintRecvErrMsg(-1, EAGAIN, 0, "TEST");
    Socks5Utils::PrintRecvErrMsg(-1, EINTR, -1, "");
    EXPECT_TRUE(true);
}

HWTEST_F(Socks5Test, RequestProxyServerInvalidTest001, TestSize.Level1)
{
    int32_t socketId = -1;
    std::shared_ptr<Socks5Instance> socks5Inst = std::make_shared<Socks5TcpInstance>(socketId);
    socks5Inst->SetSocks5Instance(socks5Inst);
    socks5Inst->options_ = std::make_shared<Socks5Option>();
    Socks5ProxyRequest req;
    Socks5ProxyResponse rsp;
    std::pair<sockaddr *, socklen_t> addrInfo{nullptr, 0};

    /* Invalid socket should fail gracefully (Send on -1 returns false) */
    auto ret = Socks5Utils::RequestProxyServer(socks5Inst, socketId, addrInfo, &req, &rsp);
    EXPECT_FALSE(ret);
}

/* ==================== fdsan 双关修复：代理实例不得关闭属主 fd ==================== */

HWTEST_F(Socks5Test, TcpInstanceCloseSocketDisownTest001, TestSize.Level1)
{
    int fds[2] = {-1, -1};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    std::shared_ptr<Socks5Instance> socks5Inst = std::make_shared<Socks5TcpInstance>(fds[0]);
    socks5Inst->CloseSocket();
    /* 修复点：TCP 实例的 socketId_ 借自 EventManager，CloseSocket 只解绑、不关闭，
     * 避免 manager 的登记本残留已归还内核的 fd 号（后续 ExecClose 二次关闭 → fdsan） */
    EXPECT_EQ(socks5Inst->GetSocketId(), SOCKS5_INVALID_SOCKET_FD);
    EXPECT_GE(fcntl(fds[0], F_GETFD), 0);
    close(fds[0]);
    close(fds[1]);
}

HWTEST_F(Socks5Test, TlsInstanceCloseSocketDisownTest001, TestSize.Level1)
{
    int fds[2] = {-1, -1};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    std::shared_ptr<Socks5Instance> socks5Inst = std::make_shared<Socks5TlsInstance>(fds[0]);
    socks5Inst->CloseSocket();
    /* 修复点：TLS 实例同 TCP，只解绑不关闭 */
    EXPECT_EQ(socks5Inst->GetSocketId(), SOCKS5_INVALID_SOCKET_FD);
    EXPECT_GE(fcntl(fds[0], F_GETFD), 0);
    close(fds[0]);
    close(fds[1]);
}

HWTEST_F(Socks5Test, UdpInstanceCloseSocketOwnsFdTest001, TestSize.Level1)
{
    int fds[2] = {-1, -1};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    auto udpInst = std::make_shared<Socks5UdpInstance>();
    udpInst->socketId_ = fds[0];
    udpInst->CloseSocket();
    /* 回归点：UDP 实例的 fd 由自己 CreateSocket 创建、归自己所有，基类关闭语义必须保持 */
    EXPECT_EQ(udpInst->GetSocketId(), SOCKS5_INVALID_SOCKET_FD);
    EXPECT_EQ(fcntl(fds[0], F_GETFD), -1);
    close(fds[1]);
}

} // namespace Socks5
} // namespace NetStack
} // namespace OHOS
