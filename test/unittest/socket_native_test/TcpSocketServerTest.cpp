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

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "gtest/gtest.h"

#include "net_address.h"
#include "socket_constant.h"
#include "socket_remote_info.h"
#include "socket_state_base.h"
#include "tcp_extra_options.h"
#include "tcp_send_options.h"
#include "tcp_socket_server_innerapi.h"

namespace {
using namespace testing::ext;
using namespace OHOS::NetStack::Socket;

static constexpr int32_t INVALID_FD = -1;
static constexpr int32_t TEST_CLIENT_ID = 100;
static constexpr uint16_t TEST_PORT = 18080;
static constexpr uint16_t TEST_PORT_2 = 18081;
static constexpr const char *TEST_ADDRESS = "127.0.0.1";
static constexpr const char *TEST_DATA = "hello tcp server";
static constexpr int32_t SLEEP_MS = 100;
static constexpr uint32_t WAIT_TIMEOUT_MS = 10000;

static int32_t GetSocketFd(const std::shared_ptr<TCPSocketServer> &server)
{
    int32_t fd = INVALID_FD;
    (void)server->GetSocketFd(fd);
    return fd;
}

static int32_t GetConnectionSocketFd(const std::shared_ptr<TCPSocketConnection> &conn)
{
    int32_t fd = INVALID_FD;
    (void)conn->GetSocketFd(fd);
    return fd;
}

class TcpSocketServerTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/* Callbacks must match the typedefs in tcp_socket_server_innerapi.h:
 *   TCPSocketConnectionOnMessageCallback = void(const std::string &, const SocketRemoteInfo &)
 *   TCPSocketConnectionOnCloseCallback   = void(void)
 *   TCPSocketConnectionOnErrorCallback   = void(int32_t, const std::string &)
 *   TCPSocketServerOnConnectCallback     = void(const int &clientId)
 *   TCPSocketServerOnErrorCallback       = void(int32_t, const std::string &)
 */
static void OnConnectionMessageCallback(const std::string &data, const SocketRemoteInfo &remoteInfo)
{
    (void)data;
    (void)remoteInfo;
}

static void OnConnectionCloseCallback()
{
}

static void OnConnectionErrorCallback(int32_t errorNumber, const std::string &errorString)
{
    (void)errorNumber;
    (void)errorString;
}

static void OnServerConnectCallback(const int &clientId)
{
    (void)clientId;
}

static void OnServerErrorCallback(int32_t errorNumber, const std::string &errorString)
{
    (void)errorNumber;
    (void)errorString;
}

/* ==================== TCPSocketConnection Tests ==================== */

HWTEST_F(TcpSocketServerTest, ConnectionConstructor001, TestSize.Level1)
{
    auto conn = std::make_shared<TCPSocketConnection>(TEST_CLIENT_ID);
    EXPECT_EQ(conn->GetClientId(), TEST_CLIENT_ID);
    int32_t fd = INVALID_FD;
    EXPECT_EQ(conn->GetSocketFd(fd), SYSTEM_INTERNAL_ERROR);
}

HWTEST_F(TcpSocketServerTest, ConnectionOnOffCallbacks001, TestSize.Level1)
{
    auto conn = std::make_shared<TCPSocketConnection>(TEST_CLIENT_ID);
    EXPECT_NE(conn, nullptr);
    conn->OnMessage(OnConnectionMessageCallback);
    conn->OnClose(OnConnectionCloseCallback);
    conn->OnError(OnConnectionErrorCallback);

    EXPECT_EQ(conn->GetClientId(), TEST_CLIENT_ID);

    conn->OffMessage();
    conn->OffClose();
    conn->OffError();
    EXPECT_EQ(conn->GetClientId(), TEST_CLIENT_ID);
}

HWTEST_F(TcpSocketServerTest, ConnectionOnOffCallbacks002, TestSize.Level1)
{
    auto conn = std::make_shared<TCPSocketConnection>(TEST_CLIENT_ID);
    EXPECT_NE(conn, nullptr);
    /* Calling Off without On should be safe */
    conn->OffMessage();
    conn->OffClose();
    conn->OffError();
    EXPECT_EQ(conn->GetClientId(), TEST_CLIENT_ID);
}

HWTEST_F(TcpSocketServerTest, ConnectionSend001, TestSize.Level1)
{
    auto conn = std::make_shared<TCPSocketConnection>(TEST_CLIENT_ID);
    TCPSendOptions options;
    options.SetData(TEST_DATA);
    int ret = conn->Send(options);
    EXPECT_EQ(ret, SYSTEM_INTERNAL_ERROR);
}

HWTEST_F(TcpSocketServerTest, ConnectionSend002, TestSize.Level1)
{
    int sv[2] = {-1, -1};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    auto conn = std::make_shared<TCPSocketConnection>(TEST_CLIENT_ID);
    conn->SetSocketFd(sv[0]);
    TCPSendOptions options;
    options.SetData("");
    int ret = conn->Send(options);
    EXPECT_EQ(ret, PARAM_ERROR_CODE);
    close(sv[0]);
    close(sv[1]);
}

HWTEST_F(TcpSocketServerTest, ConnectionSend003, TestSize.Level1)
{
    int sv[2] = {-1, -1};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    auto conn = std::make_shared<TCPSocketConnection>(TEST_CLIENT_ID);
    conn->SetSocketFd(sv[0]);
    TCPSendOptions options;
    options.SetData(TEST_DATA);
    int ret = conn->Send(options);
    EXPECT_NE(ret, SOCKET_ERROR_OK);
    close(sv[0]);
    close(sv[1]);
}

HWTEST_F(TcpSocketServerTest, ConnectionClose001, TestSize.Level1)
{
    int sv[2] = {-1, -1};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    auto conn = std::make_shared<TCPSocketConnection>(TEST_CLIENT_ID);
    conn->SetSocketFd(sv[0]);
    int ret = conn->Close();
    EXPECT_EQ(ret, SOCKET_ERROR_OK);
    int32_t fd = INVALID_FD;
    EXPECT_EQ(conn->GetSocketFd(fd), SYSTEM_INTERNAL_ERROR);
    close(sv[1]);
}

HWTEST_F(TcpSocketServerTest, ConnectionClose002, TestSize.Level1)
{
    auto conn = std::make_shared<TCPSocketConnection>(TEST_CLIENT_ID);
    int ret = conn->Close();
    EXPECT_EQ(ret, SOCKET_ERROR_OK);
}

HWTEST_F(TcpSocketServerTest, ConnectionClose003, TestSize.Level1)
{
    int sv[2] = {-1, -1};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    auto conn = std::make_shared<TCPSocketConnection>(TEST_CLIENT_ID);
    conn->SetSocketFd(sv[0]);
    conn->OnClose([]() {});
    int ret = conn->Close();
    EXPECT_EQ(ret, SOCKET_ERROR_OK);
    close(sv[1]);
}

HWTEST_F(TcpSocketServerTest, ConnectionClose004, TestSize.Level1)
{
    int sv[2] = {-1, -1};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    auto conn = std::make_shared<TCPSocketConnection>(TEST_CLIENT_ID);
    conn->SetSocketFd(sv[0]);
    conn->Close();
    int ret = conn->Close();
    EXPECT_EQ(ret, SOCKET_ERROR_OK);
    close(sv[1]);
}

HWTEST_F(TcpSocketServerTest, ConnectionGetRemoteAddress001, TestSize.Level1)
{
    auto conn = std::make_shared<TCPSocketConnection>(TEST_CLIENT_ID);
    NetAddress address;
    int ret = conn->GetRemoteAddress(address);
    EXPECT_EQ(ret, SYSTEM_INTERNAL_ERROR);
}

HWTEST_F(TcpSocketServerTest, ConnectionGetRemoteAddress002, TestSize.Level1)
{
    int sv[2] = {-1, -1};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    auto conn = std::make_shared<TCPSocketConnection>(TEST_CLIENT_ID);
    conn->SetSocketFd(sv[0]);
    NetAddress address;
    int ret = conn->GetRemoteAddress(address);
    EXPECT_EQ(ret, static_cast<int32_t>(SOCKET_SERVER_ERROR_CODE_BASE) + ERRNO_BAD_FD);
    close(sv[0]);
    close(sv[1]);
}

HWTEST_F(TcpSocketServerTest, ConnectionGetLocalAddress001, TestSize.Level1)
{
    auto conn = std::make_shared<TCPSocketConnection>(TEST_CLIENT_ID);
    NetAddress address;
    int ret = conn->GetLocalAddress(address);
    EXPECT_EQ(ret, SYSTEM_INTERNAL_ERROR);
}

HWTEST_F(TcpSocketServerTest, ConnectionGetLocalAddress002, TestSize.Level1)
{
    int sv[2] = {-1, -1};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    auto conn = std::make_shared<TCPSocketConnection>(TEST_CLIENT_ID);
    conn->SetSocketFd(sv[0]);
    NetAddress address;
    int ret = conn->GetLocalAddress(address);
    EXPECT_EQ(ret, static_cast<int32_t>(SOCKET_SERVER_ERROR_CODE_BASE) + ERRNO_BAD_FD);
    close(sv[0]);
    close(sv[1]);
}

HWTEST_F(TcpSocketServerTest, ConnectionGetSocketFd001, TestSize.Level1)
{
    auto conn = std::make_shared<TCPSocketConnection>(TEST_CLIENT_ID);
    int32_t fd = INVALID_FD;
    EXPECT_EQ(conn->GetSocketFd(fd), SYSTEM_INTERNAL_ERROR);
}

HWTEST_F(TcpSocketServerTest, ConnectionGetSocketFd002, TestSize.Level1)
{
    int sv[2] = {-1, -1};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    auto conn = std::make_shared<TCPSocketConnection>(TEST_CLIENT_ID);
    conn->SetSocketFd(sv[0]);
    int32_t fd = INVALID_FD;
    EXPECT_EQ(conn->GetSocketFd(fd), SOCKET_ERROR_OK);
    EXPECT_EQ(fd, sv[0]);
    close(sv[0]);
    close(sv[1]);
}

HWTEST_F(TcpSocketServerTest, ConnectionDestructor001, TestSize.Level1)
{
    int sv[2] = {-1, -1};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    {
        auto conn = std::make_shared<TCPSocketConnection>(TEST_CLIENT_ID);
        conn->SetSocketFd(sv[0]);
        int32_t fd = INVALID_FD;
        EXPECT_EQ(conn->GetSocketFd(fd), SOCKET_ERROR_OK);
        EXPECT_EQ(fd, sv[0]);
    }
    close(sv[1]);
}

/* ==================== TCPSocketServer Tests ==================== */

HWTEST_F(TcpSocketServerTest, ServerConstructor001, TestSize.Level1)
{
    auto server = std::make_shared<TCPSocketServer>();
    EXPECT_NE(server, nullptr);
    EXPECT_EQ(GetSocketFd(server), INVALID_FD);
    SocketStateBase state;
    EXPECT_EQ(server->GetState(state), SYSTEM_INTERNAL_ERROR);
    EXPECT_TRUE(state.IsClose());
}

HWTEST_F(TcpSocketServerTest, ServerOnOffCallback001, TestSize.Level1)
{
    auto server = std::make_shared<TCPSocketServer>();
    EXPECT_NE(server, nullptr);
    server->OnConnect(OnServerConnectCallback);
    server->OnError(OnServerErrorCallback);

    server->OffConnect();
    server->OffError();
    EXPECT_EQ(GetSocketFd(server), INVALID_FD);
}

HWTEST_F(TcpSocketServerTest, ServerOnOffCallback002, TestSize.Level1)
{
    auto server = std::make_shared<TCPSocketServer>();
    EXPECT_NE(server, nullptr);
    /* Calling Off without On should be safe */
    server->OffConnect();
    server->OffError();
    EXPECT_EQ(GetSocketFd(server), INVALID_FD);
}

HWTEST_F(TcpSocketServerTest, ServerListen001, TestSize.Level1)
{
    auto server = std::make_shared<TCPSocketServer>();
    NetAddress address;
    address.SetAddress(TEST_ADDRESS);
    address.SetPort(TEST_PORT);
    address.SetFamilyBySaFamily(AF_INET);
    int ret = server->Listen(address);
    EXPECT_EQ(ret, SOCKET_ERROR_OK);
    EXPECT_GE(GetSocketFd(server), 0);
    server->Close();
}

HWTEST_F(TcpSocketServerTest, ServerListen002, TestSize.Level1)
{
    auto server = std::make_shared<TCPSocketServer>();
    NetAddress address;
    address.SetAddress("0.0.0.0");
    address.SetPort(0);
    address.SetFamilyBySaFamily(AF_INET);
    int ret = server->Listen(address);
    EXPECT_EQ(ret, SOCKET_ERROR_OK);
    server->Close();
}

HWTEST_F(TcpSocketServerTest, ServerListen004, TestSize.Level1)
{
    auto server = std::make_shared<TCPSocketServer>();
    NetAddress address;
    address.SetAddress("");
    address.SetPort(TEST_PORT);
    address.SetFamilyBySaFamily(AF_INET);
    int ret = server->Listen(address);
    EXPECT_EQ(ret, PARAM_ERROR_CODE);
}

HWTEST_F(TcpSocketServerTest, ServerListen006, TestSize.Level1)
{
    /* Listen on an unreachable private address (192.168.255.255/32) */
    auto server = std::make_shared<TCPSocketServer>();
    NetAddress address;
    address.SetAddress("192.168.255.255");
    address.SetPort(TEST_PORT);
    address.SetFamilyBySaFamily(AF_INET);
    int ret = server->Listen(address);
    /* 2303199 = SOCKET_SERVER_ERROR_CODE_BASE(2303100) + EADDRNOTAVAIL(99) */
    EXPECT_EQ(ret, 2303199);
}

HWTEST_F(TcpSocketServerTest, ServerClose001, TestSize.Level1)
{
    auto server = std::make_shared<TCPSocketServer>();
    int ret = server->Close();
    EXPECT_EQ(ret, SYSTEM_INTERNAL_ERROR);
}

HWTEST_F(TcpSocketServerTest, ServerClose002, TestSize.Level1)
{
    auto server = std::make_shared<TCPSocketServer>();
    NetAddress address;
    address.SetAddress(TEST_ADDRESS);
    address.SetPort(TEST_PORT_2);
    address.SetFamilyBySaFamily(AF_INET);
    server->Listen(address);
    int ret = server->Close();
    EXPECT_EQ(ret, SOCKET_ERROR_OK);
    EXPECT_EQ(GetSocketFd(server), INVALID_FD);
}

HWTEST_F(TcpSocketServerTest, ServerClose003, TestSize.Level1)
{
    auto server = std::make_shared<TCPSocketServer>();
    NetAddress address;
    address.SetAddress(TEST_ADDRESS);
    address.SetPort(0);
    address.SetFamilyBySaFamily(AF_INET);
    server->Listen(address);
    server->Close();
    int ret = server->Close();
    EXPECT_EQ(ret, SYSTEM_INTERNAL_ERROR);
}

HWTEST_F(TcpSocketServerTest, ServerGetState001, TestSize.Level1)
{
    auto server = std::make_shared<TCPSocketServer>();
    SocketStateBase state;
    int ret = server->GetState(state);
    EXPECT_EQ(ret, SYSTEM_INTERNAL_ERROR);
    EXPECT_TRUE(state.IsClose());
}

HWTEST_F(TcpSocketServerTest, ServerGetState002, TestSize.Level1)
{
    auto server = std::make_shared<TCPSocketServer>();
    NetAddress address;
    address.SetAddress(TEST_ADDRESS);
    address.SetPort(0);
    address.SetFamilyBySaFamily(AF_INET);
    server->Listen(address);
    SocketStateBase state;
    int ret = server->GetState(state);
    EXPECT_EQ(ret, SOCKET_ERROR_OK);
    EXPECT_FALSE(state.IsClose());
    EXPECT_TRUE(state.IsBound());
    server->Close();
}

HWTEST_F(TcpSocketServerTest, ServerGetState003, TestSize.Level1)
{
    /* GetState after close should return SYSTEM_INTERNAL_ERROR */
    auto server = std::make_shared<TCPSocketServer>();
    NetAddress address;
    address.SetAddress(TEST_ADDRESS);
    address.SetPort(TEST_PORT_2);
    address.SetFamilyBySaFamily(AF_INET);
    server->Listen(address);
    server->Close();
    SocketStateBase state;
    int ret = server->GetState(state);
    EXPECT_EQ(ret, SYSTEM_INTERNAL_ERROR);
    EXPECT_TRUE(state.IsClose());
}

HWTEST_F(TcpSocketServerTest, ServerGetLocalAddress001, TestSize.Level1)
{
    auto server = std::make_shared<TCPSocketServer>();
    NetAddress address;
    int ret = server->GetLocalAddress(address);
    EXPECT_EQ(ret, SYSTEM_INTERNAL_ERROR);
}

HWTEST_F(TcpSocketServerTest, ServerGetLocalAddress002, TestSize.Level1)
{
    auto server = std::make_shared<TCPSocketServer>();
    NetAddress address;
    address.SetAddress(TEST_ADDRESS);
    address.SetPort(0);
    address.SetFamilyBySaFamily(AF_INET);
    server->Listen(address);
    NetAddress localAddr;
    int ret = server->GetLocalAddress(localAddr);
    EXPECT_EQ(ret, SOCKET_ERROR_OK);
    server->Close();
}

HWTEST_F(TcpSocketServerTest, ServerGetSocketFd001, TestSize.Level1)
{
    auto server = std::make_shared<TCPSocketServer>();
    EXPECT_NE(server, nullptr);
    EXPECT_EQ(GetSocketFd(server), INVALID_FD);
    SocketStateBase state;
    EXPECT_EQ(server->GetState(state), SYSTEM_INTERNAL_ERROR);
}

HWTEST_F(TcpSocketServerTest, ServerGetSocketFd002, TestSize.Level1)
{
    auto server = std::make_shared<TCPSocketServer>();
    NetAddress address;
    address.SetAddress(TEST_ADDRESS);
    address.SetPort(0);
    address.SetFamilyBySaFamily(AF_INET);
    server->Listen(address);
    EXPECT_GE(GetSocketFd(server), 0);
    server->Close();
}

HWTEST_F(TcpSocketServerTest, ServerSetExtraOptions001, TestSize.Level1)
{
    auto server = std::make_shared<TCPSocketServer>();
    TCPExtraOptions options;
    int ret = server->SetExtraOptions(options);
    EXPECT_EQ(ret, SYSTEM_INTERNAL_ERROR);
}

HWTEST_F(TcpSocketServerTest, ServerSetExtraOptions002, TestSize.Level1)
{
    auto server = std::make_shared<TCPSocketServer>();
    NetAddress address;
    address.SetAddress(TEST_ADDRESS);
    address.SetPort(0);
    address.SetFamilyBySaFamily(AF_INET);
    server->Listen(address);
    TCPExtraOptions options;
    options.SetKeepAlive(true);
    options.SetKeepAliveFlag(true);
    int ret = server->SetExtraOptions(options);
    EXPECT_EQ(ret, SOCKET_ERROR_OK);
    server->Close();
}

HWTEST_F(TcpSocketServerTest, ServerSetExtraOptions003, TestSize.Level1)
{
    auto server = std::make_shared<TCPSocketServer>();
    NetAddress address;
    address.SetAddress(TEST_ADDRESS);
    address.SetPort(0);
    address.SetFamilyBySaFamily(AF_INET);
    server->Listen(address);
    TCPExtraOptions options;
    options.SetTCPNoDelay(true);
    int ret = server->SetExtraOptions(options);
    EXPECT_EQ(ret, SOCKET_ERROR_OK);
    server->Close();
}

/* ==================== Server Accept / Connection Tests ==================== */

static int ConnectToServer(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static bool WaitForConnection(std::shared_ptr<TCPSocketServer> &server, int32_t clientId,
    uint32_t timeoutMs = WAIT_TIMEOUT_MS)
{
    auto start = std::chrono::steady_clock::now();
    while (std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count() < static_cast<int64_t>(timeoutMs)) {
        auto conn = server->GetConnectionByClientID(clientId);
        if (conn != nullptr && GetConnectionSocketFd(conn) >= 0) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_MS));
    }
    return false;
}

static uint16_t ListenAndGetRealPort(std::shared_ptr<TCPSocketServer> &server)
{
    NetAddress address;
    address.SetAddress(TEST_ADDRESS);
    address.SetPort(0);
    address.SetFamilyBySaFamily(AF_INET);
    if (server->Listen(address) != SOCKET_ERROR_OK) {
        return 0;
    }
    int32_t listenFd = GetSocketFd(server);
    sockaddr_in realAddr = {0};
    socklen_t len = sizeof(realAddr);
    if (getsockname(listenFd, reinterpret_cast<sockaddr *>(&realAddr), &len) < 0) {
        return 0;
    }
    return ntohs(realAddr.sin_port);
}

static void WaitForClientId(std::atomic<int32_t> &clientId)
{
    auto start = std::chrono::steady_clock::now();
    while (clientId.load() == -1) {
        std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_MS));
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed >= static_cast<int64_t>(WAIT_TIMEOUT_MS)) {
            break;
        }
    }
}

static int ConnectAndAccept(std::shared_ptr<TCPSocketServer> &server, uint16_t port,
                            std::atomic<int32_t> &clientId)
{
    server->OnConnect([&](const int &id) { clientId.store(id); });
    int clientFd = ConnectToServer(port);
    if (clientFd < 0) {
        return -1;
    }
    WaitForClientId(clientId);
    if (clientId.load() == -1 || !WaitForConnection(server, clientId.load())) {
        return -1;
    }
    return clientFd;
}

HWTEST_F(TcpSocketServerTest, ServerAccept001, TestSize.Level1)
{
    auto server = std::make_shared<TCPSocketServer>();
    NetAddress address;
    address.SetAddress(TEST_ADDRESS);
    address.SetPort(0);
    address.SetFamilyBySaFamily(AF_INET);
    ASSERT_EQ(server->Listen(address), SOCKET_ERROR_OK);

    int32_t listenFd = GetSocketFd(server);
    sockaddr_in realAddr = {0};
    socklen_t len = sizeof(realAddr);
    ASSERT_EQ(getsockname(listenFd, reinterpret_cast<sockaddr *>(&realAddr), &len), 0);
    uint16_t realPort = ntohs(realAddr.sin_port);

    std::atomic<bool> connectCalled(false);
    std::atomic<int32_t> connectedClientId(-1);
    server->OnConnect([&](const int &clientId) {
        connectedClientId.store(clientId);
        connectCalled.store(true);
    });

    int clientFd = ConnectToServer(realPort);
    ASSERT_GE(clientFd, 0);

    /* Wait for the accept thread to process the connection and fire OnConnect */
    auto start = std::chrono::steady_clock::now();
    while (!connectCalled.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_MS));
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed >= static_cast<int64_t>(WAIT_TIMEOUT_MS)) {
            break;
        }
    }

    EXPECT_TRUE(connectCalled.load());
    EXPECT_NE(connectedClientId.load(), -1);

    auto conn = server->GetConnectionByClientID(connectedClientId.load());
    ASSERT_NE(conn, nullptr);
    EXPECT_EQ(conn->GetClientId(), connectedClientId.load());

    close(clientFd);
    server->Close();
}

HWTEST_F(TcpSocketServerTest, ServerGetConnectionByClientID001, TestSize.Level1)
{
    auto server = std::make_shared<TCPSocketServer>();
    EXPECT_NE(server, nullptr);
    EXPECT_EQ(server->GetConnectionByClientID(TEST_CLIENT_ID), nullptr);
    EXPECT_EQ(GetSocketFd(server), INVALID_FD);
}

static bool SendAndWaitForMessage(int clientFd, const char *data, size_t len,
    std::shared_ptr<TCPSocketConnection> &conn, std::string &receivedData)
{
    struct MessageState {
        std::mutex msgMutex;
        std::condition_variable msgCv;
        bool msgReceived = false;
    };
    auto state = std::make_shared<MessageState>();
    conn->OnMessage([state, &receivedData](const std::string &d, const SocketRemoteInfo &remoteInfo) {
        std::lock_guard<std::mutex> lock(state->msgMutex);
        receivedData = d;
        state->msgReceived = true;
        (void)remoteInfo;
        state->msgCv.notify_one();
    });

    ssize_t sent = send(clientFd, data, len, 0);
    if (sent <= 0) {
        return false;
    }

    std::unique_lock<std::mutex> lock(state->msgMutex);
    return state->msgCv.wait_for(lock, std::chrono::milliseconds(WAIT_TIMEOUT_MS),
        [state]() { return state->msgReceived; });
}

HWTEST_F(TcpSocketServerTest, ServerReceiveMessage001, TestSize.Level1)
{
    auto server = std::make_shared<TCPSocketServer>();
    uint16_t realPort = ListenAndGetRealPort(server);
    ASSERT_NE(realPort, 0);

    std::atomic<int32_t> connectedClientId(-1);
    int clientFd = ConnectAndAccept(server, realPort, connectedClientId);
    ASSERT_GE(clientFd, 0);

    auto conn = server->GetConnectionByClientID(connectedClientId.load());
    ASSERT_NE(conn, nullptr);

    std::string receivedData;
    EXPECT_TRUE(SendAndWaitForMessage(clientFd, TEST_DATA, strlen(TEST_DATA), conn, receivedData));
    EXPECT_EQ(receivedData, TEST_DATA);

    close(clientFd);
    server->Close();
}

HWTEST_F(TcpSocketServerTest, ServerSendToConnection001, TestSize.Level1)
{
    auto server = std::make_shared<TCPSocketServer>();
    NetAddress address;
    address.SetAddress(TEST_ADDRESS);
    address.SetPort(0);
    address.SetFamilyBySaFamily(AF_INET);
    ASSERT_EQ(server->Listen(address), SOCKET_ERROR_OK);

    int32_t listenFd = GetSocketFd(server);
    sockaddr_in realAddr = {0};
    socklen_t len = sizeof(realAddr);
    ASSERT_EQ(getsockname(listenFd, reinterpret_cast<sockaddr *>(&realAddr), &len), 0);
    uint16_t realPort = ntohs(realAddr.sin_port);

    std::atomic<int32_t> connectedClientId(-1);
    server->OnConnect([&](const int &clientId) { connectedClientId.store(clientId); });

    int clientFd = ConnectToServer(realPort);
    ASSERT_GE(clientFd, 0);

    /* Wait for the accept thread to process the connection and set connectedClientId */
    {
        auto start = std::chrono::steady_clock::now();
        while (connectedClientId.load() == -1) {
            std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_MS));
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();
            if (elapsed >= static_cast<int64_t>(WAIT_TIMEOUT_MS)) {
                break;
            }
        }
    }

    ASSERT_TRUE(WaitForConnection(server, connectedClientId.load()));
    auto conn = server->GetConnectionByClientID(connectedClientId.load());
    ASSERT_NE(conn, nullptr);

    TCPSendOptions options;
    options.SetData(TEST_DATA);
    int ret = conn->Send(options);
    ASSERT_EQ(ret, SOCKET_ERROR_OK);

    char buf[64] = {0};
    int recvLen = recv(clientFd, buf, sizeof(buf), 0);
    EXPECT_GT(recvLen, 0);
    EXPECT_EQ(std::string(buf, recvLen), TEST_DATA);

    close(clientFd);
    server->Close();
}

HWTEST_F(TcpSocketServerTest, ServerConnectionClose001, TestSize.Level1)
{
    auto server = std::make_shared<TCPSocketServer>();
    NetAddress address;
    address.SetAddress(TEST_ADDRESS);
    address.SetPort(0);
    address.SetFamilyBySaFamily(AF_INET);
    ASSERT_EQ(server->Listen(address), SOCKET_ERROR_OK);

    int32_t listenFd = GetSocketFd(server);
    sockaddr_in realAddr = {0};
    socklen_t len = sizeof(realAddr);
    ASSERT_EQ(getsockname(listenFd, reinterpret_cast<sockaddr *>(&realAddr), &len), 0);
    uint16_t realPort = ntohs(realAddr.sin_port);

    std::atomic<int32_t> connectedClientId(-1);
    server->OnConnect([&](const int &clientId) { connectedClientId.store(clientId); });

    int clientFd = ConnectToServer(realPort);
    ASSERT_GE(clientFd, 0);

    /* Wait for the accept thread to process the connection and set connectedClientId */
    {
        auto start = std::chrono::steady_clock::now();
        while (connectedClientId.load() == -1) {
            std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_MS));
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();
            if (elapsed >= static_cast<int64_t>(WAIT_TIMEOUT_MS)) {
                break;
            }
        }
    }

    ASSERT_TRUE(WaitForConnection(server, connectedClientId.load()));
    auto conn = server->GetConnectionByClientID(connectedClientId.load());
    ASSERT_NE(conn, nullptr);

    int ret = conn->Close();
    EXPECT_EQ(ret, SOCKET_ERROR_OK);
    /* Note: conn->Close() only closes the fd and fires OnClose callback.
     * The connection is removed from the server's connectionMap_ asynchronously
     * by the accept thread when it detects the fd is closed. */

    close(clientFd);
    server->Close();
}

HWTEST_F(TcpSocketServerTest, ServerErrorCallback001, TestSize.Level1)
{
    auto server = std::make_shared<TCPSocketServer>();
    std::atomic<bool> errorSet(false);
    server->OnError([&errorSet](int32_t errCode, const std::string &errMsg) {
        (void)errCode;
        (void)errMsg;
        errorSet.store(true);
    });

    NetAddress address;
    address.SetAddress(TEST_ADDRESS);
    address.SetPort(0);
    address.SetFamilyBySaFamily(AF_INET);
    ASSERT_EQ(server->Listen(address), SOCKET_ERROR_OK);
    server->Close();

    /* Error callback may not be triggered during normal close */
    EXPECT_FALSE(errorSet.load());
}

HWTEST_F(TcpSocketServerTest, ConnectionWaitForMessageCallback001, TestSize.Level1)
{
    int sv[2] = {-1, -1};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    auto conn = std::make_shared<TCPSocketConnection>(TEST_CLIENT_ID);
    conn->SetSocketFd(sv[0]);
    conn->OnMessage(OnConnectionMessageCallback);
    EXPECT_TRUE(conn->WaitForMessageCallback());
    close(sv[0]);
    close(sv[1]);
}

HWTEST_F(TcpSocketServerTest, ConnectionWaitForMessageCallback002, TestSize.Level1)
{
    auto conn = std::make_shared<TCPSocketConnection>(TEST_CLIENT_ID);
    EXPECT_FALSE(conn->WaitForMessageCallback());
}

HWTEST_F(TcpSocketServerTest, ConnectionWaitForMessageCallback003, TestSize.Level1)
{
    int sv[2] = {-1, -1};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    auto conn = std::make_shared<TCPSocketConnection>(TEST_CLIENT_ID);
    conn->SetSocketFd(sv[0]);
    std::thread closer([conn]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_MS));
        conn->Close();
    });
    EXPECT_FALSE(conn->WaitForMessageCallback());
    closer.join();
    close(sv[1]);
}

HWTEST_F(TcpSocketServerTest, ConnectionWaitForMessageCallback004, TestSize.Level1)
{
    int sv[2] = {-1, -1};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    auto conn = std::make_shared<TCPSocketConnection>(TEST_CLIENT_ID);
    conn->SetSocketFd(sv[0]);
    EXPECT_FALSE(conn->WaitForMessageCallback());
    close(sv[0]);
    close(sv[1]);
}

HWTEST_F(TcpSocketServerTest, ServerClientAbortBeforeMessageRegistered001, TestSize.Level1)
{
    auto server = std::make_shared<TCPSocketServer>();
    uint16_t realPort = ListenAndGetRealPort(server);
    ASSERT_NE(realPort, 0);

    std::atomic<int32_t> connectedClientId(-1);
    int clientFd = ConnectAndAccept(server, realPort, connectedClientId);
    ASSERT_GE(clientFd, 0);

    auto conn = server->GetConnectionByClientID(connectedClientId.load());
    ASSERT_NE(conn, nullptr);

    EXPECT_EQ(conn->Close(), SOCKET_ERROR_OK);

    auto start = std::chrono::steady_clock::now();
    while (server->GetConnectionByClientID(connectedClientId.load()) != nullptr) {
        std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_MS));
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed >= static_cast<int64_t>(WAIT_TIMEOUT_MS)) {
            break;
        }
    }
    EXPECT_EQ(server->GetConnectionByClientID(connectedClientId.load()), nullptr);

    close(clientFd);
    server->Close();
}

} // namespace
