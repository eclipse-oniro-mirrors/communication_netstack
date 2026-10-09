/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "netstack_log.h"
#include "gtest/gtest.h"
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <iostream>
#include <limits>
#include <thread>
#include <vector>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include "bind_context.h"
#include "local_socket_context.h"
#include "local_socket_exec.h"
#include "local_socket_server_context.h"
#include "multicast_get_loopback_context.h"
#include "multicast_get_ttl_context.h"
#include "multicast_membership_context.h"
#include "multicast_set_loopback_context.h"
#include "multicast_set_reuse_address_context.h"
#include "multicast_set_ttl_context.h"
#include "socket_exec.h"
#include "socket_exec_common.h"
#include "tcp_extra_context.h"

#include "socks5.h"
#include "socks5_instance.h"
#include "socks5_none_method.h"
#include "socks5_passwd_method.h"
#include "socks5_package.h"
#include "socks5_utils.h"
#include "connect_monitor.h"

class SocketTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

namespace {
using namespace std;
using namespace testing::ext;
using namespace OHOS::NetStack;
using namespace OHOS::NetStack::Socket;
using namespace OHOS::NetStack::Socks5;

static constexpr const int SLEEP_TIME_TEN = 10;

static OHOS::sptr<ConnectWatchData> CreateConnectWatchData(int64_t deadlineMs = 200)
{
    auto data = OHOS::sptr<ConnectWatchData>(new ConnectWatchData());
    data->deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(deadlineMs);
    return data;
}

static void WaitMonitorStopped(ConnectMonitor &monitor, int32_t timeoutMs = 1000)
{
    for (int32_t waited = 0; waited < timeoutMs && monitor.running_.load(); waited += SLEEP_TIME_TEN) {
        std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME_TEN));
    }
}

static void ResetConnectMonitorState(ConnectMonitor &monitor)
{
    {
        std::lock_guard<std::mutex> lifecycleLock(monitor.lifecycleMutex_);
        monitor.running_.store(false);
        monitor.WakeUp();
        if (monitor.thread_.joinable()) {
            monitor.thread_.join();
        }
    }
    std::lock_guard<std::mutex> lock(monitor.mutex_);
    monitor.pendings_.clear();
    monitor.deadlines_.clear();
    monitor.deadlineIters_.clear();
}

static void InitUdpBindContext(BindContext &context, uint16_t port)
{
    context.address_.SetAddress("127.0.0.1");
    context.address_.SetPort(port);
    context.address_.SetFamilyBySaFamily(AF_INET);
}

static int CreateManagedUdpSocket(const std::shared_ptr<EventManager> &eventManager)
{
    int sockFd = ExecCommonUtils::MakeUdpSocket(AF_INET);
    EXPECT_GE(sockFd, 0);
    if (sockFd >= 0) {
        eventManager->SetSocketFd(sockFd);
    }
    return sockFd;
}

static void CloseManagedSocket(const std::shared_ptr<EventManager> &eventManager)
{
    int sockFd = eventManager->GetSocketFd();
    if (sockFd >= 0) {
        close(sockFd);
    }
    eventManager->SetSocketFd(-1);
}

static int GetReuseAddressOption(int sockFd)
{
    int reuse = 0;
    socklen_t reuseLen = sizeof(reuse);
    EXPECT_EQ(getsockopt(sockFd, SOL_SOCKET, SO_REUSEADDR, &reuse, &reuseLen), 0);
    return reuse;
}

HWTEST_F(SocketTest, MulticastTest001, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    MulticastMembershipContext context(env, eventManager);
    bool ret = SocketExec::ExecUdpAddMembership(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, MulticastTest002, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    MulticastMembershipContext context(env, eventManager);
    bool ret = SocketExec::ExecUdpDropMembership(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, MulticastTest003, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    MulticastSetTTLContext context(env, eventManager);
    bool ret = SocketExec::ExecSetMulticastTTL(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, MulticastTest004, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    MulticastGetTTLContext context(env, eventManager);
    bool ret = SocketExec::ExecGetMulticastTTL(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, MulticastTest005, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    MulticastSetLoopbackContext context(env, eventManager);
    bool ret = SocketExec::ExecSetLoopbackMode(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, MulticastTest006, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    MulticastGetLoopbackContext context(env, eventManager);
    bool ret = SocketExec::ExecGetLoopbackMode(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, MulticastTest007, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    MulticastSetReuseAddressContext reuseContext(env, eventManager);
    reuseContext.SetReuseAddress(true);

    EXPECT_TRUE(SocketExec::ExecSetReuseAddress(&reuseContext));
    EXPECT_TRUE(eventManager->GetReuseAddr());

    BindContext bindContext(env, eventManager);
    InitUdpBindContext(bindContext, 0);
    int sockFd = CreateManagedUdpSocket(eventManager);
    ASSERT_GE(sockFd, 0);

    EXPECT_TRUE(SocketExec::ExecUdpBind(&bindContext));
    EXPECT_EQ(GetReuseAddressOption(sockFd), 1);

    CloseManagedSocket(eventManager);
}

HWTEST_F(SocketTest, MulticastTest008, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    BindContext bindContext(env, eventManager);
    InitUdpBindContext(bindContext, 0);
    int sockFd = CreateManagedUdpSocket(eventManager);
    ASSERT_GE(sockFd, 0);

    EXPECT_TRUE(SocketExec::ExecUdpBind(&bindContext));

    MulticastSetReuseAddressContext reuseContext(env, eventManager);
    reuseContext.SetReuseAddress(true);
    EXPECT_TRUE(SocketExec::ExecSetReuseAddress(&reuseContext));
    EXPECT_TRUE(eventManager->GetReuseAddr());
    EXPECT_EQ(GetReuseAddressOption(sockFd), 1);

    CloseManagedSocket(eventManager);
}

HWTEST_F(SocketTest, MulticastTest009, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    MulticastSetReuseAddressContext context(env, eventManager);

    context.ParseParams(nullptr, 0);

    EXPECT_FALSE(context.IsParseOK());
    EXPECT_FALSE(context.GetReuseAddress());
    EXPECT_FALSE(context.IsNeedPromise());
    EXPECT_TRUE(context.IsNeedThrowException());
    EXPECT_EQ(context.GetErrorCode(), PARSE_ERROR_CODE);
    EXPECT_EQ(context.GetErrorMessage(), PARSE_ERROR_MSG);
}

HWTEST_F(SocketTest, MulticastTest010, TestSize.Level1)
{
    napi_env env = nullptr;
    std::shared_ptr<EventManager> eventManager = nullptr;
    MulticastSetReuseAddressContext context(env, eventManager);

    EXPECT_EQ(context.GetReleaseVersion(), 26);
    EXPECT_EQ(context.GetSharedManager(), nullptr);
}

HWTEST_F(SocketTest, LocalSocketTest001, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    LocalSocketBindContext context(env, eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketBind(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, LocalSocketTest002, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    LocalSocketConnectContext context(env, eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketConnect(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, LocalSocketTest003, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    LocalSocketSendContext context(env, eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketSend(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, LocalSocketTest004, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    LocalSocketCloseContext context(env, eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketClose(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, LocalSocketTest005, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    LocalSocketGetStateContext context(env, eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketGetState(&context);
    EXPECT_EQ(ret, true);
}

HWTEST_F(SocketTest, LocalSocketTest006, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    LocalSocketGetSocketFdContext context(env, eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketGetSocketFd(&context);
    EXPECT_EQ(ret, true);
}

HWTEST_F(SocketTest, LocalSocketTest007, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    LocalSocketSetExtraOptionsContext context(env, eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketSetExtraOptions(&context);
    EXPECT_EQ(ret, true);
}

HWTEST_F(SocketTest, LocalSocketTest008, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    LocalSocketGetExtraOptionsContext context(env, eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketGetExtraOptions(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, LocalSocketCloseWakesBlockedRecvWorker009, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    int sv[2] = {-1, -1};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    timeval recvTimeout = {10, 0};
    ASSERT_EQ(setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &recvTimeout, sizeof(recvTimeout)), 0);
    eventManager->SetSocketFd(sv[0]);
    eventManager->SetData(new LocalSocketManager());

    int ioFd = dup(sv[0]);
    ASSERT_GE(ioFd, 0);
    std::atomic_bool workerDone = false;
    std::thread worker([ioFd, &workerDone]() {
        pollfd fds[1] = {{.fd = ioFd, .events = POLLIN}};
        while (true) {
            if (poll(fds, 1, 10000) <= 0) {
                continue;
            }
            if ((fds[0].revents & (POLLHUP | POLLERR | POLLNVAL)) != 0) {
                break;
            }
            char buf[16];
            if (recv(ioFd, buf, sizeof(buf), 0) <= 0) {
                break;
            }
        }
        close(ioFd);
        workerDone.store(true);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    LocalSocketCloseContext context(env, eventManager);
    auto start = std::chrono::steady_clock::now();
    bool ret = LocalSocketExec::ExecLocalSocketClose(&context);
    auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
    worker.join();

    EXPECT_EQ(ret, true);
    EXPECT_EQ(eventManager->GetSocketFd(), -1);
    EXPECT_LT(elapsedMs, 5000);
    EXPECT_TRUE(workerDone.load());

    LocalSocketCloseContext secondClose(env, eventManager);
    EXPECT_EQ(LocalSocketExec::ExecLocalSocketClose(&secondClose), true);

    close(sv[1]);
    delete reinterpret_cast<LocalSocketManager *>(eventManager->GetData());
    eventManager->SetData(nullptr);
}

HWTEST_F(SocketTest, LocalSocketFdCasCloseTest010, TestSize.Level1)
{
    auto eventManager = std::make_shared<EventManager>();
    eventManager->SetSocketFd(7);
    EXPECT_EQ(eventManager->GetSocketFd(), 7);
    EXPECT_TRUE(eventManager->SetSocketFdIfEqual(7));
    EXPECT_EQ(eventManager->GetSocketFd(), -1);
    EXPECT_FALSE(eventManager->SetSocketFdIfEqual(7));
    eventManager->SetSocketFd(9);
    EXPECT_FALSE(eventManager->SetSocketFdIfEqual(7));
    EXPECT_EQ(eventManager->GetSocketFd(), 9);
}

HWTEST_F(SocketTest, LocalSocketSendAfterCloseTest011, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    int sv[2] = {-1, -1};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    eventManager->SetSocketFd(sv[0]);
    LocalSocketCloseContext closeContext(env, eventManager);
    ASSERT_TRUE(LocalSocketExec::ExecLocalSocketClose(&closeContext));
    EXPECT_EQ(eventManager->GetSocketFd(), -1);
    LocalSocketSendContext sendContext(env, eventManager);
    EXPECT_EQ(LocalSocketExec::ExecLocalSocketSend(&sendContext), false);
    close(sv[1]);
}

HWTEST_F(SocketTest, LocalSocketServerTest001, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    LocalSocketServerListenContext context(env, eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketServerListen(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, LocalSocketServerTest002, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    LocalSocketServerGetStateContext context(env, eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketServerGetState(&context);
    EXPECT_EQ(ret, true);
}

HWTEST_F(SocketTest, LocalSocketServerTest003, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    LocalSocketServerSetExtraOptionsContext context(env, eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketServerSetExtraOptions(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, LocalSocketServerTest004, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    LocalSocketServerGetExtraOptionsContext context(env, eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketServerGetExtraOptions(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, LocalSocketServerTest005, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    LocalSocketServerSendContext context(env, eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketConnectionSend(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, LocalSocketServerTest006, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    LocalSocketServerCloseContext context(env, eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketConnectionClose(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, LocalSocketServerTest007, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    LocalSocketServerEndContext context(env, eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketServerEnd(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, LocalSocketFdZeroAndEverCreatedTest012, TestSize.Level1)
{
    auto eventManager = std::make_shared<EventManager>();
    EXPECT_EQ(eventManager->GetSocketFd(), -1);
    EXPECT_FALSE(eventManager->IsSocketEverCreated());
    eventManager->SetSocketFd(0);
    EXPECT_EQ(eventManager->GetSocketFd(), 0);
    EXPECT_TRUE(eventManager->IsSocketEverCreated());
    eventManager->SetSocketFd(-1);
    EXPECT_EQ(eventManager->GetSocketFd(), -1);
    EXPECT_TRUE(eventManager->IsSocketEverCreated());
}

HWTEST_F(SocketTest, LocalSocketServerManagerTest001, TestSize.Level1)
{
    LocalSocketServerManager mgr;
    ASSERT_GE(mgr.StartEpoll(), 0);
    ASSERT_GE(mgr.stopEventFd_, 0);

    int sv[2] = {-1, -1};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    ASSERT_EQ(mgr.RegisterEpollEvent(sv[0], EPOLLIN), 0);

    // data ready on a registered fd is reported by EpollWait
    ASSERT_EQ(write(sv[1], "x", 1), 1);
    bool reported = false;
    int n = mgr.EpollWait();
    ASSERT_GE(n, 0);
    for (int i = 0; i < n; ++i) {
        if (mgr.events_[i].data.fd == sv[0]) {
            reported = true;
        }
    }
    EXPECT_TRUE(reported);

    int clientId = mgr.AddAccept(sv[0]);
    EXPECT_GT(clientId, 0);
    EXPECT_EQ(mgr.GetClientCounts(), 1U);
    EXPECT_EQ(mgr.GetAcceptFd(clientId), sv[0]);
    int dupFd = mgr.DupAcceptFd(clientId);
    EXPECT_GE(dupFd, 0);
    close(dupFd);
    EXPECT_EQ(mgr.GetClientId(sv[0]), clientId);
    EXPECT_EQ(mgr.GetClientId(-1), -1);

    // RemoveAccept must DEL the fd from epoll before closing it: the closed fd is
    // never reported again even though data was pending on it
    mgr.RemoveAccept(clientId);
    EXPECT_EQ(mgr.GetClientCounts(), 0U);
    EXPECT_EQ(mgr.GetAcceptFd(clientId), -1);

    int sv2[2] = {-1, -1};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv2), 0);
    ASSERT_EQ(mgr.RegisterEpollEvent(sv2[0], EPOLLIN), 0);
    ASSERT_EQ(write(sv2[1], "z", 1), 1);
    bool staleReported = false;
    bool freshReported = false;
    n = mgr.EpollWait();
    ASSERT_GE(n, 0);
    for (int i = 0; i < n; ++i) {
        if (mgr.events_[i].data.fd == sv[0]) {
            staleReported = true;
        }
        if (mgr.events_[i].data.fd == sv2[0]) {
            freshReported = true;
        }
    }
    EXPECT_TRUE(freshReported);
    EXPECT_FALSE(staleReported);

    int clientId2 = mgr.AddAccept(sv2[0]);
    EXPECT_GT(clientId2, 0);
    mgr.RemoveAllAccept();
    EXPECT_EQ(mgr.GetClientCounts(), 0U);
    // sv2[0] has been closed by RemoveAllAccept: writing the peer fails with EPIPE
    int sendRet = send(sv2[1], "z", 1, MSG_NOSIGNAL);
    int sendErr = errno;
    EXPECT_EQ(sendRet, -1);
    EXPECT_EQ(sendErr, EPIPE);

    // NotifyStopEvent wakes EpollWait through stopEventFd_
    mgr.NotifyStopEvent();
    bool stopReported = false;
    n = mgr.EpollWait();
    ASSERT_GE(n, 0);
    for (int i = 0; i < n; ++i) {
        if (mgr.events_[i].data.fd == mgr.stopEventFd_) {
            stopReported = true;
        }
    }
    EXPECT_TRUE(stopReported);

    close(mgr.stopEventFd_);
    mgr.stopEventFd_ = -1;
    mgr.NotifyStopEvent(); // stopEventFd_ < 0 branch
    close(mgr.epollFd_);
    mgr.epollFd_ = -1;
    close(sv[1]);
    close(sv2[1]);
}

HWTEST_F(SocketTest, LocalSocketServerManagerTest002, TestSize.Level1)
{
    LocalSocketServerManager mgr;
    auto eventManager = std::make_shared<EventManager>();
    auto eventManager2 = std::make_shared<EventManager>();

    mgr.AddEventManager(1, eventManager);
    EXPECT_EQ(mgr.GetSharedManager(1).get(), eventManager.get());
    EXPECT_EQ(mgr.GetSharedManager(2), nullptr);
    mgr.RemoveEventManager(1);
    EXPECT_EQ(mgr.GetSharedManager(1), nullptr);

    mgr.AddEventManager(2, eventManager2);
    mgr.RemoveAllEventManager();
    EXPECT_EQ(mgr.GetSharedManager(2), nullptr);

    mgr.NotifyRegisterEvent();
    EXPECT_FALSE(mgr.GetServerDestructStatus());
    mgr.SetServerDestructStatus(true);
    EXPECT_TRUE(mgr.GetServerDestructStatus());
    // WaitRegisteringEvent returns immediately once the destruct flag is set
    mgr.WaitRegisteringEvent(1);
}

HWTEST_F(SocketTest, LocalSocketServerExecFdTest001, TestSize.Level1)
{
    napi_env env = nullptr;
    int sv[2] = {-1, -1};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    auto eventManager = std::make_shared<EventManager>();
    eventManager->SetSocketFd(sv[0]);
    auto mgr = new LocalSocketServerManager();
    eventManager->SetData(mgr);

    // get state with a live fd: getsockname succeeds -> isBound, no client -> not connected
    LocalSocketServerGetStateContext stateCtx(env, eventManager);
    EXPECT_TRUE(LocalSocketExec::ExecLocalSocketServerGetState(&stateCtx));
    EXPECT_TRUE(stateCtx.GetStateRef().IsBound());
    EXPECT_FALSE(stateCtx.GetStateRef().IsConnected());

    int clientId = mgr->AddAccept(sv[1]);
    EXPECT_GT(clientId, 0);
    LocalSocketServerGetStateContext stateCtx2(env, eventManager);
    EXPECT_TRUE(LocalSocketExec::ExecLocalSocketServerGetState(&stateCtx2));
    EXPECT_TRUE(stateCtx2.GetStateRef().IsConnected());

    // get state with an invalid fd -> not bound
    eventManager->SetSocketFd(-1);
    LocalSocketServerGetStateContext stateCtx3(env, eventManager);
    EXPECT_TRUE(LocalSocketExec::ExecLocalSocketServerGetState(&stateCtx3));
    EXPECT_FALSE(stateCtx3.GetStateRef().IsBound());

    // get state without manager data -> connected state is skipped
    eventManager->SetSocketFd(sv[0]);
    eventManager->SetData(nullptr);
    LocalSocketServerGetStateContext stateCtx4(env, eventManager);
    EXPECT_TRUE(LocalSocketExec::ExecLocalSocketServerGetState(&stateCtx4));
    EXPECT_FALSE(stateCtx4.GetStateRef().IsConnected());
    eventManager->SetData(mgr);

    // get local address: live fd succeeds, invalid fd fails with EBADF
    LocalSocketServerGetLocalAddressContext addrCtx(env, eventManager);
    EXPECT_TRUE(LocalSocketExec::ExecLocalSocketServerGetLocalAddress(&addrCtx));
    eventManager->SetSocketFd(-1);
    LocalSocketServerGetLocalAddressContext addrCtx2(env, eventManager);
    EXPECT_FALSE(LocalSocketExec::ExecLocalSocketServerGetLocalAddress(&addrCtx2));

    mgr->RemoveAllAccept();
    eventManager->SetData(nullptr);
    delete mgr;
    close(sv[0]);
}

HWTEST_F(SocketTest, LocalSocketServerExecFdTest002, TestSize.Level1)
{
    napi_env env = nullptr;
    int sv[2] = {-1, -1};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    auto eventManager = std::make_shared<EventManager>();
    eventManager->SetSocketFd(sv[0]);
    auto mgr = new LocalSocketServerManager();
    eventManager->SetData(mgr);
    int clientId = mgr->AddAccept(sv[0]);
    ASSERT_GT(clientId, 0);

    // set extra options applies sockopts on every accepted fd
    LocalSocketServerSetExtraOptionsContext setCtx(env, eventManager);
    auto &options = setCtx.GetOptionsRef();
    options.SetRecvBufSizeFlag(true);
    options.SetReceiveBufferSize(4096);
    options.SetSendBufSizeFlag(true);
    options.SetSendBufferSize(4096);
    options.SetTimeoutFlag(true);
    options.SetSocketTimeout(1000);
    EXPECT_TRUE(LocalSocketExec::ExecLocalSocketServerSetExtraOptions(&setCtx));
    EXPECT_TRUE(mgr->alreadySetExtraOptions_);

    // get extra options returns the stored options once they have been set
    LocalSocketServerGetExtraOptionsContext getCtx(env, eventManager);
    EXPECT_TRUE(LocalSocketExec::ExecLocalSocketServerGetExtraOptions(&getCtx));
    EXPECT_EQ(getCtx.GetOptionsRef().GetReceiveBufferSize(), 4096U);

    // fresh manager without stored options falls back to getsockopt on the listen fd
    auto mgr2 = new LocalSocketServerManager();
    eventManager->SetData(mgr2);
    LocalSocketServerGetExtraOptionsContext getCtx2(env, eventManager);
    EXPECT_TRUE(LocalSocketExec::ExecLocalSocketServerGetExtraOptions(&getCtx2));

    // invalid fd -> EBADF
    eventManager->SetSocketFd(-1);
    LocalSocketServerGetExtraOptionsContext getCtx3(env, eventManager);
    EXPECT_FALSE(LocalSocketExec::ExecLocalSocketServerGetExtraOptions(&getCtx3));

    mgr->RemoveAllAccept();
    eventManager->SetData(nullptr);
    delete mgr;
    delete mgr2;
    close(sv[1]);
}

HWTEST_F(SocketTest, LocalSocketServerExecFdTest003, TestSize.Level1)
{
    napi_env env = nullptr;
    // server end closes the listen fd through the CAS fast path
    int sv[2] = {-1, -1};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    auto eventManager = std::make_shared<EventManager>();
    eventManager->SetSocketFd(sv[0]);
    auto mgr = new LocalSocketServerManager();
    eventManager->SetData(mgr);
    LocalSocketServerEndContext endCtx(env, eventManager);
    EXPECT_TRUE(LocalSocketExec::ExecLocalSocketServerEnd(&endCtx));
    EXPECT_EQ(eventManager->GetSocketFd(), -1);
    // second end hits the fd < 0 branch
    LocalSocketServerEndContext endCtx2(env, eventManager);
    EXPECT_TRUE(LocalSocketExec::ExecLocalSocketServerEnd(&endCtx2));
    eventManager->SetData(nullptr);
    delete mgr;
    close(sv[1]);

    // connection send / close / getLocalAddress / getSocketFd through a real accepted fd
    int sv2[2] = {-1, -1};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv2), 0);
    auto eventManager2 = std::make_shared<EventManager>();
    auto mgr2 = new LocalSocketServerManager();
    auto connData = new LocalSocketExec::LocalSocketConnectionData(1, mgr2);
    eventManager2->SetData(connData);
    int clientId = mgr2->AddAccept(sv2[0]);
    ASSERT_GT(clientId, 0);

    LocalSocketServerSendContext sendCtx(env, eventManager2);
    sendCtx.SetClientId(clientId);
    sendCtx.GetOptionsRef().SetBuffer("hello");
    EXPECT_TRUE(LocalSocketExec::ExecLocalSocketConnectionSend(&sendCtx));
    char buf[16] = {0};
    EXPECT_EQ(read(sv2[1], buf, sizeof(buf)), 5);

    // unknown client id -> DupAcceptFd fails
    LocalSocketServerSendContext sendCtx2(env, eventManager2);
    sendCtx2.SetClientId(999);
    sendCtx2.GetOptionsRef().SetBuffer("x");
    EXPECT_FALSE(LocalSocketExec::ExecLocalSocketConnectionSend(&sendCtx2));

    // connection close shuts down and removes the accepted fd
    LocalSocketServerCloseContext closeCtx(env, eventManager2);
    closeCtx.SetClientId(clientId);
    EXPECT_TRUE(LocalSocketExec::ExecLocalSocketConnectionClose(&closeCtx));
    EXPECT_EQ(mgr2->GetClientCounts(), 0U);

    // unknown client id -> DupAcceptFd fails with EBADF
    LocalSocketServerCloseContext closeCtx2(env, eventManager2);
    closeCtx2.SetClientId(999);
    EXPECT_FALSE(LocalSocketExec::ExecLocalSocketConnectionClose(&closeCtx2));

    // removed client -> EBADF
    LocalSocketServerGetLocalAddressContext addrCtx(env, eventManager2);
    addrCtx.SetClientId(clientId);
    EXPECT_FALSE(LocalSocketExec::ExecLocalSocketConnectionGetLocalAddress(&addrCtx));

    // connection data without a server manager -> EBADF
    auto eventManager4 = std::make_shared<EventManager>();
    eventManager4->SetData(new LocalSocketExec::LocalSocketConnectionData(1, nullptr));
    LocalSocketServerGetLocalAddressContext addrCtx3(env, eventManager4);
    addrCtx3.SetClientId(1);
    EXPECT_FALSE(LocalSocketExec::ExecLocalSocketConnectionGetLocalAddress(&addrCtx3));
    delete reinterpret_cast<LocalSocketExec::LocalSocketConnectionData *>(eventManager4->GetData());
    eventManager4->SetData(nullptr);

    // live accepted fd -> getsockname succeeds; getSocketFd returns the stored fd
    int clientId2 = mgr2->AddAccept(sv2[1]);
    ASSERT_GT(clientId2, 0);
    LocalSocketServerGetLocalAddressContext addrCtx2(env, eventManager2);
    addrCtx2.SetClientId(clientId2);
    EXPECT_TRUE(LocalSocketExec::ExecLocalSocketConnectionGetLocalAddress(&addrCtx2));
    LocalSocketServerGetSocketFdContext fdCtx(env, eventManager2);
    fdCtx.SetClientId(clientId2);
    EXPECT_TRUE(LocalSocketExec::ExecLocalSocketConnectionGetSocketFd(&fdCtx));
    EXPECT_EQ(fdCtx.GetConnectionSocketFd(), sv2[1]);

    // manager without connection data -> socket fd stays invalid, exec still succeeds
    auto eventManager3 = std::make_shared<EventManager>();
    LocalSocketServerGetSocketFdContext fdCtx2(env, eventManager3);
    fdCtx2.SetClientId(1);
    EXPECT_TRUE(LocalSocketExec::ExecLocalSocketConnectionGetSocketFd(&fdCtx2));
    EXPECT_EQ(fdCtx2.GetConnectionSocketFd(), -1);

    // send on an accepted fd whose peer is gone fails through the send error branch
    // (SIGPIPE must be ignored: PollSendData sends without MSG_NOSIGNAL)
    signal(SIGPIPE, SIG_IGN);
    int sv3[2] = {-1, -1};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv3), 0);
    close(sv3[1]);
    int clientId3 = mgr2->AddAccept(sv3[0]);
    ASSERT_GT(clientId3, 0);
    LocalSocketServerSendContext sendCtx3(env, eventManager2);
    sendCtx3.SetClientId(clientId3);
    sendCtx3.GetOptionsRef().SetBuffer("x");
    EXPECT_FALSE(LocalSocketExec::ExecLocalSocketConnectionSend(&sendCtx3));

    mgr2->RemoveAllAccept();
    eventManager2->SetData(nullptr);
    delete connData;
    delete mgr2;
}

HWTEST_F(SocketTest, LocalSocketClientExecFdTest001, TestSize.Level1)
{
    napi_env env = nullptr;
    int sv[2] = {-1, -1};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    auto eventManager = std::make_shared<EventManager>();
    eventManager->SetSocketFd(sv[0]);
    auto socketManager = new LocalSocketManager();
    eventManager->SetData(socketManager);

    // get state with a live fd and manager data
    LocalSocketGetStateContext stateCtx(env, eventManager);
    EXPECT_TRUE(LocalSocketExec::ExecLocalSocketGetState(&stateCtx));

    // connect to an empty abstract path fails immediately (NonBlockConnect error path)
    LocalSocketConnectContext connCtx(env, eventManager);
    EXPECT_FALSE(LocalSocketExec::ExecLocalSocketConnect(&connCtx));

    // send success path writes through the dup'ed fd
    LocalSocketSendContext sendCtx(env, eventManager);
    sendCtx.GetOptionsRef().SetBuffer("hello");
    EXPECT_TRUE(LocalSocketExec::ExecLocalSocketSend(&sendCtx));
    char buf[16] = {0};
    EXPECT_EQ(read(sv[1], buf, sizeof(buf)), 5);
    EXPECT_STREQ(buf, "hello");

    // invalid fd and no manager data: state falls back to unbound and stays disconnected
    eventManager->SetSocketFd(-1);
    delete socketManager;
    eventManager->SetData(nullptr);
    LocalSocketGetStateContext stateCtx2(env, eventManager);
    EXPECT_TRUE(LocalSocketExec::ExecLocalSocketGetState(&stateCtx2));
    EXPECT_FALSE(stateCtx2.GetStateRef().IsBound());
    EXPECT_FALSE(stateCtx2.GetStateRef().IsConnected());

    // get local address: live fd succeeds, invalid fd fails with EBADF
    eventManager->SetSocketFd(sv[0]);
    eventManager->SetData(new LocalSocketManager());
    LocalSocketGetLocalAddressContext addrCtx(env, eventManager);
    EXPECT_TRUE(LocalSocketExec::ExecLocalSocketGetLocalAddress(&addrCtx));
    eventManager->SetSocketFd(-1);
    LocalSocketGetLocalAddressContext addrCtx2(env, eventManager);
    EXPECT_FALSE(LocalSocketExec::ExecLocalSocketGetLocalAddress(&addrCtx2));

    // set extra options: live fd succeeds, invalid fd fails
    eventManager->SetSocketFd(sv[0]);
    LocalSocketSetExtraOptionsContext setCtx(env, eventManager);
    auto &options = setCtx.GetOptionsRef();
    options.SetRecvBufSizeFlag(true);
    options.SetReceiveBufferSize(4096);
    options.SetSendBufSizeFlag(true);
    options.SetSendBufferSize(4096);
    EXPECT_TRUE(LocalSocketExec::ExecLocalSocketSetExtraOptions(&setCtx));
    eventManager->SetSocketFd(-1);
    LocalSocketSetExtraOptionsContext setCtx2(env, eventManager);
    EXPECT_FALSE(LocalSocketExec::ExecLocalSocketSetExtraOptions(&setCtx2));

    // get extra options: live fd succeeds, invalid fd fails
    eventManager->SetSocketFd(sv[0]);
    LocalSocketGetExtraOptionsContext getCtx(env, eventManager);
    EXPECT_TRUE(LocalSocketExec::ExecLocalSocketGetExtraOptions(&getCtx));
    eventManager->SetSocketFd(-1);
    LocalSocketGetExtraOptionsContext getCtx2(env, eventManager);
    EXPECT_FALSE(LocalSocketExec::ExecLocalSocketGetExtraOptions(&getCtx2));

    // close releases the fd and resets the manager state
    eventManager->SetSocketFd(sv[0]);
    LocalSocketCloseContext closeCtx(env, eventManager);
    EXPECT_TRUE(LocalSocketExec::ExecLocalSocketClose(&closeCtx));
    EXPECT_EQ(eventManager->GetSocketFd(), -1);
    EXPECT_FALSE(reinterpret_cast<LocalSocketManager *>(eventManager->GetData())->isConnected_);

    delete reinterpret_cast<LocalSocketManager *>(eventManager->GetData());
    eventManager->SetData(nullptr);
    close(sv[1]);
}

HWTEST_F(SocketTest, NetAddressNumericIpTest001, TestSize.Level1)
{
    // pure numeric IPv4 address is normalized to the dotted form through inet_ntop
    NetAddress v4;
    v4.SetFamilyBySaFamily(AF_INET);
    v4.SetIpAddress("2130706433");
    EXPECT_EQ(v4.GetAddress(), "127.0.0.1");

    // non numeric input leaves the stored address untouched
    NetAddress bad;
    bad.SetFamilyBySaFamily(AF_INET);
    bad.SetIpAddress("not_a_number");
    EXPECT_EQ(bad.GetAddress(), "");

    // scoped IPv6 address keeps only the address part before '%'
    NetAddress v6;
    v6.SetFamilyBySaFamily(AF_INET6);
    v6.SetIpAddress("::1%1");
    EXPECT_EQ(v6.GetAddress(), "::1");

    // IPv6 family without a scope part is not rewritten
    NetAddress v6b;
    v6b.SetFamilyBySaFamily(AF_INET6);
    v6b.SetIpAddress("not_an_ipv6");
    EXPECT_EQ(v6b.GetAddress(), "");
}

// socks5 proxy test start
HWTEST_F(SocketTest, Socks5SocketTest001, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ConnectContext context(env, eventManager);
    bool ret = SocketExec::ExecConnect(&context);
    EXPECT_EQ(ret, false);

    context.proxyOptions = make_shared<ProxyOptions>();
    context.proxyOptions->type_ = ProxyType::SOCKS5;
    ret = SocketExec::ExecConnect(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, Socks5SocketTest002, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    UdpSendContext context(env, eventManager);
    context.parseOK_ = false;
    EXPECT_FALSE(SocketExec::ExecUdpSend(&context));

    context.parseOK_ = true;
    EXPECT_FALSE(SocketExec::ExecUdpSend(&context));

    int data = 1;
    eventManager->data_ = &data;
    shared_ptr<Socks5Instance> socks5Udp = make_shared<Socks5UdpInstance>();
    socks5Udp->options_ = make_shared<Socks5Option>();
    socks5Udp->SetSocks5Instance(socks5Udp);
    eventManager->proxyData_ = socks5Udp;
    context.proxyOptions = make_shared<ProxyOptions>();
    context.proxyOptions->type_ = ProxyType::NONE;
    EXPECT_FALSE(SocketExec::ExecUdpSend(&context));

    context.proxyOptions->type_ = ProxyType::SOCKS5;
    EXPECT_FALSE(SocketExec::ExecUdpSend(&context));
    sleep(2);
}

HWTEST_F(SocketTest, SetSocks5OptionTest001, TestSize.Level1)
{
    int32_t socketId = 1;
    auto socks5Inst = make_shared<Socks5TcpInstance>(socketId);
    socks5Inst->SetSocks5Instance(socks5Inst);
    shared_ptr<Socks5Option> opt = make_shared<Socks5Option>();
    socks5Inst->SetSocks5Option(opt);
    EXPECT_FALSE(socks5Inst->options_ == nullptr);
}

HWTEST_F(SocketTest, DoConnectTest001, TestSize.Level1)
{
    int32_t socketId = 1;
    auto socks5Inst = make_shared<Socks5TcpInstance>(socketId);
    socks5Inst->options_ = make_shared<Socks5Option>();
    socks5Inst->SetSocks5Instance(socks5Inst);
    auto ret = socks5Inst->DoConnect(Socks5Command::TCP_CONNECTION);
    EXPECT_FALSE(ret);
    EXPECT_FALSE(socks5Inst->IsConnected());
}

HWTEST_F(SocketTest, RequestMethodTest001, TestSize.Level1)
{
    int32_t socketId = 1;
    vector<Socks5MethodType> methods = {Socks5MethodType::NO_AUTH, Socks5MethodType::PASSWORD};
    auto socks5Inst = make_shared<Socks5TcpInstance>(socketId);
    socks5Inst->options_ = make_shared<Socks5Option>();
    socks5Inst->SetSocks5Instance(socks5Inst);
    auto ret = socks5Inst->RequestMethod(methods);
    EXPECT_FALSE(ret);
}

HWTEST_F(SocketTest, CreateSocks5MethodByTypeTest001, TestSize.Level1)
{
    int32_t socketId = 1;
    auto socks5Inst = make_shared<Socks5TcpInstance>(socketId);
    socks5Inst->SetSocks5Instance(socks5Inst);
    auto ret = socks5Inst->CreateSocks5MethodByType(Socks5MethodType::NO_AUTH);
    EXPECT_FALSE(ret == nullptr);

    ret = socks5Inst->CreateSocks5MethodByType(Socks5MethodType::PASSWORD);
    EXPECT_FALSE(ret == nullptr);

    ret = socks5Inst->CreateSocks5MethodByType(Socks5MethodType::GSSAPI);
    EXPECT_TRUE(ret == nullptr);

    ret = socks5Inst->CreateSocks5MethodByType(Socks5MethodType::NO_METHODS);
    EXPECT_TRUE(ret == nullptr);
}

HWTEST_F(SocketTest, ConnectTest001, TestSize.Level1)
{
    int32_t socketId = 1;
    auto socks5TcpInst = make_shared<Socks5TcpInstance>(socketId);
    socks5TcpInst->SetSocks5Instance(socks5TcpInst);
    socks5TcpInst->options_ = make_shared<Socks5Option>();
    socks5TcpInst->state_ = Socks5AuthState::SUCCESS;
    EXPECT_TRUE(socks5TcpInst->Connect());
    socks5TcpInst->state_ = Socks5AuthState::INIT;
    EXPECT_FALSE(socks5TcpInst->Connect());
}

HWTEST_F(SocketTest, ConnectTest002, TestSize.Level1)
{
    auto socks5UdpInst = make_shared<Socks5UdpInstance>();
    socks5UdpInst->SetSocks5Instance(socks5UdpInst);
    socks5UdpInst->options_ = make_shared<Socks5Option>();
    socks5UdpInst->state_ = Socks5AuthState::SUCCESS;
    EXPECT_TRUE(socks5UdpInst->Connect());
    socks5UdpInst->state_ = Socks5AuthState::INIT;
    EXPECT_FALSE(socks5UdpInst->Connect());
}

HWTEST_F(SocketTest, ConnectProxyTest001, TestSize.Level1)
{
    auto socks5UdpInst = make_shared<Socks5UdpInstance>();
    socks5UdpInst->SetSocks5Instance(socks5UdpInst);
    socks5UdpInst->options_ = make_shared<Socks5Option>();
    EXPECT_FALSE(socks5UdpInst->ConnectProxy());
}

HWTEST_F(SocketTest, RemoveHeaderTest001, TestSize.Level1)
{
    auto socks5UdpInst = make_shared<Socks5UdpInstance>();
    socks5UdpInst->SetSocks5Instance(socks5UdpInst);
    void *data = nullptr;
    size_t len = 2;
    int af = AF_INET;
    EXPECT_FALSE(socks5UdpInst->RemoveHeader(data, len, af));
}

HWTEST_F(SocketTest, AddHeaderTest001, TestSize.Level1)
{
    auto socks5UdpInst = make_shared<Socks5UdpInstance>();
    socks5UdpInst->SetSocks5Instance(socks5UdpInst);
    NetAddress dest;
    dest.SetFamilyByJsValue(static_cast<uint32_t>(NetAddress::Family::IPv4));
    socks5UdpInst->dest_ = dest;
    socks5UdpInst->AddHeader();
    EXPECT_EQ(socks5UdpInst->dest_.GetFamily(), NetAddress::Family::IPv4);
}

HWTEST_F(SocketTest, AddHeaderTest002, TestSize.Level1)
{
    auto socks5UdpInst = make_shared<Socks5UdpInstance>();
    socks5UdpInst->SetSocks5Instance(socks5UdpInst);
    NetAddress dest;
    dest.SetFamilyByJsValue(static_cast<uint32_t>(NetAddress::Family::IPv6));
    socks5UdpInst->dest_ = dest;
    socks5UdpInst->AddHeader();
    EXPECT_EQ(socks5UdpInst->dest_.GetFamily(), NetAddress::Family::IPv6);
}

HWTEST_F(SocketTest, AddHeaderTest003, TestSize.Level1)
{
    auto socks5UdpInst = make_shared<Socks5UdpInstance>();
    socks5UdpInst->SetSocks5Instance(socks5UdpInst);
    NetAddress dest;
    dest.SetFamilyByJsValue(static_cast<uint32_t>(NetAddress::Family::DOMAIN_NAME));
    socks5UdpInst->dest_ = dest;
    socks5UdpInst->AddHeader();
    EXPECT_EQ(socks5UdpInst->dest_.GetFamily(), NetAddress::Family::DOMAIN_NAME);
}

HWTEST_F(SocketTest, NoAuthMethodTest001, TestSize.Level1)
{
    int32_t socketId = 1;
    auto socks5Inst = make_shared<Socks5TcpInstance>(socketId);
    socks5Inst->SetSocks5Instance(socks5Inst);
    auto noAuthMethod = socks5Inst->CreateSocks5MethodByType(Socks5MethodType::NO_AUTH);
    noAuthMethod->socks5Inst_ = socks5Inst;
    Socks5ProxyAddress proxyAddr;
    EXPECT_TRUE(noAuthMethod->RequestAuth(socketId, "", "", proxyAddr));

    NetAddress dest;
    EXPECT_FALSE(noAuthMethod->RequestProxy(socketId, Socks5Command::TCP_CONNECTION, dest, proxyAddr).first);

    dest.family_ = NetAddress::Family::IPv4;
    EXPECT_FALSE(noAuthMethod->RequestProxy(socketId, Socks5Command::TCP_CONNECTION, dest, proxyAddr).first);

    dest.family_ = NetAddress::Family::IPv6;
    EXPECT_FALSE(noAuthMethod->RequestProxy(socketId, Socks5Command::TCP_CONNECTION, dest, proxyAddr).first);

    dest.family_ = NetAddress::Family::DOMAIN_NAME;
    EXPECT_FALSE(noAuthMethod->RequestProxy(socketId, Socks5Command::TCP_CONNECTION, dest, proxyAddr).first);
}

HWTEST_F(SocketTest, passWdMethodTest001, TestSize.Level1)
{
    int32_t socketId = 1;
    auto socks5Inst = make_shared<Socks5TcpInstance>(socketId);
    socks5Inst->SetSocks5Instance(socks5Inst);
    auto passWdMethod = socks5Inst->CreateSocks5MethodByType(Socks5MethodType::PASSWORD);
    passWdMethod->socks5Inst_ = socks5Inst;
    Socks5ProxyAddress proxyAddr;
    EXPECT_FALSE(passWdMethod->RequestAuth(socketId, "", "pass", proxyAddr));
    EXPECT_FALSE(passWdMethod->RequestAuth(socketId, "user", "", proxyAddr));
    EXPECT_FALSE(passWdMethod->RequestAuth(socketId, "user", "pass", proxyAddr));
}

HWTEST_F(SocketTest, Socks5PkgTest001, TestSize.Level1)
{
    Socks5MethodRequest request;
    Socks5MethodResponse response;

    request.version_ = 1;
    string serialized = request.Serialize();
    EXPECT_NE(serialized, "");

    EXPECT_FALSE(response.Deserialize((uint8_t*) serialized.c_str(), 1));
    EXPECT_TRUE(response.Deserialize((uint8_t*) serialized.c_str(), serialized.size()));
}

HWTEST_F(SocketTest, Socks5PkgTest002, TestSize.Level1)
{
    Socks5AuthRequest request;
    Socks5AuthResponse response;
    EXPECT_EQ(request.Serialize(), "");
    
    request.version_ = 1;
    request.username_ = "user";
    request.password_ = "pass";
    string serialized = request.Serialize();
    EXPECT_NE(serialized, "");

    EXPECT_FALSE(response.Deserialize((uint8_t*) serialized.c_str(), 1));
    EXPECT_TRUE(response.Deserialize((uint8_t*) serialized.c_str(), serialized.size()));
}

HWTEST_F(SocketTest, Socks5PkgTest003, TestSize.Level1)
{
    Socks5ProxyRequest request;
    Socks5ProxyResponse response;
    EXPECT_EQ(request.Serialize(), "");

    request.version_ = 1;
    request.cmd_ = Socks5Command::TCP_CONNECTION;
    request.reserved_ = 1;
    request.destPort_ = 1;
    request.destAddr_ = "192.168.1.10";
    request.addrType_ = Socks5AddrType::IPV4;
    string serialized = request.Serialize();
    EXPECT_NE(serialized, "");
    EXPECT_FALSE(response.Deserialize((uint8_t*) serialized.c_str(), 1));
    EXPECT_TRUE(response.Deserialize((uint8_t*) serialized.c_str(), serialized.size()));

    request.destAddr_ = "www.xxx.com";
    request.addrType_ = Socks5AddrType::DOMAIN_NAME;
    string serialized2 = request.Serialize();
    EXPECT_NE(serialized2, "");
    EXPECT_TRUE(response.Deserialize((uint8_t*) serialized2.c_str(), serialized2.size()));

    request.destAddr_ = "fe80::100";
    request.addrType_ = Socks5AddrType::IPV6;
    string serialized3 = request.Serialize();
    EXPECT_NE(serialized3, "");
    EXPECT_TRUE(response.Deserialize((uint8_t*) serialized3.c_str(), serialized3.size()));
}

HWTEST_F(SocketTest, Socks5PkgTest004, TestSize.Level1)
{
    Socks5UdpHeader header;
    EXPECT_EQ(header.Serialize(), "");

    header.reserved_ = 0;
    header.frag_ = 0;
    header.dstPort_ = 1;

    header.destAddr_ = "192.168.1.10";
    header.addrType_ = Socks5AddrType::IPV4;
    string serialized = header.Serialize();
    EXPECT_NE(serialized, "");
    EXPECT_FALSE(header.Deserialize((uint8_t*) serialized.c_str(), 1));
    EXPECT_TRUE(header.Deserialize((uint8_t*) serialized.c_str(), serialized.size()));

    header.destAddr_ = "www.xxx.com";
    header.addrType_ = Socks5AddrType::DOMAIN_NAME;
    string serialized2 = header.Serialize();
    EXPECT_NE(serialized2, "");
    EXPECT_TRUE(header.Deserialize((uint8_t*) serialized2.c_str(), serialized2.size()));

    header.destAddr_ = "fe80::100";
    header.addrType_ = Socks5AddrType::IPV6;
    string serialized3 = header.Serialize();
    EXPECT_NE(serialized3, "");
    EXPECT_TRUE(header.Deserialize((uint8_t*) serialized3.c_str(), serialized3.size()));
}

HWTEST_F(SocketTest, ConnectMonitorCalcNearestTimeoutMsBranches, TestSize.Level2)
{
    auto &monitor = ConnectMonitor::GetInstance();
    ResetConnectMonitorState(monitor);

    EXPECT_EQ(monitor.CalcNearestTimeoutMs(), -1);

    monitor.deadlines_.emplace(std::chrono::steady_clock::now() - std::chrono::milliseconds(1), 1001);
    EXPECT_EQ(monitor.CalcNearestTimeoutMs(), 0);
    monitor.deadlines_.clear();

    auto maxTimeout = static_cast<int64_t>(std::numeric_limits<int>::max()) + 1000;
    monitor.deadlines_.emplace(std::chrono::steady_clock::now() + std::chrono::milliseconds(maxTimeout), 1002);
    EXPECT_EQ(monitor.CalcNearestTimeoutMs(), std::numeric_limits<int>::max());
    monitor.deadlines_.clear();

    monitor.deadlines_.emplace(std::chrono::steady_clock::now() + std::chrono::milliseconds(50), 1003);
    int timeoutMs = monitor.CalcNearestTimeoutMs();
    EXPECT_GE(timeoutMs, 0);
    EXPECT_LE(timeoutMs, 1000);

    ResetConnectMonitorState(monitor);
}

HWTEST_F(SocketTest, ConnectMonitorRegisterAndUnregisterSuccess, TestSize.Level2)
{
    auto &monitor = ConnectMonitor::GetInstance();
    ResetConnectMonitorState(monitor);

    int sockfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    ASSERT_GE(sockfd, 0);
    auto data = CreateConnectWatchData(500);
    ASSERT_NE(data, nullptr);

    EXPECT_TRUE(monitor.Register(sockfd, data));
    monitor.Unregister(sockfd);
    close(sockfd);

    ResetConnectMonitorState(monitor);
}

HWTEST_F(SocketTest, ConnectMonitorRegisterReuseDeadlineIter, TestSize.Level2)
{
    auto &monitor = ConnectMonitor::GetInstance();
    ResetConnectMonitorState(monitor);

    int sockfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    ASSERT_GE(sockfd, 0);
    auto oldDeadline = monitor.deadlines_.emplace(std::chrono::steady_clock::now() + std::chrono::seconds(2), sockfd);
    monitor.deadlineIters_[sockfd] = oldDeadline;

    auto data = CreateConnectWatchData(500);
    ASSERT_NE(data, nullptr);
    EXPECT_TRUE(monitor.Register(sockfd, data));
    monitor.Unregister(sockfd);
    close(sockfd);

    ResetConnectMonitorState(monitor);
}

HWTEST_F(SocketTest, ConnectMonitorCheckTimeoutsBranches, TestSize.Level2)
{
    auto &monitor = ConnectMonitor::GetInstance();
    ResetConnectMonitorState(monitor);

    int activeFd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    ASSERT_GE(activeFd, 0);
    int missingFd = activeFd + 10000;
    auto now = std::chrono::steady_clock::now() - std::chrono::milliseconds(1);

    auto data = CreateConnectWatchData(100);
    ASSERT_NE(data, nullptr);
    monitor.pendings_[activeFd] = data;
    monitor.deadlineIters_[activeFd] = monitor.deadlines_.emplace(now, activeFd);
    monitor.deadlineIters_[missingFd] = monitor.deadlines_.emplace(now, missingFd);

    monitor.CheckTimeouts();
    EXPECT_EQ(monitor.pendings_.find(activeFd), monitor.pendings_.end());
    EXPECT_TRUE(monitor.deadlineIters_.empty());
    EXPECT_TRUE(monitor.deadlines_.empty());

    close(activeFd);
    ResetConnectMonitorState(monitor);
}

HWTEST_F(SocketTest, ConnectMonitorHandleReadySuccessAndFailure, TestSize.Level2)
{
    auto &monitor = ConnectMonitor::GetInstance();
    ResetConnectMonitorState(monitor);

    int validFd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    ASSERT_GE(validFd, 0);
    auto validData = CreateConnectWatchData(1000);
    ASSERT_NE(validData, nullptr);
    monitor.pendings_[validFd] = validData;
    monitor.deadlineIters_[validFd] = monitor.deadlines_.emplace(validData->deadline, validFd);
    monitor.HandleReady(validFd, EPOLLOUT);
    EXPECT_EQ(monitor.pendings_.find(validFd), monitor.pendings_.end());

    int invalidFd = -1;
    auto invalidData = CreateConnectWatchData(1000);
    ASSERT_NE(invalidData, nullptr);
    monitor.pendings_[invalidFd] = invalidData;
    monitor.deadlineIters_[invalidFd] = monitor.deadlines_.emplace(invalidData->deadline, invalidFd);
    monitor.HandleReady(invalidFd, EPOLLERR);
    EXPECT_EQ(monitor.pendings_.find(invalidFd), monitor.pendings_.end());

    close(validFd);
    ResetConnectMonitorState(monitor);
}

HWTEST_F(SocketTest, ConnectMonitorCompleteConnectNotFound, TestSize.Level2)
{
    auto &monitor = ConnectMonitor::GetInstance();
    ResetConnectMonitorState(monitor);

    int fd = 34567;
    monitor.deadlineIters_[fd] = monitor.deadlines_.emplace(std::chrono::steady_clock::now(), fd);
    monitor.CompleteConnect(fd, 0);
    EXPECT_EQ(monitor.deadlineIters_.find(fd), monitor.deadlineIters_.end());
    EXPECT_TRUE(monitor.pendings_.empty());

    ResetConnectMonitorState(monitor);
}

HWTEST_F(SocketTest, ConnectMonitorEnsureThreadJoinableBranch, TestSize.Level2)
{
    auto &monitor = ConnectMonitor::GetInstance();
    ResetConnectMonitorState(monitor);

    int fd1 = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    ASSERT_GE(fd1, 0);
    auto data1 = CreateConnectWatchData(20);
    ASSERT_NE(data1, nullptr);
    ASSERT_TRUE(monitor.Register(fd1, data1));
    WaitMonitorStopped(monitor, 2000);
    ASSERT_FALSE(monitor.running_.load());
    ASSERT_TRUE(monitor.thread_.joinable());

    int fd2 = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    ASSERT_GE(fd2, 0);
    auto data2 = CreateConnectWatchData(300);
    ASSERT_NE(data2, nullptr);
    EXPECT_TRUE(monitor.Register(fd2, data2));
    monitor.Unregister(fd2);

    close(fd1);
    close(fd2);
    ResetConnectMonitorState(monitor);
}

HWTEST_F(SocketTest, ConnectMonitorEnsureThreadRunningConcurrentRestart, TestSize.Level2)
{
    auto &monitor = ConnectMonitor::GetInstance();
    ResetConnectMonitorState(monitor);

    std::atomic<bool> oldThreadRunning(false);
    std::atomic<bool> stopOldThread(false);
    monitor.thread_ = std::thread([&oldThreadRunning, &stopOldThread]() {
        oldThreadRunning.store(true);
        while (!stopOldThread.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    });
    for (int32_t waited = 0; waited < 1000 && !oldThreadRunning.load(); waited += SLEEP_TIME_TEN) {
        std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME_TEN));
    }
    ASSERT_TRUE(oldThreadRunning.load());
    monitor.running_.store(false);
    auto pendingData = CreateConnectWatchData(5000);
    ASSERT_NE(pendingData, nullptr);
    std::unique_lock<std::mutex> lifecycleLock(monitor.lifecycleMutex_);
    {
        std::lock_guard<std::mutex> lock(monitor.mutex_);
        monitor.pendings_[54321] = pendingData;
        monitor.deadlineIters_[54321] = monitor.deadlines_.emplace(pendingData->deadline, 54321);
    }

    std::atomic<int32_t> callerReady(0);
    std::thread callerA([&monitor, &callerReady]() {
        callerReady.fetch_add(1);
        monitor.EnsureThreadRunning();
    });
    std::thread callerB([&monitor, &callerReady]() {
        callerReady.fetch_add(1);
        monitor.EnsureThreadRunning();
    });
    for (int32_t waited = 0; waited < 1000 && callerReady.load() < 2; waited += SLEEP_TIME_TEN) {
        std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME_TEN));
    }
    stopOldThread.store(true);
    lifecycleLock.unlock();
    callerA.join();
    callerB.join();
    EXPECT_EQ(callerReady.load(), 2);
    EXPECT_TRUE(monitor.running_.load());
    EXPECT_TRUE(monitor.thread_.joinable());

    ResetConnectMonitorState(monitor);
}

HWTEST_F(SocketTest, ConnectMonitorMonitorLoopEpollErrorBranch, TestSize.Level2)
{
    auto &monitor = ConnectMonitor::GetInstance();
    ResetConnectMonitorState(monitor);

    int oldEpollFd = monitor.epollFd_;
    monitor.epollFd_ = -1;
    monitor.running_.store(true);
    monitor.MonitorLoop();
    EXPECT_FALSE(monitor.running_.load());
    monitor.epollFd_ = oldEpollFd;

    ResetConnectMonitorState(monitor);
}

static int CreateTcpServerSocket()
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    EXPECT_GE(fd, 0);
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    return fd;
}

static int ConnectToServer(const char *ip, uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    EXPECT_GE(fd, 0);
    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    int ret = connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
    EXPECT_EQ(ret, 0);
    return fd;
}

static uint16_t GetBoundPort(int fd)
{
    sockaddr_in addr = {};
    socklen_t len = sizeof(addr);
    EXPECT_EQ(getsockname(fd, reinterpret_cast<sockaddr *>(&addr), &len), 0);
    return ntohs(addr.sin_port);
}

static void InitTcpServerListenContext(TcpServerListenContext &context, const char *ip, uint16_t port)
{
    context.address_.SetAddress(ip);
    context.address_.SetPort(port);
    context.address_.SetFamilyBySaFamily(AF_INET);
}

HWTEST_F(SocketTest, TcpServerDetachTest001, TestSize.Level2)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();

    int serverFd = CreateTcpServerSocket();
    ASSERT_GE(serverFd, 0);
    eventManager->SetSocketFd(serverFd);

    TcpServerListenContext listenContext(env, eventManager);
    InitTcpServerListenContext(listenContext, "127.0.0.1", 0);
    ASSERT_TRUE(SocketExec::ExecTcpServerListen(&listenContext));

    uint16_t port = GetBoundPort(serverFd);
    ASSERT_GT(port, 0);

    int clientFd = ConnectToServer("127.0.0.1", port);
    ASSERT_GE(clientFd, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    TcpServerCloseContext closeContext(env, eventManager);
    EXPECT_TRUE(SocketExec::ExecTcpServerClose(&closeContext));

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    close(clientFd);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    SUCCEED();
}

HWTEST_F(SocketTest, TcpServerDetachTest002, TestSize.Level2)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();

    int serverFd = CreateTcpServerSocket();
    ASSERT_GE(serverFd, 0);
    eventManager->SetSocketFd(serverFd);

    TcpServerListenContext listenContext(env, eventManager);
    InitTcpServerListenContext(listenContext, "127.0.0.1", 0);
    ASSERT_TRUE(SocketExec::ExecTcpServerListen(&listenContext));

    uint16_t port = GetBoundPort(serverFd);
    ASSERT_GT(port, 0);

    constexpr int CLIENT_NUM = 5;
    std::vector<int> clientFds;
    for (int i = 0; i < CLIENT_NUM; ++i) {
        int fd = ConnectToServer("127.0.0.1", port);
        ASSERT_GE(fd, 0);
        clientFds.push_back(fd);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    TcpServerCloseContext closeContext(env, eventManager);
    EXPECT_TRUE(SocketExec::ExecTcpServerClose(&closeContext));

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    for (int fd : clientFds) {
        close(fd);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    SUCCEED();
}

HWTEST_F(SocketTest, TcpServerDetachTest003, TestSize.Level2)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();

    int serverFd = CreateTcpServerSocket();
    ASSERT_GE(serverFd, 0);
    eventManager->SetSocketFd(serverFd);

    TcpServerListenContext listenContext(env, eventManager);
    InitTcpServerListenContext(listenContext, "127.0.0.1", 0);
    ASSERT_TRUE(SocketExec::ExecTcpServerListen(&listenContext));

    uint16_t port = GetBoundPort(serverFd);
    ASSERT_GT(port, 0);

    int clientFd1 = ConnectToServer("127.0.0.1", port);
    ASSERT_GE(clientFd1, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    TcpServerCloseContext closeContext(env, eventManager);
    EXPECT_TRUE(SocketExec::ExecTcpServerClose(&closeContext));
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    int clientFd2 = socket(AF_INET, SOCK_STREAM, 0);
    EXPECT_GE(clientFd2, 0);
    sockaddr_in addr2 = {};
    addr2.sin_family = AF_INET;
    addr2.sin_port = htons(port);
    addr2.sin_addr.s_addr = inet_addr("127.0.0.1");
    int ret2 = connect(clientFd2, reinterpret_cast<sockaddr *>(&addr2), sizeof(addr2));
    EXPECT_LT(ret2, 0);
    if (clientFd2 >= 0) {
        close(clientFd2);
    }

    close(clientFd1);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    SUCCEED();
}

HWTEST_F(SocketTest, TcpServerDetachTest004, TestSize.Level2)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();

    int serverFd = CreateTcpServerSocket();
    ASSERT_GE(serverFd, 0);
    eventManager->SetSocketFd(serverFd);

    TcpServerListenContext listenContext(env, eventManager);
    InitTcpServerListenContext(listenContext, "127.0.0.1", 0);
    ASSERT_TRUE(SocketExec::ExecTcpServerListen(&listenContext));

    uint16_t port = GetBoundPort(serverFd);
    ASSERT_GT(port, 0);

    int clientFd = ConnectToServer("127.0.0.1", port);
    ASSERT_GE(clientFd, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    EXPECT_EQ(shutdown(serverFd, SHUT_RDWR), 0);

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    const char *data = "hello";
    int sent = send(clientFd, data, strlen(data), 0);
    EXPECT_GT(sent, 0);

    close(clientFd);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    SUCCEED();
}

HWTEST_F(SocketTest, TcpSocketFdZeroTest001, TestSize.Level1)
{
    /* Regression test for XTS testNetworkMgrSocketTCPSocketSetExtraOptions5200:
     * fd 0 is a valid socket fd and must not be treated as "not created/closed". */
    constexpr int FD_ZERO_RETRY_TIMES = 5;
    int savedStdin = dup(STDIN_FILENO);
    bool stdinWasOpen = savedStdin >= 0;
    if (stdinWasOpen) {
        ASSERT_EQ(close(STDIN_FILENO), 0);
    }

    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    EXPECT_EQ(eventManager->GetSocketFd(), -1);

    int sockFd = -1;
    for (int i = 0; i < FD_ZERO_RETRY_TIMES; ++i) {
        sockFd = ExecCommonUtils::MakeTcpSocket(AF_INET);
        if (sockFd == 0) {
            break;
        }
        if (sockFd > 0) {
            close(sockFd);
        }
        sockFd = -1;
    }
    ASSERT_EQ(sockFd, 0);

    eventManager->SetSocketFd(sockFd);
    EXPECT_EQ(eventManager->GetSocketFd(), 0);

    BindContext bindContext(env, eventManager);
    InitUdpBindContext(bindContext, 0);
    EXPECT_TRUE(SocketExec::ExecUdpBind(&bindContext)) << "bind with fd 0 should succeed";

    TcpSetExtraOptionsContext extraContext(env, eventManager);
    EXPECT_TRUE(SocketExec::ExecTcpSetExtraOptions(&extraContext)) << "fd 0 must not be treated as bad fd";

    close(sockFd);
    eventManager->SetSocketFd(-1);
    EXPECT_EQ(eventManager->GetSocketFd(), -1);
    EXPECT_FALSE(SocketExec::ExecTcpSetExtraOptions(&extraContext)) << "closed socket must be rejected";

    if (stdinWasOpen) {
        EXPECT_EQ(dup2(savedStdin, STDIN_FILENO), STDIN_FILENO);
        close(savedStdin);
    }
}

/* M1 regression: the stop eventfd must be drained after consumption, otherwise
 * a level-triggered epoll keeps reporting the stale stop event forever. */
HWTEST_F(SocketTest, LocalSocketServerManagerDrainStopEventTest001, TestSize.Level1)
{
    LocalSocketServerManager mgr;
    ASSERT_GE(mgr.StartEpoll(), 0);
    ASSERT_GE(mgr.stopEventFd_, 0);

    mgr.NotifyStopEvent();
    mgr.DrainStopEvent();

    /* counter is empty now: a non-blocking read must fail with EAGAIN */
    eventfd_t value = 0;
    EXPECT_EQ(read(mgr.stopEventFd_, &value, sizeof(value)), -1);
    EXPECT_EQ(errno, EAGAIN);

    close(mgr.stopEventFd_);
    mgr.stopEventFd_ = -1;
    close(mgr.epollFd_);
    mgr.epollFd_ = -1;
}

/* M1 regression: after draining the stop event, EpollWait must fall back to
 * its timeout instead of returning the stale stop event immediately. */
HWTEST_F(SocketTest, LocalSocketServerManagerEpollStopEventTest001, TestSize.Level1)
{
    LocalSocketServerManager mgr;
    ASSERT_GE(mgr.StartEpoll(), 0);
    ASSERT_EQ(mgr.RegisterEpollEvent(mgr.stopEventFd_, EPOLLIN), 0);

    mgr.NotifyStopEvent();
    int eventNum = mgr.EpollWait();
    ASSERT_GT(eventNum, 0);
    bool stopSeen = false;
    for (int i = 0; i < eventNum; ++i) {
        if (mgr.events_[i].data.fd == mgr.stopEventFd_) {
            stopSeen = true;
            mgr.DrainStopEvent();
        }
    }
    EXPECT_TRUE(stopSeen);

    auto start = std::chrono::steady_clock::now();
    EXPECT_EQ(mgr.EpollWait(), 0);
    auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_GE(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count(), 400);

    close(mgr.stopEventFd_);
    mgr.stopEventFd_ = -1;
    close(mgr.epollFd_);
    mgr.epollFd_ = -1;
}

} // namespace
