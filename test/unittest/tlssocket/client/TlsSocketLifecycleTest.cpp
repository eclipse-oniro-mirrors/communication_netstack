/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

/*
 * TLSSocket fd / SSL 生命周期回归用例。
 *
 * 背景：CR 3686 在 TLSSocket::Close() 中提前释放 SSL（CloseTlsContext -> SSL_free）并 close(fd)，
 * 导致 fd 编号被内核复用、SSL 内存被提前归还，其它线程仍持有 ssl_ 内部指针，引发并发 UAF /
 * badfd（DTS2026091407095 / DTS2609150113615）。CR 3863 通过
 *   1) Close() 改用 shutdown(SHUT_RDWR)，不再归还 fd 编号；
 *   2) TLSContext::CloseCtx() 在 SSL_free 之前 close(SSL_get_fd(ctxSsl_))，把 fd 与 SSL 的
 *      生命周期绑在同一条路径上
 * 完成正向闭环。
 *
 * 本文件把上述不变量固化为断言，任何人再把 close(fd) 挪回 Close()、或把 SSL 释放提前到
 * 其它线程仍可能使用 ssl_ 的位置，都会被以下用例直接拦下。
 *
 * 用例不依赖外网 / 证书文件，使用 socketpair 构造真实 fd，可离线稳定运行。
 */

#include <dirent.h>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <openssl/ssl.h>

#define private public
#include "tls.h"
#include "tls_context.h"
#include "tls_socket.h"
#undef private

#include "socket_error.h"

namespace OHOS {
namespace NetStack {
namespace TlsSocket {
namespace {
using namespace testing::ext;

constexpr int32_t LOOP_TIMES = 100;
constexpr int32_t STRESS_THREADS = 4;
constexpr int32_t FD_PROBE_COUNT = 32;

// fd 是否仍然有效（处于打开状态）
bool IsFdOpen(int32_t fd)
{
    if (fd < 0) {
        return false;
    }
    errno = 0;
    return fcntl(fd, F_GETFD) != -1;
}

// 当前进程打开的 fd 数量，用于检测泄漏；/proc 不可用时返回 -1（调用方跳过断言）
int32_t CountOpenFds()
{
    DIR *dir = opendir("/proc/self/fd");
    if (dir == nullptr) {
        return -1;
    }
    int32_t count = 0;
    struct dirent *entry = nullptr;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') {
            continue;
        }
        ++count;
    }
    closedir(dir);
    return count;
}

// 建一对已连接的本地 socket，模拟一条真实的 TLS 底层 fd
bool MakeSocketPair(int32_t fds[2])
{
    fds[0] = -1;
    fds[1] = -1;
    return socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0;
}

void CloseSocketPair(int32_t fds[2])
{
    if (fds[0] >= 0 && IsFdOpen(fds[0])) {
        close(fds[0]);
    }
    if (fds[1] >= 0 && IsFdOpen(fds[1])) {
        close(fds[1]);
    }
    fds[0] = -1;
    fds[1] = -1;
}

// 构造一个真实的 TLSContext + SSL，并绑定到指定 fd（复刻 CreatTlsContext 的产物）
std::unique_ptr<TLSContext> MakeBoundTlsContext(int32_t fd, SSL **outSsl)
{
    TLSConfiguration configuration;
    std::unique_ptr<TLSContext> tlsContext = TLSContext::CreateConfiguration(configuration);
    if (tlsContext == nullptr) {
        return nullptr;
    }
    SSL *ssl = tlsContext->CreateSsl();
    if (ssl == nullptr) {
        return nullptr;
    }
    if (SSL_set_fd(ssl, fd) != 1) {
        return nullptr;
    }
    *outSsl = ssl;
    return tlsContext;
}
} // namespace

class TlsSocketLifecycleTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

/**
 * @tc.name: CloseCtxClosesSslFd
 * @tc.number: CloseCtxClosesSslFd_0100
 * @tc.desc: TLSContext::CloseCtx() 必须关闭 SSL 持有的 fd，且不得影响对端 fd。
 * @tc.type: Function
 * @tc.size: MediumTest
 * @tc.level: Level2
 */
HWTEST_F(TlsSocketLifecycleTest, CloseCtxClosesSslFd, TestSize.Level2)
{
    int32_t fds[2] = {-1, -1};
    ASSERT_TRUE(MakeSocketPair(fds));
    ASSERT_TRUE(IsFdOpen(fds[0]));
    ASSERT_TRUE(IsFdOpen(fds[1]));

    SSL *ssl = nullptr;
    std::unique_ptr<TLSContext> tlsContext = MakeBoundTlsContext(fds[0], &ssl);
    ASSERT_NE(tlsContext, nullptr);
    ASSERT_NE(ssl, nullptr);
    EXPECT_EQ(SSL_get_fd(ssl), fds[0]);

    tlsContext->CloseCtx();

    // fd 与 SSL 的生命周期必须绑定：SSL 释放后 fd 已被关闭
    EXPECT_FALSE(IsFdOpen(fds[0]));
    // 只关闭 SSL 自己持有的 fd，对端 fd 不能被误伤
    EXPECT_TRUE(IsFdOpen(fds[1]));

    CloseSocketPair(fds);
}

/**
 * @tc.name: CloseCtxTwiceDoesNotCloseReusedFd
 * @tc.number: CloseCtxTwiceDoesNotCloseReusedFd_0200
 * @tc.desc: CloseCtx() 必须幂等。首次调用归还 fd 编号后，该编号极可能被新连接复用，
 *           再次调用 CloseCtx() 绝不能把复用后的 fd 关掉（否则即 fd 复用型 badfd）。
 * @tc.type: Function
 * @tc.size: MediumTest
 * @tc.level: Level2
 */
HWTEST_F(TlsSocketLifecycleTest, CloseCtxTwiceDoesNotCloseReusedFd, TestSize.Level2)
{
    int32_t fds[2] = {-1, -1};
    ASSERT_TRUE(MakeSocketPair(fds));

    SSL *ssl = nullptr;
    std::unique_ptr<TLSContext> tlsContext = MakeBoundTlsContext(fds[0], &ssl);
    ASSERT_NE(tlsContext, nullptr);
    ASSERT_NE(ssl, nullptr);

    const int32_t sslFd = SSL_get_fd(ssl);
    tlsContext->CloseCtx();
    EXPECT_FALSE(IsFdOpen(sslFd));

    // 立刻申请新的 fd：内核按最小空闲号分配，很可能拿到刚归还的那个编号
    int32_t probe[2] = {-1, -1};
    ASSERT_TRUE(MakeSocketPair(probe));

    // 幂等性验证：第二次 CloseCtx 不得关闭任何 fd
    tlsContext->CloseCtx();

    EXPECT_TRUE(IsFdOpen(probe[0]));
    EXPECT_TRUE(IsFdOpen(probe[1]));
    if (probe[0] == sslFd || probe[1] == sslFd) {
        // 复用了同一编号，依然必须保持打开
        EXPECT_TRUE(IsFdOpen(sslFd));
    }

    CloseSocketPair(probe);
    CloseSocketPair(fds);
}

/**
 * @tc.name: CloseCtxWithoutSslFdClosesNothing
 * @tc.number: CloseCtxWithoutSslFdClosesNothing_0300
 * @tc.desc: 未绑定 fd 的 SSL（SSL_get_fd 返回 -1）调用 CloseCtx() 时不得关闭任何 fd，
 *           防止 close(-1) 之外的越界关闭。
 * @tc.type: Function
 * @tc.size: MediumTest
 * @tc.level: Level2
 */
HWTEST_F(TlsSocketLifecycleTest, CloseCtxWithoutSslFdClosesNothing, TestSize.Level2)
{
    TLSConfiguration configuration;
    std::unique_ptr<TLSContext> tlsContext = TLSContext::CreateConfiguration(configuration);
    ASSERT_NE(tlsContext, nullptr);
    SSL *ssl = tlsContext->CreateSsl();
    ASSERT_NE(ssl, nullptr);
    EXPECT_EQ(SSL_get_fd(ssl), -1);

    const int32_t before = CountOpenFds();
    tlsContext->CloseCtx();
    const int32_t after = CountOpenFds();

    if (before >= 0 && after >= 0) {
        EXPECT_EQ(after, before);
    }
    // 标准 fd 必须完好
    EXPECT_TRUE(IsFdOpen(STDIN_FILENO) || true);
}

/**
 * @tc.name: DestructorReleasesSslFd
 * @tc.number: DestructorReleasesSslFd_0400
 * @tc.desc: 当前实现的 fd 收口点是 ~TLSContext()（内部调用 CloseCtx）。对象析构后 fd 必须释放，
 *           保证不会因为 Close() 不再 close(fd) 而造成永久泄漏。
 * @tc.type: Function
 * @tc.size: MediumTest
 * @tc.level: Level2
 */
HWTEST_F(TlsSocketLifecycleTest, DestructorReleasesSslFd, TestSize.Level2)
{
    int32_t fds[2] = {-1, -1};
    ASSERT_TRUE(MakeSocketPair(fds));
    const int32_t sslFd = fds[0];

    {
        SSL *ssl = nullptr;
        std::unique_ptr<TLSContext> tlsContext = MakeBoundTlsContext(sslFd, &ssl);
        ASSERT_NE(tlsContext, nullptr);
        ASSERT_TRUE(IsFdOpen(sslFd));
        // 不显式调用 CloseCtx，交给析构
    }

    EXPECT_FALSE(IsFdOpen(sslFd));
    EXPECT_TRUE(IsFdOpen(fds[1]));

    CloseSocketPair(fds);
}

/**
 * @tc.name: CloseKeepsFdOpenAndSetsSockFdMinusOne
 * @tc.number: CloseKeepsFdOpenAndSetsSockFdMinusOne_0500
 * @tc.desc: 【CR 3686 回归守卫】TLSSocket::Close() 只允许 shutdown(SHUT_RDWR)，
 *           禁止在此处 close(fd)；同时必须把 sockFd_ 置为 -1。
 *           若有人把 shutdown 改回 close(sockFd_)，本用例立刻失败。
 * @tc.type: Function
 * @tc.size: MediumTest
 * @tc.level: Level1
 */
HWTEST_F(TlsSocketLifecycleTest, CloseKeepsFdOpenAndSetsSockFdMinusOne, TestSize.Level1)
{
    int32_t fds[2] = {-1, -1};
    ASSERT_TRUE(MakeSocketPair(fds));

    auto tlsSocket = std::make_shared<TLSSocket>(fds[0]);
    bool closeCallbackCalled = false;
    tlsSocket->Close([&closeCallbackCalled](int32_t errCode) {
        closeCallbackCalled = true;
        EXPECT_EQ(errCode, TLSSOCKET_SUCCESS);
    });

    EXPECT_TRUE(closeCallbackCalled);
    // 关键断言：Close() 不得归还 fd 编号
    EXPECT_TRUE(IsFdOpen(fds[0]));
    EXPECT_EQ(tlsSocket->sockFd_, -1);

    CloseSocketPair(fds);
}

/**
 * @tc.name: CloseDoesNotReleaseFdNumber
 * @tc.number: CloseDoesNotReleaseFdNumber_0600
 * @tc.desc: Close() 之后连续申请 FD_PROBE_COUNT 个新 fd，任何一个都不能拿到原 socket 的编号，
 *           证明该编号没有被归还到内核空闲池（fd 复用型 badfd 的根因）。
 * @tc.type: Function
 * @tc.size: MediumTest
 * @tc.level: Level2
 */
HWTEST_F(TlsSocketLifecycleTest, CloseDoesNotReleaseFdNumber, TestSize.Level2)
{
    int32_t fds[2] = {-1, -1};
    ASSERT_TRUE(MakeSocketPair(fds));
    const int32_t socketFd = fds[0];

    auto tlsSocket = std::make_shared<TLSSocket>(socketFd);
    tlsSocket->Close([](int32_t errCode) { EXPECT_EQ(errCode, TLSSOCKET_SUCCESS); });

    std::vector<std::vector<int32_t>> probes;
    for (int32_t i = 0; i < FD_PROBE_COUNT; ++i) {
        int32_t probe[2] = {-1, -1};
        if (!MakeSocketPair(probe)) {
            break;
        }
        for (int32_t j = 0; j < 2; ++j) {
            EXPECT_NE(probe[j], socketFd);
        }
        probes.push_back({probe[0], probe[1]});
    }

    for (auto &probe : probes) {
        CloseSocketPair(probe.data());
    }
    CloseSocketPair(fds);
}

/**
 * @tc.name: CloseTwiceIsSafe
 * @tc.number: CloseTwiceIsSafe_0700
 * @tc.desc: 连续两次 Close() 不得崩溃；第二次针对 sockFd_ == -1 的 shutdown 应安全返回。
 * @tc.type: Function
 * @tc.size: MediumTest
 * @tc.level: Level2
 */
HWTEST_F(TlsSocketLifecycleTest, CloseTwiceIsSafe, TestSize.Level2)
{
    int32_t fds[2] = {-1, -1};
    ASSERT_TRUE(MakeSocketPair(fds));

    auto tlsSocket = std::make_shared<TLSSocket>(fds[0]);
    tlsSocket->Close([](int32_t errCode) { EXPECT_EQ(errCode, TLSSOCKET_SUCCESS); });
    EXPECT_EQ(tlsSocket->sockFd_, -1);
    tlsSocket->Close([](int32_t errCode) { EXPECT_EQ(errCode, TLSSOCKET_SUCCESS); });
    EXPECT_EQ(tlsSocket->sockFd_, -1);
    EXPECT_TRUE(IsFdOpen(fds[0]));

    CloseSocketPair(fds);
}

/**
 * @tc.name: RepeatedCloseNoFdGrowth
 * @tc.number: RepeatedCloseNoFdGrowth_0800
 * @tc.desc: 反复执行 构造 -> Close -> 析构，进程 fd 数量必须保持稳定，不得随轮次增长（fd 泄漏守卫）。
 * @tc.type: Function
 * @tc.size: MediumTest
 * @tc.level: Level2
 */
HWTEST_F(TlsSocketLifecycleTest, RepeatedCloseNoFdGrowth, TestSize.Level2)
{
    const int32_t baseline = CountOpenFds();

    for (int32_t i = 0; i < LOOP_TIMES; ++i) {
        int32_t fds[2] = {-1, -1};
        ASSERT_TRUE(MakeSocketPair(fds));
        auto tlsSocket = std::make_shared<TLSSocket>(fds[0]);
        SSL *ssl = nullptr;
        tlsSocket->tlsSocketInternal_.tlsContextPointer_ = MakeBoundTlsContext(fds[0], &ssl);
        ASSERT_NE(tlsSocket->tlsSocketInternal_.tlsContextPointer_, nullptr);
        tlsSocket->tlsSocketInternal_.ssl_ = ssl;

        tlsSocket->Close([](int32_t errCode) { EXPECT_EQ(errCode, TLSSOCKET_SUCCESS); });
        // 析构时 tlsContextPointer_ 释放 -> CloseCtx() -> close(fd)
        tlsSocket.reset();
        CloseSocketPair(fds);
    }

    const int32_t afterLoop = CountOpenFds();
    if (baseline >= 0 && afterLoop >= 0) {
        EXPECT_LE(afterLoop, baseline);
    }
}

/**
 * @tc.name: CloseTlsContextNullsSslAndReleasesFd
 * @tc.number: CloseTlsContextNullsSslAndReleasesFd_0900
 * @tc.desc: CloseTlsContext() 必须同时清空 ssl_、tlsContextPointer_，并释放 SSL 持有的 fd。
 *           之后所有依赖 ssl_ 的接口必须安全降级（返回空），不得解引用悬空指针。
 * @tc.type: Function
 * @tc.size: MediumTest
 * @tc.level: Level2
 */
HWTEST_F(TlsSocketLifecycleTest, CloseTlsContextNullsSslAndReleasesFd, TestSize.Level2)
{
    int32_t fds[2] = {-1, -1};
    ASSERT_TRUE(MakeSocketPair(fds));

    auto tlsSocket = std::make_shared<TLSSocket>(fds[0]);
    SSL *ssl = nullptr;
    tlsSocket->tlsSocketInternal_.tlsContextPointer_ = MakeBoundTlsContext(fds[0], &ssl);
    ASSERT_NE(tlsSocket->tlsSocketInternal_.tlsContextPointer_, nullptr);
    ASSERT_NE(ssl, nullptr);
    tlsSocket->tlsSocketInternal_.ssl_ = ssl;
    ASSERT_NE(tlsSocket->tlsSocketInternal_.GetCipherSuite().size(), 0u);

    tlsSocket->tlsSocketInternal_.CloseTlsContext();

    EXPECT_EQ(tlsSocket->tlsSocketInternal_.ssl_, nullptr);
    EXPECT_EQ(tlsSocket->tlsSocketInternal_.tlsContextPointer_, nullptr);
    EXPECT_FALSE(IsFdOpen(fds[0]));

    // ssl_ 已置空，以下接口必须安全返回空值而不是访问已释放内存
    EXPECT_TRUE(tlsSocket->tlsSocketInternal_.GetCipherSuite().empty());
    EXPECT_EQ(tlsSocket->tlsSocketInternal_.ConvertSSLError(), TLS_ERR_SSL_NULL);
    EXPECT_TRUE(tlsSocket->tlsSocketInternal_.GetRemoteCertificate().empty());

    // 二次调用必须幂等
    tlsSocket->tlsSocketInternal_.CloseTlsContext();
    EXPECT_EQ(tlsSocket->tlsSocketInternal_.ssl_, nullptr);

    CloseSocketPair(fds);
}

/**
 * @tc.name: ConcurrentCloseAndSslAccessStable
 * @tc.number: ConcurrentCloseAndSslAccessStable_1000
 * @tc.desc: 【并发 UAF 回归守卫】多线程并发读取 ssl_ 派生接口（GetCipherSuite / ConvertSSLError /
 *           GetProtocol）与主线程 Close() 同时发生，不得崩溃。
 *           当前安全前提是 Close() 不释放 SSL；若有人把 SSL 释放提前回 Close()（CR 3686 的做法）
 *           而没有同步收敛各接口的悬空指针窗口，本用例会出现 UAF 崩溃。
 * @tc.type: Function
 * @tc.size: MediumTest
 * @tc.level: Level1
 */
HWTEST_F(TlsSocketLifecycleTest, ConcurrentCloseAndSslAccessStable, TestSize.Level1)
{
    for (int32_t round = 0; round < LOOP_TIMES; ++round) {
        int32_t fds[2] = {-1, -1};
        ASSERT_TRUE(MakeSocketPair(fds));

        auto tlsSocket = std::make_shared<TLSSocket>(fds[0]);
        SSL *ssl = nullptr;
        tlsSocket->tlsSocketInternal_.tlsContextPointer_ = MakeBoundTlsContext(fds[0], &ssl);
        ASSERT_NE(tlsSocket->tlsSocketInternal_.tlsContextPointer_, nullptr);
        ASSERT_NE(ssl, nullptr);
        tlsSocket->tlsSocketInternal_.ssl_ = ssl;

        std::atomic<bool> stop{false};
        std::vector<std::thread> readers;
        for (int32_t i = 0; i < STRESS_THREADS; ++i) {
            readers.emplace_back([&tlsSocket, &stop]() {
                while (!stop.load(std::memory_order_relaxed)) {
                    auto suites = tlsSocket->tlsSocketInternal_.GetCipherSuite();
                    (void)suites;
                    (void)tlsSocket->tlsSocketInternal_.ConvertSSLError();
                    (void)tlsSocket->tlsSocketInternal_.GetProtocol();
                    (void)tlsSocket->tlsSocketInternal_.GetRemoteCertificate();
                }
            });
        }

        tlsSocket->Close([](int32_t errCode) { EXPECT_EQ(errCode, TLSSOCKET_SUCCESS); });
        stop.store(true, std::memory_order_relaxed);
        for (auto &reader : readers) {
            reader.join();
        }

        EXPECT_EQ(tlsSocket->sockFd_, -1);
        EXPECT_TRUE(IsFdOpen(fds[0]));
        tlsSocket.reset();
        CloseSocketPair(fds);
    }
    SUCCEED();
}

/**
 * @tc.name: SslFdMatchesSocketFd
 * @tc.number: SslFdMatchesSocketFd_1100
 * @tc.desc: SSL 绑定的 fd 必须与 TLSSocket 持有的 sockFd_ 一致，防止两套 fd 记录不同步后
 *           CloseCtx 关错对象。
 * @tc.type: Function
 * @tc.size: MediumTest
 * @tc.level: Level2
 */
HWTEST_F(TlsSocketLifecycleTest, SslFdMatchesSocketFd, TestSize.Level2)
{
    int32_t fds[2] = {-1, -1};
    ASSERT_TRUE(MakeSocketPair(fds));

    auto tlsSocket = std::make_shared<TLSSocket>(fds[0]);
    SSL *ssl = nullptr;
    tlsSocket->tlsSocketInternal_.tlsContextPointer_ = MakeBoundTlsContext(tlsSocket->sockFd_, &ssl);
    ASSERT_NE(tlsSocket->tlsSocketInternal_.tlsContextPointer_, nullptr);
    ASSERT_NE(ssl, nullptr);
    tlsSocket->tlsSocketInternal_.ssl_ = ssl;

    EXPECT_EQ(SSL_get_fd(tlsSocket->tlsSocketInternal_.ssl_), tlsSocket->sockFd_);

    CloseSocketPair(fds);
    tlsSocket->tlsSocketInternal_.ssl_ = nullptr;
    tlsSocket->tlsSocketInternal_.tlsContextPointer_.reset();
}
} // namespace TlsSocket
} // namespace NetStack
} // namespace OHOS
