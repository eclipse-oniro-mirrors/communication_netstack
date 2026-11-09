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

#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <fcntl.h>
#include <future>
#include <memory>
#include <poll.h>
#include <pthread.h>
#include <shared_mutex>
#include <sys/socket.h>
#include <thread>
#include <gtest/gtest.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

// The keyword spelling is required for test-only access; keep product visibility unchanged.
// NOLINTNEXTLINE(readability-identifier-naming)
#define private public
#ifdef CERT_ALIAS_NATIVE_SOCKET_TEST
#include "tls_socket_client_innerapi.h"
#include "tls_socket_server_innerapi.h"
#else
#include "tls_socket.h"
#include "tls_socket_server.h"
#include "tls_connect_context.h"
#include "socket_constant.h"
#endif
#undef private
#include "tls_cert_alias_test_utils.h"

namespace OHOS::NetStack::TlsSocket {
namespace AliasTest = ::OHOS::NetStack::TlsSocket::Test;
namespace {
using namespace testing::ext;
class TlsCertAliasSocketTest : public testing::Test {};

struct SocketPair {
    std::shared_ptr<TLSSocket> client;
    int peer = -1;
    ~SocketPair()
    {
        if (peer >= 0) {
            close(peer);
        }
    }
    bool Open()
    {
        int sockets[2] = {-1, -1};
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
            return false;
        }
        client = std::make_shared<TLSSocket>(sockets[0]);
        peer = sockets[1];
        return true;
    }
};

void PrepareSocketSsl(const std::shared_ptr<TLSSocket> &socket)
{
    auto &internal = socket->tlsSocketInternal_;
    internal.tlsContextPointer_ = std::make_unique<TLSContext>();
    internal.tlsContextPointer_->ctx_ = SSL_CTX_new(TLS_client_method());
    ASSERT_NE(internal.tlsContextPointer_->ctx_, nullptr);
    internal.ssl_ = internal.tlsContextPointer_->CreateSsl();
    ASSERT_NE(internal.ssl_, nullptr);
    internal.socketDescriptor_ = socket->GetSocketFd();
    ASSERT_EQ(SSL_set_fd(internal.ssl_, socket->GetSocketFd()), 1);
    SSL_set_connect_state(internal.ssl_);
}

TLSSecureOptions PemOptions()
{
    TLSSecureOptions options;
    options.SetKey(SecureData(std::string("private pem")));
    options.SetKeyPass(SecureData(std::string("password")));
    options.SetCertChain({"certificate"});
    options.SetCaChain({"ca"});
    options.SetProtocolChain({"TLSv1.2", "TLSv1.3"});
    options.SetCrlChain({"crl"});
    options.SetCipherSuite("cipher");
    options.SetSignatureAlgorithms("RSA+SHA256");
    options.SetUseRemoteCipherPrefer(true);
    options.SetVerifyMode(TWO_WAY_MODE);
    return options;
}

HWTEST_F(TlsCertAliasSocketTest, PemCopyRetainsIdentityAndDefaultAliasAbsence, TestSize.Level1)
{
    auto source = PemOptions();
    TLSSecureOptions copy(source);
    EXPECT_FALSE(copy.GetCertAlias().has_value());
    EXPECT_EQ(copy.GetKey().Length(), source.GetKey().Length());
    EXPECT_EQ(copy.GetKeyPass().Length(), source.GetKeyPass().Length());
    EXPECT_EQ(copy.GetCertChain(), source.GetCertChain());
}

HWTEST_F(TlsCertAliasSocketTest, AliasCopyDiscardsPemIdentityAndPreservesOtherOptions, TestSize.Level1)
{
    auto source = PemOptions();
    source.SetCertAlias(" Alias ");
    TLSSecureOptions copy(source);
    ASSERT_TRUE(copy.GetCertAlias().has_value());
    EXPECT_EQ(*copy.GetCertAlias(), " Alias ");
    EXPECT_EQ(copy.GetKey().Length(), 0U);
    EXPECT_EQ(copy.GetKeyPass().Length(), 0U);
    EXPECT_TRUE(copy.GetCertChain().empty());
    EXPECT_EQ(copy.GetCaChain(), source.GetCaChain());
    EXPECT_EQ(copy.GetProtocolChain(), source.GetProtocolChain());
    EXPECT_EQ(copy.GetCrlChain(), source.GetCrlChain());
    EXPECT_EQ(copy.GetCipherSuite(), source.GetCipherSuite());
    EXPECT_EQ(copy.GetSignatureAlgorithms(), source.GetSignatureAlgorithms());
    EXPECT_EQ(copy.UseRemoteCipherPrefer(), source.UseRemoteCipherPrefer());
    EXPECT_EQ(copy.GetVerifyMode(), source.GetVerifyMode());
    EXPECT_GT(source.GetKey().Length(), 0U);
}

HWTEST_F(TlsCertAliasSocketTest, AssignmentClearsOldIdentityInBothDirections, TestSize.Level1)
{
    auto pem = PemOptions();
    TLSSecureOptions alias;
    alias.SetCertAlias("client");
    auto destination = pem;
    destination = alias;
    ASSERT_TRUE(destination.GetCertAlias().has_value());
    EXPECT_EQ(*destination.GetCertAlias(), "client");
    EXPECT_EQ(destination.GetKey().Length(), 0U);
    EXPECT_EQ(destination.GetKeyPass().Length(), 0U);
    EXPECT_TRUE(destination.GetCertChain().empty());
    destination = pem;
    EXPECT_FALSE(destination.GetCertAlias().has_value());
    EXPECT_EQ(destination.GetKey().Length(), pem.GetKey().Length());
    EXPECT_EQ(destination.GetKeyPass().Length(), pem.GetKeyPass().Length());
    EXPECT_EQ(destination.GetCertChain(), pem.GetCertChain());
}

HWTEST_F(TlsCertAliasSocketTest, NewConnectConfigurationClearsOldAliasAndCertificateChain, TestSize.Level1)
{
    AliasTest::SigningAdapter adapter(false);
    TLSSocket socket;
    auto &internal = socket.tlsSocketInternal_;
    auto &configuration = internal.configuration_;
    configuration.SetAliasCredential(std::make_shared<AliasCredential>());
    configuration.SetLocalCertificate(std::vector<std::string>{adapter.pem, adapter.pem});
    configuration.SetProtocol(std::vector<std::string>{PROTOCOL_TLS_V12});
    configuration.SetUseRemoteCipherPrefer(true);
    configuration.SetVerifyMode(TWO_WAY_MODE);
    TLSSecureOptions secure;
    secure.SetCertChain({adapter.pem});
    TLSConnectOptions options;
    options.SetTlsSecureOptions(secure);
    Socket::NetAddress address;
    address.SetRawAddress("192.0.2.1");
    options.SetNetAddress(address);
    options.SetServerName("example.test");
    ASSERT_TRUE(internal.SetTlsConfiguration(options));
    EXPECT_EQ(configuration.GetAliasCredential(), nullptr);
    EXPECT_NE(configuration.GetAttemptState(), nullptr);
    ASSERT_EQ(configuration.GetLocalCertificate().size(), 1U);
    EXPECT_EQ(configuration.GetCertificate().data.Length(), static_cast<size_t>(i2d_X509(adapter.cert.get(), nullptr)));
    EXPECT_EQ(configuration.GetProtocol(), TLS_V1_3);
    EXPECT_EQ(configuration.GetMinProtocol(), TLS_V1_2);
    EXPECT_EQ(configuration.GetMaxProtocol(), TLS_V1_3);
    EXPECT_FALSE(configuration.GetUseRemoteCipherPrefer());
    EXPECT_EQ(configuration.GetVerifyMode(), ONE_WAY_MODE);
    EXPECT_EQ(configuration.GetNetAddress().GetAddress(), "example.test");
    secure.SetCertChain({});
    options.SetTlsSecureOptions(secure);
    ASSERT_TRUE(internal.SetTlsConfiguration(options));
    EXPECT_TRUE(configuration.GetLocalCertificate().empty());
    EXPECT_EQ(configuration.GetAliasCredential(), nullptr);
}

HWTEST_F(TlsCertAliasSocketTest, SelfAssignmentKeepsSourceAndConnectOptionsApplyPriority, TestSize.Level1)
{
    auto options = PemOptions();
    auto *same = &options;
    options = *same;
    EXPECT_GT(options.GetKey().Length(), 0U);
    options.SetCertAlias("client");
    options = *same;
    EXPECT_EQ(*options.GetCertAlias(), "client");
    EXPECT_GT(options.GetKey().Length(), 0U);
    TLSConnectOptions connect;
    connect.SetTlsSecureOptions(options);
    EXPECT_EQ(*connect.GetTlsSecureOptions().GetCertAlias(), "client");
    EXPECT_TRUE(connect.GetTlsSecureOptions().GetCertChain().empty());
    EXPECT_EQ(connect.GetTlsSecureOptions().GetKey().Length(), 0U);
}

HWTEST_F(TlsCertAliasSocketTest, AliasValidationFailureStartsFreshAttemptWithoutPemFallback, TestSize.Level1)
{
    TLSSocket socket;
    auto &internal = socket.tlsSocketInternal_;
    auto previous = std::make_shared<TlsConnectAttemptState>();
    previous->SetFirstError(TLS_ALIAS_UNAUTHORIZED);
    std::atomic_store(&internal.attemptState_, previous);
    internal.configuration_.SetAliasCredential(std::make_shared<AliasCredential>());
    auto secure = PemOptions();
    secure.SetCertAlias(" ");
    TLSConnectOptions options;
    options.SetTlsSecureOptions(secure);
    EXPECT_FALSE(internal.SetTlsConfiguration(options));
    auto current = std::atomic_load(&internal.attemptState_);
    ASSERT_NE(current, nullptr);
    EXPECT_NE(current, previous);
    EXPECT_EQ(current->GetError(), TLS_ALIAS_INVALID);
    EXPECT_EQ(internal.ConvertSSLError(), TLS_ALIAS_INVALID);
    EXPECT_EQ(internal.configuration_.GetAliasCredential(), nullptr);
    EXPECT_TRUE(internal.configuration_.GetLocalCertificate().empty());
    EXPECT_EQ(previous->GetError(), TLS_ALIAS_UNAUTHORIZED);
}

HWTEST_F(TlsCertAliasSocketTest, PemConfigurationClearsStaleAliasAndAttemptError, TestSize.Level1)
{
    TLSSocket socket;
    auto &internal = socket.tlsSocketInternal_;
    auto stale = std::make_shared<TlsConnectAttemptState>();
    stale->SetFirstError(TLS_ALIAS_SERVICE_ERROR);
    internal.configuration_.SetAliasCredential(std::make_shared<AliasCredential>());
    internal.configuration_.SetAttemptState(stale);
    std::atomic_store(&internal.attemptState_, stale);
    TLSConnectOptions options;
    EXPECT_TRUE(internal.SetTlsConfiguration(options));
    auto current = std::atomic_load(&internal.attemptState_);
    ASSERT_NE(current, nullptr);
    EXPECT_NE(current, stale);
    EXPECT_EQ(current->GetError(), 0);
    EXPECT_EQ(internal.configuration_.GetAttemptState(), current);
    EXPECT_EQ(internal.configuration_.GetAliasCredential(), nullptr);
    EXPECT_EQ(internal.ConvertSSLError(), TLS_ERR_SSL_NULL);
}

HWTEST_F(TlsCertAliasSocketTest, InvalidAliasConnectStopsBeforeTransportAndReleasesConnectGuard, TestSize.Level1)
{
    TLSSocket socket;
    TLSSecureOptions secure;
    secure.SetCertAlias("");
    TLSConnectOptions options;
    options.SetTlsSecureOptions(secure);
    auto &internal = socket.tlsSocketInternal_;
    EXPECT_FALSE(internal.TlsConnectToHost(-1, options, false));
    EXPECT_EQ(internal.ConvertSSLError(), TLS_ALIAS_INVALID);
    EXPECT_EQ(internal.ssl_, nullptr);
    EXPECT_EQ(internal.tlsContextPointer_, nullptr);
    EXPECT_FALSE(socket.connecting_);
}

HWTEST_F(TlsCertAliasSocketTest, CancelBeforeTlsStartAndRepeatedCloseAreSafe, TestSize.Level1)
{
    TLSSocket socket;
    auto &internal = socket.tlsSocketInternal_;
    internal.CancelConnectAttempt();
    internal.CloseTlsContext();
    auto state = std::make_shared<TlsConnectAttemptState>();
    std::atomic_store(&internal.attemptState_, state);
    internal.CancelConnectAttempt();
    EXPECT_TRUE(state->IsCancelled());
    EXPECT_FALSE(internal.StartTlsConnected(TLSConnectOptions{}));
    EXPECT_EQ(internal.ssl_, nullptr);
    internal.CloseTlsContext();
    EXPECT_EQ(internal.tlsContextPointer_, nullptr);
    EXPECT_EQ(internal.ConvertSSLError(), TLS_ERR_SSL_NULL);
}

HWTEST_F(TlsCertAliasSocketTest, AliasErrorSurvivesContextCleanup, TestSize.Level1)
{
    TLSSocket socket;
    auto &internal = socket.tlsSocketInternal_;
    auto state = std::make_shared<TlsConnectAttemptState>();
    state->SetFirstError(TLS_ALIAS_UNAUTHORIZED);
    std::atomic_store(&internal.attemptState_, state);
    internal.tlsContextPointer_ = std::make_unique<TLSContext>();
    internal.tlsContextPointer_->ctx_ = SSL_CTX_new(TLS_client_method());
    ASSERT_NE(internal.tlsContextPointer_->ctx_, nullptr);
    internal.ssl_ = internal.tlsContextPointer_->CreateSsl();
    ASSERT_NE(internal.ssl_, nullptr);
    internal.CloseTlsContext();
    EXPECT_EQ(internal.tlsContextPointer_, nullptr);
    EXPECT_EQ(internal.ssl_, nullptr);
    EXPECT_TRUE(state->IsCancelled());
    EXPECT_EQ(internal.ConvertSSLError(), TLS_ALIAS_UNAUTHORIZED);
}

HWTEST_F(TlsCertAliasSocketTest, HandshakeFailureReleasesContextAndPreservesAliasError, TestSize.Level1)
{
    for (bool hasAttempt : {false, true}) {
        TLSSocket socket;
        auto &internal = socket.tlsSocketInternal_;
        if (hasAttempt) {
            auto state = std::make_shared<TlsConnectAttemptState>();
            state->SetFirstError(TLS_ALIAS_UNAUTHORIZED);
            std::atomic_store(&internal.attemptState_, state);
        }
        internal.tlsContextPointer_ = std::make_unique<TLSContext>();
        internal.tlsContextPointer_->ctx_ = SSL_CTX_new(TLS_client_method());
        ASSERT_NE(internal.tlsContextPointer_->ctx_, nullptr);
        internal.ssl_ = internal.tlsContextPointer_->CreateSsl();
        ASSERT_NE(internal.ssl_, nullptr);
        BIO *bio = BIO_new(BIO_s_mem());
        ASSERT_NE(bio, nullptr);
        SSL_set_bio(internal.ssl_, bio, bio);
        TLSConnectOptions options;
        options.SetTimeout(1);
        EXPECT_FALSE(internal.StartTlsConnected(options));
        EXPECT_EQ(internal.ssl_, nullptr);
        EXPECT_EQ(internal.tlsContextPointer_, nullptr);
        if (hasAttempt) {
            EXPECT_EQ(internal.ConvertSSLError(), TLS_ALIAS_UNAUTHORIZED);
        }
        ERR_clear_error();
    }
}

HWTEST_F(TlsCertAliasSocketTest, FailedHandshakeCloseReleasesFdAndKeepsFirstError, TestSize.Level1)
{
    for (bool hasAliasError : {false, true}) {
        SCOPED_TRACE(hasAliasError);
        SocketPair pair;
        ASSERT_TRUE(pair.Open());
        ASSERT_NO_FATAL_FAILURE(PrepareSocketSsl(pair.client));
        auto &internal = pair.client->tlsSocketInternal_;
        if (hasAliasError) {
            auto state = std::make_shared<TlsConnectAttemptState>();
            state->SetFirstError(TLS_ALIAS_UNAUTHORIZED);
            std::atomic_store(&internal.attemptState_, state);
        }
        TLSConnectOptions options;
        options.SetTimeout(1);
        ASSERT_FALSE(internal.StartTlsConnected(options));
        EXPECT_EQ(internal.ssl_, nullptr);
        EXPECT_EQ(internal.tlsContextPointer_, nullptr);
        int fd = pair.client->GetSocketFd();
        EXPECT_GE(fcntl(fd, F_GETFD), 0);
        int callbacks = 0;
        pair.client->Close([&callbacks](int32_t error) {
            ++callbacks;
            EXPECT_EQ(error, TLSSOCKET_SUCCESS);
        });
        EXPECT_EQ(callbacks, 1);
        EXPECT_EQ(internal.socketDescriptor_, -1);
        EXPECT_EQ(fcntl(fd, F_GETFD), -1);
        EXPECT_EQ(errno, EBADF);
        if (hasAliasError) {
            EXPECT_EQ(internal.ConvertSSLError(), TLS_ALIAS_UNAUTHORIZED);
        }
    }
}

HWTEST_F(TlsCertAliasSocketTest, RepeatedCloseAndDestructionDoNotCloseReusedFd, TestSize.Level1)
{
    SocketPair pair;
    ASSERT_TRUE(pair.Open());
    ASSERT_NO_FATAL_FAILURE(PrepareSocketSsl(pair.client));
    // Only failed-handshake cleanup transfers this FD out of TLSContext ownership.
    TLSConnectOptions options;
    options.SetTimeout(1);
    ASSERT_FALSE(pair.client->tlsSocketInternal_.StartTlsConnected(options));
    int fd = pair.client->GetSocketFd();
    pair.client->Close([](int32_t error) { EXPECT_EQ(error, TLSSOCKET_SUCCESS); });
    EXPECT_EQ(pair.client->tlsSocketInternal_.socketDescriptor_, -1);
    EXPECT_FALSE(pair.client->tlsSocketInternal_.Send("after close"));
    ASSERT_EQ(fcntl(fd, F_GETFD), -1);
    int replacement = dup(pair.peer);
    ASSERT_GE(replacement, 0);
    ASSERT_EQ(dup2(replacement, fd), fd);
    if (replacement != fd) {
        close(replacement);
    }
    pair.client->Close([](int32_t error) { EXPECT_EQ(error, TLSSOCKET_SUCCESS); });
    pair.client.reset();
    EXPECT_GE(fcntl(fd, F_GETFD), 0);
    close(fd);
}

HWTEST_F(TlsCertAliasSocketTest, FailedHandshakeDestructionReleasesFdWithoutExplicitClose, TestSize.Level1)
{
    SocketPair pair;
    ASSERT_TRUE(pair.Open());
    ASSERT_NO_FATAL_FAILURE(PrepareSocketSsl(pair.client));
    TLSConnectOptions options;
    options.SetTimeout(1);
    ASSERT_FALSE(pair.client->tlsSocketInternal_.StartTlsConnected(options));
    int fd = pair.client->GetSocketFd();
    pair.client.reset();
    EXPECT_EQ(fcntl(fd, F_GETFD), -1);
    EXPECT_EQ(errno, EBADF);
}

HWTEST_F(TlsCertAliasSocketTest, NormalCloseKeepsContextAndFdUntilDestruction, TestSize.Level1)
{
    SocketPair pair;
    ASSERT_TRUE(pair.Open());
    ASSERT_NO_FATAL_FAILURE(PrepareSocketSsl(pair.client));
    auto &internal = pair.client->tlsSocketInternal_;
    auto *context = internal.tlsContextPointer_.get();
    auto *ssl = internal.ssl_;
    int fd = pair.client->GetSocketFd();
    for (int count = 0; count < 2; ++count) {
        pair.client->Close([](int32_t error) { EXPECT_EQ(error, TLSSOCKET_SUCCESS); });
        EXPECT_EQ(pair.client->GetSocketFd(), -1);
        EXPECT_EQ(internal.tlsContextPointer_.get(), context);
        EXPECT_EQ(internal.ssl_, ssl);
        EXPECT_EQ(SSL_get_fd(ssl), fd);
        EXPECT_GE(fcntl(fd, F_GETFD), 0);
    }
    pair.client.reset();
    EXPECT_EQ(fcntl(fd, F_GETFD), -1);
    EXPECT_EQ(errno, EBADF);
}

HWTEST_F(TlsCertAliasSocketTest, BindingTransfersFdOwnershipToContext, TestSize.Level1)
{
    SocketPair pair;
    ASSERT_TRUE(pair.Open());
    auto &internal = pair.client->tlsSocketInternal_;
    int fd = pair.client->GetSocketFd();
    internal.RetainSocketFd(fd);
    EXPECT_EQ(internal.detachedSocketFd_, fd);
    internal.socketDescriptor_ = fd;
    ASSERT_TRUE(internal.CreatTlsContext());
    ASSERT_NE(internal.ssl_, nullptr);
    EXPECT_EQ(SSL_get_fd(internal.ssl_), fd);
    EXPECT_EQ(internal.detachedSocketFd_, -1);
    pair.client->Close([](int32_t error) { EXPECT_EQ(error, TLSSOCKET_SUCCESS); });
    EXPECT_GE(fcntl(fd, F_GETFD), 0);
    pair.client.reset();
    EXPECT_EQ(fcntl(fd, F_GETFD), -1);
    EXPECT_EQ(errno, EBADF);
}

HWTEST_F(TlsCertAliasSocketTest, ContextCleanupAndDestructionDoNotCloseReusedFd, TestSize.Level1)
{
    SocketPair pair;
    ASSERT_TRUE(pair.Open());
    ASSERT_NO_FATAL_FAILURE(PrepareSocketSsl(pair.client));
    auto &internal = pair.client->tlsSocketInternal_;
    int fd = pair.client->GetSocketFd();
    internal.CloseTlsContext();
    EXPECT_EQ(internal.ssl_, nullptr);
    EXPECT_EQ(internal.tlsContextPointer_, nullptr);
    EXPECT_EQ(internal.socketDescriptor_, -1);
    ASSERT_EQ(fcntl(fd, F_GETFD), -1);
    int replacement = dup(pair.peer);
    ASSERT_GE(replacement, 0);
    ASSERT_EQ(dup2(replacement, fd), fd);
    if (replacement != fd) {
        close(replacement);
    }
    int flags = fcntl(fd, F_GETFL);
    ASSERT_GE(flags, 0);
    ASSERT_EQ(fcntl(fd, F_SETFL, flags | O_NONBLOCK), 0);
    internal.CloseTlsContext();
    pair.client.reset();
    EXPECT_EQ(fcntl(fd, F_GETFL), flags | O_NONBLOCK);
    close(fd);
}

HWTEST_F(TlsCertAliasSocketTest, ConfigurationFailureReleasesUnboundFd, TestSize.Level1)
{
    for (bool explicitClose : {false, true}) {
        SCOPED_TRACE(explicitClose);
        SocketPair pair;
        ASSERT_TRUE(pair.Open());
        int fd = pair.client->GetSocketFd();
        TLSSecureOptions secure;
        secure.SetCertAlias("");
        TLSConnectOptions options;
        options.SetTlsSecureOptions(secure);
        int callbacks = 0;
        pair.client->Connect(options, [&callbacks](int32_t error) {
            ++callbacks;
            EXPECT_EQ(error, TLS_ALIAS_INVALID);
        });
        EXPECT_EQ(callbacks, 1);
        EXPECT_EQ(pair.client->tlsSocketInternal_.tlsContextPointer_, nullptr);
        EXPECT_GE(fcntl(fd, F_GETFD), 0);
        if (explicitClose) {
            pair.client->Close([](int32_t error) { EXPECT_EQ(error, TLSSOCKET_SUCCESS); });
            EXPECT_EQ(pair.client->tlsSocketInternal_.socketDescriptor_, -1);
            EXPECT_EQ(fcntl(fd, F_GETFD), -1);
            EXPECT_EQ(errno, EBADF);
        }
        pair.client.reset();
        EXPECT_EQ(fcntl(fd, F_GETFD), -1);
        EXPECT_EQ(errno, EBADF);
    }
}

#ifdef CERT_ALIAS_NATIVE_SOCKET_TEST
HWTEST_F(TlsCertAliasSocketTest, NativeConnectAfterCloseReturnsCancellation, TestSize.Level1)
{
    constexpr int expectedCallbacks = 3;
    SocketPair pair;
    ASSERT_TRUE(pair.Open());
    ASSERT_NO_FATAL_FAILURE(PrepareSocketSsl(pair.client));
    pair.client->Close([](int32_t error) { EXPECT_EQ(error, TLSSOCKET_SUCCESS); });
    TLSConnectOptions options;
    int callbacks = 0;
    for (int previousErrno : {0, EACCES, EBADF}) {
        errno = previousErrno;
        pair.client->Connect(options, [&callbacks](int32_t error) {
            ++callbacks;
            EXPECT_EQ(error, TLS_ERR_SYS_ECANCELED);
            EXPECT_EQ(MakeErrorMessage(error), "Operation canceled");
        });
    }
    EXPECT_EQ(callbacks, expectedCallbacks);
}

HWTEST_F(TlsCertAliasSocketTest, NativeConcurrentConnectKeepsOriginalAttemptAndDeferredFd, TestSize.Level1)
{
    constexpr int waitMilliseconds = 2000;
    SocketPair pair;
    ASSERT_TRUE(pair.Open());
    int fd = pair.client->GetSocketFd();
    TLSSecureOptions secure;
    secure.SetCertAlias("");
    TLSConnectOptions options;
    options.SetTlsSecureOptions(secure);
    std::promise<void> completed;
    std::promise<void> release;
    auto released = release.get_future();
    auto connecting = std::async(std::launch::async, [&pair, &options, &completed, &released]() {
        pair.client->Connect(options, [&completed, &released](int32_t error) {
            EXPECT_EQ(error, TLS_ALIAS_INVALID);
            completed.set_value();
            released.wait();
        });
    });
    auto status = completed.get_future().wait_for(std::chrono::milliseconds(waitMilliseconds));
    if (status == std::future_status::ready) {
        auto &internal = pair.client->tlsSocketInternal_;
        auto attempt = std::atomic_load(&internal.attemptState_);
        int callbacks = 0;
        pair.client->Connect(options, [&callbacks](int32_t error) {
            ++callbacks;
            EXPECT_EQ(error, TLS_ERR_SYS_EALREADY);
            EXPECT_EQ(MakeErrorMessage(error), "Operation already in progress");
        });
        EXPECT_EQ(callbacks, 1);
        EXPECT_EQ(std::atomic_load(&internal.attemptState_), attempt);
        pair.client->Close([](int32_t error) { EXPECT_EQ(error, TLSSOCKET_SUCCESS); });
        EXPECT_GE(fcntl(fd, F_GETFD), 0);
    }
    release.set_value();
    connecting.get();
    EXPECT_EQ(status, std::future_status::ready);
    EXPECT_EQ(fcntl(fd, F_GETFD), -1);
    EXPECT_EQ(errno, EBADF);
    EXPECT_EQ(pair.client->tlsSocketInternal_.socketDescriptor_, -1);
}

HWTEST_F(TlsCertAliasSocketTest, NativeCloseRequestRejectsConnectBeforeFdRelease, TestSize.Level1)
{
    constexpr int waitMilliseconds = 2000;
    SocketPair pair;
    ASSERT_TRUE(pair.Open());
    auto &internal = pair.client->tlsSocketInternal_;
    TLSSecureOptions secure;
    secure.SetCertAlias("");
    TLSConnectOptions options;
    options.SetTlsSecureOptions(secure);
    pair.client->Connect(options, [](int32_t error) { EXPECT_EQ(error, TLS_ALIAS_INVALID); });
    auto attempt = std::atomic_load(&internal.attemptState_);
    ASSERT_NE(attempt, nullptr);
    int fd = pair.client->GetSocketFd();
    std::unique_lock<std::mutex> lock(pair.client->cvMutex_);
    auto closing = std::async(std::launch::async, [&pair]() {
        pair.client->Close([](int32_t error) { EXPECT_EQ(error, TLSSOCKET_SUCCESS); });
    });
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(waitMilliseconds);
    while (!attempt->IsCancelled() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    EXPECT_TRUE(attempt->IsCancelled());
    EXPECT_GE(fcntl(fd, F_GETFD), 0);
    int callbacks = 0;
    pair.client->Connect(options, [&callbacks](int32_t error) {
        ++callbacks;
        EXPECT_EQ(error, TLS_ERR_SYS_ECANCELED);
    });
    EXPECT_EQ(callbacks, 1);
    EXPECT_EQ(std::atomic_load(&internal.attemptState_), attempt);
    lock.unlock();
    closing.get();
    EXPECT_EQ(fcntl(fd, F_GETFD), -1);
    EXPECT_EQ(errno, EBADF);
}

HWTEST_F(TlsCertAliasSocketTest, CloseDefersFdUntilConnectFinishes, TestSize.Level1)
{
    constexpr int waitMilliseconds = 2000;
    SocketPair pair;
    ASSERT_TRUE(pair.Open());
    ASSERT_NO_FATAL_FAILURE(PrepareSocketSsl(pair.client));
    auto &internal = pair.client->tlsSocketInternal_;
    pair.client->connecting_ = true;
    int fd = pair.client->GetSocketFd();
    std::unique_lock<std::shared_mutex> lock(internal.mutexForSsl_);
    auto closing = std::async(std::launch::async, [&pair]() {
        pair.client->Close([](int32_t error) { EXPECT_EQ(error, TLSSOCKET_SUCCESS); });
    });
    auto status = closing.wait_for(std::chrono::milliseconds(waitMilliseconds));
    lock.unlock();
    closing.get();
    EXPECT_EQ(status, std::future_status::ready);
    EXPECT_EQ(pair.client->GetSocketFd(), -1);
    EXPECT_GE(fcntl(fd, F_GETFD), 0);
    EXPECT_EQ(internal.socketDescriptor_, fd);
    EXPECT_NE(internal.ssl_, nullptr);
    if (internal.ssl_) {
        EXPECT_EQ(SSL_get_fd(internal.ssl_), fd);
    }
    pair.client->Close([](int32_t error) { EXPECT_EQ(error, TLSSOCKET_SUCCESS); });
    EXPECT_GE(fcntl(fd, F_GETFD), 0);
    pair.client->FinishConnect();
    EXPECT_FALSE(pair.client->connecting_);
    EXPECT_EQ(internal.ssl_, nullptr);
    EXPECT_EQ(internal.tlsContextPointer_, nullptr);
    EXPECT_EQ(internal.socketDescriptor_, -1);
    EXPECT_EQ(fcntl(fd, F_GETFD), -1);
    EXPECT_EQ(errno, EBADF);
    int replacement = dup(pair.peer);
    ASSERT_GE(replacement, 0);
    ASSERT_EQ(dup2(replacement, fd), fd);
    if (replacement != fd) {
        close(replacement);
    }
    pair.client->FinishConnect();
    pair.client.reset();
    EXPECT_GE(fcntl(fd, F_GETFD), 0);
    close(fd);
}

HWTEST_F(TlsCertAliasSocketTest, ConnectGuardReleasesDeferredFdOnConfigurationFailure, TestSize.Level1)
{
    SocketPair pair;
    ASSERT_TRUE(pair.Open());
    auto &internal = pair.client->tlsSocketInternal_;
    int fd = pair.client->GetSocketFd();
    TLSSecureOptions secure;
    secure.SetCertAlias("");
    TLSConnectOptions options;
    options.SetTlsSecureOptions(secure);
    pair.client->Connect(options, [&pair, fd](int32_t error) {
        EXPECT_EQ(error, TLS_ALIAS_INVALID);
        pair.client->Close([](int32_t closeError) { EXPECT_EQ(closeError, TLSSOCKET_SUCCESS); });
        EXPECT_GE(fcntl(fd, F_GETFD), 0);
        EXPECT_TRUE(pair.client->connecting_);
    });
    EXPECT_FALSE(pair.client->connecting_);
    EXPECT_EQ(internal.ConvertSSLError(), TLS_ALIAS_INVALID);
    EXPECT_EQ(internal.socketDescriptor_, -1);
    EXPECT_EQ(fcntl(fd, F_GETFD), -1);
    EXPECT_EQ(errno, EBADF);
    int replacement = dup(pair.peer);
    ASSERT_GE(replacement, 0);
    ASSERT_EQ(dup2(replacement, fd), fd);
    if (replacement != fd) {
        close(replacement);
    }
    pair.client.reset();
    EXPECT_GE(fcntl(fd, F_GETFD), 0);
    close(fd);
}

HWTEST_F(TlsCertAliasSocketTest, PendingConnectCleanupDoesNotWaitForSslMutex, TestSize.Level1)
{
    constexpr int waitMilliseconds = 2000;
    SocketPair pair;
    ASSERT_TRUE(pair.Open());
    ASSERT_NO_FATAL_FAILURE(PrepareSocketSsl(pair.client));
    auto &internal = pair.client->tlsSocketInternal_;
    pair.client->connecting_ = true;
    std::unique_lock<std::shared_mutex> lock(internal.mutexForSsl_);
    auto cleanup = std::async(std::launch::async, [&pair]() {
        pair.client->Close([](int32_t error) { EXPECT_EQ(error, TLSSOCKET_SUCCESS); });
    });
    auto status = cleanup.wait_for(std::chrono::milliseconds(waitMilliseconds));
    lock.unlock();
    cleanup.get();
    EXPECT_EQ(status, std::future_status::ready);
    EXPECT_NE(internal.tlsContextPointer_, nullptr);
    EXPECT_NE(internal.ssl_, nullptr);
    pair.client->FinishConnect();
    EXPECT_EQ(internal.tlsContextPointer_, nullptr);
    EXPECT_EQ(internal.ssl_, nullptr);
}

int RunHandshakeUntilCleanup(TLSSocket &socket, std::promise<void> &locked,
    std::promise<void> &stopped, std::future<void> &finish)
{
    auto &internal = socket.tlsSocketInternal_;
    int result;
    {
        std::unique_lock<std::shared_mutex> lock(internal.mutexForSsl_);
        locked.set_value();
        result = SSL_connect(internal.ssl_);
    }
    stopped.set_value();
    finish.wait();
    socket.FinishConnect();
    return result;
}

HWTEST_F(TlsCertAliasSocketTest, CloseWakesBlockedHandshakeBeforeContextCleanup, TestSize.Level1)
{
    constexpr int waitMilliseconds = 2000;
    SocketPair pair;
    ASSERT_TRUE(pair.Open());
    ASSERT_NO_FATAL_FAILURE(PrepareSocketSsl(pair.client));
    auto &internal = pair.client->tlsSocketInternal_;
    pair.client->connecting_ = true;
    std::promise<void> locked;
    std::promise<void> stopped;
    std::promise<void> finish;
    auto finishSignal = finish.get_future();
    auto handshake = std::async(std::launch::async, [&pair, &locked, &stopped, &finishSignal]() {
        return RunHandshakeUntilCleanup(*pair.client, locked, stopped, finishSignal);
    });
    locked.get_future().wait();
    pollfd peer{pair.peer, POLLIN, 0};
    EXPECT_EQ(poll(&peer, 1, waitMilliseconds), 1);
    int fd = pair.client->GetSocketFd();
    auto closing = std::async(std::launch::async, [&pair]() {
        pair.client->Close([](int32_t error) { EXPECT_EQ(error, TLSSOCKET_SUCCESS); });
    });
    auto status = closing.wait_for(std::chrono::milliseconds(waitMilliseconds));
    auto handshakeStatus = stopped.get_future().wait_for(std::chrono::milliseconds(waitMilliseconds));
    if (status != std::future_status::ready || handshakeStatus != std::future_status::ready) {
        // Unblock a regressed implementation so failure cannot hang the test process.
        close(pair.peer);
        pair.peer = -1;
    }
    closing.get();
    EXPECT_GE(fcntl(fd, F_GETFD), 0);
    EXPECT_EQ(internal.socketDescriptor_, fd);
    finish.set_value();
    EXPECT_LE(handshake.get(), 0);
    EXPECT_EQ(status, std::future_status::ready);
    EXPECT_EQ(handshakeStatus, std::future_status::ready);
    EXPECT_EQ(fcntl(fd, F_GETFD), -1);
    EXPECT_EQ(internal.socketDescriptor_, -1);
    EXPECT_EQ(internal.tlsContextPointer_, nullptr);
    EXPECT_EQ(internal.ssl_, nullptr);
}

#endif

void BlockSigpipeForTestThread()
{
    // These dedicated async threads model Ark's blocked SIGPIPE during SSL writes.
    sigset_t signals;
    ASSERT_EQ(sigemptyset(&signals), 0);
    ASSERT_EQ(sigaddset(&signals, SIGPIPE), 0);
    ASSERT_EQ(pthread_sigmask(SIG_BLOCK, &signals, nullptr), 0);
}

void ExpectReusedFdSurvivesClose(SocketPair &pair, int fd)
{
    ASSERT_EQ(fcntl(fd, F_GETFD), -1);
    ASSERT_EQ(errno, EBADF);
    int replacement = dup(pair.peer);
    ASSERT_GE(replacement, 0);
    ASSERT_EQ(dup2(replacement, fd), fd);
    if (replacement != fd) {
        close(replacement);
    }
    int flags = fcntl(fd, F_GETFL);
    ASSERT_GE(flags, 0);
    ASSERT_EQ(fcntl(fd, F_SETFL, flags | O_NONBLOCK), 0);
    pair.client->Close([](int32_t error) { EXPECT_EQ(error, TLSSOCKET_SUCCESS); });
    pair.client.reset();
    EXPECT_EQ(fcntl(fd, F_GETFL), flags | O_NONBLOCK);
    close(fd);
}

void ExpectFinishedConnectCleanup(SocketPair &pair, int fd)
{
    EXPECT_EQ(pair.client->tlsSocketInternal_.socketDescriptor_, -1);
    EXPECT_EQ(pair.client->tlsSocketInternal_.tlsContextPointer_, nullptr);
    if (pair.peer >= 0) {
        ExpectReusedFdSurvivesClose(pair, fd);
    }
}

#ifndef CERT_ALIAS_NATIVE_SOCKET_TEST
HWTEST_F(TlsCertAliasSocketTest, NapiConnectAfterCloseReturnsCancellation, TestSize.Level1)
{
    constexpr int expectedCallbacks = 3;
    SocketPair pair;
    ASSERT_TRUE(pair.Open());
    ASSERT_NO_FATAL_FAILURE(PrepareSocketSsl(pair.client));
    pair.client->Close([](int32_t error) { EXPECT_EQ(error, TLSSOCKET_SUCCESS); });
    int errorEvents = 0;
    pair.client->OnError([&errorEvents](int32_t error, const std::string &message) {
        ++errorEvents;
        EXPECT_EQ(error, TLS_ERR_SYS_ECANCELED);
        EXPECT_EQ(message, "Operation canceled");
    });
    TLSConnectOptions options;
    int callbacks = 0;
    for (int previousErrno : {0, EACCES, EBADF}) {
        errno = previousErrno;
        pair.client->Connect(options, [&callbacks](int32_t error) {
            ++callbacks;
            EXPECT_EQ(error, TLS_ERR_SYS_ECANCELED);
            errno = EACCES;
            EXPECT_EQ(MakeErrorMessage(error), "Operation canceled");
        }, [](int) {
            ADD_FAILURE() << "A closed socket must not start transport preparation";
            return TLSSOCKET_SUCCESS;
        });
    }
    EXPECT_EQ(callbacks, expectedCallbacks);
    EXPECT_EQ(errorEvents, callbacks);
    EXPECT_FALSE(pair.client->connecting_);
}

HWTEST_F(TlsCertAliasSocketTest, NapiCloseDefersFdAcrossTransportPreparation, TestSize.Level1)
{
    for (int32_t prepareError : {static_cast<int32_t>(TLSSOCKET_SUCCESS), TLS_ALIAS_SERVICE_ERROR}) {
        SocketPair pair;
        ASSERT_TRUE(pair.Open());
        int fd = pair.client->GetSocketFd();
        TLSConnectOptions options;
        std::promise<void> entered;
        std::promise<void> release;
        auto released = release.get_future();
        int32_t result = TLSSOCKET_SUCCESS;
        auto connecting = std::async(std::launch::async,
            [&pair, &options, &result, &entered, &released, fd, prepareError]() {
                pair.client->Connect(options, [&result](int32_t error) { result = error; },
                    [&entered, &released, fd, prepareError](int socketFd) {
                        EXPECT_EQ(socketFd, fd);
                        entered.set_value();
                        released.wait();
                        EXPECT_GE(fcntl(socketFd, F_GETFD), 0);
                        return prepareError;
                    });
            });
        entered.get_future().wait();
        auto attempt = std::atomic_load(&pair.client->tlsSocketInternal_.attemptState_);
        pair.client->Connect(options, [](int32_t error) {
            EXPECT_EQ(error, TLS_ERR_SYS_EALREADY);
            errno = EACCES;
            EXPECT_EQ(MakeErrorMessage(error), "Operation already in progress");
        });
        EXPECT_EQ(std::atomic_load(&pair.client->tlsSocketInternal_.attemptState_), attempt);
        pair.client->Close([](int32_t error) { EXPECT_EQ(error, TLSSOCKET_SUCCESS); });
        pair.client->Close([](int32_t error) { EXPECT_EQ(error, TLSSOCKET_SUCCESS); });
        EXPECT_TRUE(attempt->IsCancelled());
        EXPECT_EQ(pair.client->GetSocketFd(), -1);
        EXPECT_GE(fcntl(fd, F_GETFD), 0);
        release.set_value();
        connecting.get();
        EXPECT_EQ(result, prepareError == TLSSOCKET_SUCCESS ? TLS_ERR_SYS_BASE + ECANCELED : prepareError);
        if (prepareError == TLSSOCKET_SUCCESS) {
            errno = EACCES;
            EXPECT_EQ(MakeErrorMessage(result), "Operation canceled");
        }
        EXPECT_FALSE(pair.client->connecting_);
        ExpectReusedFdSurvivesClose(pair, fd);
    }
}

#endif

HWTEST_F(TlsCertAliasSocketTest, CloseDefersFdUntilHandshakeAndCallbackReturn, TestSize.Level1)
{
    constexpr int waitMilliseconds = 2000;
    for (uint32_t timeout : {0U, 5000U}) {
        SCOPED_TRACE(timeout);
        SocketPair pair;
        ASSERT_TRUE(pair.Open());
        ASSERT_NO_FATAL_FAILURE(PrepareSocketSsl(pair.client));
        int fd = pair.client->GetSocketFd();
        TLSConnectOptions options;
        options.SetTimeout(timeout);
        std::promise<void> completed;
        std::promise<void> release;
        auto released = release.get_future();
        int32_t result = TLSSOCKET_SUCCESS;
        auto connecting = std::async(std::launch::async, [&pair, &options, &result, &completed, &released]() {
            BlockSigpipeForTestThread();
            pair.client->Connect(options, [&result, &completed, &released](int32_t error) {
                result = error;
                completed.set_value();
                released.wait();
            });
        });
        pollfd peer{pair.peer, POLLIN, 0};
        EXPECT_EQ(poll(&peer, 1, waitMilliseconds), 1);
        auto closing = std::async(std::launch::async, [&pair]() {
            pair.client->Close([](int32_t error) { EXPECT_EQ(error, TLSSOCKET_SUCCESS); });
        });
        auto closeStatus = closing.wait_for(std::chrono::milliseconds(waitMilliseconds));
        auto connectStatus = completed.get_future().wait_for(std::chrono::milliseconds(waitMilliseconds));
        if (closeStatus != std::future_status::ready || connectStatus != std::future_status::ready) {
            close(pair.peer);
            pair.peer = -1;
        }
        closing.get();
        EXPECT_EQ(closeStatus, std::future_status::ready);
        EXPECT_EQ(connectStatus, std::future_status::ready);
        EXPECT_GE(fcntl(fd, F_GETFD), 0);
        if (timeout > 0 && connectStatus == std::future_status::ready) {
            // The failure path restored flags while it still owned the original FD.
            EXPECT_EQ(fcntl(fd, F_GETFL) & O_NONBLOCK, 0);
        }
        release.set_value();
        connecting.get();
        EXPECT_NE(result, TLSSOCKET_SUCCESS);
        ExpectFinishedConnectCleanup(pair, fd);
    }
}

HWTEST_F(TlsCertAliasSocketTest, ConfigurationPreservesCancelledAttemptForPemAndAlias, TestSize.Level1)
{
    for (bool alias : {false, true}) {
        TLSSocket socket;
        auto &internal = socket.tlsSocketInternal_;
        auto attempt = internal.BeginConnectAttempt();
        internal.CancelConnectAttempt();
        TLSSecureOptions secure;
        if (alias) {
            secure.SetCertAlias("client");
        }
        TLSConnectOptions options;
        options.SetTlsSecureOptions(secure);
        EXPECT_FALSE(internal.SetTlsConfiguration(options, attempt));
        EXPECT_EQ(std::atomic_load(&internal.attemptState_), attempt);
        EXPECT_TRUE(attempt->IsCancelled());
    }
}

#ifndef CERT_ALIAS_NATIVE_SOCKET_TEST
HWTEST_F(TlsCertAliasSocketTest, NapiConfigurationFailureReleasesPublicConnectGuard, TestSize.Level1)
{
    SocketPair pair;
    ASSERT_TRUE(pair.Open());
    TLSSecureOptions secure;
    secure.SetCertAlias("");
    TLSConnectOptions options;
    options.SetTlsSecureOptions(secure);
    int fd = pair.client->GetSocketFd();
    pair.client->Connect(options, [&pair, fd](int32_t error) {
        EXPECT_EQ(error, TLS_ALIAS_INVALID);
        pair.client->Close([](int32_t closeError) { EXPECT_EQ(closeError, TLSSOCKET_SUCCESS); });
        EXPECT_GE(fcntl(fd, F_GETFD), 0);
    });
    EXPECT_FALSE(pair.client->connecting_);
    EXPECT_EQ(pair.client->tlsSocketInternal_.ConvertSSLError(), TLS_ALIAS_INVALID);
    ExpectReusedFdSurvivesClose(pair, fd);
}

HWTEST_F(TlsCertAliasSocketTest, ProxyPreservesCertAliasErrorsWithoutSocketOffset, TestSize.Level1)
{
    TLSConnectContext context(nullptr, nullptr);
    context.proxyOptions_ = std::make_shared<Socket::ProxyOptions>();
    for (int32_t error : {TLS_ALIAS_PERMISSION, TLS_ALIAS_INVALID, TLS_ALIAS_UNSUPPORTED,
        TLS_ALIAS_NOT_FOUND, TLS_ALIAS_SERVICE_ERROR, TLS_ALIAS_UNAUTHORIZED}) {
        context.SetErrorCode(error);
        EXPECT_EQ(context.GetErrorCode(), error);
    }
}

HWTEST_F(TlsCertAliasSocketTest, NonAliasProxyErrorsKeepExistingSocketOffset, TestSize.Level1)
{
    TLSConnectContext context(nullptr, nullptr);
    context.SetErrorCode(EINVAL);
    EXPECT_EQ(context.GetErrorCode(), EINVAL);
    context.proxyOptions_ = std::make_shared<Socket::ProxyOptions>();
    EXPECT_EQ(context.GetErrorCode(), EINVAL + Socket::SOCKET_ERROR_CODE_BASE);
}

#endif

HWTEST_F(TlsCertAliasSocketTest, ServerRejectsAnyPresentAliasBeforeNetworkSetup, TestSize.Level1)
{
    for (const std::string &alias : {std::string("valid"), std::string{}}) {
        OHOS::NetStack::TlsSocketServer::TLSSocketServer server;
        TLSSecureOptions secure;
        secure.SetCertAlias(alias);
        TLSConnectOptions options;
        options.SetTlsSecureOptions(secure);
        int calls = 0;
        server.Listen(options, [&calls](int32_t error) {
            ++calls;
            EXPECT_EQ(error, TLS_ALIAS_INVALID);
        });
        EXPECT_EQ(calls, 1);
    }
}
} // namespace
} // namespace OHOS::NetStack::TlsSocket
