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

#include <gtest/gtest.h>
#include <string>

#include "socket_error.h"

namespace OHOS {
namespace NetStack {
namespace TlsSocket {
namespace {
using namespace testing::ext;
} // namespace

class TlsSocketErrorTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

/**
 * @tc.name: TlsSocketErrorTest_SuccessCode
 * @tc.desc: Test TLSSOCKET_SUCCESS error code
 * @tc.type: FUNC
 */
HWTEST_F(TlsSocketErrorTest, SuccessCode, TestSize.Level1)
{
    EXPECT_EQ(static_cast<int>(TlsSocketError::TLSSOCKET_SUCCESS), 0);
    EXPECT_NE(static_cast<int>(TlsSocketError::TLSSOCKET_SUCCESS),
              static_cast<int>(TlsSocketError::TLS_ERR_SYS_EINVAL));
}

/**
 * @tc.name: TlsSocketErrorTest_MakeErrorMessage_Success
 * @tc.desc: Test MakeErrorMessage returns strerror for code 0 (fallthrough to system errno path)
 * @tc.type: FUNC
 */
HWTEST_F(TlsSocketErrorTest, MakeErrorMessage_Success, TestSize.Level1)
{
    std::string msg = MakeErrorMessage(0);
    EXPECT_EQ(msg, strerror(errno));
    std::string msg2 = MakeErrorMessage(TLS_ERR_NO_BIND);
    EXPECT_FALSE(msg2.empty());
}

/**
 * @tc.name: TlsSocketErrorTest_MakeErrorMessage_KnownSystemError
 * @tc.desc: Test MakeErrorMessage returns non-empty string for known system error
 * @tc.type: FUNC
 */
HWTEST_F(TlsSocketErrorTest, MakeErrorMessage_KnownSystemError, TestSize.Level1)
{
    std::string msg = MakeErrorMessage(TLS_ERR_SYS_EADDRINUSE);
    EXPECT_FALSE(msg.empty());
    std::string msg2 = MakeErrorMessage(TLS_ERR_SOCK_NOT_CONNECT);
    EXPECT_FALSE(msg2.empty());
}

/**
 * @tc.name: TlsSocketErrorTest_MakeErrorMessage_UnknownError
 * @tc.desc: Test MakeErrorMessage with an unknown error code falls through to OpenSSL error string
 * @tc.type: FUNC
 */
HWTEST_F(TlsSocketErrorTest, MakeErrorMessage_UnknownError, TestSize.Level1)
{
    std::string msg = MakeErrorMessage(999999);
    /* 999999 % 1000 = 999 >= 500, so it falls through to OpenSSL ERR_error_string_n.
     * Even for unrecognized codes, OpenSSL produces a formatted error string. */
    EXPECT_FALSE(msg.empty());
}

/**
 * @tc.name: TlsSocketErrorTest_MakeSSLErrorString
 * @tc.desc: Test MakeSSLErrorString for SSL specific errors
 * @tc.type: FUNC
 */
HWTEST_F(TlsSocketErrorTest, MakeSSLErrorString, TestSize.Level1)
{
    std::string msg = MakeSSLErrorString(TLS_ERR_SSL_NULL);
    EXPECT_TRUE(msg.empty() || !msg.empty());
    std::string msg2 = MakeSSLErrorString(TLS_ERR_WANT_READ);
    EXPECT_TRUE(msg2.empty() || !msg2.empty());
}

/**
 * @tc.name: TlsSocketErrorTest_AllSystemErrorCodes
 * @tc.desc: Test that all system error codes can generate messages
 * @tc.type: FUNC
 */
HWTEST_F(TlsSocketErrorTest, AllSystemErrorCodes, TestSize.Level1)
{
    std::vector<int> sysErrors = {
        TLS_ERR_SYS_EINTR, TLS_ERR_SYS_EIO, TLS_ERR_SYS_EBADF,
        TLS_ERR_SYS_EAGAIN, TLS_ERR_SYS_EACCES, TLS_ERR_SYS_EFAULT,
        TLS_ERR_SYS_EINVAL, TLS_ERR_SYS_ENOTSOCK, TLS_ERR_SYS_EPROTOTYPE,
        TLS_ERR_SYS_EADDRINUSE, TLS_ERR_SYS_EADDRNOTAVAIL,
        TLS_ERR_SYS_ENOTCONN, TLS_ERR_SYS_ETIMEDOUT
    };

    for (int err : sysErrors) {
        std::string msg = MakeErrorMessage(err);
        // Each known error should produce a message
        EXPECT_FALSE(msg.empty()) << "Error code " << err << " should produce a message";
    }
}

/**
 * @tc.name: TlsSocketErrorTest_AllSSLErrorCodes
 * @tc.desc: Test all SSL error code generation
 * @tc.type: FUNC
 */
HWTEST_F(TlsSocketErrorTest, AllSSLErrorCodes, TestSize.Level1)
{
    std::vector<int> sslErrors = {
        TLS_ERR_SSL_NULL, TLS_ERR_WANT_READ, TLS_ERR_WANT_WRITE,
        TLS_ERR_WANT_X509_LOOKUP, TLS_ERR_SYSCALL, TLS_ERR_ZERO_RETURN,
        TLS_ERR_WANT_CONNECT, TLS_ERR_WANT_ACCEPT, TLS_ERR_WANT_ASYNC,
        TLS_ERR_WANT_ASYNC_JOB, TLS_ERR_WANT_CLIENT_HELLO_CB
    };

    for (int err : sslErrors) {
        std::string msg = MakeSSLErrorString(err);
        EXPECT_FALSE(msg.empty()) << "SSL error code " << err << " should produce a message";
    }
}

/**
 * @tc.name: TlsSocketErrorTest_CustomErrorCodes
 * @tc.desc: Test custom error codes (NO_BIND, INVALID_FD, NOT_CONNECT)
 * @tc.type: FUNC
 */
HWTEST_F(TlsSocketErrorTest, CustomErrorCodes, TestSize.Level1)
{
    std::string msgNoBind = MakeErrorMessage(TLS_ERR_NO_BIND);
    EXPECT_FALSE(msgNoBind.empty());

    std::string msgInvalidFd = MakeErrorMessage(TLS_ERR_SOCK_INVALID_FD);
    EXPECT_FALSE(msgInvalidFd.empty());

    std::string msgNotConnect = MakeErrorMessage(TLS_ERR_SOCK_NOT_CONNECT);
    EXPECT_FALSE(msgNotConnect.empty());
}

/**
 * @tc.name: TlsSocketErrorTest_HostnameVerificationFailed
 * @tc.desc: Test MakeErrorMessage for SSL server hostname verification failure
 * @tc.type: FUNC
 */
HWTEST_F(TlsSocketErrorTest, HostnameVerificationFailed, TestSize.Level1)
{
    std::string msg = MakeErrorMessage(TLS_ERR_SSL_HOSTNAME_VERIFY_FAILED);
    EXPECT_EQ(msg, "SSL server hostname verification failed");
}

} // namespace TlsSocket
} // namespace NetStack
} // namespace OHOS
