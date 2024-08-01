/*
* Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <gmock/gmock.h>
#include <openssl/ssl.h>

#ifdef GTEST_API_
#define private public
#endif

#include "tls_socket_server.h"

namespace OHOS {
namespace NetStack {
namespace TlsSocketServer {
class MockSSL {
    MOCK_METHOD(int, SSL_shutdown, (SSL*));
    MOCK_METHOD(void, SSL_free, (SSL*));
    MOCK_METHOD(void, SSL_CTX_free, (SSL_CTX*));
};


class TlsSocketServerMockBranchTest : public testing::Test {
protected:
    TLSSocketServer::Connection *connection;
    void SetUp() override {
        connection = new TLSSocketServer::Connection();
    }

    void TearDown() override {
        delete connection;
    }
};

HWTEST_F(TlsSocketServerMockBranchTest, TestClose001, testing::ext::TestSize.Level2)
{
    MockSSL mockSsl;
    connection->ssl_ = nullptr;
    EXPECT_FALSE(connection->Close());
}

HWTEST_F(TlsSocketServerMockBranchTest, TestClose002, testing::ext::TestSize.Level2)
{
    MockSSL mockSsl;
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
    SSL *ssl = SSL_new(ctx);
    connection->ssl_ = (SSL *)ssl;
    EXPECT_FALSE(connection->Close());
}

HWTEST_F(TlsSocketServerMockBranchTest, TestClose004, testing::ext::TestSize.Level2)
{
    MockSSL mockSsl;
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
    SSL *ssl = SSL_new(ctx);
    connection->ssl_ = (SSL *)ssl;
    connection->socketFd_ = socket(AF_INET, SOCK_STREAM, 0);
    EXPECT_FALSE(connection->Close());
}

HWTEST_F(TlsSocketServerMockBranchTest, TestClose005, testing::ext::TestSize.Level2)
{
    MockSSL mockSsl;
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
    SSL *ssl = SSL_new(ctx);
    connection->ssl_ = (SSL *)ssl;
    connection->tlsContextServerPointer_ = nullptr;
    EXPECT_FALSE(connection->Close());
}

HWTEST_F(TlsSocketServerMockBranchTest, TestClose006, testing::ext::TestSize.Level2)
{
    MockSSL mockSsl;
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
    SSL *ssl = SSL_new(ctx);
    connection->ssl_ = (SSL *)ssl;
    TlsSocket::TLSConfiguration connectionConfiguration_;
    connection->tlsContextServerPointer_ = TlsSocket::TLSContextServer::CreateConfiguration(connectionConfiguration_);
    EXPECT_FALSE(connection->Close());
}


HWTEST_F(TlsSocketServerMockBranchTest, TlsSocketServerBranchTest020, testing::ext::TestSize.Level2)
{
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
    SSL *ssl = SSL_new(ctx);
    connection->ssl_ = (SSL *)ssl;
    connection->connectionConfiguration_.protocol_ = TlsSocket::TLS_V1_2;
    EXPECT_EQ(connection->GetProtocol(), TlsSocket::PROTOCOL_TLS_V12);
    connection->connectionConfiguration_.protocol_ = TlsSocket::TLS_V1_3;
    EXPECT_EQ(connection->GetProtocol(), TlsSocket::PROTOCOL_TLS_V13);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
}
} // namespace TlsSocketServer
} // namespace NetStack
} // namespace OHOS
