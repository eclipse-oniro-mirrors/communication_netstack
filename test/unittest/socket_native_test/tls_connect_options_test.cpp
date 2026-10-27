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
#include <vector>

#include "tls_socket_client_innerapi.h"
#include "net_address.h"
#include "socket_native_test_utils.h"

namespace OHOS {
namespace NetStack {
namespace TlsSocket {
namespace {
using namespace testing::ext;
} // namespace

class TlsConnectOptionsTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

/**
 * @tc.name: TlsConnectOptionsTest_NetAddress
 * @tc.desc: Test SetNetAddress and GetNetAddress
 * @tc.type: FUNC
 */
HWTEST_F(TlsConnectOptionsTest, NetAddress, TestSize.Level1)
{
    TLSConnectOptions options;
    Socket::NetAddress address;
    address.SetAddress("127.0.0.1");
    address.SetPort(443);
    options.SetNetAddress(address);

    Socket::NetAddress retrieved = options.GetNetAddress();
    EXPECT_EQ(retrieved.GetAddress(), "127.0.0.1");
    EXPECT_EQ(retrieved.GetPort(), 443U);
}

/**
 * @tc.name: TlsConnectOptionsTest_NetAddressIPv6
 * @tc.desc: Test NetAddress with IPv6
 * @tc.type: FUNC
 */
HWTEST_F(TlsConnectOptionsTest, NetAddressIPv6, TestSize.Level1)
{
    TLSConnectOptions options;
    Socket::NetAddress address;
    /* Must set family BEFORE SetAddress, because SetAddress checks family_
     * to decide whether to use inet_pton(AF_INET) or inet_pton(AF_INET6). */
    address.SetFamilyBySaFamily(AF_INET6);
    address.SetAddress("::1");
    address.SetPort(8080);
    options.SetNetAddress(address);

    Socket::NetAddress retrieved = options.GetNetAddress();
    EXPECT_EQ(retrieved.GetAddress(), "::1");
    EXPECT_EQ(retrieved.GetPort(), 8080U);
}

/**
 * @tc.name: TlsConnectOptionsTest_TlsSecureOptions
 * @tc.desc: Test SetTlsSecureOptions and GetTlsSecureOptions
 * @tc.type: FUNC
 */
HWTEST_F(TlsConnectOptionsTest, TlsSecureOptions, TestSize.Level1)
{
    TLSConnectOptions options;
    TLSSecureOptions secureOpts;
    std::vector<std::string> caChain = {CA_CERT_PEM};
    secureOpts.SetCaChain(caChain);
    secureOpts.SetCipherSuite("AES256-SHA256");
    options.SetTlsSecureOptions(secureOpts);

    TLSSecureOptions retrieved = options.GetTlsSecureOptions();
    EXPECT_EQ(retrieved.GetCaChain().size(), 1U);
    EXPECT_EQ(retrieved.GetCipherSuite(), "AES256-SHA256");
}

/**
 * @tc.name: TlsConnectOptionsTest_AlpnProtocols
 * @tc.desc: Test SetAlpnProtocols and GetAlpnProtocols
 * @tc.type: FUNC
 */
HWTEST_F(TlsConnectOptionsTest, AlpnProtocols, TestSize.Level1)
{
    TLSConnectOptions options;
    std::vector<std::string> alpnProtocols;
    alpnProtocols.push_back("http/1.1");
    alpnProtocols.push_back("h2");
    options.SetAlpnProtocols(alpnProtocols);

    const std::vector<std::string> &retrieved = options.GetAlpnProtocols();
    EXPECT_EQ(retrieved.size(), 2U);
    EXPECT_EQ(retrieved[0], "http/1.1");
    EXPECT_EQ(retrieved[1], "h2");
}

/**
 * @tc.name: TlsConnectOptionsTest_AlpnEmptyProtocols
 * @tc.desc: Test AlpnProtocols with empty vector
 * @tc.type: FUNC
 */
HWTEST_F(TlsConnectOptionsTest, AlpnEmptyProtocols, TestSize.Level1)
{
    TLSConnectOptions options;
    std::vector<std::string> emptyProtocols;
    options.SetAlpnProtocols(emptyProtocols);

    const std::vector<std::string> &retrieved = options.GetAlpnProtocols();
    EXPECT_TRUE(retrieved.empty());
}

/**
 * @tc.name: TlsConnectOptionsTest_SkipRemoteValidation
 * @tc.desc: Test SetSkipRemoteValidation and GetSkipRemoteValidation
 * @tc.type: FUNC
 */
HWTEST_F(TlsConnectOptionsTest, SkipRemoteValidation, TestSize.Level1)
{
    TLSConnectOptions options;

    // Default should be false
    EXPECT_FALSE(options.GetSkipRemoteValidation());

    options.SetSkipRemoteValidation(true);
    EXPECT_TRUE(options.GetSkipRemoteValidation());

    options.SetSkipRemoteValidation(false);
    EXPECT_FALSE(options.GetSkipRemoteValidation());
}

/**
 * @tc.name: TlsConnectOptionsTest_SslServerHostnameVerification
 * @tc.desc: Test SetSslServerHostnameVerification and GetSslServerHostnameVerification
 * @tc.type: FUNC
 */
HWTEST_F(TlsConnectOptionsTest, SslServerHostnameVerification, TestSize.Level1)
{
    TLSConnectOptions options;

    // Default should be false
    EXPECT_FALSE(options.GetSslServerHostnameVerification());

    options.SetSslServerHostnameVerification(true);
    EXPECT_TRUE(options.GetSslServerHostnameVerification());

    options.SetSslServerHostnameVerification(false);
    EXPECT_FALSE(options.GetSslServerHostnameVerification());
}

/**
 * @tc.name: TlsConnectOptionsTest_Timeout
 * @tc.desc: Test SetTimeout and GetTimeout
 * @tc.type: FUNC
 */
HWTEST_F(TlsConnectOptionsTest, Timeout, TestSize.Level1)
{
    TLSConnectOptions options;

    // Default should be 0
    EXPECT_EQ(options.GetTimeout(), 0U);

    options.SetTimeout(5000);
    EXPECT_EQ(options.GetTimeout(), 5000U);

    options.SetTimeout(30000);
    EXPECT_EQ(options.GetTimeout(), 30000U);
}

/**
 * @tc.name: TlsConnectOptionsTest_HostName
 * @tc.desc: Test SetHostName and GetHostName
 * @tc.type: FUNC
 */
HWTEST_F(TlsConnectOptionsTest, HostName, TestSize.Level1)
{
    TLSConnectOptions options;

    options.SetHostName("example.com");
    EXPECT_EQ(options.GetHostName(), "example.com");

    options.SetHostName("test.example.org");
    EXPECT_EQ(options.GetHostName(), "test.example.org");
}

/**
 * @tc.name: TlsConnectOptionsTest_CheckServerIdentity
 * @tc.desc: Test SetCheckServerIdentity callback
 * @tc.type: FUNC
 */
HWTEST_F(TlsConnectOptionsTest, CheckServerIdentity, TestSize.Level1)
{
    TLSConnectOptions options;
    bool callbackCalled = false;
    std::string capturedHost;

    CheckServerIdentity identityChecker = [&callbackCalled, &capturedHost](
        const std::string &hostName, const std::vector<std::string> & /*x509Certificates*/) {
        callbackCalled = true;
        capturedHost = hostName;
    };

    options.SetCheckServerIdentity(identityChecker);
    CheckServerIdentity retrieved = options.GetCheckServerIdentity();

    // Call the callback to verify it was set correctly
    retrieved("test.host", std::vector<std::string>());
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(capturedHost, "test.host");
}

/**
 * @tc.name: TlsConnectOptionsTest_MultipleCaChain
 * @tc.desc: Test TLSSecureOptions with multiple CA certificates
 * @tc.type: FUNC
 */
HWTEST_F(TlsConnectOptionsTest, MultipleCaChain, TestSize.Level1)
{
    TLSSecureOptions secureOpts;
    std::vector<std::string> caChain;
    caChain.push_back(CA_CERT_PEM);
    caChain.push_back(CLIENT_CERT_PEM);
    secureOpts.SetCaChain(caChain);

    EXPECT_EQ(secureOpts.GetCaChain().size(), 2U);
}

} // namespace TlsSocket
} // namespace NetStack
} // namespace OHOS
