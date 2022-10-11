/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <fstream>
#include <gtest/gtest.h>
#include <iostream>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "net_address.h"
#include "socket_state_base.h"
#include "tls.h"
#include "tls_certificate.h"
#include "tls_configuration.h"
#include "tls_key.h"
#include "tls_socket.h"

namespace OHOS {
namespace NetStack {
namespace {
constexpr char IP_ADDRESS[] = "10.14.0.7";
constexpr int PORT = 7838;
constexpr std::string_view PRIVATE_KEY_PEM_CHAIN = "/data/ClientCertChain/privekey.pem.unsecure";
constexpr std::string_view CA_PATH_CHAIN = "/data/ClientCertChain/cacert.crt";
constexpr std::string_view MID_CA_PATH_CHAIN = "/data/ClientCertChain/caMidcert.crt";
constexpr std::string_view CLIENT_CRT_CHAIN = "/data/ClientCertChain/secondServer.crt";

inline bool CheckCaFileExistence(const char *function)
{
    if (access(CA_PATH_CHAIN.data(), 0)) {
        std::cout << "CA file doesnot exist! (" << function << ")";
        return false;
    }
    return true;
}

std::string ChangeToFileChain(const std::string_view fileName)
{
    std::ifstream file;
    file.open(fileName);
    std::stringstream ss;
    ss << file.rdbuf();
    std::string infos = ss.str();
    file.close();
    return infos;
}
} // namespace

class TlsSocketTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

HWTEST_F(TlsSocketTest, bindInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("bindInterface")) {
        return;
    }

    TLSSocket server;
    NetAddress address;

    address.SetAddress(IP_ADDRESS);
    address.SetPort(PORT);
    address.SetFamilyBySaFamily(AF_INET);

    bool isBind = false;
    server.Bind(address, [&isBind](bool ok) { isBind = ok; });
    EXPECT_TRUE(isBind);
}

HWTEST_F(TlsSocketTest, connectInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("connectInterface")) {
        return;
    }
    TLSConnectOptions options;
    TLSSocket server;

    TLSSecureOptions secureOption;
    NetAddress address;

    address.SetAddress(IP_ADDRESS);
    address.SetPort(PORT);
    address.SetFamilyBySaFamily(AF_INET);

    secureOption.SetKey(ChangeToFileChain(PRIVATE_KEY_PEM_CHAIN));
    std::vector<std::string> caVec = {ChangeToFileChain(CA_PATH_CHAIN), ChangeToFileChain(MID_CA_PATH_CHAIN)};
    secureOption.SetCaChain(caVec);
    secureOption.SetCert(ChangeToFileChain(CLIENT_CRT_CHAIN));

    options.SetNetAddress(address);
    options.SetTlsSecureOptions(secureOption);
    bool isBind = false;
    bool isConnect = false;
    bool isClose = false;
    bool isSend = false;

    server.Bind(address, [&isBind](bool ok) { isBind = ok; });
    EXPECT_TRUE(isBind);

    server.Connect(options, [&isConnect](bool ok) { isConnect = ok; });
    EXPECT_TRUE(isConnect);

    const std::string data = "how do you do? this is connectInterface";
    TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);
    server.Send(tcpSendOptions, [&isSend](bool ok) { isSend = ok; });
    EXPECT_TRUE(isSend);
    sleep(2);

    (void)server.Close([&isClose](bool ok) {
        if (ok) {
            isClose = ok;
        }
    });
    EXPECT_TRUE(isClose);
    sleep(2);
}

HWTEST_F(TlsSocketTest, closeInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("closeInterface")) {
        return;
    }

    TLSConnectOptions options;
    TLSSocket server;

    TLSSecureOptions secureOption;
    NetAddress address;

    address.SetAddress(IP_ADDRESS);
    address.SetPort(PORT);
    address.SetFamilyBySaFamily(AF_INET);

    secureOption.SetKey(ChangeToFileChain(PRIVATE_KEY_PEM_CHAIN));
    std::vector<std::string> caVec = {ChangeToFileChain(CA_PATH_CHAIN), ChangeToFileChain(MID_CA_PATH_CHAIN)};
    secureOption.SetCaChain(caVec);
    secureOption.SetCert(ChangeToFileChain(CLIENT_CRT_CHAIN));

    options.SetNetAddress(address);
    options.SetTlsSecureOptions(secureOption);
    bool isBind = false;
    bool isConnect = false;
    bool isSend = false;
    bool isClose = false;

    server.Bind(address, [&isBind](bool ok) { isBind = ok; });
    EXPECT_TRUE(isBind);

    server.Connect(options, [&isConnect](bool ok) { isConnect = ok; });
    EXPECT_TRUE(isConnect);

    const std::string data = "how do you do? this is closeInterface";
    TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);

    server.Send(tcpSendOptions, [&isSend](bool ok) { isSend = ok; });
    EXPECT_TRUE(isSend);
    sleep(2);

    (void)server.Close([&isClose](bool ok) {
        if (ok) {
            isClose = ok;
        }
    });
    EXPECT_TRUE(isClose);
}

HWTEST_F(TlsSocketTest, sendInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("sendInterface")) {
        return;
    }
    TLSConnectOptions options;
    TLSSocket server;

    TLSSecureOptions secureOption;
    NetAddress address;

    address.SetAddress(IP_ADDRESS);
    address.SetPort(PORT);
    address.SetFamilyBySaFamily(AF_INET);

    secureOption.SetKey(ChangeToFileChain(PRIVATE_KEY_PEM_CHAIN));
    std::vector<std::string> caVec = {ChangeToFileChain(CA_PATH_CHAIN), ChangeToFileChain(MID_CA_PATH_CHAIN)};
    secureOption.SetCaChain(caVec);
    secureOption.SetCert(ChangeToFileChain(CLIENT_CRT_CHAIN));

    options.SetNetAddress(address);
    options.SetTlsSecureOptions(secureOption);
    bool isBind = false;
    bool isConnect = false;
    bool isSend = false;
    bool isClose = false;

    server.Bind(address, [&isBind](bool ok) { isBind = ok; });
    EXPECT_TRUE(isBind);

    server.Connect(options, [&isConnect](bool ok) { isConnect = ok; });
    EXPECT_TRUE(isConnect);

    const std::string data = "how do you do? this is sendInterface";
    TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);

    server.Send(tcpSendOptions, [&isSend](bool ok) { isSend = ok; });
    EXPECT_TRUE(isSend);
    sleep(2);

    (void)server.Close([&isClose](bool ok) {
        if (ok) {
            isClose = ok;
        }
    });
    EXPECT_TRUE(isClose);
}

HWTEST_F(TlsSocketTest, getRemoteAddressInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("getRemoteAddressInterface")) {
        return;
    }

    TLSConnectOptions options;
    TLSSocket server;
    TLSSecureOptions secureOption;
    NetAddress address;

    address.SetAddress(IP_ADDRESS);
    address.SetPort(PORT);
    address.SetFamilyBySaFamily(AF_INET);

    secureOption.SetKey(ChangeToFileChain(PRIVATE_KEY_PEM_CHAIN));
    std::vector<std::string> caVec = {ChangeToFileChain(CA_PATH_CHAIN), ChangeToFileChain(MID_CA_PATH_CHAIN)};
    secureOption.SetCaChain(caVec);
    secureOption.SetCert(ChangeToFileChain(CLIENT_CRT_CHAIN));

    options.SetNetAddress(address);
    options.SetTlsSecureOptions(secureOption);

    bool isBind = false;
    bool isConnect = false;
    bool isSend = false;
    bool isOk = false;
    bool isClose = false;

    server.Bind(address, [&isBind](bool ok) { isBind = ok; });
    EXPECT_TRUE(isBind);

    server.Connect(options, [&isConnect](bool ok) { isConnect = ok; });
    EXPECT_TRUE(isConnect);

    NetAddress netAddress;
    server.GetRemoteAddress([&isOk, &netAddress](bool ok, const NetAddress &address) {
        isOk = ok;
        netAddress.SetAddress(address.GetAddress());
        netAddress.SetPort(address.GetPort());
        netAddress.SetFamilyBySaFamily(address.GetSaFamily());
    });

    EXPECT_TRUE(isOk);
    EXPECT_STREQ(netAddress.GetAddress().c_str(), IP_ADDRESS);
    EXPECT_EQ(address.GetPort(), 7838);
    EXPECT_EQ(netAddress.GetSaFamily(), AF_INET);

    const std::string data = "how do you do? this is getRemoteAddressInterface";
    TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);

    server.Send(tcpSendOptions, [&isSend](bool ok) { isSend = ok; });
    EXPECT_TRUE(isSend);
    sleep(2);

    (void)server.Close([&isClose](bool ok) {
        if (ok) {
            isClose = ok;
        }
    });
    EXPECT_TRUE(isClose);
}

HWTEST_F(TlsSocketTest, getStateInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("getRemoteAddressInterface")) {
        return;
    }

    TLSConnectOptions options;
    TLSSocket server;
    TLSSecureOptions secureOption;
    NetAddress address;

    address.SetAddress(IP_ADDRESS);
    address.SetPort(PORT);
    address.SetFamilyBySaFamily(AF_INET);

    secureOption.SetKey(ChangeToFileChain(PRIVATE_KEY_PEM_CHAIN));
    std::vector<std::string> caVec = {ChangeToFileChain(CA_PATH_CHAIN), ChangeToFileChain(MID_CA_PATH_CHAIN)};
    secureOption.SetCaChain(caVec);
    secureOption.SetCert(ChangeToFileChain(CLIENT_CRT_CHAIN));

    options.SetNetAddress(address);
    options.SetTlsSecureOptions(secureOption);

    bool isBind = false;
    bool isConnect = false;
    bool isOk = false;
    bool isClose = false;
    bool isSend = false;
    server.Bind(address, [&isBind](bool ok) { isBind = ok; });
    EXPECT_TRUE(isBind);
    server.Connect(options, [&isConnect](bool ok) { isConnect = ok; });
    EXPECT_TRUE(isConnect);

    SocketStateBase TlsSocketstate;
    server.GetState([&isOk, &TlsSocketstate](bool ok, const SocketStateBase &state) {
        isOk = ok;
        TlsSocketstate = state;
    });
    std::cout << "TlsSocketstate.IsClose(): " << TlsSocketstate.IsClose() << std::endl;
    EXPECT_TRUE(isOk);
    EXPECT_TRUE(TlsSocketstate.IsBound());
    EXPECT_TRUE(!TlsSocketstate.IsClose());
    EXPECT_TRUE(TlsSocketstate.IsConnected());

    const std::string data = "how do you do? this is getStateInterface";
    TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);
    server.Send(tcpSendOptions, [&isSend](bool ok) { isSend = ok; });
    EXPECT_TRUE(isSend);

    sleep(2);

    (void)server.Close([&isClose](bool ok) {
        if (ok) {
            isClose = ok;
        }
    });
    EXPECT_TRUE(isClose);
}

HWTEST_F(TlsSocketTest, getCertificateInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("getCertificateInterface")) {
        return;
    }
    TLSSocket server;
    TLSConnectOptions options;
    TCPSendOptions tcpSendOptions;
    TLSSecureOptions secureOption;
    NetAddress address;
    const std::string data = "how do you do? This is UT test getCertificateInterface";

    address.SetAddress(IP_ADDRESS);
    address.SetPort(PORT);
    address.SetFamilyBySaFamily(AF_INET);

    secureOption.SetKey(ChangeToFileChain(PRIVATE_KEY_PEM_CHAIN));
    std::vector<std::string> caVec = {ChangeToFileChain(CA_PATH_CHAIN), ChangeToFileChain(MID_CA_PATH_CHAIN)};
    secureOption.SetCaChain(caVec);
    secureOption.SetCert(ChangeToFileChain(CLIENT_CRT_CHAIN));

    options.SetNetAddress(address);
    options.SetTlsSecureOptions(secureOption);

    bool isBind = false;
    server.Bind(address, [&isBind](bool ok) { isBind = ok; });
    EXPECT_TRUE(isBind);

    server.Connect(options, [](bool ok) { EXPECT_TRUE(ok); });

    tcpSendOptions.SetData(data);
    server.Send(tcpSendOptions, [](bool ok) { EXPECT_TRUE(ok); });

    bool isGetCertificate;
    server.GetCertificate([&isGetCertificate](bool ok, const std::string &cert) { isGetCertificate = ok; });

    EXPECT_TRUE(isGetCertificate);
    sleep(2);
    (void)server.Close([](bool ok) { EXPECT_TRUE(ok); });
}

HWTEST_F(TlsSocketTest, getRemoteCertificateInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("getRemoteCertificateInterface")) {
        return;
    }
    TLSSocket server;
    TLSConnectOptions options;
    TCPSendOptions tcpSendOptions;
    TLSSecureOptions secureOption;
    NetAddress address;
    const std::string data = "how do you do? This is UT test getRemoteCertificateInterface";

    address.SetAddress(IP_ADDRESS);
    address.SetPort(PORT);
    address.SetFamilyBySaFamily(AF_INET);

    secureOption.SetKey(ChangeToFileChain(PRIVATE_KEY_PEM_CHAIN));
    std::vector<std::string> caVec = {ChangeToFileChain(CA_PATH_CHAIN), ChangeToFileChain(MID_CA_PATH_CHAIN)};
    secureOption.SetCaChain(caVec);
    secureOption.SetCert(ChangeToFileChain(CLIENT_CRT_CHAIN));

    options.SetNetAddress(address);
    options.SetTlsSecureOptions(secureOption);

    bool isBind = false;
    server.Bind(address, [&isBind](bool ok) { isBind = ok; });
    EXPECT_TRUE(isBind);

    server.Connect(options, [](bool ok) { EXPECT_TRUE(ok); });

    tcpSendOptions.SetData(data);

    server.Send(tcpSendOptions, [](bool ok) { EXPECT_TRUE(ok); });

    bool isRemoteCertificate;
    server.GetRemoteCertificate([&isRemoteCertificate](bool ok, const std::string &cert) { isRemoteCertificate = ok; });

    EXPECT_TRUE(isRemoteCertificate);

    sleep(2);
    (void)server.Close([](bool ok) { EXPECT_TRUE(ok); });
}

HWTEST_F(TlsSocketTest, protocolInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("protocolInterface")) {
        return;
    }
    TLSConnectOptions options;
    TLSSocket server;
    TLSSecureOptions secureOption;
    NetAddress address;

    address.SetAddress(IP_ADDRESS);
    address.SetPort(PORT);
    address.SetFamilyBySaFamily(AF_INET);

    secureOption.SetKey(ChangeToFileChain(PRIVATE_KEY_PEM_CHAIN));
    std::vector<std::string> caVec = {ChangeToFileChain(CA_PATH_CHAIN), ChangeToFileChain(MID_CA_PATH_CHAIN)};
    secureOption.SetCaChain(caVec);
    secureOption.SetCert(ChangeToFileChain(CLIENT_CRT_CHAIN));
    secureOption.SetCipherSuite("AES256-SHA256");
    std::string protocolV1_3 = "TLSv1.3";
    std::vector<std::string> protocolVec = {protocolV1_3};
    secureOption.SetProtocolChain(protocolVec);

    options.SetNetAddress(address);
    options.SetTlsSecureOptions(secureOption);
    bool isBind = false;
    bool isConnect = false;
    bool isSend = false;
    server.Bind(address, [&isBind](bool ok) { isBind = ok; });
    EXPECT_TRUE(isBind);

    server.Connect(options, [&isConnect](bool ok) { isConnect = ok; });
    EXPECT_TRUE(isConnect);

    const std::string data = "how do you do? this is protocolInterface";
    TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);

    server.Send(tcpSendOptions, [&isSend](bool ok) { isSend = ok; });
    EXPECT_TRUE(isSend);
    bool isOk = false;
    std::string getProtocolVal;
    server.GetProtocol([&isOk, &getProtocolVal](bool ok, const std::string &protocol) {
        isOk = ok;
        getProtocolVal = protocol;
    });
    EXPECT_TRUE(isOk);
    EXPECT_STREQ(getProtocolVal.c_str(), "TLSv1.3");
    sleep(2);

    (void)server.Close([](bool ok) { EXPECT_TRUE(ok); });
}

HWTEST_F(TlsSocketTest, getCipherSuiteInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("getCipherSuiteInterface")) {
        return;
    }

    TLSConnectOptions options;
    TLSSocket server;
    TLSSecureOptions secureOption;
    NetAddress address;

    address.SetAddress(IP_ADDRESS);
    address.SetPort(PORT);
    address.SetFamilyBySaFamily(AF_INET);

    secureOption.SetKey(ChangeToFileChain(PRIVATE_KEY_PEM_CHAIN));
    std::vector<std::string> caVec = {ChangeToFileChain(CA_PATH_CHAIN), ChangeToFileChain(MID_CA_PATH_CHAIN)};
    secureOption.SetCaChain(caVec);
    secureOption.SetCert(ChangeToFileChain(CLIENT_CRT_CHAIN));
    secureOption.SetCipherSuite("AES256-SHA256");
    std::string protocolV1_3 = "TLSv1.3";
    std::vector<std::string> protocolVec = {protocolV1_3};
    secureOption.SetProtocolChain(protocolVec);

    options.SetNetAddress(address);
    options.SetTlsSecureOptions(secureOption);

    bool isBind = false;
    bool isClose = false;
    bool flag = false;
    bool isSend = false;
    server.Bind(address, [&isBind](bool ok) { isBind = ok; });
    EXPECT_TRUE(isBind);

    server.Connect(options, [](bool ok) { EXPECT_TRUE(ok); });

    const std::string data = "how do you do? This is getCipherSuiteInterface";
    TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);
    server.Send(tcpSendOptions, [&isSend](bool ok) { isSend = ok; });
    EXPECT_TRUE(isSend);

    std::vector<std::string> cipherSuite;
    server.GetCipherSuite([&cipherSuite](bool ok, const std::vector<std::string> &suite) { cipherSuite = suite; });

    for (auto const &iter : cipherSuite) {
        if (iter == "AES256-SHA256") {
            flag = true;
        }
    }

    EXPECT_TRUE(flag);
    sleep(2);

    (void)server.Close([&isClose](bool ok) {
        if (ok) {
            isClose = ok;
        }
    });
    EXPECT_TRUE(isClose);
}

HWTEST_F(TlsSocketTest, getSignatureAlgorithmsInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("getSignatureAlgorithmsInterface")) {
        return;
    }
    TLSConnectOptions options;
    TLSSocket server;
    TLSSecureOptions secureOption;
    NetAddress address;

    address.SetAddress(IP_ADDRESS);
    address.SetPort(PORT);
    address.SetFamilyBySaFamily(AF_INET);

    std::string signatureAlgorithmVec = {"rsa_pss_rsae_sha256:ECDSA+SHA25"};
    secureOption.SetSignatureAlgorithms(signatureAlgorithmVec);
    secureOption.SetKey(ChangeToFileChain(PRIVATE_KEY_PEM_CHAIN));
    std::vector<std::string> caVec = {ChangeToFileChain(CA_PATH_CHAIN), ChangeToFileChain(MID_CA_PATH_CHAIN)};
    secureOption.SetCaChain(caVec);
    secureOption.SetCert(ChangeToFileChain(CLIENT_CRT_CHAIN));
    std::string protocolV1_3 = "TLSv1.3";
    std::vector<std::string> protocolVec = {protocolV1_3};
    secureOption.SetProtocolChain(protocolVec);

    options.SetNetAddress(address);
    options.SetTlsSecureOptions(secureOption);

    bool isBind = false;
    bool flag = false;
    server.Bind(address, [&isBind](bool ok) { isBind = ok; });
    EXPECT_TRUE(isBind);

    server.Connect(options, [](bool ok) { EXPECT_TRUE(ok); });

    const std::string data = "how do you do? this is getSignatureAlgorithmsInterface";
    TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);
    server.Send(tcpSendOptions, [](bool ok) {
        if (ok) {
            EXPECT_TRUE(ok);
        }
    });

    std::vector<std::string> signatureAlgorithms;
    server.GetSignatureAlgorithms([&signatureAlgorithms](bool ok, const std::vector<std::string> &algorithms) {
        if (ok) {
            signatureAlgorithms = algorithms;
        }
    });
    for (auto const &iter : signatureAlgorithms) {
        if (iter == "RSA+SHA256") {
            flag = true;
        }
    }
    EXPECT_TRUE(flag);
    sleep(2);
    (void)server.Close([](bool ok) { EXPECT_TRUE(ok); });
}

HWTEST_F(TlsSocketTest, onMessageDataInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("tlsSocketOnMessageData")) {
        return;
    }
    std::string getData = "server->client";
    TLSConnectOptions options;
    TLSSocket server;
    TLSSecureOptions secureOption;
    NetAddress address;

    address.SetAddress(IP_ADDRESS);
    address.SetPort(PORT);
    address.SetFamilyBySaFamily(AF_INET);

    secureOption.SetKey(ChangeToFileChain(PRIVATE_KEY_PEM_CHAIN));
    std::vector<std::string> caVec = {ChangeToFileChain(CA_PATH_CHAIN), ChangeToFileChain(MID_CA_PATH_CHAIN)};
    secureOption.SetCaChain(caVec);
    secureOption.SetCert(ChangeToFileChain(CLIENT_CRT_CHAIN));
    secureOption.SetCipherSuite("AES256-SHA256");
    std::string protocolV1_3 = "TLSv1.3";
    std::vector<std::string> protocolVec = {protocolV1_3};
    secureOption.SetProtocolChain(protocolVec);

    options.SetNetAddress(address);
    options.SetTlsSecureOptions(secureOption);

    bool isBind = false;
    server.Bind(address, [&isBind](bool ok) { isBind = ok; });
    EXPECT_TRUE(isBind);

    server.Connect(options, [](bool ok) { EXPECT_TRUE(ok); });
    server.OnMessage([&getData](const std::string &data, const SocketRemoteInfo &remoteInfo) {
        if (data == getData) {
            EXPECT_TRUE(true);
        } else {
            EXPECT_TRUE(false);
        }
    });

    const std::string data = "how do you do? this is tlsSocketOnMessageData";
    TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);
    server.Send(tcpSendOptions, [](bool ok) { EXPECT_TRUE(ok); });

    sleep(2);
    (void)server.Close([](bool ok) { EXPECT_TRUE(ok); });
}
} // namespace NetStack
} // namespace OHOS
