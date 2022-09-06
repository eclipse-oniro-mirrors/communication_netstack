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
#include <iostream>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <sstream>
#include <string>

#include "gtest/gtest.h"
#include "netstack_log.h"
#include "net_address.h"
#include "socket_state_base.h"
#include "tls.h"
#include "tls_configuration.h"
#include "tls_certificate.h"
#include "tls_key.h"
#include "tls_socket_internal.h"
#include "tls_socket.h"

namespace OHOS {
namespace NetStack {
static constexpr const char *IP_ADDRESS = "10.14.0.7";
std::string PRIVATE_KEY_PEM = "ClientCert/client_rsa_private.pem.unsecure";
std::string CA_DER = "ClientCert/ca.crt";
std::string CLIENT_CRT = "ClientCert/client.crt";

// static constexpr const char *PRIVATE_KEY_PEM = "ClientCertChain/privekey.pem.unsecure";
// static constexpr const char *CA_PATH = "ClientCertChain/cacert.crt";
// static constexpr const char *MID_CA_PATH = "ClientCertChain/caMidcert.crt";
// static constexpr const char *CLIENT_CRT = "ClientCertChain/secondServer.crt";

class TlsSocketTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

std::string ChangeToFile(std::string &fileName)
{
    std::ifstream file;
    file.open(fileName);
    std::stringstream ss;
    ss << file.rdbuf();
    std::string infos = ss.str();
    file.close();
    return infos;
}

void TlsSocketConnect(TLSConnectOptions &options)
{
    std::vector<std::string> caVec= {ChangeToFile(CA_DER)};

    std::vector<std::string> protocolVec = {"TlsV1_2"};
    std::string signatureAlgorithmVec = {"RSA-SHA256"};
    std::vector<std::string> alpnProtocols = {"spdy/1", "http/1.1"};

    TLSSecureOptions secureOption;
    NetAddress address;

    address.SetAddress(IP_ADDRESS);
    address.SetPort(7838);
    address.SetFamilyBySaFamily(AF_INET);

    secureOption.SetKey(ChangeToFile(PRIVATE_KEY_PEM));
    secureOption.SetCaChain(caVec);
    secureOption.SetCert(ChangeToFile(CLIENT_CRT));
    secureOption.SetCipherSuite("AES256-SHA256");
    secureOption.SetProtocolChain(protocolVec);
    secureOption.SetUseRemoteCipherPrefer(true);
    secureOption.SetSignatureAlgorithms(signatureAlgorithmVec);
    secureOption.SetPassWd("123456");

    options.SetNetAddress(address);
    options.SetTlsSecureOptions(secureOption);
    options.SetAlpnProtocols(alpnProtocols);
}

HWTEST_F(TlsSocketTest, tlsConnetOptionsSend, testing::ext::TestSize.Level2)
{
    TLSConnectOptions options;
    TLSSocket server;

    TlsSocketConnect(options);
    server.Connect(options, [](bool ok){ EXPECT_TRUE(ok); });
    std::vector<std::string> cipherSuite;
    server.GetCipherSuite([&cipherSuite](bool ok, const std::vector<std::string> &suite) {if (ok) {cipherSuite = suite;}});
   (void)server.GetCertificate([](bool ok, const std::string cert) {});
    const std::string data = "how do you do?";
    TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);
    server.Send(tcpSendOptions, [](bool ok) {if (ok) {EXPECT_TRUE(ok);}});
    sleep(2);
    (void)server.Close([](bool ok) {if (ok) {;}});
}

HWTEST_F(TlsSocketTest, tlsSocketCertChainConnect, testing::ext::TestSize.Level2)
{
    TLSConnectOptions options;
    TLSSocket server;

    TlsSocketConnect(options);

    server.Connect(options, [](bool ok){ EXPECT_TRUE(ok); });
    const std::string data = "how do you do?";
    TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);
    server.Send(tcpSendOptions, [](bool ok) {if (ok) {EXPECT_TRUE(ok);}});
    sleep(2);
    (void)server.Close([](bool ok) {if (ok) {;}});
}

HWTEST_F(TlsSocketTest, tlsSocketCertChainConnectOther, testing::ext::TestSize.Level2)
{
    TLSConnectOptions options;
    TLSSocket server;

    TlsSocketConnect(options);

    server.Connect(options, [](bool ok){ EXPECT_TRUE(ok); });
    std::vector<std::string> cipherSuite;
    server.GetCipherSuite([&cipherSuite](bool ok, const std::vector<std::string> &suite) {if (ok) {cipherSuite = suite;}});
    const std::string data = "how do you do?";
    TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);
    server.Send(tcpSendOptions, [](bool ok) {if (ok) {EXPECT_TRUE(ok);}});
    sleep(2);
    (void)server.Close([](bool ok) {if (ok) {;}});
}

HWTEST_F(TlsSocketTest, tlsConnetOptionsSend2, testing::ext::TestSize.Level2)
{
    TLSConnectOptions options;
    TLSSocket server;

    TlsSocketConnect(options);

    server.Connect(options, [](bool ok){ EXPECT_TRUE(ok); });
    std::vector<std::string> cipherSuite;
    server.GetCipherSuite([&cipherSuite](bool ok, const std::vector<std::string> &suite) {if (ok) {cipherSuite = suite;}});
    const std::string data = "how do you do? This is UT test tlsConnetOptionsSend";
    TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);
    server.Send(tcpSendOptions, [](bool ok) {if (ok) {EXPECT_TRUE(ok);}});

    sleep(2);

    (void)server.Close([](bool ok) {if (ok) {;}});
}

HWTEST_F(TlsSocketTest, tlsOptionGet, testing::ext::TestSize.Level2)
{
    TLSConnectOptions options;
    TLSSecureOptions secureOption;
    NetAddress address;
    TLSSocket server;
    std::vector<std::string> cipherSuite;
    std::vector<std::string> caVec = {ChangeToFile(CA_DER)};
    std::vector<std::string> protocolVec = {"TlsV1_2"};
    std::string signatureAlgorithmVec = {"RSA-SHA256"};
    std::vector<std::string> alpnProtocols = {"spdy/1", "http/1.1"};

    address.SetAddress("10.14.0.91");
    address.SetPort(7838);
    address.SetFamilyBySaFamily(AF_INET);
    secureOption.SetKey(PRIVATE_KEY_PEM);//
    (void)secureOption.GetKey();
    (void)options.GetTlsSecureOptions().GetKey();

    secureOption.SetCaChain(caVec);//
    secureOption.SetCert(CLIENT_CRT);//
    secureOption.SetCipherSuite("AES256-SHA256");//
    secureOption.SetProtocolChain(protocolVec);//
    secureOption.SetUseRemoteCipherPrefer(true);//
    secureOption.SetSignatureAlgorithms(signatureAlgorithmVec);//
    secureOption.SetPassWd("123456");//
    options.SetNetAddress(address);
    options.SetTlsSecureOptions(secureOption);
    options.SetAlpnProtocols(alpnProtocols);

    for (int i = 0; i < caVec.size(); i++) {
        std::cout << "setcaVec: "<< caVec[i] << std::endl;
    }
    std::cout << "setCert: " << CLIENT_CRT << std::endl;
    std::cout << "setKey: " << PRIVATE_KEY_PEM << std::endl;
    std::cout << "setCipherSuite: " << "AES256-SHA256" << std::endl;
    for (int i = 0; i < caVec.size(); i++) {
        std::cout << "setProtocolChain: "<< protocolVec[i].c_str() << std::endl;
    }
    std::cout << "setUseRemoteCipherPrefer: " << "true" << std::endl;
    std::cout << "setSignatureAlgorithms: " << signatureAlgorithmVec << std::endl;
    std::cout << "SetPassWd: " << "123456" << std::endl;

    TLSSecureOptions  tLSSecureOptions = options.GetTlsSecureOptions();
    std::vector<std::string> testCaChain = tLSSecureOptions.GetCaChain();
    std::string getCert = tLSSecureOptions.GetCert();
    std::string getKey = tLSSecureOptions.GetKey();
    std::string getPasswd = tLSSecureOptions.GetPasswd();
    std::vector<std::string> getProtocolChain = tLSSecureOptions.GetProtocolChain();
    bool getIsUseRemoteCipherPrefer = tLSSecureOptions.UseRemoteCipherPrefer();
    std::string getSignatureAlgorithms = tLSSecureOptions.GetSignatureAlgorithms();

    for (int i = 0; i < caVec.size(); i++) {
        std::cout << "getcaVec: "<< testCaChain[i] << std::endl;
    }
    std::cout << "getsetCert: " << getCert << std::endl;
    std::cout << "getsetKey: " << getKey << std::endl;
    std::cout << "getCipherSuite: " << "AES256-SHA256" << std::endl;
    for (int i = 0; i < caVec.size(); i++) {
        std::cout << "getProtocolChain: "<< getProtocolChain[i] << std::endl;
    }
    std::cout << "getUseRemoteCipherPrefer: " << getIsUseRemoteCipherPrefer << std::endl;
    std::cout << "getSignatureAlgorithms: " << getSignatureAlgorithms << std::endl;
    std::cout << "getSetPassWd: " << getPasswd << std::endl;
    sleep(1);
}

HWTEST_F(TlsSocketTest, tlsSocketGcertInternal, testing::ext::TestSize.Level2)
{
    std::cout << "TlsSocketTest, tlsSocketGetState begin " << std::endl;
    TLSSocket server;
    TLSConnectOptions options;
    TCPSendOptions tcpSendOptions;
    const std::string data = "how do you do? This is UT test tlsSocketGcertInternal";

    TlsSocketConnect(options);

    server.Connect(options, [] (bool ok){ EXPECT_TRUE(ok); });

    tcpSendOptions.SetData(data);

    server.Send(tcpSendOptions, [] (bool ok) { EXPECT_TRUE(ok); });

    bool IsGetCertificate;
    std::string certInternal;
    server.GetCertificate([&IsGetCertificate, &certInternal] (bool ok, const std::string &cert) {
        IsGetCertificate = ok;
        certInternal = cert;
    });
    std::cout << "GetCertificate IsGetCertificate: " << IsGetCertificate <<std::endl;
    if(IsGetCertificate) {
        std::cout << "cert: " << certInternal << std::endl;
    }

    EXPECT_TRUE(IsGetCertificate);

    sleep(2);
    (void)server.Close([](bool ok) {EXPECT_TRUE(ok); });
    std::cout << "TlsSocketTest, tlsSocketGetState end " << std::endl;
}

HWTEST_F(TlsSocketTest, tlsSocketGetRemoteCertificate, testing::ext::TestSize.Level2)
{
    std::cout << "TlsSocketTest, tlsSocketGetRemoteCertificate begin " << std::endl;
    TLSSocket server;
    TLSConnectOptions options;
    TCPSendOptions tcpSendOptions;
    const std::string data = "how do you do? This is UT test tlsSocketGetRemoteCertificate";

    TlsSocketConnect(options);

    server.Connect(options, [] (bool ok){ EXPECT_TRUE(ok); });

    tcpSendOptions.SetData(data);

    server.Send(tcpSendOptions, [] (bool ok) { EXPECT_TRUE(ok); });

    bool IsRemoteCertificate;
    std::string certInternal;
    server.GetRemoteCertificate([&IsRemoteCertificate, &certInternal] (bool ok, const std::string &cert) {
        IsRemoteCertificate = ok;
        certInternal = cert;
    });
    std::cout << "GetRemoteCertificate IsRemoteCertificate: " << IsRemoteCertificate <<std::endl;
    if(IsRemoteCertificate) {
        std::cout << "cert: " << certInternal.c_str() << std::endl;
    }

    EXPECT_TRUE(IsRemoteCertificate);

    sleep(2);
    (void)server.Close([](bool ok) {EXPECT_TRUE(ok); });
    std::cout << "TlsSocketTest, tlsSocketGetRemoteCertificate end " << std::endl;
}

HWTEST_F(TlsSocketTest, tlsSocketGetProtocol, testing::ext::TestSize.Level2)
{
    std::cout << "TlsSocketTest, tlsSocketGetProtocol begin " << std::endl;
    TLSSocket server;
    TLSConnectOptions options;
    TCPSendOptions tcpSendOptions;
    const std::string data = "how do you do? This is UT test tlsSocketGetProtocol";


    TlsSocketConnect(options);

    server.Connect(options, [] (bool ok){ EXPECT_TRUE(ok); });

    tcpSendOptions.SetData(data);

    server.Send(tcpSendOptions, [] (bool ok) { EXPECT_TRUE(ok); });

    bool IsGetProtocol;
    std::string protocolInternal;
    server.GetProtocol([&IsGetProtocol, &protocolInternal] (bool ok, const std::string &protocol) {
        IsGetProtocol = ok;
        protocolInternal = protocol;
    });
    std::cout << "GetProtocol IsGetProtocol: " << IsGetProtocol <<std::endl;
    if(IsGetProtocol) {
        std::cout << "protocolInternal: " << protocolInternal.c_str() << std::endl;
    }

    EXPECT_TRUE(IsGetProtocol);

    sleep(2);
    (void)server.Close([](bool ok) {EXPECT_TRUE(ok); });
    std::cout << "TlsSocketTest, tlsSocketGetProtocol end " << std::endl;
}

HWTEST_F(TlsSocketTest, tlsSocketGetSignatureAlgorithms, testing::ext::TestSize.Level2)
{
    std::cout << "TlsSocketTest, tlsSocketGetSignatureAlgorithms begin " << std::endl;
    TLSSocket server;
    TLSConnectOptions options;
    TCPSendOptions tcpSendOptions;
    const std::string data = "how do you do? This is UT test tlsSocketGetSignatureAlgorithms";


    TlsSocketConnect(options);

    server.Connect(options, [] (bool ok){ EXPECT_TRUE(ok); });

    tcpSendOptions.SetData(data);

    server.Send(tcpSendOptions, [] (bool ok) { EXPECT_TRUE(ok); });

    bool IsGetSignatureAlgorithms;
    std::vector<std::string> algorithmsInternal;
    server.GetSignatureAlgorithms([&IsGetSignatureAlgorithms, &algorithmsInternal] (bool ok, const std::vector<std::string> &algorithms) {
        IsGetSignatureAlgorithms = ok;
        algorithmsInternal = algorithms;
    });
    std::cout << "GetSignatureAlgorithms IsGetSignatureAlgorithms: " << IsGetSignatureAlgorithms <<std::endl;
    if(IsGetSignatureAlgorithms) {
        for (auto i : algorithmsInternal) {
            std::cout << "algorithmsInternal: " << i.c_str() << std::endl;
        }
    }

    EXPECT_TRUE(IsGetSignatureAlgorithms);

    sleep(2);
    (void)server.Close([](bool ok) {EXPECT_TRUE(ok); });
    std::cout << "TlsSocketTest, tlsSocketGetSignatureAlgorithms end " << std::endl;
}

HWTEST_F(TlsSocketTest, tlsSocketOnMessageData, testing::ext::TestSize.Level2)
{
    std::cout << "TlsSocketTest, tlsSocketOnMessageData begin " << std::endl;
    TLSSocket server;
    TLSConnectOptions options;
    TCPSendOptions tcpSendOptions;
    const std::string data = "how do you do? This is UT test tlsSocketOnMessageData";


    TlsSocketConnect(options);

    server.Connect(options, [] (bool ok){ EXPECT_TRUE(ok); });

    tcpSendOptions.SetData(data);

    server.Send(tcpSendOptions, [] (bool ok) { EXPECT_TRUE(ok); });

    std::string OnMessageData;
    SocketRemoteInfo OnMessageInternal;
    server.OnMessage([&OnMessageData, &OnMessageInternal] (const std::string &data, const SocketRemoteInfo &remoteInfo) {
        OnMessageData = data;
        OnMessageInternal = remoteInfo;
    });

    if (!data.empty()) {
        std::cout << "data: " << data << std::endl;

        std::cout << "remoteInfo.Address: " << OnMessageInternal.GetAddress().c_str() << std::endl;
        std::cout << "remoteInfo.Family: " << OnMessageInternal.GetFamily().c_str() << std::endl;
        std::cout << "remoteInfo.Port: " << OnMessageInternal.GetPort() << std::endl;
        std::cout << "remoteInfo.Size: " << OnMessageInternal.GetSize() << std::endl;
        EXPECT_TRUE(1);
    }

    sleep(2);
    (void)server.Close([](bool ok) {EXPECT_TRUE(ok); });
    std::cout << "TlsSocketTest, tlsSocketOnMessageData end " << std::endl;
}

} } // namespace OHOS::NetStack
