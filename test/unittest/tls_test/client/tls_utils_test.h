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

#ifndef TLS_UTILS_TEST_H
#define TLS_UTILS_TEST_H

#include <fstream>
#include <gtest/gtest.h>
#include <iostream>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <sstream>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>

namespace OHOS {
namespace NetStack {
namespace TlsSocket {
const std::string_view PRIVATE_KEY_PEM = "/data/ClientCert/client_rsa_private.pem.unsecure";
const std::string_view CA_DER = "/data/ClientCert/ca.crt";
const std::string_view CLIENT_CRT = "/data/ClientCert/client.crt";
const std::string_view IP_ADDRESS = "/data/Ip/address.txt";
const std::string_view PORT = "/data/Ip/port.txt";
const std::string_view PRIVATE_KEY_PEM_CHAIN = "/data/ClientCertChain/privekey.pem.unsecure";
const std::string_view CA_PATH_CHAIN = "/data/ClientCertChain/cacert.crt";
const std::string_view MID_CA_PATH_CHAIN = "/data/ClientCertChain/caMidcert.crt";
const std::string_view CLIENT_CRT_CHAIN = "/data/ClientCertChain/secondServer.crt";
const std::string_view ROOT_CA_PATH_CHAIN = "/data/ClientCertChain/RootCa.pem";
const std::string_view MID_CA_CHAIN = "/data/ClientCertChain/MidCa.pem";

class TlsUtilsTest {
public:
    TlsUtilsTest();
    ~TlsUtilsTest();

    static std::string ChangeToFile(const std::string_view fileName);
    static std::string GetIp(std::string ip);
    static bool CheckCaFileExistence(const char *function);
    static bool CheckCaPathChainExistence(const char *function);
};

class TlsSocketTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};
} // namespace TlsSocket
} // namespace NetStack
} // namespace OHOS
#endif // TLS_UTILS_TEST_H
