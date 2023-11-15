/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <cstring>

#include "gtest/gtest.h"
#include "http_request_options.h"
#include "netstack_log.h"
#include "secure_char.h"

using namespace OHOS::NetStack;
using namespace OHOS::NetStack::Http;

class HttpRequestOptionsTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

namespace {
using namespace std;
using namespace testing::ext;
constexpr char OTHER_CA_PATH[] = "/etc/ssl/certs/other.pem";

HWTEST_F(HttpRequestOptionsTest, CaPathTest001, TestSize.Level1)
{
    HttpRequestOptions requestOptions;

    string path = requestOptions.GetCaPath();
    EXPECT_EQ(path, HttpConstant::HTTP_DEFAULT_CA_PATH);
}

HWTEST_F(HttpRequestOptionsTest, CaPathTest002, TestSize.Level1)
{
    HttpRequestOptions requestOptions;

    requestOptions.SetCaPath("");
    string path = requestOptions.GetCaPath();
    EXPECT_EQ(path, HttpConstant::HTTP_DEFAULT_CA_PATH);
}

HWTEST_F(HttpRequestOptionsTest, CaPathTest003, TestSize.Level1)
{
    HttpRequestOptions requestOptions;

    requestOptions.SetCaPath(OTHER_CA_PATH);
    string path = requestOptions.GetCaPath();
    EXPECT_EQ(path, OTHER_CA_PATH);
}

HWTEST_F(HttpRequestOptionsTest, SetDnsServersTest, TestSize.Level1)
{
    HttpRequestOptions requestOptions;

    std::vector<std::string> dnsServers = { "8.8.8.8", "8.8.4.4" };
    requestOptions.SetDnsServers(dnsServers);

    const std::vector<std::string>& retrievedDnsServers = requestOptions.GetDnsServers();
    EXPECT_EQ(retrievedDnsServers, dnsServers);
}

HWTEST_F(HttpRequestOptionsTest, SetDohUrlTest, TestSize.Level1)
{
    HttpRequestOptions requestOptions;

    std::string dohUrl = "https://example.com/dns-query";
    requestOptions.SetDohUrl(dohUrl);

    const std::string& retrievedDohUrl = requestOptions.GetDohUrl();
    EXPECT_EQ(retrievedDohUrl, dohUrl);
}

HWTEST_F(HttpRequestOptionsTest, SetRangeNumberTest001, TestSize.Level1)
{
    HttpRequestOptions requestOptions;

    uint32_t resumeFromNumber = 10;
    uint32_t resumeToNumber = 20;
    requestOptions.SetRangeNumber(resumeFromNumber, resumeToNumber);

    const std::string& rangeString = requestOptions.GetRangeString();
    std::string expectedRangeString = "10-20";
    EXPECT_EQ(rangeString, expectedRangeString);
}

HWTEST_F(HttpRequestOptionsTest, SetRangeNumberTest002, TestSize.Level1)
{
    HttpRequestOptions requestOptions;

    uint32_t resumeFromNumber = 0;
    uint32_t resumeToNumber = 20;
    requestOptions.SetRangeNumber(resumeFromNumber, resumeToNumber);

    const std::string& rangeString = requestOptions.GetRangeString();
    std::string expectedRangeString = "-20";
    EXPECT_EQ(rangeString, expectedRangeString);
}

HWTEST_F(HttpRequestOptionsTest, SetRangeNumberTest003, TestSize.Level1)
{
    HttpRequestOptions requestOptions;

    uint32_t resumeFromNumber = 10;
    uint32_t resumeToNumber = 0;
    requestOptions.SetRangeNumber(resumeFromNumber, resumeToNumber);

    const std::string& rangeString = requestOptions.GetRangeString();
    std::string expectedRangeString = "10-";
    EXPECT_EQ(rangeString, expectedRangeString);
}

HWTEST_F(HttpRequestOptionsTest, SetRangeNumberTest004, TestSize.Level1)
{
    HttpRequestOptions requestOptions;

    uint32_t resumeFromNumber = 0;
    uint32_t resumeToNumber = 0;
    requestOptions.SetRangeNumber(resumeFromNumber, resumeToNumber);

    const std::string& rangeString = requestOptions.GetRangeString();
    std::string expectedRangeString = "";
    EXPECT_EQ(rangeString, expectedRangeString);
}

HWTEST_F(HttpRequestOptionsTest, SetClientCertTest, TestSize.Level1)
{
    HttpRequestOptions requestOptions;

    std::string cert = "path_to_cert.pem";
    std::string key = "path_to_key.pem";
    std::string certType = "PEM";
    Secure::SecureChar keyPasswd("password");

    requestOptions.SetClientCert(cert, certType, key, keyPasswd);

    std::string retrievedCert;
    std::string retrievedKey;
    std::string retrievedCertType;
    Secure::SecureChar retrievedKeyPasswd;

    requestOptions.GetClientCert(retrievedCert, retrievedCertType, retrievedKey, retrievedKeyPasswd);

    EXPECT_EQ(retrievedCert, cert);
    EXPECT_EQ(retrievedKey, key);
    EXPECT_EQ(retrievedCertType, certType);
    EXPECT_EQ(strcmp(retrievedKeyPasswd.Data(), keyPasswd.Data()), 0);
}
} // namespace