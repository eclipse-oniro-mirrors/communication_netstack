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
#include "constant.h"
#include "secure_char.h"
#include "curl/curl.h"

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

HWTEST_F(HttpRequestOptionsTest, AddMultiFormDataTest, TestSize.Level1)
{
    HttpRequestOptions requestOptions;
    for (int i = 0; i < 10; i++) {
        MultiFormData multiFormData;
        multiFormData.name = "name" + std::to_string(i);
        multiFormData.data = "data" + std::to_string(i);
        multiFormData.contentType = "contentType" + std::to_string(i);
        multiFormData.remoteFileName = "remoteFileName" + std::to_string(i);
        multiFormData.filePath = "filePath" + std::to_string(i);
        requestOptions.AddMultiFormData(multiFormData);
    }
    std::vector<MultiFormData> dataList = requestOptions.GetMultiPartDataList();
    EXPECT_EQ(dataList.size(), 10);
    for (int i = 0; i < 10; i++) {
        MultiFormData data = dataList[i];
        EXPECT_EQ(data.name, "name" + std::to_string(i));
        EXPECT_EQ(data.data, "data" + std::to_string(i));
        EXPECT_EQ(data.contentType, "contentType" + std::to_string(i));
        EXPECT_EQ(data.filePath, "filePath" + std::to_string(i));
        EXPECT_EQ(data.remoteFileName, "remoteFileName" + std::to_string(i));
    }
}

HWTEST_F(HttpRequestOptionsTest, SetUrlTest, TestSize.Level1)
{
    HttpRequestOptions requestOptions;

    std::string testValue = "Example";
    requestOptions.SetUrl(testValue);
    std::string url = requestOptions.GetUrl();
    EXPECT_EQ(url, testValue);
}

HWTEST_F(HttpRequestOptionsTest, SetPrioritylTest, TestSize.Level1)
{
    HttpRequestOptions requestOptions;

    uint32_t testValue = 2;
    requestOptions.SetPriority(testValue);
    uint32_t resultValue = requestOptions.GetPriority();
    EXPECT_EQ(resultValue, testValue);
}

HWTEST_F(HttpRequestOptionsTest, SetHttpDataTypeTest, TestSize.Level1)
{
    HttpRequestOptions requestOptions;

    HttpDataType testValue = HttpDataType::ARRAY_BUFFER;
    requestOptions.SetHttpDataType(testValue);
    HttpDataType resultValue = requestOptions.GetHttpDataType();
    EXPECT_EQ(resultValue, testValue);
}

HWTEST_F(HttpRequestOptionsTest, SetUsingProtocolTest001, TestSize.Level1)
{
    HttpRequestOptions requestOptions;

    HttpProtocol testValue = HttpProtocol::HTTP1_1;
    requestOptions.SetUsingProtocol(testValue);
    uint32_t resultValue = requestOptions.GetHttpVersion();
    EXPECT_EQ(resultValue, CURL_HTTP_VERSION_1_1);
}

HWTEST_F(HttpRequestOptionsTest, SetUsingProtocolTest002, TestSize.Level1)
{
    HttpRequestOptions requestOptions;

    HttpProtocol testValue = HttpProtocol::HTTP2;
    requestOptions.SetUsingProtocol(testValue);
    uint32_t resultValue = requestOptions.GetHttpVersion();
    EXPECT_EQ(resultValue, CURL_HTTP_VERSION_2_0);
}

HWTEST_F(HttpRequestOptionsTest, SetUsingProtocolTest003, TestSize.Level1)
{
    HttpRequestOptions requestOptions;

    HttpProtocol testValue = HttpProtocol::HTTP3;
    requestOptions.SetUsingProtocol(testValue);
    uint32_t resultValue = requestOptions.GetHttpVersion();
    EXPECT_EQ(resultValue, CURL_HTTP_VERSION_3);
}

HWTEST_F(HttpRequestOptionsTest, SetUsingProtocolTest004, TestSize.Level1)
{
    HttpRequestOptions requestOptions;

    HttpProtocol testValue = HttpProtocol::HTTP_NONE;
    requestOptions.SetUsingProtocol(testValue);
    uint32_t resultValue = requestOptions.GetHttpVersion();
    EXPECT_EQ(resultValue, CURL_HTTP_VERSION_NONE);
}

HWTEST_F(HttpRequestOptionsTest, SetMaxLimitTest, TestSize.Level1)
{
    HttpRequestOptions requestOptions;

    uint32_t testValue = 50;
    requestOptions.SetMaxLimit(testValue);
    uint32_t resultValue = requestOptions.GetMaxLimit();
    EXPECT_EQ(resultValue, testValue);
}

HWTEST_F(HttpRequestOptionsTest, SetConnectTimeoutTest, TestSize.Level1)
{
    HttpRequestOptions requestOptions;

    uint32_t testValue = 5000;
    requestOptions.SetConnectTimeout(testValue);
    uint32_t resultValue = requestOptions.GetConnectTimeout();
    EXPECT_EQ(resultValue, testValue);
}

HWTEST_F(HttpRequestOptionsTest, SetReadTimeoutTest, TestSize.Level1)
{
    HttpRequestOptions requestOptions;

    uint32_t testValue = 5000;
    requestOptions.SetReadTimeout(testValue);
    uint32_t resultValue = requestOptions.GetReadTimeout();
    EXPECT_EQ(resultValue, testValue);
}

HWTEST_F(HttpRequestOptionsTest, SetHeaderTest, TestSize.Level1)
{
    HttpRequestOptions requestOptions;

    int testSize = 10;
    for (int i = 0; i < testSize; i++) {
        requestOptions.SetHeader("key" + std::to_string(i), "value" + std::to_string(i));
    }
    const std::map<std::string, std::string> header = requestOptions.GetHeader();
    for (int i = 0; i < testSize; i++) {
        const std::string& value = header.at("key" + std::to_string(i));
        EXPECT_EQ(value, "value" + std::to_string(i));
    }
}

HWTEST_F(HttpRequestOptionsTest, SetBodyTest, TestSize.Level1)
{
    HttpRequestOptions requestOptions;

    std::string testValue = "TestBody";
    requestOptions.SetBody(testValue.data(), testValue.size());
    std::string resultValue = requestOptions.GetBody();
    EXPECT_EQ(resultValue, testValue);
}
} // namespace