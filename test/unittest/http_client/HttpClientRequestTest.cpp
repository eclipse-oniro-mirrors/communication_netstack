/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include "http_client_request.h"
#include "http_client_constant.h"
#include "netstack_log.h"

using namespace OHOS::NetStack::HttpClient;

class HttpClientRequestTest : public testing::Test {
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
static constexpr const uint32_t HTTP_DEFAULT_PRIORITY = 500;

HWTEST_F(HttpClientRequestTest, GetCaPathTest001, TestSize.Level1)
{
    HttpClientRequest req;

    string path = req.GetCaPath();
    EXPECT_EQ(path, "");
}

HWTEST_F(HttpClientRequestTest, SetCaPathTest001, TestSize.Level1)
{
    HttpClientRequest req;

    req.SetCaPath("");
    string path = req.GetCaPath();

    EXPECT_EQ(path, "");
}

HWTEST_F(HttpClientRequestTest, SetCaPathTest002, TestSize.Level1)
{
    HttpClientRequest req;

    req.SetCaPath(OTHER_CA_PATH);
    string path = req.GetCaPath();

    EXPECT_EQ(path, OTHER_CA_PATH);
}

HWTEST_F(HttpClientRequestTest, GetURLTest001, TestSize.Level1)
{
    HttpClientRequest req;

    string urlTest = req.GetURL();
    EXPECT_EQ(urlTest, "");
}

HWTEST_F(HttpClientRequestTest, SetURLTest001, TestSize.Level1)
{
    HttpClientRequest req;
    std::string url = "http://www.httpbin.org/get";
    req.SetURL(url);
    string urlTest = req.GetURL();
    EXPECT_EQ(urlTest, url);
}

HWTEST_F(HttpClientRequestTest, GetMethodTest001, TestSize.Level1)
{
    HttpClientRequest req;

    string method = req.GetMethod();
    EXPECT_EQ(method, HttpConstant::HTTP_METHOD_GET);
}

HWTEST_F(HttpClientRequestTest, SetMethodTest001, TestSize.Level1)
{
    HttpClientRequest req;
    req.SetMethod("abc");
    string method = req.GetMethod();
    NETSTACK_LOGI("SetMethodTest001 GetMethod = %{public}s", method.c_str());
    EXPECT_EQ(method, HttpConstant::HTTP_METHOD_GET);
}

HWTEST_F(HttpClientRequestTest, SetMethodTest002, TestSize.Level1)
{
    HttpClientRequest req;
    req.SetMethod(HttpConstant::HTTP_METHOD_POST);
    string method = req.GetMethod();
    EXPECT_EQ(method, HttpConstant::HTTP_METHOD_POST);
}

HWTEST_F(HttpClientRequestTest, GetBodyTest001, TestSize.Level1)
{
    HttpClientRequest req;
    std::string body = "";

    string bodyTest = req.GetBody();
    EXPECT_EQ(bodyTest, body);
}

HWTEST_F(HttpClientRequestTest, SetBodyTest001, TestSize.Level1)
{
    HttpClientRequest req;
    std::string body = "hello world";

    req.SetBody(body.data(), body.length());
    string bodyTest = req.GetBody();

    EXPECT_EQ(bodyTest, body);
}

HWTEST_F(HttpClientRequestTest, GetTimeoutTest001, TestSize.Level1)
{
    HttpClientRequest req;

    int timeouTest = req.GetTimeout();
    EXPECT_EQ(timeouTest, HttpConstant::DEFAULT_READ_TIMEOUT);
}

HWTEST_F(HttpClientRequestTest, SetTimeoutTest001, TestSize.Level1)
{
    HttpClientRequest req;
    req.SetTimeout(1000);
    int timeouTest = req.GetTimeout();
    EXPECT_EQ(timeouTest, 1000);
}

HWTEST_F(HttpClientRequestTest, GetConnectTimeoutTest001, TestSize.Level1)
{
    HttpClientRequest req;

    int timeouTest = req.GetConnectTimeout();
    EXPECT_EQ(timeouTest, HttpConstant::DEFAULT_CONNECT_TIMEOUT);
}

HWTEST_F(HttpClientRequestTest, SetConnectTimeoutTest001, TestSize.Level1)
{
    HttpClientRequest req;
    req.SetConnectTimeout(1000);
    int timeouTest = req.GetConnectTimeout();
    EXPECT_EQ(timeouTest, 1000);
}

HWTEST_F(HttpClientRequestTest, GetHttpProtocolTest001, TestSize.Level1)
{
    HttpClientRequest req;

    int timeouTest = req.GetHttpProtocol();
    EXPECT_EQ(timeouTest, HttpProtocol::HTTP_NONE);
}

HWTEST_F(HttpClientRequestTest, SetHttpProtocolTest001, TestSize.Level1)
{
    HttpClientRequest req;
    req.SetHttpProtocol(HttpProtocol::HTTP1_1);
    int protocolTest = req.GetHttpProtocol();
    EXPECT_EQ(protocolTest, HttpProtocol::HTTP1_1);
}

HWTEST_F(HttpClientRequestTest, GetHttpProxyTest001, TestSize.Level1)
{
    HttpClientRequest req;

    const OHOS::NetStack::HttpClient::HttpProxy &proxyType = req.GetHttpProxy();
    EXPECT_EQ(proxyType.host, "");
}

HWTEST_F(HttpClientRequestTest, SetHttpProxyTest001, TestSize.Level1)
{
    HttpClientRequest req;
    HttpProxy proxy;
    proxy.host = "192.168.147.60";
    req.SetHttpProxy(proxy);
    const OHOS::NetStack::HttpClient::HttpProxy &proxyType = req.GetHttpProxy();
    EXPECT_EQ(proxyType.host, proxy.host);
}

HWTEST_F(HttpClientRequestTest, GetHttpProxyTypeTest001, TestSize.Level1)
{
    HttpClientRequest req;

    int proxyType = req.GetHttpProxyType();
    EXPECT_EQ(proxyType, HttpProxyType::NOT_USE);
}

HWTEST_F(HttpClientRequestTest, SetHttpProxyTypeTest001, TestSize.Level1)
{
    HttpClientRequest req;
    req.SetHttpProxyType(HttpProxyType::USE_SPECIFIED);
    int proxyType = req.GetHttpProxyType();
    EXPECT_EQ(proxyType, HttpProxyType::USE_SPECIFIED);
}

HWTEST_F(HttpClientRequestTest, GetPriorityTest001, TestSize.Level1)
{
    HttpClientRequest req;

    uint32_t priorityTest = req.GetPriority();
    EXPECT_EQ(priorityTest, HTTP_DEFAULT_PRIORITY);
}

HWTEST_F(HttpClientRequestTest, SetPriorityTest001, TestSize.Level1)
{
    HttpClientRequest req;
    req.SetPriority(0);
    uint32_t priorityTest = req.GetPriority();
    EXPECT_EQ(priorityTest, HTTP_DEFAULT_PRIORITY);
}

HWTEST_F(HttpClientRequestTest, SetPriorityTest002, TestSize.Level1)
{
    HttpClientRequest req;

    req.SetPriority(1001);
    uint32_t priorityTest = req.GetPriority();

    EXPECT_EQ(priorityTest, HTTP_DEFAULT_PRIORITY);
}

HWTEST_F(HttpClientRequestTest, SetPriorityTest003, TestSize.Level1)
{
    HttpClientRequest req;

    req.SetPriority(500);
    uint32_t priorityTest = req.GetPriority();

    EXPECT_EQ(priorityTest, HTTP_DEFAULT_PRIORITY);
}

HWTEST_F(HttpClientRequestTest, GetHeaderTest001, TestSize.Level1)
{
    HttpClientRequest req;

    std::map<std::string, std::string> headers = req.GetHeaders();
    EXPECT_EQ(headers.empty(), true);
}

HWTEST_F(HttpClientRequestTest, SetHeaderTest001, TestSize.Level1)
{
    HttpClientRequest req;

    std::string header = "application/json";
    req.SetHeader("content-type", "application/json");
    std::map<std::string, std::string> headers = req.GetHeaders();
    EXPECT_EQ(headers["content-type"], header);
}

HWTEST_F(HttpClientRequestTest, MethodForGetTest001, TestSize.Level1)
{
    HttpClientRequest req;
    bool method = req.MethodForGet("");
    EXPECT_EQ(method, false);
}

HWTEST_F(HttpClientRequestTest, MethodForGetTest002, TestSize.Level1)
{
    HttpClientRequest req;
    bool method = req.MethodForGet("GET");
    EXPECT_EQ(method, true);
}

HWTEST_F(HttpClientRequestTest, MethodForPostTest001, TestSize.Level1)
{
    HttpClientRequest req;
    bool method = req.MethodForPost("");
    EXPECT_EQ(method, false);
}

HWTEST_F(HttpClientRequestTest, MethodForPostTest002, TestSize.Level1)
{
    HttpClientRequest req;
    bool method = req.MethodForPost("POST");
    EXPECT_EQ(method, true);
}

HWTEST_F(HttpClientRequestTest, GetResumeFromTest001, TestSize.Level1)
{
    HttpClientRequest req;

    int64_t resumeFrom = req.GetResumeFrom();
    EXPECT_EQ(resumeFrom, 0);
}

HWTEST_F(HttpClientRequestTest, SetResumeFromTest001, TestSize.Level1)
{
    HttpClientRequest req;

    req.SetResumeFrom(1000);
    int64_t resumeFrom = req.GetResumeFrom();
    EXPECT_EQ(resumeFrom, 1000);
}

HWTEST_F(HttpClientRequestTest, SetResumeFromTest002, TestSize.Level1)
{
    HttpClientRequest req;

    req.SetResumeFrom(-10);
    int64_t resumeFrom = req.GetResumeFrom();
    EXPECT_EQ(resumeFrom, 0);
}

HWTEST_F(HttpClientRequestTest, SetResumeFromTest003, TestSize.Level1)
{
    HttpClientRequest req;

    req.SetResumeFrom(MAX_RESUM_NUMBER + 5);
    int64_t resumeFrom = req.GetResumeFrom();
    EXPECT_EQ(resumeFrom, 0);
}

HWTEST_F(HttpClientRequestTest, GetResumeToTest001, TestSize.Level1)
{
    HttpClientRequest req;

    int64_t resumeFrom = req.GetResumeTo();
    EXPECT_EQ(resumeFrom, 0);
}

HWTEST_F(HttpClientRequestTest, SetResumeToTest001, TestSize.Level1)
{
    HttpClientRequest req;

    req.SetResumeTo(1000);
    int64_t resumeTo = req.GetResumeTo();
    EXPECT_EQ(resumeTo, 1000);
}

HWTEST_F(HttpClientRequestTest, SetResumeToTest002, TestSize.Level1)
{
    HttpClientRequest req;

    req.SetResumeTo(-10);
    int64_t resumeTo = req.GetResumeTo();
    EXPECT_EQ(resumeTo, 0);
}

HWTEST_F(HttpClientRequestTest, SetResumeToTest003, TestSize.Level1)
{
    HttpClientRequest req;

    req.SetResumeTo(MAX_RESUM_NUMBER + 5);
    int64_t resumeTo = req.GetResumeTo();
    EXPECT_EQ(resumeTo, 0);
}

HWTEST_F(HttpClientRequestTest, SetAddressFamilyTest001, TestSize.Level1)
{
    HttpClientRequest req;

    req.SetAddressFamily("DEFAULT");
    std::string addressFamily = req.GetAddressFamily();
    EXPECT_EQ(addressFamily, "DEFAULT");
}

HWTEST_F(HttpClientRequestTest, GetAddressFamilyTest001, TestSize.Level1)
{
    HttpClientRequest req;

    std::string addressFamily = req.GetAddressFamily();
    EXPECT_EQ(addressFamily.empty(), true);
}

HWTEST_F(HttpClientRequestTest, GetClientCertTest001, TestSize.Level1)
{
    HttpClientRequest req;

    HttpClientCert clientCert = req.GetClientCert();
    EXPECT_EQ(clientCert.certPath, "");
}

HWTEST_F(HttpClientRequestTest, SetClientCertTest001, TestSize.Level1)
{
    HttpClientRequest req;

    HttpClientCert clientCert;
    clientCert.certPath = "/path/to/client.pem";
    clientCert.certType = "PEM";
    clientCert.keyPath = "/path/to/client.key";
    clientCert.keyPassword = "passwordToKey";
    req.SetClientCert(clientCert);
    HttpClientCert client = req.GetClientCert();
    EXPECT_EQ(client.keyPassword, "passwordToKey");
}

HWTEST_F(HttpClientRequestTest, SetClientCertTest002, TestSize.Level1)
{
    HttpClientRequest req;

    HttpClientCert clientCert;
    clientCert.certPath = "/path/to/client.pem";
    req.SetClientCert(clientCert);
    HttpClientCert client = req.GetClientCert();
    EXPECT_EQ(client.keyPassword, "");
}

HWTEST_F(HttpClientRequestTest, SetMaxLimitTest001, TestSize.Level1)
{
    HttpClientRequest req;

    req.SetMaxLimit(100);
    uint32_t maxLimit = req.GetMaxLimit();
    EXPECT_EQ(maxLimit, 100);
}

HWTEST_F(HttpClientRequestTest, GetMaxLimitTest001, TestSize.Level1)
{
    HttpClientRequest req;

    uint32_t maxLimit = req.GetMaxLimit();
    EXPECT_EQ(maxLimit, 0);
}
} // namespace
