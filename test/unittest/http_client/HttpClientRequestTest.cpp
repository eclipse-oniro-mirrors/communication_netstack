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
#include "curl/curl.h"
#include "netstack_log.h"
#include "gtest/gtest.h"
#define private public
#include "http_client_constant.h"
#include "http_client_request.h"

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

HWTEST_F(HttpClientRequestTest, SetSslTypeTest001, TestSize.Level1)
{
    HttpClientRequest req;

    req.SetSslType(SslType::TLS);
    SslType sslType = req.GetSslType();
    EXPECT_EQ(sslType, SslType::TLS);
}

HWTEST_F(HttpClientRequestTest, SetSslTypeTest002, TestSize.Level1)
{
    HttpClientRequest req;

    req.SetSslType(SslType::TLCP);
    SslType sslType = req.GetSslType();
    EXPECT_EQ(sslType, SslType::TLCP);
}

HWTEST_F(HttpClientRequestTest, GetClientEncCertTest001, TestSize.Level1)
{
    HttpClientRequest req;

    HttpClientCert clientEncCert = req.GetClientEncCert();
    EXPECT_EQ(clientEncCert.certPath, "");
    EXPECT_EQ(clientEncCert.certType, "");
    EXPECT_EQ(clientEncCert.keyPath, "");
    EXPECT_EQ(clientEncCert.keyPassword, "");
}

HWTEST_F(HttpClientRequestTest, SetClientEncCertTest001, TestSize.Level1)
{
    HttpClientRequest req;

    HttpClientCert clientCert;
    clientCert.certPath = "/path/to/client.pem";
    clientCert.certType = "PEM";
    clientCert.keyPath = "/path/to/client.key";
    clientCert.keyPassword = "passwordToKey";
    req.SetClientEncCert(clientCert);
    HttpClientCert client = req.GetClientEncCert();
    EXPECT_EQ(client.certPath, "/path/to/client.pem");
    EXPECT_EQ(client.certType, "PEM");
    EXPECT_EQ(client.keyPath, "/path/to/client.key");
    EXPECT_EQ(client.keyPassword, "passwordToKey");
}

HWTEST_F(HttpClientRequestTest, SetClientEncCertTest002, TestSize.Level1)
{
    HttpClientRequest req;

    HttpClientCert clientCert;
    clientCert.certPath = "/path/to/client.pem";
    req.SetClientEncCert(clientCert);
    HttpClientCert client = req.GetClientEncCert();
    EXPECT_EQ(client.certPath, "/path/to/client.pem");
    EXPECT_EQ(client.certType, "");
    EXPECT_EQ(client.keyPath, "");
    EXPECT_EQ(client.keyPassword, "");
}

HWTEST_F(HttpClientRequestTest, SetMaxLimitTest001, TestSize.Level1)
{
    HttpClientRequest req;
    req.maxLimit_ = 0;
    req.SetMaxLimit(HttpConstant::MAX_LIMIT - 1);
    EXPECT_EQ(req.maxLimit_, HttpConstant::MAX_LIMIT - 1);
    req.maxLimit_ = 0;
    req.SetMaxLimit(HttpConstant::MAX_LIMIT + 1);
    EXPECT_EQ(req.maxLimit_, HttpConstant::MAX_LIMIT);
}

HWTEST_F(HttpClientRequestTest, SetUsingCacheTest001, TestSize.Level1)
{
    HttpClientRequest req;
    req.usingCache_ = false;
    req.SetUsingCache(true);
    EXPECT_EQ(req.usingCache_, true);
}

HWTEST_F(HttpClientRequestTest, SetDNSOverHttpsTest001, TestSize.Level1)
{
    HttpClientRequest req;
    std::string dnsOverHttps = "dnsOverHttps";
    req.SetDNSOverHttps(dnsOverHttps);
    EXPECT_EQ(req.dnsOverHttps_, dnsOverHttps);
}

HWTEST_F(HttpClientRequestTest, SetRemoteValidationTest001, TestSize.Level1)
{
    HttpClientRequest req;
    req.remoteValidation_ = "";
    req.SetRemoteValidation("skip");
    EXPECT_EQ(req.remoteValidation_, "skip");
    req.remoteValidation_ = "";
    req.SetRemoteValidation("system123");
    EXPECT_EQ(req.remoteValidation_, "");
}

HWTEST_F(HttpClientRequestTest, SetCanSkipCertVerifyFlagTest001, TestSize.Level1)
{
    HttpClientRequest req;
    req.canSkipCertVerify_ = false;
    req.SetCanSkipCertVerifyFlag(true);
    EXPECT_EQ(req.canSkipCertVerify_, true);
}

HWTEST_F(HttpClientRequestTest, SetTLSOptionsTest001, TestSize.Level1)
{
    HttpClientRequest req;
    TlsOption tlsOption;
    tlsOption.tlsVersionMin = TlsVersion::TLSv1_3;
    req.SetTLSOptions(tlsOption);
    EXPECT_EQ(req.tlsOptions_.tlsVersionMin, TlsVersion::TLSv1_3);
}

HWTEST_F(HttpClientRequestTest, SetExtraDataTest001, TestSize.Level1)
{
    HttpClientRequest req;
    EscapedData data;
    data.dataType = HttpDataType::STRING;
    data.data = "extraData";
    req.SetExtraData(data);
    EXPECT_EQ(req.extraData_.dataType, HttpDataType::STRING);
    EXPECT_EQ(req.extraData_.data, "extraData");
}

HWTEST_F(HttpClientRequestTest, SetExpectDataTypeTest001, TestSize.Level1)
{
    HttpClientRequest req;
    req.dataType_ = HttpDataType::NO_DATA_TYPE;
    req.SetExpectDataType(HttpDataType::STRING);
    EXPECT_EQ(req.dataType_, HttpDataType::STRING);
    req.SetExpectDataType(HttpDataType::NO_DATA_TYPE);
    EXPECT_EQ(req.dataType_, HttpDataType::STRING);
}

HWTEST_F(HttpClientRequestTest, SetDNSServersTest001, TestSize.Level1)
{
    HttpClientRequest req;
    req.dnsServers_.clear();
    std::vector<std::string> vec;
    vec.push_back("192.168.1.1");
    req.SetDNSServers(vec);
    EXPECT_EQ(req.dnsServers_.size(), vec.size());
}

HWTEST_F(HttpClientRequestTest, AddMultiFormDataTest001, TestSize.Level1)
{
    HttpClientRequest req;
    req.multiFormDataList_.clear();
    HttpMultiFormData data;
    req.AddMultiFormData(data);
    EXPECT_EQ(req.multiFormDataList_.size(), 1);
}

HWTEST_F(HttpClientRequestTest, SetServerAuthenticationTest001, TestSize.Level1)
{
    HttpClientRequest req;
    HttpServerAuthentication data;
    data.authenticationType = HttpAuthenticationType::DIGEST;
    req.SetServerAuthentication(data);
    EXPECT_EQ(req.serverAuth_.authenticationType, HttpAuthenticationType::DIGEST);
}

HWTEST_F(HttpClientRequestTest, GetRemoteValidationTest001, TestSize.Level1)
{
    HttpClientRequest req;
    req.remoteValidation_ = "system";
    std::string str = req.GetRemoteValidation();
    EXPECT_EQ(str, "system");
}

HWTEST_F(HttpClientRequestTest, GetMultiFormDataListTest001, TestSize.Level1)
{
    HttpClientRequest req;
    req.multiFormDataList_.clear();
    req.multiFormDataList_.emplace_back(HttpMultiFormData());
    auto ret = req.GetMultiFormDataList();
    EXPECT_EQ(ret.size(), req.multiFormDataList_.size());
}

HWTEST_F(HttpClientRequestTest, GetHttpVersionTest001, TestSize.Level1)
{
    HttpClientRequest req;
    req.protocol_ = HttpProtocol::HTTP1_1;
    auto ret = req.GetHttpVersion();
    EXPECT_EQ(ret, CURL_HTTP_VERSION_1_1);

    req.protocol_ = HttpProtocol::HTTP2;
    ret = req.GetHttpVersion();
    EXPECT_EQ(ret, CURL_HTTP_VERSION_2_0);

    req.protocol_ = HttpProtocol::HTTP3;
    ret = req.GetHttpVersion();
    EXPECT_EQ(ret, CURL_HTTP_VERSION_3);

    req.protocol_ = HttpProtocol::HTTP_NONE;
    ret = req.GetHttpVersion();
    EXPECT_EQ(ret, CURL_HTTP_VERSION_NONE);
}
} // namespace
