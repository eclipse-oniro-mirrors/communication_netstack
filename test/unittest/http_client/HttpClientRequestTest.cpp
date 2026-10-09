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

HWTEST_F(HttpClientRequestTest, SetHttpProxyTest002, TestSize.Level1)
{
    HttpClientRequest req;
    HttpProxy proxy;
    proxy.host = "192.168.147.60";
    proxy.port = 8888;
    proxy.exclusions = "www.test.org,127.0.0.1";
    proxy.username.assign("user");
    proxy.password.assign("password");
    proxy.tunnel = true;
    req.SetHttpProxy(proxy);

    const HttpProxy &actual = req.GetHttpProxy();
    EXPECT_EQ(actual.host, proxy.host);
    EXPECT_EQ(actual.port, proxy.port);
    EXPECT_EQ(actual.exclusions, proxy.exclusions);
    EXPECT_EQ(actual.username, proxy.username);
    EXPECT_EQ(actual.password, proxy.password);
    EXPECT_TRUE(actual.tunnel);
}

HWTEST_F(HttpClientRequestTest, SetHttpProxyTest003, TestSize.Level1)
{
    HttpClientRequest req;
    HttpProxy proxy;
    proxy.host = "192.168.147.60";
    proxy.port = 8888;
    proxy.exclusions = "www.test.org";
    proxy.username.assign("user");
    proxy.password.assign("password");
    proxy.tunnel = true;
    req.SetHttpProxy(proxy);

    req.SetHttpProxy(HttpProxy());
    const HttpProxy &actual = req.GetHttpProxy();
    EXPECT_TRUE(actual.host.empty());
    EXPECT_EQ(actual.port, 0);
    EXPECT_TRUE(actual.exclusions.empty());
    EXPECT_TRUE(actual.username.empty());
    EXPECT_TRUE(actual.password.empty());
    EXPECT_FALSE(actual.tunnel);
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
    SecureData keyPasswordData;
    std::string pwd = "passwordToKey";
    keyPasswordData.append(pwd.c_str());
    clientCert.keyPassword = keyPasswordData;
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
    SecureData keyPasswordData;
    std::string pwd = "passwordToKey";
    keyPasswordData.append(pwd.c_str());
    clientCert.keyPassword = keyPasswordData;
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

HWTEST_F(HttpClientRequestTest, ReplaceBodyTest001, TestSize.Level1)
{
    const char *testData = "test replace body";
    size_t testLen = strlen(testData);
    HttpClientRequest request_;
    EXPECT_EQ(request_.GetBody().empty(), true);
    request_.ReplaceBody(testData, testLen);
    EXPECT_EQ(request_.GetBody(), std::string(testData));
    EXPECT_EQ(request_.GetBody().length(), testLen);
}

HWTEST_F(HttpClientRequestTest, ReplaceBodyTest002, TestSize.Level1)
{
    HttpClientRequest request_;
    const char *initData = "initial body";
    request_.SetBody(initData, strlen(initData));
    EXPECT_EQ(request_.GetBody(), std::string(initData));
    const char *newData = "new replaced body";
    size_t newLen = strlen(newData);
    request_.ReplaceBody(newData, newLen);
    EXPECT_EQ(request_.GetBody(), std::string(newData));
    EXPECT_EQ(request_.GetBody().length(), newLen);
    EXPECT_NE(request_.GetBody(), std::string(initData));
}

HWTEST_F(HttpClientRequestTest, ReplaceBodyTest003, TestSize.Level1)
{
    HttpClientRequest request_;
    const char *emptyData = "";
    size_t emptyLen = 0;
    request_.SetBody("test", 4);
    EXPECT_EQ(request_.GetBody().empty(), false);
    request_.ReplaceBody(emptyData, emptyLen);
    EXPECT_EQ(request_.GetBody().empty(), true);
    EXPECT_EQ(request_.GetBody().length(), 0);
}

HWTEST_F(HttpClientRequestTest, SetRawHeaderTest001, TestSize.Level1)
{
    HttpClientRequest request_;
    const std::string rawHeader = "Content-Type: application/json\r\nAccept: */*";
    request_.SetRawHeader(rawHeader);
    EXPECT_EQ(request_.GetRawHeader(), rawHeader);
}

HWTEST_F(HttpClientRequestTest, SetRawHeaderTest002, TestSize.Level1)
{
    HttpClientRequest request_;
    const std::string emptyHeader = "";
    request_.SetRawHeader("test header");
    EXPECT_NE(request_.GetRawHeader(), emptyHeader);
    request_.SetRawHeader(emptyHeader);
    EXPECT_EQ(request_.GetRawHeader(), emptyHeader);
}

HWTEST_F(HttpClientRequestTest, SetRawHeaderTest003, TestSize.Level1)
{
    HttpClientRequest request_;
    const std::string header1 = "header1: value1";
    const std::string header2 = "header2: value2";
    request_.SetRawHeader(header1);
    EXPECT_EQ(request_.GetRawHeader(), header1);
    request_.SetRawHeader(header2);
    EXPECT_EQ(request_.GetRawHeader(), header2);
    EXPECT_NE(request_.GetRawHeader(), header1);
}

HWTEST_F(HttpClientRequestTest, ParseHeadersTest001, TestSize.Level1)
{
    HttpClientRequest request_;
    const std::string rawHeader = "Content-Type: application/json\r\n"
                                  "Accept: */*\r\n"
                                  "User-Agent: test-client\r\n"
                                  "X-Request-Id: 123456\r\n\r\n";
    request_.SetRawHeader(rawHeader);
    request_.ParseHeaders();
    const auto &headers = request_.GetHeaders();
    EXPECT_EQ(headers.at("content-type"), "application/json");
    EXPECT_EQ(headers.at("accept"), "*/*");
    EXPECT_EQ(headers.at("user-agent"), "test-client");
    EXPECT_EQ(headers.at("x-request-id"), "123456");
}

HWTEST_F(HttpClientRequestTest, ParseHeadersTest002, TestSize.Level1)
{
    HttpClientRequest request_;
    EXPECT_EQ(request_.GetHeaders().empty(), true);
    request_.SetRawHeader("");
    request_.ParseHeaders();
    EXPECT_EQ(request_.GetHeaders().empty(), true);
}

HWTEST_F(HttpClientRequestTest, ClearHeaderCacheTest001, TestSize.Level1)
{
    HttpClientRequest request_;
    const std::string rawHeader = "Content-Type: application/json\r\nAccept: */*";
    request_.SetRawHeader(rawHeader);
    request_.ParseHeaders();
    EXPECT_EQ(request_.GetHeaders().empty(), false);
    EXPECT_EQ(request_.GetHeaders().size(), 2);
    request_.ClearHeaderCache();
    EXPECT_EQ(request_.GetHeaders().empty(), true);
}

HWTEST_F(HttpClientRequestTest, ClearHeaderCacheTest002, TestSize.Level1)
{
    HttpClientRequest request_;
    EXPECT_EQ(request_.GetHeaders().empty(), true);
    request_.ClearHeaderCache();
    EXPECT_EQ(request_.GetHeaders().empty(), true);
}

HWTEST_F(HttpClientRequestTest, HttpProxyCredentialTest001, TestSize.Level1)
{
    HttpProxy proxy;
    EXPECT_EQ(proxy.username, "");
    EXPECT_EQ(proxy.password, "");

    proxy.host = "192.168.147.60";
    proxy.port = 8888;
    proxy.username.assign("user");
    proxy.password.assign("password");

    HttpClientRequest req;
    req.SetHttpProxy(proxy);
    const HttpProxy &proxyType = req.GetHttpProxy();
    EXPECT_EQ(proxyType.username, proxy.username);
    EXPECT_EQ(proxyType.password, proxy.password);
}

HWTEST_F(HttpClientRequestTest, HttpMethodPatchTest001, TestSize.Level1)
{
    EXPECT_EQ(std::string(HttpConstant::HTTP_METHOD_PATCH), "PATCH");

    HttpClientRequest req;
    req.SetMethod(HttpConstant::HTTP_METHOD_PATCH);
    EXPECT_EQ(req.GetMethod(), HttpConstant::HTTP_METHOD_PATCH);
}

HWTEST_F(HttpClientRequestTest, SetValidationCallbackTest001, TestSize.Level1)
{
    HttpClientRequest req;
    EXPECT_FALSE(req.GetValidationCallback());

    bool invoked = false;
    req.SetValidationCallback([&invoked](const std::vector<std::string> &pemCerts, const std::string &host,
                                         const std::string &ip) {
        invoked = true;
        return !pemCerts.empty() && !host.empty() && !ip.empty();
    });

    const ValidationCallback &callback = req.GetValidationCallback();
    EXPECT_TRUE(callback);
    EXPECT_TRUE(callback({"cert"}, "example.com", "127.0.0.1"));
    EXPECT_TRUE(invoked);
}

HWTEST_F(HttpClientRequestTest, SetEnableAutoCookieTest001, TestSize.Level1)
{
    HttpClientRequest req;
    EXPECT_FALSE(req.GetEnableAutoCookie());

    req.SetEnableAutoCookie(true);
    EXPECT_TRUE(req.GetEnableAutoCookie());

    req.SetEnableAutoCookie(false);
    EXPECT_FALSE(req.GetEnableAutoCookie());
}

HWTEST_F(HttpClientRequestTest, SetMaxRedirectsTest001, TestSize.Level1)
{
    HttpClientRequest req;
    req.SetMaxRedirects(0);
    EXPECT_EQ(req.GetMaxRedirects(), 0);

    req.SetMaxRedirects(15);
    EXPECT_EQ(req.GetMaxRedirects(), 15);
    EXPECT_EQ(req.maxRedirects_, 15);
}

HWTEST_F(HttpClientRequestTest, SetSniHostNameTest001, TestSize.Level1)
{
    HttpClientRequest req;
    EXPECT_EQ(req.GetSniHostName(), "");

    std::string sniHostName = "sni.example.com";
    req.SetSniHostName(sniHostName);
    EXPECT_EQ(req.GetSniHostName(), sniHostName);
}

HWTEST_F(HttpClientRequestTest, SetReuseConnectionsTest001, TestSize.Level1)
{
    HttpClientRequest req;
    EXPECT_TRUE(req.GetReuseConnections());

    req.SetReuseConnections(false);
    EXPECT_FALSE(req.GetReuseConnections());

    req.SetReuseConnections(true);
    EXPECT_TRUE(req.GetReuseConnections());
}

HWTEST_F(HttpClientRequestTest, SetInactivityMsTest001, TestSize.Level1)
{
    HttpClientRequest req;
    EXPECT_EQ(req.GetInactivityMs(), 0u);

    req.SetInactivityMs(60000);
    EXPECT_EQ(req.GetInactivityMs(), 60000u);
}

HWTEST_F(HttpClientRequestTest, SetBodyOrQueryConfiguredTest001, TestSize.Level1)
{
    HttpClientRequest req;
    EXPECT_FALSE(req.GetBodyOrQueryConfigured());

    req.SetBodyOrQueryConfigured(true);
    EXPECT_TRUE(req.GetBodyOrQueryConfigured());
}

HWTEST_F(HttpClientRequestTest, SetCaDataTest001, TestSize.Level1)
{
    HttpClientRequest req;
    EXPECT_EQ(req.GetCaData(), "");

    std::string caData = "-----BEGIN CERTIFICATE-----caData-----END CERTIFICATE-----";
    req.SetCaData(caData);
    EXPECT_EQ(req.GetCaData(), caData);
}

HWTEST_F(HttpClientRequestTest, SetPathPreferenceTest001, TestSize.Level1)
{
    HttpClientRequest req;
    EXPECT_EQ(req.GetPathPreference(), PathPreference::autoPath);

    req.SetPathPreference(PathPreference::primaryCellular);
    EXPECT_EQ(req.GetPathPreference(), PathPreference::primaryCellular);

    req.SetPathPreference(PathPreference::secondaryCellular);
    EXPECT_EQ(req.GetPathPreference(), PathPreference::secondaryCellular);

    req.SetPathPreference(PathPreference::autoPath);
    EXPECT_EQ(req.GetPathPreference(), PathPreference::autoPath);
}

HWTEST_F(HttpClientRequestTest, Socks5ProxyStructTest001, TestSize.Level1)
{
    Socks5Proxy socks5Proxy;
    EXPECT_EQ(socks5Proxy.host, "");
    EXPECT_EQ(socks5Proxy.port, 0);
    EXPECT_EQ(socks5Proxy.username, "");
    EXPECT_EQ(socks5Proxy.password, "");
    EXPECT_EQ(socks5Proxy.dnsStrategy, Socks5DnsStrategy::UNSPECIFIED);
    EXPECT_EQ(socks5Proxy.exclusionList, "");
}

HWTEST_F(HttpClientRequestTest, SetSocks5ProxyTest001, TestSize.Level1)
{
    HttpClientRequest req;

    Socks5Proxy socks5Proxy;
    socks5Proxy.host = "192.168.147.60";
    socks5Proxy.port = 1080;
    socks5Proxy.username.assign("user");
    socks5Proxy.password.assign("password");
    socks5Proxy.dnsStrategy = Socks5DnsStrategy::PROXY_MODE;
    socks5Proxy.exclusionList = "localhost,127.0.0.1";
    req.SetSocks5Proxy(socks5Proxy);

    const Socks5Proxy &proxy = req.GetSocks5Proxy();
    EXPECT_EQ(proxy.host, socks5Proxy.host);
    EXPECT_EQ(proxy.port, socks5Proxy.port);
    EXPECT_EQ(proxy.username, socks5Proxy.username);
    EXPECT_EQ(proxy.password, socks5Proxy.password);
    EXPECT_EQ(proxy.dnsStrategy, Socks5DnsStrategy::PROXY_MODE);
    EXPECT_EQ(proxy.exclusionList, socks5Proxy.exclusionList);
}

HWTEST_F(HttpClientRequestTest, SetSocks5ProxyTest002, TestSize.Level1)
{
    HttpClientRequest req;
    Socks5Proxy socks5Proxy;
    socks5Proxy.host = "192.168.147.60";
    socks5Proxy.port = 1080;
    socks5Proxy.username.assign("user");
    socks5Proxy.password.assign("password");
    socks5Proxy.dnsStrategy = Socks5DnsStrategy::PROXY_MODE;
    socks5Proxy.exclusionList = "localhost,127.0.0.1";
    req.SetSocks5Proxy(socks5Proxy);

    req.SetSocks5Proxy(Socks5Proxy());
    const Socks5Proxy &actual = req.GetSocks5Proxy();
    EXPECT_TRUE(actual.host.empty());
    EXPECT_EQ(actual.port, 0);
    EXPECT_TRUE(actual.username.empty());
    EXPECT_TRUE(actual.password.empty());
    EXPECT_EQ(actual.dnsStrategy, Socks5DnsStrategy::UNSPECIFIED);
    EXPECT_TRUE(actual.exclusionList.empty());
}

HWTEST_F(HttpClientRequestTest, SetPartialChainTest001, TestSize.Level1)
{
    HttpClientRequest req;
    EXPECT_EQ(req.GetPartialChain(), -1);

    req.SetPartialChain(false);
    EXPECT_EQ(req.GetPartialChain(), 0);

    req.SetPartialChain(true);
    EXPECT_EQ(req.GetPartialChain(), 1);
}

HWTEST_F(HttpClientRequestTest, SetPinnedPubkeyTest001, TestSize.Level1)
{
    HttpClientRequest req;
    EXPECT_EQ(req.GetPinnedPubkey(), "");

    std::string pubkey = "testPinnedPubkey";
    req.SetPinnedPubkey(pubkey);
    EXPECT_EQ(req.GetPinnedPubkey(), pubkey);
}

HWTEST_F(HttpClientRequestTest, SetPinnedPubkeyTest002, TestSize.Level1)
{
    HttpClientRequest req;
    req.SetPinnedPubkey(std::string("sha256//") + std::string(44, 'A'));
    EXPECT_EQ(req.GetPinnedPubkey(), std::string("sha256//") + std::string(44, 'A'));
}

HWTEST_F(HttpClientRequestTest, SetQueryParamsTest001, TestSize.Level1)
{
    HttpClientRequest req;
    EXPECT_EQ(req.GetQueryParams().dataType, HttpDataType::NO_DATA_TYPE);

    EscapedData queryParams;
    queryParams.dataType = HttpDataType::OBJECT;
    queryParams.data = "{\"key\":\"value\"}";
    req.SetQueryParams(queryParams);

    EXPECT_EQ(req.GetQueryParams().dataType, HttpDataType::OBJECT);
    EXPECT_EQ(req.GetQueryParams().data, "{\"key\":\"value\"}");
}
} // namespace
