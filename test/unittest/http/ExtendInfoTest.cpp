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
#ifdef USE_ARES
#include <cstring>
#include "gtest/gtest.h"

#ifdef GTEST_API_
#define private public
#endif

#include "http_exec.h"
#include "http_async_work.h"
#include "netstack_log.h"
#include "constant.h"
#include "secure_char.h"
#include "curl/curl.h"
#include "netstack_common_utils.h"

using namespace OHOS::NetStack;
using namespace OHOS::NetStack::Http;

struct CurlDeleter {
    void operator()(CURL *p) const { curl_easy_cleanup(p); }
};
using unique_CURL = std::unique_ptr<CURL, CurlDeleter>;

class ExtendInfoTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

namespace {
using namespace std;
using namespace testing::ext;

HWTEST_F(ExtendInfoTest, ExtendInfoWrapperDefaultValues001, TestSize.Level1)
{
    ExtendResponseInfo info;
    EXPECT_EQ(info->errorCode, 0);
    EXPECT_EQ(info->osErr, 0);
    EXPECT_EQ(info->lastRecvErrno, 0);
    EXPECT_EQ(info->lastSendErrno, 0);
    EXPECT_EQ(info->sslConnectErrno, 0);
    EXPECT_EQ(info->minTlsVersion, TlsVersion::DEFAULT);
    EXPECT_EQ(info->maxTlsVersion, TlsVersion::DEFAULT);
    EXPECT_EQ(info->lastPollinTimeUs, 0);
    EXPECT_EQ(info->lastOsPollinTimeUs, 0);
    EXPECT_EQ(info->lastPolloutTimeUs, 0);
    EXPECT_EQ(info->lastOsPolloutTimeUs, 0);
    EXPECT_EQ(info->lastSslRecvSize, -1);
    EXPECT_EQ(info->lastSslSendSize, -1);
    EXPECT_EQ(info->totalSslRecvSize, -1);
    EXPECT_EQ(info->totalSslSendSize, -1);
    EXPECT_EQ(info->dnsStatus, 0);
    EXPECT_EQ(info->isDnsFromNetsysCache, 0);
    EXPECT_EQ(info->tcpConnectErrno, 0);
    EXPECT_EQ(info->srcPort, 0);
    EXPECT_EQ(info->dstPort, 0);
    EXPECT_FALSE(info->tryConnectIpv4);
    EXPECT_FALSE(info->tryConnectIpv6);
    EXPECT_EQ(info->dlSpeed, -1);
    EXPECT_EQ(info->ulSpeed, -1);
    EXPECT_EQ(info->dlSize, -1);
    EXPECT_EQ(info->ulSize, -1);
    EXPECT_DOUBLE_EQ(info->dnsDur, 0.0);
    EXPECT_DOUBLE_EQ(info->connectDur, 0.0);
    EXPECT_DOUBLE_EQ(info->tlsDur, 0.0);
    EXPECT_DOUBLE_EQ(info->firstSendDur, 0.0);
    EXPECT_DOUBLE_EQ(info->firstRecvDur, 0.0);
    EXPECT_DOUBLE_EQ(info->totalDur, 0.0);
    EXPECT_DOUBLE_EQ(info->redirectDur, 0.0);
    EXPECT_EQ(info->proxyType, "none");
    EXPECT_TRUE(info->sslErr.empty());
    EXPECT_TRUE(info->ciphers.empty());
    EXPECT_TRUE(info->certIssuerNames.empty());
    EXPECT_TRUE(info->tryConnectIp.empty());
    EXPECT_TRUE(info->tryConnectPort.empty());
}

HWTEST_F(ExtendInfoTest, ExtendResponseInfoOperatorArrow001, TestSize.Level1)
{
    ExtendResponseInfo info;
    info->osErr = 42;
    info->sslErr = "test_ssl_error";
    info->dnsDur = 1.5;

    EXPECT_EQ(info->osErr, 42);
    EXPECT_EQ(info->sslErr, "test_ssl_error");
    EXPECT_DOUBLE_EQ(info->dnsDur, 1.5);
}

HWTEST_F(ExtendInfoTest, ExtendResponseInfoToString001, TestSize.Level1)
{
    ExtendResponseInfo info;
    info->errorCode = 100;
    info->osErr = 5;
    info->lastRecvErrno = 11;
    info->lastSendErrno = 104;
    info->sslErr = "ssl_error_test";
    info->sslConnectErrno = 1;
    info->dnsStatus = 2;
    info->srcAddr = "10.*.*.1";
    info->dstAddr = "10.*.*.2";
    info->srcPort = 12345;
    info->dstPort = 443;
    info->dlSpeed = 1024;
    info->ulSpeed = 512;
    info->dnsDur = 5.0;
    info->connectDur = 10.0;
    info->tlsDur = 15.0;

    std::string result = info.ToString();
    EXPECT_NE(result.find("osErr:5"), std::string::npos);
    EXPECT_NE(result.find("lastRecvE:11"), std::string::npos);
    EXPECT_NE(result.find("lstSendE:104"), std::string::npos);
    EXPECT_NE(result.find("sslErr:ssl_error_test"), std::string::npos);
    EXPECT_NE(result.find("sslConnE:1"), std::string::npos);
    EXPECT_NE(result.find("dnsSockE:0"), std::string::npos);
    EXPECT_NE(result.find("srcAddr:10.*.*.1"), std::string::npos);
    EXPECT_NE(result.find("dstAddr:10.*.*.2"), std::string::npos);
    EXPECT_NE(result.find("srcPort:12345"), std::string::npos);
    EXPECT_NE(result.find("dstPort:443"), std::string::npos);
    EXPECT_NE(result.find("dlSpeed:1024"), std::string::npos);
    EXPECT_NE(result.find("ulSpeed:512"), std::string::npos);
    EXPECT_NE(result.find("dnsDur:5.000"), std::string::npos);
    EXPECT_NE(result.find("tcpDur:10.000"), std::string::npos);
    EXPECT_NE(result.find("tlsDur:15.000"), std::string::npos);
}

HWTEST_F(ExtendInfoTest, ExtendResponseInfoToStringForErrLog001, TestSize.Level1)
{
    ExtendResponseInfo info;
    info->osErr = 99;

    std::string result = info.ToStringForErrLog(200);
    EXPECT_EQ(info->errorCode, 200);
    EXPECT_NE(result.find("osErr:99"), std::string::npos);
}

HWTEST_F(ExtendInfoTest, ExtResInfoInnerParserSetErrorInfo001, TestSize.Level1)
{
    std::string output;
    ExtResInfoInnerParser parser(output);
    parser.SetErrorInfo("key1", "value1");
    parser.SetErrorInfo("key2", "value2");

    EXPECT_NE(output.find("key1:value1"), std::string::npos);
    EXPECT_NE(output.find("key2:value2"), std::string::npos);
    EXPECT_NE(output.find(", "), std::string::npos);
}

HWTEST_F(ExtendInfoTest, ExtResInfoParserTraverseErrInfo001, TestSize.Level1)
{
    ExtendResponseInfo info;
    info->osErr = 7;
    std::string output;
    ExtResInfoInnerParser parser(output);
    parser.TraverseErrInfo(info, 500);

    EXPECT_EQ(info->errorCode, 500);
    EXPECT_NE(output.find("osErr:7"), std::string::npos);
    EXPECT_NE(output.find("sslErr:"), std::string::npos);
    EXPECT_NE(output.find("dnsSockE:0"), std::string::npos);
    EXPECT_NE(output.find("dlSpeed:-1"), std::string::npos);
    EXPECT_NE(output.find("dnsDur:0.000"), std::string::npos);
}

HWTEST_F(ExtendInfoTest, ExtResInfoParserTraverseErrInfoWithCiphers001, TestSize.Level1)
{
    ExtendResponseInfo info;
    info->ciphers = {"AES128-SHA", "AES256-SHA"};
    info->certIssuerNames = {"Issuer1", "Issuer2"};
    std::string output;
    ExtResInfoInnerParser parser(output);
    parser.TraverseErrInfo(info, 0);

    EXPECT_NE(output.find("ciphers:AES128-SHA|AES256-SHA"), std::string::npos);
    EXPECT_NE(output.find("issuers:Issuer1|Issuer2"), std::string::npos);
}

HWTEST_F(ExtendInfoTest, ExtResInfoParserTraverseErrInfoWithTryConnectIp001, TestSize.Level1)
{
    ExtendResponseInfo info;
    info->tryConnectIp = {"192.168.1.1", "10.0.0.1"};
    info->tryConnectPort = {"443", "8080"};
    info->tryConnectIpv4 = true;
    info->tryConnectIpv6 = false;
    std::string output;
    ExtResInfoInnerParser parser(output);
    parser.TraverseErrInfo(info, 0);

    EXPECT_NE(output.find("tryConnV4:1"), std::string::npos);
    EXPECT_NE(output.find("tryConnV6:0"), std::string::npos);
    EXPECT_NE(output.find("tryConnPort:443|8080"), std::string::npos);
}

HWTEST_F(ExtendInfoTest, ExtResInfoParserAddAllErrInfoCompleteness001, TestSize.Level1)
{
    ExtendResponseInfo info;
    info->errorCode = 1;
    info->osErr = 2;
    info->lastRecvErrno = 3;
    info->lastSendErrno = 4;
    info->sslErr = "err";
    info->sslConnectErrno = 5;
    info->minTlsVersion = TlsVersion::TLSv1_2;
    info->maxTlsVersion = TlsVersion::TLSv1_3;
    info->ciphers = {"C1"};
    info->lastSslRecvErr = "recv_err";
    info->lastSslSendErr = "send_err";
    info->lastPollinTimeUs = 1000;
    info->lastOsPollinTimeUs = 2000;
    info->lastPolloutTimeUs = 3000;
    info->lastOsPolloutTimeUs = 4000;
    info->lastSslRecvSize = 100;
    info->lastSslSendSize = 200;
    info->totalSslRecvSize = 1000;
    info->totalSslSendSize = 2000;
    info->dnsStatus = 1;
    info->dnsSockErr = 6;
    info->dnsCloseErr = 7;
    info->dnsConnErr = 8;
    info->dnsRecvErr = 9;
    info->dnsSendErr = 10;
    info->isDnsFromNetsysCache = 1;
    info->tcpConnectErrno = 11;
    info->srcAddr = "1.*.*.1";
    info->dstAddr = "2.*.*.2";
    info->srcPort = 100;
    info->dstPort = 200;
    info->tryConnectIpv4 = true;
    info->tryConnectIpv6 = true;
    info->dlSpeed = 500;
    info->ulSpeed = 600;
    info->dlSize = 700;
    info->ulSize = 800;
    info->dnsDur = 1.1;
    info->connectDur = 2.2;
    info->tlsDur = 3.3;
    info->firstSendDur = 4.4;
    info->firstRecvDur = 5.5;
    info->totalDur = 6.6;
    info->redirectDur = 7.7;
    info->certIssuerNames = {"CertIssuer"};
    info->proxyType = "http";

    std::string output = info.ToString();
    EXPECT_NE(output.find("osErr:2"), std::string::npos);
    EXPECT_NE(output.find("sslErr:err"), std::string::npos);
    EXPECT_NE(output.find("minTlsVersion:TLS_V_1_2"), std::string::npos);
    EXPECT_NE(output.find("maxTlsVersion:TLS_V_1_3"), std::string::npos);
    EXPECT_NE(output.find("ciphers:C1"), std::string::npos);
    EXPECT_NE(output.find("lastSslRecvE:recv_err"), std::string::npos);
    EXPECT_NE(output.find("lastSslRendE:send_err"), std::string::npos);
    EXPECT_NE(output.find("dnsSockE:6"), std::string::npos);
    EXPECT_NE(output.find("dnsCloseE:7"), std::string::npos);
    EXPECT_NE(output.find("dnsConnE:8"), std::string::npos);
    EXPECT_NE(output.find("dnsRecvE:9"), std::string::npos);
    EXPECT_NE(output.find("dnsSendE:6"), std::string::npos);
    EXPECT_NE(output.find("dnsFromNetsys:1"), std::string::npos);
    EXPECT_NE(output.find("tcpConnE:11"), std::string::npos);
    EXPECT_NE(output.find("srcAddr:1.*.*.1"), std::string::npos);
    EXPECT_NE(output.find("dstAddr:2.*.*.2"), std::string::npos);
    EXPECT_NE(output.find("srcPort:100"), std::string::npos);
    EXPECT_NE(output.find("dstPort:200"), std::string::npos);
    EXPECT_NE(output.find("tryConnV4:1"), std::string::npos);
    EXPECT_NE(output.find("tryConnV6:1"), std::string::npos);
    EXPECT_NE(output.find("dlSpeed:500"), std::string::npos);
    EXPECT_NE(output.find("ulSpeed:600"), std::string::npos);
    EXPECT_NE(output.find("dlSz:700"), std::string::npos);
    EXPECT_NE(output.find("ulSz:800"), std::string::npos);
    EXPECT_NE(output.find("dnsDur:1.100"), std::string::npos);
    EXPECT_NE(output.find("tcpDur:2.200"), std::string::npos);
    EXPECT_NE(output.find("tlsDur:3.300"), std::string::npos);
    EXPECT_NE(output.find("sndDur:4.400"), std::string::npos);
    EXPECT_NE(output.find("rcvDur:5.500"), std::string::npos);
    EXPECT_NE(output.find("totDur:6.600"), std::string::npos);
    EXPECT_NE(output.find("redDur:7.700"), std::string::npos);
    EXPECT_NE(output.find("lastSslRecvSz:100"), std::string::npos);
    EXPECT_NE(output.find("lastSslSendSz:200"), std::string::npos);
    EXPECT_NE(output.find("totalSslRecvSz:1000"), std::string::npos);
    EXPECT_NE(output.find("totalSslSendSz:2000"), std::string::npos);
    EXPECT_NE(output.find("issuers:CertIssuer"), std::string::npos);
}

HWTEST_F(ExtendInfoTest, ExtResInfoParserEpollTimeZero001, TestSize.Level1)
{
    ExtendResponseInfo info;
    info->lastOsPollinTimeUs = 0;
    info->lastOsPolloutTimeUs = 0;
    info->lastPollinTimeUs = 0;
    info->lastPolloutTimeUs = 0;
    std::string output;
    ExtResInfoInnerParser parser(output);
    parser.TraverseErrInfo(info, 0);

    EXPECT_NE(output.find("lastHttpIn:"), std::string::npos);
    EXPECT_NE(output.find("lastHttpOut:"), std::string::npos);
    EXPECT_NE(output.find("lastOsIn:never"), std::string::npos);
    EXPECT_NE(output.find("lastOsOut:never"), std::string::npos);
}

HWTEST_F(ExtendInfoTest, ExtResInfoParserTlsVersionDefault001, TestSize.Level1)
{
    ExtendResponseInfo info;
    info->minTlsVersion = TlsVersion::DEFAULT;
    info->maxTlsVersion = TlsVersion::DEFAULT;
    std::string output;
    ExtResInfoInnerParser parser(output);
    parser.TraverseErrInfo(info, 0);

    EXPECT_NE(output.find("minTlsVersion:"), std::string::npos);
    EXPECT_NE(output.find("maxTlsVersion:"), std::string::npos);
}

HWTEST_F(ExtendInfoTest, RequestContextExtendInfoMember001, TestSize.Level1)
{
    napi_env env = nullptr;
    auto manager = std::make_shared<EventManager>();
    RequestContext context(env, manager);

    context.extendInfo_->osErr = 42;
    context.extendInfo_->sslErr = "context_test";
    EXPECT_EQ(context.extendInfo_->osErr, 42);
    EXPECT_EQ(context.extendInfo_->sslErr, "context_test");
}

HWTEST_F(ExtendInfoTest, HttpExecGetExtendInfoFromCurl001, TestSize.Level1)
{
    unique_CURL handle(curl_easy_init());
    ASSERT_NE(handle, nullptr);

    ExtendResponseInfo extendInfo;
    HttpExec::GetExtendInfoFromCurl(handle.get(), extendInfo);

    EXPECT_EQ(extendInfo->lastSslRecvSize, 0);
    EXPECT_EQ(extendInfo->lastSslSendSize, 0);
    EXPECT_EQ(extendInfo->totalSslRecvSize, 0);
    EXPECT_EQ(extendInfo->totalSslSendSize, 0);
    EXPECT_EQ(extendInfo->tcpConnectErrno, 0);
    EXPECT_EQ(extendInfo->tryConnectIpv4, false);
    EXPECT_EQ(extendInfo->tryConnectIpv6, false);
    EXPECT_EQ(extendInfo->srcPort, 0);
    EXPECT_EQ(extendInfo->dstPort, 0);
}

HWTEST_F(ExtendInfoTest, HttpExecGetOsErrInfoFromCurl001, TestSize.Level1)
{
    unique_CURL handle(curl_easy_init());
    ASSERT_NE(handle, nullptr);

    ExtendResponseInfo extendInfo;
    HttpExec::GetOsErrInfoFromCurl(handle.get(), extendInfo);

    EXPECT_EQ(extendInfo->lastRecvErrno, 0);
    EXPECT_EQ(extendInfo->lastSendErrno, 0);
}

HWTEST_F(ExtendInfoTest, HttpExecGetTlsInfoFromCurl001, TestSize.Level1)
{
    unique_CURL handle(curl_easy_init());
    ASSERT_NE(handle, nullptr);

    ExtendResponseInfo extendInfo;
    HttpExec::GetTlsInfoFromCurl(handle.get(), extendInfo);

    EXPECT_EQ(extendInfo->sslConnectErrno, 0);
    EXPECT_TRUE(extendInfo->sslErr.empty());
    EXPECT_TRUE(extendInfo->ciphers.empty());
    EXPECT_TRUE(extendInfo->lastSslRecvErr.empty());
    EXPECT_TRUE(extendInfo->lastSslSendErr.empty());
}

HWTEST_F(ExtendInfoTest, HttpExecGetDnsInfoFromCurl001, TestSize.Level1)
{
    unique_CURL handle(curl_easy_init());
    ASSERT_NE(handle, nullptr);

    ExtendResponseInfo extendInfo;
    HttpExec::GetDnsInfoFromCurl(handle.get(), extendInfo);

    EXPECT_EQ(extendInfo->dnsStatus, 0);
    EXPECT_EQ(extendInfo->isDnsFromNetsysCache, 0);
}

HWTEST_F(ExtendInfoTest, HttpExecGetSrcAndDstInfoFromCurl001, TestSize.Level1)
{
    unique_CURL handle(curl_easy_init());
    ASSERT_NE(handle, nullptr);

    ExtendResponseInfo extendInfo;
    HttpExec::GetSrcAndDstInfoFromCurl(handle.get(), extendInfo);

    EXPECT_EQ(extendInfo->srcPort, 0);
    EXPECT_EQ(extendInfo->dstPort, 0);
}

HWTEST_F(ExtendInfoTest, HttpExecGetTcpInfoFromCurl001, TestSize.Level1)
{
    unique_CURL handle(curl_easy_init());
    ASSERT_NE(handle, nullptr);

    ExtendResponseInfo extendInfo;
    HttpExec::GetTcpInfoFromCurl(handle.get(), extendInfo);

    EXPECT_EQ(extendInfo->lastPollinTimeUs, 0);
    EXPECT_EQ(extendInfo->lastOsPollinTimeUs, 0);
    EXPECT_EQ(extendInfo->lastPolloutTimeUs, 0);
    EXPECT_EQ(extendInfo->lastOsPolloutTimeUs, 0);
    EXPECT_EQ(extendInfo->lastSslRecvSize, 0);
    EXPECT_EQ(extendInfo->lastSslSendSize, 0);
    EXPECT_EQ(extendInfo->totalSslRecvSize, 0);
    EXPECT_EQ(extendInfo->totalSslSendSize, 0);
    EXPECT_EQ(extendInfo->tcpConnectErrno, 0);
    EXPECT_FALSE(extendInfo->tryConnectIpv4);
    EXPECT_FALSE(extendInfo->tryConnectIpv6);
}

HWTEST_F(ExtendInfoTest, HttpExecGetTcpConnectInfoFromCurl001, TestSize.Level1)
{
    unique_CURL handle(curl_easy_init());
    ASSERT_NE(handle, nullptr);

    ExtendResponseInfo extendInfo;
    HttpExec::GetTcpConnectInfoFromCurl(handle.get(), extendInfo);

    EXPECT_TRUE(extendInfo->tryConnectIp.empty());
    EXPECT_TRUE(extendInfo->tryConnectPort.empty());
}

HWTEST_F(ExtendInfoTest, HttpExecGetPerfInfoFromCurl001, TestSize.Level1)
{
    unique_CURL handle(curl_easy_init());
    ASSERT_NE(handle, nullptr);

    ExtendResponseInfo extendInfo;
    HttpExec::GetPerfInfoFromCurl(handle.get(), extendInfo);

    EXPECT_TRUE(extendInfo->certIssuerNames.empty());
}

HWTEST_F(ExtendInfoTest, HttpExecGetTimeInfoFromCurl001, TestSize.Level1)
{
    unique_CURL handle(curl_easy_init());
    ASSERT_NE(handle, nullptr);

    ExtendResponseInfo extendInfo;
    HttpExec::GetTimeInfoFromCurl(handle.get(), extendInfo);

    EXPECT_DOUBLE_EQ(extendInfo->dnsDur, 0.0);
    EXPECT_DOUBLE_EQ(extendInfo->connectDur, 0.0);
    EXPECT_DOUBLE_EQ(extendInfo->tlsDur, 0.0);
    EXPECT_DOUBLE_EQ(extendInfo->firstSendDur, 0.0);
    EXPECT_DOUBLE_EQ(extendInfo->firstRecvDur, 0.0);
    EXPECT_DOUBLE_EQ(extendInfo->totalDur, 0.0);
    EXPECT_DOUBLE_EQ(extendInfo->redirectDur, 0.0);
}

HWTEST_F(ExtendInfoTest, HttpExecGetTlsVersionFromOption001, TestSize.Level1)
{
    napi_env env = nullptr;
    auto manager = std::make_shared<EventManager>();
    RequestContext context(env, manager);
    TlsOption tlsOption;
    tlsOption.tlsVersionMin = TlsVersion::TLSv1_2;
    tlsOption.tlsVersionMax = TlsVersion::TLSv1_3;
    context.options.SetTlsOption(tlsOption);

    ExtendResponseInfo extendInfo;
    HttpExec::GetTlsVersionFromOption(context.options, extendInfo);

    EXPECT_EQ(extendInfo->minTlsVersion, TlsVersion::TLSv1_2);
    EXPECT_EQ(extendInfo->maxTlsVersion, TlsVersion::TLSv1_3);
}

HWTEST_F(ExtendInfoTest, HttpExecGetTlsVersionFromOption002, TestSize.Level1)
{
    napi_env env = nullptr;
    auto manager = std::make_shared<EventManager>();
    RequestContext context(env, manager);

    ExtendResponseInfo extendInfo;
    HttpExec::GetTlsVersionFromOption(context.options, extendInfo);

    EXPECT_EQ(extendInfo->minTlsVersion, TlsVersion::DEFAULT);
    EXPECT_EQ(extendInfo->maxTlsVersion, TlsVersion::DEFAULT);
}

HWTEST_F(ExtendInfoTest, HttpExecGetExtendInfoFromCurlNullptr001, TestSize.Level1)
{
    ExtendResponseInfo extendInfo;
    HttpExec::GetExtendInfoFromCurl(nullptr, extendInfo);
    // Verify no crash and default values
    EXPECT_EQ(extendInfo->osErr, 0);
    EXPECT_EQ(extendInfo->lastRecvErrno, 0);
}

HWTEST_F(ExtendInfoTest, HttpExecGetOsErrInfoFromCurlNullptr001, TestSize.Level1)
{
    ExtendResponseInfo extendInfo;
    HttpExec::GetOsErrInfoFromCurl(nullptr, extendInfo);
    // Verify no crash and default values
    EXPECT_EQ(extendInfo->osErr, 0);
    EXPECT_EQ(extendInfo->lastRecvErrno, 0);
    EXPECT_EQ(extendInfo->lastSendErrno, 0);
}

HWTEST_F(ExtendInfoTest, HttpExecGetTlsInfoFromCurlNullptr001, TestSize.Level1)
{
    ExtendResponseInfo extendInfo;
    HttpExec::GetTlsInfoFromCurl(nullptr, extendInfo);
    // Verify no crash and default values
    EXPECT_EQ(extendInfo->sslConnectErrno, 0);
    EXPECT_TRUE(extendInfo->sslErr.empty());
    EXPECT_TRUE(extendInfo->ciphers.empty());
}

HWTEST_F(ExtendInfoTest, HttpExecGetDnsInfoFromCurlNullptr001, TestSize.Level1)
{
    ExtendResponseInfo extendInfo;
    HttpExec::GetDnsInfoFromCurl(nullptr, extendInfo);
    // Verify no crash and default values
    EXPECT_EQ(extendInfo->dnsStatus, 0);
    EXPECT_EQ(extendInfo->isDnsFromNetsysCache, 0);
}

HWTEST_F(ExtendInfoTest, HttpExecGetSrcAndDstInfoFromCurlNullptr001, TestSize.Level1)
{
    ExtendResponseInfo extendInfo;
    HttpExec::GetSrcAndDstInfoFromCurl(nullptr, extendInfo);
    // Verify no crash and default values
    EXPECT_EQ(extendInfo->srcPort, 0);
    EXPECT_EQ(extendInfo->dstPort, 0);
}

HWTEST_F(ExtendInfoTest, HttpExecGetTcpConnectInfoFromCurlNullptr001, TestSize.Level1)
{
    ExtendResponseInfo extendInfo;
    HttpExec::GetTcpConnectInfoFromCurl(nullptr, extendInfo);
    // Verify no crash and default values
    EXPECT_TRUE(extendInfo->tryConnectIp.empty());
    EXPECT_TRUE(extendInfo->tryConnectPort.empty());
}

HWTEST_F(ExtendInfoTest, HttpExecGetTcpInfoFromCurlNullptr001, TestSize.Level1)
{
    ExtendResponseInfo extendInfo;
    HttpExec::GetTcpInfoFromCurl(nullptr, extendInfo);
    // Verify no crash and default values
    EXPECT_FALSE(extendInfo->tryConnectIpv4);
    EXPECT_FALSE(extendInfo->tryConnectIpv6);
    EXPECT_EQ(extendInfo->lastPollinTimeUs, 0);
}

HWTEST_F(ExtendInfoTest, HttpExecGetPerfInfoFromCurlNullptr001, TestSize.Level1)
{
    ExtendResponseInfo extendInfo;
    HttpExec::GetPerfInfoFromCurl(nullptr, extendInfo);
    // Verify no crash and default values
    EXPECT_EQ(extendInfo->dlSpeed, -1);
    EXPECT_EQ(extendInfo->ulSpeed, -1);
}

HWTEST_F(ExtendInfoTest, HttpExecGetTimeInfoFromCurlNullptr001, TestSize.Level1)
{
    ExtendResponseInfo extendInfo;
    HttpExec::GetTimeInfoFromCurl(nullptr, extendInfo);
    // Verify no crash and default values
    EXPECT_DOUBLE_EQ(extendInfo->dnsDur, 0.0);
    EXPECT_DOUBLE_EQ(extendInfo->totalDur, 0.0);
}

} // namespace
#endif // USE_ARES
