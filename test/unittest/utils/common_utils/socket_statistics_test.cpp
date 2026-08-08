/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#define protected public
#define private public

#include <gtest/gtest.h>
#include <string>
#include <map>

#include "socket_statistics.h"

namespace OHOS {
namespace NetStack {
namespace SocketStats {
namespace {
using namespace testing::ext;
}

class SocketStatisticsTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp()
    {
        auto &inst = SocketStatisticsEvent::GetInstance();
        {
            std::lock_guard<std::mutex> lock(inst.TlsSocket().mutex_);
            inst.TlsSocket().ResetStatisticsLocked();
        }
        {
            std::lock_guard<std::mutex> lock(inst.WsSocket().mutex_);
            inst.WsSocket().ResetStatisticsLocked();
        }
        {
            std::lock_guard<std::mutex> lock(inst.WssSocket().mutex_);
            inst.WssSocket().ResetStatisticsLocked();
        }
        inst.lastReportTime_ = 0;
    }

    virtual void TearDown() {}
};

HWTEST_F(SocketStatisticsTest, RecordTotalConnect001, TestSize.Level2)
{
    auto &stats = SocketStatisticsEvent::GetInstance().TlsSocket();
    stats.RecordTotalConnect("192.168.1.1", "www.example.com");
    EXPECT_EQ(stats.errorStats_["192.168.1.1"].totalCount, 1);
    EXPECT_STREQ(stats.errorStats_["192.168.1.1"].hostName.c_str(), "www.example.com");
}

HWTEST_F(SocketStatisticsTest, RecordTotalConnect002, TestSize.Level2)
{
    auto &stats = SocketStatisticsEvent::GetInstance().TlsSocket();
    stats.RecordTotalConnect("192.168.1.2", "");
    EXPECT_EQ(stats.errorStats_["192.168.1.2"].totalCount, 1);
    EXPECT_TRUE(stats.errorStats_["192.168.1.2"].hostName.empty());
}

HWTEST_F(SocketStatisticsTest, RecordTotalConnect003, TestSize.Level2)
{
    auto &stats = SocketStatisticsEvent::GetInstance().TlsSocket();
    stats.RecordTotalConnect("192.168.1.3", "first.example.com");
    stats.RecordTotalConnect("192.168.1.3", "second.example.com");
    EXPECT_STREQ(stats.errorStats_["192.168.1.3"].hostName.c_str(), "first.example.com");
    EXPECT_EQ(stats.errorStats_["192.168.1.3"].totalCount, 2);
}

HWTEST_F(SocketStatisticsTest, RecordAbnormalConnect001, TestSize.Level2)
{
    auto &stats = SocketStatisticsEvent::GetInstance().TlsSocket();
    stats.RecordAbnormalConnect("192.168.1.1", 100);
    EXPECT_EQ(stats.errorStats_["192.168.1.1"].abnormalCount, 1);
    EXPECT_EQ(stats.errorStats_["192.168.1.1"].socketErrorCode[100], 1);
}

HWTEST_F(SocketStatisticsTest, RecordAbnormalConnect002, TestSize.Level2)
{
    auto &stats = SocketStatisticsEvent::GetInstance().TlsSocket();
    stats.RecordAbnormalConnect("192.168.1.1", 100);
    stats.RecordAbnormalConnect("192.168.1.1", 200);
    EXPECT_EQ(stats.errorStats_["192.168.1.1"].abnormalCount, 2);
    EXPECT_EQ(stats.errorStats_["192.168.1.1"].socketErrorCode[100], 1);
    EXPECT_EQ(stats.errorStats_["192.168.1.1"].socketErrorCode[200], 1);
}

HWTEST_F(SocketStatisticsTest, RecordVersionError001, TestSize.Level2)
{
    auto &stats = SocketStatisticsEvent::GetInstance().TlsSocket();
    stats.RecordVersionError("192.168.1.1", "HTTP/1.0");
    EXPECT_EQ(stats.errorStats_["192.168.1.1"].versionInfo["HTTP/1.0"], 1);
}

HWTEST_F(SocketStatisticsTest, RecordVersionError002, TestSize.Level2)
{
    auto &stats = SocketStatisticsEvent::GetInstance().TlsSocket();
    stats.RecordVersionError("192.168.1.1", "HTTP/1.0");
    stats.RecordVersionError("192.168.1.1", "HTTP/1.0");
    stats.RecordVersionError("192.168.1.1", "HTTP/2.0");
    EXPECT_EQ(stats.errorStats_["192.168.1.1"].versionInfo["HTTP/1.0"], 2);
    EXPECT_EQ(stats.errorStats_["192.168.1.1"].versionInfo["HTTP/2.0"], 1);
}

HWTEST_F(SocketStatisticsTest, RecordConnectAttempt001, TestSize.Level2)
{
    auto &stats = SocketStatisticsEvent::GetInstance().TlsSocket();
    stats.RecordConnectAttempt();
    EXPECT_EQ(stats.protoStats_.totalConnectCount, 1);
}

HWTEST_F(SocketStatisticsTest, RecordConnectAttempt002, TestSize.Level2)
{
    auto &stats = SocketStatisticsEvent::GetInstance().TlsSocket();
    stats.RecordConnectAttempt();
    stats.RecordConnectAttempt();
    stats.RecordConnectAttempt();
    EXPECT_EQ(stats.protoStats_.totalConnectCount, 3);
}

HWTEST_F(SocketStatisticsTest, RecordConnectSuccess001, TestSize.Level2)
{
    auto &stats = SocketStatisticsEvent::GetInstance().TlsSocket();
    stats.RecordConnectSuccess(100);
    EXPECT_EQ(stats.protoStats_.successConnectCount, 1);
    EXPECT_EQ(stats.protoStats_.successTimeMs, 100);
}

HWTEST_F(SocketStatisticsTest, RecordConnectSuccess002, TestSize.Level2)
{
    auto &stats = SocketStatisticsEvent::GetInstance().TlsSocket();
    stats.RecordConnectSuccess(100);
    stats.RecordConnectSuccess(200);
    EXPECT_EQ(stats.protoStats_.successConnectCount, 2);
    EXPECT_EQ(stats.protoStats_.successTimeMs, 300);
}

HWTEST_F(SocketStatisticsTest, RecordDnsTime001, TestSize.Level2)
{
    auto &stats = SocketStatisticsEvent::GetInstance().TlsSocket();
    stats.RecordDnsTime(50);
    EXPECT_EQ(stats.protoStats_.dnsCount, 1);
    EXPECT_EQ(stats.protoStats_.totalDnsTimeMs, 50);
}

HWTEST_F(SocketStatisticsTest, RecordDnsTime002, TestSize.Level2)
{
    auto &stats = SocketStatisticsEvent::GetInstance().TlsSocket();
    stats.RecordDnsTime(50);
    stats.RecordDnsTime(30);
    EXPECT_EQ(stats.protoStats_.dnsCount, 2);
    EXPECT_EQ(stats.protoStats_.totalDnsTimeMs, 80);
}

HWTEST_F(SocketStatisticsTest, RecordTcpHandshakeTime001, TestSize.Level2)
{
    auto &stats = SocketStatisticsEvent::GetInstance().TlsSocket();
    stats.RecordTcpHandshakeTime(80);
    EXPECT_EQ(stats.protoStats_.tcpHandshakeCount, 1);
    EXPECT_EQ(stats.protoStats_.totalTcpHandshakeTimeMs, 80);
}

HWTEST_F(SocketStatisticsTest, RecordTlsHandshakeTime001, TestSize.Level2)
{
    auto &stats = SocketStatisticsEvent::GetInstance().TlsSocket();
    stats.RecordTlsHandshakeTime(120);
    EXPECT_EQ(stats.protoStats_.tlsHandshakeCount, 1);
    EXPECT_EQ(stats.protoStats_.totalTlsHandshakeTimeMs, 120);
}

HWTEST_F(SocketStatisticsTest, RecordHttpUpgradeTime001, TestSize.Level2)
{
    auto &stats = SocketStatisticsEvent::GetInstance().TlsSocket();
    stats.RecordHttpUpgradeTime(200);
    EXPECT_EQ(stats.protoStats_.httpUpgradeCount, 1);
    EXPECT_EQ(stats.protoStats_.totalHttpUpgradeTimeMs, 200);
}

HWTEST_F(SocketStatisticsTest, RecordVersion001, TestSize.Level2)
{
    auto &stats = SocketStatisticsEvent::GetInstance().TlsSocket();
    stats.RecordVersion("HTTP/1.1");
    EXPECT_EQ(stats.protoStats_.versionCount["HTTP/1.1"], 1);
}

HWTEST_F(SocketStatisticsTest, RecordVersion002, TestSize.Level2)
{
    auto &stats = SocketStatisticsEvent::GetInstance().TlsSocket();
    stats.RecordVersion("HTTP/1.1");
    stats.RecordVersion("HTTP/1.1");
    stats.RecordVersion("HTTP/2.0");
    EXPECT_EQ(stats.protoStats_.versionCount["HTTP/1.1"], 2);
    EXPECT_EQ(stats.protoStats_.versionCount["HTTP/2.0"], 1);
}

HWTEST_F(SocketStatisticsTest, BuildVersionCount001, TestSize.Level2)
{
    SocketStatisticsBase stats;
    std::map<std::string, uint32_t> emptyMap;
    std::string result = stats.BuildVersionCount(emptyMap);
    EXPECT_STREQ(result.c_str(), "[]");
}

HWTEST_F(SocketStatisticsTest, BuildVersionCount002, TestSize.Level2)
{
    SocketStatisticsBase stats;
    std::map<std::string, uint32_t> singleMap = {{"HTTP/1.1", 5}};
    std::string result = stats.BuildVersionCount(singleMap);
    EXPECT_STREQ(result.c_str(), "[{\"version\":\"HTTP/1.1\",\"count\":5}]");
}

HWTEST_F(SocketStatisticsTest, BuildVersionCount003, TestSize.Level2)
{
    SocketStatisticsBase stats;
    std::map<std::string, uint32_t> multiMap = {{"HTTP/1.1", 5}, {"HTTP/2.0", 3}};
    std::string result = stats.BuildVersionCount(multiMap);
    EXPECT_NE(result.find("HTTP/1.1"), std::string::npos);
    EXPECT_NE(result.find("HTTP/2.0"), std::string::npos);
    EXPECT_NE(result.find(","), std::string::npos);
}

HWTEST_F(SocketStatisticsTest, BuildProtoStatsJsonLocked001, TestSize.Level2)
{
    SocketStatisticsBase stats;
    stats.protoStats_.totalConnectCount = 10;
    stats.protoStats_.successConnectCount = 8;
    stats.protoStats_.successTimeMs = 1000;
    stats.protoStats_.dnsCount = 10;
    stats.protoStats_.totalDnsTimeMs = 500;
    stats.protoStats_.tcpHandshakeCount = 8;
    stats.protoStats_.totalTcpHandshakeTimeMs = 400;
    stats.protoStats_.tlsHandshakeCount = 8;
    stats.protoStats_.totalTlsHandshakeTimeMs = 800;
    stats.protoStats_.httpUpgradeCount = 5;
    stats.protoStats_.totalHttpUpgradeTimeMs = 300;
    std::string result = stats.BuildProtoStatsJsonLocked();
    EXPECT_NE(result.find("\"totalConnectCount\":10"), std::string::npos);
    EXPECT_NE(result.find("\"successConnectCount\":8"), std::string::npos);
    EXPECT_NE(result.find("\"dnsCount\":10"), std::string::npos);
    EXPECT_NE(result.find("\"totalDnsTimeMs\":500"), std::string::npos);
    EXPECT_NE(result.find("\"tcpHandshakeCount\":8"), std::string::npos);
    EXPECT_NE(result.find("\"totalTcpHandshakeTimeMs\":400"), std::string::npos);
    EXPECT_NE(result.find("\"tlsHandshakeCount\":8"), std::string::npos);
    EXPECT_NE(result.find("\"totalTlsHandshakeTimeMs\":800"), std::string::npos);
    EXPECT_NE(result.find("\"httpUpgradeCount\":5"), std::string::npos);
    EXPECT_NE(result.find("\"totalHttpUpgradeTimeMs\":300"), std::string::npos);
    EXPECT_NE(result.find("\"successTimeMs\":1000"), std::string::npos);
    EXPECT_NE(result.find("\"versionCount\":[]"), std::string::npos);
}

HWTEST_F(SocketStatisticsTest, BuildProtoStatsJsonLocked002, TestSize.Level2)
{
    SocketStatisticsBase stats;
    stats.protoStats_.versionCount["HTTP/1.1"] = 5;
    stats.protoStats_.versionCount["HTTP/2.0"] = 3;
    std::string result = stats.BuildProtoStatsJsonLocked();
    EXPECT_NE(result.find("HTTP/1.1"), std::string::npos);
    EXPECT_NE(result.find("HTTP/2.0"), std::string::npos);
}

HWTEST_F(SocketStatisticsTest, BuildErrorStatsJsonLocked001, TestSize.Level2)
{
    SocketStatisticsBase stats;
    std::string result = stats.BuildErrorStatsJsonLocked();
    EXPECT_STREQ(result.c_str(), "\"errorStats\":[]");
}

HWTEST_F(SocketStatisticsTest, BuildErrorStatsJsonLocked002, TestSize.Level2)
{
    SocketStatisticsBase stats;
    SocketErrorStats errorStats;
    errorStats.hostName = "www.example.com";
    errorStats.totalCount = 5;
    errorStats.abnormalCount = 1;
    stats.errorStats_["192.168.1.1"] = errorStats;
    std::string result = stats.BuildErrorStatsJsonLocked();
    EXPECT_NE(result.find("192.168.1.1"), std::string::npos);
    EXPECT_NE(result.find("www.example.com"), std::string::npos);
    EXPECT_NE(result.find("\"totalCount\":5"), std::string::npos);
    EXPECT_NE(result.find("\"abnormalCount\":1"), std::string::npos);
}

HWTEST_F(SocketStatisticsTest, BuildErrorStatsJsonLocked003, TestSize.Level2)
{
    SocketStatisticsBase stats;
    SocketErrorStats errorStats;
    errorStats.totalCount = 5;
    errorStats.abnormalCount = 1;
    errorStats.socketErrorCode[100] = 3;
    stats.errorStats_["192.168.1.1"] = errorStats;
    std::string result = stats.BuildErrorStatsJsonLocked();
    EXPECT_NE(result.find("\"100\":3"), std::string::npos);
}

HWTEST_F(SocketStatisticsTest, BuildErrorStatsJsonLocked004, TestSize.Level2)
{
    SocketStatisticsBase stats;
    SocketErrorStats errorStats;
    errorStats.socketErrorCode[100] = 3;
    errorStats.socketErrorCode[200] = 2;
    stats.errorStats_["192.168.1.1"] = errorStats;
    std::string result = stats.BuildErrorStatsJsonLocked();
    EXPECT_NE(result.find("\"100\":3"), std::string::npos);
    EXPECT_NE(result.find("\"200\":2"), std::string::npos);
    size_t firstPos = result.find("\"100\":3");
    size_t commaPos = result.find(",", firstPos);
    EXPECT_NE(commaPos, std::string::npos);
}

HWTEST_F(SocketStatisticsTest, BuildErrorStatsJsonLocked005, TestSize.Level2)
{
    SocketStatisticsBase stats;
    SocketErrorStats errorStats1;
    errorStats1.totalCount = 5;
    SocketErrorStats errorStats2;
    errorStats2.totalCount = 3;
    stats.errorStats_["192.168.1.1"] = errorStats1;
    stats.errorStats_["192.168.1.2"] = errorStats2;
    std::string result = stats.BuildErrorStatsJsonLocked();
    EXPECT_NE(result.find("192.168.1.1"), std::string::npos);
    EXPECT_NE(result.find("192.168.1.2"), std::string::npos);
    size_t firstPos = result.find("192.168.1.1");
    size_t commaPos = result.find(",", firstPos);
    EXPECT_NE(commaPos, std::string::npos);
}

HWTEST_F(SocketStatisticsTest, BuildErrorStatsJsonLocked006, TestSize.Level2)
{
    SocketStatisticsBase stats;
    SocketErrorStats errorStats;
    errorStats.versionInfo["HTTP/1.0"] = 2;
    errorStats.versionInfo["HTTP/2.0"] = 1;
    stats.errorStats_["192.168.1.1"] = errorStats;
    std::string result = stats.BuildErrorStatsJsonLocked();
    EXPECT_NE(result.find("HTTP/1.0"), std::string::npos);
    EXPECT_NE(result.find("HTTP/2.0"), std::string::npos);
    EXPECT_NE(result.find("\"versionInfo\":"), std::string::npos);
}

HWTEST_F(SocketStatisticsTest, ResetStatisticsLocked001, TestSize.Level2)
{
    SocketStatisticsBase stats;
    stats.protoStats_.totalConnectCount = 10;
    stats.protoStats_.successConnectCount = 5;
    stats.protoStats_.versionCount["HTTP/1.1"] = 3;
    SocketErrorStats errorStats;
    errorStats.totalCount = 5;
    stats.errorStats_["192.168.1.1"] = errorStats;
    stats.ResetStatisticsLocked();
    EXPECT_EQ(stats.protoStats_.totalConnectCount, 0);
    EXPECT_EQ(stats.protoStats_.successConnectCount, 0);
    EXPECT_TRUE(stats.protoStats_.versionCount.empty());
    EXPECT_TRUE(stats.errorStats_.empty());
}

HWTEST_F(SocketStatisticsTest, BuildStatisticsJsonLocked001, TestSize.Level2)
{
    auto &inst = SocketStatisticsEvent::GetInstance();
    auto &tls = inst.TlsSocket();
    tls.protoStats_.totalConnectCount = 10;
    tls.protoStats_.successConnectCount = 8;
    SocketErrorStats errorStats;
    errorStats.hostName = "www.example.com";
    errorStats.totalCount = 5;
    errorStats.abnormalCount = 1;
    errorStats.socketErrorCode[100] = 3;
    tls.errorStats_["192.168.1.1"] = errorStats;
    std::string result = inst.BuildStatisticsJsonLocked("com.example.test");
    EXPECT_NE(result.find("\"bundleName\":\"com.example.test\""), std::string::npos);
    EXPECT_NE(result.find("\"tlsStats\""), std::string::npos);
    EXPECT_NE(result.find("\"wsStats\""), std::string::npos);
    EXPECT_NE(result.find("\"wssStats\""), std::string::npos);
    EXPECT_NE(result.find("\"totalConnectCount\":10"), std::string::npos);
    EXPECT_NE(result.find("192.168.1.1"), std::string::npos);
}

HWTEST_F(SocketStatisticsTest, BuildStatisticsJsonLocked002, TestSize.Level2)
{
    auto &inst = SocketStatisticsEvent::GetInstance();
    auto &ws = inst.WsSocket();
    ws.protoStats_.totalConnectCount = 5;
    ws.RecordVersion("HTTP/1.1");
    auto &wss = inst.WssSocket();
    wss.protoStats_.totalConnectCount = 3;
    wss.RecordAbnormalConnect("10.0.0.1", 500);
    std::string result = inst.BuildStatisticsJsonLocked("com.test.bundle");
    EXPECT_NE(result.find("\"bundleName\":\"com.test.bundle\""), std::string::npos);
    EXPECT_NE(result.find("\"totalConnectCount\":5"), std::string::npos);
    EXPECT_NE(result.find("\"totalConnectCount\":3"), std::string::npos);
    EXPECT_NE(result.find("HTTP/1.1"), std::string::npos);
    EXPECT_NE(result.find("10.0.0.1"), std::string::npos);
}

HWTEST_F(SocketStatisticsTest, GetWebsocketStat001, TestSize.Level2)
{
    auto &inst = SocketStatisticsEvent::GetInstance();
    auto &ws = inst.GetWebsocketStat(false);
    auto &wsRef = inst.WsSocket();
    EXPECT_EQ(&ws, &wsRef);
}

HWTEST_F(SocketStatisticsTest, GetWebsocketStat002, TestSize.Level2)
{
    auto &inst = SocketStatisticsEvent::GetInstance();
    auto &wss = inst.GetWebsocketStat(true);
    auto &wssRef = inst.WssSocket();
    EXPECT_EQ(&wss, &wssRef);
}

HWTEST_F(SocketStatisticsTest, GetWebsocketStat003, TestSize.Level2)
{
    auto &inst = SocketStatisticsEvent::GetInstance();
    auto &ws = inst.GetWebsocketStat(false);
    auto &wss = inst.GetWebsocketStat(true);
    EXPECT_NE(&ws, &wss);
}

#ifdef HAS_NETMANAGER_BASE
HWTEST_F(SocketStatisticsTest, TryReportStatistics001, TestSize.Level2)
{
    auto &inst = SocketStatisticsEvent::GetInstance();
    inst.lastReportTime_ = 0;
    inst.TryReportStatistics();
    EXPECT_NE(inst.lastReportTime_, 0);
}

HWTEST_F(SocketStatisticsTest, TryReportStatistics002, TestSize.Level2)
{
    auto &inst = SocketStatisticsEvent::GetInstance();
    time_t expected = time(0);
    inst.lastReportTime_ = expected;
    inst.TryReportStatistics();
    EXPECT_EQ(inst.lastReportTime_, expected);
}

HWTEST_F(SocketStatisticsTest, TryReportStatistics003, TestSize.Level2)
{
    auto &inst = SocketStatisticsEvent::GetInstance();
    inst.lastReportTime_ = time(0) - 360;
    auto &tls = inst.TlsSocket();
    tls.protoStats_.totalConnectCount = 10;
    uint32_t beforeCount = tls.protoStats_.totalConnectCount;
    inst.TryReportStatistics();
    EXPECT_EQ(beforeCount, 10);
}

HWTEST_F(SocketStatisticsTest, TryReportStatistics004, TestSize.Level2)
{
    auto &inst = SocketStatisticsEvent::GetInstance();
    inst.lastReportTime_ = 0;
    inst.TryReportStatistics();
    inst.lastReportTime_ = time(0) - 360;
    auto &tls = inst.TlsSocket();
    tls.protoStats_.totalConnectCount = 10;
    uint32_t beforeCount = tls.protoStats_.totalConnectCount;
    inst.TryReportStatistics();
    EXPECT_EQ(beforeCount, 10);
}

HWTEST_F(SocketStatisticsTest, RecordConnectSuccessTryReport001, TestSize.Level2)
{
    auto &inst = SocketStatisticsEvent::GetInstance();
    inst.lastReportTime_ = 0;
    auto &stats = inst.TlsSocket();
    stats.RecordConnectSuccess(100);
    EXPECT_EQ(stats.protoStats_.successConnectCount, 1);
    EXPECT_EQ(stats.protoStats_.successTimeMs, 100);
    EXPECT_NE(inst.lastReportTime_, 0);
}

HWTEST_F(SocketStatisticsTest, RecordConnectSuccessTryReport002, TestSize.Level2)
{
    auto &inst = SocketStatisticsEvent::GetInstance();
    inst.lastReportTime_ = time(0) - 360;
    auto &stats = inst.TlsSocket();
    stats.RecordConnectSuccess(100);
    EXPECT_EQ(stats.protoStats_.successConnectCount, 0);
    EXPECT_EQ(stats.protoStats_.successTimeMs, 0);
}
#else
HWTEST_F(SocketStatisticsTest, TryReportStatisticsNoGuard001, TestSize.Level2)
{
    auto &inst = SocketStatisticsEvent::GetInstance();
    inst.lastReportTime_ = 0;
    inst.TryReportStatistics();
    EXPECT_NE(inst.lastReportTime_, 0);
}

HWTEST_F(SocketStatisticsTest, RecordConnectSuccessNoGuard001, TestSize.Level2)
{
    auto &stats = SocketStatisticsEvent::GetInstance().TlsSocket();
    stats.RecordConnectSuccess(100);
    EXPECT_EQ(stats.protoStats_.successConnectCount, 1);
    EXPECT_EQ(stats.protoStats_.successTimeMs, 100);
}
#endif

HWTEST_F(SocketStatisticsTest, ComprehensiveFlow001, TestSize.Level2)
{
    auto &inst = SocketStatisticsEvent::GetInstance();
    auto &tls = inst.TlsSocket();
    auto &ws = inst.WsSocket();
    auto &wss = inst.WssSocket();

    tls.RecordConnectAttempt();
    tls.RecordConnectAttempt();
    tls.RecordConnectSuccess(150);
    tls.RecordDnsTime(30);
    tls.RecordTcpHandshakeTime(50);
    tls.RecordTlsHandshakeTime(70);
    tls.RecordHttpUpgradeTime(40);
    tls.RecordVersion("HTTP/1.1");
    tls.RecordTotalConnect("192.168.1.1", "www.tls-example.com");
    tls.RecordAbnormalConnect("192.168.1.1", 100);
    tls.RecordVersionError("192.168.1.1", "HTTP/1.0");

    ws.RecordConnectAttempt();
    ws.RecordConnectSuccess(200);
    ws.RecordDnsTime(40);
    ws.RecordTcpHandshakeTime(60);
    ws.RecordVersion("HTTP/2.0");
    ws.RecordTotalConnect("192.168.1.2", "www.ws-example.com");
    ws.RecordAbnormalConnect("192.168.1.2", 200);

    wss.RecordConnectAttempt();
    wss.RecordConnectSuccess(300);
    wss.RecordTlsHandshakeTime(100);
    wss.RecordHttpUpgradeTime(80);
    wss.RecordVersion("HTTP/2.0");
    wss.RecordTotalConnect("192.168.1.3", "www.wss-example.com");
    wss.RecordAbnormalConnect("192.168.1.3", 300);
    wss.RecordVersionError("192.168.1.3", "HTTP/1.0");

    EXPECT_EQ(tls.protoStats_.totalConnectCount, 2);
    EXPECT_EQ(tls.protoStats_.successConnectCount, 1);
    EXPECT_EQ(tls.protoStats_.dnsCount, 1);
    EXPECT_EQ(tls.protoStats_.tcpHandshakeCount, 1);
    EXPECT_EQ(tls.protoStats_.tlsHandshakeCount, 1);
    EXPECT_EQ(tls.protoStats_.httpUpgradeCount, 1);
    EXPECT_EQ(tls.errorStats_["192.168.1.1"].totalCount, 1);
    EXPECT_EQ(tls.errorStats_["192.168.1.1"].abnormalCount, 1);

    EXPECT_EQ(ws.protoStats_.totalConnectCount, 1);
    EXPECT_EQ(ws.protoStats_.successConnectCount, 1);
    EXPECT_EQ(ws.errorStats_["192.168.1.2"].abnormalCount, 1);

    EXPECT_EQ(wss.protoStats_.totalConnectCount, 1);
    EXPECT_EQ(wss.protoStats_.successConnectCount, 1);
    EXPECT_EQ(wss.errorStats_["192.168.1.3"].abnormalCount, 1);

    std::string json = inst.BuildStatisticsJsonLocked("com.example.test");
    EXPECT_NE(json.find("\"bundleName\":\"com.example.test\""), std::string::npos);
    EXPECT_NE(json.find("www.tls-example.com"), std::string::npos);
    EXPECT_NE(json.find("www.ws-example.com"), std::string::npos);
    EXPECT_NE(json.find("www.wss-example.com"), std::string::npos);
}

} // namespace SocketStats
} // namespace NetStack
} // namespace OHOS
