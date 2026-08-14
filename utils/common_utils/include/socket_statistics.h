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

#ifndef SOCKET_STATISTICS_H
#define SOCKET_STATISTICS_H

#include <chrono>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>

namespace OHOS {
namespace NetStack {
namespace SocketStats {

struct SocketErrorStats {
    std::string hostName;
    uint32_t totalCount = 0;
    uint32_t abnormalCount = 0;
    std::map<std::string, uint32_t> versionInfo;
    std::map<int32_t, uint32_t> socketErrorCode;
};

struct SocketProtoStats {
    uint32_t totalConnectCount = 0;
    uint32_t successConnectCount = 0;
    uint32_t successTimeMs = 0;
    uint32_t dnsCount = 0;
    uint32_t totalDnsTimeMs = 0;
    uint32_t tcpHandshakeCount = 0;
    uint32_t totalTcpHandshakeTimeMs = 0;
    uint32_t tlsHandshakeCount = 0;
    uint32_t totalTlsHandshakeTimeMs = 0;
    uint32_t httpUpgradeCount = 0;
    uint32_t totalHttpUpgradeTimeMs = 0;
    std::map<std::string, uint32_t> versionCount;
};

class SocketStatisticsEvent;

class SocketStatisticsBase {
    friend class SocketStatisticsEvent;

public:
    void RecordTotalConnect(const std::string &dstIp, const std::string &hostName);
    void RecordAbnormalConnect(const std::string &dstIp, int32_t errCode);
    void RecordVersionError(const std::string &dstIp, const std::string &version);

    void RecordConnectAttempt();
    void RecordConnectSuccess(uint32_t timeMs);
    void RecordDnsTime(uint32_t timeMs);
    void RecordTcpHandshakeTime(uint32_t timeMs);
    void RecordTlsHandshakeTime(uint32_t timeMs);
    void RecordHttpUpgradeTime(uint32_t timeMs);
    void RecordVersion(const std::string &version);

protected:
    SocketStatisticsBase() = default;
    ~SocketStatisticsBase() = default;
    SocketStatisticsBase(const SocketStatisticsBase &) = delete;
    SocketStatisticsBase &operator=(const SocketStatisticsBase &) = delete;

    std::string BuildProtoStatsJsonLocked();
    std::string BuildErrorStatsJsonLocked();
    std::string BuildVersionCount(const std::map<std::string, uint32_t> &versionCount);
    void ResetStatisticsLocked();

    std::mutex mutex_;
    SocketProtoStats protoStats_;
    std::map<std::string, SocketErrorStats> errorStats_;
};

class SocketStatisticsEvent {
public:
    static SocketStatisticsEvent &GetInstance();

    SocketStatisticsBase &TlsSocket();
    SocketStatisticsBase &WsSocket();
    SocketStatisticsBase &WssSocket();

    void TryReportStatistics();
    SocketStatisticsBase &GetWebsocketStat(bool isWss);

private:
    SocketStatisticsEvent() = default;
    ~SocketStatisticsEvent() = default;
    SocketStatisticsEvent(const SocketStatisticsEvent &) = delete;
    SocketStatisticsEvent &operator=(const SocketStatisticsEvent &) = delete;

    std::string BuildStatisticsJsonLocked(const std::string &bundleName);

    SocketStatisticsBase tlsSocket_;
    SocketStatisticsBase wsSocket_;
    SocketStatisticsBase wssSocket_;
    std::mutex reportMutex_;
    time_t lastReportTime_ = 0;
};

} // namespace SocketStats
} // namespace NetStack
} // namespace OHOS

#endif // SOCKET_STATISTICS_H
