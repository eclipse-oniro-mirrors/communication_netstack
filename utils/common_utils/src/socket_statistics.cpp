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

#include "socket_statistics.h"
#include "netstack_log.h"
#include "netstack_common_utils.h"
#ifdef HAS_NETMANAGER_BASE
#include "common_event_manager.h"
#include "want.h"
#endif

namespace OHOS {
namespace NetStack {
namespace SocketStats {

static constexpr const char *SOCKET_PERF_EVENT_NAME = "custom.event.CHR_SOCKET_PERF";
static constexpr const char *SOCKET_PERF_FIELD = "SOCKET_PERF_INFO";
static constexpr const int32_t CHR_UID = 1201;
static constexpr const int32_t REPORT_TIME_INTERVAL = 5 * 60;

#ifdef HAS_NETMANAGER_BASE
static bool PublishSocketPerfEvent(const std::string &jsonStr)
{
    AAFwk::Want want;
    want.SetAction(SOCKET_PERF_EVENT_NAME);
    want.SetParam(SOCKET_PERF_FIELD, jsonStr);
    EventFwk::CommonEventData commonEventData;
    commonEventData.SetWant(want);
    EventFwk::CommonEventPublishInfo publishInfo;
    publishInfo.SetSubscriberUid({CHR_UID});
    // LCOV_EXCL_START
    if (!EventFwk::CommonEventManager::PublishCommonEvent(commonEventData, publishInfo)) {
        return false;
    }
    // LCOV_EXCL_STOP
    return true;
}
#endif

void SocketStatisticsBase::RecordTotalConnect(const std::string &dstIp, const std::string &hostName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto &stats = errorStats_[dstIp];
    if (!hostName.empty() && stats.hostName.empty()) {
        stats.hostName = hostName;
    }
    stats.totalCount++;
}

void SocketStatisticsBase::RecordAbnormalConnect(const std::string &dstIp, int32_t errCode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto &stats = errorStats_[dstIp];
    stats.abnormalCount++;
    stats.socketErrorCode[errCode]++;
}

void SocketStatisticsBase::RecordVersionError(const std::string &dstIp, const std::string &version)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto &stats = errorStats_[dstIp];
    stats.versionInfo[version]++;
}

void SocketStatisticsBase::RecordConnectAttempt()
{
    std::lock_guard<std::mutex> lock(mutex_);
    protoStats_.totalConnectCount++;
}

void SocketStatisticsBase::RecordConnectSuccess(uint32_t timeMs)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        protoStats_.successConnectCount++;
        protoStats_.successTimeMs += timeMs;
    }
    SocketStatisticsEvent::GetInstance().TryReportStatistics();
}

void SocketStatisticsBase::RecordDnsTime(uint32_t timeMs)
{
    std::lock_guard<std::mutex> lock(mutex_);
    protoStats_.dnsCount++;
    protoStats_.totalDnsTimeMs += timeMs;
}

void SocketStatisticsBase::RecordTcpHandshakeTime(uint32_t timeMs)
{
    std::lock_guard<std::mutex> lock(mutex_);
    protoStats_.tcpHandshakeCount++;
    protoStats_.totalTcpHandshakeTimeMs += timeMs;
}

void SocketStatisticsBase::RecordTlsHandshakeTime(uint32_t timeMs)
{
    std::lock_guard<std::mutex> lock(mutex_);
    protoStats_.tlsHandshakeCount++;
    protoStats_.totalTlsHandshakeTimeMs += timeMs;
}

void SocketStatisticsBase::RecordHttpUpgradeTime(uint32_t timeMs)
{
    std::lock_guard<std::mutex> lock(mutex_);
    protoStats_.httpUpgradeCount++;
    protoStats_.totalHttpUpgradeTimeMs += timeMs;
}

void SocketStatisticsBase::RecordVersion(const std::string &version)
{
    std::lock_guard<std::mutex> lock(mutex_);
    protoStats_.versionCount[version]++;
}

std::string SocketStatisticsBase::BuildVersionCount(const std::map<std::string, uint32_t> &versionCount)
{
    std::string json;
    json.append("[");
    bool innerFirst = true;
    for (const auto &v : versionCount) {
        if (!innerFirst) {
            json.append(",");
        }
        innerFirst = false;
        json.append("{\"version\":\"").append(v.first).append("\",\"count\":")
        .append(std::to_string(v.second)).append("}");
    }
    json.append("]");
    return json;
}

std::string SocketStatisticsBase::BuildProtoStatsJsonLocked()
{
    std::string json;
    json.append("\"totalConnectCount\":").append(std::to_string(protoStats_.totalConnectCount)).append(",");
    json.append("\"successConnectCount\":").append(std::to_string(protoStats_.successConnectCount)).append(",");
    json.append("\"dnsCount\":").append(std::to_string(protoStats_.dnsCount)).append(",");
    json.append("\"totalDnsTimeMs\":").append(std::to_string(protoStats_.totalDnsTimeMs)).append(",");
    json.append("\"tcpHandshakeCount\":").append(std::to_string(protoStats_.tcpHandshakeCount)).append(",");
    json.append("\"totalTcpHandshakeTimeMs\":").append(std::to_string(protoStats_.totalTcpHandshakeTimeMs)).append(",");
    json.append("\"tlsHandshakeCount\":").append(std::to_string(protoStats_.tlsHandshakeCount)).append(",");
    json.append("\"totalTlsHandshakeTimeMs\":").append(std::to_string(protoStats_.totalTlsHandshakeTimeMs)).append(",");
    json.append("\"httpUpgradeCount\":").append(std::to_string(protoStats_.httpUpgradeCount)).append(",");
    json.append("\"totalHttpUpgradeTimeMs\":").append(std::to_string(protoStats_.totalHttpUpgradeTimeMs)).append(",");
    json.append("\"successTimeMs\":").append(std::to_string(protoStats_.successTimeMs)).append(",");
    json.append("\"versionCount\":").append(BuildVersionCount(protoStats_.versionCount));
    return json;
}

std::string SocketStatisticsBase::BuildErrorStatsJsonLocked()
{
    std::string json;
    json.append("\"errorStats\":[");
    bool first = true;
    for (const auto &item : errorStats_) {
        if (!first) {
            json.append(",");
        }
        first = false;
        json.append("{\"dstIp\":\"").append(item.first).append("\",");
        json.append("\"hostName\":\"").append(item.second.hostName).append("\",");
        json.append("\"totalCount\":").append(std::to_string(item.second.totalCount)).append(",");
        json.append("\"abnormalCount\":").append(std::to_string(item.second.abnormalCount)).append(",");
        json.append("\"versionInfo\":").append(BuildVersionCount(item.second.versionInfo)).append(",");
        json.append("\"socketErrorCode\":{");
        bool innerFirst = true;
        for (const auto &e : item.second.socketErrorCode) {
            if (!innerFirst) {
                json.append(",");
            }
            innerFirst = false;
            json.append("\"").append(std::to_string(e.first)).append("\":").append(std::to_string(e.second));
        }
        json.append("}}");
    }
    json.append("]");
    return json;
}

void SocketStatisticsBase::ResetStatisticsLocked()
{
    protoStats_ = SocketProtoStats{};
    errorStats_.clear();
}

SocketStatisticsEvent &SocketStatisticsEvent::GetInstance()
{
    static SocketStatisticsEvent instance;
    return instance;
}

SocketStatisticsBase &SocketStatisticsEvent::TlsSocket()
{
    return tlsSocket_;
}

SocketStatisticsBase &SocketStatisticsEvent::WsSocket()
{
    return wsSocket_;
}

SocketStatisticsBase &SocketStatisticsEvent::WssSocket()
{
    return wssSocket_;
}

std::string SocketStatisticsEvent::BuildStatisticsJsonLocked(const std::string &bundleName)
{
    std::string json;
    json.append("{\"bundleName\":\"").append(bundleName).append("\",");
    json.append("\"tlsStats\":{").append(tlsSocket_.BuildProtoStatsJsonLocked()).append(",");
    json.append(tlsSocket_.BuildErrorStatsJsonLocked()).append("},");
    json.append("\"wsStats\":{").append(wsSocket_.BuildProtoStatsJsonLocked()).append(",");
    json.append(wsSocket_.BuildErrorStatsJsonLocked()).append("},");
    json.append("\"wssStats\":{").append(wssSocket_.BuildProtoStatsJsonLocked()).append(",");
    json.append(wssSocket_.BuildErrorStatsJsonLocked()).append("}}");
    return json;
}

SocketStatisticsBase &SocketStatisticsEvent::GetWebsocketStat(bool isWss)
{
    return isWss ? wssSocket_ : wsSocket_;
}

void SocketStatisticsEvent::TryReportStatistics()
{
#ifdef HAS_NETMANAGER_BASE
    std::lock_guard<std::mutex> lock(reportMutex_);
    time_t currentTime = time(0);
    if (lastReportTime_ == 0) {
        lastReportTime_ = currentTime;
    }
    if (currentTime - lastReportTime_ < REPORT_TIME_INTERVAL) {
        return;
    }
    lastReportTime_ = currentTime;
    std::string bundleName = "";
    // LCOV_EXCL_START
    if (CommonUtils::GetBundleName().has_value()) {
        bundleName = CommonUtils::GetBundleName().value();
    }
    // LCOV_EXCL_STOP
    std::lock_guard<std::mutex> tlsLock(tlsSocket_.mutex_);
    std::lock_guard<std::mutex> wsLock(wsSocket_.mutex_);
    std::lock_guard<std::mutex> wssLock(wssSocket_.mutex_);
    std::string jsonStr = BuildStatisticsJsonLocked(bundleName);
    if (PublishSocketPerfEvent(jsonStr)) {
        tlsSocket_.ResetStatisticsLocked();
        wsSocket_.ResetStatisticsLocked();
        wssSocket_.ResetStatisticsLocked();
    }
#endif
}

} // namespace SocketStats
} // namespace NetStack
} // namespace OHOS
