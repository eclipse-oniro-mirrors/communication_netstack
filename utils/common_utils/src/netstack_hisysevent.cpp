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

#include <sstream>

#include "hisysevent.h"
#include "netstack_log.h"
#include "netstack_hisysevent.h"
#include "netstack_common_utils.h"

namespace OHOS::NetStack {

namespace {
using HiSysEvent = OHOS::HiviewDFX::HiSysEvent;
const uint32_t REPORT_INTERVAL = 10;
// event_name
constexpr const char *HTTP_PERF_ENAME = "HTTP_PERF";
// event params
constexpr const char *PACKAGE_NAME_EPARA = "PACKAGE_NAME";
constexpr const char *TOTAL_TIME_EPARA = "TOTAL_TIME";
constexpr const char *TOTAL_RATE_EPARA = "TOTAL_RATE";
constexpr const char *SUCCESS_COUNT_EPARA = "SUCCESS_COUNT";
constexpr const char *TOTAL_COUNT_EPARA = "TOTAL_COUNT";
constexpr const char *VERSION_EPARA = "VERSION";
constexpr const char *TOTAL_DNS_TIME_EPARA = "TOTAL_DNS_TIME";
constexpr const char *TOTAL_TLS_TIME_EPARA = "TOTAL_TLS_TIME";
constexpr const char *TOTAL_TCP_TIME_EPARA = "TOTAL_TCP_TIME";
constexpr const char *TOTAL_FIRST_RECVIVE_TIME_EPARA = "TOTAL_FIRST_RECEIVE_TIME";
const int64_t VALIAD_RESP_CODE_START = 200;
const int64_t VALIAD_RESP_CODE_END = 399;
}

bool HttpPerfInfo::IsSuccess() const
{
    if (responseCode >= VALIAD_RESP_CODE_START && responseCode <= VALIAD_RESP_CODE_END) {
        return true;
    }
    return false;
}

EventReport::EventReport()
{
    InitPackageName();
}

void EventReport::InitPackageName()
{
    auto bundleName = CommonUtils::GetBundleName();
    packageName_ = bundleName.value_or("");
    if (packageName_.empty()) {
        validFlag = false;
    }
}

bool EventReport::IsValid()
{
    return validFlag;
}

EventReport &EventReport::GetInstance()
{
    static EventReport instance;
    return instance;
}

void EventReport::ProcessHttpPerfHiSysevent(const HttpPerfInfo &httpPerfInfo)
{
    std::lock_guard<std::recursive_mutex> lock(mutex);
    time_t currentTime = time(0);

    if (reportTime == 0) {
        reportTime = currentTime;
    }
    eventInfo.totalCount += 1;
    if (httpPerfInfo.IsSuccess() && httpPerfInfo.totalTime != 0) {
        eventInfo.successCount += 1;
        eventInfo.totalTime += httpPerfInfo.totalTime;
        eventInfo.totalRate += httpPerfInfo.size / httpPerfInfo.totalTime;
        eventInfo.totalDnsTime += httpPerfInfo.dnsTime;
        eventInfo.totalTlsTime += httpPerfInfo.tlsTime;
        eventInfo.totalFirstRecvTime += httpPerfInfo.firstRecvTime;
        eventInfo.totalTcpTime += httpPerfInfo.tcpTime;
        auto it = versionMap.find(httpPerfInfo.version);
        if (it != versionMap.end()) {
            versionMap[httpPerfInfo.version] += 1;
        } else {
            versionMap[httpPerfInfo.version] = 1;
        }
    }
    if (currentTime - reportTime >= REPORT_INTERVAL) {
        eventInfo.packageName = packageName_;
        eventInfo.version = MapToJsonString(versionMap);
        NETSTACK_LOGD("Sending HTTP_PERF event");
        SendHttpPerfEvent(eventInfo);
        ResetCounters();
        reportTime = currentTime;
    }
}

void EventReport::ResetCounters()
{
    eventInfo.totalCount = 0;
    eventInfo.successCount = 0;
    eventInfo.totalTime = 0.0;
    eventInfo.totalRate = 0.0;
    eventInfo.totalDnsTime = 0.0;
    eventInfo.totalTlsTime = 0.0;
    eventInfo.totalTcpTime = 0.0;
    eventInfo.totalFirstRecvTime = 0.0;
    versionMap.clear();
}

std::string EventReport::MapToJsonString(const std::map<std::string, uint32_t> mapPara)
{
    if (mapPara.empty()) {
        return "{}";
    }
    std::stringstream sStream;
    size_t count = 0;
    for (const auto &pair : mapPara) {
        sStream << "\"" << pair.first << "\":" << pair.second;
        count++;
        if (count < mapPara.size()) {
            sStream << ",";
        }
    }
    return "{" + sStream.str() + "}";
}

void EventReport::SendHttpPerfEvent(const EventInfo &eventInfo)
{
    int ret = HiSysEventWrite(
        HiSysEvent::Domain::NETMANAGER_STANDARD, HTTP_PERF_ENAME, HiSysEvent::EventType::STATISTIC, PACKAGE_NAME_EPARA,
        eventInfo.packageName, TOTAL_TIME_EPARA, eventInfo.totalTime, TOTAL_RATE_EPARA, eventInfo.totalRate,
        SUCCESS_COUNT_EPARA, eventInfo.successCount, TOTAL_COUNT_EPARA, eventInfo.totalCount, VERSION_EPARA,
        eventInfo.version, TOTAL_DNS_TIME_EPARA, eventInfo.totalDnsTime, TOTAL_TLS_TIME_EPARA, eventInfo.totalTlsTime,
        TOTAL_TCP_TIME_EPARA, eventInfo.totalTcpTime, TOTAL_FIRST_RECVIVE_TIME_EPARA, eventInfo.totalFirstRecvTime);
    if (ret != 0) {
        NETSTACK_LOGE("Send HTTP_PERF event fail");
    }
}
}