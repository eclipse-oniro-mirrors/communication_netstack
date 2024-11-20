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
#include <iostream>
#include <iomanip>

#include "hisysevent.h"
#include "netstack_log.h"
#include "netstack_hisysevent.h"
#include "netstack_common_utils.h"

namespace OHOS::NetStack {

namespace {
using HiSysEvent = OHOS::HiviewDFX::HiSysEvent;
const uint32_t REPORT_INTERVAL = 3 * 60;
const uint32_t REPORT_NET_STACK_INTERVAL = 60;
// event_name
constexpr const char *HTTP_PERF_ENAME = "HTTP_PERF";
constexpr const char *NET_STACK_HTTP_FAULT = "NET_STACK_HTTP_FAULT";
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
constexpr const char *HTTP_NET_STACK_FAULT_QUEUE = "NET_STACK_FAULT_QUEUE";
const int64_t VALIAD_RESP_CODE_START = 200;
const int64_t VALIAD_RESP_CODE_END = 399;
const int64_t ERROR_HTTP_CODE_START = 400;
const int64_t ERROR_HTTP_CODE_START = 600;
const int64_t HTTP_SUCCEED_CODE = 0;
const int64_t REPORT_HIVIEW_INTERVAL = 10 * 60;
const int64_t HTTP_APP_UID_THRESHOLD = 20000;
const int64_t HTTP_SEND_CHR_THRESHOLD = 5;
const unsigned int MAX_QUEUE_SIZE = 10;
const unsigned int ERROR_COUNT_THRESHOLD = 10;
}

bool HttpPerfInfo::IsSuccess() const
{
    return responseCode >= VALIAD_RESP_CODE_START && responseCode <= VALIAD_RESP_CODE_END;
}

bool HttpPerfInfo::IsError() const
{
    return (responseCode >= ERROR_HTTP_CODE_START && responseCode < ERROR_HTTP_CODE_END)
            || errorCode != HTTP_SUCCEED_CODE;
}

EventReport::EventReport()
{
    InitPackageName();
    reportHiviewInterval_ = GEtParameterInt("const.telephony.netstack.interval", REPORT_HIVIEW_INTERVAL);
    errorCountThreshold_ = GEtParameterInt("const.telephony.netstack.interval", ERROR_COUNT_THRESHOLD);
    maxQueueSize_ = GEtParameterInt("const.telephony.netstack.interval", MAX_QUEUE_SIZE);
    httpPerfEventSwitch_ = GEtParameterInt("const.telephony.netstack.interval", REPORT_HIVIEW_INTERVAL);
    netStackEventSwitch_ = GEtParameterInt("const.telephony.netstack.interval", REPORT_HIVIEW_INTERVAL);
}

void EventReport::InitPackageName()
{
    if (CommonUtils::GetBundleName().has_value()) {
        packageName_ = CommonUtils::GetBundleName().value();
    } else {
        validFlag_ = false;
    }
    // init eventInfo
    ResetCounters();
}

bool EventReport::IsValid()
{
    return validFlag_;
}

EventReport &EventReport::GetInstance()
{
    static EventReport instance;
    return instance;
}

void EventReport::ProcessEvents(HttpPerfInfo &httpPerfInfo)
{
    std::lock_guard<std::recursive_mutex> lock(mutex);
    if (reportTime_ == 0) {
        reportTime_ = time(0);
    }

    if (httpPerfInfo.uid > HTTP_APP_UID_THRESHOLD && netStackEventSwitch_) {
        HandleHttpNetStackEvents(httpPerfInfo);
    }
    if (httpPerfEventSwitch_) {
        HandleHttpPerfEvents(httpPerfInfo);
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