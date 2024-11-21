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
#include <chrono>
#include <cerrno>

#include "hisysevent.h"
#include "netstack_log.h"
#include "netstack_hisysevent.h"
#include "netstack_common_utils.h"

namespace OHOS::NetStack {

namespace {
using HiSysEvent = OHOS::HiviewDFX::HiSysEvent;
const uint32_t REPORT_INTERVAL = 3 * 60;
const uint32_t REPORT_NET_STACK_INTERVAL = 60;
inline const int32_t PROP_SYSPARA_SIZE = 128;
constexpr int32_t DECIMAL_BASE = 10;
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
constexpr const char *NET_STACK_HTTP_FAULT_QUEUE = "NET_STACK_FAULT_QUEUE";
const int64_t VALIAD_RESP_CODE_START = 200;
const int64_t VALIAD_RESP_CODE_END = 399;
const int64_t ERROR_HTTP_CODE_START = 400;
const int64_t ERROR_HTTP_CODE_END = 600;
const int64_t HTTP_SUCCEED_CODE = 0;
const int64_t HTTP_APP_UID_THRESHOLD = 20000;
const int64_t HTTP_SEND_CHR_THRESHOLD = 5;
const unsigned int MAX_QUEUE_SIZE = 10;
const unsigned int ERROR_COUNT_THRESHOLD = 10;
const uint32_t REPORT_HIVIEW_INTERVAL = 10 * 60;
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

void EventReport::HandleHttpPerfEvents(const HttpPerfInfo &httpPerfInfo)
{
    eventInfo_.totalCount += 1;
    if (httpPerfInfo.IsSuccess() && httpPerfInfo.totalTime != 0) {
        eventInfo_.successCount += 1;
        eventInfo_.totalTime += httpPerfInfo.totalTime;
        eventInfo_.totalRate += httpPerfInfo.size / httpPerfInfo.totalTime;
        eventInfo_.totalDnsTime += httpPerfInfo.dnsTime;
        eventInfo_.totalTlsTime += httpPerfInfo.tlsTime;
        eventInfo_.totalFirstRecvTime += httpPerfInfo.firstRecvTime;
        eventInfo_.totalTcpTime += httpPerfInfo.tcpTime;
        auto result = versionMap_.emplace(httpPerfInfo.version, 1);
        if (!result.second) {
            ++(result.first->second);
        }
    }
    time_t currentTime = time(0);
    if (currentTime - reportTime_ >= REPORT_INTERVAL) {
        eventInfo_.packageName = packageName_;
        eventInfo_.version = MapToJsonString(versionMap_);
        NETSTACK_LOGD("Sending HTTP_PERF event");
        SendHttpPerfEvent(eventInfo_);
        ResetCounters();
        reportTime_ = currentTime;
    }
}

void EventReport::HandleHttpNetStackEvents(HttpPerfInfo &httpPerfInfo)
{
    if (sendHttpNetStackEventCount_ >= HTTP_SEND_CHR_THRESHOLD &&
        time(0) - firstReportHttpTime_ <= reportHiviewInterval_) {
        return;
    }
 
    if (sendHttpNetStackEventCount_ >= HTTP_SEND_CHR_THRESHOLD &&
        time(0) - firstReportHttpTime_ >= reportHiviewInterval_) {
        sendHttpNetStackEventCount_ = 0;
        firstReportHttpTime_ = 0;
    }
    httpPerfInfo.packageName = packageName_;
 
    if (!httpPerfInfo.IsError()) {
        totalErrorCount_ = 0;
        netStackInfoQue_.clear();
        return;
    }
 
    totalErrorCount_ += 1;
    netStackInfoQue_.push_back(httpPerfInfo);
 
    if (totalErrorCount_ >= errorCountThreshold_) {
        if (netStackInfoQue_.size() >= maxQueueSize_ || time(0) - reportTime_ >= REPORT_NET_STACK_INTERVAL) {
            SendHttpNetStackEvent(netStackInfoQue_);
            totalErrorCount_ = 0;
            netStackInfoQue_.clear();
        }
    }
}

void EventReport::ResetCounters()
{
    eventInfo_.totalCount = 0;
    eventInfo_.successCount = 0;
    eventInfo_.totalTime = 0.0;
    eventInfo_.totalRate = 0.0;
    eventInfo_.totalDnsTime = 0.0;
    eventInfo_.totalTlsTime = 0.0;
    eventInfo_.totalTcpTime = 0.0;
    eventInfo_.totalFirstRecvTime = 0.0;
    versionMap_.clear();
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

std::string EventReport::HttpNetStackInfoToJson(const HttpPerfInfo &info)
{
    std::stringstream ss;
    ss << "{"
       << "\"packageName\": " << std::quoted(info.packageName) << ", "
       << "\"method\": " << std::quoted(info.method) << ", "
       << "\"ipType\": " << std::quoted(info.ipType) << ", "
       << "\"responseCode\": " << info.responseCode << ", "
       << "\"errorCode\": " << info.errorCode << ", "
       << "\"connectTime\": " << info.connectTime << ", "
       << "\"dnsTime\": " << info.dnsTime << ", "
       << "\"tlsTime\": " << info.tlsTime
       << "}";
    return ss.str();
}
 
void EventReport::SendHttpNetStackEvent(std::deque<HttpPerfInfo> &netStackInfoQue_)
{
    std::vector<std::string> eventQueue;
    for (const auto &info : netStackInfoQue_) {
        eventQueue.push_back(HttpNetStackInfoToJson(info));
    }
 
    int ret = HiSysEventWrite(HiSysEvent::Domain::NETMANAGER_STANDARD, NET_STACK_HTTP_FAULT,
                              HiSysEvent::EventType::STATISTIC, NET_STACK_HTTP_FAULT_QUEUE, eventQueue);
    if (ret != 0) {
        NETSTACK_LOGE("Send EventReport::SendHttpNetStackEvent NET_STACK_HTTP_FAULT event failed");
    }
    firstReportHttpTime_ = time(0);
    sendHttpNetStackEventCount_++;
    netStackInfoQue_.clear();
}
 
std::string EventReport::GetParameterString(const char* key, const std::string &defValue)
{
    char valueStr[PROP_SYSPARA_SIZE] = { 0 };
    GetParameter(key, defValue.c_str(), valueStr, PROP_SYSPARA_SIZE);
    return valueStr;
}
 
int EventReport::GetParameterInt(const char* key, const int &defValue)
{
    std::string valueStr = GetParameterString(key);
    int value = defValue;
    StrToInt(valueStr, value);
    return value;
}
 
bool EventReport::IsParameterTrue(const char* key, const std::string &defValue)
{
    char valueStr[PROP_SYSPARA_SIZE] = { 0 };
    GetParameter(key, defValue.c_str(), valueStr, PROP_SYSPARA_SIZE);
    return (strcmp(valueStr, "true") == 0);
}
 
int32_t EventReport::StrToInt(const std::string &str, int32_t defaultValue)
{
    char *end = nullptr;
    const char *ptr = str.c_str();
    errno = 0;
    int64_t num = std::strtol(ptr, &end, DECIMAL_BASE);
    if (errno == ERANGE || end == ptr || *end != '\0') {
        return defaultValue;
    }
    if (num >= std::numeric_limits<int32_t>::min() && num <= std::numeric_limits<int32_t>::max()) {
        return static_cast<int32_t>(num);
    } else {
        return defaultValue;
    }
}
}