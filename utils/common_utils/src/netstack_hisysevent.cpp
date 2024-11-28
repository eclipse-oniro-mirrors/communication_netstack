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
#include <unistd.h>

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
constexpr const char *HTTP_RESPONSE_ERROR = "NET_STACK_HTTP_RESPONSE_ERROR";
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
constexpr const char *HTTP_RESPONSE_ERROR_ARRAY = "NET_STACK_ERROR_ARRAY";
const int64_t VALIAD_RESP_CODE_START = 200;
const int64_t VALIAD_RESP_CODE_END = 399;
const int64_t ERROR_HTTP_CODE_START = 400;
const int64_t ERROR_HTTP_CODE_END = 600;
const int64_t HTTP_SUCCEED_CODE = 0;
const int64_t HTTP_APP_UID_THRESHOLD = 20000;
const int64_t HTTP_SEND_CHR_THRESHOLD = 5;
const unsigned int MAX_QUEUE_SIZE = 10;
const unsigned int ERR_COUNT_THRESHOLD = 10;
const uint32_t REP_HIVIEW_INTERVAL = 10 * 60 * 1000;
}

bool HttpPerfInfo::IsSuccess() const
{
    return responseCode >= VALIAD_RESP_CODE_START && responseCode <= VALIAD_RESP_CODE_END;
}

bool HttpPerfInfo::IsError() const
{
    return (responseCode >= ERROR_HTTP_CODE_START && responseCode < ERROR_HTTP_CODE_END)
            || errCode != HTTP_SUCCEED_CODE;
}

EventReport::EventReport()
{
    InitPackageName();
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
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    if (getuid() > HTTP_APP_UID_THRESHOLD) {
        HandleHttpResponseErrorEvents(httpPerfInfo);
    }
    HandleHttpPerfEvents(httpPerfInfo);
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
    if (reportTime_ == 0) {
        reportTime_ = currentTime;
    }
    if (currentTime - reportTime_ >= REPORT_INTERVAL) {
        eventInfo_.packageName = packageName_;
        eventInfo_.version = MapToJsonString(versionMap_);
        NETSTACK_LOGD("Sending HTTP_PERF event");
        SendHttpPerfEvent(eventInfo_);
        ResetCounters();
        reportTime_ = currentTime;
    }
}

void EventReport::HandleHttpResponseErrorEvents(const HttpPerfInfo &httpPerfInfo)
{
    if (!httpPerfInfo.IsError()) {
        totalErrorCount_ = 0;
        httpPerfInfoQueue_.clear();
        return;
    }
    totalErrorCount_ += 1;
    httpPerfInfoQueue_.push_back(httpPerfInfo);

    auto now = std::chrono::steady_clock::now();
    if (topAppReportTime_ == std::chrono::steady_clock::time_point::min()) {
        topAppReportTime_ = std::chrono::steady_clock::now();
    }
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - topAppReportTime_).count();

    if (totalErrorCount_ >= ERR_COUNT_THRESHOLD) {
        if (httpPerfInfoQueue_.size() >= MAX_QUEUE_SIZE || duration >= REPORT_NET_STACK_INTERVAL) {
            SendHttpResponseErrorEvent(httpPerfInfoQueue_, now);
            totalErrorCount_ = 0;
            httpPerfInfoQueue_.clear();
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

std::string EventReport::HttpPerInfoToJson(const HttpPerfInfo &info)
{
    std::stringstream ss;
    ss << "{"
       << "\"firstSendTime\": " << info.firstSendTime << ", "
       << "\"firstRecvTime\": " << info.firstRecvTime << ", "
       << "\"packName\": " << std::quoted(packageName_) << ", "
       << "\"method\": " << std::quoted(info.method) << ", "
       << "\"ipType\": " << info.ipType << ", "
       << "\"respCode\": " << info.responseCode << ", "
       << "\"errCode\": " << info.errCode << ", "
       << "\"osErr\": " << info.osErr << ", "
       << "\"tcpTime\": " << info.tcpTime << ", "
       << "\"dnsTime\": " << info.dnsTime << ", "
       << "\"tlsTime\": " << info.tlsTime
       << "}";
    return ss.str();
}

void EventReport::SendHttpResponseErrorEvent(std::deque<HttpPerfInfo> &httpPerfInfoQueue_,
                                             const std::chrono::steady_clock::time_point now)
{
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - topAppReportTime_).count();
    if (sendHttpNetStackEventCount_ >= HTTP_SEND_CHR_THRESHOLD && duration <= REP_HIVIEW_INTERVAL) {
        NETSTACK_LOGI("Sending HTTP_RESPONSE_ERROR event already over.");
        return;
    }
 
    if (sendHttpNetStackEventCount_ >= HTTP_SEND_CHR_THRESHOLD && duration >= REP_HIVIEW_INTERVAL) {
        NETSTACK_LOGI("Sending HTTP_RESPONSE_ERROR event reopen.");
        sendHttpNetStackEventCount_ = 0;
        topAppReportTime_ = now;
    }
 
    std::vector<std::string> eventQueue;
    for (const auto &info : httpPerfInfoQueue_) {
        eventQueue.push_back(HttpPerInfoToJson(info));
    }
 
    int ret = HiSysEventWrite(HiSysEvent::Domain::NETMANAGER_STANDARD, HTTP_RESPONSE_ERROR,
                              HiSysEvent::EventType::FAULT, HTTP_RESPONSE_ERROR_ARRAY, eventQueue);
    if (ret != 0) {
        NETSTACK_LOGE("Send EventReport::SendHttpNetStackEvent HTTP_RESPONSE_ERROR_ARRAY event failed");
    }
    sendHttpNetStackEventCount_++;
}
}