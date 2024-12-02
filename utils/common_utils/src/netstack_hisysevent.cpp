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
#include <chrono>
#include <unistd.h>

#include "hisysevent.h"
#include "netstack_log.h"
#include "netstack_hisysevent.h"
#include "netstack_common_utils.h"

namespace OHOS::NetStack {

namespace {
using HiSysEvent = OHOS::HiviewDFX::HiSysEvent;
const uint32_t REPORT_INTERVAL = 3 * 60;
const uint32_t REPORT_NET_STACK_INTERVAL = 10 * 1000;
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
constexpr const char *TOTAL_FIRST_SEND_TIME_EPARA = "TOTAL_FIRST_SEND_TIME";
constexpr const char *HTTP_RESPONSE_ERROR_ARRAY = "NET_STACK_ERROR_ARRAY";
constexpr const char *IP_TYPE_EPARA = "IP_TYPE";
constexpr const char *OS_ERR_EPARA = "OS_ERR";
constexpr const char *ERROR_CODE_EPARA = "ERROR_CODE";
const int64_t VALIAD_RESP_CODE_START = 200;
const int64_t VALIAD_RESP_CODE_END = 399;
const int64_t ERROR_HTTP_CODE_START = 400;
const int64_t ERROR_HTTP_CODE_END = 600;
const int64_t HTTP_SUCCEED_CODE = 0;
const int64_t HTTP_APP_UID_THRESHOLD = 200000 * 100;
const int64_t HTTP_SEND_CHR_THRESHOLD = 5;
const unsigned int MAX_QUEUE_SIZE = 10;
const unsigned int ERR_COUNT_THRESHOLD = 10;
const uint32_t REPORT_HIVIEW_INTERVAL = 10 * 60 * 1000;
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
        validFlag = false;
    }
    // init eventInfo
    ResetCounters();
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

    if (getuid() > HTTP_APP_UID_THRESHOLD) {
        HandleHttpResponseErrorEvents(httpPerfInfo);
    }
    HandleHttpPerfEvents(httpPerfInfo);
}

void EventReport::HandleHttpPerfEvents(const HttpPerfInfo &httpPerfInfo)
{
    eventInfo.totalCount += 1;
    if (httpPerfInfo.IsSuccess() && httpPerfInfo.totalTime != 0) {
        eventInfo.successCount += 1;
        eventInfo.totalTime += httpPerfInfo.totalTime;
        eventInfo.totalRate += httpPerfInfo.size / httpPerfInfo.totalTime;
        eventInfo.totalDnsTime += httpPerfInfo.dnsTime;
        eventInfo.totalTlsTime += httpPerfInfo.tlsTime;
        eventInfo.totalFirstRecvTime += httpPerfInfo.firstRecvTime;
        eventInfo.totalTcpTime += httpPerfInfo.tcpTime;
        auto result = versionMap.emplace(httpPerfInfo.version, 1);
        if (!result.second) {
            ++(result.first->second);
        }
    }
    time_t currentTime = time(0);
    if (reportTime == 0) {
        reportTime = currentTime;
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
    int32_t httpReportInterval_ = 0;
    if (httpReponseRecordTime_  != std::chrono::steady_clock::time_point::min()) {
        httpReportInterval_ = static_cast<int32_t>(std::chrono::duration_cast<std::chrono::milliseconds>
                              (now - httpReponseRecordTime_).count());
    }
    httpReponseRecordTime_ = now;

    if (totalErrorCount_ >= ERR_COUNT_THRESHOLD) {
        if (httpPerfInfoQueue_.size() >= MAX_QUEUE_SIZE || httpReportInterval_ >= REPORT_NET_STACK_INTERVAL) {
            SendHttpResponseErrorEvent(httpPerfInfoQueue_, now);
            totalErrorCount_ = 0;
            httpPerfInfoQueue_.clear();
        }
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

void EventReport::ReportHiSysEventWrite(const std::deque<HttpPerfInfo> &httpPerfInfoQueue_)
{
    if (httpPerfInfoQueue_.empty()) {
        return;
    }   
    std::vector<double> dnsTimeArr;
    std::vector<double> tcpTimeArr;
    std::vector<double> tlsTimeArr;
    std::vector<int32_t> errCodeArr;
    std::vector<int64_t> osErrArr;
    std::vector<int> ipTypeArr;
    double totalRecvTime = 0.0;
    double totalSendTime = 0.0;

    for (const auto& info : httpPerfInfoQueue_) {
        dnsTimeArr.push_back(info.dnsTime);
        tcpTimeArr.push_back(info.tcpTime);
        tlsTimeArr.push_back(info.tlsTime);
        osErrArr.push_back(info.osErr);
        ipTypeArr.push_back(info.ipType);

        if (info.errCode != 0) {
            errCodeArr.push_back(info.errCode);
        } else {
            errCodeArr.push_back(info.responseCode);
        }

        totalRecvTime += info.firstRecvTime;
        totalSendTime += info.firstSendTime;
    }

    double receiveAverTime;
    double sendAverTime;
    size_t count = httpPerfInfoQueue_.size();
    receiveAverTime = totalRecvTime / count;
    sendAverTime = totalSendTime / count;
    int ret = HiSysEventWrite(HiSysEvent::Domain::NETMANAGER_STANDARD, HTTP_RESPONSE_ERROR,
                              HiSysEvent::EventType::FAULT, PACKAGE_NAME_EPARA, packageName_,
                              TOTAL_DNS_TIME_EPARA, dnsTimeArr, TOTAL_TCP_TIME_EPARA, tcpTimeArr,
                              TOTAL_TLS_TIME_EPARA, tlsTimeArr, ERROR_CODE_EPARA, errCodeArr, OS_ERR_EPARA, osErrArr,
                              IP_TYPE_EPARA, ipTypeArr, TOTAL_FIRST_RECVIVE_TIME_EPARA, receiveAverTime,
                              TOTAL_FIRST_SEND_TIME_EPARA, sendAverTime);
    if (ret != 0) {
        NETSTACK_LOGE("Send EventReport::ReportHiSysEventWrite event failed");
    }
}

void EventReport::SendHttpResponseErrorEvent(const std::deque<HttpPerfInfo> &httpPerfInfoQueue_,
                                             const std::chrono::steady_clock::time_point now)
{
    if (httpPerfInfoQueue_.empty()) {
        return;
    }

    if (hiviewReportFirstTime_ == std::chrono::steady_clock::time_point::min()) {
        hiviewReportFirstTime_ = now;
    }
    int32_t hiviewReportInterval_ = static_cast<int32_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now - hiviewReportFirstTime_).count());
    if (hiviewReportInterval_ >= REPORT_HIVIEW_INTERVAL) {
        sendHttpNetStackEventCount_ = 0;
        hiviewReportFirstTime_ = std::chrono::steady_clock::time_point::min();
        NETSTACK_LOGI("SendHttpResponseErrorEvent NET_STACK_HTTP_RESPONSE_ERROR event threshold reopen.");
    } else if (sendHttpNetStackEventCount_ >= HTTP_SEND_CHR_THRESHOLD) {
        NETSTACK_LOGI("SendHttpResponseErrorEvent NET_STACK_HTTP_RESPONSE_ERROR event threshold already reached.");
        return;
    }

    ReportHiSysEventWrite(httpPerfInfoQueue_);
    sendHttpNetStackEventCount_++;
}
}