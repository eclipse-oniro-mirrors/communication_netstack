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

#ifndef NETSTACK_INCLUDE_HISYSEVENT_H
#define NETSTACK_INCLUDE_HISYSEVENT_H

#include <string>
#include <map>
#include <mutex>
#include <queue>

#include "curl/curl.h"

namespace OHOS::NetStack {

struct EventInfo {
    std::string packageName;
    double totalTime;
    double totalRate;
    double totalDnsTime;
    double totalTlsTime;
    double totalTcpTime;
    double totalFirstRecvTime;
    uint32_t successCount;
    uint32_t totalCount;
    std::string version;
};

struct HttpPerfInfo {
    double totalTime;
    double dnsTime;
    double tlsTime;
    double firstSendTime;
    double firstRecvTime;
    double tcpTime;
    curl_off_t size;
    int64_t responseCode;
    std::string version;
    long osErr;
    int ipType;
    int32_t errCode;
    std::string method;
public:
    bool IsSuccess() const;
    bool IsError() const;
};

class EventReport {
public:
    void SendHttpPerfEvent(const EventInfo &eventInfo);
    static EventReport &GetInstance();
    bool IsValid();
    void ProcessEvents(HttpPerfInfo &httpPerfInfo);

private:
    EventReport();
    ~EventReport() = default;
    EventReport(const EventReport &eventReport) = delete;
    const EventReport &operator=(const EventReport &eventReport) = delete;
    void InitPackageName();
    void ResetCounters();
    std::string GetPackageName();
    std::string MapToJsonString(const std::map<std::string, uint32_t> mapPara);
    void HandleHttpPerfEvents(const HttpPerfInfo &httpPerfInfo);
    void HandleHttpResponseErrorEvents(const HttpPerfInfo &httpPerfInfo);
    void SendHttpResponseErrorEvent(std::deque<HttpPerfInfo>& netStackInfoQueue,
                                    const std::chrono::steady_clock::time_point now);
    std::string HttpPerInfoToJson(const HttpPerfInfo &info);
private:
    time_t reportTime_ = 0;
    std::chrono::steady_clock::time_point topAppReportTime_ = std::chrono::steady_clock::time_point::min();
    int sendHttpNetStackEventCount_ = 0;
    unsigned int totalErrorCount_ = 0;
    std::string packageName_;
    EventInfo eventInfo_;
    std::map<std::string, uint32_t> versionMap_;
    std::deque<HttpPerfInfo> httpPerfInfoQueue_;
    bool validFlag_ = true;
    std::recursive_mutex mutex_;
};
}
#endif