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
#include "parameter.h"

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
    double firstRecvTime;
    double tcpTime;
    curl_off_t size;
    int64_t responseCode;
    std::string version;
    int64_t currentTime;
    uint32_t uid;
    std::string packageName;
    std::string method;
    std::string ipType;
    int32_t errorCode;
    double connectTime;
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
    void SendHttpNetStackEvent(std::deque<HttpPerfInfo>& netStackInfoQueue);
    void HandleHttpPerfEvents(const HttpPerfInfo &httpPerfInfo);
    void HandleHttpNetStackEvents(HttpPerfInfo &httpPerfInfo);
    std::string HttpNetStackInfoToJson(const HttpPerfInfo &info);
    std::string GetParameterString(const char* key, const std::string &defValue = "");
    int GetParameterInt(const char* key, const int &defValue = INVALID_INT);
    bool IsParameterTrue(const char* key, const std::string &defValue);
    int32_t StrToInt(const std::string &str, int32_t defaultValue);

private:
    static constexpr const int INVALID_INT = -1;
    time_t reportTime_ = 0;
    time_t firstReportHttpTime_ = 0;
    int sendHttpNetStackEventCount_ = 0;
    unsigned int totalErrorCount_ = 0;
    std::string packageName_;
    EventInfo eventInfo_;
    std::map<std::string, uint32_t> versionMap_;
    std::deque<HttpPerfInfo> netStackInfoQue_;
    unsigned int maxQueueSize_;
    unsigned int errorCountThreshold_;
    uint32_t reportHiviewInterval_;
    bool validFlag_ = true;
    bool httpPerfEventSwitch_;
    bool netStackEventSwitch_;
    std::recursive_mutex mutex_;
};
}
#endif