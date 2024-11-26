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
    void HandleHttpResponseErrorEvents(HttpPerfInfo &httpPerfInfo);
    void SendHttpResponseErrorEvent(std::deque<HttpPerfInfo>& netStackInfoQueue);
    std::vector<std::string> convertDequeToVector(const std::deque<HttpPerfInfo>& netStackInfoQue_);
    void extractFieldsToArrays(std::deque<HttpPerfInfo> &netStackInfoQue_,
                               std::vector<std::string> &dnsTimeArr,
                               std::vector<std::string> &tlsTimeArr,
                               std::vector<std::string> &respCodeArr,
                               std::vector<std::string> &ipTypeArr,
                               std::vector<std::string> &osErrArr,
                               std::vector<std::string> &errCodeArr,
                               std::vector<std::string> &methodArr,
                               std::vector<std::string> &packageNameArr);
private:
    time_t reportTime_ = 0;
    double topAppReportTime_ = 0;
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
    std::recursive_mutex mutex_;
};
}
#endif