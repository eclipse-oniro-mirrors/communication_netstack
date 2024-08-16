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
    curl_off_t size;
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
public:
    bool IsSuccess() const;
};

class EventReport {
public:
    void ProcessHttpPerfHiSysevent(const HttpPerfInfo &httpPerfInfo);
    void SendHttpPerfEvent(const EventInfo &eventInfo);
    static EventReport &GetInstance();
    bool IsValid();

private:
    EventReport();
    ~EventReport() = default;
    EventReport(const EventReport &eventReport) = delete;
    const EventReport &operator=(const EventReport &eventReport) = delete;
    void InitPackageName();
    void ResetCounters();
    std::string GetPackageName();
    std::string MapToJsonString(const std::map<std::string, uint32_t> mapPara);

private:
    time_t reportTime;
    std::string packageName_;
    EventInfo eventInfo;
    std::map<std::string, uint32_t> versionMap;
    bool validFlag = true;
    std::recursive_mutex mutex;
};
}
#endif