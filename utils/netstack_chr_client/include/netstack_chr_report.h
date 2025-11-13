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

#ifndef COMMUNICATIONNETSTACK_NETSTACK_CHR_REPORT_H
#define COMMUNICATIONNETSTACK_NETSTACK_CHR_REPORT_H
 
#include <chrono>
#include "i_netstack_chr_client.h"
#include "want.h"
 
namespace OHOS::NetStack::ChrClient {

using namespace OHOS::NetStack::ChrClient;

class NetStackChrReport {
public:
    NetStackChrReport();
    ~NetStackChrReport();
 
    int ReportCommonEvent(DataTransChrStats chrStats);
private:
    std::mutex report_mutex_;
    std::map<int32_t, int32_t> ipTypeIgnores_ = {
        {AF_INET, 0}, // IPv4，value: 2
        {AF_INET6, 0} // IPv6，value: 10
    };
    std::map<int32_t, std::chrono::system_clock::time_point> ipTypeLastReceiveTime_ = {
        {AF_INET, std::chrono::system_clock::time_point{}}, // IPv4
        {AF_INET6, std::chrono::system_clock::time_point{}} // IPv6
    };
    void SetWantParam(AAFwk::Want& want, DataTransChrStats chrStats);
    void SetHttpInfoJsonStr(DataTransHttpInfo httpInfo, std::string& httpInfoJsonStr);
    void SetTcpInfoJsonStr(DataTransTcpInfo tcpInfo, std::string& tcpInfoJsonStr);
};
}  // namespace OHOS::NatStack::ChrClient
#endif // COMMUNICATIONNETSTACK_NETSTACK_CHR_REPORT_H