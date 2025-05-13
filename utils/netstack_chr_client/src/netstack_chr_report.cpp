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
#include <string>
#include <chrono>
#include "i_netstack_chr_client.h"
#include "netstack_chr_report.h"
#include "netstack_log.h"
#include "common_event_manager.h"
#include "want.h"

using namespace OHOS::NetStack::ChrClient;

static constexpr const char* REPORT_HTTP_EVENT_NAME = "custom.event.CHR_REPORT_HTTP";
static constexpr const std::int32_t CHR_UID = 1201;
static constexpr const int REPORT_TIME_LIMIT_MINUTE = 5;

static constexpr const int REPORT_CHR_RESULT_SUCCESS = 0;
static constexpr const int REPORT_CHR_RESULT_TIME_LIMIT_ERROR = 1;
static constexpr const int REPORT_CHR_RESULT_REPORT_FAIL = 2;

NetStackChrReport::NetStackChrReport()
{}

NetStackChrReport::~NetStackChrReport()
{}

int NetStackChrReport::ReportCommonEvent(DataTransChrStats chrStats)
{
    std::lock_guard<std::mutex> lock(report_mutex_);
    auto currentTime = std::chrono::system_clock::now();
    auto timeDifference = std::chrono::duration_cast<std::chrono::minutes>(currentTime - lastReceivedTime_);
    if (timeDifference.count() < REPORT_TIME_LIMIT_MINUTE) {
        ignoreReportTimes_ += 1;
        return REPORT_CHR_RESULT_TIME_LIMIT_ERROR;
    }
    AAFwk::Want want;
    want.SetAction(REPORT_HTTP_EVENT_NAME);
    SetWantParam(want, chrStats);

    EventFwk::CommonEventData commonEventData;
    commonEventData.SetWant(want);
    EventFwk::CommonEventPublishInfo publishInfo;
    publishInfo.SetSubscriberUid({CHR_UID});
    if (!EventFwk::CommonEventManager::PublishCommonEvent(commonEventData, publishInfo)) {
        NETSTACK_LOGE("Subscriber is nullptr, report to CHR failed.");
        return REPORT_CHR_RESULT_REPORT_FAIL;
    }
    NETSTACK_LOGI("Report to CHR success, %{public}d reports are ignore before this.", ignoreReportTimes_);
    lastReceivedTime_ = currentTime;
    ignoreReportTimes_ = 0;

    return REPORT_CHR_RESULT_SUCCESS;
}

void NetStackChrReport::SetWantParam(AAFwk::Want& want, DataTransChrStats chrStats)
{
    want.SetParam("PROCESS_NAME", chrStats.processName);
    SetHttpInfo(want, chrStats.httpInfo);
    SetTcpInfo(want, chrStats.tcpInfo);
}

void NetStackChrReport::SetHttpInfo(AAFwk::Want& want, DataTransHttpInfo httpInfo)
{
    AAFwk::Want wantHttp;
    wantHttp.SetParam("uid", static_cast<int>(httpInfo.uid));
    wantHttp.SetParam("response_code", static_cast<int>(httpInfo.responseCode));
    wantHttp.SetParam("total_time", static_cast<long>(httpInfo.totalTime));
    wantHttp.SetParam("namelookup_time", static_cast<long>(httpInfo.nameLookUpTime));
    wantHttp.SetParam("connect_time", static_cast<long>(httpInfo.connectTime));
    wantHttp.SetParam("pretransfer_time", static_cast<long>(httpInfo.preTransferTime));    
    wantHttp.SetParam("size_upload", static_cast<long>(httpInfo.sizeUpload));
    wantHttp.SetParam("size_download", static_cast<long>(httpInfo.sizeDownload));
    wantHttp.SetParam("speed_download", static_cast<long>(httpInfo.speedDownload));
    wantHttp.SetParam("speed_upload", static_cast<long>(httpInfo.speedUpload));    
    wantHttp.SetParam("effective_method", std::string(httpInfo.effectiveMethod));
    wantHttp.SetParam("starttransfer_time", static_cast<long>(httpInfo.startTransferTime));
    wantHttp.SetParam("content_type", std::string(httpInfo.contentType));
    wantHttp.SetParam("redirect_time", static_cast<long>(httpInfo.redirectTime));
    wantHttp.SetParam("redirect_count", static_cast<long>(httpInfo.redirectCount));
    wantHttp.SetParam("os_errno", static_cast<long>(httpInfo.osError));
    wantHttp.SetParam("ssl_verifyresult", static_cast<long>(httpInfo.sslVerifyResult));
    wantHttp.SetParam("appconnect_time", static_cast<long>(httpInfo.appconnectTime));
    wantHttp.SetParam("retry_after", static_cast<long>(httpInfo.retryAfter));
    wantHttp.SetParam("proxy_error", static_cast<int>(httpInfo.proxyError));
    wantHttp.SetParam("queue_time", static_cast<long>(httpInfo.queueTime));
    wantHttp.SetParam("curl_code", static_cast<long>(httpInfo.curlCode));
    want.SetParam("DATA_TRANS_HTTP_INFO", wantHttp.ToString());
}

void NetStackChrReport::SetTcpInfo(AAFwk::Want& want, DataTransTcpInfo tcpInfo)
{
    AAFwk::Want wantTcp;
    wantTcp.SetParam("tcpi_unacked", static_cast<int>(tcpInfo.unacked));
    wantTcp.SetParam("tcpi_last_data_sent", static_cast<int>(tcpInfo.lastDataSent));
    wantTcp.SetParam("tcpi_last_ack_sent", static_cast<int>(tcpInfo.lastAckSent));
    wantTcp.SetParam("tcpi_last_data_recv", static_cast<int>(tcpInfo.lastDataRecv));
    wantTcp.SetParam("tcpi_last_ack_recv", static_cast<int>(tcpInfo.lastAckRecv));
    wantTcp.SetParam("tcpi_rtt", static_cast<int>(tcpInfo.rtt));
    wantTcp.SetParam("tcpi_rttvar", static_cast<int>(tcpInfo.rttvar));
    wantTcp.SetParam("tcpi_retransmits", static_cast<int>(tcpInfo.retransmits));
    wantTcp.SetParam("tcpi_total_retrans", static_cast<int>(tcpInfo.totalRetrans));
    wantTcp.SetParam("src_ip", std::string(tcpInfo.srcIp));
    wantTcp.SetParam("dst_ip", std::string(tcpInfo.dstIp));
    wantTcp.SetParam("src_port", static_cast<int>(tcpInfo.srcPort));
    wantTcp.SetParam("dst_port", static_cast<int>(tcpInfo.dstPort));
    want.SetParam("DATA_TRANS_TCP_INFO", wantTcp.ToString());
}