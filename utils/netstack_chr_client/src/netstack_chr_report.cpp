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
#include <sstream>
#include <chrono>
#include "i_netstack_chr_client.h"
#include "netstack_chr_report.h"
#include "netstack_log.h"
#include "common_event_manager.h"
#include "want.h"

using namespace OHOS::NetStack::ChrClient;

constexpr char REPORT_HTTP_EVENT_NAME[] = "custom.event.CHR_REPORT_HTTP";
constexpr int REPORT_TIME_LIMIT_MINUTE = 5;

NetstackChrReport::NetstackChrReport()
{}

NetstackChrReport::~NetstackChrReport()
{}

int NetstackChrReport::ReportCommonEvent(DataTransChrStats chrStats)
{
    std::lock_guard<std::mutex> lock(agentMutex_);
    auto currentTime = std::chrono::system_clock::now();
    auto timeDifference = std::chrono::duration_cast<std::chrono::minutes>(currentTime - lastReceivedTime_);
    if (timeDifference.count() < REPORT_TIME_LIMIT_MINUTE) {
        ignoreReportTimes_ += 1;
        return REPORT_CHR_RESULT_TIME_LIMIT_ERROR;
    }
    AAFwk::Want want;
    want.SetAction(REPORT_HTTP_EVENT_NAME);
    if (ConvertWantParam(want, chrStats) != 0) {
        return REPORT_CHR_RESULT_SET_DATA_FAIL;
    }

    EventFwk::CommonEventData common_event_data;
    common_event_data.SetWant(want);
    EventFwk::CommonEventPublishInfo publish_info;
    if (!EventFwk::CommonEventManager::PublishCommonEvent(common_event_data, publish_info)) {
        NETSTACK_LOGE("Subscriber is nullptr, report to CHR failed.");
        return REPORT_CHR_RESULT_REPORT_FAIL;
    }
    NETSTACK_LOGI("Report to CHR success, %{public}d reports are ignore before this.", ignoreReportTimes_);
    InforLog(chrStats);
    lastReceivedTime_ = currentTime;
    ignoreReportTimes_ = 0;

    return REPORT_CHR_RESULT_SUCCESS;
}

int NetstackChrReport::ConvertWantParam(AAFwk::Want& want, DataTransChrStats chrStats)
{
    std::string httpInfoJsonStr = ConvertHttpInfoToJsonStr(chrStats);
    std::string tcpInfoJsonStr = ConvertTcpInfoToJsonStr(chrStats);
    if (httpInfoJsonStr == "" or tcpInfoJsonStr == "") {
        return -1;
    }
    want.SetParam(PROCESS_NAME, chrStats.processName);
    want.SetParam(HTTP_INFO_KEY, httpInfoJsonStr);
    want.SetParam(TCP_INFO_KEY, tcpInfoJsonStr);
    return 0;
}

std::string NetstackChrReport::ConvertHttpInfoToJsonStr(DataTransChrStats chrStats)
{
    AAFwk::Want want;
    want.SetParam(CURL_CODE_KEY, static_cast<long>(chrStats.httpInfo.curlCode));
    want.SetParam(RESPONSE_CODE_KEY, static_cast<int>(chrStats.httpInfo.responseCode));
    want.SetParam(TOTAL_TIME_KEY, static_cast<long>(chrStats.httpInfo.totalTime));
    want.SetParam(NAMELOOKUP_TIME_KEY, static_cast<long>(chrStats.httpInfo.nameLookUpTime));
    want.SetParam(CONNECT_TIME_KEY, static_cast<long>(chrStats.httpInfo.connectTime));
    want.SetParam(APPCONNECT_TIME_KEY, static_cast<long>(chrStats.httpInfo.appconnectTime));
    want.SetParam(PRETRANSFER_TIME_KEY, static_cast<long>(chrStats.httpInfo.preTransferTime));
    want.SetParam(STARTTRANSFER_TIME_KEY, static_cast<long>(chrStats.httpInfo.startTransferTime));
    want.SetParam(QUEUE_TIME_KEY, static_cast<long>(chrStats.httpInfo.queueTime));
    want.SetParam(RETRY_AFTER_KEY, static_cast<long>(chrStats.httpInfo.retryAfter));
    want.SetParam(SIZE_UPLOAD_KEY, static_cast<long>(chrStats.httpInfo.sizeUpload));
    want.SetParam(SIZE_DOWNLOAD_KEY, static_cast<long>(chrStats.httpInfo.sizeDownload));
    want.SetParam(SPEED_DOWNLOAD_KEY, static_cast<long>(chrStats.httpInfo.speedDownload));
    want.SetParam(SPEED_UPLOAD_KEY, static_cast<long>(chrStats.httpInfo.speedUpload));
    want.SetParam(EFFECTIVE_METHOD_KEY, std::string(chrStats.httpInfo.effectiveMethod));
    want.SetParam(CONTENT_TYPE_KEY, std::string(chrStats.httpInfo.contentType));
    want.SetParam(REDIRECT_TIME_KEY, static_cast<long>(chrStats.httpInfo.redirectTime));
    want.SetParam(REDIRECT_COUNT_KEY, static_cast<long>(chrStats.httpInfo.redirectCount));
    want.SetParam(PROXY_ERROR_KEY, static_cast<int>(chrStats.httpInfo.proxyError));
    want.SetParam(OS_ERRNO_KEY, static_cast<long>(chrStats.httpInfo.osError));
    want.SetParam(SSL_VERIFYRESULT_KEY, static_cast<long>(chrStats.httpInfo.sslVerifyResult));
    std::string paramStr = want.ToString();
    return paramStr;
}

std::string NetstackChrReport::ConvertTcpInfoToJsonStr(DataTransChrStats chrStats)
{
    AAFwk::Want want;
    want.SetParam(TCPI_RETRANSMITS_KEY, static_cast<int>(chrStats.tcpInfo.retransmits));
    want.SetParam(TCPI_UNACKED_KEY, static_cast<int>(chrStats.tcpInfo.unacked));
    want.SetParam(TCPI_LAST_DATA_SENT_KEY, static_cast<int>(chrStats.tcpInfo.lastDataSent));
    want.SetParam(TCPI_LAST_ACK_SENT_KEY, static_cast<int>(chrStats.tcpInfo.lastAckSent));
    want.SetParam(TCPI_LAST_DATA_RECV_KEY, static_cast<int>(chrStats.tcpInfo.lastDataRecv));
    want.SetParam(TCPI_LAST_ACK_RECV_KEY, static_cast<int>(chrStats.tcpInfo.lastAckRecv));
    want.SetParam(TCPI_RTT_KEY, static_cast<int>(chrStats.tcpInfo.rtt));
    want.SetParam(TCPI_RTTVAR_KEY, static_cast<int>(chrStats.tcpInfo.rttvar));
    want.SetParam(TCPI_TOTAL_RETRANS_KEY, static_cast<int>(chrStats.tcpInfo.totalRetrans));
    want.SetParam(SRC_IP_KEY, std::string(chrStats.tcpInfo.srcIp));
    want.SetParam(DST_IP_KEY, std::string(chrStats.tcpInfo.dstIp));
    want.SetParam(SRC_PORT_KEY, static_cast<int>(chrStats.tcpInfo.srcPort));
    want.SetParam(DST_PORT_KEY, static_cast<int>(chrStats.tcpInfo.dstPort));
    std::string paramStr = want.ToString();
    return paramStr;
}

void InforLog(DataTransChrStats chrStats)
{
    std::stringstream logString;
    logString << "[Netstack CHR Service] process_name:" << dataTransChrStats.processName << " "
              << "HTTP Info:" << chrStats.httpInfo.uid << "," << chrStats.httpInfo.responseCode << "," 
              << chrStats.httpInfo.totalTime << "," << chrStats.httpInfo.nameLookUpTime << "," 
              << chrStats.httpInfo.preTransferTime << "," << chrStats.httpInfo.sizeUpload << "," 
              << chrStats.httpInfo.sizeDownload << "," << chrStats.httpInfo.speedDownload << "," 
              << chrStats.httpInfo.speedUpload << "," << chrStats.httpInfo.effectiveMethod << "," 
              << chrStats.httpInfo.startTransferTime << "," << chrStats.httpInfo.contentType << "," 
              << chrStats.httpInfo.redirectTime << "," << chrStats.httpInfo.redirectCount << "," 
              << chrStats.httpInfo.osError << "," << chrStats.httpInfo.sslVerifyResult << "," 
              << chrStats.httpInfo.appconnectTime << "," << chrStats.httpInfo.retryAfter << "," 
              << chrStats.httpInfo.proxyError << "," << chrStats.httpInfo.queueTime << "," 
              << chrStats.httpInfo.curlCode << " "
              << "TCP Info:" << chrStats.tcpInfo.unacked << "," << chrStats.tcpInfo.lastDataSent << "," 
              << chrStats.tcpInfo.lastAckSent << "," << chrStats.tcpInfo.lastDataRecv << "," 
              << chrStats.tcpInfo.lastAckRecv << "," << chrStats.tcpInfo.rtt << ","
              << chrStats.tcpInfo.rttvar << "," << chrStats.tcpInfo.retransmits << "," 
              << chrStats.tcpInfo.totalRetrans << "," << chrStats.tcpInfo.srcIp << "," 
              << chrStats.tcpInfo.dstIp << "," << chrStats.tcpInfo.srcPort << "," 
              << chrStats.tcpInfo.dstPort << ".";
    NETSTACK_LOGI("%{public}s", logString.str().c_str());
}