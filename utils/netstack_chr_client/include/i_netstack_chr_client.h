/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef COMMUNICATIONNETSTACK_I_NETSTACK_CHR_CLIENT_H
#define COMMUNICATIONNETSTACK_I_NETSTACK_CHR_CLIENT_H

#include <cstdint>
#include <string>
#include "curl/curl.h"

namespace OHOS::NetStack::ChrClient {

typedef struct DataTransTcpInfo {
    uint8_t retransmits;
    uint32_t unacked;

    uint32_t lastDataSent;
    uint32_t lastAckSent;
    uint32_t lastDataRecv;
    uint32_t lastAckRecv;

    uint32_t rtt;
    uint32_t rttvar;
    uint32_t totalRetrans;

    std::string srcIp;
    std::string dstIp;
    uint16_t srcPort;
    uint16_t dstPort;
} DataTransTcpInfo;

typedef struct DataTransHttpInfo {
    int uid;
    long curlCode;
    int responseCode;

    curl_off_t totalTime;
    curl_off_t nameLookUpTime;
    curl_off_t connectTime;
    curl_off_t appconnectTime;
    curl_off_t preTransferTime;
    curl_off_t startTransferTime;
    curl_off_t queueTime;
    curl_off_t retryAfter;

    curl_off_t sizeUpload;
    curl_off_t sizeDownload;
    curl_off_t speedDownload;
    curl_off_t speedUpload;
    std::string effectiveMethod;
    std::string contentType;

    curl_off_t redirectTime;
    long redirectCount;

    int proxyError;
    long osError;
    long sslVerifyResult;
} DataTransHttpInfo;

typedef struct DataTransChrStats {
    std::string processName;
    DataTransHttpInfo httpInfo;
    DataTransTcpInfo tcpInfo;
} DataTransChrStats;

constexpr int REPORT_CHR_RESULT_SUCCESS = 0;
constexpr int REPORT_CHR_RESULT_TIME_LIMIT_ERROR = 1;
constexpr int REPORT_CHR_RESULT_SET_DATA_FAIL = 2;
constexpr int REPORT_CHR_RESULT_REPORT_FAIL = 3;


constexpr char PROCESS_NAME[] = "PROCESS_NAME";

constexpr char HTTP_INFO_KEY[] = "DATA_TRANS_HTTP_INFO";
constexpr char UID_KEY[] = "uid";
constexpr char RESPONSE_CODE_KEY[] = "response_code";
constexpr char TOTAL_TIME_KEY[] = "total_time";
constexpr char NAMELOOKUP_TIME_KEY[] = "namelookup_time";
constexpr char CONNECT_TIME_KEY[] = "connect_time";
constexpr char PRETRANSFER_TIME_KEY[] = "pretransfer_time";
constexpr char SIZE_UPLOAD_KEY[] = "size_upload";
constexpr char SIZE_DOWNLOAD_KEY[] = "size_download";
constexpr char SPEED_DOWNLOAD_KEY[] = "speed_download";
constexpr char SPEED_UPLOAD_KEY[] = "speed_upload";
constexpr char EFFECTIVE_METHOD_KEY[] = "effective_method";
constexpr char STARTTRANSFER_TIME_KEY[] = "starttransfer_time";
constexpr char CONTENT_TYPE_KEY[] = "content_type";
constexpr char REDIRECT_TIME_KEY[] = "redirect_time";
constexpr char REDIRECT_COUNT_KEY[] = "redirect_count";
constexpr char OS_ERRNO_KEY[] = "os_errno";
constexpr char SSL_VERIFYRESULT_KEY[] = "ssl_verifyresult";
constexpr char APPCONNECT_TIME_KEY[] = "appconnect_time";
constexpr char RETRY_AFTER_KEY[] = "retry_after";
constexpr char PROXY_ERROR_KEY[] = "proxy_error";
constexpr char QUEUE_TIME_KEY[] = "queue_time";
constexpr char CURL_CODE_KEY[] = "curl_code";

constexpr char TCP_INFO_KEY[] = "DATA_TRANS_TCP_INFO";
constexpr char TCPI_UNACKED_KEY[] = "tcpi_unacked";
constexpr char TCPI_LAST_DATA_SENT_KEY[] = "tcpi_last_data_sent";
constexpr char TCPI_LAST_ACK_SENT_KEY[] = "tcpi_last_ack_sent";
constexpr char TCPI_LAST_DATA_RECV_KEY[] = "tcpi_last_data_recv";
constexpr char TCPI_LAST_ACK_RECV_KEY[] = "tcpi_last_ack_recv";
constexpr char TCPI_RTT_KEY[] = "tcpi_rtt";
constexpr char TCPI_RTTVAR_KEY[] = "tcpi_rttvar";
constexpr char TCPI_RETRANSMITS_KEY[] = "tcpi_retransmits";
constexpr char TCPI_TOTAL_RETRANS_KEY[] = "tcpi_total_retrans";
constexpr char SRC_IP_KEY[] = "src_ip";
constexpr char DST_IP_KEY[] = "dst_ip";
constexpr char SRC_PORT_KEY[] = "src_port";
constexpr char DST_PORT_KEY[] = "dst_port";

}  // namespace OHOS::NetStack
#endif  // COMMUNICATIONNETSTACK_I_NETSTACK_CHR_CLIENT_H