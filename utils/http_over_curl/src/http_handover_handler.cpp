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

#include <dlfcn.h>
#include "http_handover_handler.h"
#include "netstack_log.h"
#include "request_info.h"
#include "request_context.h"

namespace OHOS::NetStack::HttpOverCurl {

constexpr const char *const METHOD_GET = "GET";
constexpr const char *const METHOD_HEAD = "HEAD";
constexpr const char *const METHOD_OPTIONS = "OPTIONS";
constexpr const char *const METHOD_TRACE = "TRACE";
constexpr const long TIMEOUT_IMMEDIATE_NS = 1000;

HttpHandoverHandler::HttpHandoverHandler()
    : handOverEvent_(std::make_unique<ManualResetEvent>(true)),
      handOverTimerEvent_(std::make_unique<HttpOverCurl::TimeoutTimer>())
{
    initsuccess_ = Initialize();
}

void HandoverCallback(void *user)
{
    if (user == nullptr) {
        NETSTACK_LOGE("handover callback user is nullptr");
        return;
    }

    HttpHandoverHandler* const handoverhandler = reinterpret_cast<HttpHandoverHandler*>(user);
    handoverhandler->SetHandoverEvent();
}

void HandoverTimerCallback(void *user, long timeoutMs)
{
    NETSTACK_LOGD("HandoverTimerCallback enter, set timeout %{public}ld ms.", timeoutMs);
    if (user == nullptr) {
        NETSTACK_LOGE("timer callback user is nullptr");
        return;
    }

    HttpHandoverHandler* const handoverHandler = reinterpret_cast<HttpHandoverHandler*>(user);
    handoverHandler->SetHandoverTimeoutEvent(timeoutMs);
}

bool CheckSocketTime(void *user, curl_socket_t fd)
{
    auto handover = static_cast<HttpHandoverHandler *>(user);
    if (handover && handover->CheckSocketOpentimeLessThanEndTime(fd)) {
        return false;
    }
    return true;
}

curl_socket_t OpenSocket(void *user, curlsocktype purpose, struct curl_sockaddr *addr)
{
    curl_socket_t sockfd = socket(addr->family, addr->socktype, addr->protocol);
    if (sockfd < 0) {
        NETSTACK_LOGE("Failed to open socket: %{public}d, errno: %{public}d", sockfd, errno);
        return -1;
    }
    auto handover = static_cast<HttpHandoverHandler *>(user);
    if (handover) {
        handover->SetSocketOpenTime(sockfd);
    }
    return sockfd;
}

int CloseSocketCallback(void *user, curl_socket_t fd)
{
    auto handover = static_cast<HttpHandoverHandler *>(user);
    if (handover) {
        handover->EraseFd(fd);
    }
    int ret = close(fd);
    if (ret < 0) {
        NETSTACK_LOGE("Failed to close socket: %{public}d, errno: %{public}d", fd, errno);
        return ret;
    }
    return 0;
}

static bool IsIoError(CURLcode result)
{
    if (result == CURLE_SEND_ERROR || result == CURLE_RECV_ERROR) {
        return true;
    }
    return false;
}

static bool IsConnectError(CURLcode result)
{
    if (result == CURLE_COULDNT_RESOLVE_HOST || result == CURLE_COULDNT_CONNECT ||
        result == CURLE_SSL_CONNECT_ERROR || result == CURLE_QUIC_CONNECT_ERROR) {
        return true;
    }
    return false;
}

static bool IsNetworkErrorTypeCorrect(CURLcode result)
{
    if (IsIoError(result) || IsConnectError(result)) {
        return true;
    }
    return false;
}

bool HttpHandoverHandler::IsInitSuccess()
{
    return initsuccess_;
}

bool HttpHandoverHandler::Initialize()
{
    const std::string HTTP_HANDOVER_WRAPPER_PATH = "/system/lib64/libhttp_handover.z.so";
    netHandoverHandler_ = dlopen(HTTP_HANDOVER_WRAPPER_PATH.c_str(), RTLD_NOW);
    if (netHandoverHandler_ == nullptr) {
        NETSTACK_LOGE("libhttp_handover.z.so was not loaded, error: %{public}s", dlerror());
        return false;
    }
    httpHandoverInit_ = (HTTP_HAND_OVER_INIT)dlsym(netHandoverHandler_, "HMS_NetworkBoost_HttpHandoverManagerInit");
    httpHandoverUninit_ =
        (HTTP_HAND_OVER_UNINIT)dlsym(netHandoverHandler_, "HMS_NetworkBoost_HttpHandoverManagerUninit");
    httpHandoverQuery_ =
        (HTTP_HAND_OVER_QUERY)dlsym(netHandoverHandler_, "HMS_NetworkBoost_HttpHandoverManagerQuery");
    httpHandoverAddRequest_ =
        (HTTP_HAND_OVER_ADD)dlsym(netHandoverHandler_, "HMS_NetworkBoost_HttpHandoverManagerAddRequest");
    httpHandoverDelRequest_ =
        (HTTP_HAND_OVER_DEL)dlsym(netHandoverHandler_, "HMS_NetworkBoost_HttpHandoverManagerDelRequest");
    httpHandoverQueryRequest_ =
        (HTTP_HAND_OVER_QUERY_REQUEST)dlsym(netHandoverHandler_, "HMS_NetworkBoost_HttpHandoverManagerQueryRequest");
    httpHandoverReportTimeout_ =
        (HTTP_HAND_OVER_REPORT_TIMEOUT)dlsym(netHandoverHandler_, "HMS_NetworkBoost_HttpHandoverManagerReportTimeout");
    bool hasFuncNull = (httpHandoverInit_ == nullptr || httpHandoverUninit_ == nullptr ||
        httpHandoverQuery_ == nullptr || httpHandoverAddRequest_ == nullptr || httpHandoverDelRequest_ == nullptr ||
        httpHandoverQueryRequest_ == nullptr || httpHandoverReportTimeout_ == nullptr);
    if (hasFuncNull) {
        NETSTACK_LOGE("http handover wrapper symbol failed, error: %{public}s", dlerror());
        return false;
    }
    NETSTACK_LOGD("NetHandover enabled");
    const char* stackName = "http";
    httpHandoverManager_ = httpHandoverInit_(this, HandoverCallback, HandoverTimerCallback, stackName);
    if (httpHandoverManager_ == nullptr) {
        NETSTACK_LOGE("http handover manager init fail");
        return false;
    }
    return true;
}

HttpHandoverHandler::~HttpHandoverHandler()
{
    NETSTACK_LOGD("start httpHandoverUninit_");
    if (httpHandoverManager_ != nullptr) {
        httpHandoverUninit_(httpHandoverManager_);
    }
    if (netHandoverHandler_ != nullptr) {
        dlclose(netHandoverHandler_);
    }
    httpHandoverManager_ = nullptr;
    netHandoverHandler_ = nullptr;
    httpHandoverInit_ = nullptr;
    httpHandoverUninit_ = nullptr;
    httpHandoverQuery_ = nullptr;
    httpHandoverAddRequest_ = nullptr;
    httpHandoverDelRequest_ = nullptr;
    httpHandoverQueryRequest_ = nullptr;
    httpHandoverReportTimeout_ = nullptr;
}

void HttpHandoverHandler::RegisterForPolling(Epoller &poller) const
{
    handOverEvent_->RegisterForPolling(poller);
    handOverTimerEvent_->RegisterForPolling(poller);
}

bool HttpHandoverHandler::IsItHandoverEvent(FileDescriptor descriptor) const
{
    return handOverEvent_->IsItYours(descriptor);
}

bool HttpHandoverHandler::IsItHandoverTimeoutEvent(FileDescriptor descriptor) const
{
    return handOverTimerEvent_->IsItYours(descriptor);
}

void HttpHandoverHandler::SetHandoverEvent()
{
    handOverEvent_->Set();
}

void HttpHandoverHandler::SetHandoverTimeoutEvent(long timeoutMs)
{
    if (timeoutMs > 0) {
        handOverTimerEvent_->SetTimeoutMs(timeoutMs);
    } else if (timeoutMs == 0) {  // set a very small time means immediately trigger timeout timer
        handOverTimerEvent_->SetTimeoutNs(TIMEOUT_IMMEDIATE_NS);
    } else {  // timeoutMs < 0 means stop timeout timer
        handOverTimerEvent_->Stop();
    }
}

void HttpHandoverHandler::HandoverQuery(int32_t &status, int32_t &netId)
{
    if (httpHandoverQuery_ == nullptr || httpHandoverManager_ == nullptr) {
        NETSTACK_LOGE("nullptr param error");
        return;
    }
    httpHandoverQuery_(httpHandoverManager_, &status, &netId);
}

bool HttpHandoverHandler::CheckSocketOpentimeLessThanEndTime(curl_socket_t fd)
{
    if (socketopentime_.count(fd) == 0) {
        return false;
    }
    bool ret = socketopentime_[fd] < endTime_;
    if (ret) {
        NETSTACK_LOGD("Old fd:%{public}d fdtime:%{public}d endTime:%{public}d", (int)fd, socketopentime_[fd], endTime_);
    }
    return ret;
}

void HttpHandoverHandler::SetSocketOpenTime(curl_socket_t fd)
{
    socketopentime_[fd] = endTime_;
}

void HttpHandoverHandler::EraseFd(curl_socket_t fd)
{
    if (socketopentime_.count(fd) == 0) {
        return;
    }
    socketopentime_.erase(fd);
}

void HttpHandoverHandler::SetCallback(RequestInfo *request)
{
    curl_easy_setopt(request->easyHandle, CURLOPT_CONNREUSEDATA, this);
    curl_easy_setopt(request->easyHandle, CURLOPT_CONNREUSEFUNCTION, CheckSocketTime);

    curl_easy_setopt(request->easyHandle, CURLOPT_OPENSOCKETDATA, this);
    curl_easy_setopt(request->easyHandle, CURLOPT_OPENSOCKETFUNCTION, OpenSocket);

    curl_easy_setopt(request->easyHandle, CURLOPT_CLOSESOCKETDATA, this);
    curl_easy_setopt(request->easyHandle, CURLOPT_CLOSESOCKETFUNCTION, CloseSocketCallback);
}

bool HttpHandoverHandler::TryFlowControl(RequestInfo *requestInfo, int32_t requestType)
{
    int32_t status = -1;
    int32_t netId = -1;
    HandoverQuery(status, netId);
    if (status == HttpHandoverHandler::FATAL) {
        NETSTACK_LOGE("Handover status fatal, feature disable.");
        return false;
    }

    SetCallback(requestInfo);
    if (status == HttpHandoverHandler::START) {
        handoverQueue_.insert(requestInfo);
        auto context = static_cast<Http::RequestContext *>(requestInfo->opaqueData);
        std::string reason;
        if (requestType == RequestType::INCOMING) {
            reason = "incoming request";
        } else if (requestType == RequestType::NETWORKERROR) {
            reason = "network error";
        }
        NETSTACK_LOGD("taskid=%{public}d, FlowControl reason:%{public}s", context->GetTaskId(), reason.c_str());
        AddRequest(requestInfo, requestType);
        return true;
    }
    AddRequest(requestInfo, RequestType::OLD);
    return false;
}

bool HttpHandoverHandler::RetransRequest(std::map<CURL *, RequestInfo *> &ongoingRequests,
    CURLM *multi, RequestInfo *request)
{
    auto ret = curl_multi_add_handle(multi, request->easyHandle);
    if (ret != CURLM_OK) {
        NETSTACK_LOGD("curl_multi_add_handle err, ret = %{public}d %{public}s", ret, curl_multi_strerror(ret));
        return false;
    }
    ongoingRequests[request->easyHandle] = request;
    return true;
}

bool HttpHandoverHandler::CheckRequestCanRetrans(RequestInfo *request, int32_t requestType, CURLcode result)
{
    time_t recvtime = 0;
    time_t sendtime = 0;
    int32_t isRead = IsRequestRead(request->easyHandle, recvtime, sendtime);
    if (isRead == -1) {
        return false;
    }
    auto context = static_cast<Http::RequestContext *>(request->opaqueData);
    auto method = context->options.GetMethod();
    int isInstream = context->IsRequestInStream();
    uint32_t readTimeout = context->options.GetReadTimeout();
    uint32_t connecttimeout = context->options.GetConnectTimeout();
    bool isSafe = (method == METHOD_GET || method == METHOD_HEAD || method == METHOD_OPTIONS || method == METHOD_TRACE);
    bool ret = false;
    if (IsConnectError(result) || sendtime == 0 || (isSafe && (!isInstream || isRead == 0))) {
        ret = true;
    }
    if (requestType == RequestType::INCOMING || requestType == RequestType::NETWORKERROR) {
        return ret;
    }
    std::string type;
    if (requestType == RequestType::OLD) {
        type = "old request";
    } else {
        type = "undone request";
    }
    NETSTACK_LOGI(
        "taskid=%{public}d,requestType:%{public}s,canRetrans:%{public}d,"
        "method:%{public}s,isInstream:%{public}d,recvtime:%{public}d,sendtime:%{public}d,readTimeout:%{public}u,"
        "connecttimeout:%{public}u,url:%{public}s ", context->GetTaskId(), type.c_str(), (int)ret, method.c_str(),
        isInstream, (int)recvtime, (int)sendtime, readTimeout, connecttimeout, context->options.GetUrl().c_str());

    return ret;
}

void HttpHandoverHandler::UndoneRequestHandle(std::map<CURL *, RequestInfo *> &ongoingRequests, CURLM *multi)
{
    for (auto it = ongoingRequests.begin(); it != ongoingRequests.end();) {
        auto handle = it->first;
        auto requestInfo = it->second;
        if (CheckRequestCanRetrans(requestInfo, RequestType::UNDONE, CURLE_OK)) {
            curl_multi_remove_handle(multi, handle);
            if (RetransRequest(ongoingRequests, multi, requestInfo)) {
                ++retrans_;
                AddRequest(requestInfo, RequestType::UNDONE);
                ++it;
                continue;
            }
            if (requestInfo != nullptr && requestInfo->doneCallback) {
                CURLMsg message;
                message.msg = CURLMSG_DONE;
                message.data.result = CURLE_SEND_ERROR;
                requestInfo->doneCallback(&message, requestInfo->opaqueData);
            }
            it = ongoingRequests.erase(it);
        }
        ++it;
    }
}

void HttpHandoverHandler::HandoverRequestCallback(std::map<CURL *, RequestInfo *> &ongoingRequests, CURLM *multi)
{
    handOverEvent_->Reset();
    int32_t status = -1;
    int32_t netId = -1;
    HandoverQuery(status, netId);

    NETSTACK_LOGD("Enter HandoverRequestCallback status %{public}d", status);
    if (status == HttpHandoverHandler::START) {
        NETSTACK_LOGD("start ongoingRequests:%{public}d", (int)ongoingRequests.size());
        for (auto &request : ongoingRequests) {
            if (requestEndtime_.count(request.second) == 0) {
                requestEndtime_[request.second] = endTime_;
            }
            (void)CheckRequestCanRetrans(request.second, RequestType::OLD, CURLE_OK);
        }
    } else if (status == HttpHandoverHandler::END || status == HttpHandoverHandler::TIMEOUT) {
        (status == HttpHandoverHandler::END) ? ++endTime_ : ++timeoutTime_;
        NETSTACK_LOGD("endTime:%{public}d, timeoutTime: %{public}d, ongoingRequests:%{public}d, retrans count before "
                      "end:%{public}d", endTime_, timeoutTime_, (int)ongoingRequests.size(), retrans_);
        UndoneRequestHandle(ongoingRequests, multi);

        NETSTACK_LOGD("handoverQueue_:%{public}d, retrans total count:%{public}d",
            (int)handoverQueue_.size(), retrans_);
        for (auto &request : handoverQueue_) {
            (void)RetransRequest(ongoingRequests, multi, request);
        }
        handoverQueue_.clear();
        retrans_ = 0;
    } else if (status == HttpHandoverHandler::FATAL) {
        NETSTACK_LOGE("Handover status is FATAL, feature disable.");
    }
    return;
}

void HttpHandoverHandler::HandoverTimeoutCallback()
{
    handOverTimerEvent_->ResetEvent();
    handOverTimerEvent_->Stop();
    int32_t status = -1;
    int32_t netId = -1;
    HandoverQuery(status, netId);
    if (status == HttpHandoverHandler::END) {
        return;
    }
    if (httpHandoverManager_ == nullptr) {
        NETSTACK_LOGE("httpHandoverManager_ nullptr error");
        return;
    }
    httpHandoverReportTimeout_(httpHandoverManager_);
}

int32_t HttpHandoverHandler::IsRequestInQueue(CURL *easyHandle)
{
    time_t sendtime = 0;
    CURLcode result = curl_easy_getinfo(easyHandle, CURLINFO_PRETRANSFER_TIME_T, &sendtime);
    if (result != CURLE_OK) {
        NETSTACK_LOGE("get send time failed:%{public}s", curl_easy_strerror(result));
        return -1;
    }
    return sendtime == 0 ? 1 : 0;
}

int32_t HttpHandoverHandler::IsRequestRead(CURL *easyHandle)
{
    time_t recvtime = 0;
    time_t sendtime = 0;
    return IsRequestRead(easyHandle, recvtime, sendtime);
}

int32_t HttpHandoverHandler::IsRequestRead(CURL *easyHandle, time_t &recvtime, time_t &sendtime)
{
    CURLcode result = curl_easy_getinfo(easyHandle, CURLINFO_STARTTRANSFER_TIME_T, &recvtime);
    if (result != CURLE_OK) {
        NETSTACK_LOGE("get recv time failed:%{public}s", curl_easy_strerror(result));
        return -1;
    }
    result = curl_easy_getinfo(easyHandle, CURLINFO_PRETRANSFER_TIME_T, &sendtime);
    if (result != CURLE_OK) {
        NETSTACK_LOGE("get send time failed:%{public}s", curl_easy_strerror(result));
        return -1;
    }
    return (recvtime == 0 || sendtime == recvtime) ? 0 : 1;
}

bool HttpHandoverHandler::ProcessRequestErr(std::map<CURL *, RequestInfo *> &ongoingRequests,
    CURLM *multi, RequestInfo *requestInfo, CURLMsg *msg)
{
    if (ProcessRequestNetError(ongoingRequests, multi, requestInfo, msg)) {
        return true;
    }
    SetHandoverInfo(requestInfo);
    return false;
}

void HttpHandoverHandler::SetHandoverInfo(RequestInfo *requestInfo)
{
    if (requestInfo != nullptr) {
        int32_t handOverReason = 0;
        double flowControlTime = 0;
        int32_t isRead = 0;
        int32_t isInQueue = 0;
        int32_t handOverNum = QueryRequest(requestInfo->opaqueData, handOverReason, flowControlTime, isRead, isInQueue);
        auto context = static_cast<Http::RequestContext *>(requestInfo->opaqueData);
        if (context) {
            context->SetRequestHandoverInfo(handOverNum, handOverReason, flowControlTime, isRead, isInQueue);
        }
        DelRequest(requestInfo->opaqueData);
    }
    return;
}

bool HttpHandoverHandler::ProcessRequestNetError(std::map<CURL *, RequestInfo *> &ongoingRequests, CURLM *multi,
    RequestInfo *requestInfo, CURLMsg *msg)
{
    if (!requestInfo || requestEndtime_.count(requestInfo) == 0) {
        return false;
    }
    int endTime = requestEndtime_[requestInfo];
    requestEndtime_.erase(requestInfo);
    if (!msg || !IsNetworkErrorTypeCorrect(msg->data.result)) {
        return false;
    }
    if (!CheckRequestCanRetrans(requestInfo, RequestType::NETWORKERROR, msg->data.result)) {
        return false;
    }
    if (TryFlowControl(requestInfo, RequestType::NETWORKERROR)) {
        ++retrans_;
        return true;
    }
    if (endTime == endTime_ - 1) {
        NETSTACK_LOGD("networkerror after end status");
        AddRequest(requestInfo, RequestType::NETWORKERROR);
        return RetransRequest(ongoingRequests, multi, requestInfo);
    }
    return false;
}

void HttpHandoverHandler::AddRequest(RequestInfo *requestInfo, int32_t type)
{
    if (httpHandoverManager_ == nullptr) {
        NETSTACK_LOGE("httpHandoverManager_ nullptr error");
        return;
    }
    httpHandoverAddRequest_(httpHandoverManager_, requestInfo->opaqueData, type,
        IsRequestRead(requestInfo->easyHandle), IsRequestInQueue(requestInfo->easyHandle));
}

void HttpHandoverHandler::DelRequest(void *userp)
{
    if (httpHandoverManager_ == nullptr) {
        NETSTACK_LOGE("httpHandoverManager_ nullptr error");
        return;
    }
    auto context = static_cast<Http::RequestContext *>(userp);
    if (context->IsParseOK() && context->IsExecOK()) {
        httpHandoverDelRequest_(httpHandoverManager_, userp, true);
        return;
    }
    httpHandoverDelRequest_(httpHandoverManager_, userp, false);
}

int32_t HttpHandoverHandler::QueryRequest(void *userp, int32_t &handOverReason, double &flowControlTime,
    int32_t &isRead, int32_t &isInQueue)
{
    if (httpHandoverManager_ == nullptr) {
        NETSTACK_LOGE("httpHandoverManager_ nullptr error");
        return -1;
    }
    return httpHandoverQueryRequest_(httpHandoverManager_, userp, &handOverReason,
        &flowControlTime, &isRead, &isInQueue);
}
}