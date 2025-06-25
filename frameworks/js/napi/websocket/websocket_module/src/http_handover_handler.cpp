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

#include "http_handover_handler.h"
#include <dlfcn.h>
#include "netstack_log.h"
#include "request_info.h"
#include "request_context.h"

namespace OHOS::NetStack::HttpOverCurl {

constexpr const char *const METHOD_GET = "GET";
constexpr const char *const METHOD_HEAD = "HEAD";
constexpr const char *const METHOD_OPTIONS = "OPTIONS";
constexpr const char *const METHOD_TRACE = "TRACE";

HttpHandoverHandler::HttpHandoverHandler()
    : handOverEvent_(std::make_unique<ManualResetEvent>(true))
{
    NETSTACK_LOGI("HttpHandoverHandler init");
    initsuccess_ = Initialize();
}

void HandOverCallback(void *user)
{
    NETSTACK_LOGI("HandOverCallback enter");
    if (user == nullptr) {
        NETSTACK_LOGE("user is nullptr");
        return;
    }

    HttpHandoverHandler* const handoverhandler = reinterpret_cast<HttpHandoverHandler*>(user);
    handoverhandler->Set();
}

bool HttpHandoverHandler::InitSuccess()
{
    return initsuccess_;
}

bool HttpHandoverHandler::Initialize()
{
    const std::string HTTP_HANDOVER_WRAPPER_PATH = "/system/lib64/libhttp_handover.z.so";
    if (netHandoverHandler_ == nullptr) {
        netHandoverHandler_ = dlopen(HTTP_HANDOVER_WRAPPER_PATH.c_str(), RTLD_NOW);
        if (netHandoverHandler_ == nullptr) {
            NETSTACK_LOGE("libhttp_handover.z.so was not loaded, error: %{public}s", dlerror());
            return false;
        }
    }
    httpHandOverInit_ = (HTTP_HAND_OVER_INIT)dlsym(netHandoverHandler_, "HMS_NetworkBoost_HttpHandoverManagerInit");
    httpHandOverUninit_ =
        (HTTP_HAND_OVER_UNINIT)dlsym(netHandoverHandler_, "HMS_NetworkBoost_HttpHandoverManagerUninit");
    httpHandOverQuery_ =
        (HTTP_HAND_OVER_QUERY)dlsym(netHandoverHandler_, "HMS_NetworkBoost_HttpHandoverManagerQuery");
    bool hasFuncNull = (httpHandOverInit_ == nullptr || httpHandOverUninit_ == nullptr ||
        httpHandOverQuery_ == nullptr);
    if (hasFuncNull) {
        NETSTACK_LOGE("[HTTP HANDOVER] http handover wrapper symbol failed, error: %{public}s", dlerror());
        return false;
    }
    NETSTACK_LOGI("NetHandover enabled");

    if (netHandoverHandler_ != nullptr) {
        httpHandOverManager_ = httpHandOverInit_(this, HandOverCallback);
    }
    return true;
}

HttpHandoverHandler::~HttpHandoverHandler()
{
    if (httpHandOverManager_ != nullptr) {
        NETSTACK_LOGD("start httpHandOverUninit_");
        httpHandOverUninit_(httpHandOverManager_);
    }

    if (netHandoverHandler_ != nullptr) {
        dlclose(netHandoverHandler_);
        netHandoverHandler_ = nullptr;
    }
    httpHandOverInit_ = nullptr;
    httpHandOverUninit_ = nullptr;
}

void HttpHandoverHandler::RegisterForPolling(Epoller &poller) const
{
    handOverEvent_->RegisterForPolling(poller);
}

bool HttpHandoverHandler::IsItYours(FileDescriptor descriptor) const
{
    return handOverEvent_->IsItYours(descriptor);
}

void HttpHandoverHandler::Set()
{
    handOverEvent_->Set();
}

void HttpHandoverHandler::HandOverQuery(int32_t &status, int32_t &netId)
{
    if (httpHandOverQuery_ == nullptr) {
        NETSTACK_LOGD("nullptr param error");
        return;
    }
    return httpHandOverQuery_(httpHandOverManager_, &status, &netId);
}

bool HttpHandoverHandler::CheckSocketOpentimeLessThanEndTime(curl_socket_t fd)
{
    if (socketopentime_.count(fd) == 0) {
        return false;
    }
    bool ret = socketopentime_[fd] < endTime_;
    if (ret) {
        NETSTACK_LOGI("Old fd:%{public}d fdtime:%{public}d endTime:%{public}d", (int)fd, socketopentime_[fd], endTime_);
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
    static auto checksockettime = +[](void *user, curl_socket_t fd) -> bool {
        auto handover = static_cast<HttpHandoverHandler *>(user);
        if (handover && handover->CheckSocketOpentimeLessThanEndTime(fd)) {
            return false;
        }
        return true;
    };

    curl_easy_setopt(request->easyHandle, CURLOPT_CONNREUSEDATA, this);
    curl_easy_setopt(request->easyHandle, CURLOPT_CONNREUSEFUNCTION, checksockettime);

    static auto opensocket = +[](void *user, curlsocktype purpose, struct curl_sockaddr *addr) -> curl_socket_t {
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
    };

    curl_easy_setopt(request->easyHandle, CURLOPT_OPENSOCKETDATA, this);
    curl_easy_setopt(request->easyHandle, CURLOPT_OPENSOCKETFUNCTION, opensocket);

    static auto closeSocketCallback = +[](void *user, curl_socket_t fd) -> int {
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
    };

    curl_easy_setopt(request->easyHandle, CURLOPT_CLOSESOCKETDATA, this);
    curl_easy_setopt(request->easyHandle, CURLOPT_CLOSESOCKETFUNCTION, closeSocketCallback);
}

bool HttpHandoverHandler::TryFlowControl(RequestInfo *requestInfo)
{
    int32_t status = -1;
    int32_t netId = -1;
    HandOverQuery(status, netId);
    SetCallback(requestInfo);
    if (status == HttpHandoverHandler::START) {
        handoverQueue_.insert(requestInfo);
        auto context = static_cast<Http::RequestContext *>(requestInfo->opaqueData);
        NETSTACK_LOGI("taskid=%{public}d, FlowControl", context->GetTaskId());
        return true;
    }
    return false;
}

bool HttpHandoverHandler::RetransRequest(std::map<CURL *, RequestInfo *> &ongoingRequests,
    CURLM *multi, RequestInfo *request)
{
    auto ret = curl_multi_add_handle(multi, request->easyHandle);
    if (ret != CURLM_OK) {
        NETSTACK_LOGE("curl_multi_add_handle err, ret = %{public}d %{public}s", ret, curl_multi_strerror(ret));
        return false;
    }
    ongoingRequests[request->easyHandle] = request;
    return true;
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

bool HttpHandoverHandler::CheckRequestCanRetrans(RequestInfo *request)
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
    NETSTACK_LOGI(
        "taskid=%{public}d,"
        "method:%{public}s,Instream:%{public}d,recvtime:%{public}d,sendtime:%{public}d,readTimeout:%{public}u"
        "connecttimeout:%{public}u,url:%{public}s ", context->GetTaskId(), method.c_str(),
        isInstream, (int)recvtime, (int)sendtime, readTimeout, connecttimeout, context->options.GetUrl().c_str());

    if (sendtime == 0) {
        return true;
    }
    bool isSafe = (method == METHOD_GET || method == METHOD_HEAD || method == METHOD_OPTIONS || method == METHOD_TRACE);
    if (!isSafe) {
        return false;
    }
    if (isRead == 0 || !context->IsRequestInStream()) {
        return true;
    }
    return false;
}

void HttpHandoverHandler::UndoneRequestHandle(std::map<CURL *, RequestInfo *> &ongoingRequests, CURLM *multi)
{
    std::queue<CURL *> retransfailed;
    for (auto &request : ongoingRequests) {
        if (CheckRequestCanRetrans(request.second)) {
            curl_multi_remove_handle(multi, request.first);
            if (RetransRequest(ongoingRequests, multi, request.second)) {
                ++retrans_;
            } else {
                retransfailed.push(request.first);
            }
        }
    }
    while (!retransfailed.empty()) {
        auto &handle = retransfailed.front();
        retransfailed.pop();
        if (!ongoingRequests.count(handle)) {
            continue;
        }
        auto request = ongoingRequests[handle];
        if (request != nullptr && request->doneCallback) {
            CURLMsg message;
            message.msg = CURLMSG_DONE;
            message.data.result = CURLE_SEND_ERROR;
            request->doneCallback(&message, request->opaqueData);
        }
        ongoingRequests.erase(handle);
    }
}

void HttpHandoverHandler::HandOverRequestCallback(std::map<CURL *, RequestInfo *> &ongoingRequests, CURLM *multi)
{
    handOverEvent_->Reset();
    int32_t status = -1;
    int32_t netId = -1;
    HandOverQuery(status, netId);
    NETSTACK_LOGI("Enter HandOverRequestCallback status %{public}d", status);
    if (status == HttpHandoverHandler::START) {
        NETSTACK_LOGI("ongoingRequests:%{public}d", (int)ongoingRequests.size());
        for (auto &request : ongoingRequests) {
            if (requestEndtime_.count(request.second) == 0) {
                requestEndtime_[request.second] = endTime_;
            }
            (void)CheckRequestCanRetrans(request.second);
        }
        return;
    } else if (status == HttpHandoverHandler::INIT || status == HttpHandoverHandler::CONTINUE) {
        return;
    }
    if (status == HttpHandoverHandler::END) {
        ++endTime_;
        NETSTACK_LOGI("endTime:%{public}d, ongoingRequests:%{public}d, retrans:%{public}d", endTime_,
            (int)ongoingRequests.size(), retrans_);
        UndoneRequestHandle(ongoingRequests, multi);
    }
    NETSTACK_LOGI("handoverQueue_:%{public}d, retrans:%{public}d", (int)handoverQueue_.size(), retrans_);
    for (auto &request : handoverQueue_) {
        (void)RetransRequest(ongoingRequests, multi, request);
    }
    handoverQueue_.clear();
    retrans_ = 0;
}

bool HttpHandoverHandler::CheckRequestNetError(std::map<CURL *, RequestInfo *> &ongoingRequests, CURLM *multi,
    RequestInfo *requestInfo, CURLMsg *msg)
{
    if (!requestInfo || requestEndtime_.count(requestInfo) == 0) {
        return false;
    }
    int endTime = requestEndtime_[requestInfo];
    requestEndtime_.erase(requestInfo);
    if (!msg || (msg->data.result != CURLE_SEND_ERROR && msg->data.result != CURLE_RECV_ERROR)) {
        return false;
    }
    if (!CheckRequestCanRetrans(requestInfo)) {
        return false;
    }
    if (TryFlowControl(requestInfo)) {
        ++retrans_;
        return true;
    }
    if (endTime == endTime_ - 1) {
        NETSTACK_LOGI("networkerror after end status");
        return RetransRequest(ongoingRequests, multi, requestInfo);
    }
    return false;
}
}