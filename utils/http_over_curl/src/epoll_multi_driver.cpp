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

#include "epoll_multi_driver.h"

#include "netstack_log.h"
#include "request_info.h"

namespace OHOS::NetStack::HttpOverCurl {

static constexpr size_t MAX_EPOLL_EVENTS = 10;

EpollMultiDriver::EpollMultiDriver(const std::shared_ptr<HttpOverCurl::ThreadSafeStorage<RequestInfo *>> &incomingQueue)
    : incomingQueue_(incomingQueue)
{
    Initialize();
}

void EpollMultiDriver::Initialize()
{
    timeoutTimer_.RegisterForPolling(poller_);
    incomingQueue_->GetSyncEvent().RegisterForPolling(poller_);
    multi_ = curl_multi_init();
    if (!multi_) {
        NETSTACK_LOGE("Failed to initialize curl_multi handle");
        return;
    }

    static auto socketCallback = +[](CURL *easy, curl_socket_t s, int action, void *userp, void *socketp) {
        auto instance = static_cast<EpollMultiDriver *>(userp);
        return instance->MultiSocketCallback(s, action, static_cast<CurlSocketContext *>(socketp));
    };
    curl_multi_setopt(multi_, CURLMOPT_SOCKETDATA, this);
    curl_multi_setopt(multi_, CURLMOPT_SOCKETFUNCTION, socketCallback);

    static auto timerCallback = +[](CURLM *multi, long timeout_ms, void *userp) {
        auto instance = static_cast<EpollMultiDriver *>(userp);
        instance->MultiTimeoutCallback(timeout_ms);
    };
    curl_multi_setopt(multi_, CURLMOPT_TIMERDATA, this);
    curl_multi_setopt(multi_, CURLMOPT_TIMERFUNCTION, timerCallback);
}

EpollMultiDriver::~EpollMultiDriver()
{
    if (multi_) {
        curl_multi_cleanup(multi_);
        multi_ = nullptr;
    }
}

void EpollMultiDriver::Step(int waitEventsTimeoutMs)
{
    epoll_event events[MAX_EPOLL_EVENTS];
    int eventsToHandle = poller_.Wait(events, MAX_EPOLL_EVENTS, waitEventsTimeoutMs);
    if (eventsToHandle == -1) {
        if (errno != EINTR) {
            NETSTACK_LOGE("Error on epoll, errno = %{public}d", errno);
        }
        return;
    }

    for (int idx = 0; idx < eventsToHandle; ++idx) {
        if (incomingQueue_->GetSyncEvent().IsItYours(events[idx].data.fd)) {
            IncomingRequestCallback();
        } else if (timeoutTimer_.IsItYours(events[idx].data.fd)) {
            EpollTimerCallback();
        } else { // curl socket event
            EpollSocketCallback(events[idx].data.fd, events[idx].events);
        }
    }
}

void EpollMultiDriver::IncomingRequestCallback()
{
    auto requestsToAdd = incomingQueue_->Flush();
    for (auto &request : requestsToAdd) {
        ongoingRequests_[request->easyHandle] = request;
        auto ret = curl_multi_add_handle(multi_, request->easyHandle);
        if (ret != CURLM_OK) {
            NETSTACK_LOGE("curl_multi_add_handle err, ret = %{public}d %{public}s", ret, curl_multi_strerror(ret));
            continue;
        }

        if (request->startedCallback) {
            request->startedCallback(request->easyHandle, request->opaqueData);
        }
    }
}

// Update the timer after curl_multi library does its thing. Curl will
// inform us through this callback what it wants the new timeout to be,
// after it does some work.
int EpollMultiDriver::MultiTimeoutCallback(long timeoutMs)
{
    if (timeoutMs > 0) {
        timeoutTimer_.SetTimeoutMs(timeoutMs);
    } else if (timeoutMs == 0) {
        // libcurl wants us to timeout now, however setting both fields of
        // new_value.it_value to zero disarms the timer. The closest we can
        // do is to schedule the timer to fire in 1 ns.
        timeoutTimer_.SetTimeoutNs(1);
    }

    return 0;
}

// Called by main loop when our timeout expires
void EpollMultiDriver::EpollTimerCallback()
{
    timeoutTimer_.ResetEvent();
    auto rc = curl_multi_socket_action(multi_, CURL_SOCKET_TIMEOUT, 0, &stillRunning);
    if (rc != CURLM_OK) {
        NETSTACK_LOGE("curl_multi returned error = %{public}d", rc);
    } else {
        CheckMultiInfo();
    }
}

__attribute__((no_sanitize("cfi"))) void EpollMultiDriver::CheckMultiInfo()
{
    CURLMsg *message;
    int pending;

    while ((message = curl_multi_info_read(multi_, &pending))) {
        switch (message->msg) {
            case CURLMSG_DONE: {
                auto easyHandle = message->easy_handle;
                curl_multi_remove_handle(multi_, easyHandle);
                auto requestInfo = ongoingRequests_[easyHandle];
                ongoingRequests_.erase(easyHandle);
                if (requestInfo->doneCallback) {
                    requestInfo->doneCallback(message, requestInfo->opaqueData);
                }
                delete requestInfo;
                break;
            }
            default:
                NETSTACK_LOGD("CURLMSG default");
                break;
        }
    }
}

int EpollMultiDriver::MultiSocketCallback(curl_socket_t socket, int action, CurlSocketContext *socketContext)
{
    switch (action) {
        case CURL_POLL_IN:
        case CURL_POLL_OUT:
        case CURL_POLL_INOUT:
            if (!socketContext) {
                curl_multi_assign(multi_, socket, new CurlSocketContext(poller_, socket, action));
            } else {
                socketContext->Reassign(socket, action);
            }
            break;
        case CURL_POLL_REMOVE:
            delete socketContext;
            break;
        default:
            NETSTACK_LOGE("Unexpected socket action = %{public}d", action);
    }

    return 0;
}

static int CurlPollToEpoll(int action)
{
    int kind = ((action & CURL_POLL_IN) ? EPOLLIN : (EPOLLIN & ~EPOLLIN)) |
               ((action & CURL_POLL_OUT) ? EPOLLOUT : (EPOLLOUT & ~EPOLLOUT));
    return kind;
}

EpollMultiDriver::CurlSocketContext::CurlSocketContext(HttpOverCurl::Epoller &poller, curl_socket_t sockDescriptor,
                                                       int action)
    : poller_(poller), socketDescriptor_(sockDescriptor)
{
    int kind = CurlPollToEpoll(action);
    poller_.RegisterMe(socketDescriptor_, kind);
}

void EpollMultiDriver::CurlSocketContext::Reassign(curl_socket_t sockDescriptor, int action)
{
    poller_.UnregisterMe(socketDescriptor_);
    socketDescriptor_ = sockDescriptor;
    int kind = CurlPollToEpoll(action);
    poller_.RegisterMe(socketDescriptor_, kind);
}

EpollMultiDriver::CurlSocketContext::~CurlSocketContext()
{
    poller_.UnregisterMe(socketDescriptor_);
}

// Called by main loop when we get action on a multi socket file descriptor
void EpollMultiDriver::EpollSocketCallback(int fd, int revents)
{
    int action = ((revents & EPOLLIN) ? CURL_CSELECT_IN : 0) | ((revents & EPOLLOUT) ? CURL_CSELECT_OUT : 0);
    auto rc = curl_multi_socket_action(multi_, fd, action, &stillRunning);
    if (rc != CURLM_OK) {
        NETSTACK_LOGE("curl_multi returned error = %{public}d", rc);
    } else {
        CheckMultiInfo();
    }

    if (stillRunning <= 0) {
        timeoutTimer_.Stop();
    }
}

} // namespace OHOS::NetStack::HttpOverCurl
