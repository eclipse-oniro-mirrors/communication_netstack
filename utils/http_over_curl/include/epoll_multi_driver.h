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

#ifndef COMMUNICATIONNETSTACK_EPOLL_MULTI_DRIVER_H
#define COMMUNICATIONNETSTACK_EPOLL_MULTI_DRIVER_H

#include <map>
#include <memory>

#include "curl/curl.h"

#include "epoller.h"
#include "thread_safe_storage.h"
#include "timeout_timer.h"

namespace OHOS::NetStack::HttpOverCurl {

struct RequestInfo;

class EpollMultiDriver {
public:
    EpollMultiDriver() = delete;
    explicit EpollMultiDriver(const std::shared_ptr<HttpOverCurl::ThreadSafeStorage<RequestInfo *>> &incomingQueue);
    ~EpollMultiDriver();

    void Step(int waitEventsTimeoutMs);

private:
    class CurlSocketContext {
    public:
        CurlSocketContext(HttpOverCurl::Epoller &poller, curl_socket_t socket, int action);
        void Reassign(curl_socket_t socket, int action);
        ~CurlSocketContext();

    private:
        HttpOverCurl::Epoller &poller_;
        curl_socket_t socketDescriptor_;
    };

    int MultiTimeoutCallback(long timeoutMs);
    int MultiSocketCallback(curl_socket_t s, int action, CurlSocketContext *socketContext);

    void EpollTimerCallback();
    void EpollSocketCallback(int fd, int revents);

    void CheckMultiInfo();

    void Initialize();
    void IncomingRequestCallback();

    std::shared_ptr<HttpOverCurl::ThreadSafeStorage<RequestInfo *>> incomingQueue_;

    HttpOverCurl::Epoller poller_;
    HttpOverCurl::TimeoutTimer timeoutTimer_;

    CURLM *multi_ = nullptr;
    // Number of running handles
    int stillRunning = 0;

    std::map<CURL *, RequestInfo *> ongoingRequests_;
};

} // namespace OHOS::NetStack::HttpOverCurl

#endif // COMMUNICATIONNETSTACK_EPOLL_MULTI_DRIVER_H
