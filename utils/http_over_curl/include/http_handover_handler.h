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

#ifndef COMMUNICATIONNETSTACK_HTTP_HANOVER_HANDLER_H
#define COMMUNICATIONNETSTACK_HTTP_HANOVER_HANDLER_H

#include <map>
#include <memory>
#include <set>

#include "curl/curl.h"

#include "epoller.h"
#include "thread_safe_storage.h"
#include "timeout_timer.h"
#include "manual_reset_event.h"
#include "epoll_request_handler.h"
#include "request_info.h"

namespace OHOS::NetStack::HttpOverCurl {

struct RequestInfo;

class HttpHandoverHandler {
public:
    enum { INIT, START, CONTINUE, END, FATAL };
    explicit HttpHandoverHandler();
    ~HttpHandoverHandler();

    std::set<RequestInfo *> &GetFlowControlQueue();
    bool InitSuccess();
    void HandOverQuery(int32_t &status, int32_t &netId);
    bool NeedFlowControl();
    void FlowControl(RequestInfo *requestInfo);

    void RegisterForPolling(Epoller &poller) const;
    bool IsItYours(FileDescriptor descriptor) const;
    void Set();
    void Reset();

private:

    bool Initialize();
    void *netHandoverHandler_ = nullptr;
    void *httpHandOverManager_ = nullptr;
    std::unique_ptr<ManualResetEvent> handOverEvent_;
    typedef void *(*HTTP_HAND_OVER_INIT)(void *user, void (*HMS_NetworkBoost_HandoverEventCallback)(void *));
    typedef int32_t (*HTTP_HAND_OVER_UNINIT)(void *handle);
    typedef void (*HTTP_HAND_OVER_QUERY)(void *handle, int32_t &status, int32_t &netId);
    HTTP_HAND_OVER_INIT httpHandOverInit_ = nullptr;
    HTTP_HAND_OVER_UNINIT httpHandOverUninit_ = nullptr;
    HTTP_HAND_OVER_QUERY httpHandOverQuery_ = nullptr;
    std::set<RequestInfo *> handoverQueue_;
    bool initsuccess_;
};

}  // namespace OHOS::NetStack::HttpOverCurl

#endif  // COMMUNICATIONNETSTACK_HTTP_HANOVER_HANDLER_H