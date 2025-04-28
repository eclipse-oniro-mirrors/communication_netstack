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

namespace OHOS::NetStack::HttpOverCurl {

HttpHandoverHandler::HttpHandoverHandler()
    : handOverEvent_(std::make_unique<ManualResetEvent>(true))
{
    NETSTACK_LOGI("HttpHandoverHandler init");
    initsuccess_ = Initialize();
}

void HandOverCallback(void *user)
{
    NETSTACK_LOGI("handOverCallback enter");
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
    bool hasFuncNull =
        (httpHandOverInit_ == nullptr || httpHandOverUninit_ == nullptr || httpHandOverQuery_ == nullptr);
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

void HttpHandoverHandler::Reset()
{
    handOverEvent_->Reset();
}

std::set<RequestInfo *> &HttpHandoverHandler::GetFlowControlQueue()
{
    return handoverQueue_;
}

void HttpHandoverHandler::HandOverQuery(int32_t &status, int32_t &netId)
{
    if (httpHandOverQuery_ == nullptr) {
        NETSTACK_LOGD("nullptr param error");
        return;
    }
    return httpHandOverQuery_(httpHandOverManager_, status, netId);
}

bool HttpHandoverHandler::NeedFlowControl()
{
    int32_t status = -1;
    int32_t netId = -1;
    HandOverQuery(status, netId);
    return status == HttpHandoverHandler::START;
}

void HttpHandoverHandler::FlowControl(RequestInfo* requestInfo)
{
    handoverQueue_.insert(requestInfo);
}
}