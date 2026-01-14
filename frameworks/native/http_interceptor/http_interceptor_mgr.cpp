/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "http_interceptor_mgr.h"
#include "ffrt.h"
#include "netstack_log.h"

namespace OHOS::NetStack::HttpInterceptor {

HttpInterceptorMgr &HttpInterceptorMgr::GetInstance()
{
    static std::shared_ptr<HttpInterceptorMgr> instance = std::make_shared<HttpInterceptorMgr>();
    return *instance;
}

int HttpInterceptorMgr::AddInterceptor(struct Http_Interceptor *interceptor)
{
    if (interceptor == nullptr) {
        NETSTACK_LOGE("AddInterceptor failed, interceptor ptr is nullptr");
        return OH_HTTP_PARAMETER_ERROR;
    }
    std::unique_lock<std::shared_mutex> lock(interceptor->stage == STAGE_REQUEST ? reqMutex_ : respMutex_);
    auto &targetList = interceptor->stage == STAGE_REQUEST ? requestInterceptorList_ : responseInterceptorList_;
    auto iter = std::find_if(targetList.begin(), targetList.end(), [&](const Http_Interceptor *item) {
        return item == interceptor;
    });
    if (iter != targetList.end()) {
        return OH_HTTP_RESULT_OK;
    }
    targetList.emplace_back(interceptor);
    NETSTACK_LOGI("AddInterceptor success, add new interceptor, stage=%{public}d, type=%{public}d", interceptor->stage,
        interceptor->type);
    return OH_HTTP_RESULT_OK;
}

int HttpInterceptorMgr::DeleteInterceptor(struct Http_Interceptor *interceptor)
{
    if (interceptor == nullptr) {
        NETSTACK_LOGE("DeleteInterceptor failed, interceptor ptr is nullptr");
        return OH_HTTP_PARAMETER_ERROR;
    }
    std::unique_lock<std::shared_mutex> lock(interceptor->stage == STAGE_REQUEST ? reqMutex_ : respMutex_);
    auto &targetList = interceptor->stage == STAGE_REQUEST ? requestInterceptorList_ : responseInterceptorList_;
    auto iter = std::find_if(targetList.begin(), targetList.end(), [&](const Http_Interceptor *item) {
        return item == interceptor;
    });
    if (iter == targetList.end()) {
        NETSTACK_LOGI("DeleteInterceptor success, interceptor not exist, stage=%{public}d", interceptor->stage);
        return OH_HTTP_RESULT_OK;
    }
    targetList.erase(iter);
    NETSTACK_LOGI("DeleteInterceptor success, remove interceptor, stage=%{public}d, type=%{public}d",
        interceptor->stage, interceptor->type);
    return OH_HTTP_RESULT_OK;
}

int HttpInterceptorMgr::DeleteAllInterceptor()
{
    std::unique_lock<std::shared_mutex> reqLock(reqMutex_);
    std::unique_lock<std::shared_mutex> respLock(respMutex_);
    requestInterceptorList_.clear();
    responseInterceptorList_.clear();
    NETSTACK_LOGI("DeleteAllInterceptor success");
    return OH_HTTP_RESULT_OK;
}

int HttpInterceptorMgr::StartAllInterceptor()
{
    isRunning_.store(true);
    return OH_HTTP_RESULT_OK;
}

int HttpInterceptorMgr::StopAllInterceptor()
{
    isRunning_.store(false);
    return OH_HTTP_RESULT_OK;
}

bool HttpInterceptorMgr::GetInterceptorMgrStatus()
{
    return isRunning_.load();
}

Interceptor_Result HttpInterceptorMgr::IteratorRequestInterceptor(
    std::shared_ptr<Http_Interceptor_Request> req, bool &isModified)
{
    NETSTACK_LOGI("Enter IteratorRequestInterceptor, isRunning_=%{public}s", isRunning_ ? "true" : "false");
    if (isRunning_ == false) {
        NETSTACK_LOGI("IteratorRequestInterceptor skip, interceptor manager is stop");
        return CONTINUE;
    }
    if (req == nullptr) {
        NETSTACK_LOGI("IteratorRequestInterceptor failed, req ptr is nullptr");
        return CONTINUE;
    }

    std::weak_ptr<HttpInterceptorMgr> self = shared_from_this();
    ffrt::submit([self, req]() {
        auto manage = self.lock();
        if (manage == nullptr) {
            NETSTACK_LOGI("manage ptr is nullptr");
            return;
        }
        std::shared_lock<std::shared_mutex> lock(manage->reqMutex_);
        for (const auto &interceptor : manage->requestInterceptorList_) {
            if (manage->isRunning_ == false) {
                NETSTACK_LOGI("ReadOnlyRequestThread exit, manager stop running");
                return;
            }
            if (interceptor && interceptor->type == TYPE_READ_ONLY && interceptor->handler != nullptr) {
                (void)interceptor->handler(req.get(), nullptr, nullptr);
            }
        }
        NETSTACK_LOGI("ReadOnlyRequestThread exec finish");
    });

    std::shared_lock<std::shared_mutex> lock(reqMutex_);
    for (const auto &interceptor : requestInterceptorList_) {
        if (interceptor->type == TYPE_MODIFY && interceptor->handler != nullptr) {
            int32_t isModifiedFlag = 0;
            auto ret = interceptor->handler(req.get(), nullptr, &isModifiedFlag);
            if (isModifiedFlag) {
                isModified = true;
            }
            if (ret == ABORT) {
                NETSTACK_LOGE("IteratorRequestInterceptor abort, interceptor return ABORT");
                return ABORT;
            }
        }
    }
    NETSTACK_LOGI("Exit IteratorRequestInterceptor");
    return CONTINUE;
}

Interceptor_Result HttpInterceptorMgr::IteratorResponseInterceptor(
    std::shared_ptr<Http_Response> resp, bool &isModified)
{
    NETSTACK_LOGI("Enter IteratorResponseInterceptor, isRunning_=%{public}s", isRunning_ ? "true" : "false");
    if (isRunning_ == false) {
        NETSTACK_LOGI("IteratorResponseInterceptor skip, interceptor manager is stop");
        return CONTINUE;
    }
    if (resp == nullptr) {
        NETSTACK_LOGI("IteratorResponseInterceptor failed, resp ptr is nullptr");
        return CONTINUE;
    }

    std::weak_ptr<HttpInterceptorMgr> self = shared_from_this();
    ffrt::submit([self, resp]() {
        auto manage = self.lock();
        if (manage == nullptr) {
            NETSTACK_LOGI("manage ptr is nullptr");
            return;
        }
        std::shared_lock<std::shared_mutex> lock(manage->respMutex_);
        for (const auto &interceptor : manage->responseInterceptorList_) {
            if (!manage->isRunning_) {
                NETSTACK_LOGI("ReadOnlyResponseThread exit, manager stop running");
                return;
            }
            if (interceptor->type == TYPE_READ_ONLY && interceptor->handler != nullptr) {
                (void)interceptor->handler(nullptr, resp.get(), nullptr);
            }
        }
        NETSTACK_LOGD("ReadOnlyResponseThread exec finish");
    });

    std::shared_lock<std::shared_mutex> lock(respMutex_);
    for (const auto &interceptor : responseInterceptorList_) {
        if (interceptor->type == TYPE_MODIFY && interceptor->handler != nullptr) {
            int32_t isModifiedFlag = 0;
            Interceptor_Result ret = interceptor->handler(nullptr, resp.get(), &isModifiedFlag);
            if (isModifiedFlag) {
                isModified = true;
            }
            if (ret == ABORT) {
                NETSTACK_LOGE("IteratorResponseInterceptor abort, interceptor return ABORT");
                return ABORT;
            }
        }
    }
    NETSTACK_LOGI("Exit IteratorResponseInterceptor");
    return CONTINUE;
}
} // namespace OHOS::NetStack::HttpInterceptor