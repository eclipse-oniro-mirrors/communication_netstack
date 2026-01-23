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

std::shared_ptr<Http_Interceptor_Request> HttpInterceptorMgr::CreateHttpInterceptorRequest()
{
    // LCOV_EXCL_START
    Http_Interceptor_Request *ptr = static_cast<Http_Interceptor_Request *>(malloc(sizeof(Http_Interceptor_Request)));
    if (ptr == nullptr) {
        return nullptr;
    }
    // LCOV_EXCL_STOP
    std::shared_ptr<Http_Interceptor_Request> req =
        std::shared_ptr<Http_Interceptor_Request>(ptr, [](Http_Interceptor_Request *r) {
            DestroyHttpInterceptorRequest(r);
        });
    InitHttpBuffer(&req->url);
    InitHttpBuffer(&req->method);
    InitHttpBuffer(&req->body);
    req->headers = nullptr;
    return req;
}
std::shared_ptr<Http_Interceptor_Response> HttpInterceptorMgr::CreateHttpInterceptorResponse()
{
    // LCOV_EXCL_START
    Http_Interceptor_Response *ptr =
        static_cast<Http_Interceptor_Response *>(malloc(sizeof(Http_Interceptor_Response)));
    if (ptr == nullptr) {
        return nullptr;
    }
    // LCOV_EXCL_STOP
    std::shared_ptr<Http_Interceptor_Response> resp =
        std::shared_ptr<Http_Interceptor_Response>(ptr, [](Http_Interceptor_Response *r) {
            DestroyHttpInterceptorResponse(r);
        });
    InitHttpBuffer(&resp->body);
    resp->headers = nullptr;
    resp->responseCode = OH_HTTP_OK;
    resp->performanceTiming = { 0 };
    return resp;
}

int32_t HttpInterceptorMgr::AddInterceptor(struct Http_Interceptor *interceptor)
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
        NETSTACK_LOGI("AddInterceptor success, interceptor exist, stage=%{public}d", interceptor->stage);
        return OH_HTTP_RESULT_OK;
    }
    targetList.emplace_back(interceptor);
    NETSTACK_LOGI("AddInterceptor success, add new interceptor, stage=%{public}d, type=%{public}d", interceptor->stage,
        interceptor->type);
    return OH_HTTP_RESULT_OK;
}

int32_t HttpInterceptorMgr::DeleteInterceptor(struct Http_Interceptor *interceptor)
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

int32_t HttpInterceptorMgr::DeleteAllInterceptor(int32_t groupId)
{
    std::unique_lock<std::shared_mutex> reqLock(reqMutex_);
    requestInterceptorList_.remove_if([groupId](const Http_Interceptor *interceptor) {
        return interceptor->groupId == groupId;
    });
    std::unique_lock<std::shared_mutex> respLock(respMutex_);
    responseInterceptorList_.remove_if([groupId](const Http_Interceptor *interceptor) {
        return interceptor->groupId == groupId;
    });
    NETSTACK_LOGI("DeleteAllInterceptor for groupId %{public}d success", groupId);
    return OH_HTTP_RESULT_OK;
}

int32_t HttpInterceptorMgr::SetAllInterceptorEnabled(int32_t groupId, int32_t enabled)
{
    std::unique_lock<std::shared_mutex> reqLock(reqMutex_);
    for (const auto &interceptor : requestInterceptorList_) {
        if (interceptor->groupId == groupId) {
            interceptor->enabled = enabled;
        }
    }
    std::unique_lock<std::shared_mutex> respLock(respMutex_);
    for (const auto &interceptor : responseInterceptorList_) {
        if (interceptor->groupId == groupId) {
            interceptor->enabled = enabled;
        }
    }
    NETSTACK_LOGI("SetAllInterceptorEnabled for groupId=%{public}d, enabled=%{public}d success", groupId, enabled);
    return OH_HTTP_RESULT_OK;
}

void HttpInterceptorMgr::CopyHttpInterceRequest(
    std::shared_ptr<Http_Interceptor_Request> &dst, std::shared_ptr<Http_Interceptor_Request> &src)
{
    if (dst == nullptr || src == nullptr) {
        return;
    }
    DeepCopyBuffer(&dst->url, &src->url);
    DeepCopyBuffer(&dst->method, &src->method);
    DeepCopyBuffer(&dst->body, &src->body);
    dst->headers = DeepCopyHeaders(src->headers);
}

void HttpInterceptorMgr::IteratorReadRequestInterceptor(std::shared_ptr<Http_Interceptor_Request> &readReq)
{
    if (readReq == nullptr) {
        NETSTACK_LOGI("IteratorReadRequestInterceptor failed, readReq ptr is nullptr");
        return;
    }
    std::weak_ptr<HttpInterceptorMgr> self = shared_from_this();
    ffrt::submit([self, readReq]() {
        auto manage = self.lock();
        if (manage == nullptr) {
            NETSTACK_LOGI("manage ptr is nullptr");
            return;
        }
        std::shared_lock<std::shared_mutex> lock(manage->reqMutex_);
        for (const auto &interceptor : manage->requestInterceptorList_) {
            if (interceptor && interceptor->type == TYPE_READ_ONLY && interceptor->handler != nullptr &&
                interceptor->enabled) {
                (void)interceptor->handler(readReq.get(), nullptr, nullptr);
            }
        }
        NETSTACK_LOGD("ReadOnlyRequestThread exec finish");
    });
}

Interceptor_Result HttpInterceptorMgr::IteratorRequestInterceptor(
    std::shared_ptr<Http_Interceptor_Request> &req, bool &isModified)
{
    NETSTACK_LOGD("Enter IteratorRequestInterceptor");
    if (req == nullptr) {
        NETSTACK_LOGI("IteratorRequestInterceptor failed, req ptr is nullptr");
        return CONTINUE;
    }

    std::shared_ptr<Http_Interceptor_Request> readReq = CreateHttpInterceptorRequest();
    CopyHttpInterceRequest(readReq, req);
    IteratorReadRequestInterceptor(readReq);
    std::shared_lock<std::shared_mutex> lock(reqMutex_);
    for (const auto &interceptor : requestInterceptorList_) {
        if (interceptor->type == TYPE_MODIFY && interceptor->handler != nullptr && interceptor->enabled) {
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
    NETSTACK_LOGD("Exit IteratorRequestInterceptor");
    return CONTINUE;
}

void HttpInterceptorMgr::CopyHttpInterceResponse(
    std::shared_ptr<Http_Interceptor_Response> &dst, std::shared_ptr<Http_Interceptor_Response> &src)
{
    if (dst == nullptr || src == nullptr) {
        return;
    }
    DeepCopyBuffer(&dst->body, &src->body);
    dst->responseCode = src->responseCode;
    dst->headers = DeepCopyHeaders(src->headers);
    dst->performanceTiming = src->performanceTiming;
}

void HttpInterceptorMgr::IteratorReadResponseInterceptor(std::shared_ptr<Http_Interceptor_Response> &readResp)
{
    if (readResp == nullptr) {
        NETSTACK_LOGI("IteratorReadResponseInterceptor failed, readResp ptr is nullptr");
        return;
    }
    std::weak_ptr<HttpInterceptorMgr> self = shared_from_this();
    ffrt::submit([self, readResp]() {
        auto manage = self.lock();
        if (manage == nullptr) {
            NETSTACK_LOGI("manage ptr is nullptr");
            return;
        }
        std::shared_lock<std::shared_mutex> lock(manage->respMutex_);
        for (const auto &interceptor : manage->responseInterceptorList_) {
            if (interceptor->type == TYPE_READ_ONLY && interceptor->handler != nullptr && interceptor->enabled) {
                (void)interceptor->handler(nullptr, readResp.get(), nullptr);
            }
        }
        NETSTACK_LOGD("ReadOnlyResponseThread exec finish");
    });
}

Interceptor_Result HttpInterceptorMgr::IteratorResponseInterceptor(
    std::shared_ptr<Http_Interceptor_Response> &resp, bool &isModified)
{
    NETSTACK_LOGD("Enter IteratorResponseInterceptor");
    if (resp == nullptr) {
        NETSTACK_LOGI("IteratorResponseInterceptor failed, resp ptr is nullptr");
        return CONTINUE;
    }

    std::shared_ptr<Http_Interceptor_Response> readResp = CreateHttpInterceptorResponse();
    CopyHttpInterceResponse(readResp, resp);
    IteratorReadResponseInterceptor(readResp);
    std::shared_lock<std::shared_mutex> lock(respMutex_);
    for (const auto &interceptor : responseInterceptorList_) {
        if (interceptor->type == TYPE_MODIFY && interceptor->handler != nullptr && interceptor->enabled) {
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
    NETSTACK_LOGD("Exit IteratorResponseInterceptor");
    return CONTINUE;
}
} // namespace OHOS::NetStack::HttpInterceptor