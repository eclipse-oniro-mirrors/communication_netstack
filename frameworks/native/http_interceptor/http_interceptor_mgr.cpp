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
#include "securec.h"
#include "timing.h"

namespace OHOS::NetStack::HttpInterceptor {

HttpInterceptorMgr &HttpInterceptorMgr::GetInstance()
{
    static std::shared_ptr<HttpInterceptorMgr> instance = std::make_shared<HttpInterceptorMgr>();
    return *instance;
}

std::shared_ptr<OH_Http_Interceptor_Request> HttpInterceptorMgr::CreateHttpInterceptorRequest()
{
    // LCOV_EXCL_START
    OH_Http_Interceptor_Request *ptr =
        static_cast<OH_Http_Interceptor_Request *>(malloc(sizeof(OH_Http_Interceptor_Request)));
    if (ptr == nullptr) {
        return nullptr;
    }
    // LCOV_EXCL_STOP
    std::shared_ptr<OH_Http_Interceptor_Request> req =
        std::shared_ptr<OH_Http_Interceptor_Request>(ptr, [](OH_Http_Interceptor_Request *r) {
            DestroyHttpInterceptorRequest(r);
        });
    InitHttpBuffer(&req->url);
    InitHttpBuffer(&req->method);
    InitHttpBuffer(&req->body);
    req->headers = nullptr;
    return req;
}
std::shared_ptr<OH_Http_Interceptor_Response> HttpInterceptorMgr::CreateHttpInterceptorResponse()
{
    // LCOV_EXCL_START
    OH_Http_Interceptor_Response *ptr =
        static_cast<OH_Http_Interceptor_Response *>(malloc(sizeof(OH_Http_Interceptor_Response)));
    if (ptr == nullptr) {
        return nullptr;
    }
    // LCOV_EXCL_STOP
    std::shared_ptr<OH_Http_Interceptor_Response> resp =
        std::shared_ptr<OH_Http_Interceptor_Response>(ptr, [](OH_Http_Interceptor_Response *r) {
            DestroyHttpInterceptorResponse(r);
        });
    InitHttpBuffer(&resp->body);
    resp->headers = nullptr;
    resp->responseCode = OH_HTTP_OK;
    resp->performanceTiming = { 0 };
    return resp;
}

int32_t HttpInterceptorMgr::AddInterceptor(struct OH_Http_Interceptor *interceptor)
{
    if (interceptor == nullptr) {
        NETSTACK_LOGE("AddInterceptor failed, interceptor ptr is nullptr");
        return OH_HTTP_PARAMETER_ERROR;
    }
    std::unique_lock<std::shared_mutex> lock(interceptor->stage == OH_STAGE_REQUEST ? reqMutex_ : respMutex_);
    auto &targetList = interceptor->stage == OH_STAGE_REQUEST ? requestInterceptorList_ : responseInterceptorList_;
    auto iter = std::find_if(targetList.begin(), targetList.end(), [&](const OH_Http_Interceptor *item) {
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

int32_t HttpInterceptorMgr::DeleteInterceptor(struct OH_Http_Interceptor *interceptor)
{
    if (interceptor == nullptr) {
        NETSTACK_LOGE("DeleteInterceptor failed, interceptor ptr is nullptr");
        return OH_HTTP_PARAMETER_ERROR;
    }
    std::unique_lock<std::shared_mutex> lock(interceptor->stage == OH_STAGE_REQUEST ? reqMutex_ : respMutex_);
    auto &targetList = interceptor->stage == OH_STAGE_REQUEST ? requestInterceptorList_ : responseInterceptorList_;
    auto iter = std::find_if(targetList.begin(), targetList.end(), [&](const OH_Http_Interceptor *item) {
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
    requestInterceptorList_.remove_if([groupId](const OH_Http_Interceptor *interceptor) {
        return interceptor->groupId == groupId;
    });
    std::unique_lock<std::shared_mutex> respLock(respMutex_);
    responseInterceptorList_.remove_if([groupId](const OH_Http_Interceptor *interceptor) {
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
    std::shared_ptr<OH_Http_Interceptor_Request> &dst, std::shared_ptr<OH_Http_Interceptor_Request> &src)
{
    if (dst == nullptr || src == nullptr) {
        return;
    }
    DeepCopyBuffer(&dst->url, &src->url);
    DeepCopyBuffer(&dst->method, &src->method);
    DeepCopyBuffer(&dst->body, &src->body);
    dst->headers = DeepCopyHeaders(src->headers);
}

void HttpInterceptorMgr::IteratorReadRequestInterceptor(std::shared_ptr<OH_Http_Interceptor_Request> &readReq)
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
            if (interceptor && interceptor->type == OH_TYPE_READ_ONLY && interceptor->handler != nullptr &&
                interceptor->enabled) {
                (void)interceptor->handler(readReq.get(), nullptr, nullptr);
            }
        }
        NETSTACK_LOGD("ReadOnlyRequestThread exec finish");
    });
}

OH_Interceptor_Result HttpInterceptorMgr::IteratorRequestInterceptor(
    std::shared_ptr<OH_Http_Interceptor_Request> &req, bool &isModified, bool needDeepCopy)
{
    NETSTACK_LOGD("Enter IteratorRequestInterceptor");
    if (req == nullptr) {
        NETSTACK_LOGI("IteratorRequestInterceptor failed, req ptr is nullptr");
        return OH_CONTINUE;
    }

    std::shared_ptr<OH_Http_Interceptor_Request> readReq = CreateHttpInterceptorRequest();
    CopyHttpInterceRequest(readReq, req);
    IteratorReadRequestInterceptor(readReq);
    std::shared_lock<std::shared_mutex> lock(reqMutex_);
    std::shared_ptr<OH_Http_Interceptor_Request> reqTmp = needDeepCopy ? CreateHttpInterceptorRequest() : req;
    if (needDeepCopy) {
        // LCOV_EXCL_START
        if (reqTmp == nullptr) {
            NETSTACK_LOGI("IteratorRequestInterceptor failed, reqTmp ptr is nullptr");
            return OH_CONTINUE;
        }
        // LCOV_EXCL_STOP
        CopyHttpInterceRequest(reqTmp, req);
    }

    OH_Interceptor_Result result = OH_CONTINUE;
    for (const auto &interceptor : requestInterceptorList_) {
        if (interceptor->type == OH_TYPE_MODIFY && interceptor->handler != nullptr && interceptor->enabled) {
            int32_t isModifiedFlag = 0;
            auto ret = interceptor->handler(reqTmp.get(), nullptr, &isModifiedFlag);
            if (isModifiedFlag) {
                isModified = true;
            }
            if (ret == OH_ABORT) {
                NETSTACK_LOGI("IteratorRequestInterceptor abort, interceptor return OH_ABORT");
                result = OH_ABORT;
                break;
            }
        }
    }
    if (isModified && needDeepCopy) {
        req = reqTmp;
    }
    NETSTACK_LOGD("Exit IteratorRequestInterceptor");
    return result;
}

void HttpInterceptorMgr::CopyHttpInterceResponse(
    std::shared_ptr<OH_Http_Interceptor_Response> &dst, std::shared_ptr<OH_Http_Interceptor_Response> &src)
{
    if (dst == nullptr || src == nullptr) {
        return;
    }
    DeepCopyBuffer(&dst->body, &src->body);
    dst->responseCode = src->responseCode;
    dst->headers = DeepCopyHeaders(src->headers);
    dst->performanceTiming = src->performanceTiming;
}

void HttpInterceptorMgr::IteratorReadResponseInterceptor(std::shared_ptr<OH_Http_Interceptor_Response> &readResp)
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
            if (interceptor->type == OH_TYPE_READ_ONLY && interceptor->handler != nullptr && interceptor->enabled) {
                (void)interceptor->handler(nullptr, readResp.get(), nullptr);
            }
        }
        NETSTACK_LOGD("ReadOnlyResponseThread exec finish");
    });
}

OH_Interceptor_Result HttpInterceptorMgr::IteratorResponseInterceptor(
    std::shared_ptr<OH_Http_Interceptor_Response> &resp, bool &isModified, bool needDeepCopy)
{
    NETSTACK_LOGD("Enter IteratorResponseInterceptor");
    if (resp == nullptr) {
        NETSTACK_LOGI("IteratorResponseInterceptor failed, resp ptr is nullptr");
        return OH_CONTINUE;
    }

    std::shared_ptr<OH_Http_Interceptor_Response> readResp = CreateHttpInterceptorResponse();
    CopyHttpInterceResponse(readResp, resp);
    IteratorReadResponseInterceptor(readResp);
    std::shared_lock<std::shared_mutex> lock(respMutex_);
    std::shared_ptr<OH_Http_Interceptor_Response> respTmp = needDeepCopy ? CreateHttpInterceptorResponse() : resp;
    if (needDeepCopy) {
        // LCOV_EXCL_START
        if (respTmp == nullptr) {
            NETSTACK_LOGI("IteratorResponseInterceptor failed, respTmp ptr is nullptr");
            return OH_CONTINUE;
        }
        // LCOV_EXCL_STOP
        CopyHttpInterceResponse(respTmp, resp);
    }
    OH_Interceptor_Result result = OH_CONTINUE;
    for (const auto &interceptor : responseInterceptorList_) {
        if (interceptor->type == OH_TYPE_MODIFY && interceptor->handler != nullptr && interceptor->enabled) {
            int32_t isModifiedFlag = 0;
            OH_Interceptor_Result ret = interceptor->handler(nullptr, respTmp.get(), &isModifiedFlag);
            if (isModifiedFlag) {
                isModified = true;
            }
            if (ret == OH_ABORT) {
                NETSTACK_LOGI("IteratorResponseInterceptor abort, interceptor return OH_ABORT");
                result = OH_ABORT;
                break;
            }
        }
    }
    if (isModified && needDeepCopy) {
        resp = respTmp;
    }
    NETSTACK_LOGD("Exit IteratorResponseInterceptor");
    return result;
}

bool HttpInterceptorMgr::HasEnabledInterceptor(OH_Interceptor_Stage stage)
{
    std::shared_lock<std::shared_mutex> lock(stage == OH_STAGE_REQUEST ? reqMutex_ : respMutex_);
    auto &targetList = stage == OH_STAGE_REQUEST ? requestInterceptorList_ : responseInterceptorList_;
    auto iter = std::find_if(targetList.begin(), targetList.end(), [&](const OH_Http_Interceptor *item) {
        return item->enabled == 1;
    });
    if (iter == targetList.end()) {
        NETSTACK_LOGD("interceptor not exist");
        return false;
    }
    return true;
}

bool HttpInterceptorMgr::HasEnabledRequestInterceptor()
{
    return HasEnabledInterceptor(OH_STAGE_REQUEST);
}
bool HttpInterceptorMgr::HasEnabledResponseInterceptor()
{
    return HasEnabledInterceptor(OH_STAGE_RESPONSE);
}

void HttpInterceptorMgr::ConvertStringToRawPtr(const std::string &str, Http_Buffer &out)
{
    if (str.empty()) {
        return;
    }
    // LCOV_EXCL_START
    auto buffer = static_cast<char *>(malloc(str.size() + 1));
    if (buffer == nullptr) {
        return;
    }
    buffer[str.size()] = '\0';
    if (memcpy_s(buffer, str.size(), str.data(), str.size()) != EOK) {
        free(buffer);
        return;
    }
    // LCOV_EXCL_STOP
    out.length = str.size();
    out.buffer = buffer;
}

curl_slist *HttpInterceptorMgr::CurlParseHeaderRawPtr(
    const std::shared_ptr<std::unordered_map<std::string, std::vector<std::string>>> &headers)
{
    if (headers == nullptr) {
        return nullptr;
    }
    curl_slist *curlHeader = nullptr;
    for (const auto &[key, valueVec] : *headers) {
        for (const auto &value : valueVec) {
            std::string s;
            s.append(key).append(": ").append(value);
            curlHeader = curl_slist_append(curlHeader, s.c_str());
        }
    }
    return curlHeader;
}

double HttpInterceptorMgr::GetTimingFromCurl(CURL *handle, CURLINFO info) const
{
    curl_off_t timing;
    CURLcode result = curl_easy_getinfo(handle, info, &timing);
    if (result != CURLE_OK) {
        NETSTACK_LOGE("Failed to get timing: %{public}d, %{public}s", info, curl_easy_strerror(result));
        return 0;
    }
    return Timing::TimeUtils::Microseconds2Milliseconds(timing);
}

void HttpInterceptorMgr::GetTimeInfoFromCurl(CURL *curl, Http_PerformanceTiming &timeInfo)
{
    timeInfo.dnsTiming = GetTimingFromCurl(curl, CURLINFO_NAMELOOKUP_TIME_T);
    timeInfo.tcpTiming = GetTimingFromCurl(curl, CURLINFO_CONNECT_TIME_T);
    timeInfo.tlsTiming = GetTimingFromCurl(curl, CURLINFO_APPCONNECT_TIME_T);
    timeInfo.firstSendTiming = GetTimingFromCurl(curl, CURLINFO_PRETRANSFER_TIME_T);
    timeInfo.firstReceiveTiming = GetTimingFromCurl(curl, CURLINFO_STARTTRANSFER_TIME_T);
    timeInfo.totalFinishTiming = GetTimingFromCurl(curl, CURLINFO_TOTAL_TIME_T);
    timeInfo.redirectTiming = GetTimingFromCurl(curl, CURLINFO_REDIRECT_TIME_T);
}

std::shared_ptr<OH_Http_Interceptor_Response> HttpInterceptorMgr::ConvertToNetStackResponse(CURL *curl,
    const std::shared_ptr<std::unordered_map<std::string, std::vector<std::string>>> &headers, const std::string &body)
{
    if (!curl) {
        return nullptr;
    }
    auto response = CreateHttpInterceptorResponse();
    // LCOV_EXCL_START
    if (response == nullptr) {
        return nullptr;
    }
    // LCOV_EXCL_STOP
    long statusCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &statusCode);
    response->responseCode = static_cast<Http_ResponseCode>(statusCode);
    ConvertStringToRawPtr(body, response->body);
    auto tempHeaders = CurlParseHeaderRawPtr(headers);
    if (tempHeaders) {
        response->headers = tempHeaders;
    }
    GetTimeInfoFromCurl(curl, response->performanceTiming);
    return response;
}

void HttpInterceptorMgr::ReportHttpResponse(CURL *curl,
    const std::shared_ptr<std::unordered_map<std::string, std::vector<std::string>>> &headers, const std::string &body)
{
    if (!HasEnabledResponseInterceptor()) {
        return;
    }
    auto response = ConvertToNetStackResponse(curl, headers, body);
    if (response) {
        bool isModified = false;
        IteratorResponseInterceptor(response, isModified);
    }
}
} // namespace OHOS::NetStack::HttpInterceptor