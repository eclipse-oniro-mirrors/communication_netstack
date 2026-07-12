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

#ifndef COMMUNICATIONNETSTACK_HTTP_INTERCEPTOR_MGR_H
#define COMMUNICATIONNETSTACK_HTTP_INTERCEPTOR_MGR_H
#include <atomic>
#include <cstddef>
#include <list>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "http_interceptor_type.h"

namespace OHOS {
namespace NetStack {
namespace HttpInterceptor {

struct HttpRequestData {
    const std::string &url;
    const std::string &method;
    const std::shared_ptr<std::unordered_map<std::string, std::vector<std::string>>> &headers;
    const std::shared_ptr<std::string> &body;
};

class HttpInterceptorMgr : public std::enable_shared_from_this<HttpInterceptorMgr> {
public:
    static HttpInterceptorMgr &GetInstance();

    int32_t AddInterceptor(struct OH_Http_Interceptor *interceptor);

    int32_t DeleteInterceptor(struct OH_Http_Interceptor *interceptor);

    int32_t DeleteAllInterceptor(int32_t groupId);

    int32_t SetAllInterceptorEnabled(int32_t groupId, int32_t enabled);

    OH_Interceptor_Result IteratorRequestInterceptor(std::shared_ptr<OH_Http_Interceptor_Request> &req,
        bool &isModified, OH_Interceptor_Type type = OH_TYPE_MODIFY_NETWORK_KIT, bool needDeepCopy = false);

    OH_Interceptor_Result IteratorResponseInterceptor(std::shared_ptr<OH_Http_Interceptor_Response> &resp,
        bool &isModified, OH_Interceptor_Type type = OH_TYPE_MODIFY_NETWORK_KIT, bool needDeepCopy = false,
        std::shared_ptr<OH_Http_Interceptor_Request> req = nullptr);

    void ReportHttpResponse(CURL *curl,
        const std::shared_ptr<std::unordered_map<std::string, std::vector<std::string>>> &headers,
        const std::string &body,
        const std::optional<HttpRequestData> &requestData = std::nullopt);

    bool HasEnabledRequestInterceptor();

    bool HasEnabledResponseInterceptor();

    std::shared_ptr<OH_Http_Interceptor_Request> CreateHttpInterceptorRequest();
    std::shared_ptr<OH_Http_Interceptor_Response> CreateHttpInterceptorResponse();

    HttpInterceptorMgr() = default;
    ~HttpInterceptorMgr() = default;

private:
    HttpInterceptorMgr(const HttpInterceptorMgr &) = delete;
    HttpInterceptorMgr &operator=(const HttpInterceptorMgr &) = delete;
    void CopyHttpInterceRequest(
        std::shared_ptr<OH_Http_Interceptor_Request> &dst, std::shared_ptr<OH_Http_Interceptor_Request> &src);
    void CopyHttpInterceResponse(
        std::shared_ptr<OH_Http_Interceptor_Response> &dst, std::shared_ptr<OH_Http_Interceptor_Response> &src);
    void IteratorReadRequestInterceptor(std::shared_ptr<OH_Http_Interceptor_Request> &readReq);
    void IteratorReadResponseInterceptor(std::shared_ptr<OH_Http_Interceptor_Response> &readResp,
        std::shared_ptr<OH_Http_Interceptor_Request> readReq = nullptr);
    bool HasEnabledInterceptor(OH_Interceptor_Stage stage);
    std::shared_ptr<OH_Http_Interceptor_Request> PrepareReadRequest(
        std::shared_ptr<OH_Http_Interceptor_Request> &req);
    std::shared_ptr<OH_Http_Interceptor_Response> PrepareResponseCopy(
        std::shared_ptr<OH_Http_Interceptor_Response> &resp, bool needDeepCopy);

    void ConvertStringToRawPtr(const std::string &str, Http_Buffer &out);
    curl_slist *CurlParseHeaderRawPtr(
        const std::shared_ptr<std::unordered_map<std::string, std::vector<std::string>>> &headers);
    std::shared_ptr<OH_Http_Interceptor_Request> ConvertToNetStackRequest(const HttpRequestData &requestData);
    std::shared_ptr<OH_Http_Interceptor_Response> ConvertToNetStackResponse(CURL *curl,
        const std::shared_ptr<std::unordered_map<std::string, std::vector<std::string>>> &headers,
        const std::string &body);
    void GetTimeInfoFromCurl(CURL *curl, Http_PerformanceTiming &timeInfo);
    double GetTimingFromCurl(CURL *handle, CURLINFO info) const;

private:
    std::list<OH_Http_Interceptor *> requestInterceptorList_;
    std::list<OH_Http_Interceptor *> responseInterceptorList_;
    std::shared_mutex reqMutex_;
    std::shared_mutex respMutex_;
};
} // namespace HttpInterceptor
} // namespace NetStack
} // namespace OHOS

#endif // COMMUNICATIONNETSTACK_HTTP_INTERCEPTOR_MGR_H