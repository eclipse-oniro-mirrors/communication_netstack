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
#include <list>
#include <mutex>
#include <shared_mutex>
#include <thread>

#include "http_interceptor_type.h"

namespace OHOS {
namespace NetStack {
namespace HttpInterceptor {
class HttpInterceptorMgr : public std::enable_shared_from_this<HttpInterceptorMgr> {
public:
    static HttpInterceptorMgr &GetInstance();

    int AddInterceptor(struct Http_Interceptor *interceptor);

    int DeleteInterceptor(struct Http_Interceptor *interceptor);

    int DeleteAllInterceptor();

    int StartAllInterceptor();

    int StopAllInterceptor();

    bool GetInterceptorMgrStatus();

    Interceptor_Result IteratorRequestInterceptor(std::shared_ptr<Http_Interceptor_Request> req, bool &isModified);

    Interceptor_Result IteratorResponseInterceptor(std::shared_ptr<Http_Response> resp, bool &isModified);

    HttpInterceptorMgr() = default;
    ~HttpInterceptorMgr() = default;

private:
    HttpInterceptorMgr(const HttpInterceptorMgr &) = delete;
    HttpInterceptorMgr &operator=(const HttpInterceptorMgr &) = delete;

private:
    std::list<Http_Interceptor *> requestInterceptorList_;
    std::list<Http_Interceptor *> responseInterceptorList_;
    std::shared_mutex reqMutex_;
    std::shared_mutex respMutex_;
    std::atomic<bool> isRunning_ { false };
};
} // namespace HttpInterceptor
} // namespace NetStack
} // namespace OHOS

#endif // COMMUNICATIONNETSTACK_HTTP_INTERCEPTOR_MGR_H