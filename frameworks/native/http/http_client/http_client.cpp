/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include <atomic>
#include <curl/curl.h>
#include <functional>
#include <iostream>

#include "epoll_request_handler.h"
#include "http_client.h"
#include "netstack_log.h"

namespace OHOS {
namespace NetStack {
namespace HttpClient {

class HttpGlobal {
public:
    HttpGlobal()
    {
        if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
            NETSTACK_LOGE("Failed to initialize 'curl'");
        }
    }
    ~HttpGlobal()
    {
        NETSTACK_LOGD("Deinit curl_global_cleanup()");
        curl_global_cleanup();
    }
};
static HttpGlobal g_httpGlobal;

HttpSession::HttpSession() = default;

HttpSession::~HttpSession()
{
    NETSTACK_LOGD("~HttpSession::enter");
}

HttpSession &HttpSession::GetInstance()
{
    static HttpSession gInstance;
    return gInstance;
}

std::shared_ptr<HttpClientTask> HttpSession::CreateTask(const HttpClientRequest &request)
{
    std::shared_ptr<HttpClientTask> ptr = std::make_shared<HttpClientTask>(request);
    if (ptr->GetCurlHandle() == nullptr) {
        NETSTACK_LOGE("CreateTask A error!");
        return nullptr;
    }

    return ptr;
}

std::shared_ptr<HttpClientTask> HttpSession::CreateTask(const HttpClientRequest &request, TaskType type,
                                                        const std::string &filePath)
{
    std::shared_ptr<HttpClientTask> ptr = std::make_shared<HttpClientTask>(request, type, filePath);
    if (ptr->GetCurlHandle() == nullptr) {
        NETSTACK_LOGE("CreateTask B error!");
        return nullptr;
    }
    return ptr;
}

void HttpSession::StartTask(const std::shared_ptr<HttpClientTask> &ptr)
{
    if (nullptr == ptr) {
        NETSTACK_LOGE("HttpSession::StartTask  shared_ptr = nullptr! Error!");
        return;
    }

    static HttpOverCurl::EpollRequestHandler requestHandler;

    ptr->SetStatus(TaskStatus::RUNNING);
    auto startedCallback = [ptr](CURL *, void *) {};
    auto responseCallback = [ptr](CURLMsg *curlMessage, void *) {
        ptr->ProcessResponse(curlMessage);
        ptr->SetStatus(TaskStatus::IDLE);
    };

    requestHandler.Process(ptr->GetCurlHandle(), startedCallback, responseCallback);
}

} // namespace HttpClient
} // namespace NetStack
} // namespace OHOS
