/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <iostream>
#include <curl/curl.h>

#include "http_client.h"
#include "netstack_log.h"

namespace OHOS {
namespace NetStack {
namespace HttpClient {
std::atomic_bool HttpSession::runThread_(false);
std::mutex HttpSession::curlMultiMutex_;
CURLM *HttpSession::curlMulti_;
std::atomic_bool HttpSession::initialized_(false);
std::thread HttpSession::workThread_;
std::condition_variable HttpSession::conditionVariable_;
std::mutex HttpSession::taskQueueMutex_;
std::priority_queue<std::shared_ptr<HttpClientTask>, std::vector<std::shared_ptr<HttpClientTask>>,
                    HttpSession::CompareTasks>
    HttpSession::taskQueue_;
HttpSession HttpSession::instance_;

static constexpr int CURL_MAX_WAIT_MSECS = 10;
static constexpr int CURL_TIMEOUT_MS = 50;
static constexpr int CONDITION_TIMEOUT_S = 3600;

HttpSession::~HttpSession()
{
}

void HttpSession::ExecRequest()
{
}

void HttpSession::AddRequestInfo()
{
}

void HttpSession::RequestAndResponse()
{
}

void HttpSession::ReadResponse()
{
}

void HttpSession::RunThread()
{
}

bool HttpSession::Init()
{
    return true;
}

bool HttpSession::IsInited()
{
    return initialized_;
}

void HttpSession::Deinit()
{
}

std::shared_ptr<HttpClientTask> HttpSession::CreateTask(const HttpClientRequest &request)
{
    return nullptr;
}

std::shared_ptr<HttpClientTask> HttpSession::CreateTask(const HttpClientRequest &request, TaskType type,
                                                        const std::string &filePath)
{
    return nullptr;
}

void HttpSession::StartTask(std::shared_ptr<HttpClientTask> ptr)
{
}

void HttpSession::StopTask(std::shared_ptr<HttpClientTask> ptr)
{
}

std::shared_ptr<HttpClientTask> HttpSession::GetTaskById(uint32_t taskId)
{
    return nullptr;
}

std::shared_ptr<HttpClientTask> HttpSession::GetTaskByCurlHandle(CURL *curlHandle)
{
    return nullptr;
}

} // namespace HttpClient
} // namespace NetStack
} // namespace OHOS