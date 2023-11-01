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

HttpSession::HttpSession()
{
  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    NETSTACK_LOGE("Failed to initialize 'curl'");
  }
}

HttpSession::~HttpSession()
{
    Deinit();
}

void HttpSession::ExecRequest()
{
    AddRequestInfo();
    RequestAndResponse();
}

void HttpSession::AddRequestInfo()
{
    std::shared_ptr<HttpClientTask> task = nullptr;
    std::lock_guard<std::mutex> lock(taskQueueMutex_);
    NETSTACK_LOGD("HttpSession::AddRequestInfo() start");

    while (!taskQueue_.empty()) {
        task = taskQueue_.top();
        taskQueue_.pop();

        if (task != nullptr) {
            NETSTACK_LOGD("taskQueue_ read GetTaskId : %{public}d", task->GetTaskId());
            std::lock_guard<std::mutex> guard(curlMultiMutex_);
            if (nullptr == curlMulti_) {
                NETSTACK_LOGE("HttpSession::AddRequestInfo() curlMulti_ is nullptr");
                StopTask(task);
                return;
            }
            auto ret = curl_multi_add_handle(curlMulti_, task->GetCurlHandle());
            if (ret != CURLM_OK) {
                NETSTACK_LOGE("curl_multi_add_handle err, ret = %{public}d", ret);
                StopTask(task);
                return;
            }
        }

        task = nullptr;
    }
}

void HttpSession::RequestAndResponse()
{
    int runningHandle = 0;
    NETSTACK_LOGD("HttpSession::RequestAndResponse() start");

    do {
        if (runningHandle > 0) {
            AddRequestInfo();
        }
        std::lock_guard<std::mutex> guard(curlMultiMutex_);
        if (!runThread_ || curlMulti_ == nullptr) {
            NETSTACK_LOGE("RequestAndResponse() runThread_ or curlMulti_ nullptr");
            break;
        }

        // send request
        auto ret = curl_multi_perform(curlMulti_, &runningHandle);
        if (ret != CURLM_OK) {
            NETSTACK_LOGE("curl_multi_perform() error! ret = %{public}d", ret);
            continue;
        }

        // wait for response
        ret = curl_multi_poll(curlMulti_, nullptr, 0, CURL_MAX_WAIT_MSECS, nullptr);
        if (ret != CURLM_OK) {
            NETSTACK_LOGE("curl_multi_poll() error! ret = %{public}d", ret);
            continue;
        }

        // read response
        ReadResponse();
    } while (runningHandle > 0);

    NETSTACK_LOGD("HttpSession::RequestAndResponse() end");
}

void HttpSession::ReadResponse()
{
    struct CURLMsg *m;
    do {
        int msgq = 0;
        m = curl_multi_info_read(curlMulti_, &msgq);
        if (m) {
            NETSTACK_LOGI("curl_multi_info_read() m->msg = %{public}d", m->msg);
            if (m->msg != CURLMSG_DONE) {
                continue;
            }
            auto task = GetTaskByCurlHandle(m->easy_handle);
            if (task) {
                task->ProcessResponse(m);
            }
            curl_multi_remove_handle(curlMulti_, m->easy_handle);
            StopTask(task);
        }
    } while (m);
}

void HttpSession::RunThread()
{
    NETSTACK_LOGI("RunThread start runThread_ = %{public}s", runThread_ ? "true" : "false");
    while (runThread_) {
        HttpSession::GetInstance().ExecRequest();
        std::this_thread::sleep_for(std::chrono::milliseconds(CURL_TIMEOUT_MS));
        NETSTACK_LOGD("RunThread in loop runThread_ = %{public}s", runThread_ ? "true" : "false");
        std::unique_lock<std::mutex> lock(taskQueueMutex_);
        conditionVariable_.wait_for(lock, std::chrono::seconds(CONDITION_TIMEOUT_S), [] {
            NETSTACK_LOGD("RunThread in loop wait_for taskQueue_.empty() = %{public}d runThread_ = %{public}s",
                          taskQueue_.empty(), runThread_ ? "true" : "false");
            return !taskQueue_.empty() || !runThread_;
        });
    }

    NETSTACK_LOGI("RunThread exit()");
}

bool HttpSession::Init()
{
    if (!initialized_) {
        NETSTACK_LOGD("HttpSession::Init");

        std::lock_guard<std::mutex> lock(taskQueueMutex_);
        std::lock_guard<std::mutex> guard(curlMultiMutex_);
        curlMulti_ = curl_multi_init();
        if (curlMulti_ == nullptr) {
            NETSTACK_LOGE("Failed to initialize 'curl_multi'");
            return false;
        }

        workThread_ = std::thread(RunThread);
        runThread_ = true;
        initialized_ = true;
    }

    return true;
}

bool HttpSession::IsInited()
{
    return initialized_;
}

void HttpSession::Deinit()
{
    NETSTACK_LOGD("HttpSession::Deinit");
    if (!initialized_) {
        NETSTACK_LOGD("HttpSession::Deinit not initialized");
        return;
    }

    std::unique_lock<std::mutex> lock(taskQueueMutex_);
    runThread_ = false;
    conditionVariable_.notify_all();
    lock.unlock();
    if (workThread_.joinable()) {
        NETSTACK_LOGD("HttpSession::Deinit workThread_.join()");
        workThread_.join();
    }

    std::lock_guard<std::mutex> guard(curlMultiMutex_);
    if (curlMulti_ != nullptr) {
        NETSTACK_LOGD("Deinit curl_multi_cleanup()");
        curl_multi_cleanup(curlMulti_);
        curlMulti_ = nullptr;
    }

    NETSTACK_LOGD("Deinit curl_global_cleanup()");
    curl_global_cleanup();

    initialized_ = false;

    std::this_thread::sleep_for(std::chrono::milliseconds(CURL_TIMEOUT_MS));
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

void HttpSession::StartTask(std::shared_ptr<HttpClientTask> ptr)
{
    if (nullptr == ptr) {
        NETSTACK_LOGE("HttpSession::StartTask  shared_ptr = nullptr! Error!");
        return;
    }
    NETSTACK_LOGD("HttpSession::StartTask taskId = %{public}d", ptr->GetTaskId());

    if (!IsInited()) {
        Init();
    }

    std::lock_guard<std::mutex> lock(taskQueueMutex_);
    std::lock_guard<std::mutex> guard(taskMapMutex_);
    ptr->SetStatus(TaskStatus::RUNNING);
    taskIdMap_[ptr->GetTaskId()] = ptr;
    curlTaskMap_[ptr->GetCurlHandle()] = ptr;
    taskQueue_.push(ptr);
    conditionVariable_.notify_all();
}

void HttpSession::StopTask(std::shared_ptr<HttpClientTask> ptr)
{
    if (nullptr == ptr) {
        NETSTACK_LOGE("HttpSession::StopTask  shared_ptr = nullptr! Error!");
        return;
    }

    NETSTACK_LOGD("HttpSession::StopTask taskId = %{public}d", ptr->GetTaskId());
    std::lock_guard<std::mutex> lock(taskQueueMutex_);
    std::lock_guard<std::mutex> guard(taskMapMutex_);
    ptr->SetStatus(TaskStatus::IDLE);

    if (ptr->GetCurlHandle() != nullptr) {
        curlTaskMap_.erase(ptr->GetCurlHandle());
    }
    taskIdMap_.erase(ptr->GetTaskId());
    conditionVariable_.notify_all();
}

std::shared_ptr<HttpClientTask> HttpSession::GetTaskById(uint32_t taskId)
{
    std::lock_guard<std::mutex> guard(taskMapMutex_);
    auto iter = taskIdMap_.find(taskId);
    if (iter != taskIdMap_.end()) {
        return iter->second;
    } else {
        return nullptr;
    }
}

std::shared_ptr<HttpClientTask> HttpSession::GetTaskByCurlHandle(CURL *curlHandle)
{
    std::lock_guard<std::mutex> guard(taskMapMutex_);
    auto iter = curlTaskMap_.find(curlHandle);
    if (iter != curlTaskMap_.end()) {
        return iter->second;
    } else {
        return nullptr;
    }
}

} // namespace HttpClient
} // namespace NetStack
} // namespace OHOS