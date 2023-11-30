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
#include <functional>
#include <curl/curl.h>

#include "http_client.h"
#include "netstack_log.h"

namespace OHOS {
namespace NetStack {
namespace HttpClient {

static constexpr int CURL_MAX_WAIT_MSECS = 100;
static constexpr int CURL_TIMEOUT_MS = 50;
static constexpr int CONDITION_TIMEOUT_S = 3600;

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

HttpSession::HttpSession() : curlMulti_(nullptr),
    initialized_(false),
    runThread_(false) {
}

HttpSession::~HttpSession()
{
    NETSTACK_LOGI("~HttpSession::enter");
    Deinit();
}

HttpSession &HttpSession::GetInstance()
{
    static HttpSession gInstance;
    return gInstance;
}

CURLMcode HttpSession::PerformRequest(int &runningHandle)
{
    CURLMcode ret = CURLM_LAST;
    std::unique_lock<std::mutex> lock(curlMultiMutex_);
    if (curlMulti_ == nullptr) {
        NETSTACK_LOGE("curlMulti_ is nullptr");
        return ret;
    }

    // send request
    ret = curl_multi_perform(curlMulti_, &runningHandle);
    if (ret != CURLM_OK) {
        NETSTACK_LOGE("curl_multi_perform() error! ret = %{public}d", ret);
        return ret;
    }

    // wait for response
    ret = curl_multi_poll(curlMulti_, nullptr, 0, CURL_MAX_WAIT_MSECS, nullptr);
    if (ret != CURLM_OK) {
        NETSTACK_LOGE("curl_multi_poll() error! ret = %{public}d", ret);
        return ret;
    }
    return ret;
}

void HttpSession::RequestAndResponse()
{
    NETSTACK_LOGD("HttpSession::RequestAndResponse() start");

    CURLMcode ret = CURLM_LAST;
    int runningHandle = 0;
    do {
        ret = PerformRequest(runningHandle);
        if (ret == CURLM_CALL_MULTI_PERFORM) {
            continue;
        } else if (ret == CURLM_OK) {
            ReadResponse();
        } else {
            // others are error
            continue;
        }
        // read response
    } while (runningHandle > 0 && runThread_);
    NETSTACK_LOGD("HttpSession::RequestAndResponse() end");
}

void HttpSession::ReadResponse()
{
    struct CURLMsg *m = nullptr;
    do {
        int msgq = 0;
        std::unique_lock<std::mutex> lock(curlMultiMutex_);
        struct CURLMsg *m = curl_multi_info_read(curlMulti_, &msgq);
        if (m) {
            NETSTACK_LOGI("curl_multi_info_read() m->msg = %{public}d", m->msg);
            if (m->msg != CURLMSG_DONE) {
                NETSTACK_LOGI("curl_multi_info_read failed, m->msg = %{public}d", m->msg);
                continue;
            }
            curl_multi_remove_handle(curlMulti_, m->easy_handle);
            lock.unlock();
            auto task = GetTaskByCurlHandle(m->easy_handle);
            if (task) {
                task->ProcessResponse(m);
            }
            StopTask(task);
            lock.lock();
        }
    } while (m && runThread_);
}

void HttpSession::RunThread()
{
    runThread_ = true;
    NETSTACK_LOGI("RunThread start runThread_ = %{public}s", runThread_ ? "true" : "false");

    while (runThread_) {
        RequestAndResponse();
        std::this_thread::sleep_for(std::chrono::milliseconds(CURL_TIMEOUT_MS));
        NETSTACK_LOGD("RunThread in loop runThread_ = %{public}s",
            runThread_ ? "true" : "false");
        
        std::function<bool()> f = [this]() -> bool {
            NETSTACK_LOGD("RunThread in loop wait_for taskQueue_.empty() = %{public}d runThread_ = %{public}s",
                          taskIdMap_.empty(), runThread_ ? "true" : "false");
            return !taskIdMap_.empty() || !runThread_;
        };
        std::unique_lock<std::mutex> lock(taskQueueMutex_);
        conditionVariable_.wait_for(lock, std::chrono::seconds(CONDITION_TIMEOUT_S), f);
    }

    NETSTACK_LOGI("RunThread exit()");
}

bool HttpSession::Init()
{
    std::lock_guard<std::mutex> guard(initMutex_);
    NETSTACK_LOGI("HttpSession::Init enter");
    if (!initialized_) {
        NETSTACK_LOGI("HttpSession::Init");

        std::lock_guard<std::mutex> guard(curlMultiMutex_);
        curlMulti_ = curl_multi_init();
        if (curlMulti_ == nullptr) {
            NETSTACK_LOGE("Failed to initialize 'curl_multi'");
            return false;
        }
        initialized_ = true;

        auto f = std::bind(&HttpSession::RunThread, this);
        workThread_ = std::thread(f);
    }
    return true;
}

void HttpSession::Deinit()
{
    NETSTACK_LOGI("HttpSession::Deinit");

    std::lock_guard<std::mutex> guard(initMutex_);
    if (!initialized_) {
        NETSTACK_LOGE("HttpSession::Deinit not initialized");
        return;
    }
    runThread_ = false;
    do {
        std::unique_lock<std::mutex> lock(taskQueueMutex_);
        conditionVariable_.notify_all();
    } while (0);

    if (workThread_.joinable()) {
        NETSTACK_LOGI("HttpSession::Deinit workThread_.join()");
        workThread_.join();
    }

    do {
        std::lock_guard<std::mutex> guard(taskMapMutex_);
        curlTaskMap_.clear();
        taskIdMap_.clear();
    } while (0);

    do {
        std::lock_guard<std::mutex> guard(curlMultiMutex_);
        if (curlMulti_ != nullptr) {
            NETSTACK_LOGI("Deinit curl_multi_cleanup()");
            curl_multi_cleanup(curlMulti_);
            curlMulti_ = nullptr;
        }
    } while (0);
    
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

void HttpSession::ResumTask()
{
    std::lock_guard<std::mutex> lock(taskQueueMutex_);
    conditionVariable_.notify_all();
}

void HttpSession::StartTask(std::shared_ptr<HttpClientTask> ptr)
{
    if (nullptr == ptr) {
        NETSTACK_LOGE("HttpSession::StartTask  shared_ptr = nullptr! Error!");
        return;
    }
    
    Init();
    
    /* add to task map */
    do {
        NETSTACK_LOGD("HttpSession::StartTask taskId = %{public}d", ptr->GetTaskId());
        std::lock_guard<std::mutex> guard(taskMapMutex_);
        taskIdMap_[ptr->GetTaskId()] = ptr;
        curlTaskMap_[ptr->GetCurlHandle()] = ptr;
        ptr->SetStatus(TaskStatus::RUNNING);
    } while (0);

    /* add handle to curl muti */
    do {
        std::lock_guard<std::mutex> guard(curlMultiMutex_);
        if (nullptr == curlMulti_) {
            NETSTACK_LOGE("curlMulti_ is nullptr");
            return;
        }
        auto ret = curl_multi_add_handle(curlMulti_, ptr->GetCurlHandle());
        if (ret != CURLM_OK) {
            NETSTACK_LOGE("curl_multi_add_handle err, ret = %{public}d", ret);
            return;
        }
    } while (0);
    ResumTask();
}

void HttpSession::StopTask(std::shared_ptr<HttpClientTask> ptr)
{
    std::lock_guard<std::mutex> guard(taskMapMutex_);
    if (nullptr == ptr) {
        NETSTACK_LOGE("HttpSession::StopTask  shared_ptr = nullptr! Error!");
        return;
    }
    NETSTACK_LOGD("HttpSession::StopTask taskId = %{public}d", ptr->GetTaskId());

    ptr->SetStatus(TaskStatus::IDLE);
    if (ptr->GetCurlHandle() != nullptr) {
        curlTaskMap_.erase(ptr->GetCurlHandle());
    }
    taskIdMap_.erase(ptr->GetTaskId());
    ResumTask();
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