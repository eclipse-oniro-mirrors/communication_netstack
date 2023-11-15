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

#ifndef COMMUNICATIONNETSTACK_HTTP_CLIENT_H
#define COMMUNICATIONNETSTACK_HTTP_CLIENT_H

#include <string>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <queue>
#include <atomic>
#include <iostream>

#include "http_client_request.h"
#include "http_client_error.h"
#include "http_client_task.h"

namespace OHOS {
namespace NetStack {
namespace HttpClient {
class HttpSession {
public:
    /**
     * Gets the singleton instance of HttpSession.
     * @return The singleton instance of HttpSession.
     */
    static HttpSession &GetInstance();

    /**
     * Creates an HTTP client task with the provided request.
     * @param request The HTTP request to be executed.
     * @return A shared pointer to the created HttpClientTask object.
     */
    [[nodiscard]] std::shared_ptr<HttpClientTask> CreateTask(const HttpClientRequest &request);

    /**
     * Creates an HTTP client task with the provided request and file path.
     * @param request The HTTP request to be executed.
     * @param type The type of the task.
     * @param filePath The file path to read the uploaded file (applicable for upload tasks).
     * @return A shared pointer to the created HttpClientTask object.
     */
    [[nodiscard]] std::shared_ptr<HttpClientTask> CreateTask(const HttpClientRequest &request, TaskType type,
                                                             const std::string &filePath);

private:
    friend class HttpClientTask;

    /**
     * Default constructor.
     */
    HttpSession();
    ~HttpSession();

    /**
     * Initializes the HttpSession.
     * @return true if initialization succeeds, false otherwise.
     */
    bool Init();

    /**
     * HttpSession initialization ended.
     */
    void Deinit();

    /**
     * Runs the thread for handling HTTP tasks.
     */
    static void RunThread();

    /**
     * Starts the specified HTTP client task.
     * @param ptr A shared pointer to the HttpClientTask object.
     */
    void StartTask(std::shared_ptr<HttpClientTask> ptr);

    /**
     * Stops the specified HTTP client task.
     * @param ptr A shared pointer to the HttpClientTask object.
     */
    void StopTask(std::shared_ptr<HttpClientTask> ptr);

    /**
     * Gets the HTTP client task with the specified task ID.
     * @param taskId The ID of the task to retrieve.
     * @return A shared pointer to the HttpClientTask object, or nullptr if not found.
     */
    std::shared_ptr<HttpClientTask> GetTaskById(uint32_t taskId);

    /**
     * Gets the HTTP client task with the specified Curl handle.
     * @param curlHandle The Curl handle of the task to retrieve.
     * @return A shared pointer to the HttpClientTask object, or nullptr if not found.
     */
    std::shared_ptr<HttpClientTask> GetTaskByCurlHandle(CURL *curlHandle);

    static std::mutex curlMultiMutex_;
    static CURLM *curlMulti_;
    std::mutex taskMapMutex_;
    std::mutex initMutex_;
    std::map<CURL *, std::shared_ptr<HttpClientTask>> curlTaskMap_;
    std::map<uint32_t, std::shared_ptr<HttpClientTask>> taskIdMap_;
    static std::condition_variable conditionVariable_;
    struct CompareTasks {
        bool operator()(const std::shared_ptr<HttpClientTask> &task1, const std::shared_ptr<HttpClientTask> &task2)
        {
            if (task1->GetRequest().GetPriority() == task2->GetRequest().GetPriority()) {
                return task1->GetTaskId() > task2->GetTaskId();
            }

            return task1->GetRequest().GetPriority() < task2->GetRequest().GetPriority();
        }
    };
    static std::mutex taskQueueMutex_;
    static std::priority_queue<std::shared_ptr<HttpClientTask>, std::vector<std::shared_ptr<HttpClientTask>>,
                               CompareTasks>
        taskQueue_;
    static std::atomic_bool initialized_;
    static std::thread workThread_;
    static std::atomic_bool runThread_;

    /**
     * Sends an HTTP request and handles the response.
     */
    void RequestAndResponse();

    /**
     * Reads the response received from the HTTP request.
     */
    void ReadResponse();

    /**
     * Adds additional information to the HTTP request.
     */
    void AddRequestInfo();

    /**
     * Executes the HTTP request.
     */
    void ExecRequest();
};
} // namespace HttpClient
} // namespace NetStack
} // namespace OHOS

#endif // COMMUNICATIONNETSTACK_HTTP_CLIENT_H
