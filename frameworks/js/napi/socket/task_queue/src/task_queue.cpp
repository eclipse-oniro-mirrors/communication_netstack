/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "task_queue.h"

#include <memory>
#include <mutex>
#include <queue>

#include "netstack_log.h"

namespace OHOS::NetStack::Task {
class Task {
public:
    Task() = delete;

    Task(TaskPriority priority, AsyncWorkExecutor exec, AsyncWorkCallback call, void *d)
        : executor(exec), callback(call), data(d), priority_(priority)
    {
    }

    ~Task() = default;

    bool operator<(const Task &e) const
    {
        return priority_ < e.priority_;
    }

    AsyncWorkExecutor executor;
    AsyncWorkCallback callback;
    void *data;

private:
    TaskPriority priority_;
};

std::priority_queue<Task> g_taskExecutorQueue; /* NOLINT */

std::priority_queue<Task> g_taskCallbackQueue; /* NOLINT */

std::mutex g_mutex;

void Executor(napi_env env, void *data)
{
    std::lock_guard<std::mutex> lock(g_mutex);

    if (g_taskExecutorQueue.empty()) {
        NETSTACK_LOGI("queue is empty");
        return;
    }

    auto context = static_cast<BaseContext *>(data);
    context->SetExecOK(true);

    Task task = g_taskExecutorQueue.top();
    g_taskExecutorQueue.pop();
    task.executor(env, task.data);
    g_taskCallbackQueue.push(task);
}

void Callback(napi_env env, napi_status status, void *data)
{
    std::lock_guard<std::mutex> lock(g_mutex);

    (void)status;

    auto deleter = [](BaseContext *context) { delete context; };
    std::unique_ptr<BaseContext, decltype(deleter)> context(static_cast<BaseContext *>(data), deleter);

    if (!context->IsExecOK()) {
        NETSTACK_LOGI("new async work again to read the task queue");
        auto again = new BaseContext(env, nullptr);
        again->CreateAsyncWork(context->GetAsyncWorkName(), Executor, Callback);
    }

    if (g_taskCallbackQueue.empty()) {
        return;
    }

    Task task = g_taskCallbackQueue.top();
    g_taskCallbackQueue.pop();
    task.callback(env, napi_ok, task.data);
}

void PushTask(TaskPriority priority, AsyncWorkExecutor executor, AsyncWorkCallback callback, void *data)
{
    std::lock_guard<std::mutex> lock(g_mutex);

    g_taskExecutorQueue.push(Task(priority, executor, callback, data));
}
} // namespace OHOS::NetStack::Task
