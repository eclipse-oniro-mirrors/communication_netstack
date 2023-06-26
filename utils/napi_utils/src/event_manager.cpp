/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "event_manager.h"

#include "netstack_log.h"

namespace OHOS::NetStack {
static constexpr const int CALLBACK_PARAM_NUM = 1;

static constexpr const int ASYNC_CALLBACK_PARAM_NUM = 2;

EventManager::EventManager() : data_(nullptr), isValid_(true) {}

EventManager::~EventManager()
{
    NETSTACK_LOGI("EventManager is destructed by the destructor");
}

bool EventManager::IsManagerValid() const
{
    return isValid_;
}

void EventManager::SetInvalid()
{
    isValid_ = false;
}

void EventManager::AddListener(napi_env env, const std::string &type, napi_value callback, bool once,
                               bool asyncCallback)
{
    std::lock_guard<std::mutex> lock(mutexForListenersAndEmitByUv_);
    auto it = listeners_.find(type);
    if (it != listeners_.end()) {
        listeners_.erase(it);
    }

    listeners_.insert(std::make_pair(type, EventListener(env, type, callback, once, asyncCallback)));
}

void EventManager::DeleteListener(const std::string &type, napi_value callback)
{
    std::lock_guard<std::mutex> lock(mutexForListenersAndEmitByUv_);
    auto it = listeners_.find(type);
    if (it != listeners_.end() && it->second.Match(type, callback)) {
        listeners_.erase(it);
    }
}

void EventManager::Emit(const std::string &type, const std::pair<napi_value, napi_value> &argv)
{
    if (!IsManagerValid()) {
        return;
    }

    std::lock_guard<std::mutex> lock(mutexForEmitAndEmitByUv_);
    auto it = listeners_.find(type);
    if (it != listeners_.end() && it->second.MatchType(type)) {
        if (it->second.IsAsyncCallback()) {
            /* AsyncCallback(BusinessError error, T data) */
            napi_value arg[ASYNC_CALLBACK_PARAM_NUM] = {argv.first, argv.second};
            it->second.Emit(type, ASYNC_CALLBACK_PARAM_NUM, arg);
        } else {
            /* Callback(T data) */
            napi_value arg[CALLBACK_PARAM_NUM] = {argv.second};
            it->second.Emit(type, CALLBACK_PARAM_NUM, arg);
        }

        if (it->second.MatchOnce(type)) {
            listeners_.erase(it);
        }
    }
}

void EventManager::SetData(void *data)
{
    std::lock_guard<std::mutex> lock(mutexForData_);
    data_ = data;
}

void *EventManager::GetData()
{
    std::lock_guard<std::mutex> lock(mutexForData_);
    return data_;
}

void EventManager::EmitByUv(const std::string &type, void *data, void(Handler)(uv_work_t *, int))
{
    if (!IsManagerValid()) {
        return;
    }

    std::lock_guard<std::mutex> lock1(mutexForListenersAndEmitByUv_);
    std::lock_guard<std::mutex> lock2(mutexForEmitAndEmitByUv_);
    auto it = listeners_.find(type);
    if (it != listeners_.end() && it->second.MatchType(type)) {
        auto workWrapper = new UvWorkWrapper(data, it->second.GetEnv(), type, this);
        it->second.EmitByUv(type, workWrapper, Handler);

        if (it->second.MatchOnce(type)) {
            listeners_.erase(it);
        }
    }
}

bool EventManager::HasEventListener(const std::string &type)
{
    std::lock_guard<std::mutex> lock(mutexForListenersAndEmitByUv_);
    auto it = listeners_.find(type);
    return it != listeners_.end();
}

void EventManager::DeleteListener(const std::string &type)
{
    std::lock_guard<std::mutex> lock(mutexForListenersAndEmitByUv_);
    auto it = listeners_.find(type);
    if (it != listeners_.end() && it->second.MatchType(type)) {
        listeners_.erase(it);
    }
}

UvWorkWrapper::UvWorkWrapper(void *theData, napi_env theEnv, std::string eventType, EventManager *eventManager)
    : data(theData), env(theEnv), type(std::move(eventType)), manager(eventManager)
{
}
} // namespace OHOS::NetStack
