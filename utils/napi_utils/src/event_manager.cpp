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

#include <map>
#include <algorithm>
#include "netstack_log.h"
#include "napi_utils.h"

namespace OHOS::NetStack {
static constexpr const int CALLBACK_PARAM_NUM = 1;
static constexpr const int ASYNC_CALLBACK_PARAM_NUM = 2;
static constexpr const char *ON_HEADER_RECEIVE = "headerReceive";
static constexpr const char *ON_HEADERS_RECEIVE = "headersReceive";

EventManager::EventManager() : data_(nullptr), eventRef_(nullptr), isDestroy_(false) {}

EventManager::~EventManager()
{
    NETSTACK_LOGD("EventManager is destructed by the destructor");
}

void EventManager::AddListener(napi_env env, const std::string &type, napi_value callback, bool once,
                               bool asyncCallback)
{
    std::lock_guard lock(mutexForListenersAndEmitByUv_);
    auto it = std::remove_if(listeners_.begin(), listeners_.end(),
                             [type](const EventListener &listener) -> bool { return listener.MatchType(type); });
    if (it != listeners_.end()) {
        listeners_.erase(it, listeners_.end());
    }

    listeners_.emplace_back(EventListener(env, type, callback, once, asyncCallback));
}

void EventManager::DeleteListener(const std::string &type, napi_value callback)
{
    std::lock_guard lock(mutexForListenersAndEmitByUv_);
    auto it =
        std::remove_if(listeners_.begin(), listeners_.end(), [type, callback](const EventListener &listener) -> bool {
            return listener.Match(type, callback);
        });
    listeners_.erase(it, listeners_.end());
}

void EventManager::Emit(const std::string &type, const std::pair<napi_value, napi_value> &argv)
{
    std::lock_guard lock(mutexForEmitAndEmitByUv_);
    auto listeners = listeners_;
    std::for_each(listeners.begin(), listeners.end(), [type, argv](const EventListener &listener) {
        if (listener.IsAsyncCallback()) {
            /* AsyncCallback(BusinessError error, T data) */
            napi_value arg[ASYNC_CALLBACK_PARAM_NUM] = {argv.first, argv.second};
            listener.Emit(type, ASYNC_CALLBACK_PARAM_NUM, arg);
        } else {
            /* Callback(T data) */
            napi_value arg[CALLBACK_PARAM_NUM] = {argv.second};
            listener.Emit(type, CALLBACK_PARAM_NUM, arg);
        }
    });

    auto it = std::remove_if(listeners_.begin(), listeners_.end(),
                             [type](const EventListener &listener) -> bool { return listener.MatchOnce(type); });
    listeners_.erase(it, listeners_.end());
}

void EventManager::SetData(void *data)
{
    std::lock_guard<std::mutex> lock(dataMutex_);
    data_ = data;
}

void *EventManager::GetData()
{
    std::lock_guard<std::mutex> lock(dataMutex_);
    return data_;
}

void EventManager::SetQueueData(void *data)
{
    std::lock_guard<std::mutex> lock(dataQueueMutex_);
    dataQueue_.push(data);
}

void *EventManager::GetQueueData()
{
    std::lock_guard<std::mutex> lock(dataQueueMutex_);
    if (!dataQueue_.empty()) {
        auto data = dataQueue_.front();
        dataQueue_.pop();
        return data;
    }
    NETSTACK_LOGE("eventManager data queue is empty");
    return nullptr;
}

void EventManager::EmitByUv(const std::string &type, void *data, void(Handler)(uv_work_t *, int status))
{
    std::lock_guard lock1(mutexForEmitAndEmitByUv_);
    std::lock_guard lock2(mutexForListenersAndEmitByUv_);
    if (!EventManager::IsManagerValid(this)) {
        return;
    }
    bool foundHeader = std::find_if(listeners_.begin(), listeners_.end(), [](const EventListener &listener) {
                           return listener.MatchType(ON_HEADER_RECEIVE);
                       }) != listeners_.end();
    bool foundHeaders = std::find_if(listeners_.begin(), listeners_.end(), [](const EventListener &listener) {
                            return listener.MatchType(ON_HEADERS_RECEIVE);
                        }) != listeners_.end();
    if (!foundHeader && !foundHeaders) {
        if (type == ON_HEADER_RECEIVE || type == ON_HEADERS_RECEIVE) {
            auto tempMap = static_cast<std::map<std::string, std::string> *>(data);
            delete tempMap;
        }
    } else if (foundHeader && !foundHeaders) {
        if (type == ON_HEADERS_RECEIVE) {
            auto tempMap = static_cast<std::map<std::string, std::string> *>(data);
            delete tempMap;
        }
    } else if (!foundHeader) {
        if (type == ON_HEADER_RECEIVE) {
            auto tempMap = static_cast<std::map<std::string, std::string> *>(data);
            delete tempMap;
        }
    }

    std::for_each(listeners_.begin(), listeners_.end(), [type, data, Handler, this](const EventListener &listener) {
        if (listener.MatchType(type)) {
            auto workWrapper = new UvWorkWrapper(data, listener.GetEnv(), type, this);
            listener.EmitByUv(type, workWrapper, Handler);
        }
    });
}

bool EventManager::HasEventListener(const std::string &type)
{
    std::lock_guard lock(mutexForListenersAndEmitByUv_);
    return std::any_of(listeners_.begin(), listeners_.end(),
                       [&type](const EventListener &listener) -> bool { return listener.MatchType(type); });
}

void EventManager::DeleteListener(const std::string &type)
{
    std::lock_guard lock(mutexForListenersAndEmitByUv_);
    auto it = std::remove_if(listeners_.begin(), listeners_.end(),
                             [type](const EventListener &listener) -> bool { return listener.MatchType(type); });
    listeners_.erase(it, listeners_.end());
}

std::unordered_set<EventManager *> EventManager::validManager_;
std::mutex EventManager::mutexForManager_;

void EventManager::SetInvalid(EventManager *manager)
{
    std::lock_guard lock(mutexForManager_);
    auto pos = validManager_.find(manager);
    if (pos == validManager_.end()) {
        NETSTACK_LOGE("The manager is not in the unordered_set");
        return;
    }
    validManager_.erase(pos);
    delete manager;
    manager = nullptr;
}

bool EventManager::IsManagerValid(EventManager *manager)
{
    std::lock_guard lock(mutexForManager_);
    return validManager_.find(manager) != validManager_.end();
}

void EventManager::SetValid(EventManager *manager)
{
    std::lock_guard lock(mutexForManager_);
    validManager_.emplace(manager);
}

void EventManager::CreateEventReference(napi_env env, napi_value value)
{
    if (env != nullptr && value != nullptr) {
        eventRef_ = NapiUtils::CreateReference(env, value);
    }
}

void EventManager::DeleteEventReference(napi_env env)
{
    if (env != nullptr && eventRef_ != nullptr) {
        NapiUtils::DeleteReference(env, eventRef_);
    }
}

void EventManager::SetEventDestroy(bool flag)
{
    isDestroy_.store(flag);
}

bool EventManager::IsEventDestroy()
{
    return isDestroy_.load();
}

const std::string &EventManager::GetWebSocketTextData()
{
    return webSocketTextData_;
}

void EventManager::AppendWebSocketTextData(void *data, size_t length)
{
    webSocketTextData_.append(reinterpret_cast<char *>(data), length);
}

const std::string &EventManager::GetWebSocketBinaryData()
{
    return webSocketBinaryData_;
}

void EventManager::AppendWebSocketBinaryData(void *data, size_t length)
{
    webSocketBinaryData_.append(reinterpret_cast<char *>(data), length);
}

void EventManager::ClearWebSocketTextData()
{
    webSocketTextData_.clear();
}

void EventManager::ClearWebSocketBinaryData()
{
    webSocketBinaryData_.clear();
}

UvWorkWrapper::UvWorkWrapper(void *theData, napi_env theEnv, std::string eventType, EventManager *eventManager)
    : data(theData), env(theEnv), type(std::move(eventType)), manager(eventManager)
{
}
} // namespace OHOS::NetStack
