/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "netstack_event_manager.h"

#include <algorithm>

namespace OHOS::NetStack {
constexpr const int CALLBACK_PARAM_NUM = 1;

constexpr const int ASYNC_CALLBACK_PARAM_NUM = 2;

EventManager::EventManager() : data_(nullptr) {}

void EventManager::AddListener(napi_env env,
                               const std::string &type,
                               napi_value callback,
                               bool once,
                               bool asyncCallback)
{
    listeners_.emplace_back(EventListener(env, type, callback, once, asyncCallback));
}

void EventManager::DeleteListener(const std::string &type, napi_value callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it =
        std::remove_if(listeners_.begin(), listeners_.end(), [type, callback](const EventListener &listener) -> bool {
            return listener.Match(type, callback);
        });
    listeners_.erase(it, listeners_.end());
}

void EventManager::Emit(const std::string &type, const std::pair<napi_value, napi_value> &argv)
{
    std::lock_guard<std::mutex> lock(mutex_);

    std::for_each(listeners_.begin(), listeners_.end(), [type, argv](const EventListener &listener) {
        if (listener.IsAsyncCallback()) {
            /* AsyncCallback(BusinessError error, T data) */
            napi_value arg[ASYNC_CALLBACK_PARAM_NUM] = {argv.first, argv.second};
            listener.Emit(type, ASYNC_CALLBACK_PARAM_NUM, arg);
        } else {
            /* Callback(T data)*/
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
    std::lock_guard<std::mutex> lock(mutex_);
    data_ = data;
}

void *EventManager::GetData()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return data_;
}
} // namespace OHOS::NetStack