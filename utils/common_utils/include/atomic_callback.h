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

#ifndef COMMUNICATIONNETSTACK_ATOMIC_CALLBACK_H
#define COMMUNICATIONNETSTACK_ATOMIC_CALLBACK_H

#include <functional>
#include <memory>
#include <mutex>
#include <utility>

template <typename CallbackType>
class AtomicCallback {
public:
    AtomicCallback() = default;

    void Store(CallbackType callback)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!callback) {
            callback_ = nullptr;
            return;
        }
        callback_ = std::make_shared<CallbackType>(std::move(callback));
    }

    template <typename... Args>
    void Invoke(Args &&...args) const
    {
        std::shared_ptr<CallbackType> callback;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            callback = callback_;
        }
        if (callback == nullptr) {
            return;
        }
        (*callback)(std::forward<Args>(args)...);
    }

    bool Empty() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return callback_ == nullptr;
    }

private:
    mutable std::mutex mutex_;
    std::shared_ptr<CallbackType> callback_;
};

#endif // COMMUNICATIONNETSTACK_ATOMIC_CALLBACK_H
