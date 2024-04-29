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

#ifndef COMMUNICATIONNETSTACK_EVENT_MANAGER_H
#define COMMUNICATIONNETSTACK_EVENT_MANAGER_H

#include <atomic>
#include <iosfwd>
#include <list>
#include <mutex>
#include <unordered_set>
#include <string>
#include <utility>
#include <queue>

#include "event_listener.h"
#include "napi/native_api.h"
#include "uv.h"

namespace OHOS::NetStack {
class EventManager {
public:
    EventManager();

    ~EventManager();

    EventManager(const EventManager &) = delete;
    EventManager &operator=(const EventManager &manager) = delete;

    void AddListener(napi_env env, const std::string &type, napi_value callback, bool once, bool asyncCallback);

    void DeleteListener(const std::string &type, napi_value callback);

    void Emit(const std::string &type, const std::pair<napi_value, napi_value> &argv);

    void SetData(void *data);

    [[nodiscard]] void *GetData();

    void EmitByUv(const std::string &type, void *data, void(Handler)(uv_work_t *, int status));

    bool HasEventListener(const std::string &type);

    void DeleteListener(const std::string &type);

    static void SetInvalid(EventManager *manager);

    static bool IsManagerValid(EventManager *manager);

    static void SetValid(EventManager *manager);

    void SetQueueData(void *data);

    void *GetQueueData();

    void CreateEventReference(napi_env env, napi_value value);

    void DeleteEventReference(napi_env env);

    void SetEventDestroy(bool flag);

    bool IsEventDestroy();

    const std::string &GetWebSocketTextData();

    void AppendWebSocketTextData(void *data, size_t length);

    const std::string &GetWebSocketBinaryData();

    void AppendWebSocketBinaryData(void *data, size_t length);

    void ClearWebSocketTextData();

    void ClearWebSocketBinaryData();

private:
    std::mutex mutexForListenersAndEmitByUv_;
    std::mutex mutexForEmitAndEmitByUv_;
    std::mutex dataMutex_;
    std::mutex dataQueueMutex_;
    std::list<EventListener> listeners_;
    void *data_;
    std::queue<void *> dataQueue_;
    static std::mutex mutexForManager_;
    static std::unordered_set<EventManager *> validManager_;
    napi_ref eventRef_;
    std::atomic_bool isDestroy_;
    std::string webSocketTextData_;
    std::string webSocketBinaryData_;
};

struct UvWorkWrapper {
    UvWorkWrapper() = delete;

    explicit UvWorkWrapper(void *theData, napi_env theEnv, std::string eventType, EventManager *eventManager);

    void *data;
    napi_env env;
    std::string type;
    EventManager *manager;
};
} // namespace OHOS::NetStack
#endif /* COMMUNICATIONNETSTACK_EVENT_MANAGER_H */
