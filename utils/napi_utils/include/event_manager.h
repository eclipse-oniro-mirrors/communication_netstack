/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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
#include <condition_variable>
#include <iosfwd>
#include <list>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <unordered_set>
#include <utility>

#include "event_listener.h"
#include "napi/native_api.h"
#include "uv.h"

namespace OHOS::NetStack {
static constexpr const uint32_t EVENT_MANAGER_MAGIC_NUMBER = 0x86161616;
struct EventManagerMagic {
    uint32_t magicNumber_ = EVENT_MANAGER_MAGIC_NUMBER;
    ~EventManagerMagic()
    {
        magicNumber_ = ~magicNumber_;
    }
};

namespace Websocket {
class UserData;
}

namespace Socks5 {
    class Socks5Instance;
}

class EventManager : public std::enable_shared_from_this<EventManager> {
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

    void EmitByUvWithoutCheck(const std::string &type, void *data, void(Handler)(uv_work_t *, int status));

    void EmitByUvWithoutCheckShared(const std::string &type, void *data, void(Handler)(uv_work_t *, int status));

    bool HasEventListener(const std::string &type);

    void DeleteListener(const std::string &type);

    static void SetInvalid(EventManager *manager);

    static void SetInvalidWithoutDelete(EventManager *manager);

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

    void NotifyRcvThdExit();

    void WaitForRcvThdExit();

    void SetReuseAddr(bool reuse);

    void SetWebSocketUserData(const std::shared_ptr<Websocket::UserData> &userData);

    std::shared_ptr<Websocket::UserData> GetWebSocketUserData();

    bool GetReuseAddr();

    std::shared_ptr<Socks5::Socks5Instance> GetProxyData();

    void SetProxyData(std::shared_ptr<Socks5::Socks5Instance> data);

private:
    std::recursive_mutex mutexForListenersAndEmitByUv_;
    std::recursive_mutex mutexForEmitAndEmitByUv_;
    std::mutex dataMutex_;
    std::mutex dataQueueMutex_;
    std::list<EventListener> listeners_;
    void *data_;
    std::queue<void *> dataQueue_;
    static EventManagerMagic magic_;
    static std::mutex mutexForManager_;
    static std::unordered_set<EventManager *> validManager_;
    napi_ref eventRef_;
    std::atomic_bool isDestroy_;
    std::string webSocketTextData_;
    std::string webSocketBinaryData_;
    std::mutex sockRcvThdMtx_;
    std::condition_variable sockRcvThdCon_;
    bool sockRcvExit_ = false;
    std::atomic_bool isReuseAddr_ = false;
    std::shared_ptr<Websocket::UserData> webSocketUserData_;
    std::shared_ptr<Socks5::Socks5Instance> proxyData_;

public:
    struct {
        uint32_t magicNumber = EVENT_MANAGER_MAGIC_NUMBER;
    } innerMagic_;
};

struct UvWorkWrapper {
    UvWorkWrapper() = delete;

    UvWorkWrapper(void *theData, napi_env theEnv, std::string eventType, EventManager *eventManager);

    void *data = nullptr;
    napi_env env = nullptr;
    std::string type;
    EventManager *manager = nullptr;
};

class EventManagerForHttp {
private:
    [[maybe_unused]] std::mutex mutexForListenersAndEmitByUv_;
    [[maybe_unused]] std::mutex mutexForEmitAndEmitByUv_;
    [[maybe_unused]] std::mutex dataMutex_;
    [[maybe_unused]] std::mutex dataQueueMutex_;
    [[maybe_unused]] std::list<EventListener> listeners_;
    [[maybe_unused]] void *data_ = nullptr;
    [[maybe_unused]] std::queue<void *> dataQueue_;
    [[maybe_unused]] static EventManagerMagic magic_;
    [[maybe_unused]] static std::mutex mutexForManager_;
    [[maybe_unused]] static std::unordered_set<EventManager *> validManager_;
    [[maybe_unused]] napi_ref eventRef_ = nullptr;
    [[maybe_unused]] std::atomic_bool isDestroy_;
    [[maybe_unused]] std::string webSocketTextData_;
    [[maybe_unused]] std::string webSocketBinaryData_;
    [[maybe_unused]] std::mutex sockRcvThdMtx_;
    [[maybe_unused]] std::condition_variable sockRcvThdCon_;
    [[maybe_unused]] bool sockRcvExit_ = false;
    [[maybe_unused]] std::atomic_bool isReuseAddr_ = false;
    [[maybe_unused]] std::shared_ptr<Websocket::UserData> webSocketUserData_;

public:
    [[maybe_unused]] struct {
        uint32_t magicNumber = EVENT_MANAGER_MAGIC_NUMBER;
    } innerMagic_;
};

struct EventManagerWrapper {
    EventManagerForHttp eventManager;
    std::shared_ptr<EventManager> sharedManager;
};

struct UvWorkWrapperShared {
    UvWorkWrapperShared() = delete;

    UvWorkWrapperShared(void *theData, napi_env theEnv, std::string eventType,
                        const std::shared_ptr<EventManager> &eventManager);

    void *data = nullptr;
    napi_env env = nullptr;
    std::string type;
    std::shared_ptr<EventManager> manager;
};
} // namespace OHOS::NetStack
#endif /* COMMUNICATIONNETSTACK_EVENT_MANAGER_H */
