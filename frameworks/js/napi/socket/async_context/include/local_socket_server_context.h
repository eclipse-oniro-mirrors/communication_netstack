/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef LOCAL_SOCKET_SERVER_CONTEXT_H
#define LOCAL_SOCKET_SERVER_CONTEXT_H

#include <cstddef>
#include <unistd.h>
#include <map>

#include "base_context.h"
#include "event_list.h"
#include "local_socket_context.h"
#include "napi/native_api.h"
#include "nocopyable.h"
#include "socket_state_base.h"

namespace OHOS::NetStack::Socket {
struct LocalSocketServerManager : public SocketBaseManager {
    int clientId_ = 0;
    int threadCounts_ = 0;
    LocalExtraOptions extraOptions_;
    bool alreadySetExtraOptions_ = false;
    bool isServerDestruct_ = false;
    std::mutex finishMutex_;
    std::condition_variable finishCond_;
    std::mutex clientMutex_;
    std::condition_variable cond_;
    std::map<int, int> acceptFds_;                      // id & fd
    std::map<int, EventManager *> clientEventManagers_; // id & EventManager*
    explicit LocalSocketServerManager(int sockfd) : SocketBaseManager(sockfd) {}

    int AddAccept(int accpetFd)
    {
        std::lock_guard<std::mutex> lock(clientMutex_);
        acceptFds_.emplace(++clientId_, accpetFd);
        return clientId_;
    }
    void RemoveAllAccept()
    {
        std::lock_guard<std::mutex> lock(clientMutex_);
        for (const auto &[id, fd] : acceptFds_) {
            if (fd > 0) {
                close(fd);
            }
        }
        acceptFds_.clear();
    }
    void RemoveAccept(int clientId)
    {
        std::lock_guard<std::mutex> lock(clientMutex_);
        if (auto ite = acceptFds_.find(clientId); ite != acceptFds_.end()) {
            close(ite->second);
            acceptFds_.erase(ite);
        }
    }
    int GetAcceptFd(int clientId)
    {
        std::lock_guard<std::mutex> lock(clientMutex_);
        if (auto ite = acceptFds_.find(clientId); ite != acceptFds_.end()) {
            return ite->second;
        }
        return 0;
    }
    size_t GetClientCounts()
    {
        std::lock_guard<std::mutex> lock(clientMutex_);
        return acceptFds_.size();
    }
    EventManager *WaitForManager(int clientId)
    {
        EventManager *manager = nullptr;
        std::unique_lock<std::mutex> lock(clientMutex_);
        cond_.wait(lock, [&manager, &clientId, this]() {
            if (auto iter = clientEventManagers_.find(clientId); iter != clientEventManagers_.end()) {
                manager = iter->second;
                if (manager->HasEventListener(EVENT_MESSAGE)) {
                    return true;
                }
            }
            return false;
        });
        return manager;
    }
    void NotifyRegisterEvent()
    {
        std::lock_guard<std::mutex> lock(clientMutex_);
        cond_.notify_one();
    }
    void AddEventManager(int clientId, EventManager *manager)
    {
        std::lock_guard<std::mutex> lock(clientMutex_);
        clientEventManagers_.insert(std::make_pair(clientId, manager));
        cond_.notify_one();
    }
    void RemoveEventManager(int clientId)
    {
        std::lock_guard<std::mutex> lock(clientMutex_);
        if (auto ite = clientEventManagers_.find(clientId); ite != clientEventManagers_.end()) {
            EventManager::SetInvalid(ite->second);
            clientEventManagers_.erase(ite);
        }
    }
    void RemoveAllEventManager()
    {
        std::lock_guard<std::mutex> lock(clientMutex_);
        for (const auto &[id, manager] : clientEventManagers_) {
            EventManager::SetInvalid(manager);
        }
        clientEventManagers_.clear();
    }
    void IncreaseThreadCounts()
    {
        std::lock_guard<std::mutex> lock(finishMutex_);
        ++threadCounts_;
    }
    void NotifyLoopFinished()
    {
        std::lock_guard<std::mutex> lock(finishMutex_);
        if (--threadCounts_ == 0) {
            finishCond_.notify_one();
        }
    }
    void WaitForEndingLoop()
    {
        std::unique_lock<std::mutex> lock(finishMutex_);
        finishCond_.wait(lock, [this]() {
            return threadCounts_ == 0;
        });
    }
};

class LocalSocketServerBaseContext : public LocalSocketBaseContext {
public:
    LocalSocketServerBaseContext(napi_env env, EventManager *manager) : LocalSocketBaseContext(env, manager) {}
    [[nodiscard]] int GetSocketFd() const override;
    void SetSocketFd(int sock) override;
};

class LocalSocketServerListenContext final : public LocalSocketServerBaseContext {
public:
    LocalSocketServerListenContext(napi_env env, EventManager *manager) : LocalSocketServerBaseContext(env, manager) {}
    void ParseParams(napi_value *params, size_t paramsCount) override;
    const std::string &GetSocketPath() const;

private:
    std::string socketPath_;
};

class LocalSocketServerGetStateContext final : public LocalSocketServerBaseContext {
public:
    LocalSocketServerGetStateContext(napi_env env, EventManager *manager) : LocalSocketServerBaseContext(env, manager)
    {
    }
    void ParseParams(napi_value *params, size_t paramsCount) override;
    SocketStateBase &GetStateRef();

private:
    SocketStateBase state_;
};

class LocalSocketServerSetExtraOptionsContext final : public LocalSocketServerBaseContext {
public:
    LocalSocketServerSetExtraOptionsContext(napi_env env, EventManager *manager)
        : LocalSocketServerBaseContext(env, manager)
    {
    }
    void ParseParams(napi_value *params, size_t paramsCount) override;
    LocalExtraOptions &GetOptionsRef();

private:
    LocalExtraOptions options_;
};

class LocalSocketServerGetExtraOptionsContext final : public LocalSocketServerBaseContext {
public:
    LocalSocketServerGetExtraOptionsContext(napi_env env, EventManager *manager)
        : LocalSocketServerBaseContext(env, manager)
    {
    }
    void ParseParams(napi_value *params, size_t paramsCount) override;
    LocalExtraOptions &GetOptionsRef();

private:
    LocalExtraOptions options_;
};

class LocalSocketServerSendContext final : public LocalSocketServerBaseContext {
public:
    LocalSocketServerSendContext(napi_env env, EventManager *manager) : LocalSocketServerBaseContext(env, manager) {}
    void ParseParams(napi_value *params, size_t paramsCount) override;
    int GetAcceptFd();
    LocalSocketOptions &GetOptionsRef();
    int GetClientId() const;
    void SetClientId(int clientId);

private:
    bool GetData(napi_value sendOptions);
    LocalSocketOptions options_;
    int clientId_ = 0;
};

class LocalSocketServerCloseContext final : public LocalSocketServerBaseContext {
public:
    LocalSocketServerCloseContext(napi_env env, EventManager *manager) : LocalSocketServerBaseContext(env, manager) {}
    void ParseParams(napi_value *params, size_t paramsCount) override;
    int GetClientId() const;
    void SetClientId(int clientId);

private:
    int clientId_ = 0;
};
} // namespace OHOS::NetStack::Socket
#endif