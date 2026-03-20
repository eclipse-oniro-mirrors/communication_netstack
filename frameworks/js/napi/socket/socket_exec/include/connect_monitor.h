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

#ifndef COMMUNICATIONNETSTACK_CONNECT_MONITOR_H
#define COMMUNICATIONNETSTACK_CONNECT_MONITOR_H

#include <atomic>
#include <chrono>
#include <map>
#include <mutex>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <thread>
#include <unistd.h>

#include "event_manager.h"
#include "napi/native_api.h"
#include "refbase.h"

namespace OHOS::NetStack::Socket {

class ConnectContext;

struct ConnectWatchData : public virtual RefBase {
    int sockfd = -1;
    napi_env env = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callbackRef = nullptr;
    napi_threadsafe_function tsfn = nullptr;
    ConnectContext* context = nullptr;
    std::shared_ptr<EventManager> manager;
    std::chrono::steady_clock::time_point deadline;
    std::string socketPath;
};

class ConnectMonitor {
public:
    static ConnectMonitor& GetInstance();

    bool Register(int fd, const sptr<ConnectWatchData>& data);
    void Unregister(int fd);

private:
    ConnectMonitor();
    ~ConnectMonitor();
    ConnectMonitor(const ConnectMonitor&) = delete;
    ConnectMonitor& operator=(const ConnectMonitor&) = delete;

    void EnsureThreadRunning();
    void MonitorLoop();
    int CalcNearestTimeoutMs();
    void CheckTimeouts();
    void HandleReady(int fd, uint32_t events);
    void CompleteConnect(int fd, int errCode);
    void WakeUp();

    int epollFd_ = -1;
    int eventFd_ = -1;
    std::mutex mutex_;
    std::map<int, sptr<ConnectWatchData>> pendings_;
    std::multimap<std::chrono::steady_clock::time_point, int> deadlines_;
    std::map<int, std::multimap<std::chrono::steady_clock::time_point, int>::iterator> deadlineIters_;
    std::thread thread_;
    std::atomic<bool> running_ { false };

    static constexpr int MAX_EVENTS = 64;
};

} // namespace OHOS::NetStack::Socket

#endif // COMMUNICATIONNETSTACK_CONNECT_MONITOR_H
