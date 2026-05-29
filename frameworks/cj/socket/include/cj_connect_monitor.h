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

#ifndef CJ_CONNECT_MONITOR_H
#define CJ_CONNECT_MONITOR_H

#include <atomic>
#include <chrono>
#include <functional>
#include <map>
#include <mutex>
#include <thread>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "ffi_structs.h"

namespace OHOS::NetStack::Socket {

using CjConnectCallback = std::function<void(int32_t errCode)>;

struct CjConnectWatchData {
    int sockfd = -1;
    uint32_t timeout = 0;
    CjConnectCallback callback;
    std::chrono::steady_clock::time_point deadline;
};

class CjConnectMonitor {
public:
    static CjConnectMonitor& GetInstance();

    bool Register(int fd, uint32_t timeout, CjConnectCallback callback);
    void Unregister(int fd);

private:
    CjConnectMonitor();
    ~CjConnectMonitor();
    CjConnectMonitor(const CjConnectMonitor&) = delete;
    CjConnectMonitor& operator=(const CjConnectMonitor&) = delete;

    void EnsureThreadRunning();
    void MonitorLoop();
    int CalcNearestTimeoutMs();
    void CheckTimeouts();
    void HandleReady(int fd, uint32_t events);
    void CompleteConnect(int fd, int errCode);
    void WakeUp();

    int epollFd_ = -1;
    int eventFd_ = -1;
    std::mutex lifecycleMutex_;
    std::mutex mutex_;
    std::map<int, CjConnectWatchData> pendings_;
    std::multimap<std::chrono::steady_clock::time_point, int> deadlines_;
    std::map<int, std::multimap<std::chrono::steady_clock::time_point, int>::iterator> deadlineIters_;
    std::thread thread_;
    std::atomic<bool> running_ { false };

    static constexpr int MAX_EVENTS = 64;
    static constexpr int DEFAULT_CONNECT_TIMEOUT = 60000;
};

}
#endif
