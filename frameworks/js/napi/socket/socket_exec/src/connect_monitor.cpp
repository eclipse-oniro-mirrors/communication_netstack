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

#include "connect_monitor.h"

#include <cerrno>
#include <limits>
#include <sys/socket.h>
#include <vector>

#include "netstack_log.h"

namespace OHOS::NetStack::Socket {

ConnectMonitor& ConnectMonitor::GetInstance()
{
    static ConnectMonitor instance;
    return instance;
}

ConnectMonitor::ConnectMonitor()
{
    epollFd_ = epoll_create1(EPOLL_CLOEXEC);
    eventFd_ = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    epoll_event ev {};
    ev.events = EPOLLIN;
    ev.data.fd = eventFd_;
    epoll_ctl(epollFd_, EPOLL_CTL_ADD, eventFd_, &ev);
}

ConnectMonitor::~ConnectMonitor()
{
    std::lock_guard<std::mutex> lock(lifecycleMutex_);
    running_.store(false);
    WakeUp();
    if (thread_.joinable()) {
        thread_.join();
    }
    if (eventFd_ >= 0) {
        close(eventFd_);
    }
    if (epollFd_ >= 0) {
        close(epollFd_);
    }
}

void ConnectMonitor::EnsureThreadRunning()
{
    std::lock_guard<std::mutex> lock(lifecycleMutex_);
    if (running_.load()) {
        return;
    }
    if (thread_.joinable()) {
        thread_.join();
    }
    if (!running_.load()) {
        running_.store(true);
        NETSTACK_LOGI("connect monitor thread starting");
        thread_ = std::thread(&ConnectMonitor::MonitorLoop, this);
        pthread_setname_np(thread_.native_handle(), "ConnectMonitor");
    }
}

void ConnectMonitor::WakeUp()
{
    uint64_t val = 1;
    write(eventFd_, &val, sizeof(val));
}

bool ConnectMonitor::Register(int fd, const sptr<ConnectWatchData>& data)
{
    if (data == nullptr) {
        return false;
    }
    NETSTACK_LOGI("connect monitor register :%{public}d", fd);

    epoll_event ev {};
    ev.events = EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLONESHOT;
    ev.data.fd = fd;
    if (epoll_ctl(epollFd_, EPOLL_CTL_ADD, fd, &ev) < 0) {
        NETSTACK_LOGE("connect monitor epoll_ctl add failed, %{public}d, errno:%{public}d", fd, errno);
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto deadlineIt = deadlineIters_.find(fd);
        if (deadlineIt != deadlineIters_.end()) {
            deadlines_.erase(deadlineIt->second);
            deadlineIters_.erase(deadlineIt);
        }
        pendings_[fd] = data;
        deadlineIters_[fd] = deadlines_.emplace(data->deadline, fd);
    }
    EnsureThreadRunning();
    WakeUp();
    return true;
}

void ConnectMonitor::Unregister(int fd)
{
    NETSTACK_LOGI("connect monitor unregister :%{public}d", fd);
    sptr<ConnectWatchData> data;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = pendings_.find(fd);
        if (it == pendings_.end()) {
            return;
        }
        data = std::move(it->second);
        pendings_.erase(it);
        auto deadlineIt = deadlineIters_.find(fd);
        if (deadlineIt != deadlineIters_.end()) {
            deadlines_.erase(deadlineIt->second);
            deadlineIters_.erase(deadlineIt);
        }
    }
    epoll_ctl(epollFd_, EPOLL_CTL_DEL, fd, nullptr);
    WakeUp();
    if (data && data->tsfn) {
        napi_release_threadsafe_function(data->tsfn, napi_tsfn_abort);
    }
}

void ConnectMonitor::MonitorLoop()
{
    while (running_.load()) {
        int timeoutMs = CalcNearestTimeoutMs();
        epoll_event events[MAX_EVENTS];
        int n = epoll_wait(epollFd_, events, MAX_EVENTS, timeoutMs);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            NETSTACK_LOGE("connect monitor epoll_wait error: %{public}d", errno);
            break;
        }
        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == eventFd_) {
                uint64_t val;
                read(eventFd_, &val, sizeof(val));
                continue;
            }
            HandleReady(events[i].data.fd, events[i].events);
        }
        CheckTimeouts();

        std::lock_guard<std::mutex> lock(mutex_);
        if (pendings_.empty()) {
            NETSTACK_LOGI("connect monitor thread exiting, no pending connections");
            running_.store(false);
            break;
        }
    }
    NETSTACK_LOGI("connect monitor thread stopped");
    running_.store(false);
}

int ConnectMonitor::CalcNearestTimeoutMs()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (deadlines_.empty()) {
        return -1;
    }
    auto now = std::chrono::steady_clock::now();
    auto nearestDeadline = deadlines_.begin()->first;
    if (nearestDeadline <= now) {
        return 0;
    }
    auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(nearestDeadline - now).count();
    if (remaining > std::numeric_limits<int>::max()) {
        return std::numeric_limits<int>::max();
    }
    return static_cast<int>(remaining);
}

void ConnectMonitor::CheckTimeouts()
{
    auto now = std::chrono::steady_clock::now();
    std::vector<int> timedOut;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        while (!deadlines_.empty() && deadlines_.begin()->first <= now) {
            int fd = deadlines_.begin()->second;
            deadlines_.erase(deadlines_.begin());
            deadlineIters_.erase(fd);
            if (pendings_.find(fd) != pendings_.end()) {
                NETSTACK_LOGI("connect monitor timeout :%{public}d", fd);
                timedOut.push_back(fd);
            }
        }
    }
    for (int fd : timedOut) {
        CompleteConnect(fd, EINPROGRESS);
    }
}

void ConnectMonitor::HandleReady(int fd, uint32_t events)
{
    int err = 0;
    socklen_t len = sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
        err = errno;
    }
    // 兼容性处理：统一返回 EINPROGRESS
    CompleteConnect(fd, err == 0 ? 0 : EINPROGRESS);
}

void ConnectMonitor::CompleteConnect(int fd, int errCode)
{
    NETSTACK_LOGD("connect monitor complete :%{public}d, errCode:%{public}d", fd, errCode);
    sptr<ConnectWatchData> data;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto deadlineIt = deadlineIters_.find(fd);
        if (deadlineIt != deadlineIters_.end()) {
            deadlines_.erase(deadlineIt->second);
            deadlineIters_.erase(deadlineIt);
        }
        auto it = pendings_.find(fd);
        if (it == pendings_.end()) {
            return;
        }
        data = std::move(it->second);
        pendings_.erase(it);
    }
    epoll_ctl(epollFd_, EPOLL_CTL_DEL, fd, nullptr);

    if (!data || !data->tsfn) {
        return;
    }

    int* errData = new int(errCode);
    if (napi_call_threadsafe_function(data->tsfn, errData, napi_tsfn_blocking) != napi_ok) {
        delete errData;
    }
    napi_release_threadsafe_function(data->tsfn, napi_tsfn_release);
}

} // namespace OHOS::NetStack::Socket
