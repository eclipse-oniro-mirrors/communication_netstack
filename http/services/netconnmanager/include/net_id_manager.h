/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef NET_ID_MANAGER_H
#define NET_ID_MANAGER_H

#include <mutex>
#include <map>
#include <atomic>
#include <singleton.h>

namespace OHOS {
namespace NetManagerStandard {
// Class used to reserve and release net IDs.
class NetIdManager {
    DECLARE_DELAYED_SINGLETON(NetIdManager)
public:
    int32_t ReserveNetId();
    void ReleaseNetId(int32_t netId);

public:
    static constexpr int32_t TUN_IF_RANGE = 0x0400;
    static constexpr int32_t MAX_NET_ID = 65535 - TUN_IF_RANGE;
    static constexpr int32_t MIN_NET_ID = 100;

private:
    std::atomic<int32_t> lastNetId_ = -1;
    std::atomic<int32_t> maxNetId_ = MAX_NET_ID;
    std::map<int32_t, bool> netIdInUse_;
    std::mutex mtx_;
};
} // namespace NetManagerStandard
} // namespace OHOS
#endif // NET_ID_MANAGER_H