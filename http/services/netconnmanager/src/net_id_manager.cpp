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

#include "net_id_manager.h"

namespace OHOS {
namespace NetManagerStandard {

NetIdManager::NetIdManager() {}

NetIdManager::~NetIdManager() {}

int32_t NetIdManager::ReserveNetId()
{
    std::lock_guard<std::mutex> lck(mtx_);
    for (int32_t i = MIN_NET_ID; i <= maxNetId_; ++i) {
        if (lastNetId_ < maxNetId_) {
            ++lastNetId_;
        } else {
            lastNetId_ = MIN_NET_ID;
        }
        if (netIdInUse_.find(lastNetId_) == netIdInUse_.end()) {
            netIdInUse_.insert(std::pair<int32_t, bool>(lastNetId_, true));
            break;
        }
    }

    return lastNetId_;
}

void NetIdManager::ReleaseNetId(int32_t netId)
{
    std::lock_guard<std::mutex> lck(mtx_);
    auto it = netIdInUse_.find(netId);
    if (it != netIdInUse_.end()) {
        netIdInUse_.erase(it);
    }
}
} // namespace NetManagerStandard
} // namespace OHOS