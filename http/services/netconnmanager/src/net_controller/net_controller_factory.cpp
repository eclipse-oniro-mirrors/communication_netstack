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
#include "net_controller_factory.h"
#include "netmgr_log_wrapper.h"
#include "telephony_controller.h"
#include "net_specifier.h"

namespace OHOS {
namespace NetManagerStandard {
NetControllerFactory::NetControllerFactory() {}
NetControllerFactory::~NetControllerFactory() {}

sptr<INetController> NetControllerFactory::MakeNetController(uint16_t netType)
{
    NETMGR_LOGD("make controller netType[%{public}d]", netType);
    sptr<INetController> netController = GetNetControllerFromMap(netType);
    if (netController != nullptr) {
        return netController;
    }
    NETMGR_LOGD("factory need create netController");

    switch (netType) {
        case NET_TYPE_CELLULAR:
            NETMGR_LOGD("factory create TelephonyController");
            netController = (std::make_unique<TelephonyController>()).release();
            netControllers.insert(std::make_pair(NET_TYPE_CELLULAR, netController));
            break;
        default:
            break;
    }

    return netController;
}

sptr<INetController> NetControllerFactory::GetNetControllerFromMap(uint16_t netType)
{
    auto it = netControllers.find(netType);
    if (it != netControllers.end()) {
        return it->second;
    }
    NETMGR_LOGD("INetController* is not found, return null");
    return nullptr;
}
} // namespace NetManagerStandard
} // namespace OHOS