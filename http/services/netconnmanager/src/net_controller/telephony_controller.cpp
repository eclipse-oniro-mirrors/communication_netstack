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
#include "telephony_controller.h"
#include "cellular_data_manager.h"
#include "netmgr_log_wrapper.h"

namespace OHOS {
namespace NetManagerStandard {
TelephonyController::TelephonyController() {};

int32_t TelephonyController::RequestNetwork(const std::string &ident, NetCapabilities netCapabilitiy)
{
    NETMGR_LOGD("Request telephony network.");
    return Telephony::CellularDataManager::GetInstance().RequestNet(ident, static_cast<uint32_t>(netCapabilitiy));
}

int32_t TelephonyController::ReleaseNetwork(const std::string &ident, NetCapabilities netCapabilitiy)
{
    NETMGR_LOGD("Release telephony network.");
    return Telephony::CellularDataManager::GetInstance().ReleaseNet(ident, static_cast<uint32_t>(netCapabilitiy));
}
} // namespace NetManagerStandard
} // namespace OHOS
