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

#ifndef TELEPHONY_CONTROLLER_H
#define TELEPHONY_CONTROLLER_H

#include <singleton.h>
#include "i_net_controller.h"

namespace OHOS {
namespace NetManagerStandard {
class TelephonyController : public INetController {
public:
    TelephonyController();
    ~TelephonyController() = default;

    /**
     * @brief When a network request is initiated, the cellular data activation data interface will be called
     *
     * @param ident_ Unique identification of mobile phone card
     * @param netCapabilitiy Network capabilities registered by Cellular Data
     *
     * @return Return the return value of the cellular data interface call
     */
    int32_t RequestNetwork(const std::string &ident, NetCapabilities netCapabilitiy) override;

    /**
     * @brief When the network is disconnected, the cellular data deactivation interface will be called
     *
     * @param ident_ Unique identification of mobile phone card
     * @param netCapabilitiy Network capabilities registered by Cellular Data
     *
     * @return Return the return value of the cellular data interface call
     */
    int32_t ReleaseNetwork(const std::string &ident, NetCapabilities netCapabilitiy) override;
};
} // namespace NetManagerStandard
} // namespace OHOS
#endif // TELEPHONY_CONTROLLER_H
