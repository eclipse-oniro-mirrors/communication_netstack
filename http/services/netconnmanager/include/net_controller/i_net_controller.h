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
#ifndef I_NET_CONTROLLER_H
#define I_NET_CONTROLLER_H

#include "net_provider_info.h"

namespace OHOS {
namespace NetManagerStandard {
class INetController : public virtual RefBase {
public:
    virtual ~INetController() = default;
    virtual int32_t RequestNetwork(const std::string &ident, NetCapabilities netCapabilitiy) = 0;
    virtual int32_t ReleaseNetwork(const std::string &ident, NetCapabilities netCapabilitiy) = 0;
};
} // namespace NetManagerStandard
} // namespace OHOS
#endif // I_NET_CONTROLLER_H