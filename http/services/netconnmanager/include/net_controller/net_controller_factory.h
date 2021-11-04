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
#ifndef NET_CONTROLLER_FACTORY_H
#define NET_CONTROLLER_FACTORY_H

#include <map>
#include <singleton.h>
#include "i_net_controller.h"

namespace OHOS {
namespace NetManagerStandard {
class NetControllerFactory {
    DECLARE_DELAYED_SINGLETON(NetControllerFactory)
public:
    sptr<INetController> MakeNetController(uint16_t netType);

private:
    sptr<INetController> GetNetControllerFromMap(uint16_t netType);
    std::map<uint16_t, sptr<INetController>> netControllers;
};
} // namespace NetManagerStandard
} // namespace OHOS
#endif // NET_CONTROLLER_FACTORY_H