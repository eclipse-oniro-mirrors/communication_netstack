/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef NETADDRESS_H
#define NETADDRESS_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include <string>

namespace OHOS {
namespace NetManagerStandard {
enum SocketFamily { IPV4 = 1, IPV6 = 2 };
struct NetAddress  {
    std::string ipAddress = "";
    int32_t family = 1; // IPv4 = 1; IPv6 = 2, default is IPv4
    int32_t port = 8080; // [0, 65535]
};
} // namespace NetManagerStandard
} // namespace OHOS
#endif // NETADDRESS_H