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

#ifndef NET_CONN_TYPES_H
#define NET_CONN_TYPES_H

namespace OHOS {
namespace NetManagerStandard {
enum ResultCode {
    ERR_NONE = 0,
    ERR_SERVICE_REQUEST_SUCCESS = (-1),
    ERR_SERVICE_REQUEST_CONNECT_FAIL = (-2),
    ERR_SERVICE_UPDATE_NET_LINK_INFO_FAIL = (-3),
    ERR_SERVICE_CONNECTING = (-4),
    ERR_SERVICE_CONNECTED = (-5),
    ERR_SERVICE_DISCONNECTED_FAIL = (-6),
    ERR_SERVICE_DISCONNECTING = (-7),
    ERR_SERVICE_DISCONNECTED_SUCCESS = (-8),
    ERR_SERVICE_NULL_PTR = (-9),
    ERR_NO_PROVIDER = (-10),
    ERR_NO_NETWORK = (-11),
    ERR_INVALID_PARAMS = (-12),
    ERR_INVALID_NETORK_TYPE = (-13)
};
} // namespace NetManagerStandard
} // namespace OHOS
#endif // NET_CONN_TYPES_H
