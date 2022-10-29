/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef COMMUNICATION_NETSTACK_SOCKET_ERROR_H
#define COMMUNICATION_NETSTACK_SOCKET_ERROR_H

#include <string>
#include <map>

namespace OHOS {
namespace NetStack {
enum TlsSocketError {
    TLSSOCKET_SUCCESS = 0,
    TLSSOCKET_ERROR_ERRNO_BASE = 2303100,
    TLSSOCKET_ERROR_SSL_BASE = 2303500,
    TLSSOCKET_ERROR_SSL_NULL = 2303501,
    TLSSOCKET_ERROR_PARAM_INVALID = 2300401
};

std::string MakeErrnoString();
std::string MakeSSLErrorString(int error);
} // namespace NetStack
} // namespace OHOS
#endif // COMMUNICATION_NETSTACK_SOCKET_ERROR_H
