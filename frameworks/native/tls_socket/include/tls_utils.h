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

#ifndef COMMUNICATION_NETSTACK_TLS_UTILS_H
#define COMMUNICATION_NETSTACK_TLS_UTILS_H

#include <string>
#include <unistd.h>

namespace OHOS {
namespace NetStack {
namespace TlsSocket {
const int32_t UID_TRANSFORM_DIVISOR = 200000;
const std::string BASE_PATH = "/data/certificates/user_cacerts/";
const std::string USER_CERT_PATH = BASE_PATH + std::to_string(getuid() / UID_TRANSFORM_DIVISOR);
const std::string ROOT_CERT_PATH = "/data/certificates/user_cacerts/0";
const std::string SYSTEM_REPLACE_CA_PATH = "/etc/security/certificates";
const std::string SYSTEM_REPLACE_CA_FILE = "/etc/ssl/certs/cacert.pem";

bool CheckFilePath(const std::string &fileName, std::string &realPath);
} // namespace TlsSocket
} // namespace NetStack
} // namespace OHOS
#endif // COMMUNICATION_NETSTACK_TLS_UTILS_H