/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "tls_utils_test.h"

namespace OHOS {
namespace NetStack {
namespace TlsSocket {
std::string TlsUtilsTest::ChangeToFile(const std::string_view fileName)
{
    std::ifstream file;
    file.open(fileName);
    std::stringstream ss;
    ss << file.rdbuf();
    std::string infos = ss.str();
    file.close();
    return infos;
}

std::string TlsUtilsTest::GetIp(std::string ip)
{
    return ip.substr(0, ip.length() - 1);
}

bool TlsUtilsTest::CheckCaFileExistence(const char *function)
{
    if (access(CA_DER.data(), 0)) {
        std::cout << "CA file does not exist! (" << function << ")";
        return false;
    }
    return true;
}

bool TlsUtilsTest::CheckCaPathChainExistence(const char *function)
{
    if (access(CA_PATH_CHAIN.data(), 0)) {
        std::cout << "CA file does not exist! (" << function << ")";
        return false;
    }
    return true;
}
} // namespace TlsSocket
} // namespace NetStack
} // namespace OHOS
