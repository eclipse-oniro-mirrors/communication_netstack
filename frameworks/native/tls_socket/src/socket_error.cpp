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

#include "socket_error.h"

#include <cstring>
#include <map>

#include <openssl/err.h>
#include <openssl/ssl.h>

namespace OHOS {
namespace NetStack {
static constexpr const size_t MAX_ERR_LEN = 1024;

std::string MakeErrnoString()
{
    return strerror(errno);
}

std::string MakeSSLErrorString(int error)
{
    static const std::map<int32_t, std::string> ERROR_MAP = {
        {TLSSOCKET_ERROR_SSL_NULL, "ssl is null"},
    };
    auto search = ERROR_MAP.find(error);
    if (search != ERROR_MAP.end()) {
        return search->second;
    }
    char err[MAX_ERR_LEN] = {0};
    ERR_error_string_n(error - TLSSOCKET_ERROR_SSL_BASE, err, sizeof(err));
    return err;
}
} // namespace NetStack
} // namespace OHOS
