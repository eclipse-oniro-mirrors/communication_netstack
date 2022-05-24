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

#include "calculate_md5.h"
#include "openssl/md5.h"
#include "securec.h"

static constexpr const int HEX_LENGTH = 2;

namespace OHOS::NetStack {
std::string CalculateMD5(const std::string &source)
{
    unsigned char md5[MD5_DIGEST_LENGTH] = {0};
    (void)MD5(reinterpret_cast<const unsigned char *>(source.c_str()), source.size(), md5);
    std::string str;
    for (unsigned char i : md5) {
        char s[HEX_LENGTH + 1] = {0};
        int d = i;
        if (sprintf_s(s, HEX_LENGTH + 1, "%02x", d) < 0) {
            return {};
        }
        str += s;
    }
    return str;
}
} // namespace OHOS::NetStack