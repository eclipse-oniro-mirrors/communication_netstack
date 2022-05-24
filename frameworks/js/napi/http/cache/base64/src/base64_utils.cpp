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

#include <memory>

#include "glib.h"
#include "netstack_log.h"

#include "base64_utils.h"

namespace OHOS::NetStack::Base64 {
std::string Encode(const std::string &source)
{
    gchar *encodeData = g_base64_encode(reinterpret_cast<const guchar *>(source.c_str()), source.size());
    if (encodeData == nullptr) {
        NETSTACK_LOGE("base64 encode failed");
        return {};
    }
    gsize out_len = strlen(encodeData);
    std::string dest(encodeData, out_len);
    g_free(encodeData);
    return dest;
}

std::string Decode(const std::string &encoded)
{
    gsize out_len = 0;
    guchar *decodeData = g_base64_decode(encoded.c_str(), &out_len);
    if (decodeData == nullptr) {
        NETSTACK_LOGE("base64 decode failed");
        return {};
    }
    std::string dest(reinterpret_cast<char *>(decodeData), out_len);
    g_free(decodeData);
    return dest;
}
} // namespace OHOS::NetStack::Base64