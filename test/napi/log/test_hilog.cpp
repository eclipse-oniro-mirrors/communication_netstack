/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include <string>

#include "netstack_log.h"

namespace OHOS::HiviewDFX {
static constexpr uint32_t MAX_BUFFER_SIZE = 4096;

static void StripFormatString(const std::string &prefix, std::string &str)
{
    for (auto pos = str.find(prefix, 0); pos != std::string::npos; pos = str.find(prefix, pos)) {
        str.erase(pos, prefix.size());
    }
}

#define PRINT_LOG(LEVEL)                        \
    do {                                        \
        std::string newFmt(fmt);                \
        StripFormatString("{public}", newFmt);  \
        StripFormatString("{private}", newFmt); \
                                                \
        va_list args;                           \
        va_start(args, fmt);                    \
        printf(#LEVEL " ");                     \
        fflush(stdout);                         \
        vfprintf(stdout, newFmt.c_str(), args); \
        fflush(stdout);                         \
        printf("\n");                           \
        fflush(stdout);                         \
        va_end(args);                           \
    } while (0)

int HiLog::Debug(const HiLogLabel &label, const char *fmt, ...)
{
    if (label.domain != NETSTACK_LOG_DOMAIN) {
        return 0;
    }
    PRINT_LOG(Debug);
    return 0;
}
int HiLog::Info(const HiLogLabel &label, const char *fmt, ...)
{
    if (label.domain != NETSTACK_LOG_DOMAIN) {
        return 0;
    }
    PRINT_LOG(Info);
    return 0;
}
int HiLog::Warn(const HiLogLabel &label, const char *fmt, ...)
{
    if (label.domain != NETSTACK_LOG_DOMAIN) {
        return 0;
    }
    PRINT_LOG(Warn);
    return 0;
}
int HiLog::Error(const HiLogLabel &label, const char *fmt, ...)
{
    if (label.domain != NETSTACK_LOG_DOMAIN) {
        return 0;
    }
    PRINT_LOG(Error);
    return 0;
}
int HiLog::Fatal(const HiLogLabel &label, const char *fmt, ...)
{
    if (label.domain != NETSTACK_LOG_DOMAIN) {
        return 0;
    }
    PRINT_LOG(Fatal);
    return 0;
}
} // namespace OHOS::HiviewDFX