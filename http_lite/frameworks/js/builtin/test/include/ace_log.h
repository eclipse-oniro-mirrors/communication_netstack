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

#ifndef TEST_HEADERS_ACE_LOG_H
#define TEST_HEADERS_ACE_LOG_H

#include <cstring>

#define __LITEOS__

#define HILOG_ERROR(mod, ...) \
    do {                      \
        printf(__VA_ARGS__);  \
        fflush(stdout);       \
        puts("");             \
        fflush(stdout);       \
    } while (0)

#define HILOG_INFO(mod, ...) \
    do {                     \
        printf(__VA_ARGS__); \
        fflush(stdout);      \
        puts("");            \
        fflush(stdout);      \
    } while (0)

typedef enum { HILOG_MODULE_ACE = 1 } HiLogModuleType;

#define HILOG_WARN(mod, format, ...)                                         \
    do {                                                                     \
        if (strcmp(format, "todo call linux putmsg interface here!") == 0) { \
            OHOS::ACELite::TestPutMessage(const_cast<void *>(msgPtr));       \
            return MSGQ_OK;                                                  \
        }                                                                    \
    } while (0)

static void *msgPtr;

namespace OHOS {
namespace ACELite {
void TestPutMessage(void *data);
} // namespace ACELite
} // namespace OHOS

#endif /* TEST_HEADERS_ACE_LOG_H */
