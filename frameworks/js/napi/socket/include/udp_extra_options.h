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

#ifndef UDP_EXTRA_OPTIONS_H
#define UDP_EXTRA_OPTIONS_H

#include "extra_options_base.h"

namespace OHOS {
namespace NetManagerStandard {
class UDPExtraOptions : public ExtraOptionsBase {
public:
    UDPExtraOptions () {}
    ~UDPExtraOptions() {}

    bool GetBroadcast()
    {
        return broadcast_;
    }

    void SetBroadcast(bool broadcast)
    {
        this->broadcast_ = broadcast;
    }
private:
    bool broadcast_ = false;
};
} // namespace NetManagerStandard
} // namespace OHOS
#endif // UDP_EXTRA_OPTIONS_H