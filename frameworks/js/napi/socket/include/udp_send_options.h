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

#ifndef UDP_SEND_OPTIONS_H
#define UDP_SEND_OPTIONS_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_util.h"

namespace OHOS {
namespace NetManagerStandard {
class UDPSendOptions {
public:
    UDPSendOptions() {}
    ~UDPSendOptions() {}

    std::string GetData()
    {
        return data_;
    }

    void SetData(const std::string& data)
    {
        this->data_ = data;
    }
private:
    std::string data_ = "";
};
} // namespace NetManagerStandard
} // namespace OHOS
#endif // UDP_SEND_OPTIONS_H