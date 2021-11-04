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

#ifndef TCP_SEND_OPTIONS_H
#define TCP_SEND_OPTIONS_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include <string>

namespace OHOS {
namespace NetManagerStandard {
class TCPSendOptions {
public:
    TCPSendOptions() {}
    ~TCPSendOptions() {}

    std::string GetData()
    {
        return data_;
    }

    void SetData(std::string data)
    {
        this->data_ = data;
    }

    std::string GetEncoding()
    {
        return encoding_;
    }

    void SetEncoding(std::string encoding)
    {
        this->encoding_ = encoding;
    }
private:
    std::string data_ = "";
    std::string encoding_ = "";
};
} // namespace NetManagerStandard
} // namespace OHOS
#endif // TCP_SEND_OPTIONS_H