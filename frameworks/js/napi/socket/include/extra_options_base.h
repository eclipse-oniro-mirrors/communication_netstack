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

#ifndef EXTRA_OPTIONS_BASE_H
#define EXTRA_OPTIONS_BASE_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_util.h"

namespace OHOS {
namespace NetManagerStandard {
class ExtraOptionsBase {
public:
    ExtraOptionsBase() {}
    ~ExtraOptionsBase() {}

    int32_t GetReceiveBufferSize()
    {
        return receiveBufferSize_;
    }

    void SetReceiveBufferSize(int32_t receiveBufferSize)
    {
        this->receiveBufferSize_ = receiveBufferSize;
    }

    int32_t GetSendBufferSize()
    {
        return sendBufferSize_;
    }

    void SetSendBufferSize(int32_t sendBufferSize)
    {
        this->sendBufferSize_ = sendBufferSize;
    }

    int32_t GetReuseAddress()
    {
        return reuseAddress_;
    }

    void SetReuseAddress(int32_t reuseAddress)
    {
        this->reuseAddress_ = reuseAddress;
    }

    int32_t GetSocketTimeout()
    {
        return socketTimeout_;
    }

    void SetSocketTimeout(int32_t socketTimeout)
    {
        this->socketTimeout_ = socketTimeout;
    }
private:
    int32_t receiveBufferSize_ = 0;
    int32_t sendBufferSize_ = 0;
    int32_t reuseAddress_ = 0;
    int32_t socketTimeout_ = 0;
};
} // namespace NetManagerStandard
} // namespace OHOS
#endif // EXTRA_OPTIONS_BASE_H