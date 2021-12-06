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

#ifndef TCP_EXTRA_OPTIONS_H
#define TCP_EXTRA_OPTIONS_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "extra_options_base.h"

namespace OHOS {
namespace NetManagerStandard {
class TCPExtraOptions : public ExtraOptionsBase {
public:
    TCPExtraOptions() {}
    ~TCPExtraOptions() {}

    class SocketLinger {
    public:
        bool on_ = true;
        int32_t linger_ = 0;
    } socketLinger_;

    bool GetKeepAlive()
    {
        return keepAlive_;
    }

    void SetKeepAlive(bool keepAlive)
    {
        this->keepAlive_ = keepAlive;
    }

    bool GetOOBInline()
    {
        return OOBInline_;
    }

    void SetOOBInline(bool OOBInline)
    {
        this->OOBInline_ = OOBInline;
    }

    bool GetTCPNoDelay()
    {
        return TCPNoDelay_;
    }

    void SetTCPNoDelay(bool TCPNoDelay)
    {
        this->TCPNoDelay_ = TCPNoDelay;
    }

    bool GetSocketLingerOn()
    {
        return socketLinger_.on_;
    }

    void SetSocketLingerOn(bool on)
    {
        this->socketLinger_.on_ = on;
    }

    int32_t GetSocketLingerLinger()
    {
        return socketLinger_.linger_;
    }

    void SetSocketLingerLinger(int32_t linger)
    {
        this->socketLinger_.linger_ = linger;
    }
private:
    bool keepAlive_ = false;
    bool OOBInline_ = false;
    bool TCPNoDelay_ = false;
};
} // namespace NetManagerStandard
} // namespace OHOS
#endif // TCP_EXTRA_OPTIONS_H