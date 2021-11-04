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

#ifndef SOCKET_REMOTE_INFO_H
#define SOCKET_REMOTE_INFO_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_util.h"

namespace OHOS {
namespace NetManagerStandard {
class SocketRemoteInfo {
public:
    SocketRemoteInfo() {}
    ~SocketRemoteInfo() {}

    std::string GetAddress()
    {
        return address_;
    }

    void SetAddress(const std::string& address)
    {
        this->address_ = address;
    }

    std::string GetFamily()
    {
        return family_;
    }

    void SetFamily(const std::string& family)
    {
        this->family_ = family;
    }

    int32_t GetPort()
    {
        return port_;
    }

    void SetPort(int32_t port)
    {
        this->port_ = port;
    }

    int32_t GetSize()
    {
        return size_;
    }

    void SetSize(int32_t size)
    {
        this->size_ = size;
    }
private:
    std::string address_ = "";
    std::string family_ = "IPv4";
    int32_t port_ = 0;
    int32_t size_ = 0;
};
} // namespace NetManagerStandard
} // namespace OHOS
#endif // SOCKET_REMOTE_INFO_H