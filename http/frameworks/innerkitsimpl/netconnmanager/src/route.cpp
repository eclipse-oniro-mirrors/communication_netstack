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

#include "netmgr_log_wrapper.h"
#include "route.h"

namespace OHOS {
namespace NetManagerStandard {
bool Route::operator==(const Route &obj) const
{
    bool out = true;
    out = out && (iface_ == obj.iface_);
    out = out && (destination_ == obj.destination_);
    out = out && (gateway_ == obj.gateway_);
    return out;
}

bool Route::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(iface_)) {
        return false;
    }

    if (!destination_.Marshalling(parcel)) {
        NETMGR_LOGE("write destination_ to parcel failed");
        return false;
    }

    if (!gateway_.Marshalling(parcel)) {
        NETMGR_LOGE("write gateway_ to parcel failed");
        return false;
    }

    return true;
}

sptr<Route> Route::Unmarshalling(Parcel &parcel)
{
    sptr<Route> ptr = (std::make_unique<Route>()).release();
    if (ptr == nullptr) {
        NETMGR_LOGE("make_unique<Route>() failed");
        return nullptr;
    }

    if (!parcel.ReadString(ptr->iface_)) {
        return nullptr;
    }

    sptr<INetAddr> destination = INetAddr::Unmarshalling(parcel);
    if (destination == nullptr) {
        NETMGR_LOGE("read destination from parcel failed");
        return nullptr;
    }
    ptr->destination_ = *destination;

    sptr<INetAddr> gateway = INetAddr::Unmarshalling(parcel);
    if (gateway == nullptr) {
        NETMGR_LOGE("read gateway from parcel failed");
        return nullptr;
    }
    ptr->gateway_ = *gateway;

    return ptr;
}

bool Route::Marshalling(Parcel &parcel, const sptr<Route> &object)
{
    if (object == nullptr) {
        NETMGR_LOGE("Route object ptr is nullptr");
        return false;
    }
    if (!parcel.WriteString(object->iface_)) {
        return false;
    }

    if (!object->destination_.Marshalling(parcel)) {
        NETMGR_LOGE("write object->destination_ to parcel failed");
        return false;
    }

    if (!object->gateway_.Marshalling(parcel)) {
        NETMGR_LOGE("write object->gateway_ to parcel failed");
        return false;
    }

    return true;
}

std::string Route::ToString(const std::string &tab) const
{
    std::string str;
    str.append("\n");
    str.append(tab);
    str.append("[Route]");

    str.append("\n");
    str.append(tab);
    str.append("iface_ = ");
    str.append(iface_);

    str.append("\n");
    str.append(tab);
    str.append("destination_ = ");
    str.append(destination_.ToString(tab + "    "));

    str.append("\n");
    str.append(tab);
    str.append("gateway_ = ");
    str.append(gateway_.ToString(tab + "    "));

    return str;
}
} // namespace NetManagerStandard
} // namespace OHOS