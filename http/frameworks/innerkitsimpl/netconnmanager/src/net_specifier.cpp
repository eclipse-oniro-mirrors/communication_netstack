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
#include "net_specifier.h"

namespace OHOS {
namespace NetManagerStandard {
bool NetSpecifier::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(ident_)) {
        return false;
    }

    if (!parcel.WriteUint32(netType_)) {
        return false;
    }

    if (!parcel.WriteUint64(netCapabilities_)) {
        return false;
    }

    return true;
}

sptr<NetSpecifier> NetSpecifier::Unmarshalling(Parcel &parcel)
{
    sptr<NetSpecifier> ptr = (std::make_unique<NetSpecifier>()).release();
    if (ptr == nullptr) {
        NETMGR_LOGE("make_unique<NetSpecifier>() failed");
        return nullptr;
    }

    if (!parcel.ReadString(ptr->ident_)) {
        return nullptr;
    }

    if (!parcel.ReadUint32(ptr->netType_)) {
        return nullptr;
    }

    if (!parcel.ReadUint64(ptr->netCapabilities_)) {
        return nullptr;
    }

    return ptr;
}

bool NetSpecifier::Marshalling(Parcel &parcel, const sptr<NetSpecifier> &object)
{
    if (object == nullptr) {
        NETMGR_LOGE("NetSpecifier object ptr is nullptr");
        return false;
    }
    if (!parcel.WriteString(object->ident_)) {
        return false;
    }

    if (!parcel.WriteUint32(object->netType_)) {
        return false;
    }

    if (!parcel.WriteUint64(object->netCapabilities_)) {
        return false;
    }

    return true;
}

std::string NetSpecifier::ToString(const std::string &tab) const
{
    std::string str;
    str.append("\n");
    str.append(tab);
    str.append("[NetSpecifier]");

    str.append("\n");
    str.append(tab);
    str.append("ident_ = ");
    str.append(ident_);

    str.append("\n");
    str.append(tab);
    str.append("netType_ = ");
    str.append(std::to_string(netType_));

    str.append("\n");
    str.append(tab);
    str.append("netCapabilities_ = ");
    str.append(std::to_string(netCapabilities_));

    return str;
}
} // namespace NetManagerStandard
} // namespace OHOS