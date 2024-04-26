/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "netstack_bundle_utils.h"

#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "bundle_mgr_proxy.h"

namespace OHOS::NetStack::BundleUtils {
bool IsAtomicService()
{
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        NETSTACK_LOGE("systemAbilityManger is null");
        return false;
    }
    auto bundleMgrSa = systemAbilityManager->GetSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (bundleMgrSa == nullptr) {
        NETSTACK_LOGE("bundleMgrSa is null");
        return false;
    }
    sptr<AppExecFwk::BundleMgrProxy> bundleMgrProxy = iface_cast<AppExecFwk::BundleMgrProxy>(bundleMgrSa);
    if (bundleMgrProxy == nullptr) {
        NETSTACK_LOGE("buildMgrProxy is null.");
        return false;
    }
    AppExecFwk::BundleInfo bundleInfo;
    auto flagsWithAppInfo = AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION;
    auto flagsWithSign = AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO;
    if (bundleMgrProxy->GetBundleInfoForSelf(int32_t(flagsWithAppInfo) | int32_t(flagsWithSign),
                                             bundleInfo) != ERR_OK) {
        NETSTACK_LOGE("getBundleInfoForSelf occur err");
        return false;
    }
    return bundleInfo.applicationInfo.bundleType == AppExecFwk::BundleType::ATOMIC_SERVICE
}
}