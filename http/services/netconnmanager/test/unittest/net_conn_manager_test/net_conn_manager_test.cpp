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

#include <gtest/gtest.h>

#include "netmgr_log_wrapper.h"
#include "net_conn_manager.h"

namespace OHOS {
namespace NetManagerStandard {
using namespace testing::ext;
class NetConnManagerTest : public testing::Test {
public:
    enum {
        NO_ERROR = 0,
        ERROR = 1,
    };

    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    sptr<NetLinkInfo> GetUpdateLinkInfoSample();
};

bool g_initState = false;

void NetConnManagerTest::SetUpTestCase() {}

void NetConnManagerTest::TearDownTestCase() {}

void NetConnManagerTest::SetUp() {}

void NetConnManagerTest::TearDown() {}

sptr<NetLinkInfo> NetConnManagerTest::GetUpdateLinkInfoSample()
{
    sptr<NetLinkInfo> netLinkInfo = (std::make_unique<NetLinkInfo>()).release();
    netLinkInfo->ifaceName_ = "test";
    netLinkInfo->domain_ = "test";

    sptr<INetAddr> netAddr = (std::make_unique<INetAddr>()).release();
    netAddr->type_ = INetAddr::IPV4;
    netAddr->family_ = 0x10;
    netAddr->prefixlen_ = 23;
    netAddr->address_ = "192.168.2.0";
    netAddr->netMask_ = "192.255.255.255";
    netAddr->hostName_ = "netAddr";
    netLinkInfo->netAddrList_.push_back(*netAddr);

    sptr<INetAddr> dns = (std::make_unique<INetAddr>()).release();
    dns->type_ = INetAddr::IPV4;
    dns->family_ = 0x10;
    dns->prefixlen_ = 23;
    dns->address_ = "192.168.2.0";
    dns->netMask_ = "192.255.255.255";
    dns->hostName_ = "netAddr";
    netLinkInfo->dnsList_.push_back(*dns);

    sptr<Route> route = (std::make_unique<Route>()).release();
    route->iface_ = "iface0";
    route->destination_.type_ = INetAddr::IPV4;
    route->destination_.family_ = 0x10;
    route->destination_.prefixlen_ = 23;
    route->destination_.address_ = "192.168.2.0";
    route->destination_.netMask_ = "192.255.255.255";
    route->destination_.hostName_ = "netAddr";
    route->gateway_.type_ = INetAddr::IPV4;
    route->gateway_.family_ = 0x10;
    route->gateway_.prefixlen_ = 23;
    route->gateway_.address_ = "192.168.2.0";
    route->gateway_.netMask_ = "192.255.255.255";
    route->gateway_.hostName_ = "netAddr";
    netLinkInfo->routeList_.push_back(*route);

    netLinkInfo->mtu_ = 1234;

    return netLinkInfo;
}
/**
 * @tc.name: NetConnManager001
 * @tc.desc: Test NetConnManager ready.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnManagerTest, NetConnManager001, TestSize.Level0)
{
    if (DelayedSingleton<NetConnManager>::GetInstance() == nullptr) {
        NETMGR_LOGE("NetConnManager init failed");
        return;
    }
    NETMGR_LOGD("NetConnManager init success.");
    g_initState = true;
}

/**
 * @tc.name: NetConnManager002
 * @tc.desc: Test NetConnManager SystemReady.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnManagerTest, NetConnManager002, TestSize.Level0)
{
    if (!g_initState) {
        NETMGR_LOGE("NetConnManager init failed");
        return;
    }
    int32_t result = DelayedSingleton<NetConnManager>::GetInstance()->SystemReady();
    if (result != 0) {
        NETMGR_LOGE("SystemReady test failed");
        return;
    }
    NETMGR_LOGD("SystemReady test success.");
}

/**
 * @tc.name: NetConnManager00
 * @tc.desc: Test NetConnManager RegisterNetProvider.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnManagerTest, NetConnManager003, TestSize.Level0)
{
    if (!g_initState) {
        NETMGR_LOGE("NetConnManager init failed");
        return;
    }
    uint32_t netCapabilities = 0x00;
    netCapabilities |= NET_CAPABILITIES_INTERNET;
    netCapabilities |= NET_CAPABILITIES_MMS;

    std::string ident = "ident01";
    int32_t result = DelayedSingleton<NetConnManager>::GetInstance()->RegisterNetProvider(
        NET_TYPE_CELLULAR, ident, netCapabilities);
    if (result != 0) {
        NETMGR_LOGE("RegisterNetProvider test failed");
        return;
    }
    NETMGR_LOGD("RegisterNetProvider test success.");
}

/**
 * @tc.name: NetConnManager004
 * @tc.desc: Test NetConnManager UnregisterNetProvider.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnManagerTest, NetConnManager004, TestSize.Level0)
{
    if (!g_initState) {
        NETMGR_LOGE("NetConnManager init failed");
        return;
    }
    uint32_t providerId = 0x00;

    int32_t result = DelayedSingleton<NetConnManager>::GetInstance()->UnregisterNetProvider(providerId);
    if (result != 0) {
        NETMGR_LOGE("UnregisterNetProvider test failed");
        return;
    }
    NETMGR_LOGD("UnregisterNetProvider test success.");
}

/**
 * @tc.name: NetConnManager005
 * @tc.desc: Test NetConnManager UpdateNetProviderInfo.
 * @tc.type: FUNC
 */

HWTEST_F(NetConnManagerTest, NetConnManager005, TestSize.Level0)
{
    if (!g_initState) {
        NETMGR_LOGE("NetConnManager init failed");
        return;
    }
    uint32_t providerId = 0x01;
    sptr<NetProviderInfo> netProviderInfo = new NetProviderInfo;
    netProviderInfo->isAvailable_ = true;
    netProviderInfo->isRoaming_ = true;
    netProviderInfo->strength_ = 100;
    netProviderInfo->frequency_ = 16;
    int32_t result =
        DelayedSingleton<NetConnManager>::GetInstance()->UpdateNetProviderInfo(providerId, netProviderInfo);
    if (result != 0) {
        NETMGR_LOGE("UpdateNetProviderInfo test failed");
        return;
    }
    NETMGR_LOGD("UpdateNetProviderInfo test success.");
}

/**
 * @tc.name: NetConnManager006
 * @tc.desc: Test NetConnManager UpdateNetLinkInfo.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnManagerTest, NetConnManager006, TestSize.Level0)
{
    if (!g_initState) {
        NETMGR_LOGE("NetConnManager init failed");
        return;
    }
    uint32_t providerId = 0x1;
    sptr<NetLinkInfo> netLinkInfo = GetUpdateLinkInfoSample();
    int32_t result = DelayedSingleton<NetConnManager>::GetInstance()->UpdateNetLinkInfo(providerId, netLinkInfo);
    if (result != 0) {
        NETMGR_LOGE("UpdateNetLinkInfo test failed");
        return;
    }
    NETMGR_LOGD("UpdateNetLinkInfo test success.");
}
} // namespace NetManagerStandard
} // namespace OHOS