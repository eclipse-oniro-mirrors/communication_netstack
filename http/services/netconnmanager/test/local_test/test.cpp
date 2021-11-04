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

#include <iostream>
#include "i_net_conn_service.h"
#include "net_service.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace NetManagerStandard {
sptr<INetConnService> g_NetConnService = nullptr;
sptr<NetService> netService = nullptr;
sptr<Network> network = nullptr;
sptr<NetProvider> netProvider = nullptr;
uint32_t providerId = 0;

const int32_t INPUT_REG_NET_PROVIDER = 0;
const int32_t INPUT_UPT_NET_PROVIDER = 1;
const int32_t INPUT_UPT_NET_LINK_INFO = 2;
const int32_t INPUT_CREAT_NET_SERVICE = 3;
const int32_t INPUT_NS_CONNECT = 4;
const int32_t INPUT_NS_DISCONNECT = 5;
const int32_t INPUT_UNREG_NET_PROVIDER = 6;
const int32_t INPUT_UPT_NET_CAPABILITIES = 7;
const int32_t INPUT_QUIT = 100;
using NsTestFunc = void (*)();
std::map<int32_t, NsTestFunc> g_memberFuncMap;

int32_t GetInputData()
{
    int32_t input;
    std::cin >> input;
    while (std::cin.fail()) {
        std::cin.clear();
        std::cin.ignore();
        printf("Input error, please input number again\n");
        std::cin >> input;
    }
    return input;
}

void TestRegisterNetProvider()
{
    printf("please input netType_ NET_TYPE_UNKNOWN(%d) or NET_TYPE_CELLULAR(%d)\n", NET_TYPE_UNKNOWN,
        NET_TYPE_CELLULAR);
    uint16_t nT = GetInputData();
    NetworkType networkType = static_cast<NetworkType>(nT);

    printf("please input ident\n");
    std::string ident;
    std::cin >> ident;

    printf("please input netCapabilities NET_CAPABILITIES_INTERNET(%d) or NET_CAPABILITIES_MMS(%d)\n",
        NET_CAPABILITIES_INTERNET, NET_CAPABILITIES_MMS);
    uint32_t netCapabilities = GetInputData();

    uint32_t id = g_NetConnService->RegisterNetProvider(networkType, ident, netCapabilities);
    printf("RegisterNetProvider providerId:%d\n", id);
    providerId = id;

    return;
}

void TestUnRegisterNetProvider()
{
    uint32_t result = g_NetConnService->UnregisterNetProvider(providerId);
    providerId = 0;
    printf("TestUnRegisterNetProvider result:%d\n", result);
    return;
}

void TestUpdateNetCapabilities()
{
    printf("please input netCapabilities NET_CAPABILITIES_INTERNET(%d) or NET_CAPABILITIES_MMS(%d)\n",
        NET_CAPABILITIES_INTERNET, NET_CAPABILITIES_MMS);
    uint32_t netCapabilities = GetInputData();

    uint32_t result = g_NetConnService->UpdateNetCapabilities(providerId, netCapabilities);
    printf("TestSetNetCapabilities result:%d\n", result);
    return;
}

void TestUpdateNetProviderInfo()
{
    sptr<NetProviderInfo> netProviderInfo = (std::make_unique<NetProviderInfo>()).release();
    netProviderInfo->isAvailable_ = true;
    netProviderInfo->isRoaming_ = true;
    netProviderInfo->strength_ = 100;
    netProviderInfo->frequency_ = 16;
    uint32_t result = g_NetConnService->UpdateNetProviderInfo(providerId, netProviderInfo);
    printf("TestUpdateNetProviderInfo result:%d\n", result);
    // test to do
    return;
}

INetAddr GetINetAddrSample1()
{
    INetAddr addr1;
    addr1.type_ = 0XFF;
    addr1.family_ = 0x02;
    addr1.prefixlen_ = 0x03;
    addr1.address_ = "str03";
    addr1.netMask_ = "str04";
    addr1.hostName_ = "str05";
    return addr1;
}

INetAddr GetINetAddrSample2()
{
    INetAddr addr2;
    addr2.type_ = 0XFE;
    addr2.family_ = 0x04;
    addr2.prefixlen_ = 0x05;
    addr2.address_ = "str06";
    addr2.netMask_ = "str07";
    addr2.hostName_ = "str08";
    return addr2;
}

INetAddr GetDnsSample1()
{
    INetAddr dns1;
    dns1.type_ = 0XFD;
    dns1.family_ = 0x06;
    dns1.prefixlen_ = 0x07;
    dns1.address_ = "str09";
    dns1.netMask_ = "str10";
    dns1.hostName_ = "str11";
    return dns1;
}

INetAddr GetDnsSample2()
{
    INetAddr dns2;
    dns2.type_ = 0XFC;
    dns2.family_ = 0x08;
    dns2.prefixlen_ = 0x09;
    dns2.address_ = "str12";
    dns2.netMask_ = "str13";
    dns2.hostName_ = "str14";
    return dns2;
}

Route GetRouteSample1()
{
    Route route1;
    route1.iface_ = "str15";
    route1.destination_.type_ = 0XFB;
    route1.destination_.family_ = 0x0A;
    route1.destination_.prefixlen_ = 0x0B;
    route1.destination_.address_ = "str16";
    route1.destination_.netMask_ = "str17";
    route1.destination_.hostName_ = "str18";
    route1.gateway_.type_ = 0XFA;
    route1.gateway_.family_ = 0x0C;
    route1.gateway_.prefixlen_ = 0x0D;
    route1.gateway_.address_ = "str19";
    route1.gateway_.netMask_ = "str20";
    route1.gateway_.hostName_ = "str21";
    return route1;
}

Route GetRouteSample2()
{
    Route route2;
    route2.iface_ = "str22";
    route2.destination_.type_ = 0XF9;
    route2.destination_.family_ = 0x0E;
    route2.destination_.prefixlen_ = 0x0F;
    route2.destination_.address_ = "str23";
    route2.destination_.netMask_ = "str24";
    route2.destination_.hostName_ = "str25";
    route2.gateway_.type_ = 0XF8;
    route2.gateway_.family_ = 0x10;
    route2.gateway_.prefixlen_ = 0x11;
    route2.gateway_.address_ = "str26";
    route2.gateway_.netMask_ = "str27";
    route2.gateway_.hostName_ = "str28";
    return route2;
}

void TestUpdateNetLinkInfo()
{
    sptr<NetLinkInfo> netLinkInfo = (std::make_unique<NetLinkInfo>()).release();
    netLinkInfo->ifaceName_ = "str01";
    netLinkInfo->domain_ = "str02";
    netLinkInfo->netAddrList_.push_back(GetINetAddrSample1());
    netLinkInfo->netAddrList_.push_back(GetINetAddrSample2());
    netLinkInfo->dnsList_.push_back(GetDnsSample1());
    netLinkInfo->dnsList_.push_back(GetDnsSample2());
    netLinkInfo->routeList_.push_back(GetRouteSample1());
    netLinkInfo->routeList_.push_back(GetRouteSample2());
    netLinkInfo->mtu_ = 0x13;

    uint32_t result = g_NetConnService->UpdateNetLinkInfo(providerId, netLinkInfo);
    printf("TestUpdateNetProviderInfo result:%d\n", result);
    return;
}

void TestCreateNetService()
{
    printf("please input netType_ NET_TYPE_UNKNOWN(%d) or NET_TYPE_CELLULAR(%d)\n", NET_TYPE_UNKNOWN,
        NET_TYPE_CELLULAR);
    uint16_t nT = GetInputData();
    NetworkType networkType = static_cast<NetworkType>(nT);

    printf("please input ident\n");
    std::string ident;
    std::cin >> ident;

    printf("please input netCapabilities NET_CAPABILITIES_INTERNET(%d) or NET_CAPABILITIES_MMS(%d)\n",
        NET_CAPABILITIES_INTERNET, NET_CAPABILITIES_MMS);
    uint32_t netCapabilities = GetInputData();

    netProvider = (std::make_unique<NetProvider>(networkType, ident)).release();
    if (netProvider == nullptr) {
        printf("netProvider make error\n");
        return;
    }

    network = (std::make_unique<Network>(netProvider)).release();
    if (network == nullptr) {
        printf("network make error\n");
        return;
    }
    NetCapabilities netCapability = static_cast<NetCapabilities>(netCapabilities);
    netService = (std::make_unique<NetService>(ident, networkType, netCapability, network)).release();
    if (netService == nullptr) {
        printf("netService make shared error\n");
        return;
    }
}

void TestNetServiceConnect()
{
    netService->ServiceConnect();
}

void TestNetServiceDisConnect()
{
    netService->ServiceDisConnect();
}

sptr<INetConnService> GetProxy()
{
    printf("NetConnService GetProxy ... ");
    sptr<ISystemAbilityManager> systemAbilityMgr =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityMgr == nullptr) {
        printf("NetConnService Get ISystemAbilityManager failed ... ");
        return nullptr;
    }

    sptr<IRemoteObject> remote = systemAbilityMgr->CheckSystemAbility(COMMUNICATION_NET_MANAGER_SYS_ABILITY_ID);
    if (remote) {
        sptr<INetConnService> NetConnService = iface_cast<INetConnService>(remote);
        printf("NetConnService Get COMMUNICATION_NET_MANAGER_SYS_ABILITY_ID success ... ");
        return NetConnService;
    } else {
        printf("NetConnService Get COMMUNICATION_NET_MANAGER_SYS_ABILITY_ID fail ... ");
        return nullptr;
    }
}

void Prompt()
{
    printf(
        "\n-----------start test remote api--------------\n"
        "0 TestRegisterNetProvider\n"
        "1 TestUpdateNetProviderInfo\n"
        "2 TestUpdateNetLinkInfo\n"
        "3 TestCreateNetService\n"
        "4 TestNetServiceConnect\n"
        "5 TestNetServiceDisConnect\n"
        "6 TestUnRegisterNetProvider\n"
        "7 TestUpdateNetCapabilities\n"
        "100:exit \n");
}

void ProcessInput(bool &loopFlag)
{
    int32_t inputCMD = GetInputData();
    auto itFunc = g_memberFuncMap.find(inputCMD);
    if (itFunc != g_memberFuncMap.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            (*memberFunc)();
            return;
        }
    }
    printf("inputCMD is:[%d]\n", inputCMD);
    switch (inputCMD) {
        case INPUT_QUIT: {
            loopFlag = false;
            printf("exit...\n");
            break;
        }
        default:
            printf("please input correct number...\n");
            break;
    }
}

void TestInputQuit(bool &loopFlag)
{
    loopFlag = false;
}

void Init()
{
    g_memberFuncMap[INPUT_REG_NET_PROVIDER] = TestRegisterNetProvider;
    g_memberFuncMap[INPUT_UPT_NET_PROVIDER] = TestUpdateNetProviderInfo;
    g_memberFuncMap[INPUT_UPT_NET_LINK_INFO] = TestUpdateNetLinkInfo;

    g_memberFuncMap[INPUT_UPT_NET_CAPABILITIES] = TestUpdateNetCapabilities;
    g_memberFuncMap[INPUT_CREAT_NET_SERVICE] = TestCreateNetService;
    g_memberFuncMap[INPUT_NS_CONNECT] = TestNetServiceConnect;
    g_memberFuncMap[INPUT_NS_DISCONNECT] = TestNetServiceDisConnect;
    g_memberFuncMap[INPUT_UNREG_NET_PROVIDER] = TestUnRegisterNetProvider;
}
} // namespace NetManagerStandard
} // namespace OHOS

using namespace OHOS::NetManagerStandard;

int main()
{
    Init();
    g_NetConnService = GetProxy();
    if (g_NetConnService == nullptr) {
        printf("g_NetConnService is nullptr");
    }
    bool loopFlag = true;
    while (loopFlag) {
        Prompt();
        ProcessInput(loopFlag);
    }
    printf("...exit test...");
}
