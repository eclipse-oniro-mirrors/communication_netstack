#include <thread>
#include <stdint.h>
#include <iostream>
//#include <gtest/gtest.h>
#include "native_netd_service.h"
#include "netlink_manager.h"
#include "fwmark_server.h"
#include "dnsresolv_service.h"
#include "netnative_log_wrapper.h"
#include "main.h"

using namespace OHOS::nmd;
std::map<int32_t, NetdTestFunc> g_memberFuncMap;
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

void Prompt()
{
    printf(
        "\n-----------start test netd api--------------\n"
        "0 TestSetResolverConfig\n"
        "1 TestCreateNetworkCache\n"
        "2 TestFlushNetworkCache\n"
        "3 TestDestoryNetworkCache\n"
        "4 TestGetaddrinfo\n"
        "5 TestInterfaceSetMtu\n"
        "6 TestNetworkSetDefault\n"
        "7 TestNetworkGETDefault\n"
        "8 TestNetworkClearDefault\n"
        "9 TestNetworkCreatePhysical\n"
        "10 TestInterfaceAddAddress\n"
        "11 TestInterfaceDelAddress\n"
        "12 TestNetworkAddInterface\n"
        "13 TestNetworkRemoveInterface\n"
        "14 TestGetFwmarkForNetwork\n"
        "15 TestInterfaceSetCfg\n"
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

void Init()
{
    g_memberFuncMap[SET_RESOLVER_CONFIG] = TestSetResolverConfig;
    g_memberFuncMap[CREATE_NETWORK_CACHE] = TestCreateNetworkCache;
    g_memberFuncMap[FLUSH_NETWORK_CACHE] = TestFlushNetworkCache;

    g_memberFuncMap[DESTORY_NETWORK_CACHE] = TestDestoryNetworkCache;
    g_memberFuncMap[GET_ADDR_INFO] = TestGetaddrinfo;
    g_memberFuncMap[INTERFACE_SET_MTU] = TestInterfaceSetMtu;

    g_memberFuncMap[NETWORK_SET_DEFAULT] = TestNetworkSetDefault;
    g_memberFuncMap[NETWORK_GET_DEFAULT] = TestNetworkGetDefault;
    g_memberFuncMap[NETWORK_ClEAR_DEFAULT] = TestNetworkClearDefault;

    g_memberFuncMap[NETWORK_CREATE_PHYSICAL] = TestNetworkCreatePhysical;
    g_memberFuncMap[INTERFACE_ADD_ADDRESS] = TestInterfaceAddAddress;
    g_memberFuncMap[INTERFACE_DEL_ADDRESS] = TestInterfaceDelAddress;

    g_memberFuncMap[NETWORK_ADD_INTERFACE] = TestNetworkAddInterface;
    g_memberFuncMap[NETWORK_REMOVE_INTERFACE] = TestNetworkRemoveInterface;
    g_memberFuncMap[GET_FWMARK_FOR_NETWORK] = TestGetFwmarkForNetwork;

    g_memberFuncMap[INTERFACE_SET_CFG] = TestInterfaceSetCfg;
}

int main(int argc, char *argv[])
{
    std::cout << ("netd test begin.....") << std::endl;
    Init();

    bool loopFlag = true;
    while (loopFlag) {
        Prompt();
        ProcessInput(loopFlag);
    }

    std::cout << "Test finished, you can terminate by press Ctrl + C" << std::endl;

    return 0;
}