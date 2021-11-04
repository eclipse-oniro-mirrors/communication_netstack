#include "main.h"
#include "netnative_log_wrapper.h"
#include "native_netd_service.h"
#include <iostream>
#include <string.h>

//设置网络MTU
void TestInterfaceSetMtu()
{
    // service.interfaceSetMtu("eth0", 1500)
    NETNATIVE_LOGE("TestInterfaceSetMtu begin");
    OHOS::nmd::NativeNetdService nativeNetdSvc;
    nativeNetdSvc.init();

    int mtuVal = 1200;
    std::string ifName = std::string("eth0");
    int mtuValOld = nativeNetdSvc.interfaceGetMtu(ifName);
    NETNATIVE_LOGE("before SetMtu, mtuVal %{public}d", mtuValOld);
    nativeNetdSvc.interfaceSetMtu(ifName, mtuVal);
    mtuValOld = nativeNetdSvc.interfaceGetMtu(ifName);
    NETNATIVE_LOGE("after SetMtu, mtuVal %{public}d", mtuValOld);
    NETNATIVE_LOGE("TestInterfaceSetMtu end");
}

void TestNetworkSetDefault()
{
    NETNATIVE_LOGE("TestNetworkSetDefault begin");
    OHOS::nmd::NativeNetdService nativeNetdSvc;
    nativeNetdSvc.init();
    int netId = 0;
    nativeNetdSvc.networkSetDefault(netId);
    NETNATIVE_LOGE("TestNetworkSetDefault end");
}

void TestNetworkGetDefault()
{
    NETNATIVE_LOGE("TestNetworkGetDefault begin");
    OHOS::nmd::NativeNetdService nativeNetdSvc;
    nativeNetdSvc.init();
    nativeNetdSvc.networkGetDefault();
    NETNATIVE_LOGE("TestNetworkGetDefault end");
}

//清除默认网络
void TestNetworkClearDefault()
{
    // service.networkClearDefault()
    NETNATIVE_LOGE("TestNetworkClearDefault begin");
    OHOS::nmd::NativeNetdService nativeNetdSvc;
    nativeNetdSvc.init();
    nativeNetdSvc.networkClearDefault();
    NETNATIVE_LOGE("TestNetworkClearDefault end");
}

//创建网络
void TestNetworkCreatePhysical()
{
    NETNATIVE_LOGE("TestNetworkCreatePhysical begin");
    OHOS::nmd::NativeNetdService nativeNetdSvc;
    nativeNetdSvc.init();
    nativeNetdSvc.networkCreatePhysical(12, OHOS::nmd::NetworkPermission::PERMISSION_NONE);
    NETNATIVE_LOGE("TestNetworkCreatePhysical end");
}

//添加地址
void TestInterfaceAddAddress()
{
    NETNATIVE_LOGE("TestInterfaceAddAddress begin");
    OHOS::nmd::NativeNetdService nativeNetdSvc;
    nativeNetdSvc.init();
    nativeNetdSvc.interfaceAddAddress("lo", "127.0.0.4", 32);
    NETNATIVE_LOGE("TestInterfaceAddAddress end");
}

//移除地址
void TestInterfaceDelAddress()
{
    NETNATIVE_LOGE("TestInterfaceDelAddress begin");
    OHOS::nmd::NativeNetdService nativeNetdSvc;
    nativeNetdSvc.init();
    nativeNetdSvc.interfaceDelAddress("lo", "127.0.0.4", 32);
    NETNATIVE_LOGE("TestInterfaceDelAddress end");
}

//网络添加
void TestNetworkAddInterface()
{
    NETNATIVE_LOGE("TestNetworkAddInterface begin");
    OHOS::nmd::NativeNetdService nativeNetdSvc;
    nativeNetdSvc.init();
    nativeNetdSvc.networkAddInterface(12, "eth0");
    NETNATIVE_LOGE("TestNetworkAddInterface end");
}
//网络移除
void TestNetworkRemoveInterface()
{
    NETNATIVE_LOGE("TestNetworkRemoveInterface begin");
    OHOS::nmd::NativeNetdService nativeNetdSvc;
    nativeNetdSvc.init();
    nativeNetdSvc.networkRemoveInterface(12, "eth0");
    NETNATIVE_LOGE("TestNetworkRemoveInterface end");
}

void TestGetFwmarkForNetwork()
{
    NETNATIVE_LOGE("TestGetFwmarkForNetwork begin");
    OHOS::nmd::NativeNetdService nativeNetdSvc;
    nativeNetdSvc.init();
    OHOS::nmd::mark_mask_parcel testFwmark = nativeNetdSvc.getFwmarkForNetwork(12);
    NETNATIVE_LOGE("mark %{public}d,mask %{public}d", testFwmark.mark, testFwmark.mask);
    NETNATIVE_LOGE("TestGetFwmarkForNetwork end");
}

void TestInterfaceSetCfg()
{
    NETNATIVE_LOGE("TestInterfaceSetCfg begin");
    OHOS::nmd::NativeNetdService nativeNetdSvc;
    nativeNetdSvc.init();
    OHOS::nmd::interface_configuration_parcel parcel = nativeNetdSvc.interfaceGetConfig("lo");
    NETNATIVE_LOGE("before: parcel get hwaddr = %{public}s", parcel.hwAddr.c_str());
    parcel.hwAddr = std::string("192.168.55.10");
    nativeNetdSvc.interfaceSetConfig(parcel);
    parcel = nativeNetdSvc.interfaceGetConfig("lo");
    NETNATIVE_LOGE("after: parcel get hwaddr = %{public}s", parcel.hwAddr.c_str());
    NETNATIVE_LOGE("TestInterfaceSetCfg end");
}