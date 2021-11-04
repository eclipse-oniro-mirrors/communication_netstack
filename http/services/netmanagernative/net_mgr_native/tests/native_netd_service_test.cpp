#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <native_netd_service.h>
#include <fwmark.h>

TEST(native_netd_service, interfaceGetList)
{
    nmd::native_nted_service nns;
    std::vector<std::string> ifs = nns.interfaceGetList();
    for (size_t i = 0; i < ifs.size(); i++) {
        std::cout << ifs.at(i) << std::endl;
    }
    size_t si = ifs.size();
    size_t sss = 0;
    EXPECT_NE(si, sss);
}

TEST(native_netd_service, interfaceGetConfig)
{
    nmd::native_nted_service nns;
    std::cout << nns.interfaceGetConfig("eth0") << std::endl;
    EXPECT_EQ(nns.interfaceGetConfig("eth0").ifName, "eth0");
}

TEST(native_netd_service, networkRemoveRouteParcel)
{
    nmd::native_nted_service nns;
    nmd::route_info_parcel routeInfoParcel = {"", "", "", 1500};
    EXPECT_NE(nns.networkCreatePhysical(12, nmd::NetworkPermission::PERMISSION_NONE), -1);
    EXPECT_NE(nns.networkAddInterface(12, "eth0"), -1);
    nns.networkRemoveRouteParcel(12, routeInfoParcel);
}

TEST(native_netd_service, networkAddRouteParcel)
{
    nmd::native_nted_service nns;
    nmd::route_info_parcel routeInfoParcel = {"", "", "", 1500};
    EXPECT_NE(nns.networkCreatePhysical(12, nmd::NetworkPermission::PERMISSION_NONE), -1);
    EXPECT_NE(nns.networkAddInterface(12, "eth0"), -1);
    nns.networkAddRouteParcel(12, routeInfoParcel);
    nmd::mark_mask_parcel testFwmark = nns.getFwmarkForNetwork(12);
    EXPECT_EQ(12, testFwmark.mark);
    EXPECT_EQ(65535, testFwmark.mask);
}

TEST(native_netd_service, networkSetPermissionForNetwork)
{
    nmd::native_nted_service nns;
    EXPECT_NE(nns.networkCreatePhysical(12, nmd::NetworkPermission::PERMISSION_NONE), -1);
    EXPECT_NE(nns.networkAddInterface(12, "eth0"), -1);
    nns.networkSetPermissionForNetwork(12, nmd::NetworkPermission::PERMISSION_NONE);
}

TEST(native_netd_service, init)
{
    nmd::native_nted_service nns;
    nns.init();
}

TEST(native_netd_service, networkCreatePhysical)
{
    nmd::native_nted_service nns;
    EXPECT_NE(nns.networkCreatePhysical(12, nmd::NetworkPermission::PERMISSION_NONE), -1);
    EXPECT_NE(nns.networkAddInterface(12, "eth0"), -1);
    EXPECT_NE(nns.networkDestroy(12), -1);
}

TEST(native_netd_service, networkRemoveInterface)
{
    nmd::native_nted_service nns;
    EXPECT_NE(nns.networkCreatePhysical(12, nmd::NetworkPermission::PERMISSION_NONE), -1);
    EXPECT_NE(nns.networkAddInterface(12, "eth0"), -1);
    EXPECT_NE(nns.networkRemoveInterface(12, "eth0"), -1);
    EXPECT_NE(nns.networkDestroy(12), -1);
}

TEST(native_netd_service, socketDestroy)
{
    nmd::native_nted_service nns;
    EXPECT_NE(nns.networkCreatePhysical(12, nmd::NetworkPermission::PERMISSION_NONE), -1);
    EXPECT_NE(nns.networkAddInterface(12, "eth0"), -1);
    nns.socketDestroy(12);
}

TEST(native_netd_service, socketDestroyByIfName)
{
    nmd::native_nted_service nns;
    EXPECT_NE(nns.networkCreatePhysical(12, nmd::NetworkPermission::PERMISSION_NONE), -1);
    EXPECT_NE(nns.networkAddInterface(12, "eth0"), -1);
    nns.socketDestroy("eth0");
}

TEST(native_netd_service, interfaceAddAddress)
{
    nmd::native_nted_service nns;
    EXPECT_NE(nns.interfaceAddAddress("lo", "192.168.0.12", 32), -1);
}

TEST(native_netd_service, interfaceDelAddress)
{
    nmd::native_nted_service nns;
    EXPECT_NE(nns.interfaceDelAddress("lo", "192.168.0.12", 32), -1);
}

TEST(native_netd_service, networkAddRoute)
{
    nmd::native_nted_service nns;
    EXPECT_NE(nns.networkCreatePhysical(12, nmd::NetworkPermission::PERMISSION_NONE), -1);
    EXPECT_NE(nns.networkAddInterface(12, "eth0"), -1);
    EXPECT_NE(nns.networkAddRoute(12, "eth0", "47.94.251.146/32", "10.205.127.254"), -1);
}

TEST(native_netd_service, networkRemoveRoute)
{
    nmd::native_nted_service nns;
    EXPECT_NE(nns.networkCreatePhysical(12, nmd::NetworkPermission::PERMISSION_NONE), -1);
    EXPECT_NE(nns.networkAddInterface(12, "eth0"), -1);
    EXPECT_NE(nns.networkRemoveRoute(12, "eth0", "47.94.251.146/32", "10.205.127.254"), -1);
}

TEST(native_netd_service, networkGetDefault)
{
    nmd::native_nted_service nns;
    EXPECT_NE(nns.networkCreatePhysical(12, nmd::NetworkPermission::PERMISSION_NONE), -1);
    EXPECT_NE(nns.networkAddInterface(12, "eth0"), -1);
    EXPECT_EQ(nns.networkGetDefault(), 0);
}

TEST(native_netd_service, networkSetDefault)
{
    nmd::native_nted_service nns;
    EXPECT_NE(nns.networkCreatePhysical(12, nmd::NetworkPermission::PERMISSION_NONE), -1);
    EXPECT_NE(nns.networkAddInterface(12, "eth0"), -1);
    EXPECT_NE(nns.networkSetDefault(12), -1);
}

TEST(native_netd_service, networkGetDefaultWhenDefaultSat)
{
    nmd::native_nted_service nns;
    EXPECT_NE(nns.networkCreatePhysical(12, nmd::NetworkPermission::PERMISSION_NONE), -1);
    EXPECT_NE(nns.networkAddInterface(12, "eth0"), -1);
    EXPECT_NE(nns.networkSetDefault(12), -1);
    std::cout << nns.networkGetDefault() << std::endl;
    EXPECT_EQ(nns.networkGetDefault(), 12);
}

TEST(native_netd_service, networkGetDefaultWhenDefaultCleared)
{
    nmd::native_nted_service nns;
    EXPECT_NE(nns.networkCreatePhysical(12, nmd::NetworkPermission::PERMISSION_NONE), -1);
    EXPECT_NE(nns.networkAddInterface(12, "eth0"), -1);
    EXPECT_NE(nns.networkSetDefault(12), -1);
    EXPECT_NE(nns.networkClearDefault(), -1);
    EXPECT_EQ(nns.networkGetDefault(), 0);
}