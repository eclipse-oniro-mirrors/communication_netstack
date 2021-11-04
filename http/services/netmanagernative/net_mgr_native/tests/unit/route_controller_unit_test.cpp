#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <logger.h>
#include <net/if.h>
#include <thread>
#include <utils.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include "route_controller.h"

TEST(route_controller_test, addInterfaceToDefaultNetwork)
{
    EXPECT_NE(
        nmd::route_controller::addInterfaceToDefaultNetwork("eth0", nmd::NetworkPermission::PERMISSION_NONE), -1);
}

TEST(route_controller_test, removeInterfaceToDefaultNetwork)
{
    EXPECT_NE(
        nmd::route_controller::removeInterfaceFromDefaultNetwork("eth0", nmd::NetworkPermission::PERMISSION_NONE),
        -1);
}

TEST(route_controller_test, createChildChains)
{
    EXPECT_EQ(nmd::route_controller::createChildChains("mangle", "INPUT", "test_mangle_INPUT"), 0);
}

TEST(route_controller_test, removeInterfaceFromPhysicalNetwork)
{
    EXPECT_EQ(nmd::route_controller::removeInterfaceFromPhysicalNetwork(
                  0, "eth0", nmd::NetworkPermission::PERMISSION_NONE),
        1);
}

TEST(route_controller_test, addRoute)
{
    EXPECT_EQ(nmd::route_controller::addRoute(0, "eth0", "47.94.251.146/32", "10.205.127.254"), 1);
}

TEST(route_controller_test, removeRoute)
{
    EXPECT_EQ(nmd::route_controller::removeRoute(0, "eth0", "47.94.251.146/32", "10.205.127.254"), 1);
}
