#include <bitcast.h>
#include <gtest/gtest.h>
#include <network_controller.h>
#include <route_controller.h>
#include <netlink_manager.h>

TEST(network_controller, should_create_network)
{
    nmd::network_controller controller;
    controller.createPhysicalNetwork(12, nmd::NetworkPermission::PERMISSION_SYSTEM);
    std::vector<nmd::network *> nws = controller.getNetworks();
    unsigned long size = 1;
    EXPECT_EQ(nws.size(), size);
}

TEST(network_controller, should_be_indefault_when_create)
{
    nmd::network_controller controller;
    controller.createPhysicalNetwork(12, nmd::NetworkPermission::PERMISSION_SYSTEM);
    std::vector<nmd::network *> nws = controller.getNetworks();
    unsigned long size = 1;
    EXPECT_EQ(nws.size(), size);
    EXPECT_FALSE(nws[0]->isDefault());
}

TEST(network_controller, should_be_default_when_as_default)
{
    nmd::network_controller controller;
    controller.createPhysicalNetwork(12, nmd::NetworkPermission::PERMISSION_SYSTEM);
    std::vector<nmd::network *> nws = controller.getNetworks();
    unsigned long size = 1;
    EXPECT_EQ(nws.size(), size);
    EXPECT_FALSE(nws[0]->isDefault());
    controller.setDefaultNetwork(12);
    EXPECT_TRUE(nws[0]->isDefault());
}

TEST(network_controller, should_create_network_and_add_interface)
{
    nmd::network_controller controller;
    controller.createPhysicalNetwork(12, nmd::NetworkPermission::PERMISSION_SYSTEM);
    std::vector<nmd::network *> nws = controller.getNetworks();

    unsigned long size = 1;
    EXPECT_EQ(nws.size(), size);

    std::string interfaceNameEth0 = "eth0";
    int result = controller.addInterfaceToNetwork(12, interfaceNameEth0);
    EXPECT_EQ(result, 1);

    bool hasInterfaceEth0 = nws[0]->hasInterface(interfaceNameEth0);
    EXPECT_TRUE(hasInterfaceEth0);

    std::string interfaceNameEth1 = "eth1";
    bool hasInterfaceEth1 = nws[0]->hasInterface(interfaceNameEth1);
    EXPECT_FALSE(hasInterfaceEth1);
}

TEST(network_controller, should_create_network_and_add_exists_interface)
{
    nmd::network_controller controller;
    controller.createPhysicalNetwork(12, nmd::NetworkPermission::PERMISSION_SYSTEM);
    std::vector<nmd::network *> nws = controller.getNetworks();

    unsigned long size = 1;
    EXPECT_EQ(nws.size(), size);

    std::string interfaceNameEth0 = "eth0";
    int result = controller.addInterfaceToNetwork(12, interfaceNameEth0);
    EXPECT_EQ(result, 1);

    bool hasInterfaceEth0 = nws[0]->hasInterface(interfaceNameEth0);
    EXPECT_TRUE(hasInterfaceEth0);

    result = controller.addInterfaceToNetwork(12, interfaceNameEth0);
    EXPECT_EQ(result, 1);

    std::string interfaceNameEth1 = "eth1";
    bool hasInterfaceEth1 = nws[0]->hasInterface(interfaceNameEth1);
    EXPECT_FALSE(hasInterfaceEth1);
}

TEST(network_controller, should_create_network_as_default_and_add_interface)
{
    nmd::network_controller controller;
    controller.createPhysicalNetwork(12, nmd::NetworkPermission::PERMISSION_SYSTEM);
    std::vector<nmd::network *> nws = controller.getNetworks();

    unsigned long size = 1;
    EXPECT_EQ(nws.size(), size);
    controller.setDefaultNetwork(12);

    std::string interfaceNameEth0 = "eth0";
    int result = controller.addInterfaceToNetwork(12, interfaceNameEth0);
    EXPECT_EQ(result, 1);

    bool hasInterfaceEth0 = nws[0]->hasInterface(interfaceNameEth0);
    EXPECT_TRUE(hasInterfaceEth0);
}

TEST(network_controller, should_create_network_as_default_and_remove_default)
{
    nmd::network_controller controller;
    controller.createPhysicalNetwork(12, nmd::NetworkPermission::PERMISSION_SYSTEM);
    std::vector<nmd::network *> nws = controller.getNetworks();

    unsigned long size = 1;
    EXPECT_EQ(nws.size(), size);
    controller.setDefaultNetwork(12);

    controller.createPhysicalNetwork(13, nmd::NetworkPermission::PERMISSION_SYSTEM);
    nws = controller.getNetworks();

    size = 2;
    EXPECT_EQ(nws.size(), size);
    controller.setDefaultNetwork(13);
    EXPECT_EQ(controller.getDefaultNetwork(), 13);
}

TEST(network_controller, should_have_iprule_when_add_interface)
{
    int pid = getpid();
    nmd::netlink_manager::setPid(pid);
    EXPECT_EQ(pid, nmd::netlink_manager::getPid());

    nmd::network_controller controller;
    controller.createPhysicalNetwork(12, nmd::NetworkPermission::PERMISSION_SYSTEM);
    std::vector<nmd::network *> nws = controller.getNetworks();

    unsigned long size = 1;
    EXPECT_EQ(nws.size(), size);

    std::string interfaceNameEth0 = "eth0";
    int result = controller.addInterfaceToNetwork(12, interfaceNameEth0);
    EXPECT_EQ(result, 1);
    bool hasInterfaceEth0 = nws[0]->hasInterface(interfaceNameEth0);
    EXPECT_TRUE(hasInterfaceEth0);
}

TEST(network_controller, should_destroy_network)
{
    nmd::network_controller controller;
    controller.createPhysicalNetwork(12, nmd::NetworkPermission::PERMISSION_SYSTEM);
    std::vector<nmd::network *> nws = controller.getNetworks();

    unsigned long size = 1;
    EXPECT_EQ(nws.size(), size);

    std::string interfaceNameEth0 = "eth0";
    int result = controller.addInterfaceToNetwork(12, interfaceNameEth0);
    EXPECT_EQ(result, 1);

    bool hasInterfaceEth0 = nws[0]->hasInterface(interfaceNameEth0);
    EXPECT_TRUE(hasInterfaceEth0);

    std::string interfaceNameEth1 = "eth1";
    bool hasInterfaceEth1 = nws[0]->hasInterface(interfaceNameEth1);
    EXPECT_FALSE(hasInterfaceEth1);

    EXPECT_EQ(controller.destroyNetwork(12), 1);
}

TEST(network_controller, clearDefaultNetwork)
{
    nmd::network_controller controller;
    controller.createPhysicalNetwork(12, nmd::NetworkPermission::PERMISSION_SYSTEM);
    std::vector<nmd::network *> nws = controller.getNetworks();

    unsigned long size = 1;
    EXPECT_EQ(nws.size(), size);

    std::string interfaceNameEth0 = "eth0";
    int result = controller.addInterfaceToNetwork(12, interfaceNameEth0);
    EXPECT_EQ(result, 1);

    bool hasInterfaceEth0 = nws[0]->hasInterface(interfaceNameEth0);
    EXPECT_TRUE(hasInterfaceEth0);

    std::string interfaceNameEth1 = "eth1";
    bool hasInterfaceEth1 = nws[0]->hasInterface(interfaceNameEth1);
    EXPECT_FALSE(hasInterfaceEth1);

    EXPECT_EQ(controller.clearDefaultNetwork(), 1);
}

TEST(network_controller, removeInterfaceFromNetwork)
{
    nmd::network_controller controller;
    controller.createPhysicalNetwork(12, nmd::NetworkPermission::PERMISSION_SYSTEM);
    std::vector<nmd::network *> nws = controller.getNetworks();

    unsigned long size = 1;
    EXPECT_EQ(nws.size(), size);

    std::string interfaceNameEth0 = "eth0";
    int result = controller.addInterfaceToNetwork(12, interfaceNameEth0);
    EXPECT_EQ(result, 1);

    bool hasInterfaceEth0 = nws[0]->hasInterface(interfaceNameEth0);
    EXPECT_TRUE(hasInterfaceEth0);

    std::string interfaceNameEth1 = "eth1";
    bool hasInterfaceEth1 = nws[0]->hasInterface(interfaceNameEth1);
    EXPECT_FALSE(hasInterfaceEth1);

    EXPECT_EQ(controller.removeInterfaceFromNetwork(12, interfaceNameEth0), 1);

    hasInterfaceEth0 = nws[0]->hasInterface(interfaceNameEth0);
    EXPECT_FALSE(hasInterfaceEth0);
}

TEST(network_controller, getFwmarkForNetwork)
{
    nmd::network_controller controller;
    controller.createPhysicalNetwork(12, nmd::NetworkPermission::PERMISSION_SYSTEM);
    std::vector<nmd::network *> nws = controller.getNetworks();

    unsigned long size = 1;
    EXPECT_EQ(nws.size(), size);
    std::cout << controller.getFwmarkForNetwork(12) << std::endl;
    EXPECT_EQ(controller.getFwmarkForNetwork(12), 196620);
}

TEST(network_controller, setPermissionForNetwork)
{
    nmd::network_controller controller;
    controller.createPhysicalNetwork(12, nmd::NetworkPermission::PERMISSION_SYSTEM);
    std::vector<nmd::network *> nws = controller.getNetworks();

    unsigned long size = 1;
    EXPECT_EQ(nws.size(), size);
    std::cout << controller.getFwmarkForNetwork(12) << std::endl;
    controller.setPermissionForNetwork(12, nmd::NetworkPermission::PERMISSION_NONE);
    EXPECT_EQ(controller.getFwmarkForNetwork(12), 196620);
}

TEST(network_controller, getNetwork)
{
    nmd::network_controller controller;
    controller.createPhysicalNetwork(12, nmd::NetworkPermission::PERMISSION_SYSTEM);
    std::vector<nmd::network *> nws = controller.getNetworks();

    unsigned long size = 1;
    EXPECT_EQ(nws.size(), size);
    controller.getNetwork(12);
}