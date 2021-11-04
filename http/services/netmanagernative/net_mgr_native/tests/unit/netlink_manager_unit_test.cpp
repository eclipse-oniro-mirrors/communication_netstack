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
#include "netlink_manager.h"
#include "netlink_listener.h"

TEST(netlinkManager, init)
{
    nmd::netlink_manager manager(getpid());
    manager.setPid(1);
    manager.getReporter()->getListener().onInterfaceAddressUpdated("128.9.12.3", "eth0", 0, 0);
    manager.getReporter()->getListener().onInterfaceAddressRemoved("128.9.12.3", "eth0", 0, 0);
    manager.getReporter()->getListener().onInterfaceAdded("eth0");
    manager.getReporter()->getListener().onInterfaceRemoved("eth0");
    manager.getReporter()->getListener().onInterfaceChanged("eth0", true);
    manager.getReporter()->getListener().onInterfaceLinkStateChanged("eth0", true);
    manager.getReporter()->getListener().onRouteChanged(true, "192.168.1.1", "192.168.1.1", "eth0");
    EXPECT_EQ(manager.getPid(), 1);
}

TEST(netlink_listener, stopListen)
{
    int pid = getpid();
    nmd::netlink_listener nls(AF_INET, pid);
    nls.stopListen();
    EXPECT_EQ(false, nls.getNetlinkListenerState());
}
