#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <chrono>
#include <stdint.h>
#include <iostream>
#include <iptables_process.h>
#include <native_netd_service.h>
#include "netlink_manager.h"
#include "netlink_msg.h"
#include "netlink_socket.h"
#include <arpa/inet.h>
#include <asm/types.h>
#include <dnsresolv_controller.h>
#include <errno.h>
#include <fcntl.h>
#include <fwmark_server.h>
#include <iostream>
#include <linux/limits.h>
#include <linux/netlink.h>
#include <logger.h>
#include <memory>
#include <net/if.h>
#include <route_controller.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include "dnsresolv_service.h"
#include <logger.h>
#include "traffic_init.h"

DISABLE_WARNING_PUSH
DISABLE_WARNING_SIGN_CONVERSION
DISABLE_WARNING_IMPLICIT_INT_CONVERSION
DISABLE_WARNING_SHORTEN_64_TO_32
DISABLE_WARNING_SIGN_CONVERSION
DISABLE_WARNING_SIGN_COMPARE
DISABLE_WARNING_OLD_STYLE_CAST
DISABLE_WARNING_CAST_ALIGN
DISABLE_WARNING_SIGN_CONVERSION
DISABLE_WARNING_C99_EXTENSIONS

int main(int argc, char *argv[])
{
    nmd::native_nted_service service;
    service.init();

    int pid = getpid();
    nmd::netlink_manager manager(pid);
    std::thread nlManager([&] { manager.start(); });

    nmd::fwmark_server fwmarkServer;
    std::thread fwserve([&] { fwmarkServer.start(); });

    nmd::dnsresolv_service dnsresolvService;
    std::thread dnsresolvServe([&] { dnsresolvService.start(); });

    // nmd::traffic_init::start_traffic_account();

    testing::InitGoogleTest(&argc, argv);
    int result = RUN_ALL_TESTS();

    manager.stop();
    fwmarkServer.stop();
    dnsresolvService.stop();

    std::cout << "Test finished, you can terminate by press Ctrl + C" << std::endl;

    nlManager.join();
    fwserve.join();
    dnsresolvServe.join();

    return result;
}

DISABLE_WARNING_POP