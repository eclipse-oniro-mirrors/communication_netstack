#include <iostream>
#include <vector>
#include <functional>
#include <chrono>
#include <thread>

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

#include "time_elapsed.h"
#include "dnsresolv_client_test.h"
#include <fwmark_client.h>

namespace nwG {
void createPhysicalNetwork(nmd::native_nted_service service)
{
    GEN_INVOKE_US(
        createNetwork, 创建网络, service.networkCreatePhysical(12, nmd::NetworkPermission::PERMISSION_NONE));
    createNetwork();

    GEN_INVOKE_US(addInterface, 网络添加interface, service.networkAddInterface(12, "eth0"));
    addInterface();

    GEN_INVOKE_US(removeInterface, 网络移除interface, service.networkRemoveInterface(12, "eth0"));
    removeInterface();

    GEN_INVOKE_US(interfaceAddAddress, interface添加地址, service.interfaceAddAddress("lo", "192.168.0.12", 32));
    interfaceAddAddress();

    GEN_INVOKE_US(interfaceRemoveAddress, interface移除地址, service.interfaceDelAddress("lo", "192.168.0.12", 32));
    interfaceRemoveAddress();

    GEN_INVOKE_US(interfaceAddRoute, interface添加路由,
        service.networkAddRoute(12, "eth0", "47.94.251.146/32", "10.205.127.254"));
    interfaceAddRoute();

    GEN_INVOKE_US(interfaceRemoveRoute, interface删除路由,
        service.networkRemoveRoute(12, "eth0", "47.94.251.146/32", "10.205.127.254"));
    interfaceRemoveRoute();

    GEN_INVOKE_US(setDefaultNetwork, 设置默认网络, service.networkSetDefault(12));
    setDefaultNetwork();

    GEN_INVOKE_US(getDefaultNetwork, 获取默认网络, service.networkGetDefault());
    getDefaultNetwork();

    GEN_INVOKE_US(clearDefaultNetwork, 清除默认网络, service.networkClearDefault());
    clearDefaultNetwork();

    GEN_INVOKE_US(getInterfaceList, 获取interface列表, service.interfaceGetList());
    getInterfaceList();

    GEN_INVOKE_US(setPermissionForNetwork, 设置网络权限,
        service.networkSetPermissionForNetwork(12, nmd::NetworkPermission::PERMISSION_NETWORK));
    setPermissionForNetwork();

    GEN_INVOKE_US(interfaceSetMtu, 设置网络MTU, service.interfaceSetMtu("eth0", 1500));
    interfaceSetMtu();

    GEN_INVOKE_US(setProcSysNet, 设置网络参数,
        service.setProcSysNet(nmd::set_proc_sys_net::IPV4, nmd::set_proc_sys_net::CONF, "eth0", "forwarding", "1"));
    setProcSysNet();
}

void destroyNetwork(nmd::native_nted_service service)
{
    GEN_INVOKE_US(removeInterface, 网络移除interface, service.networkRemoveInterface(12, "eth0"));
    removeInterface();

    GEN_INVOKE_US(networkDestroy, 网络销毁, service.networkDestroy(12));
    networkDestroy();
}
}; // namespace nwG

namespace dnsG {
dnsresolv_client_test dnsClientTest;
void getAddrInfo(nmd::native_nted_service)
{
    GEN_INVOKE_US(dnsResolve, DNS解析, dnsClientTest.get_addr_info_test("cenocloud.com"));
    dnsResolve();
}
}; // namespace dnsG

namespace fwmarkG {
void bindSocket(nmd::native_nted_service)
{
    nmd::fwmark_client client;
    nmd::fwmark_command command;
    command.cmdId = nmd::fwmark_command::SELECT_NETWORK;
    command.fd = 999999999;
    command.netId = 12;
    client.send(&command);

    GEN_INVOKE_US(bindSocketToNetwork, 绑定socket, client.send(&command));
    bindSocketToNetwork();
}
}; // namespace fwmarkG

namespace trfcG {
void getTraffic(nmd::native_nted_service service)
{
    GEN_INVOKE_US(getInterfaceRxTraffic, 获取interface下行的流量, service.getIfaceRxBytes("eth0"));
    getInterfaceRxTraffic();

    GEN_INVOKE_US(getInterfacTxTraffic, 获取interface上行的流量, service.getIfaceTxBytes("eth0"));
    getInterfacTxTraffic();

    GEN_INVOKE_US(getAllRx, 获取所有下行流量, service.getAllRxBytes());
    getAllRx();

    GEN_INVOKE_US(getAllTx, 获取所有上行流量, service.getAllTxBytes());
    getAllTx();

    GEN_INVOKE_US(getUid0Tx, 获取UID0的上行流量, service.getUidTxBytes(0));
    getUid0Tx();

    GEN_INVOKE_US(getUid0Rx, 获取UID0的下行流量, service.getUidRxBytes(0));
    getUid0Rx();

    GEN_INVOKE_US(getCellularRxTraffic, 获取蜂窝下行流量, service.getCellularRxBytes());
    getCellularRxTraffic();

    GEN_INVOKE_US(getCellularTxTraffic, 获取蜂窝上行流量, service.getCellularTxBytes());
    getCellularTxTraffic();

    GEN_INVOKE_US(getRxTetherTraffic, 获取热点下行流量, service.getTetherRxBytes());
    getRxTetherTraffic();

    GEN_INVOKE_US(getTxTetherTraffic, 获取热点上行流量, service.getTetherTxBytes());
    getTxTetherTraffic();
}
}; // namespace trfcG

void startStableTest(nmd::native_nted_service service, int groupDuration, int apiDuration, int times)
{
    std::vector<std::function<void(nmd::native_nted_service service)>> networkAndRouteGroup;
    networkAndRouteGroup.push_back(nwG::createPhysicalNetwork);
    networkAndRouteGroup.push_back(nwG::destroyNetwork);

    dnsG::dnsClientTest.initConfig();
    std::vector<std::function<void(nmd::native_nted_service service)>> dnsGroup;
    dnsGroup.push_back(dnsG::getAddrInfo);

    std::vector<std::function<void(nmd::native_nted_service service)>> fwmarkGroup;
    fwmarkGroup.push_back(fwmarkG::bindSocket);

    std::vector<std::function<void(nmd::native_nted_service service)>> trafficGroup;
    trafficGroup.push_back(trfcG::getTraffic);

    std::vector<std::vector<std::function<void(nmd::native_nted_service service)>>> groups;
    // groups.push_back(networkAndRouteGroup);
    groups.push_back(dnsGroup);
    // groups.push_back(fwmarkGroup);
    // groups.push_back(trafficGroup);

    for (int t = 0; t < times; t++) {
        for (unsigned long i = 0; i < groups.size(); i++) {
            for (unsigned long j = 0; j < groups.at(i).size(); j++) {
                groups.at(i).at(j)(service);
                std::this_thread::sleep_for(std::chrono::milliseconds(apiDuration));
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(groupDuration));
        }
    }
}

int main(int argc, char *args[])
{
    int groupDuration = 0;
    int apiDuration = 0;
    int times = 200;

    if (argc > 1) {
        groupDuration = atoi(args[1]);
        apiDuration = atoi(args[2]);
        times = atoi(args[3]);
    }

    nmd::native_nted_service service;
    service.init();

    int pid = getpid();
    nmd::netlink_manager manager(pid);
    std::thread nlManager([&] { manager.start(); });

    nmd::fwmark_server fwmarkServer;
    std::thread fwserve([&] { fwmarkServer.start(); });

    nmd::dnsresolv_service dnsresolvService;
    std::thread dnsresolvServe([&] { dnsresolvService.start(); });

    // wait for servers started
    std::this_thread::sleep_for(std::chrono::milliseconds(3000));
    // nmd::traffic_init::start_traffic_account();

    startStableTest(service, groupDuration, apiDuration, times);
}