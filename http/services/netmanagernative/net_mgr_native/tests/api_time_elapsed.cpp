#include "time_elapsed.h"
#include <interface_controller.h>
#include <traffic_controller.h>
#include <dnsresolv_controller.h>

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

int main()
{
    nmd::native_nted_service nns;

    GEN_INVOKE_US(createNetwork, 创建网络, nns.networkCreatePhysical(12, nmd::NetworkPermission::PERMISSION_NONE));
    createNetwork();

    GEN_INVOKE_US(addInterface, 网络添加interface, nns.networkAddInterface(12, "eth0"));
    addInterface();

    GEN_INVOKE_US(removeInterface, 网络移除interface, nns.networkRemoveInterface(12, "eth0"));
    removeInterface();

    GEN_INVOKE_US(interfaceAddAddress, interface添加地址, nns.interfaceAddAddress("lo", "192.168.0.12", 32));
    interfaceAddAddress();

    GEN_INVOKE_US(interfaceRemoveAddress, interface移除地址, nns.interfaceDelAddress("lo", "192.168.0.12", 32));
    interfaceRemoveAddress();

    GEN_INVOKE_US(interfaceAddRoute, interface添加路由,
        nns.networkAddRoute(12, "eth0", "47.94.251.146/32", "10.205.127.254"));
    interfaceAddRoute();

    GEN_INVOKE_US(interfaceRemoveRoute, interface删除路由,
        nns.networkRemoveRoute(12, "eth0", "47.94.251.146/32", "10.205.127.254"));
    interfaceRemoveRoute();

    GEN_INVOKE_US(setDefaultNetwork, 设置默认网络, nns.networkSetDefault(12));
    setDefaultNetwork();

    GEN_INVOKE_US(getDefaultNetwork, 获取默认网络, nns.networkGetDefault());
    getDefaultNetwork();

    GEN_INVOKE_US(clearDefaultNetwork, 清除默认网络, nns.networkClearDefault());
    clearDefaultNetwork();

    GEN_INVOKE_US(getInterfaceList, 获取interface列表, nns.interfaceGetList());
    getInterfaceList();

    GEN_INVOKE_US(setPermissionForNetwork, 设置网络权限,
        nns.networkSetPermissionForNetwork(12, nmd::NetworkPermission::PERMISSION_NETWORK));
    setPermissionForNetwork();

    GEN_INVOKE_US(interfaceSetMtu, 设置网络MTU, nns.interfaceSetMtu("eth0", 1500));
    interfaceSetMtu();

    GEN_INVOKE_US(setProcSysNet, 设置网络参数,
        nns.setProcSysNet(nmd::set_proc_sys_net::IPV4, nmd::set_proc_sys_net::CONF, "eth0", "forwarding", "1"));
    setProcSysNet();

    // std::string vv="";
    // GEN_INVOKE_US(getProcSysNet, 获取网络参数, nns.getProcSysNet(nmd::set_proc_sys_net::IPV4,
    // nmd::get_proc_sys_net::CONF, "eth0", "forwarding", &vv)); getProcSysNet();

    GEN_INVOKE_US(destroyNetwork, 销毁网络, nns.networkDestroy(12));
    destroyNetwork();

    GEN_INVOKE_US(getInterfaceConfig, 获取interface配置, nmd::interface_controller::getConfig("eth0"));
    getInterfaceConfig();

    GEN_INVOKE_US(getInterfaceTraffic, 获取interface的流量, nmd::traffic_controller::getInterfaceTraffic("eth0"));
    getInterfaceTraffic();

    GEN_INVOKE_US(getCellularRxTraffic, 获取蜂窝下行流量, nmd::traffic_controller::getCellularRxTraffic());
    getCellularRxTraffic();

    GEN_INVOKE_US(getCellularTxTraffic, 获取蜂窝上行流量, nmd::traffic_controller::getCellularTxTraffic());
    getCellularTxTraffic();

    GEN_INVOKE_US(getRxTetherTraffic, 获取热点下行流量, nmd::traffic_controller::getRxTetherTraffic());
    getRxTetherTraffic();

    GEN_INVOKE_US(getTxTetherTraffic, 获取热点上行流量, nmd::traffic_controller::getTxTetherTraffic());
    getTxTetherTraffic();

    GEN_INVOKE_US(getAllRx, 获取所有下行流量, nmd::traffic_controller::getAllRxTraffic());
    getAllRx();

    GEN_INVOKE_US(getAddTx, 获取所有上行流量, nmd::traffic_controller::getAllTxTraffic());
    getAddTx();

    GEN_INVOKE_US(getUid0Tx, 获取UID0的上行流量, nmd::traffic_controller::getTxUidTraffic(0));
    getUid0Tx();

    GEN_INVOKE_US(getUid0Rx, 获取UID0的下行流量, nmd::traffic_controller::getRxUidTraffic(0));
    getUid0Rx();

    return 1;
}