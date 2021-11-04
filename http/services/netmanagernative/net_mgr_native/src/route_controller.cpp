#include "route_controller.h"

#include "bitcast.h"
#include "fwmark.h"
#include "interface_utils.h"
#include "iptables_process.h"
//#include "logger.h"
#include "netlink_manager.h"
#include "warning_disable.h"
#include <arpa/inet.h>
#include <iostream>
#include <linux/fib_rules.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <map>
#include <net/if.h>
#include <netlink_msg.h>
#include <netlink_socket.h>
#include <sstream>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <mutex>
#include "netnative_log_wrapper.h"

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

constexpr char PING[] = "#PING\n";
constexpr size_t PING_SIZE = sizeof(PING) - 1;

const char *const ROUTE_TABLE_NAME_LOCAL = "local";
const char *const ROUTE_TABLE_NAME_MAIN = "main";

const uint32_t ROUTE_TABLE_LOCAL_NETWORK = 97;
const uint32_t ROUTE_TABLE_LEGACY_NETWORK = 98;
const uint32_t ROUTE_TABLE_LEGACY_SYSTEM = 99;

const char *const ROUTE_TABLE_NAME_LOCAL_NETWORK = "local_network";
const char *const ROUTE_TABLE_NAME_LEGACY_NETWORK = "legacy_network";
const char *const ROUTE_TABLE_NAME_LEGACY_SYSTEM = "legacy_system";

const char *const RT_TABLES_PATH = "/data/misc/net/rt_tables";

const uint32_t NETID_UNSET = 0u;

namespace OHOS {
namespace nmd {

std::map<std::string, uint32_t> route_controller::interfaceToTable_;

route_controller::route_controller() {}

route_controller::~route_controller() {}

int route_controller::addInterfaceToDefaultNetwork(const char *interfaceName, NetworkPermission permission)
{
    uint32_t table = getRouteTableForInterface(interfaceName);
    if (table == RT_TABLE_UNSPEC) {
        return -ESRCH;
    }

    fwmark mark;
    mark.bits.netId = NETID_UNSET;
    mark.bits.permission = permission;

    uint32_t fwmask = 0xFFFF;

    nmd::netlink_socket netLinker;
    netLinker.create(NETLINK_ROUTE);
    nmd::netlink_msg nlmsg(NLM_F_CREATE | NLM_F_EXCL, 1024, netlink_manager::getPid());
    struct fib_rule_hdr msg;
    msg.action = FR_ACT_TO_TBL;
    msg.family = AF_INET;
    nlmsg.addRule(RTM_NEWRULE, msg);
    nlmsg.addAttr32(FRA_FWMARK, mark.val);
    nlmsg.addAttr32(FRA_FWMASK, fwmask);
    msg.table = RT_TABLE_UNSPEC;

    if (table == RT_TABLE_UNSPEC) {
        return -1;
    }
    nlmsg.addAttr32(FRA_TABLE, table);

    return netLinker.sendNetlinkMsgToKernel(nlmsg.getNetLinkMessage());
}
int route_controller::removeInterfaceFromDefaultNetwork(const char *interfaceName, NetworkPermission permission)
{
    uint32_t table = getRouteTableForInterface(interfaceName);
    if (table == RT_TABLE_UNSPEC) {
        return -ESRCH;
    }

    fwmark mark;
    mark.bits.netId = NETID_UNSET;
    mark.bits.permission = permission;

    uint32_t fwmask = 0xFFFF;

    nmd::netlink_socket netLinker;
    netLinker.create(NETLINK_ROUTE);
    nmd::netlink_msg nlmsg(NLM_F_CREATE | NLM_F_EXCL, 1024, netlink_manager::getPid());
    struct fib_rule_hdr msg;
    msg.action = FR_ACT_TO_TBL;
    msg.family = AF_INET;
    nlmsg.addRule(RTM_DELRULE, msg);
    nlmsg.addAttr32(FRA_FWMARK, mark.val);
    nlmsg.addAttr32(FRA_FWMASK, fwmask);
    msg.table = RT_TABLE_UNSPEC;

    if (table == RT_TABLE_UNSPEC) {
        return -1;
    }
    nlmsg.addAttr32(FRA_TABLE, table);

    return netLinker.sendNetlinkMsgToKernel(nlmsg.getNetLinkMessage());
}

void addTableName(uint32_t table, const std::string &name, std::string *contents)
{
    char tableString[10];
    snprintf(tableString, sizeof(tableString), "%u", table);
    *contents += tableString;
    *contents += " ";
    *contents += name;
    *contents += "\n";
}

void route_controller::updateTableNamesFile()
{
    std::string contents;

    addTableName(RT_TABLE_LOCAL, ROUTE_TABLE_NAME_LOCAL, &contents);
    addTableName(RT_TABLE_MAIN, ROUTE_TABLE_NAME_MAIN, &contents);

    addTableName(ROUTE_TABLE_LOCAL_NETWORK, ROUTE_TABLE_NAME_LOCAL_NETWORK, &contents);
    addTableName(ROUTE_TABLE_LEGACY_NETWORK, ROUTE_TABLE_NAME_LEGACY_NETWORK, &contents);
    addTableName(ROUTE_TABLE_LEGACY_SYSTEM, ROUTE_TABLE_NAME_LEGACY_SYSTEM, &contents);

    for (const auto &entry : interfaceToTable_) {
        addTableName(entry.second, entry.first, &contents);
    }

    int fd = -1;
    if ((fd = open(RT_TABLES_PATH, O_CREAT | O_EXCL, 0777)) != -1) {
        write(fd, contents.c_str(), contents.length());
    }
}

int route_controller::createChildChains(const char *table, const char *parentChain, const char *childChain)
{
    std::string command("*");
    command.append(table);
    command.append("\n");

    command.append(":");
    command.append(childChain);
    command.append(" -\n");

    command.append("-A ");
    command.append(parentChain);
    command.append(" -j ");
    command.append(childChain);
    command.append("\n");

    command.append("COMMIT\n");

    // if (route_controller::executeIptablesRestore(command) == -1) {
    //    return -1;
    //}

    return 0;
}

std::mutex iptablesRestoreLock;
int route_controller::executeIptablesRestore(std::string command)
{
    std::lock_guard<std::mutex> lk(iptablesRestoreLock);
    std::shared_ptr<iptables_process> process = iptables_process::forkAndExecute();

    NETNATIVE_LOGE("executeIptablesRestore::write to iptable_restore process failed");
    if (write(process->stdin_, command.c_str(), command.length()) == -1) {
        NETNATIVE_LOGE("executeIptablesRestore::write to iptable_restore process failed");
    }
    NETNATIVE_LOGE("executeIptablesRestore::write to iptable_restore process succ");
    if (write(process->stdin_, PING, PING_SIZE) == -1) {
        NETNATIVE_LOGE("executeIptablesRestore::ping to iptable_restore process failed");
    }

    std::string result;
    if (!process->waitForAck(result)) {
        // LogError << "iptables restore failed." << endl;
        NETNATIVE_LOGE("executeIptablesRestore::iptables restore failed.");
        return -1;
    }
    NETNATIVE_LOGI("executeIptablesRestore::command::%{public}s", command.c_str());
    NETNATIVE_LOGI("executeIptablesRestore::command::iptables restored:%{public}s", result.c_str());
    // common::logger::info() << "command:" << command << endl;
    // common::logger::info() << "iptables restored:" << result << endl;
    return 0;
}

int nmd::route_controller::addInterfaceToPhysicalNetwork(
    uint16_t netId, const char *interfaceName, NetworkPermission permission)
{
    // 0. build a fwmark which contain the netid and permision
    fwmark mark;
    mark.bits.netId = netId;
    mark.bits.permission = permission;

    uint32_t fwmask = 0xFFFFFFFF;

    //	 modify incoming package with fwmark
    //	 *mangle
    //	 -A routectrl_mangle_INPUT -i interface -j MARK --set-mark fwmark/mask
    //	 COMMIT
    std::string command("*mangle\n-A routectrl_mangle_INPUT -i ");
    command.append(interfaceName);
    command.append(" -j MARK --set-mark 0x");

    std::stringstream stream;
    stream << std::hex << mark.val;
    std::string fwmarkString(stream.str());
    command.append(fwmarkString);
    command.append("/0x");

    std::stringstream maskStream;
    maskStream << std::hex << fwmask;
    std::string fwmaskString(maskStream.str());

    command.append(fwmaskString);
    command.append("\n");

    command.append("COMMIT\n");

    if (route_controller::executeIptablesRestore(command) == -1) {
        return -1;
    }

    // 2. change out rule
    nmd::netlink_socket netLinker;
    netLinker.create(NETLINK_ROUTE);
    nmd::netlink_msg nlmsg(NLM_F_CREATE | NLM_F_EXCL, 1024, netlink_manager::getPid());
    struct fib_rule_hdr msg;
    msg.action = FR_ACT_TO_TBL;
    msg.family = AF_INET;
    nlmsg.addRule(RTM_NEWRULE, msg);
    nlmsg.addAttr32(FRA_FWMARK, mark.val);
    nlmsg.addAttr32(FRA_FWMASK, fwmask);
    msg.table = RT_TABLE_UNSPEC;

    uint32_t table = getRouteTableForInterface(interfaceName);
    if (table == RT_TABLE_UNSPEC) {
        return -1;
    }
    nlmsg.addAttr32(FRA_TABLE, table);

    netLinker.sendNetlinkMsgToKernel(nlmsg.getNetLinkMessage());

    updateTableNamesFile();
    return 1;
}

int nmd::route_controller::removeInterfaceFromPhysicalNetwork(
    uint16_t netId, const char *interfaceName, NetworkPermission permission)
{
    fwmark mark;
    mark.bits.netId = netId;
    mark.bits.permission = permission;
    uint32_t fwmask = 0xFFFFFFFF;

    nmd::netlink_socket netLinker;
    netLinker.create(NETLINK_ROUTE);
    nmd::netlink_msg nlmsg(NLM_F_CREATE | NLM_F_EXCL, 1024, netlink_manager::getPid());
    struct fib_rule_hdr msg;
    msg.action = FR_ACT_TO_TBL;
    msg.family = AF_INET;
    nlmsg.addRule(RTM_DELRULE, msg);
    nlmsg.addAttr32(FRA_FWMARK, mark.val);
    nlmsg.addAttr32(FRA_FWMASK, fwmask);
    msg.table = RT_TABLE_UNSPEC;

    uint32_t table = getRouteTableForInterface(interfaceName);
    if (table == RT_TABLE_UNSPEC) {
        return -1;
    }
    nlmsg.addAttr32(FRA_TABLE, table);
    netLinker.sendNetlinkMsgToKernel(nlmsg.getNetLinkMessage());

    interfaceToTable_.erase(interfaceName);

    updateTableNamesFile();

    return 1;
}

int nmd::route_controller::read_addr_gw(const char *addr, _inet_addr *res)
{
    std::string addressString(addr);
    if (strchr(addr, ':')) {
        res->family = AF_INET6;
        res->bitlen = 128;
    } else {
        res->family = AF_INET;
        res->bitlen = 32;
    }

    return inet_pton(res->family, addressString.c_str(), res->data);
}

int nmd::route_controller::read_addr(const char *addr, _inet_addr *res)
{
    const char *slash = strchr(addr, '/');
    const char *prefixlenString = slash + 1;
    if (!slash || !*prefixlenString) {
        return -EINVAL;
    }

    char *endptr = nullptr;
    unsigned templen = strtoul(prefixlenString, &endptr, 10);
    if (*endptr || templen > 255) {
        return -EINVAL;
    }
    res->prefixlen = templen;

    std::string addressString(addr, slash - addr);
    if (strchr(addr, ':')) {
        res->family = AF_INET6;
        res->bitlen = 128;
    } else {
        res->family = AF_INET;
        res->bitlen = 32;
    }

    return inet_pton(res->family, addressString.c_str(), res->data);
}

int nmd::route_controller::addRoute(int, std::string interfaceName, std::string destination, std::string nextHop)
{
    nmd::netlink_socket netLinker;
    netLinker.create(NETLINK_ROUTE);
    nmd::netlink_msg nlmsg(NLM_F_CREATE | NLM_F_EXCL, 1024, netlink_manager::getPid());

    struct rtmsg msg;
    msg.rtm_family = AF_INET;
    msg.rtm_dst_len = 32;
    msg.rtm_protocol = RTPROT_STATIC;
    msg.rtm_scope = RT_SCOPE_NOWHERE;
    msg.rtm_type = RTN_UNICAST;

    nlmsg.addRoute(RTM_NEWROUTE, msg);

    unsigned int table = getRouteTableForInterface(interfaceName.c_str());
    if (table == RT_TABLE_UNSPEC) {
        return -1;
    }
    msg.rtm_table = RT_TABLE_UNSPEC;
    nlmsg.addAttr32(RTA_TABLE, table);

    _inet_addr dst;
    int readAddrResult = 0;
    if ((readAddrResult = read_addr(destination.c_str(), &dst)) != 1) {
        // LogError << "dest parse failed:" << readAddrResult << endl;
        NETNATIVE_LOGE("dest parse failed:%{public}d", readAddrResult);
        return -1;
    } else {
        msg.rtm_family = dst.family;
        msg.rtm_dst_len = dst.bitlen;
        if (dst.family == AF_INET) {
            msg.rtm_scope = RT_SCOPE_LINK;
        } else if (dst.family == AF_INET6) {
            msg.rtm_scope = RT_SCOPE_UNIVERSE;
        }
        nlmsg.addAttr(RTA_DST, (void *)dst.data, dst.bitlen / 8);
    }

    _inet_addr gw;
    if ((readAddrResult = read_addr_gw(nextHop.c_str(), &gw)) != 1) {
        // LogError << "gw parse failed:" << readAddrResult << endl;
        NETNATIVE_LOGE("gw parse failed:%{public}d", readAddrResult);
        return -1;
    } else {
        if (gw.bitlen != 0) {
            msg.rtm_scope = 0;
            msg.rtm_family = gw.family;
        }
        nlmsg.addAttr(RTA_GATEWAY, (void *)gw.data, gw.bitlen / 8);
    }
    unsigned int index = if_nametoindex(interfaceName.c_str());
    nlmsg.addAttr32(RTA_OIF, index);

    netLinker.sendNetlinkMsgToKernel(nlmsg.getNetLinkMessage());

    return 1;
}

int route_controller::removeRoute(int, std::string interfaceName, std::string destination, std::string nextHop)
{
    nmd::netlink_socket netLinker;
    netLinker.create(NETLINK_ROUTE);
    nmd::netlink_msg nlmsg(NLM_F_CREATE | NLM_F_EXCL, 1024, netlink_manager::getPid());

    struct rtmsg msg;
    msg.rtm_family = AF_INET;
    msg.rtm_dst_len = 32;
    msg.rtm_scope = RT_SCOPE_NOWHERE;

    nlmsg.addRoute(RTM_DELROUTE, msg);

    unsigned int table = getRouteTableForInterface(interfaceName.c_str());
    if (table == RT_TABLE_UNSPEC) {
        return -1;
    }
    msg.rtm_table = RT_TABLE_UNSPEC;
    nlmsg.addAttr32(RTA_TABLE, table);

    _inet_addr dst;
    int readAddrResult = 0;
    if ((readAddrResult = read_addr(destination.c_str(), &dst)) != 1) {
        // LogError << "dest parse failed:" << readAddrResult << endl;
        NETNATIVE_LOGE("dest parse failed:%{public}d", readAddrResult);
        return -1;
    } else {
        msg.rtm_family = dst.family;
        msg.rtm_dst_len = dst.bitlen;
        if (dst.family == AF_INET) {
            msg.rtm_scope = RT_SCOPE_LINK;
        } else if (dst.family == AF_INET6) {
            msg.rtm_scope = RT_SCOPE_UNIVERSE;
        }
        nlmsg.addAttr(RTA_DST, (void *)dst.data, dst.bitlen / 8);
    }

    _inet_addr gw;
    if ((readAddrResult = read_addr_gw(nextHop.c_str(), &gw)) != 1) {
        // LogError << "gw parse failed:" << readAddrResult << endl;
        NETNATIVE_LOGE("gw parse failed:%{public}d", readAddrResult);
        return -1;
    } else {
        if (gw.bitlen != 0) {
            msg.rtm_scope = 0;
            msg.rtm_family = gw.family;
        }
        nlmsg.addAttr(RTA_GATEWAY, (void *)gw.data, gw.bitlen / 8);
    }
    unsigned int index = if_nametoindex(interfaceName.c_str());
    nlmsg.addAttr32(RTA_OIF, index);

    netLinker.sendNetlinkMsgToKernel(nlmsg.getNetLinkMessage());

    return 1;
}

uint32_t route_controller::getRouteTableForInterface(const char *interfaceName)
{
    auto iter = interfaceToTable_.find(interfaceName);
    if (iter != interfaceToTable_.end()) {
        return iter->second;
    }

    uint32_t index = if_nametoindex(interfaceName);
    if (index == 0) {
        // LogError << "[RouteController] cannot find interface " << interfaceName << ",error:" << strerror(errno)
        //		 << endl;
        NETNATIVE_LOGE(
            "[RouteController] cannot find interface %{public}s,error:%{public}s", interfaceName, strerror(errno));
        return RT_TABLE_UNSPEC;
    }
    index += 1000;
    interfaceToTable_[interfaceName] = index;
    return index;
}

} // namespace nmd
} // namespace OHOS
DISABLE_WARNING_POP
