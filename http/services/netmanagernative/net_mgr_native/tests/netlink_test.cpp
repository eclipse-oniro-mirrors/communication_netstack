#include "netlink_handler.h"
#include "netlink_msg.h"
#include "netlink_socket.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <logger.h>
#include <net/if.h>
#include <route_controller.h>
#include <thread>

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

TEST(netlink, shouldCreateIpRule)
{
    int pid = getpid();
    nmd::netlink_socket netLinker;
    netLinker.setPid(pid);
    netLinker.create(NETLINK_ROUTE);
    netLinker.binding();
    nmd::netlink_msg nlmsg(NLM_F_CREATE | NLM_F_EXCL, 4096, pid);

    struct fib_rule_hdr msg;

    msg.action = FR_ACT_TO_TBL;
    msg.family = AF_INET;
    nlmsg.addRule(RTM_NEWRULE, msg);

    nlmsg.addAttr32(FRA_FWMARK, 0x33);
    nlmsg.addAttr32(FRA_FWMASK, 0xFF);

    msg.table = RT_TABLE_UNSPEC;
    nlmsg.addAttr32(FRA_TABLE, 1009);

    netLinker.sendNetlinkMsgToKernel(nlmsg.getNetLinkMessage());

    netLinker.shutdown();
}

TEST(netlink, shouldDeleteIpRule)
{
    int pid = getpid();
    nmd::netlink_socket netLinker;
    netLinker.setPid(pid);
    netLinker.create(NETLINK_ROUTE);
    netLinker.binding();
    nmd::netlink_msg nlmsg(NLM_F_CREATE | NLM_F_EXCL, 4096, pid);

    struct fib_rule_hdr msg;

    msg.action = FR_ACT_TO_TBL;
    msg.family = AF_INET;
    nlmsg.addRule(RTM_DELRULE, msg);

    nlmsg.addAttr32(FRA_FWMARK, 0x33);
    nlmsg.addAttr32(FRA_FWMASK, 0xFF);

    msg.table = RT_TABLE_UNSPEC;
    nlmsg.addAttr32(FRA_TABLE, 1009);

    netLinker.sendNetlinkMsgToKernel(nlmsg.getNetLinkMessage());

    netLinker.shutdown();
}

TEST(netlink, shouldAddRoute)
{
    int pid = getpid();

    nmd::netlink_socket netLinker;
    netLinker.setPid(pid);
    netLinker.create(NETLINK_ROUTE);
    netLinker.binding();

    nmd::netlink_msg nlmsg(NLM_F_CREATE | NLM_F_EXCL, 1024, pid);
    struct rtmsg msg;
    msg.rtm_family = AF_INET;
    msg.rtm_dst_len = 32;
    msg.rtm_protocol = RTPROT_STATIC;
    msg.rtm_type = RTN_UNICAST;

    nlmsg.addRoute(RTM_NEWROUTE, msg);
    msg.rtm_table = RT_TABLE_UNSPEC;
    nlmsg.addAttr32(RTA_TABLE, 1006);

    nmd::_inet_addr dst;
    const char *dstStr = "47.94.251.146/32";
    int a = 0;
    if ((a = nmd::route_controller::read_addr(dstStr, &dst)) != 1) {
        LogError << "dest parse failed:" << a << endl;
    } else {
        msg.rtm_family = dst.family;
        msg.rtm_dst_len = dst.bitlen;
        if (dst.family == AF_INET) {
            msg.rtm_scope = RT_SCOPE_LINK;
        } else if (dst.family == AF_INET6) {
            msg.rtm_scope = RT_SCOPE_UNIVERSE;
        }
        nlmsg.addAttr(RTA_DST, (char *)dst.data, dst.bitlen / 8);
    }

    nmd::_inet_addr gw;
    const char *gwStr = "10.205.127.254";
    if ((a = nmd::route_controller::read_addr_gw(gwStr, &gw)) != 1) {
        LogError << "gw parse failed:" << a << endl;
    } else {
        if (gw.bitlen != 0) {
            msg.rtm_scope = 0;
            msg.rtm_family = gw.family;
        }
        nlmsg.addAttr(RTA_GATEWAY, (char *)gw.data, gw.bitlen / 8);
    }

    nlmsg.addAttr32(RTA_OIF, if_nametoindex("eth0"));
    netLinker.sendNetlinkMsgToKernel(nlmsg.getNetLinkMessage());
    netLinker.setOnDataReceiveHandler(
        [](int fd, char *buf, ssize_t size) { std::cout << fd << size << buf << std::endl; });
    netLinker.acceptAndListen();

    netLinker.shutdown();
}

TEST(netlink, shouldDeleteRoute)
{
    int pid = getpid();

    nmd::netlink_socket netLinker;
    netLinker.setPid(pid);
    netLinker.create(NETLINK_ROUTE);
    netLinker.binding();

    nmd::netlink_msg nlmsg(0, 1024, pid);
    struct rtmsg msg;
    msg.rtm_family = AF_INET;
    msg.rtm_dst_len = 32;
    nlmsg.addRoute(RTM_DELROUTE, msg);

    msg.rtm_table = RT_TABLE_UNSPEC;
    nlmsg.addAttr32(RTA_TABLE, 1006);

    nmd::_inet_addr dst;
    const char *dstStr = "47.94.251.146/32";
    int a = 0;
    if ((a = nmd::route_controller::read_addr(dstStr, &dst)) != 1) {
        LogError << "dest parse failed:" << a << endl;
    } else {
        msg.rtm_family = dst.family;
        msg.rtm_dst_len = dst.bitlen;
        if (dst.family == AF_INET) {
            msg.rtm_scope = RT_SCOPE_LINK;
        } else if (dst.family == AF_INET6) {
            msg.rtm_scope = RT_SCOPE_UNIVERSE;
        }
        nlmsg.addAttr(RTA_DST, (char *)dst.data, dst.bitlen / 8);
    }

    nmd::_inet_addr gw;
    const char *gwStr = "10.205.127.254";
    if ((a = nmd::route_controller::read_addr_gw(gwStr, &gw)) != 1) {
        LogError << "gw parse failed:" << a << endl;
    } else {
        if (gw.bitlen != 0) {
            msg.rtm_scope = 0;
            msg.rtm_family = gw.family;
        }
        nlmsg.addAttr(RTA_GATEWAY, (char *)gw.data, gw.bitlen / 8);
    }

    nlmsg.addAttr32(RTA_OIF, if_nametoindex("eth0"));
    netLinker.sendNetlinkMsgToKernel(nlmsg.getNetLinkMessage());
    netLinker.setOnDataReceiveHandler(
        [](int fd, char *buf, ssize_t size) { std::cout << fd << size << buf << std::endl; });
    netLinker.acceptAndListen();

    netLinker.shutdown();
}

DISABLE_WARNING_POP
