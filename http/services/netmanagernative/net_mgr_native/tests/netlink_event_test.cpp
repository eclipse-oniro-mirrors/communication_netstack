#include "netlink_handler.h"
#include "netlink_msg.h"
#include "netlink_socket.h"
#include "netlink_event.h"
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

TEST(netlink_event, shouldGetNetlinkTypeName)
{
    nmd::netlink_event event;
    EXPECT_EQ(event.rtMessageName(RTM_NEWLINK), "RTM_NEWLINK");
    EXPECT_EQ(event.rtMessageName(RTM_DELLINK), "RTM_DELLINK");
    EXPECT_EQ(event.rtMessageName(RTM_NEWADDR), "RTM_NEWADDR");
    EXPECT_EQ(event.rtMessageName(RTM_DELADDR), "RTM_DELADDR");
    EXPECT_EQ(event.rtMessageName(RTM_NEWROUTE), "RTM_NEWROUTE");
    EXPECT_EQ(event.rtMessageName(RTM_DELROUTE), "RTM_DELROUTE");
    EXPECT_EQ(event.rtMessageName(RTM_NEWRULE), "RTM_NEWRULE");
    EXPECT_EQ(event.rtMessageName(RTM_DELRULE), "RTM_DELRULE");
    EXPECT_EQ(event.rtMessageName(RTM_NEWNDUSEROPT), "RTM_NEWNDUSEROPT");
    EXPECT_EQ(event.rtMessageName(10086), nullptr);
}

TEST(netlink_event, shouldParseIpRuleMesssage)
{
    int pid = getpid();
    nmd::netlink_msg nlmsg(NLM_F_CREATE | NLM_F_EXCL, 4096, pid);
    struct fib_rule_hdr msg;

    msg.action = FR_ACT_TO_TBL;
    msg.family = AF_INET;
    nlmsg.addRule(RTM_NEWRULE, msg);

    nlmsg.addAttr32(FRA_FWMARK, 0x33);
    nlmsg.addAttr32(FRA_FWMASK, 0xFF);

    msg.table = RT_TABLE_UNSPEC;
    nlmsg.addAttr32(FRA_TABLE, 1009);

    nmd::netlink_event event;
    EXPECT_TRUE(event.parseRuleMessage(nlmsg.getNetLinkMessage()));
}

TEST(netlink_event, shouldParseRouteMesssage)
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

    nmd::netlink_event event;
    event.parseRouteMessage(nlmsg.getNetLinkMessage());
}

TEST(netlink_event, shouldParseNetlinkMesssage)
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

    nmd::netlink_event event;
    event.parseNetLinkMessage((char *)nlmsg.getNetLinkMessage(), 4096);
}

TEST(netlink_event, parseInterfaceInfoInfoMessage)
{
    int pid = getpid();

    nmd::netlink_socket netLinker;
    netLinker.setPid(pid);
    netLinker.create(NETLINK_ROUTE);
    netLinker.binding();

    nmd::netlink_msg nlmsg(NLM_F_CREATE | NLM_F_EXCL, 1024, pid);
    struct ifinfomsg msg;
    msg.ifi_index = if_nametoindex("eth0");

    nlmsg.addInterfaceInfo(RTM_NEWROUTE, msg);

    nlmsg.addAttr(IFLA_IFNAME, (char *)"eth0", 16);

    nmd::netlink_event event;
    event.parseInterfaceInfoInfoMessage(nlmsg.getNetLinkMessage());
}

TEST(netlink_event, parseInterafaceAddressMessage)
{
    int pid = getpid();

    nmd::netlink_socket netLinker;
    netLinker.setPid(pid);
    netLinker.create(RTM_NEWADDR);
    netLinker.binding();

    nmd::netlink_msg nlmsg(NLM_F_CREATE | NLM_F_EXCL, 1024, pid);
    struct ifaddrmsg msg;
    msg.ifa_index = if_nametoindex("eth0");

    nlmsg.addInterfaceAddress(RTM_NEWADDR, msg);

    in_addr addr;
    nlmsg.addAttr(IFA_ADDRESS, &addr, sizeof(addr));

    nmd::netlink_event event;
    event.parseInterafaceAddressMessage(nlmsg.getNetLinkMessage());
}

TEST(netlink_event, addInterfaceAddressCacheInfo)
{
    int pid = getpid();
    nmd::netlink_msg nlmsg(NLM_F_CREATE | NLM_F_EXCL, 1024, pid);
    struct ifa_cacheinfo msg = {0, 0, 0, 0};
    nlmsg.addInterfaceAddressCacheInfo(0, msg);
    int len = nlmsg.getNetLinkMessage()->nlmsg_len;
    int len1 = NLMSG_LENGTH(sizeof(struct rta_cacheinfo));
    EXPECT_EQ(len, len1);
}

TEST(netlink_event, addNeighborDiscovery)
{
    int pid = getpid();
    nmd::netlink_msg nlmsg(NLM_F_CREATE | NLM_F_EXCL, 1024, pid);
    struct ndmsg msg = {0, 0, 0, 0, 0, 0, 0};
    nlmsg.addNeighborDiscovery(0, msg);
    int len = nlmsg.getNetLinkMessage()->nlmsg_len;
    int len1 = NLMSG_LENGTH(sizeof(struct ndmsg));
    EXPECT_EQ(len, len1);
}

TEST(netlink_event, addNeighborDiscoveryAttributeCacheInfo)
{
    int pid = getpid();
    nmd::netlink_msg nlmsg(NLM_F_CREATE | NLM_F_EXCL, 1024, pid);
    struct nda_cacheinfo nda = {0, 0, 0, 0};
    nlmsg.addNeighborDiscoveryAttributeCacheInfo(0, nda);
    int len = nlmsg.getNetLinkMessage()->nlmsg_len;
    int len1 = NLMSG_LENGTH(sizeof(struct nda_cacheinfo));
    EXPECT_EQ(len, len1);
}

TEST(netlink_event, addTrafficControl)
{
    int pid = getpid();
    nmd::netlink_msg nlmsg(NLM_F_CREATE | NLM_F_EXCL, 1024, pid);
    struct tcmsg msg = {0, 0, 0, 0, 0, 0, 0};
    nlmsg.addTrafficControl(0, msg);
    int len = nlmsg.getNetLinkMessage()->nlmsg_len;
    int len1 = NLMSG_LENGTH(sizeof(struct tcmsg));
    EXPECT_EQ(len, len1);
}

TEST(netlink_event, addRouteNextHop)
{
    int pid = getpid();
    nmd::netlink_msg nlmsg(NLM_F_CREATE | NLM_F_EXCL, 1024, pid);
    struct rtnexthop msg = {0, 0, 0, 0};
    nlmsg.addRouteNextHop(0, msg);
    int len = nlmsg.getNetLinkMessage()->nlmsg_len;
    int len1 = NLMSG_LENGTH(sizeof(struct rtnexthop));
    EXPECT_EQ(len, len1);
}

TEST(netlink_event, addRouteAttributeCacheInfo)
{
    int pid = getpid();
    nmd::netlink_msg nlmsg(NLM_F_CREATE | NLM_F_EXCL, 1024, pid);
    struct rta_cacheinfo msg = {0, 0, 0, 0, 0, 0, 0, 0};
    nlmsg.addRouteAttributeCacheInfo(0, msg);
    int len = nlmsg.getNetLinkMessage()->nlmsg_len;
    int len1 = NLMSG_LENGTH(sizeof(struct rta_cacheinfo));
    EXPECT_EQ(len, len1);
}

DISABLE_WARNING_POP
