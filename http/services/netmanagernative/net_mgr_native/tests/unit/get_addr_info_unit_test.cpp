
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "get_addr_info.h"
#include "dnsresolv.h"
#include <arpa/inet.h>

class get_addr_info_unit_test : public ::testing::Test {
public:
    virtual void SetUp() override {}
    virtual void TearDown() override {}

protected:
    const uint16_t TEST_NETID = 65501;
    const uint16_t TEST_MARK = 65501;

public:
    static int validateHints(const addrinfo *hints)
    {
        return nmd::get_addr_info::validateHints(hints);
    }

    static int checkHostNameAndExplore(
        const addrinfo &ai, const char *hostname, const char *servname, addrinfo *cur)
    {
        return nmd::get_addr_info::checkHostNameAndExplore(ai, hostname, servname, cur);
    }

    static int getPort(const addrinfo *ai, const char *servname, bool matchonly)
    {
        return nmd::get_addr_info::getPort(ai, servname, matchonly);
    }

    static int strToNumber(const char *p)
    {
        return nmd::get_addr_info::strToNumber(p);
    }

    static int exploreNull(const addrinfo *pai, const char *servname, addrinfo **res)
    {
        return nmd::get_addr_info::exploreNull(pai, servname, res);
    }

    static const nmd::afd *findAfd(int af)
    {
        return nmd::get_addr_info::findAfd(af);
    }

    static addrinfo *getAi(const addrinfo *pai, const nmd::afd *pafd, const char *addr)
    {
        return nmd::get_addr_info::getAi(pai, pafd, addr);
    }

    static int ip6StrToScopeid(const char *scope, const struct sockaddr_in6 &sin6, uint32_t &scopeid)
    {
        return nmd::get_addr_info::ip6StrToScopeid(scope, sin6, scopeid);
    }

    static int exploreNumericScope(const addrinfo *pai, const char *hostname, const char *servname, addrinfo **res)
    {
        return nmd::get_addr_info::exploreNumericScope(pai, hostname, servname, res);
    }
    static bool haveIpv6(uint32_t mark, uid_t uid)
    {
        return nmd::get_addr_info::haveIpv6(mark, uid);
    }
    static bool haveIpv4(uint32_t mark, uid_t uid)
    {
        return nmd::get_addr_info::haveIpv4(mark, uid);
    }
    static int sendViaTcp(nmd::dns_res_state &statp, nmd::dns_res_params &params, const uint8_t *buf,
        const size_t buflen, uint8_t *ans, size_t anssiz, int &terrno, const size_t ns, time_t &at, int &rcode,
        int &delay)
    {
        return nmd::get_addr_info::sendViaTcp(
            statp, params, buf, buflen, ans, anssiz, terrno, ns, at, rcode, delay);
    }
    static int sendViaUdp(nmd::dns_res_state &statp, nmd::dns_res_params &params, const uint8_t *buf,
        const size_t buflen, uint8_t *ans, size_t anssiz, int &terrno, size_t &ns, bool &needTcp,
        int &gotsomewhere, time_t &at, int &rcode, int &delay)
    {
        return nmd::get_addr_info::sendViaUdp(
            statp, params, buf, buflen, ans, anssiz, terrno, ns, needTcp, gotsomewhere, at, rcode, delay);
    }

    static bool sockEq(const struct sockaddr *socka, const struct sockaddr *sockb)
    {
        return nmd::get_addr_info::sockEq(socka, sockb);
    }
};

TEST_F(get_addr_info_unit_test, validateHints)
{
    auto ret = get_addr_info_unit_test::validateHints(nullptr);
    EXPECT_NE(ret, 0);

    addrinfo hints;
    bzero(&hints, sizeof(addrinfo));
    ret = get_addr_info_unit_test::validateHints(&hints);
    EXPECT_EQ(ret, 0);

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;
    hints.ai_protocol = 0;
    ret = get_addr_info_unit_test::validateHints(&hints);
    EXPECT_EQ(ret, 0);
}

TEST_F(get_addr_info_unit_test, checkHostNameAndExplore)
{
    addrinfo ai = {};
    addrinfo sentinel = {};
    addrinfo *cur = &sentinel;

    auto ret = get_addr_info_unit_test::checkHostNameAndExplore(ai, nullptr, nullptr, cur);
    EXPECT_EQ(ret, 0);
    if (nullptr != cur->ai_next) {
        freeaddrinfo(cur->ai_next);
    }
}

TEST_F(get_addr_info_unit_test, getPort)
{
    addrinfo ai = {};
    auto ret = get_addr_info_unit_test::getPort(&ai, nullptr, true);
    EXPECT_EQ(ret, 0);

    ai.ai_family = AF_INET;
    ai.ai_socktype = SOCK_RAW;
    ret = get_addr_info_unit_test::getPort(&ai, "", true);
    EXPECT_THAT(ret, ::testing::Eq(EAI_SERVICE));

    ai.ai_socktype = SOCK_DGRAM;
    ret = get_addr_info_unit_test::getPort(&ai, "", true);
    EXPECT_THAT(ret, ::testing::Eq(EAI_SERVICE));

    ai.ai_flags = AI_NUMERICSERV;
    ai.ai_socktype = SOCK_DGRAM;
    ret = get_addr_info_unit_test::getPort(&ai, "", true);
    EXPECT_THAT(ret, ::testing::Eq(EAI_NONAME));
}

TEST_F(get_addr_info_unit_test, strToNumber)
{
    auto ret = get_addr_info_unit_test::strToNumber("");
    EXPECT_EQ(ret, -1);

    ret = get_addr_info_unit_test::strToNumber("53");
    EXPECT_EQ(ret, 53);

    ret = get_addr_info_unit_test::strToNumber("4294967296");
    EXPECT_EQ(ret, -1);
}

TEST_F(get_addr_info_unit_test, exploreNull)
{
    addrinfo ai = {};
    addrinfo sentinel = {};
    addrinfo *cur = &sentinel;

    auto ret = get_addr_info_unit_test::exploreNull(&ai, nullptr, &cur);
    EXPECT_EQ(ret, 0);
}

TEST_F(get_addr_info_unit_test, findAfd)
{
    auto ret = get_addr_info_unit_test::findAfd(PF_UNSPEC);
    EXPECT_THAT(ret, ::testing::Eq(nullptr));
}

TEST_F(get_addr_info_unit_test, getAi)
{
    addrinfo ai = {};
    ai.ai_flags = AI_CANONNAME;
    ai.ai_family = AF_INET;
    ai.ai_socktype = SOCK_STREAM;
    ai.ai_protocol = IPPROTO_TCP;

    const nmd::afd *pafd = findAfd(ai.ai_family);
    EXPECT_THAT(pafd, ::testing::Ne(nullptr));

    uint8_t *buff[nmd::MAX_PACKET] = {};

    auto ret = get_addr_info_unit_test::getAi(&ai, pafd, reinterpret_cast<const char *>(buff));
    if (nullptr != ret) {
        freeaddrinfo(ret);
    }
}

TEST_F(get_addr_info_unit_test, ip6StrToScopeid)
{
    struct sockaddr_in6 in6 = {};
    bzero(&in6, sizeof(sockaddr_in6));
    uint32_t scopeID(0);
    auto ret = get_addr_info_unit_test::ip6StrToScopeid("", in6, scopeID);
    EXPECT_THAT(ret, ::testing::Eq(-1));

    in6.sin6_family = AF_INET6;
    const char *ipv6Addr = "02:42:ac:11:00:02";
    inet_pton(AF_INET6, ipv6Addr, in6.sin6_addr.s6_addr);
    ret = get_addr_info_unit_test::ip6StrToScopeid("10", in6, scopeID);
    EXPECT_THAT(ret, ::testing::Eq(0));
    EXPECT_THAT(scopeID, ::testing::Eq(10u));
}

TEST_F(get_addr_info_unit_test, exploreNumericScope)
{
    struct addrinfo ai = {};
    ai.ai_family = AF_INET6;
    struct addrinfo *res(nullptr);
    auto ret = get_addr_info_unit_test::exploreNumericScope(&ai, "02:42:ac:11:00:02%10", nullptr, &res);
    EXPECT_THAT(ret, ::testing::Eq(0));
    EXPECT_THAT(res, ::testing::Eq(nullptr));
}

TEST_F(get_addr_info_unit_test, haveIpv6)
{
    auto ret = get_addr_info_unit_test::haveIpv6(nmd::MARK_UNSET, nmd::NET_CONTEXT_INVALID_UID);
    EXPECT_THAT(ret, ::testing::Eq(false));
}

TEST_F(get_addr_info_unit_test, haveIpv4)
{
    auto ret = get_addr_info_unit_test::haveIpv4(nmd::MARK_UNSET, nmd::NET_CONTEXT_INVALID_UID);
    EXPECT_THAT(ret, ::testing::Eq(true));
}

TEST_F(get_addr_info_unit_test, sendViaTcp)
{
    nmd::netd_net_context netcontext = {};
    netcontext.appNetId = TEST_NETID;
    netcontext.appMark = TEST_MARK;
    netcontext.dnsNetId = TEST_NETID;
    netcontext.dnsMark = TEST_MARK;
    netcontext.uid = nmd::NET_CONTEXT_INVALID_UID;
    netcontext.pid = nmd::NET_CONTEXT_INVALID_PID;

    nmd::dns_res_state res;
    res.init(&netcontext);
    res.nsaddrs = {nmd::common::net_utils::ip_sock_addr::toIPSockAddr("8.8.8.8", 53),
        nmd::common::net_utils::ip_sock_addr::toIPSockAddr("114.114.114.114", 53)};
    nmd::dns_res_params params;
    params.baseTimeoutMsec = 0;
    params.retryCount = 1;

    uint8_t buf[] = {0xa8, 0xd2, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x63, 0x65,
        0x6e, 0x6f, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x1c, 0x00, 0x01};
    std::vector<uint8_t> answer = std::vector<uint8_t>(nmd::MAX_PACKET, 0); // buffer to put answer
    int terrno = ETIME;
    int rcode = nmd::RCODE_INTERNAL_ERROR;
    time_t query_time = 0;
    int delay = 0;
    size_t ns = 0;
    int resplen = get_addr_info_unit_test::sendViaTcp(
        res, params, buf, sizeof(buf), answer.data(), answer.size(), terrno, ns, query_time, rcode, delay);
    EXPECT_THAT(resplen, ::testing::Ne(0));
    EXPECT_THAT(terrno, ::testing::Eq(0));

    ns = 20;
    resplen = get_addr_info_unit_test::sendViaTcp(
        res, params, buf, sizeof(buf), answer.data(), answer.size(), terrno, ns, query_time, rcode, delay);
    EXPECT_THAT(resplen, ::testing::Eq(-1));
    EXPECT_THAT(terrno, ::testing::Eq(EINVAL));
}

TEST_F(get_addr_info_unit_test, sendViaUdp)
{
    nmd::netd_net_context netcontext = {};
    netcontext.appNetId = TEST_NETID;
    netcontext.appMark = TEST_MARK;
    netcontext.dnsNetId = TEST_NETID;
    netcontext.dnsMark = TEST_MARK;
    netcontext.uid = nmd::NET_CONTEXT_INVALID_UID;
    netcontext.pid = nmd::NET_CONTEXT_INVALID_PID;

    nmd::dns_res_state res;
    res.init(&netcontext);
    res.nsaddrs = {nmd::common::net_utils::ip_sock_addr::toIPSockAddr("8.8.8.8", 53),
        nmd::common::net_utils::ip_sock_addr::toIPSockAddr("114.114.114.114", 53)};
    nmd::dns_res_params params;
    params.baseTimeoutMsec = 0;
    params.retryCount = 1;

    uint8_t buf[] = {0xa8, 0xd2, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x63, 0x65,
        0x6e, 0x6f, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x1c, 0x00, 0x01};
    std::vector<uint8_t> answer = std::vector<uint8_t>(nmd::MAX_PACKET, 0); // buffer to put answer
    int terrno = ETIME;
    int rcode = nmd::RCODE_INTERNAL_ERROR;
    time_t query_time = 0;
    int delay = 0;
    size_t ns = 0;
    bool useTcp = false;
    int gotsomewhere = 0;

    int resplen = get_addr_info_unit_test::sendViaUdp(res, params, buf, sizeof(buf), answer.data(), answer.size(),
        terrno, ns, useTcp, gotsomewhere, query_time, rcode, delay);
    EXPECT_THAT(resplen, ::testing::Ne(0));
    EXPECT_THAT(terrno, ::testing::Eq(0));

    ns = 20;
    resplen = get_addr_info_unit_test::sendViaUdp(res, params, buf, sizeof(buf), answer.data(), answer.size(),
        terrno, ns, useTcp, gotsomewhere, query_time, rcode, delay);
    EXPECT_THAT(resplen, ::testing::Eq(-1));
    EXPECT_THAT(terrno, ::testing::Eq(EINVAL));
}

TEST_F(get_addr_info_unit_test, sockEq)
{
    auto ret = get_addr_info_unit_test::sockEq(nullptr, nullptr);
    EXPECT_THAT(ret, ::testing::Eq(false));

    sockaddr_in addra;
    bzero(&addra, sizeof(addra));
    sockaddr_in addrb;
    bzero(&addrb, sizeof(addrb));
    ret = get_addr_info_unit_test::sockEq(
        reinterpret_cast<struct sockaddr *>(&addra), reinterpret_cast<struct sockaddr *>(&addrb));
    EXPECT_THAT(ret, ::testing::Eq(false));

    addra.sin_family = AF_INET, addra.sin_addr.s_addr = inet_addr("192.168.0.1");
    addrb.sin_family = AF_INET, addrb.sin_addr.s_addr = inet_addr("192.168.0.1");
    ret = get_addr_info_unit_test::sockEq(
        reinterpret_cast<struct sockaddr *>(&addra), reinterpret_cast<struct sockaddr *>(&addrb));
    EXPECT_THAT(ret, ::testing::Eq(true));

    DISABLE_WARNING_PUSH
    DISABLE_WARNING_C99_EXTENSIONS
    struct sockaddr_in6 sin6a = {.sin6_family = AF_INET6,
        .sin6_addr.s6_addr = {// 2000::
            0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
    struct sockaddr_in6 sin6b = {.sin6_family = AF_INET6,
        .sin6_addr.s6_addr = {// 2000::
            0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
    DISABLE_WARNING_POP
    ret = get_addr_info_unit_test::sockEq(
        reinterpret_cast<struct sockaddr *>(&sin6a), reinterpret_cast<struct sockaddr *>(&sin6b));
    EXPECT_THAT(ret, ::testing::Eq(true));

    ret = get_addr_info_unit_test::sockEq(
        reinterpret_cast<struct sockaddr *>(&addra), reinterpret_cast<struct sockaddr *>(&sin6b));
    EXPECT_THAT(ret, ::testing::Eq(false));
}