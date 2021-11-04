#include "dnsresolv.h"
#include "dnsresolv_controller.h"
#include "dnsresolv_service.h"
#include "get_addr_info.h"
#include "warning_disable.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "time_elapsed.h"

namespace {
int hostnameToIp(const char *hostname)
{
    int ret = 0;

    if (!hostname) {
        printf("invalid params\n");
        return -1;
    }

    struct addrinfo hints;
    struct addrinfo *res, *res_p;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;
    hints.ai_protocol = 0;

    ret = nmd::dnsresolv_controller::getaddrinfo(hostname, NULL, &hints, &res);
    if (ret != 0) {
        printf("getaddrinfo: %s\n", gai_strerror(ret));
        return -1;
    }

    for (res_p = res; res_p != NULL; res_p = res_p->ai_next) {
        char host[1024] = {0};
        ret = getnameinfo(res_p->ai_addr, res_p->ai_addrlen, host, sizeof(host), NULL, 0, NI_NUMERICHOST);
        if (ret != 0)
            printf("getnameinfo: %s\n", gai_strerror(ret));
        else
            printf("%s ip: %s\n", hostname, host);
    }

    freeaddrinfo(res);
    return ret;
}

int hostnameToIpV6(const char *hostname)
{
    int ret = 0;

    if (!hostname) {
        printf("invalid params\n");
        return -1;
    }

    struct addrinfo hints;
    struct addrinfo *res, *res_p;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC; /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;
    hints.ai_protocol = IPPROTO_TCP;

    ret = nmd::dnsresolv_controller::getaddrinfo(hostname, "https", &hints, &res);
    if (ret != 0) {
        printf("getaddrinfo: %s\n", gai_strerror(ret));
        return -1;
    }

    struct sockaddr_in *ipv4;
    struct sockaddr_in6 *ipv6;
    char host[1024] = {0};
    bzero(host, 1024);
    for (res_p = res; res_p != NULL; res_p = res_p->ai_next) {
        switch (res_p->ai_family) {
            case AF_INET:
                ipv4 = reinterpret_cast<struct sockaddr_in *>(res_p->ai_addr);
                inet_ntop(res_p->ai_family, &ipv4->sin_addr, host, sizeof(host));
                break;
            case AF_INET6:
                ipv6 = reinterpret_cast<struct sockaddr_in6 *>(res_p->ai_addr);
                inet_ntop(res_p->ai_family, &ipv6->sin6_addr, host, sizeof(host));
                break;
        }

        printf("[IPv%d]%s\n", res_p->ai_family == AF_INET ? 4 : 6, host);
    }

    freeaddrinfo(res);
    return ret;
}

int ipToHostname(const char *ip)
{
    int ret = 0;

    if (!ip) {
        printf("invalid params\n");
        return -1;
    }

    struct addrinfo hints;
    struct addrinfo *res, *res_p;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME | AI_NUMERICHOST;
    hints.ai_protocol = 0;

    ret = nmd::dnsresolv_controller::getaddrinfo(ip, NULL, &hints, &res);
    if (ret != 0) {
        printf("getaddrinfo: %s\n", gai_strerror(ret));
        return -1;
    }

    for (res_p = res; res_p != NULL; res_p = res_p->ai_next) {
        char host[1024] = {0};
        ret = getnameinfo(res_p->ai_addr, res_p->ai_addrlen, host, sizeof(host), NULL, 0, NI_NAMEREQD);
        if (ret != 0)
            printf("getnameinfo: %s\n", gai_strerror(ret));
        else
            printf("hostname: %s\n", host);
    }

    freeaddrinfo(res);
    return ret;
}
} // namespace

class dnsresolv_test : public ::testing::Test {
public:
    virtual void SetUp() override
    {
        resolver_.createNetworkCache(TEST_NETID);
        resolver_.createNetworkCache(nmd::NETID_UNSET);
    }
    virtual void TearDown() override
    {
        resolver_.flushNetworkCache(TEST_NETID);
        resolver_.flushNetworkCache(nmd::NETID_UNSET);

        resolver_.destoryNetworkCache(TEST_NETID);
        resolver_.destoryNetworkCache(nmd::NETID_UNSET);
    }

protected:
    const uint16_t TEST_NETID = 65501;
    nmd::dnsresolv_service resolver_;
};

TEST_F(dnsresolv_test, setGetDnsresolvParams)
{
    const nmd::dnsresolver_params params = {
        TEST_NETID, 0, 1, {"8.8.8.8", "114.114.114.114"}, {"baidu.com", "google.com"}};
    int ret = resolver_.setResolverConfig(params);
    EXPECT_EQ(ret, 0);

    std::vector<std::string> servers;
    std::vector<std::string> domains;
    nmd::dns_res_params getParam;
    ret = resolver_.getResolverInfo(params.netId, servers, domains, getParam);
    EXPECT_EQ(ret, 0);

    ASSERT_EQ(servers.size(), 2u);
    ASSERT_EQ(domains.size(), 2u);
    EXPECT_THAT(servers[0], ::testing::Eq("8.8.8.8"));
    EXPECT_THAT(servers[1], ::testing::Eq("114.114.114.114"));
    EXPECT_THAT(domains[0], ::testing::Eq("baidu.com"));
    EXPECT_THAT(domains[1], ::testing::Eq("google.com"));
}

TEST_F(dnsresolv_test, getAddrInfoForNet)
{
    const nmd::dnsresolver_params params = {
        TEST_NETID, 0, 1, {"8.8.8.8", "114.114.114.114"}, {"baidu.com", "google.com"}};
    int ret = resolver_.setResolverConfig(params);
    ASSERT_EQ(ret, 0);

    struct addrinfo hints;
    struct addrinfo *res, *res_p;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;
    hints.ai_protocol = 0;

    ret = nmd::dnsresolv_controller::getaddrinfoForNet(
        "cenocloud.com", NULL, &hints, TEST_NETID, nmd::MARK_UNSET, &res);
    ASSERT_EQ(ret, 0);

    for (res_p = res; res_p != NULL; res_p = res_p->ai_next) {
        char host[1024] = {0};
        ret = getnameinfo(res_p->ai_addr, res_p->ai_addrlen, host, sizeof(host), NULL, 0, NI_NUMERICHOST);
        if (ret != 0)
            printf("getnameinfo: %s\n", gai_strerror(ret));
        else
            printf("ip: %s\n", host);
    }

    freeaddrinfo(res);
}

TEST_F(dnsresolv_test, hostnameToIp)
{
    const nmd::dnsresolver_params params = {
        nmd::NETID_UNSET, 0, 1, {"8.8.8.8", "114.114.114.114"}, {"baidu.com", "google.com"}};
    resolver_.setResolverConfig(params);
    int ret = hostnameToIp("baidu.com");
    ASSERT_EQ(ret, 0);

    ret = hostnameToIp("pan");
    ASSERT_EQ(ret, 0);
}

TEST_F(dnsresolv_test, getAddrinfo)
{
    const nmd::dnsresolver_params params = {
        nmd::NETID_UNSET, 0, 1, {"8.8.8.8", "114.114.114.114"}, {"baidu.com", "google.com"}};
    resolver_.setResolverConfig(params);
    GEN_INVOKE_US(hoooooo, dnsTime, hostnameToIp("www.baidu.com"));
    int ret = hoooooo();
    ASSERT_EQ(ret, 0);

    ret = hoooooo();
    ASSERT_EQ(ret, 0);
}

TEST_F(dnsresolv_test, getAddrinfoFromHostFile)
{
    int ret = hostnameToIp("localhost");
    ASSERT_EQ(ret, 0);
}

TEST_F(dnsresolv_test, IPToHostName)
{
    const nmd::dnsresolver_params params = {
        nmd::NETID_UNSET, 0, 1, {"8.8.8.8", "114.114.114.114"}, {"baidu.com", "google.com"}};
    resolver_.setResolverConfig(params);
    int ret = ipToHostname("127.0.0.1");
    ASSERT_EQ(ret, 0);
}

TEST_F(dnsresolv_test, hostnameToIpFailed)
{
    const nmd::dnsresolver_params params = {
        nmd::NETID_UNSET, 0, 1, {"8.8.8.8", "114.114.114.114"}, {"baidu.com", "google.com"}};
    resolver_.setResolverConfig(params);
    int ret = hostnameToIp("unknow");
    EXPECT_EQ(ret, -1);

    resolver_.destoryNetworkCache(nmd::NETID_UNSET);
    ret = hostnameToIp("www.baidu.com");
    EXPECT_EQ(ret, -1);
}

TEST_F(dnsresolv_test, getDnsResolvInfo)
{
    const nmd::dnsresolver_params params = {
        nmd::NETID_UNSET, 0, 1, {"8.8.8.8", "114.114.114.114"}, {"baidu.com", "google.com"}};
    auto ret = resolver_.setResolverConfig(params);
    EXPECT_THAT(ret, ::testing::Eq(0));

    std::vector<std::string> servers;
    std::vector<std::string> domains;
    nmd::dns_res_params resolvParam;
    ret = resolver_.getResolverInfo(params.netId, servers, domains, resolvParam);
    EXPECT_THAT(ret, ::testing::Eq(0));
    EXPECT_THAT(servers, ::testing::Eq(params.servers));
    EXPECT_THAT(domains, ::testing::Eq(params.domains));
    EXPECT_THAT(resolvParam.baseTimeoutMsec, ::testing::Eq(params.baseTimeoutMsec));
    EXPECT_THAT(resolvParam.retryCount, ::testing::Eq(params.retryCount));
}

TEST_F(dnsresolv_test, getDnsResolvInfoFailed)
{
    std::vector<std::string> servers;
    std::vector<std::string> domains;
    nmd::dns_res_params resolvParam;
    auto ret = resolver_.getResolverInfo(TEST_NETID, servers, domains, resolvParam);
    EXPECT_THAT(ret, ::testing::Eq(0));
    EXPECT_THAT(servers.size(), ::testing::Eq(0u));
    EXPECT_THAT(domains.size(), ::testing::Eq(0u));

    ret = resolver_.destoryNetworkCache(TEST_NETID);
    EXPECT_THAT(ret, ::testing::Eq(0));
    ret = resolver_.getResolverInfo(TEST_NETID, servers, domains, resolvParam);
    EXPECT_THAT(ret, ::testing::Eq(-1));
}

TEST_F(dnsresolv_test, getAddrinfoIpv6)
{
    const nmd::dnsresolver_params params = {
        nmd::NETID_UNSET, 0, 1, {"8.8.8.8", "114.114.114.114"}, {"baidu.com", "google.com"}};
    resolver_.setResolverConfig(params);
    int ret = hostnameToIpV6("www.google.com");
    ASSERT_EQ(ret, 0);
}
#include "dnsresolv_client_test.h"
TEST_F(dnsresolv_test, get_addr_info_client_test)
{
    dnsresolv_client_test dnsClientTest;
    auto ret = dnsClientTest.initConfig();
    EXPECT_EQ(ret, 0);

    ret = dnsClientTest.get_addr_info_test("www.baidu.com");
    EXPECT_EQ(ret, 0);
    ret = dnsClientTest.get_addr_info_test("www.baidu.com");
    EXPECT_EQ(ret, 0);
}
