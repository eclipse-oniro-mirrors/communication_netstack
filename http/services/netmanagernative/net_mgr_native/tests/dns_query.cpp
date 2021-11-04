#include "main.h"
#include "dnsresolv.h"
#include "native_netd_service.h"
#include "netlink_manager.h"
#include "fwmark_server.h"
#include "dnsresolv_service.h"

#include "netnative_log_wrapper.h"
#include <iostream>

const uint16_t TEST_NETID = 65501;
const uint32_t NETID_UNSET = 0u;
void jobRunBadParam()
{
    auto job = std::make_shared<OHOS::nmd::dnsresolv_job>(-1, nullptr, 0, nullptr);
    // ASSERT_THAT(job, ::testing::Ne(nullptr));
    if (job == nullptr) {
        std::cout << "job is null!" << std::endl;
    }
    job->run();
}

void TestSetResolverConfig()
{
    NETNATIVE_LOGE("TestSetResolverConfig:: begin");
    OHOS::nmd::NativeNetdService service;
    service.init();

    int pid = getpid();
    OHOS::nmd::netlink_manager manager(pid);
    std::thread nlManager([&] { manager.start(); });

    OHOS::nmd::fwmark_server fwmarkServer;
    std::thread fwserve([&] { fwmarkServer.start(); });

    OHOS::nmd::dnsresolv_service dnsresolvService;
    std::thread dnsresolvServe([&] { dnsresolvService.start(); });

    nlManager.detach();
    fwserve.detach();
    dnsresolvServe.detach();

    NETNATIVE_LOGE("TestSetResolverConfig:: createNetworkCache");
    //先创建
    dnsresolvService.createNetworkCache(NETID_UNSET);
    NETNATIVE_LOGE("TestSetResolverConfig::end createNetworkCache");

    const OHOS::nmd::dnsresolver_params param = {
        NETID_UNSET, 0, 1, {"8.8.8.8", "114.114.114.114"}, {"baidu.com", "google.com"}};
    NETNATIVE_LOGE("TestSetResolverConfig begin to setResolverConfig");
    dnsresolvService.setResolverConfig(param);
    NETNATIVE_LOGE("TestSetResolverConfig end ");
}

void TestCreateNetworkCache()
{
    OHOS::nmd::NativeNetdService service;
    service.init();

    int pid = getpid();
    OHOS::nmd::netlink_manager manager(pid);
    std::thread nlManager([&] { manager.start(); });

    OHOS::nmd::fwmark_server fwmarkServer;
    std::thread fwserve([&] { fwmarkServer.start(); });

    OHOS::nmd::dnsresolv_service dnsresolvService;
    std::thread dnsresolvServe([&] { dnsresolvService.start(); });

    nlManager.detach();
    fwserve.detach();
    dnsresolvServe.detach();

    NETNATIVE_LOGE("TestCreateNetworkCache:: begin");
    dnsresolvService.createNetworkCache(NETID_UNSET);
    NETNATIVE_LOGE("TestCreateNetworkCache:: end");
}

void TestFlushNetworkCache()
{
    OHOS::nmd::NativeNetdService service;
    service.init();

    int pid = getpid();
    OHOS::nmd::netlink_manager manager(pid);
    std::thread nlManager([&] { manager.start(); });

    OHOS::nmd::fwmark_server fwmarkServer;
    std::thread fwserve([&] { fwmarkServer.start(); });

    OHOS::nmd::dnsresolv_service dnsresolvService;
    std::thread dnsresolvServe([&] { dnsresolvService.start(); });

    nlManager.detach();
    fwserve.detach();
    dnsresolvServe.detach();

    NETNATIVE_LOGE("TestflushNetworkCache:: begin");
    dnsresolvService.flushNetworkCache(TEST_NETID);
    NETNATIVE_LOGE("TestflushNetworkCache:: end");
}

void TestDestoryNetworkCache()
{
    OHOS::nmd::NativeNetdService service;
    service.init();

    int pid = getpid();
    OHOS::nmd::netlink_manager manager(pid);
    std::thread nlManager([&] { manager.start(); });

    OHOS::nmd::fwmark_server fwmarkServer;
    std::thread fwserve([&] { fwmarkServer.start(); });

    OHOS::nmd::dnsresolv_service dnsresolvService;
    std::thread dnsresolvServe([&] { dnsresolvService.start(); });

    nlManager.detach();
    fwserve.detach();
    dnsresolvServe.detach();

    NETNATIVE_LOGE("destoryNetworkCache:: begin");
    dnsresolvService.destoryNetworkCache(NETID_UNSET);
    NETNATIVE_LOGE("destoryNetworkCache:: end");
}

void TestGetaddrinfo()
{
    OHOS::nmd::NativeNetdService service;
    service.init();

    int pid = getpid();
    OHOS::nmd::netlink_manager manager(pid);
    std::thread nlManager([&] { manager.start(); });

    OHOS::nmd::fwmark_server fwmarkServer;
    std::thread fwserve([&] { fwmarkServer.start(); });

    OHOS::nmd::dnsresolv_service dnsresolvService;
    std::thread dnsresolvServe([&] { dnsresolvService.start(); });

    nlManager.detach();
    fwserve.detach();
    dnsresolvServe.detach();

    //先创建
    NETNATIVE_LOGE("createNetworkCache:: begin");
    dnsresolvService.createNetworkCache(NETID_UNSET);

    const OHOS::nmd::dnsresolver_params param = {
        OHOS::nmd::NETID_UNSET, 0, 1, {"8.8.8.8", "114.114.114.114"}, {"baidu.com", "google.com"}};
    //配置
    NETNATIVE_LOGE("setResolverConfig:: begin");
    dnsresolvService.setResolverConfig(param);

    char hostName[OHOS::nmd::MAX_NAME_LEN];
    strncpy(hostName, "www.baidu.com", OHOS::nmd::MAX_NAME_LEN);
    char serverName[OHOS::nmd::MAX_NAME_LEN] = "";
    struct addrinfo hints;
    bzero(&hints, sizeof(addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;
    hints.ai_protocol = 0;

    //域名解析
    NETNATIVE_LOGI("getaddrinfo:: begin");
    struct addrinfo *res1, *res_p1;
    int ret = dnsresolvService.getaddrinfo(hostName, serverName, &hints, &res1);
    if (ret != 0) {
        // printf("getaddrinfo: %s\n", gai_strerror(ret));
        NETNATIVE_LOGE("getaddrinfo error: %{public}s", gai_strerror(ret));
        return;
    }

    for (res_p1 = res1; res_p1 != NULL; res_p1 = res_p1->ai_next) {
        char host[1024] = {0};
        ret = getnameinfo(res_p1->ai_addr, res_p1->ai_addrlen, host, sizeof(host), NULL, 0, NI_NUMERICHOST);
        if (ret != 0)
            printf("getnameinfo: %s\n", gai_strerror(ret));
        else
            printf("ip: %s\n", host);
    }
    freeaddrinfo(res1);
    NETNATIVE_LOGI("getaddrinfo:: end");
}
