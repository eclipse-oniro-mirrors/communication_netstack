#include "native_netd_service.h"
#include "netlink_manager.h"
#include "fwmark_server.h"
#include "dnsresolv_service.h"
#include <thread>

void native_netd_service_init()
{
    auto netdService_ = std::make_unique<nmd::NativeNetdService>();
    netdService_->init();

    int32_t pid = getpid();
    auto manager_ = std::make_unique<nmd::netlink_manager>(pid);
    std::thread nlManager([&] { manager_->start(); });

    auto fwmarkServer_ = std::make_unique<nmd::fwmark_server>();
    std::thread fwserve([&] { fwmarkServer_->start(); });

    auto dnsResolvService_ = std::make_unique<nmd::dnsresolv_service>();
    std::thread dnsresolvServe([&] { dnsResolvService_->start(); });

    nlManager.detach();
    fwserve.detach();
    dnsresolvServe.detach();
}
