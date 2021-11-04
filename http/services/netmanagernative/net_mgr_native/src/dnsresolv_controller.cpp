#include "dnsresolv_controller.h"
#include "dnsresolv.h"
#include "dnsresolv_cache.h"
#include "get_addr_info.h"
#include "netnative_log_wrapper.h"

namespace OHOS {
namespace nmd {
int nmd::dnsresolv_controller::getaddrinfo(
    const char *hostname, const char *servname, const struct addrinfo *hints, struct addrinfo **res)
{
    return getaddrinfoForNet(hostname, servname, hints, NETID_UNSET, MARK_UNSET, res);
}

int nmd::dnsresolv_controller::getaddrinfoForNet(const char *hostname, const char *servname,
    const struct addrinfo *hints, uint16_t netid, unsigned mark, struct addrinfo **res)
{
    netd_net_context netcontext = {};
    netcontext.appNetId = netid;
    netcontext.appMark = mark;
    netcontext.dnsNetId = netid;
    netcontext.dnsMark = mark;
    netcontext.uid = NET_CONTEXT_INVALID_UID;

    return nmd::get_addr_info::getaddrinfoFornetContext(hostname, servname, hints, &netcontext, res);
}

int nmd::dnsresolv_controller::getaddrinfoFornetContext(const char *hostname, const char *servname,
    const addrinfo *hints, const netd_net_context &netcontext, addrinfo **res)
{
    return nmd::get_addr_info::getaddrinfoFornetContext(hostname, servname, hints, &netcontext, res);
}

int nmd::dnsresolv_controller::setResolverConfig(const nmd::dnsresolver_params &resolvParams)
{
    return dnsresolv_cache::setResolverConfig(resolvParams);
}

int nmd::dnsresolv_controller::createNetworkCache(const uint16_t netid)
{
    return dnsresolv_cache::createNetworkCache(netid);
}

int nmd::dnsresolv_controller::destoryNetworkCache(const uint16_t netid)
{
    return dnsresolv_cache::destoryNetworkCache(netid);
}

int nmd::dnsresolv_controller::flushNetworkCache(const uint16_t netid)
{
    return dnsresolv_cache::flushNetworkCache(netid);
}

int nmd::dnsresolv_controller::getResolverInfo(const uint16_t netid, std::vector<std::string> &servers,
    std::vector<std::string> &domains, nmd::dns_res_params &param)
{
    return dnsresolv_cache::getResolverInfo(netid, servers, domains, param);
}
} // namespace nmd
} // namespace OHOS
