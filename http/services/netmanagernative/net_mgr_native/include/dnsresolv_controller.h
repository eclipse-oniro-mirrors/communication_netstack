#ifndef __INCLUDE_DNSRESOLV_CONTROLLER_H__
#define __INCLUDE_DNSRESOLV_CONTROLLER_H__

#include <netdb.h>
#include <netinet/in.h>
#include <vector>
#include <string>
namespace OHOS {
namespace nmd {
struct dnsresolver_params;
struct netd_net_context;
class dnsresolv_controller {
public:
    int getResolverInfo(const uint16_t netid, std::vector<std::string> &servers, std::vector<std::string> &domains,
        struct dns_res_params &param);
    int setResolverConfig(const dnsresolver_params &resolvParams);
    int createNetworkCache(const uint16_t netid);
    int destoryNetworkCache(const uint16_t netid);
    int flushNetworkCache(const uint16_t netid);

public:
    static int getaddrinfo(
        const char *hostname, const char *servname, const struct addrinfo *hints, struct addrinfo **res);
    static int getaddrinfoForNet(const char *hostname, const char *servname, const struct addrinfo *hints,
        uint16_t netid, unsigned mark, struct addrinfo **res);
    static int getaddrinfoFornetContext(const char *hostname, const char *servname, const addrinfo *hints,
        const netd_net_context &netcontext, addrinfo **res);
};
} // namespace nmd
} // namespace OHOS
#endif //!__INCLUDE_DNSRESOLV_CONTROLLER_H__