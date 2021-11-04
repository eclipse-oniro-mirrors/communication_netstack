#ifndef __INCLUDE_ROUTE_CONTROLLER_H__
#define __INCLUDE_ROUTE_CONTROLLER_H__

#include "network.h"
#include <map>
#include <netinet/in.h>

namespace OHOS {
namespace nmd {

typedef struct _inet_addr {
    int family;
    int bitlen;
    int prefixlen;
    uint8_t data[sizeof(struct in6_addr)];
} _inet_addr;

class route_controller {
private:
    static int executeIptablesRestore(std::string command);
    static void updateTableNamesFile();
    static std::map<std::string, uint32_t> interfaceToTable_;
    static uint32_t getRouteTableForInterface(const char *interfaceName);

public:
    route_controller(/* args */);
    ~route_controller();

    static int createChildChains(const char *table, const char *parentChain, const char *childChain);
    static int addInterfaceToDefaultNetwork(const char *interface, NetworkPermission permission);
    static int removeInterfaceFromDefaultNetwork(const char *interface, NetworkPermission permission);
    static int addInterfaceToPhysicalNetwork(uint16_t netId, const char *interface, NetworkPermission permission);

    static int removeInterfaceFromPhysicalNetwork(
        uint16_t netId, const char *interfaceName, NetworkPermission permission);

    static int addRoute(int netId, std::string interfaceName, std::string destination, std::string nextHop);

    static int removeRoute(int netId, std::string interfaceName, std::string destination, std::string nextHop);

    static int read_addr(const char *addr, _inet_addr *res);
    static int read_addr_gw(const char *addr, _inet_addr *res);

private:
    void modifyIpRule(std::string interface, NetworkPermission permission);
};
} // namespace nmd
} // namespace OHOS

#endif //!__INCLUDE_ROUTE_CONTROLLER_H__