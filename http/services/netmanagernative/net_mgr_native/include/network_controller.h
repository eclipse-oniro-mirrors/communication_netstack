#ifndef __INCLUDE_NETWORK_CONTROLLER_H__
#define __INCLUDE_NETWORK_CONTROLLER_H__

#include "network.h"
#include <map>
#include <tuple>
#include <vector>
#include <set>
namespace OHOS {
namespace nmd {
class network_controller {
private:
    int defaultNetId_;
    std::map<int, network *> networks_;

public:
    network_controller() = default;
    ~network_controller();

    int createPhysicalNetwork(uint16_t netId, Permission permission);

    int destroyNetwork(int netId);

    int setDefaultNetwork(int netId);

    int clearDefaultNetwork();

    int getDefaultNetwork();

    int addInterfaceToNetwork(int netId, std::string &interafceName);

    int removeInterfaceFromNetwork(int netId, std::string &interafceName);

    int addRoute(int netId, std::string interfaceName, std::string destination, std::string nextHop);

    int removeRoute(int netId, std::string interfaceName, std::string destination, std::string nextHop);

    int getFwmarkForNetwork(int netId);

    int setPermissionForNetwork(int netId, Permission permission);

    std::vector<nmd::network *> getNetworks();

    nmd::network *getNetwork(int netId);

private:
    std::tuple<bool, nmd::network *> findNetworkById(int netId);
    int getNetworkForInterface(std::string &interfaceName);
};

} // namespace nmd
} // namespace OHOS
#endif //!__INCLUDE_NETWORK_CONTROLLER_H__