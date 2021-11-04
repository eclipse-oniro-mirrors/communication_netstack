#include "network_controller.h"
#include "route_controller.h"
#include "fwmark.h"
#include <network.h>

#define INTERFACE_UNSET -1
namespace OHOS {
namespace nmd {
network_controller::~network_controller()
{
    std::map<int, network *>::iterator it = networks_.begin();
    for (it = networks_.begin(); it != networks_.end(); ++it) {
        delete it->second;
    }
}

int network_controller::createPhysicalNetwork(uint16_t netId, Permission permission)
{
    network *nw = new network(netId, permission);
    this->networks_.insert(std::pair<long, network *>(netId, nw));
    return netId;
}

int network_controller::destroyNetwork(int netId)
{
    std::tuple<bool, network *> net = this->findNetworkById(netId);
    network *nw = std::get<1>(net);

    if (this->defaultNetId_ == netId) {
        nw->removeAsDefault();
        this->defaultNetId_ = 0;
    }

    if (std::get<0>(net)) {
        nw->clearInterfaces();
    }

    this->networks_.erase(netId);
    delete nw;
    return 1;
}

int network_controller::setDefaultNetwork(int netId)
{
    if (this->defaultNetId_ == netId) {
        return netId;
    }

    // check is this network exists

    std::tuple<bool, network *> net = this->findNetworkById(netId);
    if (std::get<0>(net)) {
        network *nw = std::get<1>(net);
        nw->asDefault();
    }

    if (this->defaultNetId_ != 0) {
        net = this->findNetworkById(this->defaultNetId_);
        if (std::get<0>(net)) {
            network *nw = std::get<1>(net);
            nw->removeAsDefault();
        }
    }
    this->defaultNetId_ = netId;
    return this->defaultNetId_;
}

int network_controller::clearDefaultNetwork()
{
    if (this->defaultNetId_ != 0) {
        std::tuple<bool, network *> net = this->findNetworkById(this->defaultNetId_);
        if (std::get<0>(net)) {
            network *nw = std::get<1>(net);
            nw->removeAsDefault();
        }
    }
    this->defaultNetId_ = 0;
    return 1;
}

std::tuple<bool, network *> network_controller::findNetworkById(int netId)
{
    std::map<int, network *>::iterator it;
    for (it = this->networks_.begin(); it != this->networks_.end(); ++it) {
        if (netId == it->first) {
            return std::make_tuple(true, it->second);
        }
    }
    return std::make_tuple<bool, network *>(false, nullptr);
}

int network_controller::getDefaultNetwork()
{
    return this->defaultNetId_;
}

int network_controller::getNetworkForInterface(std::string &interfaceName)
{
    std::map<int, network *>::iterator it;
    for (it = this->networks_.begin(); it != this->networks_.end(); ++it) {
        if (it->second->hasInterface(interfaceName)) {
            return it->first;
        }
    }
    return INTERFACE_UNSET;
}

int network_controller::addInterfaceToNetwork(int netId, std::string &interafceName)
{
    int alreadySetNetId = getNetworkForInterface(interafceName);
    if (alreadySetNetId != netId && alreadySetNetId != INTERFACE_UNSET) {
        return -1;
    }
    std::tuple<bool, network *> net = this->findNetworkById(netId);
    if (std::get<0>(net)) {
        network *nw = std::get<1>(net);
        return nw->addInterface(interafceName);
    }
    return -1;
}

int network_controller::removeInterfaceFromNetwork(int netId, std::string &interafceName)
{
    int alreadySetNetId = getNetworkForInterface(interafceName);
    if (alreadySetNetId != netId || alreadySetNetId == INTERFACE_UNSET) {
        return 1;
    } else if (alreadySetNetId == netId) {
        std::tuple<bool, network *> net = this->findNetworkById(netId);
        if (std::get<0>(net)) {
            network *nw = std::get<1>(net);
            return nw->removeInterface(interafceName);
        }
    }
    return 1;
}

int network_controller::addRoute(int netId, std::string interfaceName, std::string destination, std::string nextHop)
{
    return route_controller::addRoute(netId, interfaceName, destination, nextHop);
}

int network_controller::removeRoute(
    int netId, std::string interfaceName, std::string destination, std::string nextHop)
{
    return route_controller::removeRoute(netId, interfaceName, destination, nextHop);
}

int network_controller::getFwmarkForNetwork(int netId)
{
    std::tuple<bool, network *> net = this->findNetworkById(netId);
    if (std::get<0>(net)) {
        network *nw = std::get<1>(net);
        fwmark mark;
        mark.bits.netId = nw->getNetId();
        mark.bits.permission = nw->getPermission();
        return static_cast<int>(mark.val);
    }
    return 0;
}

int network_controller::setPermissionForNetwork(int netId, Permission permission)
{
    std::tuple<bool, network *> net = this->findNetworkById(netId);
    if (std::get<0>(net)) {
        network *nw = std::get<1>(net);
        fwmark mark;
        mark.bits.netId = nw->getNetId();
        mark.bits.permission = permission;
        return 1;
    }
    return 0;
}

network *network_controller::getNetwork(int netId)
{
    return networks_.find(netId)->second;
}

std::vector<network *> network_controller::getNetworks()
{
    std::vector<nmd::network *> nws;
    std::map<int, network *>::iterator it;
    for (it = this->networks_.begin(); it != this->networks_.end(); ++it) {
        nws.push_back(it->second);
    }
    return nws;
}
} // namespace nmd
} // namespace OHOS