#include "network.h"
#include "interface_utils.h"
#include "route_controller.h"
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <sys/uio.h>

namespace OHOS {
namespace nmd {
network::network(uint16_t netId, NetworkPermission permission) : netId_(netId), permission_(permission) {}

network::~network() {}

void network::asDefault()
{
    std::set<std::string>::iterator it;
    for (it = this->interfaces_.begin(); it != this->interfaces_.end(); ++it) {
        route_controller::addInterfaceToDefaultNetwork(it->c_str(), this->permission_);
    }
    this->isDefault_ = true;
}

void network::removeAsDefault()
{
    std::set<std::string>::iterator it;
    for (it = this->interfaces_.begin(); it != this->interfaces_.end(); ++it) {
        route_controller::removeInterfaceFromDefaultNetwork(it->c_str(), this->permission_);
    }
    this->isDefault_ = true;
}

int network::addInterface(std::string &interfaceName)
{
    if (hasInterface(interfaceName)) {
        return 1;
    }

    route_controller::addInterfaceToPhysicalNetwork(this->netId_, interfaceName.c_str(), this->permission_);

    if (this->isDefault_) {
        route_controller::addInterfaceToDefaultNetwork(interfaceName.c_str(), this->permission_);
    }

    this->interfaces_.insert(interfaceName);
    return 1;
}

int network::removeInterface(std::string &interfaceName)
{
    if (!hasInterface(interfaceName)) {
        return 1;
    }

    route_controller::removeInterfaceFromPhysicalNetwork(this->netId_, interfaceName.c_str(), this->permission_);

    if (this->isDefault_) {
        route_controller::removeInterfaceFromDefaultNetwork(interfaceName.c_str(), this->permission_);
    }

    this->interfaces_.erase(interfaceName);
    return 1;
}

int network::clearInterfaces()
{
    std::set<std::string>::iterator it;
    for (it = this->interfaces_.begin(); it != this->interfaces_.end(); ++it) {
        route_controller::removeInterfaceFromPhysicalNetwork(this->netId_, it->c_str(), this->permission_);
    }
    this->interfaces_.clear();
    return 1;
}

bool network::hasInterface(std::string &interfaceName)
{
    return this->interfaces_.find(interfaceName) != this->interfaces_.end();
}
} // namespace nmd
} // namespace OHOS