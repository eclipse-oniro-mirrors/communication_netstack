#ifndef __INCLUDE_NETWORK_H__
#define __INCLUDE_NETWORK_H__

#include <set>
#include <string>
namespace OHOS {
namespace nmd {

typedef enum Permission {
    PERMISSION_NONE = 0x0,
    PERMISSION_NETWORK = 0x1,
    PERMISSION_SYSTEM = 0x3,
} NetworkPermission;

class network {
private:
    uint16_t netId_;

    bool isDefault_ = false;

    NetworkPermission permission_;

    std::set<std::string> interfaces_;

public:
    network(uint16_t netId, NetworkPermission permission);

    void asDefault();
    void removeAsDefault();

    int addInterface(std::string &interfaceName);
    int removeInterface(std::string &interfaceName);
    int clearInterfaces();

    bool hasInterface(std::string &interfaceName);
    std::set<std::string> getAllInterface()
    {
        return this->interfaces_;
    }

    uint16_t getNetId()
    {
        return this->netId_;
    }
    NetworkPermission getPermission()
    {
        return this->permission_;
    }

    bool isDefault()
    {
        return this->isDefault_;
    }

    virtual ~network();
};

} // namespace nmd
} // namespace OHOS
#endif //!__INCLUDE_NETWORK_H__