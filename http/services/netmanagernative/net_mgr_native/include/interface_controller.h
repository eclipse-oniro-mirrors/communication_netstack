#ifndef __INCLUDE_INTERFACE_CONTROLLER_H__
#define __INCLUDE_INTERFACE_CONTROLLER_H__
#include <string>
#include <vector>
#include <ostream>

namespace OHOS {
namespace nmd {

typedef struct interface_configuration_parcel {
    std::string ifName;
    std::string hwAddr;
    std::string ipv4Addr;
    int prefixLength;
    std::vector<std::string> flags;
    friend std::ostream &operator<<(std::ostream &os, const nmd::interface_configuration_parcel &parcel)
    {
        os << "ifName: " << parcel.ifName << "\n"
           << "hwAddr: " << parcel.hwAddr << "\n"
           << "ipv4Addr: " << parcel.ipv4Addr << "\n"
           << "prefixLength: " << parcel.prefixLength << "\n"
           << "flags: ["
           << "\n";
        for (unsigned long i = 0; i < parcel.flags.size(); i++) {
            os << "  " << parcel.flags[i] << "\n";
        }
        os << "] "
           << "\n";
        return os;
    }
} interface_configuration_parcel;

class interface_controller {
private:
    /* data */
public:
    interface_controller(/* args */);
    ~interface_controller();
    static int setMtu(const char *interfaceName, const char *mtuValue);
    static int getMtu(const char *interfaceName);
    static std::vector<std::string> getInterfaceNames();
    static int clearAddrs(const std::string &ifName);
    static int interfaceAddAddress(const std::string &ifName, const std::string &addr, const int prefixLen);
    static int interfaceDelAddress(const std::string &ifName, const std::string &addr, const int prefixLen);
    static int setParameter(
        const char *family, const char *which, const char *ifName, const char *parameter, const char *value);
    static int getParameter(
        const char *family, const char *which, const char *ifName, const char *parameter, std::string *value);
    static interface_configuration_parcel getConfig(const std::string &ifName);
    static int setConfig(const nmd::interface_configuration_parcel &cfg);
};
} // namespace nmd
} // namespace OHOS

#endif //!__INCLUDE_INTERFACE_CONTROLLER_H__
