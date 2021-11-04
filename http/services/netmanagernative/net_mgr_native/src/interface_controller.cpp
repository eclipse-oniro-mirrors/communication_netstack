#include "interface_controller.h"
#include "interface_utils.h"
#include "logger.h"
#include "error_code.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <system_error>
#include <unistd.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <warning_disable.h>
#include "netnative_log_wrapper.h"

DISABLE_WARNING_PUSH
DISABLE_WARNING_SIGN_CONVERSION
DISABLE_WARNING_OLD_STYLE_CAST
DISABLE_WARNING_CAST_ALIGN
DISABLE_WARNING_C99_EXTENSIONS

#define IFNAMSIZ 16
const char gSysNetPath[] = "/sys/class/net/";
const char gProcNetPath[] = "/proc/sys/net/";

namespace OHOS {
namespace nmd {
interface_controller::interface_controller(/* args */) {}

interface_controller::~interface_controller() {}

bool isIfaceName(const std::string &name)
{
    size_t i;
    if ((name.empty()) || (name.size() > IFNAMSIZ)) {
        return false;
    }

    /* First character must be alphanumeric */
    if (!isalnum(name[0])) {
        return false;
    }

    for (i = 1; i < name.size(); i++) {
        if (!isalnum(name[i]) && (name[i] != '_') && (name[i] != '-') && (name[i] != ':') && (name[i] != '.')) {
            return false;
        }
    }

    return true;
}

int interface_controller::getMtu(const char *interfaceName)
{
    if (!isIfaceName(interfaceName)) {
        std::error_code err = nmd::common::error_code::errNoInfName;
        // LogError << err.message() << endl;
        NETNATIVE_LOGE("interface_controller::getMtu isIfaceName fail %{public}s", err.message().c_str());
        return -1;
    }
    std::string setMtuPath = std::string(gSysNetPath).append(interfaceName).append("/mtu");
    int fd = open(setMtuPath.c_str(), 0, 0666);
    if (fd == -1) {
        // LogError << strerror(errno) << endl;
        NETNATIVE_LOGE("interface_controller::getMtu open fail %{public}s", strerror(errno));
        return -1;
    }
    char originMtuValue[100] = {0};
    if (read(fd, originMtuValue, sizeof(int)) == -1) {
        // LogError << strerror(errno) << endl;
        NETNATIVE_LOGE("interface_controller::getMtu read fail %{public}s", strerror(errno));
    }
    close(fd);
    return atoi(originMtuValue);
}

int interface_controller::setMtu(const char *interfaceName, const char *mtuValue)
{
    if (!isIfaceName(interfaceName)) {
        std::error_code err = nmd::common::error_code::errNoInfName;
        // LogError << err.message() << endl;
        NETNATIVE_LOGE("interface_controller::setMtu isIfaceName fail %{public}s", err.message().c_str());
        return -1;
    }
    std::string setMtuPath = std::string(gSysNetPath).append(interfaceName).append("/mtu");
    int flags = O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC;
    int fd = open(setMtuPath.c_str(), flags, 0666);

    if (fd == -1) {
        // LogError << strerror(errno) << endl;
        NETNATIVE_LOGE("interface_controller::setMtu open fail %{public}s", strerror(errno));
        return -1;
    }
    if (write(fd, mtuValue, strlen(mtuValue)) == -1) {
        // LogError << strerror(errno) << endl;
        NETNATIVE_LOGE("interface_controller::setMtu write fail %{public}s", strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

std::vector<std::string> interface_controller::getInterfaceNames()
{
    std::vector<std::string> ifaceNames;
    DIR *d(nullptr);
    struct dirent *de(nullptr);
    if (!(d = opendir(gSysNetPath))) {
        std::error_code err = std::error_code(errno, std::system_category());
        // LogError << err.message() << endl;
        NETNATIVE_LOGE("interface_controller::getInterfaceNames opendir fail %{public}s", err.message().c_str());
        return ifaceNames;
    }
    while ((de = readdir(d))) {
        if ((de->d_type != DT_DIR) && (de->d_type != DT_LNK))
            continue;
        if (de->d_name[0] == '.')
            continue;
        ifaceNames.push_back(std::string(de->d_name));
    }
    closedir(d);
    return ifaceNames;
}

int interface_controller::clearAddrs(const std::string &ifName)
{
    nmd::common::interface_utils::ifcClearAddresses(ifName.c_str());
    return 0;
}

int interface_controller::interfaceAddAddress(
    const std::string &ifName, const std::string &addr, const int prefixLen)
{
    if (ifName.empty() || addr.empty() || prefixLen < 0) {
        return -1;
    }

    return nmd::common::interface_utils::ifcAddAddr(ifName.c_str(), addr.c_str(), prefixLen);
}

int interface_controller::interfaceDelAddress(
    const std::string &ifName, const std::string &addr, const int prefixLen)
{
    if (ifName.empty() || addr.empty() || prefixLen < 0) {
        return -1;
    }

    return nmd::common::interface_utils::ifcDelAddr(ifName.c_str(), addr.c_str(), prefixLen);
}

inline bool isAddressFamilyPathComponent(const char *component)
{
    return strcmp(component, "ipv4") == 0 || strcmp(component, "ipv6") == 0;
}

inline bool isNormalPathComponent(const char *component)
{
    return (strcmp(component, ".") != 0) && (strcmp(component, "..") != 0) && (strchr(component, '/') == nullptr);
}

inline bool isInterfaceName(const char *name)
{
    return isNormalPathComponent(name) && (strcmp(name, "default") != 0) && (strcmp(name, "all") != 0);
}

std::string getParameterPathname(
    const char *family, const char *which, const char *interface, const char *parameter)
{
    if (!isAddressFamilyPathComponent(family)) {
        errno = EAFNOSUPPORT;
        return "";
    } else if (!isNormalPathComponent(which) || !isInterfaceName(interface) || !isNormalPathComponent(parameter)) {
        errno = EINVAL;
        return "";
    }
    return std::string(gProcNetPath)
        .append(family)
        .append("/")
        .append(which)
        .append("/")
        .append(interface)
        .append("/")
        .append(parameter);
}

int interface_controller::setParameter(
    const char *family, const char *which, const char *ifName, const char *parameter, const char *value)
{
    const std::string path(getParameterPathname(family, which, ifName, parameter));
    if (path.empty()) {
        return -1;
    }
    int flags = O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC;
    int fd = open(path.c_str(), flags, 0666);

    if (fd == -1) {
        // LogError << strerror(errno) << endl;
        NETNATIVE_LOGE("interface_controller::setParameter opendir fail %{public}s", strerror(errno));
        return -1;
    }
    if (write(fd, value, strlen(value)) == -1) {
        // LogError << strerror(errno) << endl;
        NETNATIVE_LOGE("interface_controller::setParameter write fail %{public}s", strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

int interface_controller::getParameter(
    const char *family, const char *which, const char *ifName, const char *parameter, std::string *value)
{
    const std::string path(getParameterPathname(family, which, ifName, parameter));
    if (path.empty()) {
        return -1;
    }
    int fd = open(path.c_str(), 0, 0666);

    if (fd == -1) {
        // LogError << strerror(errno) << endl;
        NETNATIVE_LOGE("interface_controller::getParameter open fail %{public}s", strerror(errno));
        return -1;
    }
    char buf[100] = {0};
    if (read(fd, buf, sizeof(int)) == -1) {
        // LogError << strerror(errno) << endl;
        NETNATIVE_LOGE("interface_controller::getParameter read fail %{public}s", strerror(errno));
        close(fd);
        return -1;
    }
    *value = buf;
    close(fd);
    return 0;
}

int ipv4NetmaskToPrefixLength(in_addr_t mask)
{
    int prefixLength = 0;
    uint32_t m = ntohl(mask);
    while (m & (1 << 31)) {
        prefixLength++;
        m = m << 1;
    }
    return prefixLength;
}

std::string hwAddrToStr(unsigned char *hwaddr)
{
    char buf[64] = {'\0'};
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
    return std::string(buf);
}

interface_configuration_parcel interface_controller::getConfig(const std::string &ifName)
{
    struct in_addr addr = {};
    int prefixLength = 0;
    unsigned char hwaddr[ETH_ALEN] = {};
    unsigned flags = 0;
    nmd::interface_configuration_parcel cfgResult;

    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);

    struct ifreq ifr = {};
    strcpy(ifr.ifr_name, ifName.c_str());

    if (ioctl(fd, SIOCGIFADDR, &ifr) != -1) {
        addr.s_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
    }

    if (ioctl(fd, SIOCGIFNETMASK, &ifr) != -1) {
        prefixLength = ipv4NetmaskToPrefixLength(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr);
    }

    if (ioctl(fd, SIOCGIFFLAGS, &ifr) != -1) {
        flags = ifr.ifr_flags;
    }

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) != -1) {
        memcpy((void *)hwaddr, &ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    } else {
        // LogError << "Failed to retrieve HW addr for " << ifName << " (" << strerror(errno) << ")";
        NETNATIVE_LOGE("interface_controller::getConfig Failed to retrieve HW addr for  %{public}s (%{public}s)",
            ifName.c_str(), strerror(errno));
    }

    cfgResult.ifName = ifName;
    cfgResult.hwAddr = hwAddrToStr(hwaddr);
    cfgResult.ipv4Addr = std::string(inet_ntoa(addr));
    cfgResult.prefixLength = prefixLength;
    cfgResult.flags.push_back(flags & IFF_UP ? "up" : "down");
    if (flags & IFF_BROADCAST)
        cfgResult.flags.push_back("broadcast");
    if (flags & IFF_LOOPBACK)
        cfgResult.flags.push_back("loopback");
    if (flags & IFF_POINTOPOINT)
        cfgResult.flags.push_back("point-to-point");
    if (flags & IFF_RUNNING)
        cfgResult.flags.push_back("running");
    if (flags & IFF_MULTICAST)
        cfgResult.flags.push_back("multicast");

    return cfgResult;
}

int interface_controller::setConfig(const nmd::interface_configuration_parcel &cfg)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    struct ifreq ifr = {
        .ifr_addr = {.sa_family = AF_INET}, // Clear the IPv4 address.
    };
    strcpy(ifr.ifr_name, cfg.ifName.c_str());

    // Make sure that clear IPv4 address before set flag
    // SIOCGIFFLAGS might override ifr and caused clear IPv4 addr ioctl error
    if (ioctl(fd, SIOCSIFADDR, &ifr) == -1) {
        return -1;
    }

    if (!cfg.flags.empty()) {
        if (ioctl(fd, SIOCGIFFLAGS, &ifr) == -1) {
            return -1;
        }
        uint16_t flags = ifr.ifr_flags;
        for (const auto &flag : cfg.flags) {
            if (flag == std::string("up")) {
                ifr.ifr_flags = ifr.ifr_flags | IFF_UP;
            } else if (flag == std::string("down")) {
                ifr.ifr_flags = (ifr.ifr_flags & (~IFF_UP));
            }
        }

        if (ifr.ifr_flags != flags) {
            if (ioctl(fd, SIOCSIFFLAGS, &ifr) == -1) {
                return -1;
            }
        }
    }

    if (interfaceAddAddress(cfg.ifName.c_str(), cfg.ipv4Addr.c_str(), cfg.prefixLength) == -1) {
        // LogError << "Failed to add addr";
        NETNATIVE_LOGE("interface_controller::setConfig Failed to add addr");
        return -1;
    }
    return 1;
}

} // namespace nmd
} // namespace OHOS
DISABLE_WARNING_POP