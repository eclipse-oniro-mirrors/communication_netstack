#include "interface_controller.h"
#include "interface_utils.h"
#include "native_netd_service.h"
#include "net_utils.h"
#include "warning_disable.h"
#include "utils.h"
#include <fcntl.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

namespace {

struct IfaddrsDeleter {
    void operator()(struct ifaddrs *p) const
    {
        if (p != nullptr) {
            freeifaddrs(p);
        }
    }
};

typedef std::unique_ptr<struct ifaddrs, struct IfaddrsDeleter> ScopedIfaddrs;

int netmaskToPrefixLength(const uint8_t *buf, size_t buflen)
{
    if (buf == nullptr)
        return -1;

    int prefixLength = 0;
    bool endOfContiguousBits = false;
    for (unsigned int i = 0; i < buflen; i++) {
        const uint8_t value = buf[i];

        // Bad bit sequence: check for a contiguous set of bits from the high
        // end by verifying that the inverted value + 1 is a power of 2
        // (power of 2 iff. (v & (v - 1)) == 0).
        const uint8_t inverse = ~value + 1;
        if ((inverse & (inverse - 1)) != 0)
            return -1;

        prefixLength += (value == 0) ? 0 : CHAR_BIT - ffs(value) + 1;

        // Bogus netmask.
        if (endOfContiguousBits && value != 0)
            return -1;

        if (value != 0xff)
            endOfContiguousBits = true;
    }

    return prefixLength;
}

template<typename T>
int netmaskToPrefixLength(const T *p)
{
    return netmaskToPrefixLength(reinterpret_cast<const uint8_t *>(p), sizeof(T));
}

bool interfaceHasAddress(const std::string &ifname, const char *addrString, int prefixLength)
{
    struct addrinfo *addrinfoList = nullptr;

    DISABLE_WARNING_PUSH
    DISABLE_WARNING_MISSING_FIELD_INITIALIZERS

    const struct addrinfo hints = {AI_NUMERICHOST, AF_UNSPEC, SOCK_DGRAM};

    DISABLE_WARNING_POP

    if (getaddrinfo(addrString, nullptr, &hints, &addrinfoList) != 0 || addrinfoList == nullptr ||
        addrinfoList->ai_addr == nullptr) {
        return false;
    }
    nmd::common::net_utils::ScopedAddrinfo addrinfoCleanup(addrinfoList);

    struct ifaddrs *ifaddrsList = nullptr;

    int getIfaddrResult = getifaddrs(&ifaddrsList);
    ScopedIfaddrs ifaddrsCleanup(ifaddrsList);

    if (getIfaddrResult != 0) {
        return false;
    }

    for (struct ifaddrs *addr = ifaddrsList; addr != nullptr; addr = addr->ifa_next) {
        if (std::string(addr->ifa_name) != ifname || addr->ifa_addr == nullptr ||
            addr->ifa_addr->sa_family != addrinfoList->ai_addr->sa_family) {
            continue;
        }

        switch (addr->ifa_addr->sa_family) {
            case AF_INET: {
                auto *addr4 = reinterpret_cast<const struct sockaddr_in *>(addr->ifa_addr);
                auto *want = reinterpret_cast<const struct sockaddr_in *>(addrinfoList->ai_addr);
                if (memcmp(&addr4->sin_addr, &want->sin_addr, sizeof(want->sin_addr)) != 0) {
                    continue;
                }

                if (prefixLength < 0)
                    return true; // not checking prefix lengths

                if (addr->ifa_netmask == nullptr)
                    return false;
                auto *nm = reinterpret_cast<const struct sockaddr_in *>(addr->ifa_netmask);
                EXPECT_EQ(prefixLength, netmaskToPrefixLength(&nm->sin_addr));
                return (prefixLength == netmaskToPrefixLength(&nm->sin_addr));
            }
            case AF_INET6: {
                auto *addr6 = reinterpret_cast<const struct sockaddr_in6 *>(addr->ifa_addr);
                auto *want = reinterpret_cast<const struct sockaddr_in6 *>(addrinfoList->ai_addr);
                if (memcmp(&addr6->sin6_addr, &want->sin6_addr, sizeof(want->sin6_addr)) != 0) {
                    continue;
                }

                if (prefixLength < 0)
                    return true; // not checking prefix lengths

                if (addr->ifa_netmask == nullptr)
                    return false;
                auto *nm = reinterpret_cast<const struct sockaddr_in6 *>(addr->ifa_netmask);
                EXPECT_EQ(prefixLength, netmaskToPrefixLength(&nm->sin6_addr));
                return (prefixLength == netmaskToPrefixLength(&nm->sin6_addr));
            }
            default:
                // Cannot happen because we have already screened for matching
                // address families at the top of each iteration.
                continue;
        }
    }
    return false;
}
void getValueFromFilesystem(const std::string &filePath, char *returnValue)
{
    int fd = open(filePath.c_str(), 0, 0666);
    read(fd, returnValue, sizeof(int));
    close(fd);
}
} // namespace

TEST(interface, loIpAddrShouldClear)
{
    // get origin addr
    unsigned orignAddr, afterClearAddr, recoverAddr;
    nmd::common::interface_utils::ifcInit();
    nmd::common::interface_utils::ifcGetAddr("lo", &orignAddr);
    // clear addr
    nmd::native_nted_service nativeNetdService;
    nativeNetdService.interfaceClearAddrs("lo");
    // recover addr
    nmd::common::interface_utils::ifcGetAddr("lo", &afterClearAddr);
    EXPECT_EQ(afterClearAddr, 0u);
    nmd::common::interface_utils::ifcInit();
    nmd::common::interface_utils::ifcSetAddr("lo", orignAddr);
    nmd::common::interface_utils::ifcGetAddr("lo", &recoverAddr);
    EXPECT_EQ(recoverAddr, orignAddr);
}

TEST(interface, InterfaceMtuShouldBe2000AfterSetMtu)
{
    std::string testMtu("2000");
    std::string ifName = "eth0";
    std::string setMtuPath = std::string("/sys/class/net/") + ifName + std::string("/mtu");
    // get origin mtu
    char originMtuValue[100] = {0};
    getValueFromFilesystem(setMtuPath, originMtuValue);
    // set mtu
    nmd::native_nted_service nativeNetdService;
    EXPECT_EQ(nativeNetdService.interfaceSetMtu(ifName, 2000), 0);
    char updateMtuValue[100] = {0};
    getValueFromFilesystem(setMtuPath, updateMtuValue);
    EXPECT_EQ(std::string(updateMtuValue), testMtu);
    // recover origin mtu
    nmd::interface_controller::setMtu(ifName.c_str(), originMtuValue);
    char recoverMtuValue[100] = {0};
    getValueFromFilesystem(setMtuPath, recoverMtuValue);
    EXPECT_EQ(std::string(recoverMtuValue), originMtuValue);
}

TEST(interface, InterfaceMtuShouldBe2000AfterGetMtu)
{
    std::string ifName = "eth0";
    std::string setMtuPath = std::string("/sys/class/net/") + ifName + std::string("/mtu");
    // get origin mtu
    char originMtuValue[100] = {0};
    getValueFromFilesystem(setMtuPath, originMtuValue);
    // get mtu
    nmd::native_nted_service nativeNetdService;
    EXPECT_EQ(nativeNetdService.interfaceGetMtu(ifName), atoi(originMtuValue));
}

TEST(interface, InterfaceMtuShouldGetMtuFailedWhenNameIsFault)
{
    std::string ifName = "__xx";
    EXPECT_EQ(nmd::interface_controller::getMtu(ifName.c_str()), -1);
}

TEST(interface, InterfaceMtuShouldGetMtuFailedWhenNameIsNotExists)
{
    std::string ifName = "xxxxx20";
    EXPECT_EQ(nmd::interface_controller::getMtu(ifName.c_str()), -1);
}

TEST(interface, InterfaceMtuShouldSetMtuFailedWhenNameIsFault)
{
    std::string testMtu("2000");
    std::string ifName = "__xx";
    std::string setMtuPath = std::string("/sys/class/net/") + ifName + std::string("/mtu");
    // get origin mtu
    char originMtuValue[100] = {0};
    getValueFromFilesystem(setMtuPath, originMtuValue);
    // set mtu
    EXPECT_EQ(nmd::interface_controller::setMtu(ifName.c_str(), testMtu.c_str()), -1);
}

TEST(interface, InterfaceMtuShouldSetMtuFailedWhenNameIsFault1)
{
    std::string testMtu("2000");
    std::string ifName = "a4_-:.xx";
    std::string setMtuPath = std::string("/sys/class/net/") + ifName + std::string("/mtu");
    // get origin mtu
    char originMtuValue[100] = {0};
    getValueFromFilesystem(setMtuPath, originMtuValue);
    // set mtu
    EXPECT_EQ(nmd::interface_controller::setMtu(ifName.c_str(), testMtu.c_str()), -1);
}

TEST(interface, interfaceAddAddressFaildWhenIfNameIsEmpty)
{
    EXPECT_EQ(nmd::interface_controller::interfaceAddAddress("", "192.168.1.1", 8), -1);
}

TEST(interface, interfaceAddAddressFaildWhenAddrIsEmpty)
{
    EXPECT_EQ(nmd::interface_controller::interfaceAddAddress("eth0", "", 8), -1);
}

TEST(interface, interfaceDelAddressFaildWhenIfNameIsEmpty)
{
    EXPECT_EQ(nmd::interface_controller::interfaceDelAddress("", "192.168.1.1", 8), -1);
}

TEST(interface, interfaceDelAddressFaildWhenAddrIsEmpty)
{
    EXPECT_EQ(nmd::interface_controller::interfaceDelAddress("eth0", "", 8), -1);
}

TEST(interface, setParameterFailedWhenParameterPathIsEmpty)
{
    EXPECT_EQ(nmd::interface_controller::setParameter("ipv8", "/", "eth0", "p", "v"), -1);
}

TEST(interface, InterfaceMtuShouldSetMtuFailedWhenNameIsEmpty)
{
    std::string testMtu("2000");
    std::string ifName = "";
    std::string setMtuPath = std::string("/sys/class/net/") + ifName + std::string("/mtu");
    // get origin mtu
    char originMtuValue[100] = {0};
    getValueFromFilesystem(setMtuPath, originMtuValue);
    // set mtu
    EXPECT_EQ(nmd::interface_controller::setMtu(ifName.c_str(), testMtu.c_str()), -1);
}

TEST(interface, InterfaceListSizeShouldNotBeZero)
{
    auto interfaceList = nmd::interface_controller::getInterfaceNames();
    EXPECT_NE(interfaceList.size(), 0u);
}

TEST(interface, InterfaceAddressShouldBeAddAndDelete)
{
    // add addr
    std::string ifName = "eth0";
    std::string addrString = "10.0.0.1";
    int prefixLen = 24;
    auto ret = nmd::interface_controller::interfaceAddAddress(ifName, addrString, prefixLen);
    EXPECT_EQ(ret, 0);
    EXPECT_TRUE(interfaceHasAddress(ifName, addrString.c_str(), prefixLen));

    // delete addr
    ret = nmd::interface_controller::interfaceDelAddress(ifName, addrString, prefixLen);
    EXPECT_EQ(ret, 0);
    EXPECT_FALSE(interfaceHasAddress(ifName, addrString.c_str(), prefixLen));
}

TEST(interface, SetProcSysNetArgShouldBeChange)
{
    nmd::native_nted_service test;
    std::string path = ("/proc/sys/net/ipv4/conf/eth0/disable_policy");
    // get origin
    char originDisablePolicyValue[100] = {0};
    getValueFromFilesystem(path, originDisablePolicyValue);
    // set
    test.setProcSysNet(4, 1, std::string("eth0"), std::string("disable_policy"), std::string("1"));
    char afterSetDisablePolicyValue[100] = {0};
    getValueFromFilesystem(path, afterSetDisablePolicyValue);
    EXPECT_EQ(std::string(afterSetDisablePolicyValue), std::string("1\n"));
    // recover
    test.setProcSysNet(
        4, 1, std::string("eth0"), std::string("disable_policy"), std::string(originDisablePolicyValue));
    char recoverSetDisablePolicyValue[100] = {0};
    getValueFromFilesystem(path, recoverSetDisablePolicyValue);
    EXPECT_EQ(std::string(recoverSetDisablePolicyValue), std::string(originDisablePolicyValue));
}

TEST(interface, GetProcSysNetArg)
{
    nmd::native_nted_service test;
    test.setProcSysNet(4, 1, std::string("eth0"), std::string("disable_policy"), std::string("1"));
    std::string readValue;
    test.getProcSysNet(4, 1, std::string("eth0"), std::string("disable_policy"), &readValue);
    std::cout << readValue << std::endl;
    EXPECT_EQ(readValue, std::string("1\n"));
}

TEST(interface, interfaceGetInterfaceConfig)
{
    nmd::interface_configuration_parcel parcel = nmd::interface_controller::getConfig("eth0");
    EXPECT_EQ(parcel.ifName, "eth0");
}

TEST(interface, interfaceSetInterfaceConfig)
{
    nmd::native_nted_service nativeNetdService;
    nmd::interface_configuration_parcel parcel = nmd::interface_controller::getConfig("lo");
    EXPECT_EQ(parcel.ifName, "lo");
    std::cout << parcel << std::endl;
    nativeNetdService.interfaceSetConfig(parcel);
    parcel = nmd::interface_controller::getConfig("lo");
    EXPECT_EQ(parcel.ifName, "lo");
}