#ifndef __INCLUDE_NATIVE_NTED_SERVICE_H__
#define __INCLUDE_NATIVE_NTED_SERVICE_H__

#include "event_reporter.h"
#include <interface_controller.h>
#include <memory>
#include <network_controller.h>
#include <route_controller.h>
#include <string>
#include <traffic_controller.h>
#include <vector>

#include "dnsresolv_service.h"

typedef char byte;
namespace OHOS {
namespace nmd {
enum set_proc_sys_net {
    IPV4 = 4,
    IPV6 = 6,
    CONF = 1,
    NEIGH = 2,
};
typedef struct route_info_parcel {
    std::string destination;
    std::string ifName;
    std::string nextHop;
    int mtu;
} route_info_parcel;

typedef struct tether_offload_rule_parcel {
    int inputInterfaceIndex;
    int outputInterfaceIndex;
    std::vector<byte> destination;
    int prefixLength;
    std::vector<byte> srcL2Address;
    std::vector<byte> dstL2Address;
    int pmtu = 1500;
} tether_offload_rule_parcel;

typedef struct tether_config_parcel {
    bool usingLegacyDnsProxy;
    std::vector<std::string> dhcpRanges;
} tether_config_parcel;

typedef struct mark_mask_parcel {
    int mark;
    int mask;
} mark_mask_parcel;
class NativeNetdService {
private:
    std::shared_ptr<network_controller> networkController_;
    std::shared_ptr<route_controller> routeController_;
    std::shared_ptr<interface_controller> interfaceController_;
    static std::vector<unsigned int> interfaceIdex_;

public:
    NativeNetdService();
    ~NativeNetdService();

    static void getOriginInterfaceIdex();
    static std::vector<unsigned int> getCurrentInterfaceIdex();
    static void updateInterfaceIdex(unsigned int infIdex);

    void initChildChains();
    void initUnixSocket();
    void init();

    int networkCreatePhysical(int netId, int permission);
    int networkDestroy(int netId);
    int networkAddInterface(int netId, std::string iface);
    int networkRemoveInterface(int netId, std::string iface);
    void socketDestroy(std::string iface);
    void socketDestroy(int netId);
    mark_mask_parcel getFwmarkForNetwork(int netId);
    int networkAddRoute(int netId, std::string ifName, std::string destination, std::string nextHop);
    int networkRemoveRoute(int netId, std::string ifName, std::string destination, std::string nextHop);
    int networkGetDefault();
    int networkSetDefault(int netId);
    int networkClearDefault();
    int networkSetPermissionForNetwork(int netId, NetworkPermission permission);
    std::vector<std::string> interfaceGetList();

    int setProcSysNet(int32_t ipversion, int32_t which, const std::string ifname, const std::string parameter,
        const std::string value);
    int getProcSysNet(int32_t ipversion, int32_t which, const std::string ifname, const std::string parameter,
        std::string *value);

    nmd::interface_configuration_parcel interfaceGetConfig(std::string ifName);
    void interfaceSetConfig(interface_configuration_parcel cfg);
    void interfaceClearAddrs(const std::string ifName);
    int interfaceGetMtu(std::string ifName);
    int interfaceSetMtu(std::string ifName, int mtuValue);
    int interfaceAddAddress(std::string ifName, std::string addrString, int prefixLength);
    int interfaceDelAddress(std::string ifName, std::string addrString, int prefixLength);

    void registerUnsolicitedEventListener(inetd_unsolicited_event_listener listener);
    void networkAddRouteParcel(int netId, route_info_parcel routeInfo);
    void networkRemoveRouteParcel(int netId, route_info_parcel routeInfo);

    long getCellularRxBytes();
    long getCellularTxBytes();
    long getAllRxBytes();
    long getAllTxBytes();
    long getUidTxBytes(int uid);
    long getUidRxBytes(int uid);
    traffic_stats_parcel interfaceGetStats(std::string interfaceName);
    long getIfaceRxBytes(std::string interfaceName);
    long getIfaceTxBytes(std::string interfaceName);
    long getTetherRxBytes();
    long getTetherTxBytes();
};
} // namespace nmd
} // namespace OHOS

#endif //!__INCLUDE_NATIVE_NTED_SERVICE_H__