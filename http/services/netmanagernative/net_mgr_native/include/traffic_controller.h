#ifndef __INCLUDE_TRAFFIC_CONTROLLER_H__
#define __INCLUDE_TRAFFIC_CONTROLLER_H__
#include <ostream>
#include <string>
#include <vector>
namespace OHOS {
namespace nmd {

typedef struct arp_cache_information {
    std::string ipAddr;
    std::string macAddr;
    std::string dev;
    std::string state;

    friend std::ostream &operator<<(std::ostream &os, const arp_cache_information &information)
    {
        os << "ipAddr: " << information.ipAddr << " macAddr: " << information.macAddr
           << " dev: " << information.dev << " state: " << information.state;
        return os;
    }
} arp_cache_information;

typedef struct tether_traffic_account {
    std::string bytes;
    std::string sourceIp;
    std::string destinationIp;

    friend std::ostream &operator<<(std::ostream &os, const tether_traffic_account &account)
    {
        os << "bytes: " << account.bytes << " sourceIp: " << account.sourceIp
           << " destinationIp: " << account.destinationIp;
        return os;
    }
} tether_traffic_account;

typedef struct tether_stats_parcel {
    std::string iface;
    unsigned int ifIndex = 0;
    long rxBytes;
    long rxPackets;
    long txBytes;
    long txPackets;

    friend std::ostream &operator<<(std::ostream &os, const tether_stats_parcel &parcel)
    {
        os << "iface: " << parcel.iface << "ifIndex: " << parcel.ifIndex << "rxBytes: " << parcel.rxBytes
           << "rxPackets: " << parcel.rxPackets << "txBytes: " << parcel.txBytes
           << "txPackets: " << parcel.txPackets;
        return os;
    }
} tether_stats_parcel;

typedef tether_stats_parcel traffic_stats_parcel;

class traffic_controller {
private:
public:
    traffic_controller(/* args */);
    ~traffic_controller();
    bool isTetherEnable();
    static nmd::traffic_stats_parcel getInterfaceTraffic(const std::string &ifName);
    static long getAllRxTraffic();
    static long getAllTxTraffic();
    static std::vector<arp_cache_information> getTetherClientInfo();
    static void startTrafficTether();
    static long getTxTetherTraffic();
    static long getRxTetherTraffic();
    static long getRxUidTraffic(int uid);
    static long getTxUidTraffic(int uid);
    static long getCellularRxTraffic();
    static long getCellularTxTraffic();
    static void traffic_controller_log();
    static void execIptablesRuleMethod(std::string &cmd);
};

} // namespace nmd
} // namespace OHOS

#endif //!__INCLUDE_TRAFFIC_CONTROLLER_H__