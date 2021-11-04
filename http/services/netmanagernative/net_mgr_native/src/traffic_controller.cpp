#include "traffic_controller.h"
#include "logger.h"
#include "native_netd_service.h"
#include "error_code.h"
#include <algorithm>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <warning_disable.h>
#include "netnative_log_wrapper.h"

namespace OHOS {
namespace nmd {
constexpr const char *ARP_CACHE = "/proc/net/arp";
constexpr uint32_t ARP_STRING_LEN = 200;
constexpr uint32_t ARP_BUFFER_LEN = (ARP_STRING_LEN + 1);
constexpr const char *ARP_LINE_FORMAT = "%100s %*s 0x%100s %100s %*s %100s";
const std::string interfaceListDir = "/sys/class/net/";
std::vector<std::string> tetherIptablesRuleCache;

std::vector<std::string> getInterfaceList()
{
    DIR *dir(nullptr);
    struct dirent *ptr(nullptr);
    std::vector<std::string> ifList;
    if ((dir = opendir(interfaceListDir.c_str())) == NULL) {
        nmd::traffic_controller::traffic_controller_log();
        return ifList;
    }
    while ((ptr = readdir(dir)) != NULL) {
        if (strcmp(ptr->d_name, ".") == 0 || strcmp(ptr->d_name, "..") == 0)
            continue;
        ifList.push_back(ptr->d_name);
    }
    closedir(dir);
    return ifList;
}

long getInterfaceTrafficByType(const std::string &path, const std::string &type)
{
    std::string trafficPath = path + type;
    if (path.empty()) {
        return -1;
    }
    int fd = open(trafficPath.c_str(), 0, 0666);
    if (fd == -1) {
        nmd::traffic_controller::traffic_controller_log();
        return -1;
    }
    char buf[100] = {0};
    if (read(fd, buf, sizeof(long)) == -1) {
        nmd::traffic_controller::traffic_controller_log();
        close(fd);
        return -1;
    }
    close(fd);
    long infBytes = atol(buf);
    return infBytes;
}

void splitIptablesResult(std::string &s, std::vector<std::string> &sv, const char *delim)
{
    sv.clear();
    char *buffer = new char[s.size() + 1];
    buffer[s.size()] = '\0';
    std::copy(s.begin(), s.end(), buffer);
    char *p = std::strtok(buffer, delim);
    do {
        sv.push_back(p);
    } while ((p = std::strtok(NULL, delim)));
    delete[] buffer;
    return;
}

void getAllTetherTrafficStats(
    const std::string &iptablesRule, std::vector<nmd::tether_traffic_account> &tetherTrafficAccount)
{
    FILE *pp = popen(iptablesRule.c_str(), "r");
    if (!pp) {
        nmd::traffic_controller::traffic_controller_log();
        return;
    }
    char tmp[1024] = {};
    int i = 0;
    while (fgets(tmp, sizeof(tmp), pp) != NULL) {
        if (i < 2) {
            i++;
            continue;
        }
        std::string iptableResult = tmp;
        std::vector<std::string> splitResult;
        splitIptablesResult(iptableResult, splitResult, " ");
        nmd::tether_traffic_account tmpTetherTrafficAccount = {"", "", ""};
        tmpTetherTrafficAccount.bytes = splitResult[1];
        tmpTetherTrafficAccount.sourceIp = splitResult[6];
        tmpTetherTrafficAccount.destinationIp = splitResult[7];
        tetherTrafficAccount.push_back(tmpTetherTrafficAccount);
    }
    pclose(pp);
}

void traffic_controller::traffic_controller_log()
{
    std::error_code err = std::error_code(errno, std::system_category());
    // LogError << err.message() << endl;
    NETNATIVE_LOGD("traffic_controller::traffic_controller_log() %{public}s", err.message().c_str());
}

void traffic_controller::execIptablesRuleMethod(std::string &cmd)
{
    FILE *pp = popen(cmd.c_str(), "r");
    if (!pp) {
        nmd::traffic_controller::traffic_controller_log();
        return;
    }
    char tmp[1024];
    while (fgets(tmp, sizeof(tmp), pp) != NULL) {
        // LogError << tmp << endl;
        NETNATIVE_LOGD("traffic_controller::execIptablesRuleMethod  fgets %{public}s", tmp);
    }
    pclose(pp);
    return;
}

traffic_stats_parcel traffic_controller::getInterfaceTraffic(const std::string &ifName)
{
    nmd::traffic_stats_parcel interfaceTrafficBytes = {"", 0, 0, 0, 0, 0};
    std::vector<std::string> ifNameList = getInterfaceList();
    if (ifNameList.empty()) {
        return interfaceTrafficBytes;
    }
    for (auto iter = ifNameList.begin(); iter != ifNameList.end(); iter++) {
        if (ifName == *iter) {
            std::string base_traffic_path = interfaceListDir + (*iter) + "/" + "statistics" + "/";
            long infRxBytes = getInterfaceTrafficByType(base_traffic_path, "rx_bytes");
            long infRxPackets = getInterfaceTrafficByType(base_traffic_path, "rx_packets");
            long infTxBytes = getInterfaceTrafficByType(base_traffic_path, "tx_bytes");
            long infTxPackets = getInterfaceTrafficByType(base_traffic_path, "tx_packets");

            interfaceTrafficBytes.iface = ifName;
            interfaceTrafficBytes.ifIndex = if_nametoindex(ifName.c_str());

            interfaceTrafficBytes.rxBytes = infRxBytes == -1 ? 0 : infRxBytes;
            interfaceTrafficBytes.rxPackets = infRxPackets == -1 ? 0 : infRxPackets;
            interfaceTrafficBytes.txBytes = infTxBytes == -1 ? 0 : infTxBytes;
            interfaceTrafficBytes.txPackets = infTxPackets == -1 ? 0 : infTxPackets;
        }
    }
    return interfaceTrafficBytes;
}

long traffic_controller::getCellularRxTraffic()
{
    long allCelluRxBytes = 0;
    std::vector<std::string> ifNameList = getInterfaceList();
    if (ifNameList.empty()) {
        return allCelluRxBytes;
    }
    for (auto iter = ifNameList.begin(); iter != ifNameList.end(); iter++) {
        if ((*iter) == "rmnet0") {
            std::string base_traffic_path = interfaceListDir + (*iter) + "/" + "statistics" + "/";
            long rxBytes = getInterfaceTrafficByType(base_traffic_path, "rx_bytes");
            allCelluRxBytes = allCelluRxBytes + rxBytes;
            break;
        }
    }
    return allCelluRxBytes;
}

long traffic_controller::getCellularTxTraffic()
{
    long allCelluTxBytes = 0;
    std::vector<std::string> ifNameList = getInterfaceList();
    if (ifNameList.empty()) {
        return allCelluTxBytes;
    }
    for (auto iter = ifNameList.begin(); iter != ifNameList.end(); iter++) {
        if ((*iter) == "rmnet0") {
            std::string base_traffic_path = interfaceListDir + (*iter) + "/" + "statistics" + "/";
            long txBytes = getInterfaceTrafficByType(base_traffic_path, "tx_bytes");
            allCelluTxBytes = allCelluTxBytes + txBytes;
            break;
        }
    }
    return allCelluTxBytes;
}

long traffic_controller::getAllRxTraffic()
{
    long allRxBytes = 0;
    std::vector<std::string> ifNameList = getInterfaceList();
    if (ifNameList.empty()) {
        return allRxBytes;
    }
    for (auto iter = ifNameList.begin(); iter != ifNameList.end(); iter++) {
        if (*iter != "lo") {
            std::string base_traffic_path = interfaceListDir + (*iter) + "/" + "statistics" + "/";
            long rxBytes = getInterfaceTrafficByType(base_traffic_path, "rx_bytes");
            allRxBytes = allRxBytes + rxBytes;
        }
    }
    return allRxBytes;
}

long traffic_controller::getAllTxTraffic()
{
    long allTxBytes = 0;
    std::vector<std::string> ifNameList = getInterfaceList();
    if (ifNameList.empty()) {
        return allTxBytes;
    }
    for (auto iter = ifNameList.begin(); iter != ifNameList.end(); iter++) {
        if (*iter != "lo") {
            std::string base_traffic_path = interfaceListDir + (*iter) + "/" + "statistics" + "/";
            long txBytes = getInterfaceTrafficByType(base_traffic_path, "tx_bytes");
            allTxBytes = allTxBytes + txBytes;
        }
    }
    return allTxBytes;
}

std::vector<arp_cache_information> traffic_controller::getTetherClientInfo()
{
    std::vector<nmd::arp_cache_information> tetherClientInfo;
    FILE *arpCache = fopen(ARP_CACHE, "r");
    if (!arpCache) {
        traffic_controller_log();
        return tetherClientInfo;
    }

    char header[ARP_BUFFER_LEN];
    if (!fgets(header, sizeof(header), arpCache)) {
        fclose(arpCache);
        return tetherClientInfo;
    }

    char ipAddr[ARP_BUFFER_LEN] = {0}, hwAddr[ARP_BUFFER_LEN] = {0}, device[ARP_BUFFER_LEN] = {0},
         state[ARP_BUFFER_LEN] = {0};
    while (4 == fscanf(arpCache, ARP_LINE_FORMAT, ipAddr, state, hwAddr, device)) {
        arp_cache_information tmpArpCacheInfo = {"", "", "", ""};
        tmpArpCacheInfo.dev = device;
        tmpArpCacheInfo.ipAddr = ipAddr;
        tmpArpCacheInfo.macAddr = hwAddr;
        tmpArpCacheInfo.state = state;
        tetherClientInfo.push_back(tmpArpCacheInfo);
        memset(ipAddr, 0, ARP_BUFFER_LEN);
        memset(hwAddr, 0, ARP_BUFFER_LEN);
        memset(device, 0, ARP_BUFFER_LEN);
        memset(state, 0, ARP_BUFFER_LEN);
    }
    fclose(arpCache);
    return tetherClientInfo;
}

void traffic_controller::startTrafficTether()
{
    auto tetherClientInfo = nmd::traffic_controller::getTetherClientInfo();

    if (tetherClientInfo.empty()) {
        return;
    } else {
        for (auto iter = tetherClientInfo.begin(); iter != tetherClientInfo.end(); iter++) {
            // find in cache , to prevent iptables if one ip to exec many times
            auto it = find(tetherIptablesRuleCache.begin(), tetherIptablesRuleCache.end(), (*iter).ipAddr);
            if (it != tetherIptablesRuleCache.end()) {
                continue;
            } else {
                std::string trafficInputIptables =
                    "iptables -I TETHER_TRAFFIC -d " + iter->ipAddr; //相对于这个ip的入网，即input的流量
                execIptablesRuleMethod(trafficInputIptables);
                std::string trafficOutputIptables =
                    "iptables -I TETHER_TRAFFIC -s " + iter->ipAddr; //相对于这个ip的出网，即output的流量
                execIptablesRuleMethod(trafficOutputIptables);
                std::string trafficInputIptablesAttach =
                    "iptables -I FORWARD -d " + iter->ipAddr + " -j TETHER_TRAFFIC";
                execIptablesRuleMethod(trafficInputIptablesAttach);
                std::string trafficOutputIptablesAttach =
                    "iptables -I FORWARD -s " + iter->ipAddr + " -j TETHER_TRAFFIC";
                execIptablesRuleMethod(trafficOutputIptablesAttach);
                tetherIptablesRuleCache.push_back((*iter).ipAddr);
            }
        }
    }
}

long traffic_controller::getTxTetherTraffic()
{
    std::vector<nmd::tether_traffic_account> tetherTrafficAccount;
    long tetherTrafficBytes = 0;
    std::string getIptablesResutlRule = "iptables -n -v -L TETHER_TRAFFIC -t filter -x";
    getAllTetherTrafficStats(getIptablesResutlRule, tetherTrafficAccount);
    for (auto iter = tetherTrafficAccount.begin(); iter != tetherTrafficAccount.end(); ++iter) {
        if ((*iter).destinationIp != "0.0.0.0/0") {
            tetherTrafficBytes = tetherTrafficBytes + atol(((*iter).bytes).c_str());
        }
    }
    return tetherTrafficBytes;
}

long traffic_controller::getRxTetherTraffic()
{
    std::vector<nmd::tether_traffic_account> tetherTrafficAccount;
    long tetherTrafficBytes = 0;
    std::string getIptablesResutlRule = "iptables -n -v -L TETHER_TRAFFIC -t filter -x";
    getAllTetherTrafficStats(getIptablesResutlRule, tetherTrafficAccount);
    for (auto iter = tetherTrafficAccount.begin(); iter != tetherTrafficAccount.end(); ++iter) {
        if ((*iter).sourceIp != "0.0.0.0/0") {
            tetherTrafficBytes = tetherTrafficBytes + atol(((*iter).bytes).c_str());
        }
    }
    return tetherTrafficBytes;
}
int logForGetUidTraffic(int sock)
{
    nmd::traffic_controller::traffic_controller_log();
    close(sock);
    return -1;
}
long getUidTrafficFromBPF(int uid, int cgroupType)
{
    int sock;
    sockaddr_un s_un;
    char buf[128];
    ssize_t writeRet;
    ssize_t readRet;

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        return logForGetUidTraffic(sock);
    }
    s_un.sun_family = AF_UNIX;
    strcpy(s_un.sun_path, "/dev/socket/traffic");
    DISABLE_WARNING_PUSH
    DISABLE_WARNING_OLD_STYLE_CAST
    if (connect(sock, (sockaddr *)&s_un, sizeof(s_un)) != 0) {
        return logForGetUidTraffic(sock);
    }
    memset(buf, 0, sizeof(buf));
    std::string query = std::to_string(uid) + "," + std::to_string(cgroupType);
    strcpy(buf, query.c_str());
    writeRet = write(sock, buf, strlen(buf));
    if (writeRet < 0) {
        return logForGetUidTraffic(sock);
    }
    memset(buf, 0, sizeof(buf));
    readRet = read(sock, buf, sizeof(buf));
    if (readRet < 0) {
        return logForGetUidTraffic(sock);
    }
    close(sock);
    return atol(buf);
}

long traffic_controller::getRxUidTraffic(int uid)
{
    long result = getUidTrafficFromBPF(uid, 0);
    return result;
}

long traffic_controller::getTxUidTraffic(int uid)
{
    long result = getUidTrafficFromBPF(uid, 1);
    return result;
}

} // namespace nmd
} // namespace OHOS
DISABLE_WARNING_POP