#include "interface_utils.h"
#include "bitcast.h"
#include "warning_disable.h"
#include <iostream>
#include <linux/rtnetlink.h>
#include <logger.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "netnative_log_wrapper.h"

namespace OHOS {
namespace nmd {
namespace common {

int ifc_ctl_sock = -1;
// pthread_mutex_t ifc_sock_mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
pthread_mutex_t ifc_sock_mutex = PTHREAD_MUTEX_INITIALIZER;
const uint32_t INET_ADDRLEN = 4;
const uint32_t INET6_ADDRLEN = 16;

void ifcInitIfr(const char *name, struct ifreq *ifr)
{
    memset(ifr, 0, sizeof(struct ifreq));
    strncpy(ifr->ifr_name, name, IFNAMSIZ);
    ifr->ifr_name[IFNAMSIZ - 1] = 0;
}

void initSockaddrin(struct sockaddr *sa, in_addr_t addr)
{
    struct sockaddr_in *sin = reinterpret_cast<struct sockaddr_in *>(sa);
    sin->sin_family = AF_INET;
    sin->sin_port = 0;
    sin->sin_addr.s_addr = addr;
}

void ifcClose(void)
{
    if (ifc_ctl_sock != -1) {
        (void)close(ifc_ctl_sock);
        ifc_ctl_sock = -1;
    }
    pthread_mutex_unlock(&ifc_sock_mutex);
}

void ifcClearIpv4Addresses(const char *name)
{
    unsigned count, addr;
    nmd::common::interface_utils::ifcInit();
    for (count = 0, addr = 1; ((addr != 0) && (count < 255)); count++) {
        if (OHOS::nmd::common::interface_utils::ifcGetAddr(name, &addr) < 0) {
            break;
        }
        if (addr) {
            OHOS::nmd::common::interface_utils::ifcSetAddr(name, 0);
        }
    }
    ifcClose();
}

int stringToIp(const char *string, struct sockaddr_storage *ss)
{
    struct addrinfo *ai(nullptr);

    if (ss == NULL) {
        return -EFAULT;
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_NUMERICHOST;
    hints.ai_socktype = SOCK_DGRAM;

    int ret = getaddrinfo(string, NULL, &hints, &ai);
    if (ret == 0) {
        memcpy(ss, ai->ai_addr, ai->ai_addrlen);
        freeaddrinfo(ai);
    } else {
        // Getaddrinfo has its own error codes. Convert to negative errno.
        // There, the only thing that can reasonably happen is that the passed-in string is invalid.
        ret = (ret == EAI_SYSTEM) ? -errno : -EINVAL;
    }

    return ret;
}

namespace interface_utils {

int ifcInit(void)
{
    int ret;
    pthread_mutex_lock(&ifc_sock_mutex);
    if (ifc_ctl_sock == -1) {
        ifc_ctl_sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (ifc_ctl_sock < 0) {
            std::error_code err = std::error_code(errno, std::system_category());
            // LogError << err.message() << "[socket error in ifcInit()]" << endl;
            NETNATIVE_LOGE("interface_utils::ifcInit socket fail %{public}s [socket error in ifcInit()]",
                err.message().c_str());
        }
    }

    ret = ifc_ctl_sock < 0 ? -1 : 0;

    return ret;
}

int ifcGetAddr(const char *name, in_addr_t *addr)
{
    struct ifreq ifr;
    int ret = 0;

    ifcInitIfr(name, &ifr);
    ifcInit();
    if (addr != NULL) {
        ret = ioctl(ifc_ctl_sock, SIOCGIFADDR, &ifr);
        if (ret == -1) {
            *addr = 0;
        } else {
            *addr = OHOS::nmd::common::bit_cast<sockaddr_in>(ifr.ifr_addr).sin_addr.s_addr;
        }
    }
    ifcClose();
    return ret;
}

int ifcSetAddr(const char *name, in_addr_t addr)
{
    struct ifreq ifr;
    int ret;

    ifcInitIfr(name, &ifr);
    ifcInit();
    initSockaddrin(&ifr.ifr_addr, addr);

    ret = ioctl(ifc_ctl_sock, SIOCSIFADDR, &ifr);
    ifcClose();
    return ret;
}

void ifcClearAddresses(const char *name)
{
    return ifcClearIpv4Addresses(name);
}

int getInterfaceIndex(const char *interfaceName)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd == -1) {
        return 0;
    }

    // get inierface index for ioctl
    struct ifreq req;

    strncpy(req.ifr_ifrn.ifrn_name, interfaceName, sizeof(req.ifr_ifrn.ifrn_name));

    int iod = ioctl(fd, SIOCGIFINDEX, &req);
    if (iod == -1) {
        return 0;
    }
    return req.ifr_ifru.ifru_ivalue;
}

int ifcAddAddr(const char *ifName, const char *addr, const int prefixLen)
{
    return ifcActOnAddr(RTM_NEWADDR, ifName, addr, prefixLen, false);
}

int ifcActOnAddr(
    unsigned short action, const char *name, const char *address, const int prefixlen, const bool nodad)
{
    DISABLE_WARNING_PUSH
    DISABLE_WARNING_OLD_STYLE_CAST

    struct sockaddr_storage ss = {};
    int saved_errno = 0;
    void *addr = nullptr;
    uint16_t addrlen = 0;
    struct {
        struct nlmsghdr n;
        struct ifaddrmsg r;
        // Allow for IPv4 or IPv6 address, headers, IPv4 broadcast address and padding.
        char attrbuf[NLMSG_ALIGN(sizeof(struct rtattr)) + NLMSG_ALIGN(INET6_ADDRLEN) +
            NLMSG_ALIGN(sizeof(struct rtattr)) + NLMSG_ALIGN(INET_ADDRLEN)];
    } req;
    struct rtattr *rta(nullptr);
    struct nlmsghdr *nh(nullptr);
    struct nlmsgerr *err(nullptr);

    // Get interface ID.
    uint32_t ifindex = if_nametoindex(name);
    if (ifindex == 0) {
        return -errno;
    }

    // Convert string representation to sockaddr_storage.
    int ret = stringToIp(address, &ss);
    if (ret) {
        return ret;
    }

    // Determine address type and length.
    if (ss.ss_family == AF_INET) {
        struct sockaddr_in *sin = reinterpret_cast<struct sockaddr_in *>(&ss);
        addr = &sin->sin_addr;
        addrlen = INET_ADDRLEN;
    } else if (ss.ss_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = reinterpret_cast<struct sockaddr_in6 *>(&ss);
        addr = &sin6->sin6_addr;
        addrlen = INET6_ADDRLEN;
    } else {
        return -EAFNOSUPPORT;
    }

    // Fill in netlink structures.
    memset(&req, 0, sizeof(req));

    // Netlink message header.
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.r));
    req.n.nlmsg_type = action;
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.n.nlmsg_pid = static_cast<uint32_t>(getpid());

    // Interface address message header.
    req.r.ifa_family = static_cast<uint8_t>(ss.ss_family);
    req.r.ifa_flags = nodad ? IFA_F_NODAD : 0;
    req.r.ifa_prefixlen = static_cast<uint8_t>(prefixlen);
    req.r.ifa_index = ifindex;

    // Routing attribute. Contains the actual IP address.
    rta = reinterpret_cast<struct rtattr *>((reinterpret_cast<char *>(&req)) + NLMSG_ALIGN(req.n.nlmsg_len));
    rta->rta_type = IFA_LOCAL;
    rta->rta_len = RTA_LENGTH(addrlen);
    req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + RTA_LENGTH(addrlen);
    memcpy(RTA_DATA(rta), addr, addrlen);

    // Add an explicit IFA_BROADCAST for IPv4 RTM_NEWADDRs.
    if (ss.ss_family == AF_INET && action == RTM_NEWADDR) {
        rta = reinterpret_cast<struct rtattr *>((reinterpret_cast<char *>(&req)) + NLMSG_ALIGN(req.n.nlmsg_len));
        rta->rta_type = IFA_BROADCAST;
        rta->rta_len = RTA_LENGTH(addrlen);
        req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + RTA_LENGTH(addrlen);
        (reinterpret_cast<struct in_addr *>(addr))->s_addr |= htonl((unsigned int)(1 << (32 - prefixlen)) - 1);
        memcpy(RTA_DATA(rta), addr, addrlen);
    }

    int s = socket(PF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (s < 0) {
        return -errno;
    }

    if (send(s, &req, req.n.nlmsg_len, 0) < 0) {
        saved_errno = errno;
        close(s);
        return -saved_errno;
    }

    char buf[NLMSG_ALIGN(sizeof(struct nlmsgerr)) + sizeof(req)];
    ssize_t len = recv(s, buf, sizeof(buf), 0);
    saved_errno = errno;
    close(s);
    if (len < 0) {
        return -saved_errno;
    }

    // Parse the acknowledgement to find the return code.
    nh = reinterpret_cast<struct nlmsghdr *>(buf);
    if (!NLMSG_OK(nh, static_cast<unsigned>(len)) || nh->nlmsg_type != NLMSG_ERROR) {
        return -EINVAL;
    }

    err = (nlmsgerr *)NLMSG_DATA(nh);

    DISABLE_WARNING_POP

    return err->error;
}

int ifcDelAddr(const char *ifName, const char *addr, const int prefixLen)
{
    return ifcActOnAddr(RTM_DELADDR, ifName, addr, prefixLen, false);
}

} // namespace interface_utils
} // namespace common
} // namespace nmd
} // namespace OHOS
