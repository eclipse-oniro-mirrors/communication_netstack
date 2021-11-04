#include <arpa/inet.h>
#include <iostream>
#include <netinet/in.h>
#include <logger.h>
#include <net/if.h>
#include <netlink_event.h>
#include <arpa/inet.h>
#include <limits.h>
#include <linux/genetlink.h>
#include <linux/if.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_log.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <warning_disable.h>
#include "native_netd_service.h"
#include "netnative_log_wrapper.h"

DISABLE_WARNING_PUSH
DISABLE_WARNING_SIGN_CONVERSION
DISABLE_WARNING_IMPLICIT_INT_CONVERSION
DISABLE_WARNING_SHORTEN_64_TO_32
DISABLE_WARNING_SIGN_CONVERSION
DISABLE_WARNING_SIGN_COMPARE
DISABLE_WARNING_OLD_STYLE_CAST
DISABLE_WARNING_CAST_ALIGN
DISABLE_WARNING_SIGN_CONVERSION

namespace OHOS {
namespace nmd {
netlink_event::~netlink_event() {}

const char *netlink_event::rtMessageName(int type)
{
    switch (type) {
        case RTM_NEWLINK:
            return "RTM_NEWLINK";
        case RTM_DELLINK:
            return "RTM_DELLINK";
        case RTM_NEWADDR:
            return "RTM_NEWADDR";
        case RTM_DELADDR:
            return "RTM_DELADDR";
        case RTM_NEWROUTE:
            return "RTM_NEWROUTE";
        case RTM_DELROUTE:
            return "RTM_DELROUTE";
        case RTM_NEWRULE:
            return "RTM_NEWRULE";
        case RTM_DELRULE:
            return "RTM_DELRULE";
        case RTM_NEWNDUSEROPT:
            return "RTM_NEWNDUSEROPT";
        default:
            return nullptr;
    }
}

bool netlink_event::parseInterfaceInfoInfoMessage(struct nlmsghdr *hdr)
{
    struct ifinfomsg *interfaceInfo = (struct ifinfomsg *)NLMSG_DATA(hdr);
    struct rtattr *rta;

    if (hdr->nlmsg_len < NLMSG_LENGTH(sizeof(*interfaceInfo))) {
        return false;
    }

    std::vector<unsigned int> currentInterfaceList = NativeNetdService::getCurrentInterfaceIdex();
    char name[32] = {'\0'};
    if_indextoname(interfaceInfo->ifi_index, name);
    switch (hdr->nlmsg_type) {
        case RTM_NEWLINK:
            for (size_t i = 0; i < currentInterfaceList.size(); i++) {
                if (currentInterfaceList[i] == interfaceInfo->ifi_index) {
                    goto LINK_CHANGE;
                }
            }
            this->params_.insert(std::pair<std::string, std::string>("INTERFACE", name));
            this->action_ = Action::Add;
            NativeNetdService::updateInterfaceIdex(interfaceInfo->ifi_index);
            return true;
        case RTM_DELLINK:
            this->params_.insert(std::pair<std::string, std::string>("INTERFACE", name));
            this->action_ = Action::Remove;
            return true;
    }
LINK_CHANGE:
    int len = IFLA_PAYLOAD(hdr);
    for (rta = IFLA_RTA(interfaceInfo); RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
        switch (rta->rta_type) {
            case IFLA_IFNAME:
                this->params_.insert(
                    std::pair<std::string, std::string>("INTERFACE", std::string((char *)RTA_DATA(rta))));
                this->params_.insert(
                    std::pair<std::string, std::string>("IFINDEX", std::to_string(interfaceInfo->ifi_index)));
                this->action_ = (interfaceInfo->ifi_flags & /*IFF_LOWER_UP*/ 1 << 16) ? Action::LinkUp :
                                                                                        Action::LinkDown;
                return true;
        }
    }
    return false;
}

bool netlink_event::parseInterafaceAddressMessage(struct nlmsghdr *hdr)
{
    struct ifaddrmsg *interfaceAddress = (struct ifaddrmsg *)NLMSG_DATA(hdr);
    struct ifa_cacheinfo *cacheinfo = nullptr;
    char ifname[IFNAMSIZ] = "";
    char addrstr[46] = "";
    uint32_t flags;

    if (hdr->nlmsg_len < NLMSG_LENGTH(sizeof(*interfaceAddress))) {
        return false;
    }

    uint8_t type = hdr->nlmsg_type;
    if ((type != RTM_NEWADDR) && (type != RTM_DELADDR)) {
        return false;
    }

    const char *msgtype = rtMessageName(type);
    struct rtattr *rta;
    int len = IFA_PAYLOAD(hdr);
    for (rta = IFA_RTA(interfaceAddress); RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
        if (rta->rta_type == IFA_ADDRESS) {
            if (interfaceAddress->ifa_family == AF_INET) {
                struct in_addr *addr4 = (struct in_addr *)RTA_DATA(rta);
                if (RTA_PAYLOAD(rta) < sizeof(*addr4)) {
                    NETNATIVE_LOGD("[NetlinkEvent] Short IPv4 address  (%{public}d bytes) in  %{public}s",
                        RTA_PAYLOAD(rta), msgtype);
                    // LogError << "[NetlinkEvent] Short IPv4 address  (" << RTA_PAYLOAD(rta) << " bytes) in "
                    //         << msgtype << endl;
                    continue;
                }
                inet_ntop(AF_INET, addr4, addrstr, sizeof(addrstr));
            } else if (interfaceAddress->ifa_family == AF_INET6) {
                struct in6_addr *addr6 = (struct in6_addr *)RTA_DATA(rta);
                if (RTA_PAYLOAD(rta) < sizeof(*addr6)) {
                    NETNATIVE_LOGD("[NetlinkEvent] Short IPv6 address  (%{public}d bytes) in  %{public}s",
                        RTA_PAYLOAD(rta), msgtype);
                    // LogError << "[NetlinkEvent] Short IPv6 address  (" << RTA_PAYLOAD(rta) << " bytes) in "
                    //         << msgtype << endl;
                    continue;
                }
                inet_ntop(AF_INET6, addr6, addrstr, sizeof(addrstr));
            } else {
                NETNATIVE_LOGD("[NetlinkEvent] Unknown address family %{public}d", interfaceAddress->ifa_family);
                // LogError << "[NetlinkEvent] Unknown address family " << interfaceAddress->ifa_family << endl;
                continue;
            }

            if (!if_indextoname(interfaceAddress->ifa_index, ifname)) {
                NETNATIVE_LOGD("[NetlinkEvent] Unknown ifindex  %{public}d in %{public}s",
                    interfaceAddress->ifa_index, msgtype);
                // LogError << "[NetlinkEvent] Unknown ifindex " << interfaceAddress->ifa_index << " in " << msgtype
                //         << endl;
            }
        } else if (rta->rta_type == IFA_CACHEINFO) {
            if (RTA_PAYLOAD(rta) < sizeof(*cacheinfo)) {
                NETNATIVE_LOGD(
                    "[NetlinkEvent] Short IFA_CACHEINFO (%{public}d  vs. %{public}d  bytes) in %{public}s",
                    RTA_PAYLOAD(rta), sizeof(cacheinfo), msgtype);
                // LogError << "[NetlinkEvent] Short IFA_CACHEINFO (" << RTA_PAYLOAD(rta) << " vs."
                //         << sizeof(cacheinfo) << " bytes) in " << msgtype << endl;
                continue;
            }
            cacheinfo = (struct ifa_cacheinfo *)RTA_DATA(rta);
        } else if (rta->rta_type == IFA_FLAGS) {
            flags = *(uint32_t *)RTA_DATA(rta);
        }
    }

    this->action_ = (type == RTM_NEWADDR) ? Action::AddressUpdated : Action::AddressRemoved;
    char *tmpBuf[1];
    asprintf(tmpBuf, "%s/%d", addrstr, interfaceAddress->ifa_prefixlen);
    this->params_.insert(std::pair<std::string, std::string>("ADDRESS", std::string(tmpBuf[0])));
    this->params_.insert(std::pair<std::string, std::string>("INTERFACE", ifname));
    this->params_.insert(std::pair<std::string, std::string>("FLAGS", std::to_string(flags)));
    this->params_.insert(std::pair<std::string, std::string>("SCOPE", std::to_string(interfaceAddress->ifa_scope)));
    this->params_.insert(
        std::pair<std::string, std::string>("IFINDEX", std::to_string(interfaceAddress->ifa_index)));

    if (cacheinfo) {
        this->params_.insert(
            std::pair<std::string, std::string>("PREFERRED", std::to_string(cacheinfo->ifa_prefered)));
        this->params_.insert(std::pair<std::string, std::string>("VALID", std::to_string(cacheinfo->ifa_valid)));
        this->params_.insert(std::pair<std::string, std::string>("CSTAMP", std::to_string(cacheinfo->cstamp)));
        this->params_.insert(std::pair<std::string, std::string>("TSTAMP", std::to_string(cacheinfo->tstamp)));
    }
    free(tmpBuf[0]);
    return true;
}

bool netlink_event::parseRuleMessage(struct nlmsghdr *hdr)
{
    uint8_t type = hdr->nlmsg_type;
    const char *msgname = rtMessageName(type);

    if (type != RTM_NEWRULE && type != RTM_DELRULE) {
        NETNATIVE_LOGD("[NetLinkEvent] incorrect message type %{public}d  : %{public}s", type, msgname);
        // LogError << "[NetLinkEvent] incorrect message type " << type << ":" << msgname << endl;
        return false;
    }
    this->action_ = type == RTM_NEWRULE ? Action::NewRule : Action::DelRule;
    return true;
}

bool netlink_event::parseRouteMessage(struct nlmsghdr *hdr)
{
    uint8_t type = hdr->nlmsg_type;
    const char *msgname = rtMessageName(type);

    if (type != RTM_NEWROUTE && type != RTM_DELROUTE) {
        NETNATIVE_LOGD("[NetLinkEvent] incorrect message type %{public}d  : %{public}s", type, msgname);
        // LogError << "[NetLinkEvent] incorrect message type " << type << ":" << msgname << endl;
        return false;
    }

    struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(hdr);
    if (hdr->nlmsg_len < NLMSG_LENGTH(sizeof(*rtm))) {
        NETNATIVE_LOGD("[NetLinkEvent] nl less than rt");
        // LogError << "[NetLinkEvent] nl less than rt" << endl;
        return false;
    }

    int family = rtm->rtm_family;
    int prefixLength = rtm->rtm_dst_len;

    // Currently we only support: destination, (one) next hop, ifindex.
    char dst[INET6_ADDRSTRLEN] = "";
    char gw[INET6_ADDRSTRLEN] = "";
    char dev[IFNAMSIZ] = "";

    size_t len = RTM_PAYLOAD(hdr);
    struct rtattr *rta;
    for (rta = RTM_RTA(rtm); RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
        switch (rta->rta_type) {
            case RTA_DST:
                if (!inet_ntop(family, RTA_DATA(rta), dst, sizeof(dst))) {
                    return false;
                }
                continue;
            case RTA_GATEWAY:
                if (!inet_ntop(family, RTA_DATA(rta), gw, sizeof(gw))) {
                    return false;
                }
                continue;
            case RTA_OIF:
                if (!if_indextoname(*(int *)RTA_DATA(rta), dev)) {
                    return false;
                }
                continue;
            default:
                continue;
        }
    }

    // If there's no RTA_DST attribute, then:
    // - If the prefix length is zero, it's the default route.
    // - If the prefix length is nonzero, there's something we don't understand.
    //   Ignore the event.
    if (!*dst && !prefixLength) {
        if (family == AF_INET) {
            strncpy(dst, "0.0.0.0", sizeof(dst));
        } else if (family == AF_INET6) {
            strncpy(dst, "::", sizeof(dst));
        }
    }

    if (!*dst || (!*gw && !*dev)) {
        return false;
    }

    this->action_ = (type == RTM_NEWROUTE) ? Action::RouteUpdated : Action::RouteRemoved;

    char *tmpBuf[1];
    asprintf(tmpBuf, "%s/%d", dst, prefixLength);
    this->params_.insert(std::pair<std::string, std::string>("ROUTE", std::string(tmpBuf[0])));
    this->params_.insert(std::pair<std::string, std::string>("GATEWAY", std::string((*gw) ? gw : "")));
    this->params_.insert(std::pair<std::string, std::string>("INTERFACE", std::string((*dev) ? dev : "")));
    free(tmpBuf[0]);
    return true;
}

bool netlink_event::parseNetLinkMessage(char *buffer, ssize_t size)
{
    struct nlmsghdr *nh;
    for (nh = (struct nlmsghdr *)buffer; NLMSG_OK(nh, (unsigned)size) && (nh->nlmsg_type != NLMSG_DONE);
         nh = NLMSG_NEXT(nh, size)) {
        const char *msgname = rtMessageName(nh->nlmsg_type);
        if (!msgname) {
            NETNATIVE_LOGD("[NetlinkEvent] Unexpected netlink message type : %{public}d", nh->nlmsg_type);
            // LogError << "[NetlinkEvent] Unexpected netlink message type :" << nh->nlmsg_type << endl;
            continue;
        }
        // common::logger::info() << "[NetlinkEvent] got message: " << msgname << endl;
        NETNATIVE_LOGI("[NetlinkEvent] got message: %{public}s", msgname);

        if (nh->nlmsg_type == RTM_NEWLINK || nh->nlmsg_type == RTM_DELLINK) {
            if (parseInterfaceInfoInfoMessage(nh)) {
                return true;
            }
        } else if (nh->nlmsg_type == RTM_NEWADDR || nh->nlmsg_type == RTM_DELADDR) {
            if (parseInterafaceAddressMessage(nh)) {
                return true;
            }
        } else if (nh->nlmsg_type == RTM_NEWROUTE || nh->nlmsg_type == RTM_DELROUTE) {
            if (parseRouteMessage(nh)) {
                return true;
            }
        } else if (nh->nlmsg_type == RTM_NEWRULE || nh->nlmsg_type == RTM_DELRULE) {
            if (parseRuleMessage(nh)) {
                return true;
            }
        } else {
            NETNATIVE_LOGI("[NetlinkEvent] can not parse message type: %{public}s", msgname);
            // common::logger::info() << "[NetlinkEvent] can not parse message type: " << msgname << endl;
        }
    }
    return false;
}

const char *netlink_event::findParam(const char *key)
{
    std::map<std::string, std::string>::iterator it;
    if ((it = this->params_.find(std::string(key))) != this->params_.end()) {
        return it->second.data();
    }
    return "";
}

} // namespace nmd
} // namespace OHOS
DISABLE_WARNING_POP
