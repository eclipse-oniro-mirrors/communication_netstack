#ifndef __INCLUDE_NETLINK_EVENT_H__
#define __INCLUDE_NETLINK_EVENT_H__

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <map>
#include <string>

namespace OHOS {
namespace nmd {
enum class Action {
    Unknown = 0,
    Add,
    Remove,
    Change,
    LinkUp,
    LinkDown,
    AddressUpdated,
    AddressRemoved,
    RouteUpdated,
    RouteRemoved,
    NewRule,
    DelRule,
};
class netlink_event {
private:
    Action action_;
    std::map<std::string, std::string> params_;

public:
    netlink_event() = default;
    bool parseInterfaceInfoInfoMessage(struct nlmsghdr *hdr);
    bool parseInterafaceAddressMessage(struct nlmsghdr *hdr);
    bool parseRouteMessage(struct nlmsghdr *hdr);
    bool parseRuleMessage(struct nlmsghdr *hdr);
    bool parseNetLinkMessage(char *buffer, ssize_t size);

    void setAction(Action action)
    {
        this->action_ = action;
    }
    Action getAction()
    {
        return this->action_;
    }

    void addParam(std::string key, std::string value)
    {
        this->params_.insert(std::pair<std::string, std::string>(key, value));
    }
    const char *findParam(const char *key);
    const char *rtMessageName(int type);

    ~netlink_event();
};
} // namespace nmd
} // namespace OHOS
#endif //!__INCLUDE_NETLINK_EVENT_H__