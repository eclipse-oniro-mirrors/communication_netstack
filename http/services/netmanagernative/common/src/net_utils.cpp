#include "net_utils.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>

#define BUFF_MAX_LEN 100
namespace OHOS {
namespace nmd {
namespace common {
namespace net_utils {
std::string ip_address::toString() const noexcept
{
    char repr[INET6_ADDRSTRLEN] = "\0";

    switch (mData.family) {
        case AF_UNSPEC:
            return "<unspecified>";
        case AF_INET: {
            const in_addr v4 = mData.ip.v4;
            inet_ntop(AF_INET, &v4, repr, sizeof(repr));
            break;
        }
        case AF_INET6: {
            const in6_addr v6 = mData.ip.v6;
            inet_ntop(AF_INET6, &v6, repr, sizeof(repr));
            break;
        }
        default:
            return "<unknown_family>";
    }

    if (mData.family == AF_INET6 && mData.scope_id > 0) {
        // return StringPrintf("%s%%%u", repr, mData.scope_id);
        char repr6[BUFF_MAX_LEN] = {};
        snprintf(repr6, sizeof(repr6), "%s%%%u", repr, mData.scope_id);
        return repr6;
    }

    return repr;
}

bool ip_address::forString(const std::string &repr, ip_address *ip)
{
    addrinfo hints = {};
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

    addrinfo *res(nullptr);
    const int ret = getaddrinfo(repr.c_str(), nullptr, &hints, &res);
    ScopedAddrinfo res_cleanup(res);
    if (ret != 0) {
        return false;
    }

    bool rval = true;
    switch (res[0].ai_family) {
        case AF_INET: {
            sockaddr_in *sin = reinterpret_cast<sockaddr_in *>(res[0].ai_addr);
            if (ip)
                *ip = ip_address(sin->sin_addr);
            break;
        }
        case AF_INET6: {
            sockaddr_in6 *sin6 = reinterpret_cast<sockaddr_in6 *>(res[0].ai_addr);
            if (ip)
                *ip = ip_address(sin6->sin6_addr, sin6->sin6_scope_id);
            break;
        }
        default:
            rval = false;
            break;
    }

    return rval;
}

ip_prefix::ip_prefix(const ip_address &ip, size_t length) : ip_prefix(ip)
{
    // Silently treat CIDR lengths like "-1" as meaning the full bit length
    // appropriate to the address family.
    if (length < 0)
        return;
    if (length >= mData.cidrlen)
        return;

    switch (mData.family) {
        case AF_UNSPEC:
            break;
        case AF_INET: {
            const in_addr_t mask = (length > 0) ? (~0U) << (IPV4_ADDR_BITS - length) : 0U;
            mData.ip.v4.s_addr &= htonl(mask);
            mData.cidrlen = static_cast<uint8_t>(length);
            break;
        }
        case AF_INET6: {
            // The byte in which this CIDR length falls.
            const size_t which = length / 8;
            const int mask = (length % 8 == 0) ? 0 : 0xff << (8 - length % 8);
            mData.ip.v6.s6_addr[which] &= mask;
            for (size_t i = which + 1; i < IPV6_ADDR_LEN; i++) {
                mData.ip.v6.s6_addr[i] = 0U;
            }
            mData.cidrlen = static_cast<uint8_t>(length);
            break;
        }
        default:
            // TODO: Complain bitterly about possible data corruption?
            return;
    }
}

bool ip_prefix::isUninitialized() const noexcept
{
    static const compact_ipdata empty {};
    return mData == empty;
}

bool ip_prefix::forString(const std::string &repr, ip_prefix *prefix)
{
    size_t index = repr.find('/');
    if (index == std::string::npos)
        return false;

    // Parse the IP address.
    ip_address ip;
    if (!ip_address::forString(repr.substr(0, index), &ip))
        return false;

    // Parse the prefix length. Can't use base::ParseUint because it accepts non-base 10 input.
    const char *prefixString = repr.c_str() + index + 1;
    if (!isdigit(*prefixString))
        return false;
    char *endptr;
    unsigned long prefixlen = strtoul(prefixString, &endptr, 10);
    if (*endptr != '\0')
        return false;

    uint8_t maxlen = (ip.family() == AF_INET) ? 32 : 128;
    if (prefixlen > maxlen)
        return false;

    *prefix = ip_prefix(ip, prefixlen);
    return true;
}

std::string ip_prefix::toString() const noexcept
{
    // return StringPrintf("%s/%d", ip().toString().c_str(), mData.cidrlen);
    char result[BUFF_MAX_LEN] = {};
    snprintf(result, sizeof(result), "%s/%d", ip().toString().c_str(), mData.cidrlen);
    return result;
}

std::string ip_sock_addr::toString() const noexcept
{
    switch (mData.family) {
        case AF_INET6:
            // return StringPrintf("[%s]:%u", ip().toString().c_str(), mData.port);
            {
                char result[BUFF_MAX_LEN] = {};
                snprintf(result, sizeof(result), "[%s]:%u", ip().toString().c_str(), mData.port);
                return result;
            }
        default:
            // return StringPrintf("%s:%u", ip().toString().c_str(), mData.port);
            {
                char result[BUFF_MAX_LEN] = {};
                snprintf(result, sizeof(result), "%s:%u", ip().toString().c_str(), mData.port);
                return result;
            }
    }
}

} // namespace net_utils
} // namespace common
} // namespace nmd
} // namespace OHOS