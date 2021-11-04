#ifndef __INCLUDE_NET_ADDR_H__
#define __INCLUDE_NET_ADDR_H__

#include "warning_disable.h"
#include <cstring>
#include <limits>
#include <memory>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string>
#include <unistd.h>
namespace OHOS {
namespace nmd {
namespace common {
namespace net_utils {

enum protocol : uint8_t {
    PROTO_UNKNOWN = 0,
    PROTO_TCP = 6,
    PROTO_UDP = 17,
};

// See also NetworkConstants.java in frameworks/base.
constexpr int IPV4_ADDR_LEN = 4;
constexpr int IPV4_ADDR_BITS = 32;
constexpr int IPV6_ADDR_LEN = 16;
constexpr int IPV6_ADDR_BITS = 128;

// Referred from SHA256_DIGEST_LENGTH in boringssl
constexpr size_t SHA256_SIZE = 32;

struct compact_ipdata {
    uint8_t family {AF_UNSPEC};
    uint8_t cidrlen {0U}; // written and read in host-byte order
    in_port_t port {0U}; // written and read in host-byte order
    uint32_t scope_id {0U};

    DISABLE_WARNING_PUSH
    DISABLE_WARNING_C99_EXTENSIONS
    union {
        in_addr v4;
        in6_addr v6;
    } ip {.v6 = IN6ADDR_ANY_INIT}; // written and read in network-byte order

    DISABLE_WARNING_POP
    // Classes that use compact_ipdata and this method should be sure to clear
    // (i.e. zero or make uniform) any fields not relevant to the class.
    friend bool operator==(const compact_ipdata &a, const compact_ipdata &b)
    {
        if ((a.family != b.family) || (a.cidrlen != b.cidrlen) || (a.port != b.port) || (a.scope_id != b.scope_id)) {
            return false;
        }
        switch (a.family) {
            case AF_UNSPEC:
                // After the above checks, two AF_UNSPEC objects can be
                // considered equal, for convenience.
                return true;
            case AF_INET: {
                const in_addr v4a = a.ip.v4;
                const in_addr v4b = b.ip.v4;
                return (v4a.s_addr == v4b.s_addr);
            }
            case AF_INET6: {
                const in6_addr v6a = a.ip.v6;
                const in6_addr v6b = b.ip.v6;
                return IN6_ARE_ADDR_EQUAL(&v6a, &v6b);
            }
        }
        return false;
    }

    // Classes that use compact_ipdata and this method should be sure to clear
    // (i.e. zero or make uniform) any fields not relevant to the class.
    friend bool operator!=(const compact_ipdata &a, const compact_ipdata &b)
    {
        return !(a == b);
    }

    // Classes that use compact_ipdata and this method should be sure to clear
    // (i.e. zero or make uniform) any fields not relevant to the class.
    friend bool operator<(const compact_ipdata &a, const compact_ipdata &b)
    {
        if (a.family != b.family)
            return (a.family < b.family);
        switch (a.family) {
            case AF_INET: {
                const in_addr v4a = a.ip.v4;
                const in_addr v4b = b.ip.v4;
                if (v4a.s_addr != v4b.s_addr)
                    return (ntohl(v4a.s_addr) < ntohl(v4b.s_addr));
                break;
            }
            case AF_INET6: {
                const in6_addr v6a = a.ip.v6;
                const in6_addr v6b = b.ip.v6;
                const int cmp = std::memcmp(v6a.s6_addr, v6b.s6_addr, IPV6_ADDR_LEN);
                if (cmp != 0)
                    return cmp < 0;
                break;
            }
        }
        if (a.cidrlen != b.cidrlen)
            return (a.cidrlen < b.cidrlen);
        if (a.port != b.port)
            return (a.port < b.port);
        return (a.scope_id < b.scope_id);
    }
};

static_assert(AF_UNSPEC <= std::numeric_limits<uint8_t>::max(), "AF_UNSPEC value too large");
static_assert(AF_INET <= std::numeric_limits<uint8_t>::max(), "AF_INET value too large");
static_assert(AF_INET6 <= std::numeric_limits<uint8_t>::max(), "AF_INET6 value too large");
static_assert(sizeof(compact_ipdata) == 24U, "compact_ipdata unexpectedly large");

struct addrinfo_deleter {
    void operator()(struct addrinfo *p) const
    {
        if (p != nullptr) {
            freeaddrinfo(p);
        }
    }
};

typedef std::unique_ptr<struct addrinfo, struct addrinfo_deleter> ScopedAddrinfo;

inline bool usesScopedIds(const in6_addr &ipv6)
{
    return (IN6_IS_ADDR_LINKLOCAL(&ipv6) || IN6_IS_ADDR_MC_LINKLOCAL(&ipv6));
}

class ip_prefix;
class ip_sock_addr;

class ip_address {
public:
    static bool forString(const std::string &repr, ip_address *ip);
    static ip_address forString(const std::string &repr)
    {
        ip_address ip;
        if (!forString(repr, &ip))
            return ip_address();
        return ip;
    }

    ip_address() = default;
    ip_address(const ip_address &) = default;
    ip_address(ip_address &&) = default;

    DISABLE_WARNING_PUSH
    DISABLE_WARNING_C99_EXTENSIONS

    explicit ip_address(const in_addr &ipv4) : mData({AF_INET, IPV4_ADDR_BITS, 0U, 0U, {.v4 = ipv4}}) {}
    explicit ip_address(const in6_addr &ipv6) : mData({AF_INET6, IPV6_ADDR_BITS, 0U, 0U, {.v6 = ipv6}}) {}
    ip_address(const in6_addr &ipv6, uint32_t scope_id)
        : mData({AF_INET6, IPV6_ADDR_BITS, 0U,
              // Sanity check: scoped_ids only for link-local addresses.
              usesScopedIds(ipv6) ? scope_id : 0U, {.v6 = ipv6}})
    {}

    DISABLE_WARNING_POP

    ip_address(const ip_address &ip, uint32_t scope_id) : ip_address(ip)
    {
        mData.scope_id = (family() == AF_INET6 && usesScopedIds(mData.ip.v6)) ? scope_id : 0U;
    }

    ip_address &operator=(const ip_address &) = default;
    ip_address &operator=(ip_address &&) = default;

    constexpr sa_family_t family() const noexcept
    {
        return mData.family;
    }
    constexpr uint32_t scope_id() const noexcept
    {
        return mData.scope_id;
    }

    std::string toString() const noexcept;

    friend std::ostream &operator<<(std::ostream &os, const ip_address &ip)
    {
        os << ip.toString();
        return os;
    }
    friend bool operator==(const ip_address &a, const ip_address &b)
    {
        return (a.mData == b.mData);
    }
    friend bool operator!=(const ip_address &a, const ip_address &b)
    {
        return (a.mData != b.mData);
    }
    friend bool operator<(const ip_address &a, const ip_address &b)
    {
        return (a.mData < b.mData);
    }
    friend bool operator>(const ip_address &a, const ip_address &b)
    {
        return (b.mData < a.mData);
    }
    friend bool operator<=(const ip_address &a, const ip_address &b)
    {
        return (a < b) || (a == b);
    }
    friend bool operator>=(const ip_address &a, const ip_address &b)
    {
        return (b < a) || (a == b);
    }

private:
    friend class ip_prefix;
    friend class ip_sock_addr;

    explicit ip_address(const compact_ipdata &ipdata) : mData(ipdata)
    {
        mData.port = 0U;
        switch (mData.family) {
            case AF_INET:
                mData.cidrlen = IPV4_ADDR_BITS;
                mData.scope_id = 0U;
                break;
            case AF_INET6:
                mData.cidrlen = IPV6_ADDR_BITS;
                if (usesScopedIds(ipdata.ip.v6))
                    mData.scope_id = ipdata.scope_id;
                break;
            default:
                mData.cidrlen = 0U;
                mData.scope_id = 0U;
                break;
        }
    }

    compact_ipdata mData {};
};

class ip_prefix {
public:
    static bool forString(const std::string &repr, ip_prefix *prefix);
    static ip_prefix forString(const std::string &repr)
    {
        ip_prefix prefix;
        if (!forString(repr, &prefix))
            return ip_prefix();
        return prefix;
    }

    ip_prefix() = default;
    ip_prefix(const ip_prefix &) = default;
    ip_prefix(ip_prefix &&) = default;

    explicit ip_prefix(const ip_address &ip) : mData(ip.mData) {}

    // Truncate the IP address |ip| at length |length|. Lengths greater than
    // the address-family-relevant maximum, along with negative values, are
    // interpreted as if the address-family-relevant maximum had been given.
    ip_prefix(const ip_address &ip, size_t length);

    ip_prefix &operator=(const ip_prefix &) = default;
    ip_prefix &operator=(ip_prefix &&) = default;

    constexpr sa_family_t family() const noexcept
    {
        return mData.family;
    }
    ip_address ip() const noexcept
    {
        return ip_address(mData);
    }
    in_addr addr4() const noexcept
    {
        return mData.ip.v4;
    }
    in6_addr addr6() const noexcept
    {
        return mData.ip.v6;
    }
    constexpr int length() const noexcept
    {
        return mData.cidrlen;
    }

    bool isUninitialized() const noexcept;
    std::string toString() const noexcept;

    friend std::ostream &operator<<(std::ostream &os, const ip_prefix &prefix)
    {
        os << prefix.toString();
        return os;
    }
    friend bool operator==(const ip_prefix &a, const ip_prefix &b)
    {
        return (a.mData == b.mData);
    }
    friend bool operator!=(const ip_prefix &a, const ip_prefix &b)
    {
        return (a.mData != b.mData);
    }
    friend bool operator<(const ip_prefix &a, const ip_prefix &b)
    {
        return (a.mData < b.mData);
    }
    friend bool operator>(const ip_prefix &a, const ip_prefix &b)
    {
        return (b.mData < a.mData);
    }
    friend bool operator<=(const ip_prefix &a, const ip_prefix &b)
    {
        return (a < b) || (a == b);
    }
    friend bool operator>=(const ip_prefix &a, const ip_prefix &b)
    {
        return (b < a) || (a == b);
    }

private:
    compact_ipdata mData {};
};

// An Internet socket address.
//
// Cannot represent other types of socket addresses (e.g. UNIX socket address, et cetera).
class ip_sock_addr {
public:
    // TODO: static forString

    static ip_sock_addr toIPSockAddr(const std::string &repr, in_port_t port)
    {
        return ip_sock_addr(ip_address::forString(repr), port);
    }
    static ip_sock_addr toIPSockAddr(const sockaddr &sa)
    {
        switch (sa.sa_family) {
            case AF_INET:
                return ip_sock_addr(*reinterpret_cast<const sockaddr_in *>(&sa));
            case AF_INET6:
                return ip_sock_addr(*reinterpret_cast<const sockaddr_in6 *>(&sa));
            default:
                return ip_sock_addr();
        }
    }
    static ip_sock_addr toIPSockAddr(const sockaddr_storage &ss)
    {
        return toIPSockAddr(*reinterpret_cast<const sockaddr *>(&ss));
    }

    ip_sock_addr() = default;
    ip_sock_addr(const ip_sock_addr &) = default;
    ip_sock_addr(ip_sock_addr &&) = default;

    explicit ip_sock_addr(const ip_address &ip) : mData(ip.mData) {}
    ip_sock_addr(const ip_address &ip, in_port_t port) : mData(ip.mData)
    {
        mData.port = port;
    }
    explicit ip_sock_addr(const sockaddr_in &ipv4sa)
        : ip_sock_addr(ip_address(ipv4sa.sin_addr), ntohs(ipv4sa.sin_port))
    {}
    explicit ip_sock_addr(const sockaddr_in6 &ipv6sa)
        : ip_sock_addr(ip_address(ipv6sa.sin6_addr, ipv6sa.sin6_scope_id), ntohs(ipv6sa.sin6_port))
    {}

    ip_sock_addr &operator=(const ip_sock_addr &) = default;
    ip_sock_addr &operator=(ip_sock_addr &&) = default;

    constexpr sa_family_t family() const noexcept
    {
        return mData.family;
    }
    ip_address ip() const noexcept
    {
        return ip_address(mData);
    }
    constexpr in_port_t port() const noexcept
    {
        return mData.port;
    }

    // Implicit conversion to sockaddr_storage.
    operator sockaddr_storage() const noexcept
    {
        sockaddr_storage ss;
        ss.ss_family = mData.family;
        switch (mData.family) {
            case AF_INET:
                reinterpret_cast<sockaddr_in *>(&ss)->sin_addr = mData.ip.v4;
                reinterpret_cast<sockaddr_in *>(&ss)->sin_port = htons(mData.port);
                break;
            case AF_INET6:
                reinterpret_cast<sockaddr_in6 *>(&ss)->sin6_addr = mData.ip.v6;
                reinterpret_cast<sockaddr_in6 *>(&ss)->sin6_port = htons(mData.port);
                reinterpret_cast<sockaddr_in6 *>(&ss)->sin6_scope_id = mData.scope_id;
                break;
        }
        return ss;
    }

    std::string toString() const noexcept;

    friend std::ostream &operator<<(std::ostream &os, const ip_sock_addr &prefix)
    {
        os << prefix.toString();
        return os;
    }
    friend bool operator==(const ip_sock_addr &a, const ip_sock_addr &b)
    {
        return (a.mData == b.mData);
    }
    friend bool operator!=(const ip_sock_addr &a, const ip_sock_addr &b)
    {
        return (a.mData != b.mData);
    }
    friend bool operator<(const ip_sock_addr &a, const ip_sock_addr &b)
    {
        return (a.mData < b.mData);
    }
    friend bool operator>(const ip_sock_addr &a, const ip_sock_addr &b)
    {
        return (b.mData < a.mData);
    }
    friend bool operator<=(const ip_sock_addr &a, const ip_sock_addr &b)
    {
        return (a < b) || (a == b);
    }
    friend bool operator>=(const ip_sock_addr &a, const ip_sock_addr &b)
    {
        return (b < a) || (a == b);
    }

private:
    compact_ipdata mData {};
};

class sock_addr_utils final {
public:
    static socklen_t sockaddrSize(const sockaddr *sa)
    {
        if (sa == nullptr) {
            return 0;
        }

        switch (sa->sa_family) {
            case AF_INET:
                return sizeof(sockaddr_in);
            case AF_INET6:
                return sizeof(sockaddr_in6);
            default:
                return 0;
        }
    }

public:
    sock_addr_utils(/* args */) = default;
    ~sock_addr_utils() = default;
};

class fd_wrapper final {
public:
    fd_wrapper() = default;
    explicit fd_wrapper(const int fd)
    {
        reset(fd);
    };
    fd_wrapper(const fd_wrapper &) = delete;
    void operator=(const fd_wrapper &) = delete;
    ~fd_wrapper()
    {
        reset();
    }

    int getFd() const
    {
        return fd_;
    }

    operator int() const
    {
        return getFd();
    }
    bool operator>=(int rhs) const
    {
        return getFd() >= rhs;
    }
    bool operator<(int rhs) const
    {
        return getFd() < rhs;
    }
    bool operator==(int rhs) const
    {
        return getFd() == rhs;
    }
    bool operator!=(int rhs) const
    {
        return getFd() != rhs;
    }
    bool operator==(const fd_wrapper &rhs) const
    {
        return getFd() == rhs.getFd();
    }
    bool operator!=(const fd_wrapper &rhs) const
    {
        return getFd() != rhs.getFd();
    }

public:
    void reset(int newFd = -1)
    {
        if (fd_ != -1) {
            close(fd_);
        }
        fd_ = newFd;
    }

private:
    int fd_ = -1;
};

using socket_fd = fd_wrapper;

} // namespace net_utils
} // namespace common
} // namespace nmd
} // namespace OHOS
#endif //!__INCLUDE_NET_ADDR_H__