
#include "get_addr_info.h"
#include "dnsresolv.h"
#include "dnsresolv_cache.h"
#include "net_utils.h"
#include "error_code.h"
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <limits>
#include <net/if.h>
#include <poll.h>
#include <random>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "utils.h"
#include <fcntl.h>
#include <sys/uio.h>
#include <warning_disable.h>
#include "logger.h"
#include "netnative_log_wrapper.h"

DISABLE_WARNING_PUSH
DISABLE_WARNING_IMPLICIT_INT_CONVERSION
DISABLE_WARNING_SHORTEN_64_TO_32
DISABLE_WARNING_SIGN_CONVERSION
DISABLE_WARNING_SIGN_COMPARE
DISABLE_WARNING_OLD_STYLE_CAST
DISABLE_WARNING_CAST_ALIGN
DISABLE_WARNING_SIGN_CONVERSION

namespace OHOS {
namespace nmd {

#define BOUNDED_INCR(x)      \
    do {                     \
        BOUNDS_CHECK(cp, x); \
        cp += (x);           \
    } while (0)

#define BOUNDS_CHECK(ptr, count)     \
    do {                             \
        if (eom - (ptr) < (count)) { \
            herrno = NO_RECOVERY;    \
            return nullptr;          \
        }                            \
    } while (0)

#define PERIOD 0x2e
#define hyphenchar(c) ((c) == 0x2d)
#define bslashchar(c) ((c) == 0x5c)
#define periodchar(c) ((c) == PERIOD)
#define asterchar(c) ((c) == 0x2a)
#define alphachar(c) (((c) >= 0x41 && (c) <= 0x5a) || ((c) >= 0x61 && (c) <= 0x7a))
#define digitchar(c) ((c) >= 0x30 && (c) <= 0x39)
#define underscorechar(c) ((c) == 0x5f)

#define borderchar(c) (alphachar(c) || digitchar(c))
#define middlechar(c) (borderchar(c) || hyphenchar(c) || underscorechar(c))
#define domainchar(c) ((c) > 0x20 && (c) < 0x7f)

bool res_hnok(const char *dn)
{
    char pch = PERIOD, ch = *dn++;

    while (ch != '\0') {
        char nch = *dn++;

        if (periodchar(ch)) {
        } else if (periodchar(pch) || periodchar(nch) || nch == '\0') {
            if (!borderchar(ch)) {
                return false;
            }
        } else {
            if (!middlechar(ch)) {
                return false;
            }
        }
        pch = ch, ch = nch;
    }
    return true;
}

const char in_addrany[] = {0, 0, 0, 0};
const char in_loopback[] = {127, 0, 0, 1};
const char in6_addrany[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
const char in6_loopback[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

const struct afd {
    int a_af;
    int a_addrlen;
    int a_socklen;
    int a_off;
    const char *a_addrany;
    const char *a_loopback;
    int a_scoped;
} afdl[] = {
    {PF_INET6, sizeof(struct in6_addr), sizeof(struct sockaddr_in6), offsetof(struct sockaddr_in6, sin6_addr),
        in6_addrany, in6_loopback, 1},
    {PF_INET, sizeof(struct in_addr), sizeof(struct sockaddr_in), offsetof(struct sockaddr_in, sin_addr),
        in_addrany, in_loopback, 0},
    {0, 0, 0, 0, nullptr, nullptr, 0},
};

struct Explore {
    int e_af;
    int e_socktype;
    int e_protocol;
    int e_wild;
#define WILD_AF(ex) ((ex).e_wild & 0x01)
#define WILD_SOCKTYPE(ex) ((ex).e_wild & 0x02)
#define WILD_PROTOCOL(ex) ((ex).e_wild & 0x04)
};

const Explore explore_options[] = {
    {PF_INET6, SOCK_DGRAM, IPPROTO_UDP, 0x07},
    {PF_INET6, SOCK_STREAM, IPPROTO_TCP, 0x07},
    {PF_INET6, SOCK_RAW, ANY_SOCK_TYPE, 0x05},
    {PF_INET, SOCK_DGRAM, IPPROTO_UDP, 0x07},
    {PF_INET, SOCK_STREAM, IPPROTO_TCP, 0x07},
    {PF_INET, SOCK_RAW, ANY_SOCK_TYPE, 0x05},
    {PF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP, 0x07},
    {PF_UNSPEC, SOCK_STREAM, IPPROTO_TCP, 0x07},
    {PF_UNSPEC, SOCK_RAW, ANY_SOCK_TYPE, 0x05},
};

class get_addr_info::hostfd_wrapper {
public:
    void sethtent()
    {
        if (nullptr == hostfd) {
            hostfd = fopen(_PATH_HOSTS, "re");
        } else {
            rewind(hostfd);
        }
    }

    void ednhtent()
    {
        if (nullptr == hostfd) {
            return;
        }
        fclose(hostfd);
        hostfd = nullptr;
    }

    addrinfo *gethtent(const char *name, const addrinfo *pai)
    {
        if (nullptr == hostfd) {
            sethtent();
        }

        if (nullptr == hostfd) {
            return nullptr;
        }

        char hostbuf[MAX_PACKET] = {};
        char *p(nullptr);
        char *cp(nullptr);
        char *cname(nullptr);
        char *tname(nullptr);
        const char *addr(nullptr);
    again:
        if (!(p = fgets(hostbuf, sizeof(hostbuf), hostfd))) {
            return nullptr;
        }
        if (*p == '#') {
            goto again;
        }
        if (!(cp = strpbrk(p, "#\n"))) {
            goto again;
        }
        *cp = '\0';
        if (!(cp = strpbrk(p, " \t"))) {
            goto again;
        }
        *cp++ = '\0';
        addr = p;
        cname = nullptr;
        while (cp && *cp) {
            if (*cp == ' ' || *cp == '\t') {
                cp++;
                continue;
            }
            if (!cname) {
                cname = cp;
            }
            tname = cp;
            if ((cp = strpbrk(cp, " \t")) != nullptr) {
                *cp++ = '\0';
            }
            if (strcasecmp(name, tname) == 0) {
                goto found;
            }
        }
        goto again;

    found:
        addrinfo *result(nullptr);
        int error = getaddrinfoNumeric(addr, nullptr, *pai, &result);
        if (error) {
            goto again;
        }

        for (addrinfo *cur = result; cur; cur = cur->ai_next) {
            cur->ai_flags = pai->ai_flags;

            if (pai->ai_flags & AI_CANONNAME) {
                if (getCanonName(pai, cur, cname) != 0) {
                    freeaddrinfo(result);
                    goto again;
                }
            }
        }
        return result;
    }

private:
    FILE *hostfd = nullptr;
};

int nmd::get_addr_info::getaddrinfoFornetContext(const char *hostname, const char *servname, const addrinfo *hints,
    const netd_net_context *netcontext, addrinfo **res)
{
    if (nullptr == netcontext || nullptr == res) {
        return -1;
    }

    addrinfo sentinel = {};
    addrinfo *cur = &sentinel;
    int ret = 0;
    do {
        if (nullptr == hostname && nullptr == servname) {
            ret = EAI_NONAME;
            break;
        }

        if (nullptr != hints && ((ret = validateHints(hints)) != 0)) {
            break;
        }

        addrinfo tmpAdrrInfo = nullptr != hints ? *hints : addrinfo {};

        if ((ret = checkHostNameAndExplore(tmpAdrrInfo, hostname, servname, cur)) != 0) {
            break;
        }

        if (sentinel.ai_next != nullptr) {
            break;
        }

        if (hostname == nullptr) {
            ret = EAI_NODATA;
            break;
        }

        if (tmpAdrrInfo.ai_flags & AI_NUMERICHOST) {
            ret = EAI_NONAME;
            break;
        }

        return resolvGetAddrInfo(hostname, servname, hints, netcontext, res);

    } while (0);

    if (ret != 0) {
        freeaddrinfo(sentinel.ai_next);
        *res = nullptr;
    } else {
        *res = sentinel.ai_next;
    }

    return ret;
}

int nmd::get_addr_info::validateHints(const addrinfo *hints)
{
    if (nullptr == hints) {
        return static_cast<int>(common::dnsresolv_error_code::errBadHints);
    }

    // error check for hints
    if (0 != hints->ai_addrlen || nullptr != hints->ai_canonname || nullptr != hints->ai_addr ||
        nullptr != hints->ai_next) {
        return static_cast<int>(common::dnsresolv_error_code::errBadHints);
    }

    if (hints->ai_flags & ~AI_MASK) {
        return EAI_BADFLAGS;
    }

    if (!(hints->ai_family == PF_UNSPEC || hints->ai_family == PF_INET || hints->ai_family == PF_INET6)) {
        return EAI_FAMILY;
    }

    // Socket types which are not in explore_options.
    switch (hints->ai_socktype) {
        case SOCK_RAW:
        case SOCK_DGRAM:
        case SOCK_STREAM:
        case ANY_SOCK_TYPE:
            break;
        default:
            return EAI_SOCKTYPE;
    }

    if (hints->ai_socktype == ANY_SOCK_TYPE || hints->ai_protocol == ANY_SOCK_TYPE) {
        return 0;
    }

    // if both socktype/protocol are specified, check if they are meaningful combination.
    for (const Explore &ex : explore_options) {
        if (hints->ai_family != ex.e_af) {
            continue;
        }
        if (ex.e_socktype == ANY_SOCK_TYPE) {
            continue;
        }
        if (ex.e_protocol == ANY_SOCK_TYPE) {
            continue;
        }
        if (hints->ai_socktype == ex.e_socktype && hints->ai_protocol != ex.e_protocol) {
            return static_cast<int>(common::dnsresolv_error_code::errBadHints);
        }
    }

    return 0;
}

int nmd::get_addr_info::checkHostNameAndExplore(
    const addrinfo &ai, const char *hostname, const char *servname, addrinfo *cur)
{
    // Check for special cases:
    // (1) numeric servname is disallowed if socktype/protocol are left unspecified.
    // (2) servname is disallowed for raw and other inet{,6} sockets.
    if (MATCH_FAMILY(ai.ai_family, PF_INET, 1) || MATCH_FAMILY(ai.ai_family, PF_INET6, 1)) {
        addrinfo tmp = ai;
        if (tmp.ai_family == PF_UNSPEC) {
            tmp.ai_family = PF_INET6;
        }
        auto ret = getPort(&tmp, servname, true);
        if (0 != ret) {
            return ret;
        }
    }

    // NULL hostname, or numeric hostname
    int error = 0;
    for (const Explore &ex : explore_options) {
        /* PF_UNSPEC entries are prepared for DNS queries only */
        if (ex.e_af == PF_UNSPEC) {
            continue;
        }

        if (!MATCH_FAMILY(ai.ai_family, ex.e_af, WILD_AF(ex))) {
            continue;
        }

        if (!MATCH(ai.ai_socktype, ex.e_socktype, WILD_SOCKTYPE(ex))) {
            continue;
        }

        if (!MATCH(ai.ai_protocol, ex.e_protocol, WILD_PROTOCOL(ex))) {
            continue;
        }

        addrinfo tmp = ai;
        if (tmp.ai_family == PF_UNSPEC) {
            tmp.ai_family = ex.e_af;
        }

        if (tmp.ai_socktype == ANY_SOCK_TYPE && ex.e_socktype != ANY_SOCK_TYPE) {
            tmp.ai_socktype = ex.e_socktype;
        }

        if (tmp.ai_protocol == ANY_SOCK_TYPE && ex.e_protocol != ANY_SOCK_TYPE) {
            tmp.ai_protocol = ex.e_protocol;
        }

        if (hostname == nullptr) {
            error = exploreNull(&tmp, servname, &cur->ai_next);
        } else {
            error = exploreNumericScope(&tmp, hostname, servname, &cur->ai_next);
        }

        if (error != 0) {
            return -1;
        };

        while (cur->ai_next)
            cur = cur->ai_next;
    }
    return 0;
}

int nmd::get_addr_info::strToNumber(const char *p)
{
    if (*p == '\0') {
        return -1;
    }
    char *ep = nullptr;
    errno = 0;
    unsigned long v = strtoul(p, &ep, 10);
    if (errno == 0 && ep && *ep == '\0' && v <= std::numeric_limits<unsigned int>::max()) {
        return static_cast<int>(v);
    } else {
        return -1;
    }
}

int nmd::get_addr_info::exploreNull(const addrinfo *pai, const char *servname, addrinfo **res)
{
    *res = nullptr;
    struct addrinfo sentinel;
    sentinel.ai_next = nullptr;
    struct addrinfo *cur = &sentinel;

    int socketFd = socket(pai->ai_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (socketFd < 0) {
        if (errno != EMFILE) {
            return 0;
        }
    } else {
        close(socketFd);
    }

    // if the servname does not match socktype/protocol, ignore it.
    if (getPort(pai, servname, true) != 0) {
        return 0;
    }

    const struct afd *pafd = findAfd(pai->ai_family);
    if (pafd == nullptr) {
        return 0;
    }

    int error;
    if (pai->ai_flags & AI_PASSIVE) {
        GET_AI(cur->ai_next, pafd, pafd->a_addrany);
        GET_PORT(cur->ai_next, servname);
    } else {
        GET_AI(cur->ai_next, pafd, pafd->a_loopback);
        GET_PORT(cur->ai_next, servname);
    }
    cur = cur->ai_next;

    *res = sentinel.ai_next;
    return 0;
free:
    freeaddrinfo(sentinel.ai_next);
    return error;
}

const nmd::afd *nmd::get_addr_info::findAfd(int af)
{
    if (af == PF_UNSPEC) {
        return nullptr;
    }

    for (const nmd::afd *pafd = afdl; pafd->a_af; pafd++) {
        if (pafd->a_af == af) {
            return pafd;
        }
    }
    return nullptr;
}

addrinfo *nmd::get_addr_info::getAi(const addrinfo *pai, const afd *pafd, const char *addr)
{
    struct addrinfo *ai =
        reinterpret_cast<struct addrinfo *>(malloc(sizeof(struct addrinfo) + sizeof(sockaddr_union)));
    if (nullptr == ai) {
        return nullptr;
    }

    memcpy(ai, pai, sizeof(struct addrinfo));
    ai->ai_addr = reinterpret_cast<struct sockaddr *>(ai + 1);
    memset(ai->ai_addr, 0, sizeof(sockaddr_union));

    ai->ai_addrlen = static_cast<unsigned int>(pafd->a_socklen);
    ai->ai_addr->sa_family = static_cast<unsigned short>(ai->ai_family = pafd->a_af);
    char *p = reinterpret_cast<char *>(ai->ai_addr);
    memcpy(p + pafd->a_off, addr, static_cast<size_t>(pafd->a_addrlen));
    return ai;
}

int nmd::get_addr_info::getPort(const addrinfo *ai, const char *servname, bool matchonly)
{
    if (nullptr == servname) {
        return 0;
    }

    switch (ai->ai_family) {
        case AF_INET:
        case AF_INET6:
            break;
        default:
            return 0;
    }

    bool allownumeric(false);
    switch (ai->ai_socktype) {
        case SOCK_RAW:
            return EAI_SERVICE;
        case SOCK_DGRAM:
        case SOCK_STREAM:
        case ANY_SOCK_TYPE:
            allownumeric = true;
            break;
        default:
            return EAI_SOCKTYPE;
    }

    auto port = strToNumber(servname);
    if (port >= 0) {
        if (!allownumeric) {
            return EAI_SERVICE;
        }
        if (port < 0 || port > 65535) {
            return EAI_SERVICE;
        }
        port = htons(static_cast<uint16_t>(port));
    } else {
        if (ai->ai_flags & AI_NUMERICSERV) {
            return EAI_NONAME;
        }

        std::string proto;
        switch (ai->ai_socktype) {
            case SOCK_DGRAM:
                proto = "udp";
                break;
            case SOCK_STREAM:
                proto = "tcp";
                break;
            default:
                proto.clear();
                break;
        }

        auto srv = getservbyname(servname, proto.c_str());
        if (nullptr == srv) {
            return EAI_SERVICE;
        }
        port = srv->s_port;
    }

    if (!matchonly) {
        switch (ai->ai_family) {
            case AF_INET:
                (reinterpret_cast<struct sockaddr_in *>(ai->ai_addr))->sin_port = static_cast<uint16_t>(port);
                break;
            case AF_INET6:
                (reinterpret_cast<struct sockaddr_in6 *>(ai->ai_addr))->sin6_port = static_cast<uint16_t>(port);
                break;
        }
    }

    return 0;
}

int nmd::get_addr_info::exploreNumericScope(
    const addrinfo *pai, const char *hostname, const char *servname, addrinfo **res)
{
    // if the servname does not match socktype/protocol, ignore it.
    if (getPort(pai, servname, true) != 0) {
        return 0;
    }

    const struct afd *pafd = findAfd(pai->ai_family);
    if (pafd == nullptr) {
        return 0;
    }

    if (!pafd->a_scoped) {
        return exploreNumeric(pai, hostname, servname, res, hostname);
    }

    const char *cp = strchr(hostname, SCOPE_DELIMITER);
    if (cp == nullptr) {
        return exploreNumeric(pai, hostname, servname, res, hostname);
    }

    auto hostFreeFunc = [](char *host) {
        if (nullptr == host) {
            return;
        }
        free(host);
    };
    char *hostname2 = strdup(hostname);
    common::utils::auto_destroyer<char *> autoFreeHost(hostname2, hostFreeFunc);
    if (nullptr == hostname2) {
        return EAI_MEMORY;
    }

    hostname2[cp - hostname] = '\0';
    const char *addr = hostname2;
    const char *scope = cp + 1;

    int error = exploreNumeric(pai, addr, servname, res, hostname);
    if (error == 0) {
        for (struct addrinfo *cur = *res; cur; cur = cur->ai_next) {
            if (cur->ai_family != AF_INET6) {
                continue;
            }
            struct sockaddr_in6 *sin6 = reinterpret_cast<struct sockaddr_in6 *>(cur->ai_addr);

            uint32_t scopeid(0);
            if (ip6StrToScopeid(scope, *sin6, scopeid) != 0) {
                return EAI_NODATA;
            }
            sin6->sin6_scope_id = scopeid;
        }
    }

    return error;
}

int nmd::get_addr_info::exploreNumeric(
    const addrinfo *pai, const char *hostname, const char *servname, addrinfo **res, const char *canonname)
{
    int error;
    const struct afd *pafd(nullptr);
    struct addrinfo *cur(nullptr);
    struct addrinfo sentinel;
    char pton[PTON_MAX] = {};

    *res = nullptr;
    sentinel.ai_next = nullptr;
    cur = &sentinel;

    if (getPort(pai, servname, true) != 0) {
        return 0;
    }

    pafd = findAfd(pai->ai_family);
    if (nullptr == pafd) {
        return 0;
    }

    if (inet_pton(pafd->a_af, hostname, pton) == 1) {
        if (pai->ai_family == pafd->a_af || pai->ai_family == PF_UNSPEC) {
            GET_AI(cur->ai_next, pafd, pton);
            GET_PORT(cur->ai_next, servname);
            if ((pai->ai_flags & AI_CANONNAME)) {
                /*
                 * Set the numeric address itself as
                 * the canonical name, based on a
                 * clarification in rfc2553bis-03.
                 */
                error = getCanonName(pai, cur->ai_next, canonname);
                if (error != 0) {
                    freeaddrinfo(sentinel.ai_next);
                    return error;
                }
            }
            while (cur->ai_next)
                cur = cur->ai_next;
        } else {
            return EAI_FAMILY;
        }
    }

    *res = sentinel.ai_next;
    return 0;

free:
    freeaddrinfo(sentinel.ai_next);
    return error;
}

int nmd::get_addr_info::ip6StrToScopeid(const char *scope, const struct sockaddr_in6 &sin6, uint32_t &scopeid)
{
    const struct in6_addr *a6 = &sin6.sin6_addr;

    // empty scopeid portion is invalid
    if (*scope == '\0') {
        return -1;
    }

    if (IN6_IS_ADDR_LINKLOCAL(a6) || IN6_IS_ADDR_MC_LINKLOCAL(a6)) {
        /*
         * We currently assume a one-to-one mapping between links
         * and interfaces, so we simply use interface indices for
         * like-local scopes.
         */
        scopeid = if_nametoindex(scope);
        if (scopeid != 0) {
            return 0;
        }
    }

    // try to convert to a numeric id as a last resort
    errno = 0;
    char *ep(nullptr);
    uint64_t lscopeid = strtoul(scope, &ep, 10);
    scopeid = static_cast<uint32_t>(lscopeid & 0xffffffffUL);
    if (errno == 0 && ep && *ep == '\0' && scopeid == lscopeid) {
        return 0;
    } else {
        return -1;
    }
}

int nmd::get_addr_info::getCanonName(const addrinfo *pai, addrinfo *ai, const char *str)
{
    if ((pai->ai_flags & AI_CANONNAME) != 0) {
        ai->ai_canonname = strdup(str);
        if (nullptr == ai->ai_canonname) {
            return EAI_MEMORY;
        }
    }
    return 0;
}

int nmd::get_addr_info::resolvGetAddrInfo(const char *hostname, const char *servname, const addrinfo *hints,
    const netd_net_context *netcontext, addrinfo **res)
{
    if (hostname == nullptr && servname == nullptr) {
        return EAI_NONAME;
    }

    if (hostname == nullptr) {
        return EAI_NODATA;
    }

    int error = EAI_FAIL;
    if (hints && (error = validateHints(hints))) {
        *res = nullptr;
        return error;
    }

    addrinfo ai = hints ? *hints : addrinfo {};
    addrinfo sentinel = {};
    addrinfo *cur = &sentinel;
    // hostname as alphanumeric name.
    // We would like to prefer AF_INET6 over AF_INET, so we'll make a outer loop by AFs.
    for (const Explore &ex : explore_options) {
        // Require exact match for family field
        if (ai.ai_family != ex.e_af) {
            continue;
        }

        if (!MATCH(ai.ai_socktype, ex.e_socktype, WILD_SOCKTYPE(ex))) {
            continue;
        }

        if (!MATCH(ai.ai_protocol, ex.e_protocol, WILD_PROTOCOL(ex))) {
            continue;
        }

        addrinfo tmp = ai;
        if (tmp.ai_socktype == ANY_SOCK_TYPE && ex.e_socktype != ANY_SOCK_TYPE) {
            tmp.ai_socktype = ex.e_socktype;
        }

        if (tmp.ai_protocol == ANY_SOCK_TYPE && ex.e_protocol != ANY_SOCK_TYPE) {
            tmp.ai_protocol = ex.e_protocol;
        }

        error = exploreFqdn(&tmp, hostname, servname, &cur->ai_next, netcontext);

        while (cur->ai_next)
            cur = cur->ai_next;
    }

    if ((*res = sentinel.ai_next)) {
        return 0;
    }

    freeaddrinfo(sentinel.ai_next);
    *res = nullptr;
    return (error == 0) ? EAI_FAIL : error;
}

int nmd::get_addr_info::exploreFqdn(const addrinfo *pai, const char *hostname, const char *servname,
    addrinfo **res, const netd_net_context *netcontext)
{
    addrinfo *result = nullptr;
    int error = 0;

    // If the servname does not match socktype/protocol, return error code.
    if ((error = getPort(pai, servname, true))) {
        return error;
    }

    if (!getAddrinfoFromFile(hostname, pai, &result)) {
        error = dnsGetaddrinfo(hostname, pai, netcontext, &result);
    }
    if (error) {
        freeaddrinfo(result);
        return error;
    }

    for (addrinfo *cur = result; cur; cur = cur->ai_next) {
        // canonname should be filled already
        if ((error = getPort(cur, servname, 0))) {
            freeaddrinfo(result);
            return error;
        }
    }
    *res = result;
    return 0;
}

bool nmd::get_addr_info::getAddrinfoFromFile(const char *name, const addrinfo *pai, addrinfo **res)
{
    struct addrinfo sentinel = {};
    struct addrinfo *cur = &sentinel;
    hostfd_wrapper hostfd;
    struct addrinfo *p(nullptr);
    while ((p = hostfd.gethtent(name, pai)) != nullptr) {
        cur->ai_next = p;
        while (cur && cur->ai_next)
            cur = cur->ai_next;
    }

    *res = sentinel.ai_next;
    return sentinel.ai_next != nullptr;
}

int nmd::get_addr_info::dnsGetaddrinfo(
    const char *name, const addrinfo *pai, const netd_net_context *netcontext, addrinfo **rv)
{
    res_target q = {};
    res_target q2 = {};

    switch (pai->ai_family) {
        case AF_UNSPEC: {
            /* prefer IPv6 */
            q.name = name;
            q.qclass = C_IN;
            bool query_ipv6(true);
            bool query_ipv4(true);
            if (pai->ai_flags & AI_ADDRCONFIG) {
                query_ipv6 = haveIpv6(netcontext->appMark, netcontext->uid);
                query_ipv4 = haveIpv4(netcontext->appMark, netcontext->uid);
            }
            if (query_ipv6) {
                q.qtype = T_AAAA;
                if (query_ipv4) {
                    q.next = &q2;
                    q2.name = name;
                    q2.qclass = C_IN;
                    q2.qtype = T_A;
                }
            } else if (query_ipv4) {
                q.qtype = T_A;
            } else {
                return EAI_NODATA;
            }
            break;
        }
        case AF_INET:
            q.name = name;
            q.qclass = C_IN;
            q.qtype = T_A;
            break;
        case AF_INET6:
            q.name = name;
            q.qclass = C_IN;
            q.qtype = T_AAAA;
            break;
        default:
            return EAI_FAMILY;
    }

    dns_res_state res;
    res.init(netcontext);

    int error(0);
    if (resSearchN(name, &q, res, error) < 0) {
        return error;
    }

    addrinfo sentinel = {};
    addrinfo *cur = &sentinel;
    addrinfo *ai = getAnswer(q.answer, q.n, q.name, q.qtype, pai, error);
    if (nullptr != ai) {
        cur->ai_next = ai;
        while (cur && cur->ai_next)
            cur = cur->ai_next;
    }
    if (q.next) {
        ai = getAnswer(q2.answer, q2.n, q2.name, q2.qtype, pai, error);
        if (nullptr != ai) {
            cur->ai_next = ai;
        }
    }

    if (nullptr == sentinel.ai_next) {
        return error;
    }

    *rv = sentinel.ai_next;
    return 0;
}

bool nmd::get_addr_info::haveIpv6(uint32_t mark, uid_t uid)
{
    DISABLE_WARNING_PUSH
    DISABLE_WARNING_C99_EXTENSIONS
    static const struct sockaddr_in6 sin6_test = {.sin6_family = AF_INET6,
        .sin6_addr.s6_addr = {// 2000::
            0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
    sockaddr_union addr = {.sin6 = sin6_test};
    DISABLE_WARNING_POP
    return findSrcAddr(&addr.sa, nullptr, mark, uid) == 1;
}

bool nmd::get_addr_info::haveIpv4(uint32_t mark, uid_t uid)
{
    static sockaddr_in sin_test = {};
    sin_test.sin_family = AF_INET,
    sin_test.sin_addr.s_addr = inet_addr("8.8.8.8"); // 8.8.8.8
    sockaddr_union addr = {};
    addr.sin = sin_test;
    return findSrcAddr(&addr.sa, nullptr, mark, uid) == 1;
}

int nmd::get_addr_info::findSrcAddr(const sockaddr *addr, sockaddr *src_addr, unsigned mark, uid_t uid)
{
    socklen_t len(0);

    switch (addr->sa_family) {
        case AF_INET:
            len = sizeof(struct sockaddr_in);
            break;
        case AF_INET6:
            len = sizeof(struct sockaddr_in6);
            break;
        default:
            return 0;
    }

    int sock = socket(addr->sa_family, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
    if (sock == -1) {
        if (errno == EAFNOSUPPORT) {
            return 0;
        } else {
            return -1;
        }
    }
    if (mark != MARK_UNSET && setsockopt(sock, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0) {
        close(sock);
        return 0;
    }
    if (uid > 0 && uid != NET_CONTEXT_INVALID_UID && fchown(sock, uid, static_cast<gid_t>(-1)) < 0) {
        close(sock);
        return 0;
    }

    int ret(-1);
    do {
        ret = connect(sock, addr, len);
    } while (ret == -1 && errno == EINTR);

    if (ret == -1) {
        close(sock);
        return 0;
    }

    if (src_addr && getsockname(sock, src_addr, &len) == -1) {
        close(sock);
        return -1;
    }
    close(sock);
    return 1;
}

bool nmd::get_addr_info::isTrailingWithDot(const std::string &name, uint32_t &dots)
{
    const char *cp(nullptr);
    for (cp = name.c_str(); *cp; cp++) {
        dots += (*cp == '.');
    }
    return (cp > name && *--cp == '.') ? true : false;
}

int nmd::get_addr_info::tryQueyWithDomain(const bool trailingDot, const std::string &name, const uint32_t dots,
    res_target *target, dns_res_state &res, int &herrno)
{
    HEADER *hp = reinterpret_cast<HEADER *>(target->answer.data());
    int saved_herrno = -1;
    int gotNoData = 0;
    int gotServFail = 0;
    int triedAsIs = 0;
    int ret = 0;
    if (dots >= res.ndots) {
        ret = resQueryDomainN(name.c_str(), nullptr, target, res, herrno);
        if (ret > 0) {
            return ret;
        }
        saved_herrno = herrno;
        triedAsIs++;
    }

    if ((!dots) || (dots && !trailingDot)) {
        int done = 0;

        getResolvConfigFromCache(res);

        for (const auto &domain : res.searchDomains) {
            ret = resQueryDomainN(name.c_str(), domain.c_str(), target, res, herrno);
            if (ret > 0) {
                return ret;
            }

            /*
             * If no server present, give up.
             * If name isn't found in this domain,
             * keep trying higher domains in the search list
             * (if that's enabled).
             * On a NO_DATA error, keep trying, otherwise
             * a wildcard entry of another type could keep us
             * from finding this entry higher in the domain.
             * If we get some other error (negative answer or
             * server failure), then stop searching up,
             * but try the input name below in case it's
             * fully-qualified.
             */
            if (errno == ECONNREFUSED) {
                herrno = TRY_AGAIN;
                return -1;
            }

            switch (herrno) {
                case NO_DATA:
                    gotNoData++;
                    [[fallthrough]];
                case HOST_NOT_FOUND:
                    break;
                case TRY_AGAIN:
                    if (hp->rcode == SERVFAIL) {
                        // try next search element, if any
                        gotServFail++;
                        break;
                    }
                    [[fallthrough]];
                default:
                    // anything else implies that we're done
                    done++;
            }
        }
    }

    /*
     * if we have not already tried the name "as is", do that now.
     * note that we do this regardless of how many dots were in the
     * name or whether it ends with a dot.
     */
    if (!triedAsIs) {
        ret = resQueryDomainN(name.c_str(), nullptr, target, res, herrno);
        if (ret > 0) {
            return ret;
        }
    }

    /*
     * if we got here, we didn't satisfy the search.
     * if we did an initial full query, return that query's h_errno
     * (note that we wouldn't be here if that query had succeeded).
     * else if we ever got a nodata, send that back as the reason.
     * else send back meaningless h_errno, that being the one from
     * the last DNSRCH we did.
     */
    if (saved_herrno != -1) {
        herrno = saved_herrno;
    } else if (gotNoData) {
        herrno = NO_DATA;
    } else if (gotServFail) {
        herrno = TRY_AGAIN;
    }
    return -1;
}

int nmd::get_addr_info::resSearchN(const char *name, res_target *target, dns_res_state &res, int &herrno)
{
    errno = 0;
    herrno = HOST_NOT_FOUND;
    uint32_t dots = 0;
    const bool trailingDot = isTrailingWithDot(name, dots);

    /*
     * If there are dots in the name already, let's just give it a try
     * 'as is'.  The threshold can be set with the "ndots" option.
     */
    return tryQueyWithDomain(trailingDot, name, dots, target, res, herrno);
}

int nmd::get_addr_info::resQueryDomainN(
    const char *name, const char *domain, res_target *target, dns_res_state &res, int &herrno)
{
    char nbuf[MAXDNAME] = {};
    const char *longname(nbuf);
    size_t n(0);
    size_t d(0);
    if (domain == nullptr) {
        // Check for trailing '.'; copy without '.' if present.
        n = strlen(name);
        if (n + 1 > sizeof(nbuf)) {
            herrno = NO_RECOVERY;
            return -1;
        }
        if (n > 0 && name[--n] == '.') {
            strncpy(nbuf, name, n);
            nbuf[n] = '\0';
        } else {
            longname = name;
        }
    } else {
        n = strlen(name);
        d = strlen(domain);
        if (n + 1 + d + 1 > sizeof(nbuf)) {
            herrno = NO_RECOVERY;
            return -1;
        }
        snprintf(nbuf, sizeof(nbuf), "%s.%s", name, domain);
    }
    return resQueryN(longname, target, res, herrno);
}

int nmd::get_addr_info::resQueryN(const char *name, res_target *target, dns_res_state &res, int &herrno)
{
    int rcode = NOERROR;
    int ancount = 0;

    for (res_target *t = target; t; t = t->next) {
        HEADER *hp = reinterpret_cast<HEADER *>(t->answer.data());
        hp->rcode = NOERROR; /* default */

        int cl = t->qclass;
        int type = t->qtype;
        const size_t anslen = t->answer.size();

        uint8_t buf[MAX_PACKET] = {};
        int n = resMakePacketForQuery(
            QUERY, reinterpret_cast<const uint8_t *>(name), cl, type, nullptr, 0, buf, sizeof(buf));
        if (n <= 0) {
            // common::logger::error() << "[get_addr_info] Unable to resMakePacketForQuery. " << endl;
            NETNATIVE_LOGE("[get_addr_info] Unable to resMakePacketForQuery. ");
            herrno = NO_RECOVERY;
            return n;
        }

        n = resQueryPacketSend(res, buf, static_cast<size_t>(n), t->answer.data(), anslen, rcode, 0);
        if (n < 0 || hp->rcode != NOERROR || ntohs(hp->ancount) == 0) {
            if (rcode != RCODE_TIMEOUT) {
                rcode = hp->rcode; // record most recent error
            }
            continue;
        }

        ancount += ntohs(hp->ancount);
        t->n = static_cast<size_t>(n);
    }

    if (ancount == 0) {
        herrno = getHerrnoFromRcode(rcode);
        return -1;
    }
    return ancount;
}

int nmd::get_addr_info::resMakePacketForQuery(uint32_t op, const uint8_t *dname, int cl, int type,
    const uint8_t *data, size_t datalen, uint8_t *buf, size_t buflen)
{
    if ((buf == nullptr) || (buflen < HFIXEDSZ)) {
        return -1;
    }
    memset(buf, 0, HFIXEDSZ);
    HEADER *hp = reinterpret_cast<HEADER *>(buf);
    std::random_device rd; // Will be used to obtain a seed for the random number engine
    std::mt19937 gen(rd()); // Standard mersenne_twister_engine seeded with rd()
    std::uniform_int_distribution<> distrib(0, 65536);
    hp->id = htons(static_cast<uint16_t>(distrib(gen)));
    hp->opcode = op;
    hp->rd = true;
    hp->ad = false;
    hp->rcode = NOERROR;
    uint8_t *cp = buf + HFIXEDSZ;
    uint8_t *ep = buf + buflen;

    const uint8_t *dnptrs[20] = {};
    const uint8_t **dpp = dnptrs;
    *dpp++ = buf;
    *dpp++ = nullptr;
    const uint8_t **lastdnptr = dnptrs + sizeof dnptrs / sizeof dnptrs[0];

    // perform opcode specific processing
    switch (op) {
        case QUERY:
            [[fallthrough]];
        case NS_NOTIFY_OP: {
            if (ep - cp < QFIXEDSZ) {
                return -1;
            }
            int n(-1);
            if ((n = dnCompress(dname, cp, static_cast<size_t>(ep - cp - QFIXEDSZ), dnptrs, lastdnptr)) < 0) {
                return -1;
            }
            cp += n;
            *reinterpret_cast<uint16_t *>(cp) = htons(static_cast<uint16_t>(type));
            cp += INT16SZ;
            *reinterpret_cast<uint16_t *>(cp) = htons(static_cast<uint16_t>(cl));
            cp += INT16SZ;
            hp->qdcount = htons(1);
            if (op == QUERY || data == nullptr) {
                break;
            }

            // Make an additional record for completion domain.
            if ((ep - cp) < RRFIXEDSZ) {
                return -1;
            }
            n = dnCompress(data, cp, static_cast<size_t>(ep - cp - RRFIXEDSZ), dnptrs, lastdnptr);
            if (n < 0) {
                return -1;
            }
            cp += n;
            *reinterpret_cast<uint16_t *>(cp) = htons(ns_t_null);
            cp += INT16SZ;
            *reinterpret_cast<uint16_t *>(cp) = htons(static_cast<uint16_t>(cl));
            cp += INT16SZ;
            *reinterpret_cast<uint32_t *>(cp) = htonl(0);
            cp += INT32SZ;
            *reinterpret_cast<uint16_t *>(cp) = htons(0);
            cp += INT16SZ;
            hp->arcount = htons(1);
        } break;

        case IQUERY:
            // Initialize answer section
            if ((ep - cp) < static_cast<uint8_t>(1 + RRFIXEDSZ + datalen)) {
                return (-1);
            }
            *cp++ = '\0'; /* no domain name */
            *reinterpret_cast<uint16_t *>(cp) = htons(static_cast<uint16_t>(type));
            cp += INT16SZ;
            *reinterpret_cast<uint16_t *>(cp) = htons(static_cast<uint16_t>(cl));
            cp += INT16SZ;
            *reinterpret_cast<uint32_t *>(cp) = htonl(0);
            cp += INT32SZ;
            *reinterpret_cast<uint16_t *>(cp) = htons(static_cast<uint16_t>(datalen));
            cp += INT16SZ;
            if (datalen) {
                memcpy(cp, data, datalen);
                cp += datalen;
            }
            hp->ancount = htons(1);
            break;

        default:
            return -1;
    }
    return static_cast<int>(cp - buf);
}

int nmd::get_addr_info::resQueryPacketSend(dns_res_state &statp, const uint8_t *buf, size_t buflen, uint8_t *ans,
    size_t anssiz, int &rcode, uint32_t flags)
{
    size_t anslen = 0;
    dnsresolv_cache_status cache_status =
        nmd::dnsresolv_cache::lookupFromResolvCache(statp.netid, buf, buflen, ans, anssiz, &anslen, flags);
    if (cache_status == RESOLV_CACHE_FOUND) {
        HEADER *hp = reinterpret_cast<HEADER *>(ans);
        rcode = hp->rcode;
        // common::logger::info() << "[get_addr_info] get answer form cache. anslen: " << anslen << endl;
        NETNATIVE_LOGE("[get_addr_info] get answer form cache. anslen: %{public}d", anslen);
        return static_cast<int>(anslen);
    }

    if (cache_status != RESOLV_CACHE_UNSUPPORTED) {
        getResolvConfigFromCache(statp);
    }

    if (statp.nameserverCount() == 0) {
        errno = ESRCH;
        return -ESRCH;
    }

    dns_res_state stats[MAXNS] {};
    dns_res_params params;
    // Send request, RETRY times, or until successful.
    uint8_t retryTimes = (flags & NETD_DNS_RESOLV_NO_RETRY) ? 1 : params.retryCount;
    bool useTcp = buflen > PACKETSZ;
    int gotsomewhere = 0;
    // Use an impossible error code as default value
    int terrno = ETIME;

    for (int attempt = 0; attempt < retryTimes; ++attempt) {
        for (size_t ns = 0; ns < statp.nsaddrs.size(); ++ns) {
            rcode = RCODE_INTERNAL_ERROR;
            time_t query_time = 0;
            int delay = 0;
            bool fallbackTCP = false;
            int resplen(-1);
            size_t actualNs = ns;
            terrno = ETIME;
            if (useTcp) {
                // TCP; at most one attempt per server.
                attempt = retryTimes;
                resplen = sendViaTcp(statp, params, buf, buflen, ans, anssiz, terrno, ns, query_time, rcode, delay);
                // common::logger::info() << "[get_addr_info] send dns request by tcp. resplen: " << resplen
                //                       << " terrno: " << terrno << endl;
                NETNATIVE_LOGE("[get_addr_info] send dns request by tcp. resplen: %{public}d terrno: %{public}d",
                    resplen, terrno);
            } else {
                // UDP
                resplen = sendViaUdp(statp, params, buf, buflen, ans, anssiz, terrno, actualNs, useTcp,
                    gotsomewhere, query_time, rcode, delay);
                fallbackTCP = useTcp ? true : false;
                // common::logger::info() << "[get_addr_info] send dns request by udp. resplen: " << resplen
                //                       << " terrno: " << terrno << endl;
                NETNATIVE_LOGE("[get_addr_info] send dns request by udp. resplen: %{public}d terrno: %{public}d",
                    resplen, terrno);
            }

            if (resplen == 0) {
                continue;
            }

            if (fallbackTCP) {
                ns--;
                continue;
            }

            if (resplen < 0) {
                statp.closeSockets();
                return -terrno;
            };

            if (cache_status == RESOLV_CACHE_NOTFOUND) {
                nmd::dnsresolv_cache::resolvCacheAdd(statp.netid, buf, buflen, ans, static_cast<size_t>(resplen));
            }
            statp.closeSockets();
            return (resplen);
        } // for each ns
    } // for each retry
    statp.closeSockets();
    terrno = useTcp ? terrno : gotsomewhere ? ETIMEDOUT : ECONNREFUSED;
    errno = useTcp   ? terrno :
        gotsomewhere ? ETIMEDOUT // no answer obtained
                       :
                       ECONNREFUSED; // no nameservers found

    return -terrno;
}

int nmd::get_addr_info::getHerrnoFromRcode(int rcode)
{
    switch (rcode) {
        case RCODE_TIMEOUT:
            return RCODE_TIMEOUT; // extended h_errno.
        case NXDOMAIN:
            return HOST_NOT_FOUND;
        case SERVFAIL:
            return TRY_AGAIN;
        case NOERROR:
            return NO_DATA;
        case FORMERR:
        case NOTIMP:
        case REFUSED:
        default:
            return NO_RECOVERY;
    }
}

int nmd::get_addr_info::dnCompress(
    const uint8_t *src, uint8_t *dst, size_t dstsiz, const uint8_t **dnptrs, const uint8_t **lastdnptr)
{
    return (ns_name_compress(reinterpret_cast<const char *>(src), dst, dstsiz,
        reinterpret_cast<const unsigned char **>(dnptrs), lastdnptr));
}

bool nmd::get_addr_info::resetNsSock(
    nmd::common::net_utils::socket_fd &sock, const int type, const sockaddr *nsap, int &terrno, int &ret)
{
    sock.reset(socket(nsap->sa_family, type, 0));
    if (sock < 0) {
        terrno = errno;
        switch (errno) {
            case EPROTONOSUPPORT:
            case EPFNOSUPPORT:
            case EAFNOSUPPORT: {
                ret = 0;
                return false;
            }
            default: {
                ret = -1;
                return false;
            }
        }
    }
    return true;
}

int nmd::get_addr_info::waitForReply(dns_res_state &statp, dns_res_params &params, const uint8_t *buf,
    const size_t buflen, uint8_t *ans, size_t anssiz, int &terrno, size_t &ns, bool &needTcp, int &gotsomewhere,
    int &rcode, int &delay)
{
    delay = 0;
    timespec timeout = getTimeout(params);
    timespec start_time = evNowTime();
    timespec finish = evAddTime(start_time, timeout);
    for (;;) {
        // Wait for reply.
        std::vector<int> fdAvailable;
        auto result = udpRetryingPollWrapper(statp, ns, finish, fdAvailable);

        if (fdAvailable.empty()) {
            const bool isTimeout = (result == ETIMEDOUT);
            rcode = (isTimeout) ? RCODE_TIMEOUT : rcode;
            terrno = (isTimeout) ? ETIMEDOUT : errno;
            gotsomewhere = (isTimeout) ? 1 : gotsomewhere;
            // Leave the UDP sockets open on timeout so we can keep listening for
            // a late response from this server while retrying on the next server.
            if (!isTimeout) {
                statp.closeSockets();
            }
            return 0;
        }
        bool needRetry = false;
        for (const int &fd : fdAvailable) {
            needRetry = false;
            sockaddr_storage from;
            socklen_t fromlen = sizeof(from);
            ssize_t resplen = recvfrom(fd, ans, anssiz, 0, reinterpret_cast<sockaddr *>(&from), &fromlen);
            if (resplen <= 0) {
                terrno = errno;
                continue;
            }
            gotsomewhere = 1;
            if (resplen < HFIXEDSZ) {
                // Undersized message.
                terrno = EMSGSIZE;
                continue;
            }

            size_t receivedFromNs = ns;
            needRetry = isInvalidAnswer(statp, from, buf, buflen, ans, anssiz, receivedFromNs);
            if (needRetry) {
                continue;
            }

            timespec done = evNowTime();
            delay = calculateElapsedTime(done, start_time);

            HEADER *anhp = reinterpret_cast<HEADER *>(ans);
            if (anhp->rcode == SERVFAIL || anhp->rcode == NOTIMP || anhp->rcode == REFUSED) {
                // common::logger::debug() << "[get_addr_info] server rejected query. " << endl;
                NETNATIVE_LOGD("[get_addr_info] server rejected query. ");
                rcode = anhp->rcode;
                continue;
            }
            if (anhp->tc) {
                // To get the rest of answer,
                // use TCP with same server.
                // common::logger::debug() << "[get_addr_info] truncated answer. " << endl;
                NETNATIVE_LOGD("[get_addr_info] truncated answer. ");
                terrno = E2BIG;
                needTcp = true;
                return 1;
            }

            rcode = anhp->rcode;
            ns = receivedFromNs;
            terrno = 0;
            return static_cast<int>(resplen);
        }

        if (!needRetry) {
            return 0;
        }
    }
}

int nmd::get_addr_info::sendViaUdp(dns_res_state &statp, dns_res_params &params, const uint8_t *buf,
    const size_t buflen, uint8_t *ans, size_t anssiz, int &terrno, size_t &ns, bool &needTcp, int &gotsomewhere,
    time_t &at, int &rcode, int &delay)
{
    if (ns >= statp.nsaddrs.size()) {
        // common::logger::error() << "[get_addr_info] Unable to sendViaUdp: invalid param ns:  " << ns
        //                        << " nsaddr.size: " << statp.nsaddrs.size() << endl;
        NETNATIVE_LOGE(
            "[get_addr_info] Unable to sendViaUdp: invalid param ns: %{public}d nsaddr.size: %{public}d", ns,
            statp.nsaddrs.size());
        terrno = EINVAL;
        return -1;
    }

    at = time(nullptr);
    const sockaddr_storage ss = statp.nsaddrs[ns];
    const sockaddr *nsap = reinterpret_cast<const sockaddr *>(&ss);
    const socklen_t nsaplen = nmd::common::net_utils::sock_addr_utils::sockaddrSize(nsap);

    if (statp.nssocks[ns] == -1) {
        int ret(0);
        bool reset = resetNsSock(statp.nssocks[ns], SOCK_DGRAM | SOCK_CLOEXEC, nsap, terrno, ret);
        if (!reset) {
            return ret;
        }

        if (statp.mark != MARK_UNSET) {
            if (setsockopt(statp.nssocks[ns], SOL_SOCKET, SO_MARK, &(statp.mark), sizeof(statp.mark)) < 0) {
                terrno = errno;
                statp.closeSockets();
                return -1;
            }
        }
        // Use a "connected" datagram socket to receive an ECONNREFUSED error
        // on the next socket operation when the server responds with an
        // ICMP port-unreachable error. This way we can detect the absence of
        // a nameserver without timing out.
        if (randomBind(statp.nssocks[ns], nsap->sa_family) < 0) {
            terrno = errno;
            statp.closeSockets();
            return 0;
        }

        if (connect(statp.nssocks[ns], nsap, nsaplen) < 0) {
            terrno = errno;
            statp.closeSockets();
            return 0;
        }
    }
    if (send(statp.nssocks[ns], buf, buflen, 0) != static_cast<ssize_t>(buflen)) {
        terrno = errno;
        statp.closeSockets();
        return 0;
    }

    return waitForReply(statp, params, buf, buflen, ans, anssiz, terrno, ns, needTcp, gotsomewhere, rcode, delay);
}
void nmd::get_addr_info::closeInvalidSock(dns_res_state &statp, const struct sockaddr *nsap)
{
    struct sockaddr_storage peer;
    socklen_t size = sizeof(peer);
    unsigned old_mark;
    socklen_t mark_size = sizeof(old_mark);
    if (getpeername(statp.tcpNsSock, reinterpret_cast<struct sockaddr *>(&peer), &size) < 0 ||
        !sockEq((reinterpret_cast<struct sockaddr *>(&peer)), nsap) ||
        getsockopt(statp.tcpNsSock, SOL_SOCKET, SO_MARK, &old_mark, &mark_size) < 0 || old_mark != statp.mark) {
        statp.closeSockets();
    }
}

int nmd::get_addr_info::sendViaTcp(dns_res_state &statp, dns_res_params &params, const uint8_t *buf,
    const size_t buflen, uint8_t *ans, size_t anssiz, int &terrno, const size_t ns, time_t &at, int &rcode,
    int &delay)
{
    at = time(NULL);
    delay = 0;
    const HEADER *hp = reinterpret_cast<const HEADER *>(buf);
    HEADER *anhp = reinterpret_cast<HEADER *>(ans);

    if (ns >= statp.nsaddrs.size()) {
        // common::logger::error() << "[get_addr_info] Unable to sendViaTcp: invalid param ns:  " << ns
        //                        << " nsaddr.size: " << statp.nsaddrs.size() << endl;
        NETNATIVE_LOGE(
            "[get_addr_info] Unable to sendViaTcp: invalid param ns: %{public}d nsaddr.size: %{public}d", ns,
            statp.nsaddrs.size());
        terrno = EINVAL;
        return -1;
    }

    sockaddr_storage ss = statp.nsaddrs[ns];
    struct sockaddr *nsap = reinterpret_cast<sockaddr *>(&ss);
    auto nsaplen = nmd::common::net_utils::sock_addr_utils::sockaddrSize(nsap);

    bool connreset(false);
same_ns:
    bool truncating(false);

    struct timespec start_time = evNowTime();

    // Are we still talking to whom we want to talk to?
    if (statp.tcpNsSock >= 0 && statp.isTcp) {
        closeInvalidSock(statp, nsap);
    }

    if (statp.tcpNsSock < 0 || !statp.isTcp) {
        if (statp.tcpNsSock >= 0) {
            statp.closeSockets();
        }

        int ret(0);
        bool reset = resetNsSock(statp.tcpNsSock, SOCK_STREAM | SOCK_CLOEXEC, nsap, terrno, ret);
        if (!reset) {
            return ret;
        }

        if (statp.mark != MARK_UNSET) {
            if (setsockopt(statp.tcpNsSock, SOL_SOCKET, SO_MARK, &statp.mark, sizeof(statp.mark)) < 0) {
                terrno = errno;
                return -1;
            }
        }
        errno = 0;
        if (randomBind(statp.tcpNsSock, nsap->sa_family) < 0) {
            terrno = errno;
            statp.closeSockets();
            return 0;
        }

        if (connect_with_timeout(statp.tcpNsSock, nsap, nsaplen, getTimeout(params)) < 0) {
            terrno = errno;
            statp.closeSockets();
            /*
             * The way connect_with_timeout() is implemented prevents us from reliably
             * determining whether this was really a timeout or e.g. ECONNREFUSED. Since
             * currently both cases are handled in the same way, there is no need to
             * change this (yet). If we ever need to reliably distinguish between these
             * cases, both connect_with_timeout() and retrying_poll() need to be
             * modified, though.
             */
            rcode = RCODE_TIMEOUT;
            return (0);
        }
        statp.isTcp = true;
    }

    // Send length & message
    uint16_t len = htons(static_cast<uint16_t>(buflen));
    const iovec iov[] = {
        {&len, INT16SZ},
        {const_cast<uint8_t *>(buf), static_cast<size_t>(buflen)},
    };

    if (writev(statp.tcpNsSock, iov, 2) != static_cast<ssize_t>(INT16SZ + buflen)) {
        terrno = errno;
        statp.closeSockets();
        return 0;
    }

    // Receive length & response
read_len:
    uint8_t *cp = ans;
    len = INT16SZ;
    ssize_t n(0);
    while ((n = read(statp.tcpNsSock, reinterpret_cast<char *>(cp), static_cast<size_t>(len))) > 0) {
        cp += n;
        if ((len -= n) == 0) {
            break;
        }
    }
    if (n <= 0) {
        terrno = errno;
        statp.closeSockets();
        /*
         * A long running process might get its TCP
         * connection reset if the remote server was
         * restarted.  Requery the server instead of
         * trying a new one.  When there is only one
         * server, this means that a query might work
         * instead of failing.  We only allow one reset
         * per query to prevent looping.
         */
        if (terrno == ECONNRESET && !connreset) {
            connreset = true;
            goto same_ns;
        }
        return (0);
    }
    uint16_t resplen = ntohs(*reinterpret_cast<const uint16_t *>(ans));
    if (resplen > anssiz) {
        truncating = true;
        len = static_cast<uint16_t>(anssiz);
    } else {
        len = resplen;
    }
    if (len < HFIXEDSZ) {
        // Undersized message.
        terrno = EMSGSIZE;
        statp.closeSockets();
        return 0;
    }
    cp = ans;
    while (len != 0 && (n = read(statp.tcpNsSock, reinterpret_cast<char *>(cp), static_cast<size_t>(len))) > 0) {
        cp += n;
        len -= n;
    }

    if (n <= 0) {
        terrno = errno;
        statp.closeSockets();
        return 0;
    }

    if (truncating) {
        // Flush rest of answer so connection stays in synch.
        anhp->tc = 1;
        len = static_cast<uint16_t>(resplen - anssiz);
        while (len != 0) {
            char junk[PACKETSZ];

            n = read(statp.tcpNsSock, junk, (len > sizeof junk) ? sizeof junk : len);
            if (n > 0) {
                len -= n;
            } else {
                break;
            }
        }
        resplen = static_cast<uint16_t>(anssiz);
    }
    /*
     * If the calling application has bailed out of
     * a previous call and failed to arrange to have
     * the circuit closed or the server has got
     * itself confused, then drop the packet and
     * wait for the correct one.
     */
    if (hp->id != anhp->id) {
        goto read_len;
    }

    /*
     * All is well, or the error is fatal.  Signal that the
     * next nameserver ought not be tried.
     */
    if (resplen > 0) {
        struct timespec done = evNowTime();
        delay = calculateElapsedTime(done, start_time);
        rcode = anhp->rcode;
    }
    terrno = 0;
    return resplen;
}

int nmd::get_addr_info::connect_with_timeout(
    int sock, const sockaddr *nsap, socklen_t salen, const timespec timeout)
{
    int res(-1);
    auto origflags = fcntl(sock, F_GETFL, 0);

    do {
        fcntl(sock, F_SETFL, origflags | O_NONBLOCK);
        res = connect(sock, nsap, salen);
        if (res < 0 && errno != EINPROGRESS) {
            res = -1;
            break;
        }

        if (res != 0) {
            timespec now = evNowTime();
            timespec finish = evAddTime(now, timeout);
            res = retryingPoll(sock, POLLIN | POLLOUT, finish);
            if (res <= 0) {
                res = -1;
            }
        }

    } while (false);

    fcntl(sock, F_SETFL, origflags);
    return res;
}

int nmd::get_addr_info::randomBind(const int s, const sa_family_t family)
{
    // clear all, this also sets the IP4/6 address to 'any'
    sockaddr_union u;
    memset(&u, 0, sizeof u);

    socklen_t slen(0);
    switch (family) {
        case AF_INET:
            u.sin.sin_family = family;
            slen = sizeof(u.sin);
            break;
        case AF_INET6:
            u.sin6.sin6_family = family;
            slen = sizeof(u.sin6);
            break;
        default:
            errno = EPROTO;
            return -1;
    }

    std::random_device rd; // Will be used to obtain a seed for the random number engine
    std::mt19937 gen(rd()); // Standard mersenne_twister_engine seeded with rd()
    std::uniform_int_distribution<> distrib(1025, 65534);
    for (uint8_t j = 0; j < 10; j++) {
        // find a random port between 1025 .. 65534
        int port = distrib(gen);
        if (family == AF_INET) {
            u.sin.sin_port = htons(static_cast<uint16_t>(port));
        } else {
            u.sin6.sin6_port = htons(static_cast<uint16_t>(port));
        }

        if (!bind(s, &u.sa, slen)) {
            return 0;
        }
    }

    // nothing after 10 attempts, our network table is probably busy
    // let the system decide which port is best
    if (family == AF_INET) {
        u.sin.sin_port = 0;
    } else {
        u.sin6.sin6_port = 0;
    }

    return bind(s, &u.sa, slen);
}

timespec nmd::get_addr_info::getTimeout(const dns_res_params &params)
{
    auto timeout = params.baseTimeoutMsec == 0 ? RES_DEFAULT_TIMEOUT : params.baseTimeoutMsec;
    if (timeout < 1) {
        timeout = 1;
    }

    struct timespec result = {};
    result.tv_sec = timeout;
    result.tv_nsec = (timeout % 1000) * 1000000;
    return result;
}

timespec nmd::get_addr_info::evNowTime(void)
{
    struct timespec tsnow;
    clock_gettime(CLOCK_REALTIME, &tsnow);
    return tsnow;
}

timespec nmd::get_addr_info::evAddTime(const timespec &addend1, const timespec &addend2)
{
    struct timespec x;

    x.tv_sec = addend1.tv_sec + addend2.tv_sec;
    x.tv_nsec = addend1.tv_nsec + addend2.tv_nsec;
    if (x.tv_nsec >= BILLION) {
        x.tv_sec++;
        x.tv_nsec -= BILLION;
    }
    return x;
}
int nmd::get_addr_info::evCmpTime(const timespec &a, const timespec &b)
{
#define SGN(x) ((x) < 0 ? (-1) : (x) > 0 ? (1) : (0));
    time_t s = a.tv_sec - b.tv_sec;
    long n;

    if (s != 0) {
        return SGN(s);
    }

    n = a.tv_nsec - b.tv_nsec;
    return SGN(n);
}

timespec nmd::get_addr_info::evSubTime(const timespec &minuend, const timespec &subtrahend)
{
    struct timespec x;

    x.tv_sec = minuend.tv_sec - subtrahend.tv_sec;
    if (minuend.tv_nsec >= subtrahend.tv_nsec) {
        x.tv_nsec = minuend.tv_nsec - subtrahend.tv_nsec;
    } else {
        x.tv_nsec = BILLION - subtrahend.tv_nsec + minuend.tv_nsec;
        x.tv_sec--;
    }
    return x;
}

timespec nmd::get_addr_info::evConsTime(const time_t sec, const long nsec)
{
    struct timespec x;

    x.tv_sec = sec;
    x.tv_nsec = nsec;
    return x;
}

int nmd::get_addr_info::udpRetryingPollWrapper(
    dns_res_state &statp, const size_t ns, const timespec &finish, std::vector<int> &fdAvailable)
{
    int n = retryingPoll(statp.nssocks[ns], POLLIN, finish);
    if (n <= 0) {
        return errno;
    }
    fdAvailable.push_back(statp.nssocks[ns]);
    return 0;
}

int nmd::get_addr_info::retryingPoll(const int sock, const short events, const timespec &finish)
{
retry:
    timespec now = evNowTime();
    timespec timeout;
    if (evCmpTime(finish, now) > 0) {
        timeout = evSubTime(finish, now);
    } else {
        timeout = evConsTime(0L, 0L);
    }

    struct pollfd fds = {};
    fds.fd = sock;
    fds.events = events;
    int n = ppoll(&fds, 1, &timeout, nullptr);
    if (n == 0) {
        errno = ETIMEDOUT;
        return 0;
    }
    if (n < 0) {
        if (errno == EINTR) {
            goto retry;
        }
        return n;
    }
    if (fds.revents & (POLLIN | POLLOUT | POLLERR)) {
        int error;
        socklen_t len = sizeof(error);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error) {
            errno = error;
            // common::logger::error() << "[get_addr_info] retryingPoll getsockopt failed. " << endl;
            NETNATIVE_LOGI("[get_addr_info] retryingPoll getsockopt failed. ");
            return -1;
        }
    }
    // common::logger::info() << "[get_addr_info] retryingPoll returning. " << endl;
    NETNATIVE_LOGI("[get_addr_info] retryingPoll returning. ");
    return n;
}

bool nmd::get_addr_info::isInvalidAnswer(dns_res_state &statp, const sockaddr_storage &from, const uint8_t *buf,
    size_t buflen, uint8_t *ans, size_t anssiz, size_t &receivedFromNs)
{
    const HEADER *hp = reinterpret_cast<const HEADER *>(buf);
    HEADER *anhp = reinterpret_cast<HEADER *>(ans);
    if (hp->id != anhp->id) {
        // response from old query, ignore it.
        return true;
    }

    int ret = lookupNameserverFromResNs(statp, reinterpret_cast<const sockaddr *>(&from));
    if (ret < 0) {
        // response from wrong server? ignore it.
        return true;
    }
    receivedFromNs = static_cast<size_t>(ret);

    if (!resQueriesMatch(buf, buf + buflen, ans, ans + anssiz)) {
        // response contains wrong query? ignore it.
        return true;
    }
    return false;
}

// Looks up the nameserver address in res.nsaddrs[], returns the ns number if found, otherwise -1.
int nmd::get_addr_info::lookupNameserverFromResNs(dns_res_state &statp, const sockaddr *sa)
{
    int ns = 0;
    if (AF_INET == sa->sa_family) {
        const sockaddr_in *inp = reinterpret_cast<const struct sockaddr_in *>(sa);

        const sockaddr_in *srv(nullptr);
        for (const auto &ipsa : statp.nsaddrs) {
            sockaddr_storage ss = ipsa;
            srv = reinterpret_cast<sockaddr_in *>(&ss);
            if (srv->sin_family == inp->sin_family && srv->sin_port == inp->sin_port &&
                (srv->sin_addr.s_addr == INADDR_ANY || srv->sin_addr.s_addr == inp->sin_addr.s_addr)) {
                return ns;
            }
            ++ns;
        }
    }

    if (AF_INET6 == sa->sa_family) {
        const sockaddr_in6 *in6p = reinterpret_cast<const struct sockaddr_in6 *>(sa);
        for (const auto &ipsa : statp.nsaddrs) {
            sockaddr_storage ss = ipsa;
            const sockaddr_in6 *srv6 = reinterpret_cast<sockaddr_in6 *>(&ss);
            if (srv6->sin6_family == in6p->sin6_family && srv6->sin6_port == in6p->sin6_port &&
#ifdef HAVE_SIN6_SCOPE_ID
                (srv6->sin6_scope_id == 0 || srv6->sin6_scope_id == in6p->sin6_scope_id) &&
#endif
                (IN6_IS_ADDR_UNSPECIFIED(&srv6->sin6_addr) ||
                    IN6_ARE_ADDR_EQUAL(&srv6->sin6_addr, &in6p->sin6_addr))) {
                return ns;
            }
            ++ns;
        }
    }

    return -1;
}

bool nmd::get_addr_info::resQueriesMatch(
    const uint8_t *buf1, const uint8_t *eom1, const uint8_t *buf2, const uint8_t *eom2)
{
    const uint8_t *cp = buf1 + HFIXEDSZ;
    int qdcount = ntohs((reinterpret_cast<const HEADER *>(buf1))->qdcount);

    if (buf1 + HFIXEDSZ > eom1 || buf2 + HFIXEDSZ > eom2) {
        return -1;
    }

    /*
     * Only header section present in replies to
     * dynamic update packets.
     */
    if (((reinterpret_cast<const HEADER *>(buf1))->opcode == ns_o_update) &&
        ((reinterpret_cast<const HEADER *>(buf2))->opcode == ns_o_update)) {
        return true;
    }

    if (qdcount != ntohs((reinterpret_cast<const HEADER *>(buf2))->qdcount))
        return (0);
    while (qdcount-- > 0) {
        char tname[MAXDNAME + 1];
        int n = dnExpand(buf1, eom1, cp, tname, sizeof tname);
        if (n < 0) {
            return false;
        }
        cp += n;
        if (cp + 2 * INT16SZ > eom1) {
            return false;
        }
        int ttype = ntohs(*reinterpret_cast<const uint16_t *>(cp));
        cp += INT16SZ;
        int tclass = ntohs(*reinterpret_cast<const uint16_t *>(cp));
        cp += INT16SZ;
        if (!findNameInQueryPacket(tname, ttype, tclass, buf2, eom2)) {
            return false;
        }
    }
    return true;
}

bool nmd::get_addr_info::sockEq(const struct sockaddr *socka, const struct sockaddr *sockb)
{
    if (nullptr == socka || nullptr == sockb) {
        return false;
    }

    if (socka->sa_family != sockb->sa_family) {
        return false;
    }

    if (AF_INET == socka->sa_family) {
        const struct sockaddr_in *a4 = reinterpret_cast<const struct sockaddr_in *>(socka);
        const struct sockaddr_in *b4 = reinterpret_cast<const struct sockaddr_in *>(sockb);
        return a4->sin_port == b4->sin_port && a4->sin_addr.s_addr == b4->sin_addr.s_addr;
    }

    if (AF_INET6 == socka->sa_family) {
        const struct sockaddr_in6 *a6 = reinterpret_cast<const struct sockaddr_in6 *>(socka);
        const struct sockaddr_in6 *b6 = reinterpret_cast<const struct sockaddr_in6 *>(sockb);
        return a6->sin6_port == b6->sin6_port &&
#ifdef HAVE_SIN6_SCOPE_ID
            a6->sin6_scope_id == b6->sin6_scope_id &&
#endif
            IN6_ARE_ADDR_EQUAL(&a6->sin6_addr, &b6->sin6_addr);
    }
    return false;
}

bool nmd::get_addr_info::findNameInQueryPacket(
    const std::string &name, int type, int cl, const uint8_t *buf, const uint8_t *eom)
{
    const uint8_t *cp = buf + HFIXEDSZ;
    int qdcount = ntohs((reinterpret_cast<const HEADER *>(buf))->qdcount);

    while (qdcount-- > 0) {
        char tname[MAXDNAME + 1];
        int n = dnExpand(buf, eom, cp, tname, sizeof tname);
        if (n < 0) {
            return false;
        }
        cp += n;
        if (cp + 2 * INT16SZ > eom) {
            return false;
        }
        int ttype = ntohs(*reinterpret_cast<const uint16_t *>(cp));
        cp += INT16SZ;
        int tclass = ntohs(*reinterpret_cast<const uint16_t *>(cp));
        cp += INT16SZ;
        if (ttype == type && tclass == cl && ns_samename(tname, name.c_str()) == 1) {
            return true;
        }
    }
    return false;
}

int nmd::get_addr_info::calculateElapsedTime(const timespec &t1, const timespec &t0)
{
    long ms0 = t0.tv_sec * 1000 + t0.tv_nsec / 1000000;
    long ms1 = t1.tv_sec * 1000 + t1.tv_nsec / 1000000;
    return static_cast<int>(ms1 - ms0);
}
nmd::res_n_ok_func nmd::get_addr_info::getResNOkFunc(int qtype)
{
    switch (qtype) {
        case T_A:
        case T_AAAA:
        case T_ANY: // use T_ANY only for T_A/T_AAAA lookup
            return res_hnok;
            break;
        default:
            return nullptr;
    }
}

addrinfo *nmd::get_addr_info::getAnswer(const std::vector<uint8_t> &answer, size_t anslen, const char *qname,
    int qtype, const struct addrinfo *pai, int &herrno)
{
    struct addrinfo sentinel = {};
    addrinfo *cur = &sentinel;

    char *canonname = nullptr;
    const uint8_t *eom = answer.data() + anslen;

    res_n_ok_func pnameOk = getResNOkFunc(qtype);
    if (nullptr == pnameOk) {
        return nullptr;
    }

    // find first satisfactory answer
    const HEADER *hp = reinterpret_cast<const HEADER *>(answer.data());
    int ancount = ntohs(hp->ancount);
    int qdcount = ntohs(hp->qdcount);
    char hostbuf[8 * 1024] = {};
    char *bp = hostbuf;
    char *ep = hostbuf + sizeof(hostbuf);
    const uint8_t *cp = answer.data();
    BOUNDED_INCR(HFIXEDSZ);
    if (qdcount != 1) {
        herrno = NO_RECOVERY;
        return (nullptr);
    }

    int n = dnExpand(answer.data(), eom, cp, bp, static_cast<size_t>(ep - bp));
    if ((n < 0) || !(*pnameOk)(bp)) {
        herrno = NO_RECOVERY;
        return (nullptr);
    }
    BOUNDED_INCR(n + QFIXEDSZ);
    if (qtype == T_A || qtype == T_AAAA || qtype == T_ANY) {
        /* res_send() has already verified that the query name is the
         * same as the one we sent; this just gets the expanded name
         * (i.e., with the succeeding search-domain tacked on).
         */
        n = static_cast<int>(strlen(bp) + 1); /* for the \0 */
        if (n >= MAX_NAME_LEN) {
            herrno = NO_RECOVERY;
            return (nullptr);
        }
        canonname = bp;
        bp += n;
        // The qname can be abbreviated, but h_name is now absolute.
        qname = canonname;
    }
    int haveanswer(0);
    int had_error(0);
    char tbuf[MAXDNAME] = {};
    while (ancount-- > 0 && cp < eom && !had_error) {
        n = dnExpand(answer.data(), eom, cp, bp, static_cast<size_t>(ep - bp));
        if ((n < 0) || !(*pnameOk)(bp)) {
            had_error++;
            continue;
        }
        cp += n; // name
        BOUNDS_CHECK(cp, 3 * INT16SZ + INT32SZ);
        int type = ntohs(*reinterpret_cast<const uint16_t *>(cp));
        cp += INT16SZ; // type
        int cl = ntohs(*reinterpret_cast<const uint16_t *>(cp));
        cp += INT16SZ + INT32SZ; // class, TTL
        n = ntohs(*reinterpret_cast<const uint16_t *>(cp));
        cp += INT16SZ; // len
        BOUNDS_CHECK(cp, n);
        if (cl != C_IN) {
            cp += n;
            continue;
        }
        if ((qtype == T_A || qtype == T_AAAA || qtype == T_ANY) && type == T_CNAME) {
            n = dnExpand(answer.data(), eom, cp, tbuf, sizeof tbuf);
            if ((n < 0) || !(*pnameOk)(tbuf)) {
                had_error++;
                continue;
            }
            cp += n;
            // Get canonical name.
            n = static_cast<int>(strlen(tbuf) + 1); // for the \0
            if (n > ep - bp || n >= MAX_NAME_LEN) {
                had_error++;
                continue;
            }
            strncpy(bp, tbuf, static_cast<size_t>(ep - bp));
            canonname = bp;
            bp += n;
            continue;
        }
        if (qtype == T_ANY) {
            if (!(type == T_A || type == T_AAAA)) {
                cp += n;
                continue;
            }
        } else if (type != qtype) {
            cp += n;
            continue;
        }
        switch (type) {
            case T_A:
            case T_AAAA: {
                if (strcasecmp(canonname, bp) != 0) {
                    cp += n;
                    continue;
                }
                if (type == T_A && n != INADDRSZ) {
                    cp += n;
                    continue;
                }
                if (type == T_AAAA && n != IN6ADDRSZ) {
                    cp += n;
                    continue;
                }
                if (type == T_AAAA) {
                    struct in6_addr in6;
                    memcpy(&in6, cp, IN6ADDRSZ);
                    if (IN6_IS_ADDR_V4MAPPED(&in6)) {
                        cp += n;
                        continue;
                    }
                }
                if (!haveanswer) {
                    canonname = bp;
                    size_t nn = strlen(bp) + 1; // for the \0
                    bp += nn;
                }

                // don't overwrite pai
                addrinfo ai = *pai;
                ai.ai_family = (type == T_A) ? AF_INET : AF_INET6;
                const nmd::afd *afd = findAfd(ai.ai_family);
                if (afd == nullptr) {
                    cp += n;
                    continue;
                }
                cur->ai_next = getAi(&ai, afd, reinterpret_cast<const char *>(cp));
                if (cur->ai_next == nullptr)
                    had_error++;
                while (cur && cur->ai_next)
                    cur = cur->ai_next;
                cp += n;
            } break;
            default:
                abort();
        }
        if (!had_error) {
            haveanswer++;
        }
    }
    if (haveanswer) {
        if (!canonname) {
            getCanonName(pai, sentinel.ai_next, qname);
        } else {
            getCanonName(pai, sentinel.ai_next, canonname);
        }
        herrno = NETDB_SUCCESS;
        return sentinel.ai_next;
    }

    herrno = NO_RECOVERY;
    return nullptr;
}

int nmd::get_addr_info::dnExpand(
    const uint8_t *msg, const uint8_t *eom, const uint8_t *src, char *dst, size_t dstsiz)
{
    int n = ns_name_uncompress(msg, eom, src, dst, dstsiz);

    if (n > 0 && dst[0] == '.')
        dst[0] = '\0';
    return n;
}

void nmd::get_addr_info::getResolvConfigFromCache(dns_res_state &statp)
{
    auto config = nmd::dnsresolv_cache::lookupResolvConfig(statp.netid);
    if (nullptr == config) {
        // common::logger::error() << "[dnsresolv_client] Unable to getResolvConfigFromCache. netid: " << statp.netid
        //                        << endl;
        NETNATIVE_LOGE("[dnsresolv_client] Unable to getResolvConfigFromCache. netid: %{public}d", statp.netid);
        return;
    }
    statp.nsaddrs = config->nameserverSockAddrs;
    statp.searchDomains = config->searchDomains;
}

int nmd::get_addr_info::getaddrinfoNumeric(
    const char *hostname, const char *servname, addrinfo hints, addrinfo **result)
{
    hints.ai_flags = AI_NUMERICHOST;
    netd_net_context netcontext = {};
    netcontext.appNetId = NETID_UNSET;
    netcontext.appMark = MARK_UNSET;
    netcontext.dnsNetId = NETID_UNSET;
    netcontext.dnsMark = MARK_UNSET;
    netcontext.uid = NET_CONTEXT_INVALID_UID;
    netcontext.pid = NET_CONTEXT_INVALID_PID;
    return getaddrinfoFornetContext(hostname, servname, &hints, &netcontext, result);
}

int nmd::get_addr_info::ns_name_compress(const char *src, unsigned char *dst, size_t dstsiz,
    const unsigned char **dnptrs, const unsigned char **lastdnptr)
{
    unsigned char tmp[NS_MAXCDNAME];

    if (ns_name_pton(src, tmp, sizeof tmp) == -1)
        return (-1);
    return (ns_name_pack(tmp, dst, (int)dstsiz, dnptrs, lastdnptr));
}

int nmd::get_addr_info::ns_name_pton(const char *src, unsigned char *dst, size_t dstsiz)
{
    return (ns_name_pton2(src, dst, dstsiz, NULL));
}

int nmd::get_addr_info::ns_name_pton2(const char *src, unsigned char *dst, size_t dstsiz, size_t *dstlen)
{
    unsigned char *label, *bp, *eom;
    int c, n, escaped, e = 0;
    char *cp;

    escaped = 0;
    bp = dst;
    eom = dst + dstsiz;
    label = bp++;

    while ((c = *src++) != 0) {
        if (escaped) {
            if (c == '[') { /* start a bit string label */
                if ((cp = (char *)strchr(src, ']')) == NULL) {
                    errno = EINVAL; /* ??? */
                    return (-1);
                }
                if ((e = encode_bitsring(&src, cp + 2, &label, &bp, eom)) != 0) {
                    errno = e;
                    return (-1);
                }
                escaped = 0;
                label = bp++;
                if ((c = *src++) == 0)
                    goto done;
                else if (c != '.') {
                    errno = EINVAL;
                    return (-1);
                }
                continue;
            } else if ((cp = (char *)strchr(digits, c)) != NULL) {
                n = (int)(cp - digits) * 100;
                if ((c = *src++) == 0 || (cp = (char *)strchr(digits, c)) == NULL) {
                    errno = EMSGSIZE;
                    return (-1);
                }
                n += (int)(cp - digits) * 10;
                if ((c = *src++) == 0 || (cp = (char *)strchr(digits, c)) == NULL) {
                    errno = EMSGSIZE;
                    return (-1);
                }
                n += (int)(cp - digits);
                if (n > 255) {
                    errno = EMSGSIZE;
                    return (-1);
                }
                c = n;
            }
            escaped = 0;
        } else if (c == '\\') {
            escaped = 1;
            continue;
        } else if (c == '.') {
            c = (int)(bp - label - 1);
            if ((c & NS_CMPRSFLGS) != 0) { /* Label too big. */
                errno = EMSGSIZE;
                return (-1);
            }
            if (label >= eom) {
                errno = EMSGSIZE;
                return (-1);
            }
            *label = c;
            /* Fully qualified ? */
            if (*src == '\0') {
                if (c != 0) {
                    if (bp >= eom) {
                        errno = EMSGSIZE;
                        return (-1);
                    }
                    *bp++ = '\0';
                }
                if ((bp - dst) > MAXCDNAME) {
                    errno = EMSGSIZE;
                    return (-1);
                }
                if (dstlen != NULL)
                    *dstlen = (bp - dst);
                return (1);
            }
            if (c == 0 || *src == '.') {
                errno = EMSGSIZE;
                return (-1);
            }
            label = bp++;
            continue;
        }
        if (bp >= eom) {
            errno = EMSGSIZE;
            return (-1);
        }
        *bp++ = (unsigned char)c;
    }
    c = (int)(bp - label - 1);
    if ((c & NS_CMPRSFLGS) != 0) { /* Label too big. */
        errno = EMSGSIZE;
        return (-1);
    }
done:
    if (label >= eom) {
        errno = EMSGSIZE;
        return (-1);
    }
    *label = c;
    if (c != 0) {
        if (bp >= eom) {
            errno = EMSGSIZE;
            return (-1);
        }
        *bp++ = 0;
    }
    if ((bp - dst) > MAXCDNAME) { /* src too big */
        errno = EMSGSIZE;
        return (-1);
    }
    if (dstlen != NULL)
        *dstlen = (bp - dst);
    return (0);
}

int nmd::get_addr_info::ns_name_skip(const unsigned char **ptrptr, const unsigned char *eom)
{
    const unsigned char *cp;
    unsigned int n;
    int l;

    cp = *ptrptr;
    while (cp < eom && (n = *cp++) != 0) {
        /* Check for indirection. */
        switch (n & NS_CMPRSFLGS) {
            case 0: /* normal case, n == len */
                cp += n;
                continue;
            case NS_TYPE_ELT: /* EDNS0 extended label */
                if ((l = labellen(cp - 1)) < 0) {
                    errno = EMSGSIZE; /* XXX */
                    return (-1);
                }
                cp += l;
                continue;
            case NS_CMPRSFLGS: /* indirection */
                cp++;
                break;
            default: /* illegal type */
                errno = EMSGSIZE;
                return (-1);
        }
        break;
    }
    if (cp > eom) {
        errno = EMSGSIZE;
        return (-1);
    }
    *ptrptr = cp;
    return (0);
}

int nmd::get_addr_info::labellen(const unsigned char *lp)
{
    int bitlen;
    unsigned char l = *lp;

    if ((l & NS_CMPRSFLGS) == NS_CMPRSFLGS) {
        /* should be avoided by the caller */
        return (-1);
    }

    if ((l & NS_CMPRSFLGS) == NS_TYPE_ELT) {
        if (l == DNS_LABELTYPE_BITSTRING) {
            if ((bitlen = *(lp + 1)) == 0)
                bitlen = 256;
            return ((bitlen + 7) / 8 + 1);
        }
        return (-1); /* unknwon ELT */
    }
    return (l);
}

int nmd::get_addr_info::encode_bitsring(
    const char **bp, const char *end, unsigned char **labelp, unsigned char **dst, unsigned const char *eom)
{
    int afterslash = 0;
    const char *cp = *bp;
    unsigned char *tp;
    char c;
    const char *beg_blen;
    char *end_blen = NULL;
    int value = 0, count = 0, tbcount = 0, blen = 0;

    beg_blen = end_blen = NULL;

    /* a bitstring must contain at least 2 characters */
    if (end - cp < 2)
        return (EINVAL);

    /* XXX: currently, only hex strings are supported */
    if (*cp++ != 'x')
        return (EINVAL);
    if (!isxdigit((*cp) & 0xff)) /* reject '\[x/BLEN]' */
        return (EINVAL);

    for (tp = *dst + 1; cp < end && tp < eom; cp++) {
        switch ((c = *cp)) {
            case ']': /* end of the bitstring */
                if (afterslash) {
                    if (beg_blen == NULL)
                        return (EINVAL);
                    blen = (int)strtol(beg_blen, &end_blen, 10);
                    if (*end_blen != ']')
                        return (EINVAL);
                }
                if (count)
                    *tp++ = ((value << 4) & 0xff);
                cp++; /* skip ']' */
                goto done;
            case '/':
                afterslash = 1;
                break;
            default:
                if (afterslash) {
                    if (!isdigit(c & 0xff))
                        return (EINVAL);
                    if (beg_blen == NULL) {
                        if (c == '0') {
                            /* blen never begings with 0 */
                            return (EINVAL);
                        }
                        beg_blen = cp;
                    }
                } else {
                    if (!isxdigit(c & 0xff))
                        return (EINVAL);
                    value <<= 4;
                    value += digitvalue[(int)c];
                    count += 4;
                    tbcount += 4;
                    if (tbcount > 256)
                        return (EINVAL);
                    if (count == 8) {
                        *tp++ = value;
                        count = 0;
                    }
                }
                break;
        }
    }
done:
    if (cp >= end || tp >= eom)
        return (EMSGSIZE);

    /*
     * bit length validation:
     * If a <length> is present, the number of digits in the <bit-data>
     * MUST be just sufficient to contain the number of bits specified
     * by the <length>. If there are insignificant bits in a final
     * hexadecimal or octal digit, they MUST be zero.
     * RFC 2673, Section 3.2.
     */
    if (blen > 0) {
        int traillen;

        if (((blen + 3) & ~3) != tbcount)
            return (EINVAL);
        traillen = tbcount - blen; /* between 0 and 3 */
        if (((value << (8 - traillen)) & 0xff) != 0)
            return (EINVAL);
    } else
        blen = tbcount;
    if (blen == 256)
        blen = 0;

    /* encode the type and the significant bit fields */
    **labelp = DNS_LABELTYPE_BITSTRING;
    **dst = blen;

    *bp = cp;
    *dst = tp;

    return (0);
}

int nmd::get_addr_info::ns_name_pack(const unsigned char *src, unsigned char *dst, int dstsiz,
    const unsigned char **dnptrs, const unsigned char **lastdnptr)
{
    unsigned char *dstp;
    const unsigned char **cpp, **lpp, *eob, *msg;
    const unsigned char *srcp;
    int n, l, first = 1;

    srcp = src;
    dstp = dst;
    eob = dstp + dstsiz;
    lpp = cpp = NULL;
    if (dnptrs != NULL) {
        if ((msg = *dnptrs++) != NULL) {
            for (cpp = dnptrs; *cpp != NULL; cpp++)
                continue;
            lpp = cpp; /* end of list to search */
        }
    } else
        msg = NULL;

    /* make sure the domain we are about to add is legal */
    l = 0;
    do {
        int l0;

        n = *srcp;
        if ((n & NS_CMPRSFLGS) == NS_CMPRSFLGS) {
            errno = EMSGSIZE;
            return (-1);
        }
        if ((l0 = labellen(srcp)) < 0) {
            errno = EINVAL;
            return (-1);
        }
        l += l0 + 1;
        if (l > MAXCDNAME) {
            errno = EMSGSIZE;
            return (-1);
        }
        srcp += l0 + 1;
    } while (n != 0);

    /* from here on we need to reset compression pointer array on error */
    srcp = src;
    do {
        /* Look to see if we can use pointers. */
        n = *srcp;
        if (n != 0 && msg != NULL) {
            l = dn_find(srcp, msg, (const unsigned char *const *)dnptrs, (const unsigned char *const *)lpp);
            if (l >= 0) {
                if (dstp + 1 >= eob) {
                    goto cleanup;
                }
                *dstp++ = ((unsigned int)l >> 8) | NS_CMPRSFLGS;
                *dstp++ = l % 256;
                //  _DIAGASSERT(__type_fit(int, dstp - dst));
                return (int)(dstp - dst);
            }
            /* Not found, save it. */
            if (lastdnptr != NULL && cpp < lastdnptr - 1 && (dstp - msg) < 0x4000 && first) {
                *cpp++ = dstp;
                *cpp = NULL;
                first = 0;
            }
        }
        /* copy label to buffer */
        if ((n & NS_CMPRSFLGS) == NS_CMPRSFLGS) {
            /* Should not happen. */
            goto cleanup;
        }
        n = labellen(srcp);
        if (dstp + 1 + n >= eob) {
            goto cleanup;
        }
        memcpy(dstp, srcp, (size_t)(n + 1));
        srcp += n + 1;
        dstp += n + 1;
    } while (n != 0);

    if (dstp > eob) {
    cleanup:
        if (msg != NULL)
            *lpp = NULL;
        errno = EMSGSIZE;
        return (-1);
    }
    // _DIAGASSERT(__type_fit(int, dstp - dst));
    return (int)(dstp - dst);
}

int nmd::get_addr_info::dn_find(const unsigned char *domain, const unsigned char *msg,
    const unsigned char *const *dnptrs, const unsigned char *const *lastdnptr)
{
    const unsigned char *dn, *cp, *sp;
    const unsigned char *const *cpp;
    unsigned int n;

    for (cpp = dnptrs; cpp < lastdnptr; cpp++) {
        sp = *cpp;
        /*
         * terminate search on:
         * root label
         * compression pointer
         * unusable offset
         */
        while (*sp != 0 && (*sp & NS_CMPRSFLGS) == 0 && (sp - msg) < 0x4000) {
            dn = domain;
            cp = sp;
            while ((n = *cp++) != 0) {
                /*
                 * check for indirection
                 */
                switch (n & NS_CMPRSFLGS) {
                    case 0: /* normal case, n == len */
                        n = labellen(cp - 1); /* XXX */

                        if (n != *dn++)
                            goto next;

                        for (; n > 0; n--)
                            if (mklower(*dn++) != mklower(*cp++))
                                goto next;
                        /* Is next root for both ? */
                        if (*dn == '\0' && *cp == '\0') {
                            //  _DIAGASSERT(__type_fit(int, sp - msg));
                            return (int)(sp - msg);
                        }
                        if (*dn)
                            continue;
                        goto next;
                    case NS_CMPRSFLGS: /* indirection */
                        cp = msg + (((n & 0x3f) << 8) | *cp);
                        break;

                    default: /* illegal type */
                        errno = EMSGSIZE;
                        return (-1);
                }
            }
        next:;
            sp += *sp + 1;
        }
    }
    errno = ENOENT;
    return (-1);
}

int nmd::get_addr_info::mklower(int ch)
{
    if (ch >= 0x41 && ch <= 0x5A)
        return (ch + 0x20);
    return (ch);
}

int nmd::get_addr_info::ns_makecanon(const char *src, char *dst, size_t dstsize)
{
    size_t n = strlen(src);

    if (n + sizeof "." > dstsize) { /* Note: sizeof == 2 */
        errno = EMSGSIZE;
        return (-1);
    }
    strcpy(dst, src);
    while (n >= 1U && dst[n - 1] == '.') /* Ends in "." */
        if (n >= 2U && dst[n - 2] == '\\' && /* Ends in "\." */
            (n < 3U || dst[n - 3] != '\\')) /* But not "\\." */
            break;
        else
            dst[--n] = '\0';
    dst[n++] = '.';
    dst[n] = '\0';
    return (0);
}

int nmd::get_addr_info::ns_samename(const char *a, const char *b)
{
    char ta[NS_MAXDNAME], tb[NS_MAXDNAME];

    if (ns_makecanon(a, ta, sizeof ta) < 0 || ns_makecanon(b, tb, sizeof tb) < 0)
        return (-1);
    if (strcasecmp(ta, tb) == 0)
        return (1);
    else
        return (0);
}
} // namespace nmd
} // namespace OHOS
DISABLE_WARNING_POP