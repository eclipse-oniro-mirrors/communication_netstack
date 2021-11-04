#ifndef __INCLUDE_DNSRESOLV_H__
#define __INCLUDE_DNSRESOLV_H__
#include "net_utils.h"
#include "warning_disable.h"
#include <netinet/in.h>
#include <string>
#include <vector>

#define AI_MASK (AI_PASSIVE | AI_CANONNAME | AI_NUMERICHOST | AI_NUMERICSERV | AI_ADDRCONFIG)

#define GET_AI(ai, afd, addr)                                \
    do {                                                     \
        /* external reference: pai, error, and label free */ \
        (ai) = getAi(pai, (afd), (addr));                    \
        if ((ai) == NULL) {                                  \
            error = EAI_MEMORY;                              \
            goto free;                                       \
        }                                                    \
    } while (0)

#define GET_PORT(ai, serv)                             \
    do {                                               \
        /* external reference: error and label free */ \
        error = getPort((ai), (serv), 0);              \
        if (error != 0)                                \
            goto free;                                 \
    } while (0)

#define MATCH_FAMILY(x, y, w) ((x) == (y) || ((w) && ((x) == PF_UNSPEC || (y) == PF_UNSPEC)))
#define MATCH(x, y, w) ((x) == (y) || ((w) && ((x) == ANY_SOCK_TYPE || (y) == ANY_SOCK_TYPE)))

namespace OHOS {
namespace nmd {

DISABLE_WARNING_PUSH
DISABLE_WARNING_OLD_STYLE_CAST
const uid_t NET_CONTEXT_INVALID_UID = ((uid_t)-1);
DISABLE_WARNING_POP

const uint8_t RES_DEFAULT_TIMEOUT = 5; // default dns request timeout

const int32_t ANY_SOCK_TYPE = 0;

const pid_t NET_CONTEXT_INVALID_PID = -1;

const uint8_t PTON_MAX = 16;
constexpr int MAX_PACKET = 8 * 1024;

const uint8_t RCODE_TIMEOUT = 255;
const uint8_t RCODE_INTERNAL_ERROR = 254;

const uint8_t MAXNS = 4; // max # name servers we'll track

const long BILLION = 1000000000;

const uint16_t DNS_REQ_PORT = 53;
const char *const DNS_REQ_PORT_STR = "53";

const uint8_t ANYSIZE_ARRAY = 1;

// MARK_UNSET represents the default (i.e. unset) value for a socket mark.
const uint32_t NETID_UNSET = 0u;
const uint32_t MARK_UNSET = 0u;

const uint32_t MAX_NAME_LEN = 64;
const uint32_t MAX_NAME_LIST_LEN = 1024;

struct netd_net_context {
    uint16_t appNetId;
    uint32_t appMark;
    uint16_t dnsNetId;
    uint32_t dnsMark;
    uid_t uid = NET_CONTEXT_INVALID_UID;
    uint32_t flags;
    pid_t pid = NET_CONTEXT_INVALID_PID;
};

union sockaddr_union {
    struct sockaddr sa;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
};

struct res_target {
    struct res_target *next;
    const char *name; // domain name
    int qclass;
    int qtype; // class and type of query
    std::vector<uint8_t> answer = std::vector<uint8_t>(MAX_PACKET, 0); // buffer to put answer
    size_t n = 0; // result length
};

struct dns_res_state {
    void init(const netd_net_context *netcontext)
    {
        if (nullptr == netcontext) {
            return;
        }
        netid = netcontext->dnsNetId;
        ndots = 1;
        mark = netcontext->dnsMark;

        for (auto &sock : nssocks) {
            sock.reset();
        }
    }

    void closeSockets()
    {
        tcpNsSock.reset();
        isTcp = false;

        for (auto &sock : nssocks) {
            sock.reset();
        }
    }

    size_t nameserverCount()
    {
        return nsaddrs.size();
    }

    uint16_t netid; // NetId: cache key and socket mark
    uid_t uid; // uid of the app that sent the DNS lookup
    pid_t pid; // pid of the app that sent the DNS lookup
    uint16_t id; // current message id
    std::vector<std::string> searchDomains {}; // domains to search
    std::vector<nmd::common::net_utils::ip_sock_addr> nsaddrs;
    nmd::common::net_utils::socket_fd nssocks[MAXNS]; // UDP sockets to nameservers
    unsigned ndots : 4; // threshold for initial abs. query
    unsigned mark; // If non-0 SET_MARK to mark on all request sockets
    nmd::common::net_utils::socket_fd tcpNsSock; // TCP socket
    bool isTcp = false;
};

// Per-netid configuration parameters passed from netd to the resolver
struct dns_res_params {
    uint16_t baseTimeoutMsec; // base query retry timeout (if 0, use RES_TIMEOUT)
    uint8_t retryCount = 1; // number of retries
    void operator=(const dns_res_params &param)
    {
        baseTimeoutMsec = param.baseTimeoutMsec;
        retryCount = param.retryCount;
    }
};

enum dns_request_send_flag : uint32_t {
    // Send a single request to a single resolver and fail on timeout or network errors
    NETD_DNS_RESOLV_NO_RETRY = 1 << 0,

    // Don't lookup this request in the cache, and don't cache the result of the lookup.
    NETD_DNS_RESOLV_NO_CACHE_STORE = 1 << 1,

    // Don't lookup the request in cache.
    NETD_DNS_RESOLV_NO_CACHE_LOOKUP = 1 << 2,
};

struct dnsresolver_params {
    uint16_t netId = 0;
    uint16_t baseTimeoutMsec = 0;
    uint8_t retryCount = 0;
    std::vector<std::string> servers;
    std::vector<std::string> domains;
};

typedef struct alignas(8) dnsresolver_request_cmd {
    enum cmd_id {
        CREATE_NETWORK_CACHE,
        SET_RESOLVER_CONFIG,
        DESOTRY_NETWORK_CACHE,
        GET_ADDR_INFO,
        GET_ADDR_INFO_PROXY,
    } cmdID;
    uint16_t netid;
    union {
        struct dnsresolv_req_param {
            addrinfo hints;
            uid_t uid;
            char hostName[MAX_NAME_LEN];
            char serverName[MAX_NAME_LEN];
        } reqParam;

        struct dnsresolv_cfg_param {
            uint16_t baseTimeoutMsec;
            uint8_t retryCount;
            uint8_t serverCount;
            uint8_t domainCount;
            char servers[MAX_NAME_LIST_LEN];
            char domains[MAX_NAME_LIST_LEN];
        } cfgParam;
    } u;
} dnsresolver_request_cmd_t;

#define cmd_hints u.reqParam.hints
#define cmd_uid u.reqParam.uid
#define cmd_hostName u.reqParam.hostName
#define cmd_serverName u.reqParam.serverName

#define cmd_baseTimeoutMsec u.cfgParam.baseTimeoutMsec
#define cmd_retryCount u.cfgParam.retryCount
#define cmd_serverCount u.cfgParam.serverCount
#define cmd_domainCount u.cfgParam.domainCount
#define cmd_servers u.cfgParam.servers
#define cmd_domains u.cfgParam.domains

typedef struct alignas(8) dnsresolver_response_cmd {
    enum cmd_id {
        QUERY_STATE_OK,
        QUERY_STATE_FAIL,
        QUERY_SUCCESS_WITH_RESULT,
        QUERY_STATE_BUTT
    } cmdID = QUERY_STATE_BUTT;
    int result = 0;
    size_t resSize = 0;
    uint8_t resData[ANYSIZE_ARRAY];
} dnsresolver_response_cmd_t, *p_dnsresolver_response_cmd;

typedef void (*get_network_context_callback)(uint16_t netid, uid_t uid, netd_net_context &netcontext);
struct dnsresolv_callbacks {
    dnsresolv_callbacks() : getNetworkContext(nullptr) {}
    get_network_context_callback getNetworkContext;
};

} // namespace nmd
} // namespace OHOS
#endif //!__INCLUDE_DNSRESOLV_H__