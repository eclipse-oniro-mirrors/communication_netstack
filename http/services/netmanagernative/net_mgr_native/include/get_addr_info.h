#ifndef __INCLUDE_GET_ADDR_INFO_H__
#define __INCLUDE_GET_ADDR_INFO_H__

#include <chrono>
#include <netdb.h>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#include "net_utils.h"

#define _PATH_HOSTS "/etc/hosts"
#define SCOPE_DELIMITER '%'
#define NS_TYPE_ELT 0x40 /* EDNS0 extended label type */
#define DNS_LABELTYPE_BITSTRING 0x41
#define NETDB_SUCCESS 0
static const char digits[] = "0123456789";
static const char digitvalue[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*16*/
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*32*/
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*48*/
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -1, -1, -1, -1, -1, -1, /*64*/
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*80*/
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*96*/
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*112*/
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*128*/
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 /*256*/
};

class get_addr_info_unit_test;
namespace OHOS {
namespace nmd {

struct netd_net_context;
struct afd;
struct dns_res_state;
struct res_target;
struct dns_res_state;
struct dns_res_params;
typedef bool (*res_n_ok_func)(const char *dn);

class get_addr_info {
#ifdef UNIT_TEST
    friend get_addr_info_unit_test;
#endif
public:
    get_addr_info(/* args */) = default;
    ~get_addr_info() = default;

public:
    static int getaddrinfoFornetContext(const char *hostname, const char *servname, const addrinfo *hints,
        const netd_net_context *netcontext, addrinfo **res);

    static int resolvGetAddrInfo(const char *hostname, const char *servname, const addrinfo *hints,
        const netd_net_context *netcontext, addrinfo **res);
    static int getaddrinfoNumeric(const char *hostname, const char *servname, addrinfo hints, addrinfo **result);

    static int ns_name_pton(const char *, unsigned char *, size_t);
    static int ns_name_pton2(const char *, unsigned char *, size_t, size_t *);
    static int ns_name_compress(const char *src, unsigned char *dst, size_t dstsiz, const unsigned char **dnptrs,
        const unsigned char **lastdnptr);
    static int ns_name_skip(const unsigned char **ptrptr, const unsigned char *eom);
    static int labellen(const unsigned char *lp);
    static int encode_bitsring(
        const char **bp, const char *end, unsigned char **labelp, unsigned char **dst, unsigned const char *eom);
    static int ns_name_pack(const unsigned char *src, unsigned char *dst, int dstsiz, const unsigned char **dnptrs,
        const unsigned char **lastdnptr);
    static int dn_find(const unsigned char *domain, const unsigned char *msg, const unsigned char *const *dnptrs,
        const unsigned char *const *lastdnptr);
    static int mklower(int ch);
    static int ns_makecanon(const char *src, char *dst, size_t dstsize);
    static int ns_samename(const char *a, const char *b);

private:
    static int validateHints(const addrinfo *hints);
    static int checkHostNameAndExplore(
        const addrinfo &ai, const char *hostname, const char *servname, addrinfo *cur);
    static int getPort(const addrinfo *ai, const char *servname, bool matchonly);
    static int strToNumber(const char *p);
    static int exploreNull(const addrinfo *pai, const char *servname, addrinfo **res);
    static const afd *findAfd(int af);
    static addrinfo *getAi(const addrinfo *pai, const afd *pafd, const char *addr);
    static int exploreNumericScope(const addrinfo *pai, const char *hostname, const char *servname, addrinfo **res);
    static int exploreNumeric(
        const addrinfo *pai, const char *hostname, const char *servname, addrinfo **res, const char *canonname);
    static int ip6StrToScopeid(const char *scope, const struct sockaddr_in6 &sin6, uint32_t &scopeid);
    static int getCanonName(const addrinfo *pai, addrinfo *ai, const char *str);
    static int exploreFqdn(const addrinfo *pai, const char *hostname, const char *servname, addrinfo **res,
        const netd_net_context *netcontext);
    static bool getAddrinfoFromFile(const char *name, const addrinfo *pai, addrinfo **res);
    static int dnsGetaddrinfo(
        const char *name, const addrinfo *pai, const netd_net_context *netcontext, addrinfo **rv);
    static bool haveIpv6(uint32_t mark, uid_t uid);
    static bool haveIpv4(uint32_t mark, uid_t uid);

    static int findSrcAddr(const sockaddr *addr, sockaddr *src_addr, unsigned mark, uid_t uid);
    static int resSearchN(const char *name, res_target *target, dns_res_state &res, int &herrno);
    static int resQueryDomainN(
        const char *name, const char *domain, res_target *target, dns_res_state &res, int &herrno);
    static int resQueryN(const char *name, res_target *target, dns_res_state &res, int &herrno);
    static int resMakePacketForQuery(uint32_t op, // opcode of query
        const uint8_t *dname, // domain name
        int cl, int type, // class and type of query
        const uint8_t *data, // resource record data
        size_t datalen, // length of data
        uint8_t *buf, // buffer to put query
        size_t buflen); // size of buffer
    static int resQueryPacketSend(dns_res_state &statp, const uint8_t *buf, size_t buflen, uint8_t *ans,
        size_t anssiz, int &rcode, uint32_t flags);
    static int getHerrnoFromRcode(int rcode);

    static int dnCompress(
        const uint8_t *src, uint8_t *dst, size_t dstsiz, const uint8_t **dnptrs, const uint8_t **lastdnptr);
    static int sendViaUdp(dns_res_state &statp, dns_res_params &params, const uint8_t *buf, const size_t buflen,
        uint8_t *ans, size_t anssiz, int &terrno, size_t &ns, bool &needTcp, int &gotsomewhere, time_t &at,
        int &rcode, int &delay);
    static int sendViaTcp(dns_res_state &statp, dns_res_params &params, const uint8_t *buf, const size_t buflen,
        uint8_t *ans, size_t anssiz, int &terrno, const size_t ns, time_t &at, int &rcode, int &delay);
    static int randomBind(const int s, const sa_family_t family);
    static timespec getTimeout(const dns_res_params &params);
    static timespec evNowTime(void);
    static timespec evAddTime(const timespec &addend1, const timespec &addend2);
    static int evCmpTime(const timespec &a, const timespec &b);
    static timespec evSubTime(const timespec &minuend, const timespec &subtrahend);
    static timespec evConsTime(const time_t sec, const long nsec);
    static int calculateElapsedTime(const timespec &t1, const timespec &t0);
    static int udpRetryingPollWrapper(
        dns_res_state &statp, const size_t ns, const timespec &finish, std::vector<int> &fdAvailable);
    static int retryingPoll(const int sock, const short events, const timespec &finish);
    static bool isInvalidAnswer(dns_res_state &statp, const sockaddr_storage &from, const uint8_t *buf,
        size_t buflen, uint8_t *ans, size_t anssiz, size_t &receivedFromNs);

    static addrinfo *getAnswer(const std::vector<uint8_t> &answer, size_t anslen, const char *qname, int qtype,
        const struct addrinfo *pai, int &herrno);

    static int dnExpand(const uint8_t *msg, const uint8_t *eom, const uint8_t *src, char *dst, size_t dstsiz);
    static void getResolvConfigFromCache(dns_res_state &statp);

    static int lookupNameserverFromResNs(dns_res_state &statp, const sockaddr *sa);
    static bool resQueriesMatch(const uint8_t *buf1, const uint8_t *eom1, const uint8_t *buf2, const uint8_t *eom2);
    static bool findNameInQueryPacket(
        const std::string &name, int type, int cl, const uint8_t *buf, const uint8_t *eom);
    static bool sockEq(const struct sockaddr *socka, const struct sockaddr *sockb);
    static int connect_with_timeout(int sock, const sockaddr *nsap, socklen_t salen, const timespec timeout);
    static bool isTrailingWithDot(const std::string &name, uint32_t &dots);
    static int tryQueyWithDomain(const bool trailingDot, const std::string &name, const uint32_t dots,
        res_target *target, dns_res_state &res, int &herrno);
    static bool resetNsSock(
        nmd::common::net_utils::socket_fd &sock, const int type, const sockaddr *nsap, int &terrno, int &ret);
    static int waitForReply(dns_res_state &statp, dns_res_params &params, const uint8_t *buf, const size_t buflen,
        uint8_t *ans, size_t anssiz, int &terrno, size_t &ns, bool &needTcp, int &gotsomewhere, int &rcode,
        int &delay);

    static void closeInvalidSock(dns_res_state &statp, const struct sockaddr *nsap);

    static res_n_ok_func getResNOkFunc(int qtype);

private:
    class hostfd_wrapper;
};

} // namespace nmd
} // namespace OHOS
#endif //!__INCLUDE_GET_ADDR_INFO_H__