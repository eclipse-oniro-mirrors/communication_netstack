#ifndef __INCLUDE_DNSRESOLV_CACHE_H__
#define __INCLUDE_DNSRESOLV_CACHE_H__
#include "dnsresolv.h"
#include "rwlock.h"
#include <arpa/nameser.h>
#include <chrono>
#include <cstddef>
#include <memory>
#include <stdint.h>
#include <unordered_map>
#include <vector>

namespace OHOS {
namespace nmd {

enum dnsresolv_cache_status {
    RESOLV_CACHE_UNSUPPORTED, /* the cache can't handle that kind of queries */
    /* or the answer buffer is too small */
    RESOLV_CACHE_NOTFOUND, /* the cache doesn't know about this query */
    RESOLV_CACHE_FOUND, /* the cache found the answer */
    RESOLV_CACHE_SKIP /* Don't do anything on cache */
};

class dns_packet {
    const uint32_t FNV_MULT = 16777619U;
    const uint32_t FNV_BASIS = 2166136261U;
    using PackIterator = std::vector<uint8_t>::const_iterator;

public:
    explicit dns_packet(const uint8_t *packet, const size_t packageLen, const std::time_t expires = -1)
        : packet_(packet, packet + packageLen), itCursor_(packet_.begin()), expirationTime_(expires)
    {}

    dns_packet(const dns_packet &dp)
        : packet_(dp.packet_), itCursor_(packet_.begin()), expirationTime_(dp.expirationTime_)
    {}

    void operator=(const dns_packet &dp)
    {
        this->packet_ = dp.packet_;
        this->itCursor_ = this->packet_.begin();
        this->expirationTime_ = dp.expirationTime_;
    }

    bool operator==(const dns_packet &dp) const;
    uint32_t hash() const;

    bool isExpired();
    const std::vector<uint8_t> &getDnsPacket() const
    {
        return packet_;
    }

private:
    void rewind() const;
    void skip(const long index) const;
    uint32_t hashBytes(int numBytes, uint32_t hash) const;
    int readInt16() const;
    uint32_t hashQR(uint32_t hash) const;
    uint32_t hashRR(uint32_t hash) const;
    uint32_t hashQName(uint32_t hash) const;
    bool isEqualQR(const dns_packet &dp) const;
    bool isEqualRR(const dns_packet &dp) const;
    bool isEqualDomainName(const dns_packet &dp) const;
    bool isEqualBytes(const dns_packet &dp, const int numberByte) const;

private:
    std::vector<uint8_t> packet_;
    mutable PackIterator itCursor_;
    std::time_t expirationTime_;
};

struct dns_packet_hash_func {
    uint32_t operator()(const dns_packet &dp) const
    {
        return dp.hash();
    }
};

using ResolvCache = std::unordered_map<dns_packet, dns_packet, dns_packet_hash_func>;

struct network_config {
    explicit network_config(const uint16_t _netid) : netid(_netid), resolvCache(std::make_unique<ResolvCache>()) {}

    const uint16_t netid;
    std::unique_ptr<ResolvCache> resolvCache;
    std::vector<std::string> nameservers;
    std::vector<nmd::common::net_utils::ip_sock_addr> nameserverSockAddrs;
    dns_res_params params {};
    std::vector<std::string> searchDomains;
};

using NetworkConfigMap = std::unordered_map<uint16_t, std::unique_ptr<network_config>>;

class dnsresolv_cache {
public:
    static dnsresolv_cache_status lookupFromResolvCache(uint16_t netid, const uint8_t *query, size_t querylen,
        uint8_t *answer, const size_t answersize, size_t *answerlen, uint32_t flags);

    static int resolvCacheAdd(const uint16_t netid, const uint8_t *query, const size_t querylen,
        const uint8_t *answer, const size_t answerlen);
    static network_config *lookupResolvConfig(const uint16_t netid);
    static int getResolverInfo(const uint16_t netid, std::vector<std::string> &servers,
        std::vector<std::string> &domains, dns_res_params &param);
    static int setResolverConfig(const dnsresolver_params &resolvParams);
    static int createNetworkCache(const uint16_t netid);
    static int destoryNetworkCache(const uint16_t netid);
    static int flushNetworkCache(const uint16_t netid);

public:
    dnsresolv_cache(/* args */) = default;
    ~dnsresolv_cache() = default;

private:
    static bool isValidServer(const std::string &server);
    static ResolvCache *findResolvCache(const uint16_t netid);
    static std::time_t getTTLFromAnswer(const uint8_t *answer, const size_t answerlen);
    static uint32_t getNegativeTTL(ns_msg handle);
    static int skipName(const uint8_t *ptr, const uint8_t *eom);

private:
    static nmd::common::rwlock sCacheLock_;
    static NetworkConfigMap sNetworkConfig_;
};

} // namespace nmd
} // namespace OHOS
#endif //!__INCLUDE_DNSRESOLV_CACHE_H__