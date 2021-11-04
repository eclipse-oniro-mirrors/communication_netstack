
#include "dnsresolv_cache.h"
#include "get_addr_info.h"
#include "utils.h"
#include "warning_disable.h"
#include <ctype.h>
#include "logger.h"
#include "netnative_log_wrapper.h"

namespace OHOS {
namespace nmd {

int memcasecmp(const void *vs1, const void *vs2, const size_t n)
{
    unsigned int i;
    unsigned char const *s1 = reinterpret_cast<unsigned char const *>(vs1);
    unsigned char const *s2 = reinterpret_cast<unsigned char const *>(vs2);
    for (i = 0; i < n; i++) {
        unsigned char u1 = *s1++;
        unsigned char u2 = *s2++;
        if (toupper(u1) != toupper(u2))
            return toupper(u1) - toupper(u2);
    }
    return 0;
}

nmd::NetworkConfigMap nmd::dnsresolv_cache::sNetworkConfig_;
nmd::common::rwlock nmd::dnsresolv_cache::sCacheLock_;

nmd::dnsresolv_cache_status nmd::dnsresolv_cache::lookupFromResolvCache(uint16_t netid, const uint8_t *query,
    size_t querylen, uint8_t *answer, const size_t answersize, size_t *answerlen, uint32_t flags)
{
    if (flags & (NETD_DNS_RESOLV_NO_CACHE_STORE | NETD_DNS_RESOLV_NO_CACHE_LOOKUP)) {
        return flags & NETD_DNS_RESOLV_NO_CACHE_STORE ? RESOLV_CACHE_SKIP : RESOLV_CACHE_NOTFOUND;
    }

    sCacheLock_.write_guard();
    auto resolvCache = findResolvCache(netid);
    if (nullptr == resolvCache) {
        return RESOLV_CACHE_UNSUPPORTED;
    }

    auto find = resolvCache->find(dns_packet(query, querylen));
    if (find == resolvCache->end()) {
        return RESOLV_CACHE_NOTFOUND;
    }

    if (find->second.isExpired()) {
        // remove expired cache
        resolvCache->erase(find);
        return RESOLV_CACHE_NOTFOUND;
    }

    auto ansPack = find->second.getDnsPacket();
    *answerlen = ansPack.size();
    if (*answerlen > answersize) {
        return RESOLV_CACHE_UNSUPPORTED;
    }

    std::copy(ansPack.begin(), ansPack.end(), answer);

    return RESOLV_CACHE_FOUND;
}

int nmd::dnsresolv_cache::resolvCacheAdd(const uint16_t netid, const uint8_t *query, const size_t querylen,
    const uint8_t *answer, const size_t answerlen)
{
    sCacheLock_.write_guard();
    auto resolvCache = findResolvCache(netid);
    if (nullptr == resolvCache) {
        return -1;
    }

    dns_packet key(query, querylen);
    auto find = resolvCache->find(key);
    if (find != resolvCache->end() && !(find->second.isExpired())) {
        // already in cache, no need cache
        return 0;
    }

    auto ttl = getTTLFromAnswer(answer, answerlen);
    if (ttl > 0) {
        auto now = nmd::common::utils::getCurrentTime();
        dns_packet value(answer, answerlen, now + ttl);
        // update
        resolvCache->erase(key);
        resolvCache->insert(std::make_pair(key, value));
    }

    return 0;
}

int nmd::dnsresolv_cache::setResolverConfig(const dnsresolver_params &resolvParams)
{
    if (resolvParams.servers.empty()) {
        // common::logger::error()
        //    << "[dnsresolv_cache] Unable to setResolverConfig: invalid param: servers is empty() " << endl;
        NETNATIVE_LOGE("[dnsresolv_cache] Unable to setResolverConfig: invalid param: servers is empty()");
        return -1;
    }

    sCacheLock_.write_guard();
    auto config = lookupResolvConfig(resolvParams.netId);
    if (nullptr == config) {
        // common::logger::error() << "[dnsresolv_cache] Unable to setResolverConfig: can not find config if netid: "
        //                        << resolvParams.netId << endl;
        NETNATIVE_LOGE("[dnsresolv_cache] Unable to setResolverConfig: can not find config if netid: %{public}d",
            resolvParams.netId);
        return -1;
    }

    std::vector<nmd::common::net_utils::ip_sock_addr> ipSockAddrs;
    ipSockAddrs.reserve(resolvParams.servers.size());
    for (const auto &server : resolvParams.servers) {
        if (!isValidServer(server)) {
            // common::logger::error() << "[dnsresolv_cache] Unable to setResolverConfig: invalid server." << endl;
            NETNATIVE_LOGE("[dnsresolv_cache] Unable to setResolverConfig: invalid server.");
            return -1;
        }
        ipSockAddrs.push_back(nmd::common::net_utils::ip_sock_addr::toIPSockAddr(server, DNS_REQ_PORT));
    }

    config->nameservers = std::move(resolvParams.servers);
    config->nameserverSockAddrs = std::move(ipSockAddrs);
    config->searchDomains = std::move(resolvParams.domains);

    return 0;
}

int nmd::dnsresolv_cache::createNetworkCache(const uint16_t netid)
{
    sCacheLock_.write_guard();
    auto config = lookupResolvConfig(netid);
    if (config != nullptr) {
        // common::logger::error()
        //    << "[dnsresolv_cache] Unable to createNetworkCache: cache already exist. netid: " << netid << endl;
        NETNATIVE_LOGE(
            "[dnsresolv_cache] Unable to createNetworkCache: cache already exist. netid: %{public}d", netid);
        return -2;
    }

    sNetworkConfig_.insert(std::make_pair(netid, std::make_unique<network_config>(netid)));

    return 0;
}

int nmd::dnsresolv_cache::destoryNetworkCache(const uint16_t netid)
{
    sCacheLock_.write_guard();
    sNetworkConfig_.erase(netid);
    return 0;
}

int nmd::dnsresolv_cache::flushNetworkCache(const uint16_t netid)
{
    sCacheLock_.write_guard();

    auto config = lookupResolvConfig(netid);
    if (nullptr == config) {
        // common::logger::error()
        //    << "[dnsresolv_cache] Unable to setResolverConfig: config is nullptr. netid: " << netid << endl;
        NETNATIVE_LOGE(
            "[dnsresolv_cache] Unable to setResolverConfig: config is nullptr. netid:  %{public}d", netid);
        return -1;
    }

    config->resolvCache->clear();

    return 0;
}

int nmd::dnsresolv_cache::getResolverInfo(const uint16_t netid, std::vector<std::string> &servers,
    std::vector<std::string> &domains, nmd::dns_res_params &param)
{
    sCacheLock_.write_guard();

    auto config = lookupResolvConfig(netid);
    if (nullptr == config) {
        // common::logger::error()
        //    << "[dnsresolv_cache] Unable to getResolverInfo: config is nullptr. netid: " << netid << endl;
        NETNATIVE_LOGE("[dnsresolv_cache] Unable to getResolverInfo: config is nullptr. netid: %{public}d", netid);
        return -1;
    }

    servers = config->nameservers;
    domains = config->searchDomains;
    param.baseTimeoutMsec = config->params.baseTimeoutMsec;
    param.retryCount = config->params.retryCount;

    return 0;
}

nmd::network_config *nmd::dnsresolv_cache::lookupResolvConfig(const uint16_t netid)
{
    auto find = sNetworkConfig_.find(netid);
    if (find == sNetworkConfig_.end()) {
        return nullptr;
    }
    return find->second.get();
}

bool nmd::dnsresolv_cache::isValidServer(const std::string &server)
{
    addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    addrinfo *result = nullptr;
    int err = nmd::get_addr_info::getaddrinfoNumeric(server.c_str(), DNS_REQ_PORT_STR, hints, &result);
    if (err != 0) {
        // common::logger::error() << "[dnsresolv_cache] Unable to getaddrinfoNumeric: server " << server
        //                        << "error: " << gai_strerror(err) << endl;
        NETNATIVE_LOGE("[dnsresolv_cache] Unable to getaddrinfoNumeric: server %{public}s error: %{public}s",
            server.c_str(), gai_strerror(err));
        return false;
    }
    // freeaddrinfo(result);
    return true;
}

nmd::ResolvCache *nmd::dnsresolv_cache::findResolvCache(const uint16_t netid)
{
    auto config = lookupResolvConfig(netid);
    return nullptr == config ? nullptr : config->resolvCache.get();
}

std::time_t nmd::dnsresolv_cache::getTTLFromAnswer(const uint8_t *answer, const size_t answerlen)
{
    ns_msg handle;
    uint32_t result = 0;
    if (ns_initparse(answer, static_cast<int>(answerlen), &handle) >= 0) {
        // get number of answer records
        int ancount = ns_msg_count(handle, ns_s_an);

        if (ancount == 0) {
            result = getNegativeTTL(handle);
        } else {
            uint32_t ttl(0);
            ns_rr rr;
            for (int n = 0; n < ancount; n++) {
                if (ns_parserr(&handle, ns_s_an, n, &rr) == 0) {
                    ttl = rr.ttl;
                    if (n == 0 || ttl < result) {
                        result = ttl;
                    }
                } else {
                    // common::logger::info()
                    //    << "[dnsresolv_cache] Unable to getTTLFromAnswer: ns_parserr failed ancount no = " << n
                    //    << endl;
                    NETNATIVE_LOGI(
                        "[dnsresolv_cache] Unable to getTTLFromAnswer: ns_parserr failed ancount no =  %{public}d",
                        n);
                }
            }
        }
    } else {
        // common::logger::info() << "[dnsresolv_cache] Unable to getTTLFromAnswer: ns_initparse failed " << endl;
        NETNATIVE_LOGI("[dnsresolv_cache] Unable to getTTLFromAnswer: ns_initparse failed ");
    }

    return std::time_t(result);
}

uint32_t nmd::dnsresolv_cache::getNegativeTTL(ns_msg handle)
{
    int n, nscount;
    uint32_t result = 0;
    ns_rr rr;

    nscount = ns_msg_count(handle, ns_s_ns);
    for (n = 0; n < nscount; n++) {
        if ((ns_parserr(&handle, ns_s_ns, n, &rr) == 0) && (ns_rr_type(rr) == ns_t_soa)) {
            const uint8_t *rdata = ns_rr_rdata(rr); // find the data
            const uint8_t *edata = rdata + ns_rr_rdlen(rr); // add the len to find the end
            int len;
            uint32_t ttl, rec_result = rr.ttl;

            // find the MINIMUM-TTL field from the blob of binary data for this record
            // skip the server name
            len = skipName(rdata, edata);
            if (len == -1)
                continue; // error skipping
            rdata += len;

            // skip the admin name
            len = skipName(rdata, edata);
            if (len == -1)
                continue; // error skipping
            rdata += len;

            if (edata - rdata != 5 * NS_INT32SZ)
                continue;
            // skip: serial number + refresh interval + retry interval + expiry
            rdata += NS_INT32SZ * 4;
            // finally read the MINIMUM TTL
            ttl = ntohl(*reinterpret_cast<const uint32_t *>(rdata));
            if (ttl < rec_result) {
                rec_result = ttl;
            }
            // Now that the record is read successfully, apply the new min TTL
            if (n == 0 || rec_result < result) {
                result = rec_result;
            }
        }
    }
    return result;
}

int nmd::dnsresolv_cache::skipName(const uint8_t *ptr, const uint8_t *eom)
{
    const uint8_t *saveptr = ptr;

    if (-1 == nmd::get_addr_info::ns_name_skip(&ptr, eom)) {
        return -1;
    }
    return static_cast<int>(ptr - saveptr);
}

bool nmd::dns_packet::operator==(const dns_packet &dp) const
{
    this->rewind();
    dp.rewind();

    // compare RD, ignore TC, see comment in _dnsPacket_checkQuery
    if ((packet_[2] & 1) != (dp.packet_[2] & 1)) {
        return false;
    }

    if (packet_[3] != dp.packet_[3]) {
        return false;
    }

    // mark ID and header bytes as compared
    this->skip(4);
    dp.skip(4);

    // compare QDCOUNT
    int count1 = this->readInt16();
    int count2 = dp.readInt16();
    if (count1 != count2 || count1 < 0) {
        return false;
    }

    // assume: ANcount and NScount are 0
    this->skip(4);
    dp.skip(4);

    // compare ARCOUNT
    int arcount1 = this->readInt16();
    int arcount2 = dp.readInt16();
    if (arcount1 != arcount2 || arcount1 < 0) {
        return false;
    }

    // compare the QDCOUNT QRs
    for (; count1 > 0; count1--) {
        if (!this->isEqualQR(dp)) {
            return false;
        }
    }

    // compare the ARCOUNT RRs
    for (; arcount1 > 0; arcount1--) {
        if (!this->isEqualRR(dp)) {
            return 0;
        }
    }

    return true;
}

uint32_t nmd::dns_packet::hash() const
{
    uint32_t hash = FNV_BASIS;
    rewind();
    // ignore the ID
    skip(2);
    hash = hash * FNV_MULT ^ (packet_[2] & 1);

    // mark the first header byte as processed
    skip(1);

    // process the second header byte
    hash = hashBytes(1, hash);

    // read QDCOUNT
    int count = readInt16();

    // assume: ANcount and NScount are 0
    skip(4);

    // read ARCOUNT
    int arcount = readInt16();

    // hash QDCOUNT QRs
    for (; count > 0; count--) {
        hash = hashQR(hash);
    }

    // hash ARCOUNT RRs
    for (; arcount > 0; arcount--) {
        hash = hashRR(hash);
    }

    return hash;
}

void nmd::dns_packet::rewind() const
{
    itCursor_ = packet_.begin();
}

void nmd::dns_packet::skip(const long index) const
{
    const PackIterator it = (itCursor_ + index) > packet_.end() ? packet_.end() : (itCursor_ + index);
    itCursor_ = it;
}

uint32_t nmd::dns_packet::hashBytes(int numBytes, uint32_t hash) const
{
    PackIterator it = itCursor_;

    while (numBytes > 0 && it < packet_.end()) {
        hash = hash * FNV_MULT ^ *it++;
        numBytes--;
    }

    itCursor_ = it;
    return hash;
}

int nmd::dns_packet::readInt16() const
{
    PackIterator it = itCursor_;
    if (it + 2 > packet_.end()) {
        return -1;
    }

    itCursor_ = it + 2;
    return (*it << 8) | *(it + 1);
}

uint32_t nmd::dns_packet::hashQR(uint32_t hash) const
{
    hash = hashQName(hash);
    hash = hashBytes(4, hash); // TYPE and CLASS
    return hash;
}

uint32_t nmd::dns_packet::hashRR(uint32_t hash) const
{
    int rdlength;
    hash = hashQR(hash);
    hash = hashBytes(4, hash); // TTL
    rdlength = readInt16();
    hash = hashBytes(rdlength, hash); // RDATA
    return hash;
}

uint32_t nmd::dns_packet::hashQName(uint32_t hash) const
{
    PackIterator it = itCursor_;
    while (true) {
        if (it >= packet_.end()) {
            break;
        }

        int c = *it++;

        if (c == 0) {
            break;
        }

        if (c >= 64) {
            break;
        }
        if (it + c >= packet_.end()) {
            break;
        }

        while (c > 0) {
            uint8_t ch = *it++;
            ch = static_cast<uint8_t>(std::tolower(static_cast<uint8_t>(ch)));
            hash = hash * FNV_MULT ^ ch;
            c--;
        }
    }
    itCursor_ = it;
    return hash;
}

bool nmd::dns_packet::isEqualQR(const dns_packet &dp) const
{
    // compare domain name encoding + TYPE + CLASS
    if (!this->isEqualDomainName(dp) || !this->isEqualBytes(dp, 2 + 2)) {
        return false;
    }

    return true;
}
bool nmd::dns_packet::isEqualRR(const dns_packet &dp) const
{
    // compare query + TTL
    if (!isEqualQR(dp) || !isEqualBytes(dp, 4)) {
        return false;
    }

    // compare RDATA
    int rdlength1 = readInt16();
    int rdlength2 = dp.readInt16();
    if (rdlength1 != rdlength2 || !isEqualBytes(dp, rdlength1)) {
        return 0;
    }

    return 1;
}

bool nmd::dns_packet::isEqualDomainName(const dns_packet &dp) const
{
    PackIterator p1 = itCursor_;
    PackIterator p2 = dp.itCursor_;

    for (;;) {
        if (p1 >= packet_.end() || p2 >= dp.packet_.end()) {
            break;
        }
        int c1 = *p1++;
        int c2 = *p2++;
        if (c1 != c2) {
            break;
        }

        if (c1 == 0) {
            itCursor_ = p1;
            dp.itCursor_ = p2;
            return true;
        }
        if (c1 >= 64) {
            break;
        }
        if ((p1 + c1 > packet_.end()) || (p2 + c1 > dp.packet_.end())) {
            break;
        }
        if (memcasecmp(&(*p1), &(*p2), static_cast<size_t>(c1)) != 0) {
            break;
        }
        p1 += c1;
        p2 += c1;
    }
    return 0;
}

bool nmd::dns_packet::isEqualBytes(const dns_packet &dp, const int numberByte) const
{
    PackIterator it = this->itCursor_;
    PackIterator it2 = dp.itCursor_;

    if (numberByte < 0) {
        return false;
    }

    if (it + numberByte > this->packet_.end() || it2 + numberByte > dp.packet_.end()) {
        return false;
    }

    if (std::memcmp(&(*it), &(*it2), static_cast<size_t>(numberByte)) != 0) {
        return false;
    }

    it += numberByte;
    it2 += numberByte;
    return true;
}

bool nmd::dns_packet::isExpired()
{
    if (-1 == expirationTime_) {
        return false;
    }
    auto now = nmd::common::utils::getCurrentTime();
    if (now >= expirationTime_) {
        return true;
    }
    return false;
}

} // namespace nmd
} // namespace OHOS
