#ifndef __INCLUDE_DNSRESOLV_CLIENT_H__
#define __INCLUDE_DNSRESOLV_CLIENT_H__
#include <netdb.h>
#include <stdint.h>
#include "dnsresolv.h"

namespace OHOS {
namespace nmd {

enum dnsresolv_query_state { QUERY_START, QUERY_WAIT_REPONSE, QUERY_OK, QUERY_FAILED, QUERY_RESULT, QUERY_END };

class dnsresolv_client {
private:
    dnsresolv_query_state queryState_ = QUERY_START;
    int socketFd_ = -1;

public:
    dnsresolv_client(/* args */) = default;
    ~dnsresolv_client() = default;

    int init();
    int initConfiguration(const dnsresolver_params &param);
    int unInitConfiguration(const dnsresolver_params &param);

public:
    int getaddrinfo(
        const char *hostname, const char *servname, const struct addrinfo *hints, struct addrinfo **res);
    int getaddrinfo_proxy(const char *hostname, const char *servname, const struct addrinfo *hints,
        struct addrinfo **res, uint16_t netid);

private:
    dnsresolv_query_state startQuery(
        const char *hostname, const char *servname, const struct addrinfo *hints, int &result);
    dnsresolv_query_state sendRequest(struct dnsresolver_request_cmd &reqCmd, int &result);
    dnsresolv_query_state recvResponese(int &result, struct dnsresolver_response_cmd &repcmd);
    dnsresolv_query_state recvResult(
        int &result, const struct dnsresolver_response_cmd &repcmdState, p_dnsresolver_response_cmd &repcmdResult);
    dnsresolv_query_state parseResult(
        int &result, const p_dnsresolver_response_cmd repcmdResult, struct addrinfo **res);

    int createNetworkCache(const uint16_t netid);
    int destroyNetworkCache(const uint16_t netid);
    int setResolverConfig(const dnsresolver_params &param);
    int sendRequestWithResponse(const dnsresolver_request_cmd &reqcmd, dnsresolver_response_cmd &repcmd);
    void setNameList(char *buffer, const size_t bufferSize, const std::vector<std::string> namelist);
};
} // namespace nmd
} // namespace OHOS

#endif //!__INCLUDE_DNSRESOLV_CLIENT_H__