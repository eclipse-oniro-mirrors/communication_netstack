#ifndef __INCLUDE_DNSRESOLV_SERVICE_H__
#define __INCLUDE_DNSRESOLV_SERVICE_H__
#include "dnsresolv.h"
#include "dnsresolv_controller.h"
#include "job.h"
#include "server_template.h"
#include <stdint.h>
#include <string>
#include <vector>
namespace OHOS {
namespace nmd {

const char *const DNS_RESOLV_SERVICE_SOCK_NAME = "dnsresolvproxy.sock";
const char *const DNS_RESOLV_SERVICE_NAME = "DNSResolverService";

class dnsresolv_job : public job {
public:
    dnsresolv_job(const int fd, const uint8_t *msg, const size_t msgLen,
        const std::shared_ptr<common::socket_base> serverSocket)
        : job(fd, msg, msgLen, serverSocket)
    {}

    ~dnsresolv_job() = default;

    virtual void run() override;

    void setupCallbacks(const dnsresolv_callbacks &callbacks)
    {
        dnsresolvCallbacks_ = callbacks;
    }

private:
    void doCreateNetworkCache(const dnsresolver_request_cmd *command);
    void doSetResolverConfig(const dnsresolver_request_cmd *command);
    void doDestroyNetworkCache(const dnsresolver_request_cmd *command);
    void doGetAddrInfo(const dnsresolver_request_cmd *command);
    void doGetAddrInfoProxy(const dnsresolver_request_cmd *command);
    void responseOk();
    void responseOk(const struct addrinfo *res);
    void responseFailed(const int ret);
    size_t getNameList(const char *buffer, const size_t bufferSize, std::vector<std::string> &namelist);
    ssize_t sendResponseResult(dnsresolver_response_cmd &cmd);

private:
    dnsresolv_callbacks dnsresolvCallbacks_;
    dnsresolv_controller dnsresolvCtrl_;
};

class dnsresolv_service : public common::server_template {
public:
    int getResolverInfo(const uint16_t netid, std::vector<std::string> &servers, std::vector<std::string> &domains,
        dns_res_params &param);
    int setResolverConfig(const dnsresolver_params &resolvParams);
    int createNetworkCache(const uint16_t netid);
    int flushNetworkCache(const uint16_t netid);
    int destoryNetworkCache(const uint16_t netid);
    int getaddrinfo(
        const char *hostname, const char *servname, const struct addrinfo *hints, struct addrinfo **res);

public:
    dnsresolv_service() : common::server_template(DNS_RESOLV_SERVICE_SOCK_NAME, DNS_RESOLV_SERVICE_NAME) {}
    ~dnsresolv_service() = default;

    bool init(const dnsresolv_callbacks &callbacks);

private:
    virtual void initJob(const int socketFd, const uint8_t *msg, const size_t msgLen) override;

private:
    dnsresolv_controller dnsresolvCtrl_;
    dnsresolv_callbacks dnsresolvCallbacks_;
};
} // namespace nmd
} // namespace OHOS
#endif //!__INCLUDE_DNSRESOLV_SERVICE_H_