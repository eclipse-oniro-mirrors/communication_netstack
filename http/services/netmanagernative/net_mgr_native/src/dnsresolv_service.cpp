#include "dnsresolv_service.h"
#include "utils.h"
#include "netnative_log_wrapper.h"

namespace OHOS {
namespace nmd {
int dnsresolv_service::getResolverInfo(const uint16_t netid, std::vector<std::string> &servers,
    std::vector<std::string> &domains, dns_res_params &param)
{
    return dnsresolvCtrl_.getResolverInfo(netid, servers, domains, param);
}

int dnsresolv_service::setResolverConfig(const nmd::dnsresolver_params &resolvParams)
{
    return dnsresolvCtrl_.setResolverConfig(resolvParams);
}

int dnsresolv_service::createNetworkCache(const uint16_t netid)
{
    return dnsresolvCtrl_.createNetworkCache(netid);
}
int dnsresolv_service::flushNetworkCache(const uint16_t netid)
{
    return dnsresolvCtrl_.flushNetworkCache(netid);
}
int dnsresolv_service::destoryNetworkCache(const uint16_t netid)
{
    return dnsresolvCtrl_.destoryNetworkCache(netid);
}

int dnsresolv_service::getaddrinfo(
    const char *hostname, const char *servname, const struct addrinfo *hints, struct addrinfo **res)
{
    return dnsresolvCtrl_.getaddrinfo(hostname, servname, hints, res);
}

bool dnsresolv_service::init(const dnsresolv_callbacks &callbacks)
{
    NETNATIVE_LOGE("dnsresolv_service::init");
    if (nullptr == callbacks.getNetworkContext) {
        return false;
    }
    dnsresolvCallbacks_ = callbacks;
    return true;
}

void dnsresolv_service::initJob(const int socketFd, const uint8_t *msg, const size_t msgLen)
{
    auto job = new nmd::dnsresolv_job(socketFd, msg, msgLen, this->server_);
    job->setupCallbacks(dnsresolvCallbacks_);
    this->job_ = job;
}

void dnsresolv_job::run()
{
    if (fd_ < 0 || msg_.empty() || nullptr == serverSocket_) {
        return;
    }
    dnsresolver_request_cmd *command = reinterpret_cast<dnsresolver_request_cmd *>(msg_.data());

    switch (command->cmdID) {
        case dnsresolver_request_cmd::cmd_id::CREATE_NETWORK_CACHE:
            doCreateNetworkCache(command);
            break;
        case dnsresolver_request_cmd::cmd_id::SET_RESOLVER_CONFIG:
            doSetResolverConfig(command);
            break;
        case dnsresolver_request_cmd::cmd_id::DESOTRY_NETWORK_CACHE:
            doDestroyNetworkCache(command);
            break;
        case dnsresolver_request_cmd::cmd_id::GET_ADDR_INFO:
            doGetAddrInfo(command);
            break;
        case dnsresolver_request_cmd::cmd_id::GET_ADDR_INFO_PROXY:
            doGetAddrInfoProxy(command);
            break;
        default:
            break;
    }
}

void dnsresolv_job::responseOk()
{
    dnsresolver_response_cmd cmdRepStateOK;
    bzero(&cmdRepStateOK, sizeof(cmdRepStateOK));

    cmdRepStateOK.cmdID = dnsresolver_response_cmd::cmd_id::QUERY_STATE_OK;

    auto sendRet = sendResponseResult(cmdRepStateOK);
    if (sendRet < 0) {
        // common::logger::error() << "[dnsresolv_job] Unable to send response result. error: " << sendRet << endl;
        NETNATIVE_LOGE("[dnsresolv_job] Unable to send response result. error: %{public}d", sendRet);
        return;
    }
}

void dnsresolv_job::responseOk(const struct addrinfo *res)
{
    if (nullptr == res) {
        return;
    }

    size_t resSize(0);
    for (const struct addrinfo *res_p = res; res_p != NULL; res_p = res_p->ai_next) {
        resSize += sizeof(addrinfo);
        resSize += res_p->ai_addrlen;
        if (nullptr != res_p->ai_canonname) {
            resSize += (strlen(res_p->ai_canonname) + 1);
        }
    }

    dnsresolver_response_cmd cmdRepStateOK;
    bzero(&cmdRepStateOK, sizeof(cmdRepStateOK));

    cmdRepStateOK.cmdID = dnsresolver_response_cmd::cmd_id::QUERY_STATE_OK;
    cmdRepStateOK.resSize = resSize;

    auto sendRet = sendResponseResult(cmdRepStateOK);
    if (sendRet < 0) {
        // common::logger::error() << "[dnsresolv_job] Unable to send response result. error: " << sendRet << endl;
        NETNATIVE_LOGE("[dnsresolv_job] Unable to send response result. error: %{public}d", sendRet);
        return;
    }

    auto cmdFreeFunc = [](p_dnsresolver_response_cmd cmd) {
        if (nullptr == cmd) {
            return;
        }
        free(cmd);
    };

    p_dnsresolver_response_cmd cmdRepResult =
        reinterpret_cast<p_dnsresolver_response_cmd>(malloc(offsetof(dnsresolver_response_cmd, resData[resSize])));
    common::utils::auto_destroyer<p_dnsresolver_response_cmd> autoDeleteCmd(cmdRepResult, cmdFreeFunc);
    if (nullptr == cmdRepResult) {
        // common::logger::error() << "[dnsresolv_job] Unable to send response result. error: no memory. " << endl;
        NETNATIVE_LOGE("[dnsresolv_job] Unable to send response result. error: no memory. ");
        return;
    }

    cmdRepResult->result = 0;
    cmdRepResult->resSize = resSize;
    for (size_t i = 0; i < resSize; ++i) {
        cmdRepResult->resData[i] = 0;
    }

    cmdRepResult->cmdID = dnsresolver_response_cmd::cmd_id::QUERY_SUCCESS_WITH_RESULT;
    uint8_t *cur = cmdRepResult->resData;
    for (const struct addrinfo *res_p = res; res_p != NULL; res_p = res_p->ai_next) {
        memcpy(cur, res_p, sizeof(addrinfo));
        cur += sizeof(addrinfo);
        memcpy(cur, res_p->ai_addr, res_p->ai_addrlen);
        cur += res_p->ai_addrlen;

        if (nullptr != res_p->ai_canonname) {
            memcpy(cur, res_p->ai_canonname, strlen(res_p->ai_canonname));
            cur += (strlen(res_p->ai_canonname) + 1); // include "\0"
        }
    }

    sendRet = sendResponseResult(*cmdRepResult);
    if (sendRet < 0) {
        // common::logger::error() << "[dnsresolv_job] Unable to send response result. error: " << sendRet << endl;
        NETNATIVE_LOGE("[dnsresolv_job] Unable to send response result. error: %{public}d", sendRet);
        return;
    }
}

void dnsresolv_job::responseFailed(const int ret)
{
    dnsresolver_response_cmd cmdRep;
    bzero(&cmdRep, sizeof(cmdRep));

    cmdRep.cmdID = dnsresolver_response_cmd::cmd_id::QUERY_STATE_FAIL;
    cmdRep.result = ret;

    auto sendRet = sendResponseResult(cmdRep);
    if (sendRet < 0) {
        // common::logger::error() << "[dnsresolv_job] Unable to send response result. error: " << sendRet << endl;
        NETNATIVE_LOGE("[dnsresolv_job] Unable to send response result. error: %{public}d", sendRet);
        return;
    }
}

ssize_t dnsresolv_job::sendResponseResult(dnsresolver_response_cmd &cmdRep)
{
    size_t repSize = cmdRep.cmdID == dnsresolver_response_cmd::cmd_id::QUERY_SUCCESS_WITH_RESULT ?
        (sizeof(cmdRep) + cmdRep.resSize) :
        sizeof(cmdRep);
    iovec iov[1] = {{&cmdRep, repSize}};

    msghdr hdr;
    bzero(&hdr, sizeof(hdr));
    hdr.msg_iov = iov;
    hdr.msg_iovlen = 1;

    return this->serverSocket_->sendMsg(this->fd_, hdr);
}

void dnsresolv_job::doCreateNetworkCache(const dnsresolver_request_cmd *command)
{
    auto ret = dnsresolvCtrl_.createNetworkCache(command->netid);
    if (ret != 0) {
        responseFailed(ret);
        return;
    }

    responseOk();
}

void dnsresolv_job::doDestroyNetworkCache(const dnsresolver_request_cmd *command)
{
    auto ret = dnsresolvCtrl_.destoryNetworkCache(command->netid);
    if (ret != 0) {
        responseFailed(ret);
        return;
    }

    responseOk();
}

void dnsresolv_job::doSetResolverConfig(const dnsresolver_request_cmd *command)
{
    dnsresolver_params param;
    param.netId = command->netid;
    param.baseTimeoutMsec = command->cmd_baseTimeoutMsec;
    param.retryCount = command->cmd_retryCount;
    auto ret = getNameList(command->cmd_servers, MAX_NAME_LIST_LEN, param.servers);
    if (ret != command->cmd_serverCount) {
        // common::logger::error() << "[dnsresolv_job] Unable to getNameList: invalid param.servers " << endl;
        NETNATIVE_LOGE("[dnsresolv_job] Unable to getNameList: invalid param.servers ");
        responseFailed(static_cast<int>(ret));
        return;
    }

    ret = getNameList(command->cmd_domains, MAX_NAME_LIST_LEN, param.domains);
    if (ret != command->cmd_domainCount) {
        // common::logger::error() << "[dnsresolv_job] Unable to getNameList: invalid param.domains " << endl;
        NETNATIVE_LOGE("[dnsresolv_job] Unable to getNameList: invalid param.domains ");
        responseFailed(static_cast<int>(ret));
        return;
    }

    auto result = dnsresolvCtrl_.setResolverConfig(param);
    if (result != 0) {
        // common::logger::error() << "[dnsresolv_job] Unable to setResolverConfig: error code: " << result << endl;
        NETNATIVE_LOGE("[dnsresolv_job] Unable to setResolverConfig: error code: %{public}d", result);
        responseFailed(result);
        return;
    }

    responseOk();
}

void dnsresolv_job::doGetAddrInfo(const dnsresolver_request_cmd *command)
{
    const char *hostname = 0 == strlen(command->cmd_hostName) ? nullptr : command->cmd_hostName;
    const char *servername = 0 == strlen(command->cmd_serverName) ? nullptr : command->cmd_serverName;

    struct addrinfo *res = nullptr;
    auto ret = dnsresolv_controller::getaddrinfo(hostname, servername, &(command->cmd_hints), &res);
    if (ret != 0) {
        responseFailed(ret);
        return;
    }

    responseOk(res);
    freeaddrinfo(res);
}

void dnsresolv_job::doGetAddrInfoProxy(const dnsresolver_request_cmd *command)
{
    netd_net_context netContext;
    dnsresolvCallbacks_.getNetworkContext(command->netid, command->cmd_uid, netContext);

    struct addrinfo *res = nullptr;
    auto ret = dnsresolv_controller::getaddrinfoFornetContext(
        command->cmd_hostName, command->cmd_serverName, &(command->cmd_hints), netContext, &res);
    if (ret != 0) {
        responseFailed(ret);
        return;
    }

    responseOk(res);
}

size_t dnsresolv_job::getNameList(const char *buffer, const size_t bufferSize, std::vector<std::string> &namelist)
{
    if (nullptr == buffer || 0 == bufferSize || !namelist.empty()) {
        // common::logger::error() << "[dnsresolv_client] Unable to getNameList: invalid param. " << endl;
        NETNATIVE_LOGE("[dnsresolv_client] Unable to getNameList: invalid param. ");
        return 0;
    }

    char *buffCur = const_cast<char *>(buffer);
    size_t buffCount(0);
    std::string name;
    while (buffCount < bufferSize) {
        name.clear();
        name.assign(buffCur);
        if (name.empty()) {
            break;
        }
        namelist.push_back(name);
        buffCur += (name.length() + 1);
        buffCount += (name.length() + 1);
    }

    return namelist.size();
}
} // namespace nmd
} // namespace OHOS
