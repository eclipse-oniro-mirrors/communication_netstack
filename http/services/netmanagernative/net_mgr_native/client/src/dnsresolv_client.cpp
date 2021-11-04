#include "dnsresolv_client.h"
#include <linux/un.h>
#include <sys/socket.h>
#include "logger.h"
#include <vector>
#include "netnative_log_wrapper.h"

namespace OHOS {
namespace nmd {
constexpr const char *DNSRESOLV_SERVICE_SOCK_PATH = "/dev/socket/dnsresolvproxy.sock";
} // namespace nmd

int nmd::dnsresolv_client::init()
{
    socketFd_ = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (socketFd_ == -1) {
        // common::logger::error() << "[dnsresolv_client] Unable to create socket ." << endl;
        NETNATIVE_LOGE("[dnsresolv_client] Unable to create socket .");
        return EAI_SYSTEM;
    }

    struct sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, DNSRESOLV_SERVICE_SOCK_PATH);

    struct sockaddr addr_ {};
    struct sockaddr *ad = reinterpret_cast<sockaddr *>(&addr);
    memcpy(&(addr_), ad, sizeof(*ad));
    int ret = connect(socketFd_, &addr_, sizeof(addr_));
    if (ret < 0) {
        // common::logger::error() << "[dnsresolv_client] Unable to connect server: " << DNSRESOLV_SERVICE_SOCK_PATH
        //                         << " error: " << ret << strerror(errno) << endl;
        NETNATIVE_LOGE("[dnsresolv_client] Unable to connect server: %{public}s, error: %{public}d, %{public}s",
            DNSRESOLV_SERVICE_SOCK_PATH, ret, strerror(errno));
        return EAI_SYSTEM;
    }

    return 0;
}

int nmd::dnsresolv_client::initConfiguration(const dnsresolver_params &param)
{
    auto ret = createNetworkCache(param.netId);
    if (ret < 0) {
        if (ret == -2) {
            // common::logger::warn() << "[dnsresolv_client] Network cache of netid: " << param.netId
            //                       << " has been created." << endl;
            NETNATIVE_LOGE("[dnsresolv_client] Network cache of netid: %{public}d has been created.", param.netId);
        }
    }
    // common::logger::info() << "[dnsresolv_client] Create network cache for netid: " << param.netId << endl;
    NETNATIVE_LOGE("[dnsresolv_client] Network cache of netid: %{public}d ", param.netId);

    ret = setResolverConfig(param);
    if (ret < 0) {
        // common::logger::error() << "[dnsresolv_client] Unable to set resolv config for netid: " << param.netId
        //                         << endl;
        NETNATIVE_LOGE("[dnsresolv_client] Unable to set resolv config for netid: %{public}d ", param.netId);
        return ret;
    }

    return 0;
}

int nmd::dnsresolv_client::unInitConfiguration(const dnsresolver_params &param)
{
    auto ret = destroyNetworkCache(param.netId);
    if (ret < 0) {
        // common::logger::error() << "[dnsresolv_client] Unable to destroy network cache for netid: " << param.netId
        //                         << endl;
        NETNATIVE_LOGE("[dnsresolv_client] Unable to destroy network cache for netid:  %{public}d ", param.netId);
        return ret;
    }

    // common::logger::info() << "[dnsresolv_client] Destroy network cache for netid: " << param.netId << endl;
    NETNATIVE_LOGE("[dnsresolv_client] Destroy network cache for netid: %{public}d ", param.netId);
    return 0;
}

int nmd::dnsresolv_client::getaddrinfo(
    const char *hostname, const char *servname, const struct addrinfo *hints, struct addrinfo **res)
{
    int ret = 0;
    dnsresolver_response_cmd repCmdState;
    queryState_ = QUERY_START;
    p_dnsresolver_response_cmd repCmdResult(nullptr);
    while (queryState_ != QUERY_END) {
        switch (queryState_) {
            case QUERY_START:
                queryState_ = startQuery(hostname, servname, hints, ret);
                break;
            case QUERY_WAIT_REPONSE:
                queryState_ = recvResponese(ret, repCmdState);
                break;
            case QUERY_OK:
                queryState_ = recvResult(ret, repCmdState, repCmdResult);
                break;
            case QUERY_FAILED:
                queryState_ = QUERY_END;
                break;
            case QUERY_RESULT:
                queryState_ = parseResult(ret, repCmdResult, res);
                break;
            case QUERY_END:
                break;

            default:
                break;
        }
    }

    if (nullptr != repCmdResult) {
        delete repCmdResult;
        repCmdResult = nullptr;
    }

    return ret;
}

nmd::dnsresolv_query_state nmd::dnsresolv_client::sendRequest(dnsresolver_request_cmd &reqCmd, int &result)
{
    if (socketFd_ < 0) {
        // common::logger::error() << "[dnsresolv_client] Unable to send request invalid socketFd_: " << socketFd_
        //                         << endl;
        NETNATIVE_LOGE("[dnsresolv_client] Unable to send request invalid socketFd_: %{public}d ", socketFd_);
        result = EAI_SYSTEM;
        return QUERY_END;
    }

    iovec iov[1] = {{&reqCmd, sizeof(reqCmd)}};

    msghdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.msg_iov = iov;
    hdr.msg_iovlen = 1;

    auto ret = sendmsg(socketFd_, &hdr, 0);
    if (ret < 0) {
        // common::logger::error() << "[dnsresolv_client] Unable to send request cmdid: " << reqCmd.cmdID
        //                         << " error: " << ret << strerror(errno) << endl;
        NETNATIVE_LOGE("[dnsresolv_client] Unable to send request cmdid: %{public}d, error : %{public}s  ",
            reqCmd.cmdID, strerror(errno));
        result = EAI_SYSTEM;
        return QUERY_END;
    }

    return QUERY_WAIT_REPONSE;
}

nmd::dnsresolv_query_state nmd::dnsresolv_client::recvResponese(int &result, dnsresolver_response_cmd &repcmdRes)
{
    if (socketFd_ < 0) {
        // common::logger::error() << "[dnsresolv_client] Unable to recv response. invalid socketFd_: " << socketFd_
        //                         << endl;
        NETNATIVE_LOGE(" [dnsresolv_client] Unable to recv response. invalid socketFd_: %{public}d ", socketFd_);
        result = EAI_SYSTEM;
        return QUERY_END;
    }

    const size_t buffSize = dnsresolver_response_cmd::cmd_id::QUERY_STATE_BUTT == repcmdRes.cmdID ?
        sizeof(dnsresolver_response_cmd) :
        (sizeof(dnsresolver_response_cmd) + repcmdRes.resSize);
    std::vector<uint8_t> buff(buffSize, 0);

    auto ret = recv(socketFd_, buff.data(), buffSize, 0);
    if (ret < 0) {
        // common::logger::error() << "[dnsresolv_client] Unable to recv response. "
        //                         << " error : " << ret << strerror(errno) << endl;
        NETNATIVE_LOGE("[dnsresolv_client] Unable to recv response. error : ret = %{public}d, %{public}s ", ret,
            strerror(errno));
        result = EAI_SYSTEM;
        return QUERY_END;
    }

    dnsresolver_response_cmd *repCmd = reinterpret_cast<dnsresolver_response_cmd *>(buff.data());

    if (nullptr == repCmd) {
        // common::logger::error() << "[dnsresolv_client] Unable to recv response. "
        //                         << "recv buffer is null." << endl;
        NETNATIVE_LOGE("[dnsresolv_client] Unable to recv response. recv buffer is null.");
        result = EAI_SYSTEM;
        return QUERY_END;
    }

    switch (repCmd->cmdID) {
        case dnsresolver_response_cmd::cmd_id::QUERY_STATE_FAIL: {
            result = repCmd->result;
            return QUERY_FAILED;
        } break;

        case dnsresolver_response_cmd::cmd_id::QUERY_STATE_OK: {
            result = repCmd->result;
            repcmdRes = *repCmd;
            return QUERY_OK;
        } break;

        case dnsresolver_response_cmd::cmd_id::QUERY_SUCCESS_WITH_RESULT: {
            result = repCmd->result;
            repcmdRes = *repCmd;
            memcpy(repcmdRes.resData, repCmd->resData, repCmd->resSize);
            return QUERY_RESULT;
        } break;
        default:
            // unreachable
            abort();
            break;
    }

    return QUERY_END;
}

nmd::dnsresolv_query_state nmd::dnsresolv_client::startQuery(
    const char *hostname, const char *servname, const struct addrinfo *hints, int &result)
{
    if ((hostname != nullptr && strcspn(hostname, " \n\r\t^'\"") != strlen(hostname)) ||
        (servname != nullptr && strcspn(servname, " \n\r\t^'\"") != strlen(servname))) {
        result = EAI_NODATA;
        return QUERY_END;
    }

    dnsresolver_request_cmd_t reqCmd;
    bzero(&reqCmd, sizeof(reqCmd));
    reqCmd.cmdID = dnsresolver_request_cmd::cmd_id::GET_ADDR_INFO;
    if (nullptr != hostname) {
        strncpy(reqCmd.cmd_hostName, hostname, MAX_NAME_LEN);
    }

    if (nullptr != servname) {
        strncpy(reqCmd.cmd_serverName, servname, MAX_NAME_LEN);
    }

    if (nullptr != hints) {
        reqCmd.cmd_hints = *hints;
    }

    return sendRequest(reqCmd, result);
}

nmd::dnsresolv_query_state nmd::dnsresolv_client::recvResult(
    int &result, const struct dnsresolver_response_cmd &repcmdState, p_dnsresolver_response_cmd &repcmdResult)
{
    if (dnsresolver_response_cmd::cmd_id::QUERY_STATE_OK != repcmdState.cmdID) {
        result = EAI_SYSTEM;
        return QUERY_END;
    }

    repcmdResult = reinterpret_cast<p_dnsresolver_response_cmd>(
        malloc(offsetof(dnsresolver_response_cmd, resData[repcmdState.resSize])));
    if (nullptr == repcmdResult) {
        result = EAI_SYSTEM;
        return QUERY_END;
    }
    *repcmdResult = repcmdState;

    for (size_t i = 0; i < repcmdResult->resSize; ++i) {
        repcmdResult->resData[i] = 0;
    }

    return recvResponese(result, *repcmdResult);
}

nmd::dnsresolv_query_state nmd::dnsresolv_client::parseResult(
    int &result, const p_dnsresolver_response_cmd repcmdResult, struct addrinfo **res)
{
    if (nullptr == repcmdResult) {
        result = EAI_SYSTEM;
        *res = nullptr;
        return QUERY_END;
    }

    *res = nullptr;
    struct addrinfo *ai(nullptr);
    struct addrinfo **nextres = res;
    size_t bufferCount(0);
    uint8_t *bufferCur = repcmdResult->resData;
    struct addrinfo *tmpAddrInfo(nullptr);
    result = repcmdResult->result;
    while (bufferCount < repcmdResult->resSize) {
        ai = reinterpret_cast<struct addrinfo *>(
            calloc(1, sizeof(struct addrinfo) + sizeof(struct sockaddr_storage)));
        if (ai == NULL) {
            result = EAI_SYSTEM;
            break;
        }

        tmpAddrInfo = reinterpret_cast<struct addrinfo *>(bufferCur);
        ai->ai_flags = tmpAddrInfo->ai_flags;
        ai->ai_family = tmpAddrInfo->ai_family;
        ai->ai_socktype = tmpAddrInfo->ai_socktype;
        ai->ai_protocol = tmpAddrInfo->ai_protocol;

        // set ai_addrlen and ai_addrinfo
        ai->ai_addr = reinterpret_cast<struct sockaddr *>(ai + 1);
        ai->ai_addrlen = tmpAddrInfo->ai_addrlen;
        if (ai->ai_addrlen > sizeof(struct sockaddr_storage)) {
            // unreachable in case of too big
            result = EAI_SYSTEM;
            break;
        }
        bufferCur += sizeof(addrinfo);
        bufferCount += sizeof(addrinfo);
        memcpy(ai->ai_addr, bufferCur, ai->ai_addrlen);

        // set ai_cannonname if need
        bufferCur += ai->ai_addrlen;
        bufferCount += ai->ai_addrlen;
        if (nullptr != tmpAddrInfo->ai_canonname) {
            size_t namelen = strlen(reinterpret_cast<char *>(bufferCur)) + 1;
            ai->ai_canonname = reinterpret_cast<char *>(malloc(namelen));
            memcpy(ai->ai_canonname, bufferCur, namelen);

            if (ai->ai_canonname[namelen - 1] != '\0') {
                result = EAI_SYSTEM;
                break;
            }
            bufferCur += namelen;
            bufferCount += namelen;
        }

        *nextres = ai;
        nextres = &ai->ai_next;
        ai = nullptr;
    };

    if (result != repcmdResult->result && nullptr != *res) {
        // something error, clean result
        freeaddrinfo(*res);
        *res = nullptr;
    }

    return QUERY_END;
}

int nmd::dnsresolv_client::createNetworkCache(const uint16_t netid)
{
    dnsresolver_request_cmd reqCmd;
    bzero(&reqCmd, sizeof(reqCmd));
    reqCmd.cmdID = dnsresolver_request_cmd::cmd_id::CREATE_NETWORK_CACHE;
    reqCmd.netid = netid;

    dnsresolver_response_cmd repCmd;
    auto ret = sendRequestWithResponse(reqCmd, repCmd);
    if (ret != 0) {
        return ret;
    }

    return repCmd.cmdID == dnsresolver_response_cmd::cmd_id::QUERY_STATE_OK ? 0 : -1;
}

int nmd::dnsresolv_client::destroyNetworkCache(const uint16_t netid)
{
    dnsresolver_request_cmd reqCmd;
    bzero(&reqCmd, sizeof(reqCmd));
    reqCmd.cmdID = dnsresolver_request_cmd::cmd_id::DESOTRY_NETWORK_CACHE;
    reqCmd.netid = netid;

    dnsresolver_response_cmd repCmd;
    auto ret = sendRequestWithResponse(reqCmd, repCmd);
    if (ret != 0) {
        return ret;
    }

    return repCmd.cmdID == dnsresolver_response_cmd::cmd_id::QUERY_STATE_OK ? 0 : -1;
}

int nmd::dnsresolv_client::setResolverConfig(const dnsresolver_params &param)
{
    dnsresolver_request_cmd reqCmd;
    bzero(&reqCmd, sizeof(reqCmd));
    reqCmd.cmdID = dnsresolver_request_cmd::cmd_id::SET_RESOLVER_CONFIG;
    reqCmd.netid = param.netId;
    reqCmd.cmd_baseTimeoutMsec = param.baseTimeoutMsec;
    reqCmd.cmd_retryCount = param.retryCount;
    reqCmd.cmd_serverCount = static_cast<uint8_t>(param.servers.size());
    reqCmd.cmd_domainCount = static_cast<uint8_t>(param.domains.size());
    setNameList(reqCmd.cmd_servers, MAX_NAME_LIST_LEN, param.servers);
    setNameList(reqCmd.cmd_domains, MAX_NAME_LIST_LEN, param.domains);

    dnsresolver_response_cmd repCmd;
    auto ret = sendRequestWithResponse(reqCmd, repCmd);
    if (ret != 0) {
        return ret;
    }

    return repCmd.cmdID == dnsresolver_response_cmd::cmd_id::QUERY_STATE_OK ? 0 : -1;
}

int nmd::dnsresolv_client::sendRequestWithResponse(
    const dnsresolver_request_cmd &reqcmd, dnsresolver_response_cmd &repcmd)
{
    int ret(0);
    sendRequest(const_cast<dnsresolver_request_cmd &>(reqcmd), ret);
    if (ret < 0) {
        return ret;
    }

    recvResponese(ret, repcmd);
    if (ret < 0) {
        return ret;
    }

    return ret;
}

void nmd::dnsresolv_client::setNameList(
    char *buffer, const size_t bufferSize, const std::vector<std::string> namelist)
{
    if (nullptr == buffer || 0 == bufferSize || namelist.empty()) {
        // common::logger::error() << "[dnsresolv_client] Unable to setNameList: invalid param. " << endl;
        NETNATIVE_LOGE("[dnsresolv_client] Unable to setNameList: invalid param. ");
        return;
    }

    char *buffCur = buffer;
    size_t buffCount(0);
    for (auto &name : namelist) {
        if (name.empty()) {
            continue;
        }

        if ((bufferSize - buffCount) < (name.length() + 1)) {
            // common::logger::warn() << "[dnsresolv_client] No  enough buffer to setNameList. " << endl;
            NETNATIVE_LOGD("[dnsresolv_client] No  enough buffer to setNameList.");
            break;
        }

        strcpy(buffCur, name.c_str());
        buffCur += (name.length() + 1);
        buffCount += (name.length() + 1);
    }
}
} // namespace OHOS