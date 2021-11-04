#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "dnsresolv_service.h"
#include "socket_base.h"
#include "dnsresolv.h"
#include <memory>
namespace {
void setNameList(char *buffer, const size_t bufferSize, const std::vector<std::string> namelist)
{
    if (nullptr == buffer || 0 == bufferSize || namelist.empty()) {
        return;
    }

    char *buffCur = buffer;
    size_t buffCount(0);
    for (auto &name : namelist) {
        if (name.empty()) {
            continue;
        }

        if ((bufferSize - buffCount) < (name.length() + 1)) {
            break;
        }

        strcpy(buffCur, name.c_str());
        buffCur += (name.length() + 1);
        buffCount += (name.length() + 1);
    }
}
} // namespace

class mock_socket : public nmd::common::socket_base {
public:
    MOCK_METHOD2(sendMsg, ssize_t(const int socketFd, const msghdr &msg));
};

class dnsresolv_service_unit_test : public ::testing::Test {
public:
    virtual void SetUp() override {}
    virtual void TearDown() override {}

protected:
    const uint16_t TEST_NETID = 65501;
};

TEST_F(dnsresolv_service_unit_test, jobRunBadParam)
{
    mock_socket mockSocket;
    EXPECT_CALL(mockSocket, sendMsg(::testing::_, ::testing::_)).Times(0);

    auto job = std::make_shared<nmd::dnsresolv_job>(-1, nullptr, 0, nullptr);
    ASSERT_THAT(job, ::testing::Ne(nullptr));
    job->run();
}

TEST_F(dnsresolv_service_unit_test, doCreateNetworkCache)
{
    nmd::dnsresolver_response_cmd cmdRep;
    bzero(&cmdRep, sizeof(cmdRep));
    cmdRep.cmdID = nmd::dnsresolver_response_cmd::cmd_id::QUERY_STATE_OK;
    size_t repSize = cmdRep.cmdID == nmd::dnsresolver_response_cmd::cmd_id::QUERY_SUCCESS_WITH_RESULT ?
        (sizeof(cmdRep) + cmdRep.resSize) :
        sizeof(cmdRep);
    iovec iov[1] = {{&cmdRep, repSize}};

    msghdr hdr;
    bzero(&hdr, sizeof(hdr));
    hdr.msg_iov = iov;
    hdr.msg_iovlen = 1;
    mock_socket *mockSocket = new mock_socket();
    ASSERT_THAT(mockSocket, ::testing::Ne(nullptr));
    EXPECT_CALL(*mockSocket, sendMsg(1, ::testing::_)).Times(2);

    nmd::dnsresolver_request_cmd reqCmd;
    bzero(&reqCmd, sizeof(reqCmd));
    reqCmd.cmdID = nmd::dnsresolver_request_cmd::cmd_id::CREATE_NETWORK_CACHE;
    reqCmd.netid = TEST_NETID;

    auto job = std::make_shared<nmd::dnsresolv_job>(1, reinterpret_cast<uint8_t *>(&reqCmd), sizeof(reqCmd),
        std::shared_ptr<nmd::common::socket_base>(mockSocket));
    ASSERT_THAT(job, ::testing::Ne(nullptr));
    job->run();
    job->run();
}

TEST_F(dnsresolv_service_unit_test, doDestroyNetworkCache)
{
    nmd::dnsresolver_response_cmd cmdRep;
    bzero(&cmdRep, sizeof(cmdRep));
    cmdRep.cmdID = nmd::dnsresolver_response_cmd::cmd_id::QUERY_STATE_OK;
    size_t repSize = cmdRep.cmdID == nmd::dnsresolver_response_cmd::cmd_id::QUERY_SUCCESS_WITH_RESULT ?
        (sizeof(cmdRep) + cmdRep.resSize) :
        sizeof(cmdRep);
    iovec iov[1] = {{&cmdRep, repSize}};

    msghdr hdr;
    bzero(&hdr, sizeof(hdr));
    hdr.msg_iov = iov;
    hdr.msg_iovlen = 1;
    mock_socket *mockSocket = new mock_socket();
    ASSERT_THAT(mockSocket, ::testing::Ne(nullptr));
    EXPECT_CALL(*mockSocket, sendMsg(1, ::testing::_)).Times(1);

    nmd::dnsresolver_request_cmd reqCmd;
    bzero(&reqCmd, sizeof(reqCmd));
    reqCmd.cmdID = nmd::dnsresolver_request_cmd::cmd_id::DESOTRY_NETWORK_CACHE;
    reqCmd.netid = TEST_NETID;

    auto job = std::make_shared<nmd::dnsresolv_job>(1, reinterpret_cast<uint8_t *>(&reqCmd), sizeof(reqCmd),
        std::shared_ptr<nmd::common::socket_base>(mockSocket));
    ASSERT_THAT(job, ::testing::Ne(nullptr));
    job->run();
}

TEST_F(dnsresolv_service_unit_test, doSetResolverConfig)
{
    nmd::dnsresolver_response_cmd cmdRep;
    bzero(&cmdRep, sizeof(cmdRep));
    cmdRep.cmdID = nmd::dnsresolver_response_cmd::cmd_id::QUERY_STATE_OK;
    size_t repSize = cmdRep.cmdID == nmd::dnsresolver_response_cmd::cmd_id::QUERY_SUCCESS_WITH_RESULT ?
        (sizeof(cmdRep) + cmdRep.resSize) :
        sizeof(cmdRep);
    iovec iov[1] = {{&cmdRep, repSize}};

    msghdr hdr;
    bzero(&hdr, sizeof(hdr));
    hdr.msg_iov = iov;
    hdr.msg_iovlen = 1;
    mock_socket *mockSocket = new mock_socket();
    ASSERT_THAT(mockSocket, ::testing::Ne(nullptr));
    EXPECT_CALL(*mockSocket, sendMsg(1, ::testing::_)).Times(1);
    const nmd::dnsresolver_params param = {
        TEST_NETID, 0, 1, {"8.8.8.8", "114.114.114.114"}, {"baidu.com", "google.com"}};

    nmd::dnsresolver_request_cmd reqCmd;
    bzero(&reqCmd, sizeof(reqCmd));
    reqCmd.cmdID = nmd::dnsresolver_request_cmd::cmd_id::SET_RESOLVER_CONFIG;
    reqCmd.netid = param.netId;
    reqCmd.cmd_baseTimeoutMsec = param.baseTimeoutMsec;
    reqCmd.cmd_retryCount = param.retryCount;
    reqCmd.cmd_serverCount = static_cast<uint8_t>(param.servers.size());
    reqCmd.cmd_domainCount = static_cast<uint8_t>(param.domains.size());
    setNameList(reqCmd.cmd_servers, nmd::MAX_NAME_LIST_LEN, param.servers);
    setNameList(reqCmd.cmd_domains, nmd::MAX_NAME_LIST_LEN, param.domains);

    auto job = std::make_shared<nmd::dnsresolv_job>(1, reinterpret_cast<uint8_t *>(&reqCmd), sizeof(reqCmd),
        std::shared_ptr<nmd::common::socket_base>(mockSocket));
    ASSERT_THAT(job, ::testing::Ne(nullptr));
    job->run();
}

TEST_F(dnsresolv_service_unit_test, doGetAddrInfo)
{
    mock_socket *mockSocket = new mock_socket();
    ASSERT_THAT(mockSocket, ::testing::Ne(nullptr));
    EXPECT_CALL(*mockSocket, sendMsg(1, ::testing::_)).Times(1);

    nmd::dnsresolver_request_cmd reqCmd;
    bzero(&reqCmd, sizeof(reqCmd));
    reqCmd.cmdID = nmd::dnsresolver_request_cmd::cmd_id::CREATE_NETWORK_CACHE;
    reqCmd.netid = nmd::NETID_UNSET;
    auto job = std::make_shared<nmd::dnsresolv_job>(1, reinterpret_cast<uint8_t *>(&reqCmd), sizeof(reqCmd),
        std::shared_ptr<nmd::common::socket_base>(mockSocket));
    ASSERT_THAT(job, ::testing::Ne(nullptr));
    job->run();

    mock_socket *mockSocket1 = new mock_socket();
    ASSERT_THAT(mockSocket1, ::testing::Ne(nullptr));
    EXPECT_CALL(*mockSocket1, sendMsg(1, ::testing::_)).Times(1);
    const nmd::dnsresolver_params param = {
        nmd::NETID_UNSET, 0, 1, {"8.8.8.8", "114.114.114.114"}, {"baidu.com", "google.com"}};

    nmd::dnsresolver_request_cmd reqCmd1;
    bzero(&reqCmd1, sizeof(reqCmd1));
    reqCmd1.cmdID = nmd::dnsresolver_request_cmd::cmd_id::SET_RESOLVER_CONFIG;
    reqCmd1.netid = param.netId;
    reqCmd1.cmd_baseTimeoutMsec = param.baseTimeoutMsec;
    reqCmd1.cmd_retryCount = param.retryCount;
    reqCmd1.cmd_serverCount = static_cast<uint8_t>(param.servers.size());
    reqCmd1.cmd_domainCount = static_cast<uint8_t>(param.domains.size());
    setNameList(reqCmd1.cmd_servers, nmd::MAX_NAME_LIST_LEN, param.servers);
    setNameList(reqCmd1.cmd_domains, nmd::MAX_NAME_LIST_LEN, param.domains);

    auto job1 = std::make_shared<nmd::dnsresolv_job>(1, reinterpret_cast<uint8_t *>(&reqCmd1), sizeof(reqCmd1),
        std::shared_ptr<nmd::common::socket_base>(mockSocket1));
    ASSERT_THAT(job1, ::testing::Ne(nullptr));
    job1->run();

    mock_socket *mockSocket2 = new mock_socket();
    ASSERT_THAT(mockSocket2, ::testing::Ne(nullptr));
    EXPECT_CALL(*mockSocket2, sendMsg(1, ::testing::_)).Times(2);
    struct addrinfo hints;
    bzero(&hints, sizeof(addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;
    hints.ai_protocol = 0;
    nmd::dnsresolver_request_cmd_t reqCmd2;
    bzero(&reqCmd2, sizeof(reqCmd2));
    reqCmd2.cmdID = nmd::dnsresolver_request_cmd::cmd_id::GET_ADDR_INFO;
    strncpy(reqCmd2.cmd_hostName, "www.baidu.com", nmd::MAX_NAME_LEN);
    reqCmd2.cmd_hints = hints;

    auto job2 = std::make_shared<nmd::dnsresolv_job>(1, reinterpret_cast<uint8_t *>(&reqCmd2), sizeof(reqCmd2),
        std::shared_ptr<nmd::common::socket_base>(mockSocket2));
    ASSERT_THAT(job2, ::testing::Ne(nullptr));
    job2->run();
}

TEST_F(dnsresolv_service_unit_test, doGetAddrInfoFromCache)
{
    mock_socket *mockSocket = new mock_socket();
    ASSERT_THAT(mockSocket, ::testing::Ne(nullptr));
    EXPECT_CALL(*mockSocket, sendMsg(1, ::testing::_)).Times(2);
    struct addrinfo hints;
    bzero(&hints, sizeof(addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;
    hints.ai_protocol = 0;
    nmd::dnsresolver_request_cmd_t reqCmd;
    bzero(&reqCmd, sizeof(reqCmd));
    reqCmd.cmdID = nmd::dnsresolver_request_cmd::cmd_id::GET_ADDR_INFO;
    strncpy(reqCmd.cmd_hostName, "www.baidu.com", nmd::MAX_NAME_LEN);
    reqCmd.cmd_hints = hints;

    auto job = std::make_shared<nmd::dnsresolv_job>(1, reinterpret_cast<uint8_t *>(&reqCmd), sizeof(reqCmd),
        std::shared_ptr<nmd::common::socket_base>(mockSocket));
    ASSERT_THAT(job, ::testing::Ne(nullptr));
    job->run();
}

TEST_F(dnsresolv_service_unit_test, doGetAddrInfoFailed)
{
    mock_socket *mockSocket = new mock_socket();
    ASSERT_THAT(mockSocket, ::testing::Ne(nullptr));
    EXPECT_CALL(*mockSocket, sendMsg(1, ::testing::_)).Times(1);
    struct addrinfo hints;
    bzero(&hints, sizeof(addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;
    hints.ai_protocol = 0;
    nmd::dnsresolver_request_cmd_t reqCmd;
    bzero(&reqCmd, sizeof(reqCmd));
    reqCmd.cmdID = nmd::dnsresolver_request_cmd::cmd_id::GET_ADDR_INFO;
    strncpy(reqCmd.cmd_hostName, "unknow", nmd::MAX_NAME_LEN);
    reqCmd.cmd_hints = hints;

    auto job = std::make_shared<nmd::dnsresolv_job>(1, reinterpret_cast<uint8_t *>(&reqCmd), sizeof(reqCmd),
        std::shared_ptr<nmd::common::socket_base>(mockSocket));
    ASSERT_THAT(job, ::testing::Ne(nullptr));
    job->run();
}

TEST_F(dnsresolv_service_unit_test, init)
{
    nmd::dnsresolv_service dnsService;
    nmd::dnsresolv_callbacks callbacks;
    auto ret = dnsService.init(callbacks);
    EXPECT_THAT(ret, ::testing::Eq(false));

    auto callbackFunc = [](uint16_t netid, uid_t uid, nmd::netd_net_context &netcontext) {
        if (nmd::NETID_UNSET == netid || nmd::NET_CONTEXT_INVALID_UID == uid) {
            netcontext.appNetId = netid;
        }
    };
    callbacks.getNetworkContext = callbackFunc;
    ret = dnsService.init(callbacks);
    EXPECT_THAT(ret, ::testing::Eq(true));
}