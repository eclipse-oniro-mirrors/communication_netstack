#include "traffic_controller.h"
#include "native_netd_service.h"
#include "traffic_init.h"
#include <iostream>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <sys/prctl.h>

TEST(traffic, getInterfaceRxTrafficTest)
{
    nmd::native_nted_service testNetdService;
    std::string ifName("eth0");
    long trafficBytes1 = testNetdService.getIfaceRxBytes(ifName);
    nmd::traffic_stats_parcel result = testNetdService.interfaceGetStats(ifName);
    long trafficBytes2 = result.rxBytes;
    std::cout << trafficBytes2 << std::endl;
    ASSERT_LE(trafficBytes1, trafficBytes2);
}

TEST(traffic, getInterfaceTxTrafficTest)
{
    nmd::native_nted_service testNetdService;
    std::string ifName("eth0");
    long trafficBytes1 = testNetdService.getIfaceTxBytes(ifName);
    nmd::traffic_stats_parcel result = testNetdService.interfaceGetStats(ifName);
    long trafficBytes2 = result.txBytes;
    std::cout << trafficBytes2 << std::endl;
    ASSERT_LE(trafficBytes1, trafficBytes2);
}

TEST(traffic, getCellularRxTraffic)
{
    nmd::native_nted_service testNetdService;
    long trafficBytes = testNetdService.getCellularRxBytes();
    std::cout << trafficBytes << std::endl;
}

TEST(traffic, getCellularTxTraffic)
{
    nmd::native_nted_service testNetdService;
    long trafficBytes = testNetdService.getCellularTxBytes();
    std::cout << trafficBytes << std::endl;
}

TEST(traffic, getAllRxTraffic)
{
    nmd::native_nted_service testNetdService;
    long trafficBytes = testNetdService.getAllRxBytes();
    std::cout << trafficBytes << std::endl;
}

TEST(traffic, getAllTxTraffic)
{
    nmd::native_nted_service testNetdService;
    long trafficBytes = testNetdService.getAllTxBytes();
    std::cout << trafficBytes << std::endl;
}

TEST(traffic, getUid0RxBytes)
{
    nmd::native_nted_service testNetdService;
    nmd::traffic_init::start_traffic_account();
    sleep(2);
    long trafficUidRxBytes = testNetdService.getUidRxBytes(0);
    std::cout << trafficUidRxBytes << std::endl;
}

TEST(traffic, getUid0TxBytes)
{
    nmd::native_nted_service testNetdService;
    nmd::traffic_init::start_traffic_account();
    sleep(2);
    long trafficUidRxBytes = testNetdService.getUidTxBytes(0);
    std::cout << trafficUidRxBytes << std::endl;
}

TEST(traffic, getTetherTxTraffic)
{
    nmd::native_nted_service nativeNetdService;
    std::string cmd = "iptables -t filter -N TETHER_TRAFFIC";
    nmd::traffic_controller::execIptablesRuleMethod(cmd);
    nmd::traffic_controller::startTrafficTether();
    nmd::traffic_controller::traffic_controller_log();
    long resultTx = nativeNetdService.getTetherTxBytes();
    std::cout << resultTx << std::endl;
}

TEST(traffic, getTetherRxTraffic)
{
    nmd::native_nted_service nativeNetdService;
    std::string cmd = "iptables -t filter -N TETHER_TRAFFIC";
    nmd::traffic_controller::execIptablesRuleMethod(cmd);
    nmd::traffic_controller::startTrafficTether();
    nmd::traffic_controller::traffic_controller_log();
    long resultRx = nativeNetdService.getTetherRxBytes();
    std::cout << resultRx << std::endl;
}

TEST(traffic_init, initTrafficAccoutEnv)
{
    constexpr const char *ingressBpfProg = "/sys/fs/bpf/cgroup-ingress-traffic-uid";
    constexpr const char *egressBpfProg = "/sys/fs/bpf/cgroup-egress-traffic-uid";
    constexpr const char *unixSocketTraffic = "/dev/socket/traffic";
    constexpr const char *trafficCgroupPath = "/sys/fs/cgroup/unified/cgroup-traffic-uid/cgroup.procs";

    nmd::traffic_init::init_traffic_env();

    int ingressBpfFile = access(ingressBpfProg, F_OK);
    int egressBpfFile = access(egressBpfProg, F_OK);
    int unixSocketFile = access(unixSocketTraffic, F_OK);
    int cgroupPidFile = access(trafficCgroupPath, F_OK);
    EXPECT_EQ(ingressBpfFile, -1);
    EXPECT_EQ(egressBpfFile, -1);
    EXPECT_EQ(unixSocketFile, 0);
    EXPECT_EQ(cgroupPidFile, 0);
}

TEST(traffic_init, loadTrafficBpf)
{
    nmd::traffic_init::load_traffic_bpf();
    char cmd[1024] = {0};
    char buf_ps[1024];
    FILE *ptr;
    strcpy(cmd, "ps -ef | grep load-traffic-bpf | grep -v \"grep\" | wc -l");
    sleep(2);
    if ((ptr = popen(cmd, "r")) != NULL) {
        while (fgets(buf_ps, 1024, ptr) != NULL) {
            EXPECT_NE(std::string(buf_ps), std::string("0\n"));
        }
    }
}

TEST(traffic_init, loadExecveBpf)
{
    nmd::traffic_init::load_execve_bpf();
    char cmd[1024] = {0};
    char buf_ps[1024];
    FILE *ptr;
    strcpy(cmd, "ps -ef | grep load-execve-bpf | grep -v \"grep\" | wc -l");
    sleep(2);
    if ((ptr = popen(cmd, "r")) != NULL) {
        while (fgets(buf_ps, 1024, ptr) != NULL) {
            EXPECT_NE(std::string(buf_ps), std::string("0\n"));
        }
    }
}