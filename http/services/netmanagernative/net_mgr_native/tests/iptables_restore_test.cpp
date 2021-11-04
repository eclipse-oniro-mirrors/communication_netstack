#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <iostream>
#include <iptables_process.h>
#include <memory>

TEST(iptables_restore, IpTablesRestoreProcessForkAndExecute)
{
    std::shared_ptr<nmd::iptables_process> process = nmd::iptables_process::forkAndExecute();

    std::string result;
    EXPECT_TRUE(process->waitForAck(result));
}