#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <sys/types.h>
#include <dirent.h>
#include "traffic_init.h"
#include "utils.h"

class traffic_init_unit_test : public ::testing::Test {
public:
    static void recursion_mkdir(const char *dir)
    {
        nmd::traffic_init::recursion_mkdir(dir);
    }

    static void create_cgroup()
    {
        nmd::traffic_init::create_cgroup();
    }

    static void write_all_pid_to_cgroup()
    {
        nmd::traffic_init::write_all_pid_to_cgroup();
    }

    static int create_unix_socket()
    {
        return nmd::traffic_init::create_unix_socket();
    }

private:
};

TEST_F(traffic_init_unit_test, recursionMkdir)
{
    const char *dir = "/root/test/test/";
    traffic_init_unit_test::recursion_mkdir(dir);
    DIR *d = opendir(dir);
    EXPECT_TRUE(d != NULL);
    nmd::common::utils::removeDirectory("/root/test/");
    closedir(d);
}

TEST_F(traffic_init_unit_test, writeAllPidToCgroup)
{
    char cmd[1024] = {0};
    char buf_ps[100];
    FILE *ptr;

    traffic_init_unit_test::create_cgroup();
    traffic_init_unit_test::write_all_pid_to_cgroup();
    strcpy(cmd, "cat /sys/fs/cgroup/unified/cgroup-traffic-uid/cgroup.procs | wc -l");
    if ((ptr = popen(cmd, "r")) != NULL) {
        while (fgets(buf_ps, 100, ptr) != NULL) {
            EXPECT_NE(std::string(buf_ps), std::string("0\n"));
        }
    }
}

TEST_F(traffic_init_unit_test, createUnixSocket)
{
    remove("/dev/socket/traffic");
    nmd::traffic_init::traffic_init_log();
    int ret = traffic_init_unit_test::create_unix_socket();
    EXPECT_EQ(0, ret);
}
