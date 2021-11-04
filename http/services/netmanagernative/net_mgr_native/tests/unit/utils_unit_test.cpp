#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <logger.h>
#include <net/if.h>
#include <thread>
#include <utils.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>

TEST(utils, shouldGetCurrentTime)
{
    nmd::common::utils::getCurrentTime();
}

TEST(utils, shouldRemoveDirectory)
{
    mkdir("test_dir", 777);
    mkdir("test_dir/test_dir", 777);

    nmd::common::utils::removeDirectory("test_dir");

    DIR *d = opendir("test_dir");

    EXPECT_TRUE(d == NULL);
}
