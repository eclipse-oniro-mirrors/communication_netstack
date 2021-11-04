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
#include "blocking_queue.h"

TEST(blocking_queue, shoudEnqueue)
{
    nmd::blocking_queue<int> queue(30);
    EXPECT_TRUE(queue.isEmpty());
    queue.push(1);
    EXPECT_EQ(queue.pop(), 1);
    for (int i = 0; i < 30; i++) {
        queue.push(i);
    }
    EXPECT_TRUE(queue.isFull());
}
