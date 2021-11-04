#include "error_code.h"
#include <iostream>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

// test error_code
TEST(error_code, error_code_is_1)
{
    std::error_code ec1 = nmd::common::error_code::errNoInfName;
    EXPECT_EQ(ec1.value(), 1);
    EXPECT_EQ(ec1.message(), "no such interface name");
}