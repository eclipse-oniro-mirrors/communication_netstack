#include <bitcast.h>
#include <gtest/gtest.h>

TEST(bit_cast, can_cast_different_type)
{
    constexpr double f64v = 19880124.0;
    auto u64v = nmd::common::bit_cast<std::uint64_t>(f64v);
    std::stringstream ss;
    ss << std::hex << u64v;
    EXPECT_EQ(ss.str(), "4172f58bc0000000");
}
