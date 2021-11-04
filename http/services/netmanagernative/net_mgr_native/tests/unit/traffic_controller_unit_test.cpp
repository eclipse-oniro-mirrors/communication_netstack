#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "traffic_controller.h"

TEST(traffic_controller_unit, getTetherClientInfo)
{
    auto tetherClientInfo = nmd::traffic_controller::getTetherClientInfo();
    for (auto iter = tetherClientInfo.begin(); iter != tetherClientInfo.end(); iter++) {
        std::cout << (*iter).ipAddr << std::endl;
    }
}