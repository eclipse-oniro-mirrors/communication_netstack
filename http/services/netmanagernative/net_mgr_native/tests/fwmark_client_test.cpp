#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <fwmark_client.h>

TEST(fwmark_client, bindSocket)
{
    nmd::fwmark_client client;
    nmd::fwmark_command command;
    command.cmdId = nmd::fwmark_command::SELECT_NETWORK;
    command.fd = 1;
    command.netId = 12;
    client.send(&command);
}
