#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <sock_diag.h>

TEST(sock_diag, destroySocket)
{
    nmd::sock_diag diag;
    diag.open();
    diag.destroySockets("eth0");
}

TEST(sock_diag, isINETLoopbackWhenIs)
{
    nmd::sock_diag diag;
    inet_diag_msg msg;
    msg.idiag_family = AF_INET;
    diag.isLoopbackSocket(&msg);
}

TEST(sock_diag, isINETNotLoopbackWhenNot)
{
    nmd::sock_diag diag;
    inet_diag_msg msg;
    msg.idiag_family = AF_INET;
    diag.isLoopbackSocket(&msg);
}

TEST(sock_diag, isINET6LoopbackWhenIs)
{
    nmd::sock_diag diag;
    inet_diag_msg msg;
    msg.idiag_family = AF_INET6;
    diag.isLoopbackSocket(&msg);
}

TEST(sock_diag, isINET6NotLoopbackWhenNot)
{
    nmd::sock_diag diag;
    inet_diag_msg msg;
    msg.idiag_family = AF_INET6;
    diag.isLoopbackSocket(&msg);
}