#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <logger.h>
#include <net/if.h>
#include <thread>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <warning_disable.h>
#include <netlink_handler.h>

DISABLE_WARNING_PUSH
DISABLE_WARNING_SIGN_CONVERSION
DISABLE_WARNING_IMPLICIT_INT_CONVERSION
DISABLE_WARNING_SHORTEN_64_TO_32
DISABLE_WARNING_SIGN_CONVERSION
DISABLE_WARNING_SIGN_COMPARE
DISABLE_WARNING_OLD_STYLE_CAST
DISABLE_WARNING_CAST_ALIGN
DISABLE_WARNING_SIGN_CONVERSION
DISABLE_WARNING_C99_EXTENSIONS

namespace event_handler_test {
static int defaultOnInterfaceAddressUpdatedInvokeCount = 0;
static int defaultOnInterfaceAddressRemovedInvokeCount = 0;
static int defaultOnInterfaceAddedInvokeCount = 0;
static int defaultOnInterfaceRemovedInvokeCount = 0;
static int defaultOnInterfaceChangedInvokeCount = 0;
static int defaultOnInterfaceLinkStateChangedInvokeCount = 0;
static int defaultOnRouteChangedInvokeCount = 0;

void defaultOnInterfaceAddressUpdated(const std::string &addr, const std::string &ifName, int flags, int scope)
{
    defaultOnInterfaceAddressUpdatedInvokeCount = 1;
    std::cout << "InterfaceAddressUpdate:" << addr << "," << ifName << "," << flags << "," << scope << std::endl;
}
void defaultOnInterfaceAddressRemoved(const std::string &addr, const std::string &ifName, int flags, int scope)
{
    defaultOnInterfaceAddressRemovedInvokeCount = 1;
    std::cout << "InterfaceAddressRemoved:" << addr << "," << ifName << "," << flags << "," << scope << std::endl;
}
void defaultOnInterfaceAdded(const std::string &ifName)
{
    defaultOnInterfaceAddedInvokeCount = 1;
    std::cout << "InterfaceAdded:" << ifName << std::endl;
}
void defaultOnInterfaceRemoved(const std::string &ifName)
{
    defaultOnInterfaceRemovedInvokeCount = 1;
    std::cout << "InterfaceRemoved:" << ifName << std::endl;
}
void defaultOnInterfaceChanged(const std::string &ifName, bool up)
{
    defaultOnInterfaceChangedInvokeCount = 1;
    std::cout << "InterfaceChanged:" << ifName << "," << up << std::endl;
}
void defaultOnInterfaceLinkStateChanged(const std::string &ifName, bool up)
{
    defaultOnInterfaceLinkStateChangedInvokeCount = 1;
    std::cout << "InterfaceLinkStateChanged:" << ifName << "," << up << std::endl;
}
void defaultOnRouteChanged(
    bool updated, const std::string &route, const std::string &gateway, const std::string &ifName)
{
    defaultOnRouteChangedInvokeCount = 1;
    std::cout << "RouteChanged:" << updated << "," << route << "," << gateway << "," << ifName << std::endl;
}

void initTest()
{
    defaultOnInterfaceAddressUpdatedInvokeCount = 0;
    defaultOnInterfaceAddressRemovedInvokeCount = 0;
    defaultOnInterfaceAddedInvokeCount = 0;
    defaultOnInterfaceRemovedInvokeCount = 0;
    defaultOnInterfaceChangedInvokeCount = 0;
    defaultOnInterfaceLinkStateChangedInvokeCount = 0;
    defaultOnRouteChangedInvokeCount = 0;
}
} // namespace event_handler_test

TEST(netlink_handler, onUnknown)
{
    nmd::event_reporter report;

    nmd::inetd_unsolicited_event_listener glistener {
        .onInterfaceAddressUpdated = event_handler_test::defaultOnInterfaceAddressUpdated,
        .onInterfaceAddressRemoved = event_handler_test::defaultOnInterfaceAddressRemoved,
        .onInterfaceAdded = event_handler_test::defaultOnInterfaceAdded,
        .onInterfaceRemoved = event_handler_test::defaultOnInterfaceRemoved,
        .onInterfaceChanged = event_handler_test::defaultOnInterfaceChanged,
        .onInterfaceLinkStateChanged = event_handler_test::defaultOnInterfaceLinkStateChanged,
        .onRouteChanged = event_handler_test::defaultOnRouteChanged,
    };

    report.registerEventListener(glistener);

    nmd::netlink_handler handler(NETLINK_ROUTE, getpid());
    handler.setEventListener(std::make_shared<nmd::event_reporter>(report));

    std::shared_ptr<nmd::netlink_event> ev = std::make_shared<nmd::netlink_event>();
    ev->setAction(nmd::Action::Unknown);
    handler.onEvent(ev);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceAddressUpdatedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceAddressRemovedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceAddedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceRemovedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceChangedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceLinkStateChangedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnRouteChangedInvokeCount, 0);
}

TEST(netlink_handler, onAdd)
{
    nmd::event_reporter report;

    nmd::inetd_unsolicited_event_listener glistener {
        .onInterfaceAddressUpdated = event_handler_test::defaultOnInterfaceAddressUpdated,
        .onInterfaceAddressRemoved = event_handler_test::defaultOnInterfaceAddressRemoved,
        .onInterfaceAdded = event_handler_test::defaultOnInterfaceAdded,
        .onInterfaceRemoved = event_handler_test::defaultOnInterfaceRemoved,
        .onInterfaceChanged = event_handler_test::defaultOnInterfaceChanged,
        .onInterfaceLinkStateChanged = event_handler_test::defaultOnInterfaceLinkStateChanged,
        .onRouteChanged = event_handler_test::defaultOnRouteChanged,
    };

    report.registerEventListener(glistener);
    nmd::netlink_handler handler(NETLINK_ROUTE, getpid());
    handler.setEventListener(std::make_shared<nmd::event_reporter>(report));

    event_handler_test::initTest();
    std::shared_ptr<nmd::netlink_event> ev = std::make_shared<nmd::netlink_event>();
    ev->setAction(nmd::Action::Add);
    ev->addParam("INTERFACE", "test_INTERFACE");
    handler.onEvent(ev);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceAddressUpdatedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceAddressRemovedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceAddedInvokeCount, 1);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceRemovedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceChangedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceLinkStateChangedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnRouteChangedInvokeCount, 0);
}

TEST(netlink_handler, onLinkUp)
{
    nmd::event_reporter report;

    nmd::inetd_unsolicited_event_listener glistener {
        .onInterfaceAddressUpdated = event_handler_test::defaultOnInterfaceAddressUpdated,
        .onInterfaceAddressRemoved = event_handler_test::defaultOnInterfaceAddressRemoved,
        .onInterfaceAdded = event_handler_test::defaultOnInterfaceAdded,
        .onInterfaceRemoved = event_handler_test::defaultOnInterfaceRemoved,
        .onInterfaceChanged = event_handler_test::defaultOnInterfaceChanged,
        .onInterfaceLinkStateChanged = event_handler_test::defaultOnInterfaceLinkStateChanged,
        .onRouteChanged = event_handler_test::defaultOnRouteChanged,
    };

    report.registerEventListener(glistener);

    nmd::netlink_handler handler(NETLINK_ROUTE, getpid());
    handler.setEventListener(std::make_shared<nmd::event_reporter>(report));

    event_handler_test::initTest();
    std::shared_ptr<nmd::netlink_event> ev = std::make_shared<nmd::netlink_event>();
    ev->addParam("INTERFACE", "test_INTERFACE");
    ev->setAction(nmd::Action::LinkUp);
    handler.onEvent(ev);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceAddressUpdatedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceAddressRemovedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceAddedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceRemovedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceChangedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceLinkStateChangedInvokeCount, 1);
    EXPECT_EQ(event_handler_test::defaultOnRouteChangedInvokeCount, 0);
}

TEST(netlink_handler, onLinkDown)
{
    nmd::event_reporter report;

    nmd::inetd_unsolicited_event_listener glistener {
        .onInterfaceAddressUpdated = event_handler_test::defaultOnInterfaceAddressUpdated,
        .onInterfaceAddressRemoved = event_handler_test::defaultOnInterfaceAddressRemoved,
        .onInterfaceAdded = event_handler_test::defaultOnInterfaceAdded,
        .onInterfaceRemoved = event_handler_test::defaultOnInterfaceRemoved,
        .onInterfaceChanged = event_handler_test::defaultOnInterfaceChanged,
        .onInterfaceLinkStateChanged = event_handler_test::defaultOnInterfaceLinkStateChanged,
        .onRouteChanged = event_handler_test::defaultOnRouteChanged,
    };

    report.registerEventListener(glistener);

    nmd::netlink_handler handler(NETLINK_ROUTE, getpid());
    handler.setEventListener(std::make_shared<nmd::event_reporter>(report));

    event_handler_test::initTest();
    std::shared_ptr<nmd::netlink_event> ev = std::make_shared<nmd::netlink_event>();
    ev->addParam("INTERFACE", "test_INTERFACE");
    ev->setAction(nmd::Action::LinkDown);
    handler.onEvent(ev);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceAddressUpdatedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceAddressRemovedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceAddedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceRemovedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceChangedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceLinkStateChangedInvokeCount, 1);
    EXPECT_EQ(event_handler_test::defaultOnRouteChangedInvokeCount, 0);
}

TEST(netlink_handler, onChange)
{
    nmd::event_reporter report;

    nmd::inetd_unsolicited_event_listener glistener {
        .onInterfaceAddressUpdated = event_handler_test::defaultOnInterfaceAddressUpdated,
        .onInterfaceAddressRemoved = event_handler_test::defaultOnInterfaceAddressRemoved,
        .onInterfaceAdded = event_handler_test::defaultOnInterfaceAdded,
        .onInterfaceRemoved = event_handler_test::defaultOnInterfaceRemoved,
        .onInterfaceChanged = event_handler_test::defaultOnInterfaceChanged,
        .onInterfaceLinkStateChanged = event_handler_test::defaultOnInterfaceLinkStateChanged,
        .onRouteChanged = event_handler_test::defaultOnRouteChanged,
    };

    report.registerEventListener(glistener);

    nmd::netlink_handler handler(NETLINK_ROUTE, getpid());
    handler.setEventListener(std::make_shared<nmd::event_reporter>(report));

    event_handler_test::initTest();
    std::shared_ptr<nmd::netlink_event> ev = std::make_shared<nmd::netlink_event>();
    ev->addParam("INTERFACE", "test_INTERFACE");
    ev->setAction(nmd::Action::Change);
    handler.onEvent(ev);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceAddressUpdatedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceAddressRemovedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceAddedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceRemovedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceChangedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceLinkStateChangedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnRouteChangedInvokeCount, 0);
}

TEST(netlink_handler, onRemove)
{
    nmd::event_reporter report;

    nmd::inetd_unsolicited_event_listener glistener {
        .onInterfaceAddressUpdated = event_handler_test::defaultOnInterfaceAddressUpdated,
        .onInterfaceAddressRemoved = event_handler_test::defaultOnInterfaceAddressRemoved,
        .onInterfaceAdded = event_handler_test::defaultOnInterfaceAdded,
        .onInterfaceRemoved = event_handler_test::defaultOnInterfaceRemoved,
        .onInterfaceChanged = event_handler_test::defaultOnInterfaceChanged,
        .onInterfaceLinkStateChanged = event_handler_test::defaultOnInterfaceLinkStateChanged,
        .onRouteChanged = event_handler_test::defaultOnRouteChanged,
    };

    report.registerEventListener(glistener);

    nmd::netlink_handler handler(NETLINK_ROUTE, getpid());
    handler.setEventListener(std::make_shared<nmd::event_reporter>(report));

    event_handler_test::initTest();
    std::shared_ptr<nmd::netlink_event> ev = std::make_shared<nmd::netlink_event>();
    ev->addParam("INTERFACE", "test_INTERFACE");
    ev->setAction(nmd::Action::Remove);
    handler.onEvent(ev);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceAddressUpdatedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceAddressRemovedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceAddedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceRemovedInvokeCount, 1);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceChangedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceLinkStateChangedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnRouteChangedInvokeCount, 0);
}

TEST(netlink_handler, onRouteRemoved)
{
    nmd::event_reporter report;

    nmd::inetd_unsolicited_event_listener glistener {
        .onInterfaceAddressUpdated = event_handler_test::defaultOnInterfaceAddressUpdated,
        .onInterfaceAddressRemoved = event_handler_test::defaultOnInterfaceAddressRemoved,
        .onInterfaceAdded = event_handler_test::defaultOnInterfaceAdded,
        .onInterfaceRemoved = event_handler_test::defaultOnInterfaceRemoved,
        .onInterfaceChanged = event_handler_test::defaultOnInterfaceChanged,
        .onInterfaceLinkStateChanged = event_handler_test::defaultOnInterfaceLinkStateChanged,
        .onRouteChanged = event_handler_test::defaultOnRouteChanged,
    };

    report.registerEventListener(glistener);

    event_handler_test::initTest();
    nmd::netlink_handler handler(NETLINK_ROUTE, getpid());
    handler.setEventListener(std::make_shared<nmd::event_reporter>(report));
    std::shared_ptr<nmd::netlink_event> ev = std::make_shared<nmd::netlink_event>();

    ev->addParam("ROUTE", "test_ROUTE");
    ev->addParam("GATEWAY", "test_GATEWAY");
    ev->addParam("INTERFACE", "test_INTERFACE");
    ev->setAction(nmd::Action::RouteRemoved);
    handler.onEvent(ev);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceAddressUpdatedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceAddressRemovedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceAddedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceRemovedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceChangedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceLinkStateChangedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnRouteChangedInvokeCount, 1);
}
TEST(netlink_handler, onRouteUpdated)
{
    nmd::event_reporter report;

    nmd::inetd_unsolicited_event_listener glistener {
        .onInterfaceAddressUpdated = event_handler_test::defaultOnInterfaceAddressUpdated,
        .onInterfaceAddressRemoved = event_handler_test::defaultOnInterfaceAddressRemoved,
        .onInterfaceAdded = event_handler_test::defaultOnInterfaceAdded,
        .onInterfaceRemoved = event_handler_test::defaultOnInterfaceRemoved,
        .onInterfaceChanged = event_handler_test::defaultOnInterfaceChanged,
        .onInterfaceLinkStateChanged = event_handler_test::defaultOnInterfaceLinkStateChanged,
        .onRouteChanged = event_handler_test::defaultOnRouteChanged,
    };

    report.registerEventListener(glistener);

    nmd::netlink_handler handler(NETLINK_ROUTE, getpid());
    handler.setEventListener(std::make_shared<nmd::event_reporter>(report));

    event_handler_test::initTest();
    std::shared_ptr<nmd::netlink_event> ev = std::make_shared<nmd::netlink_event>();
    ev->addParam("ROUTE", "test_ROUTE");
    ev->addParam("GATEWAY", "test_GATEWAY");
    ev->addParam("INTERFACE", "test_INTERFACE");
    ev->setAction(nmd::Action::RouteUpdated);
    handler.onEvent(ev);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceAddressUpdatedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceAddressRemovedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceAddedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceRemovedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceChangedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceLinkStateChangedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnRouteChangedInvokeCount, 1);
}

TEST(netlink_handler, onAddressRemoved)
{
    nmd::event_reporter report;

    nmd::inetd_unsolicited_event_listener glistener {
        .onInterfaceAddressUpdated = event_handler_test::defaultOnInterfaceAddressUpdated,
        .onInterfaceAddressRemoved = event_handler_test::defaultOnInterfaceAddressRemoved,
        .onInterfaceAdded = event_handler_test::defaultOnInterfaceAdded,
        .onInterfaceRemoved = event_handler_test::defaultOnInterfaceRemoved,
        .onInterfaceChanged = event_handler_test::defaultOnInterfaceChanged,
        .onInterfaceLinkStateChanged = event_handler_test::defaultOnInterfaceLinkStateChanged,
        .onRouteChanged = event_handler_test::defaultOnRouteChanged,
    };

    report.registerEventListener(glistener);

    nmd::netlink_handler handler(NETLINK_ROUTE, getpid());
    handler.setEventListener(std::make_shared<nmd::event_reporter>(report));

    event_handler_test::initTest();
    std::shared_ptr<nmd::netlink_event> ev = std::make_shared<nmd::netlink_event>();
    ev->setAction(nmd::Action::AddressRemoved);
    handler.onEvent(ev);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceAddressUpdatedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceAddressRemovedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceAddedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceRemovedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceChangedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceLinkStateChangedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnRouteChangedInvokeCount, 0);
}

TEST(netlink_handler, onAddressUpdated)
{
    nmd::event_reporter report;

    nmd::inetd_unsolicited_event_listener glistener {
        .onInterfaceAddressUpdated = event_handler_test::defaultOnInterfaceAddressUpdated,
        .onInterfaceAddressRemoved = event_handler_test::defaultOnInterfaceAddressRemoved,
        .onInterfaceAdded = event_handler_test::defaultOnInterfaceAdded,
        .onInterfaceRemoved = event_handler_test::defaultOnInterfaceRemoved,
        .onInterfaceChanged = event_handler_test::defaultOnInterfaceChanged,
        .onInterfaceLinkStateChanged = event_handler_test::defaultOnInterfaceLinkStateChanged,
        .onRouteChanged = event_handler_test::defaultOnRouteChanged,
    };

    report.registerEventListener(glistener);

    nmd::netlink_handler handler(NETLINK_ROUTE, getpid());
    handler.setEventListener(std::make_shared<nmd::event_reporter>(report));

    event_handler_test::initTest();
    std::shared_ptr<nmd::netlink_event> ev = std::make_shared<nmd::netlink_event>();
    ev->setAction(nmd::Action::AddressUpdated);
    handler.onEvent(ev);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceAddressUpdatedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceAddressRemovedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceAddedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceRemovedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceChangedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceLinkStateChangedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnRouteChangedInvokeCount, 0);
}

TEST(netlink_handler, notify)
{
    nmd::event_reporter report;

    nmd::inetd_unsolicited_event_listener glistener {
        .onInterfaceAddressUpdated = event_handler_test::defaultOnInterfaceAddressUpdated,
        .onInterfaceAddressRemoved = event_handler_test::defaultOnInterfaceAddressRemoved,
        .onInterfaceAdded = event_handler_test::defaultOnInterfaceAdded,
        .onInterfaceRemoved = event_handler_test::defaultOnInterfaceRemoved,
        .onInterfaceChanged = event_handler_test::defaultOnInterfaceChanged,
        .onInterfaceLinkStateChanged = event_handler_test::defaultOnInterfaceLinkStateChanged,
        .onRouteChanged = event_handler_test::defaultOnRouteChanged,
    };

    report.registerEventListener(glistener);

    event_handler_test::initTest();
    nmd::netlink_handler handler(NETLINK_ROUTE, getpid());
    handler.setEventListener(std::make_shared<nmd::event_reporter>(report));

    handler.notifyInterfaceChanged("eth0", true);
    handler.notifyAddressUpdated("192.168.12.13", "eth0", 0, 0);
    handler.notifyAddressRemoved("192.168.12.13", "eth0", 0, 0);

    EXPECT_EQ(event_handler_test::defaultOnInterfaceAddressUpdatedInvokeCount, 1);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceAddressRemovedInvokeCount, 1);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceAddedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceRemovedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceChangedInvokeCount, 1);
    EXPECT_EQ(event_handler_test::defaultOnInterfaceLinkStateChangedInvokeCount, 0);
    EXPECT_EQ(event_handler_test::defaultOnRouteChangedInvokeCount, 0);
}

DISABLE_WARNING_POP
