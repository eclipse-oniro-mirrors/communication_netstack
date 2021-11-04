#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <logger.h>
#include <net/if.h>
#include <thread>
#include <event_reporter.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <warning_disable.h>

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

namespace event_report_test {
void defaultOnInterfaceAddressUpdated(const std::string &addr, const std::string &ifName, int flags, int scope)
{
    std::cout << "InterfaceAddressUpdate:" << addr << "," << ifName << "," << flags << "," << scope << std::endl;
}
void defaultOnInterfaceAddressRemoved(const std::string &addr, const std::string &ifName, int flags, int scope)
{
    std::cout << "InterfaceAddressRemoved:" << addr << "," << ifName << "," << flags << "," << scope << std::endl;
}
void defaultOnInterfaceAdded(const std::string &ifName)
{
    std::cout << "InterfaceAdded:" << ifName << std::endl;
}
void defaultOnInterfaceRemoved(const std::string &ifName)
{
    std::cout << "InterfaceRemoved:" << ifName << std::endl;
}
void defaultOnInterfaceChanged(const std::string &ifName, bool up)
{
    std::cout << "InterfaceChanged:" << ifName << "," << up << std::endl;
}
void defaultOnInterfaceLinkStateChanged(const std::string &ifName, bool up)
{
    std::cout << "InterfaceLinkStateChanged:" << ifName << "," << up << std::endl;
}
void defaultOnRouteChanged(
    bool updated, const std::string &route, const std::string &gateway, const std::string &ifName)
{
    std::cout << "RouteChanged:" << updated << "," << route << "," << gateway << "," << ifName << std::endl;
}
} // namespace event_report_test

TEST(event_reporter, registerEventListener)
{
    nmd::event_reporter report;

    nmd::inetd_unsolicited_event_listener glistener {
        .onInterfaceAddressUpdated = event_report_test::defaultOnInterfaceAddressUpdated,
        .onInterfaceAddressRemoved = event_report_test::defaultOnInterfaceAddressRemoved,
        .onInterfaceAdded = event_report_test::defaultOnInterfaceAdded,
        .onInterfaceRemoved = event_report_test::defaultOnInterfaceRemoved,
        .onInterfaceChanged = event_report_test::defaultOnInterfaceChanged,
        .onInterfaceLinkStateChanged = event_report_test::defaultOnInterfaceLinkStateChanged,
        .onRouteChanged = event_report_test::defaultOnRouteChanged,
    };

    report.registerEventListener(glistener);
}

DISABLE_WARNING_POP
