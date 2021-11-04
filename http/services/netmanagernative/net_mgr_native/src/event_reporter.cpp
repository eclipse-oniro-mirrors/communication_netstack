#include "event_reporter.h"
namespace OHOS {
void nmd::event_reporter::registerEventListener(inetd_unsolicited_event_listener &listener)
{
    this->listener_ = listener;
}

nmd::event_reporter::~event_reporter() {}
} // namespace OHOS