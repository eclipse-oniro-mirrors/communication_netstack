#ifndef __INCLUDE_FWMARK_COMMAND_H__
#define __INCLUDE_FWMARK_COMMAND_H__
#include <stdint.h>
namespace OHOS {
namespace nmd {
struct fwmark_command {
    enum cmd_id {
        SELECT_NETWORK,
    } cmdId;
    uint16_t netId;
    unsigned fd;
};
} // namespace nmd
} // namespace OHOS
#endif //!__INCLUDE_FWMARK_COMMAND_H__