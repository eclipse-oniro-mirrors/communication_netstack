#ifndef __INCLUDE_FWMARK_H__
#define __INCLUDE_FWMARK_H__

#include "network.h"
namespace OHOS {
namespace nmd {
union fwmark {
    uint32_t val;
    struct {
        uint16_t netId : 16;
        NetworkPermission permission : 2;
        uint16_t reserved : 14;
    } bits;
    constexpr fwmark() : val(0) {}
};
} // namespace nmd
} // namespace OHOS
#endif //!__INCLUDE_FWMARK_H__