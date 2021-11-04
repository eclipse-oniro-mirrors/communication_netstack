#include "error_code.h"

namespace OHOS {
namespace nmd {
namespace common {
nmd::common::error_code_category::error_code_category() {}

const char *error_code_category::name() const noexcept
{
    return "netd error code";
}

std::string error_code_category::message(int ev) const
{
    switch (static_cast<nmd::common::error_code>(ev)) {
        case nmd::common::error_code::errNoInfName:
            return "no such interface name";
            break;
        case nmd::common::error_code::errIpverAndWhich:
            return "bad ip version or bad which for setProcSysNet";
            break;
        default:
            return "this is unknow error_code";
            break;
    }
}
const std::error_category &error_code_category::get()
{
    const static nmd::common::error_code_category category_const;
    return category_const;
}

std::error_code make_error_code(nmd::common::error_code e)
{
    return std::error_code(static_cast<int>(e), nmd::common::error_code_category::get());
}
} // namespace common
} // namespace nmd
} // namespace OHOS
