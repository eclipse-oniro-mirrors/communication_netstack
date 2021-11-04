#ifndef __INCLUDE_ERROR_CODE_H__
#define __INCLUDE_ERROR_CODE_H__

#include <system_error>

namespace OHOS {
namespace nmd {
namespace common {
enum class error_code { errNoInfName = 1, errIpverAndWhich = 2 };
class error_code_category : public std::error_category {
public:
    error_code_category();
    const char *name() const noexcept override;
    std::string message(int ev) const override;
    const static error_category &get();
};
std::error_code make_error_code(error_code e);

enum class dnsresolv_error_code {
    errBadHints = 1,
};
} // namespace common
} // namespace nmd
} // namespace OHOS
namespace std {
template<>
struct is_error_code_enum<OHOS::nmd::common::error_code> : std::true_type {};
} // namespace std

#endif //!__INCLUDE_ERROR_CODE_H__