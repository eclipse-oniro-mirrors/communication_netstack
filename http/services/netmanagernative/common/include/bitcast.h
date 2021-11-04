#ifndef __INCLUDE_BITCAST_H__
#define __INCLUDE_BITCAST_H__

#include <cstring>
#include <memory>
#include <type_traits>

namespace OHOS {
namespace nmd {
namespace common {
namespace internal_casts {

template<class Dest, class Source>
struct is_bitcastable
    : std::integral_constant<bool,
          sizeof(Dest) == sizeof(Source) && std::is_trivially_copyable<Source>::value &&
              std::is_trivially_copyable<Dest>::value && std::is_default_constructible<Dest>::value> {};

} // namespace internal_casts

template<typename Dest, typename Source,
    typename std::enable_if<internal_casts::is_bitcastable<Dest, Source>::value, int>::type = 0>
inline Dest bit_cast(const Source &source) noexcept
{
    Dest dest;
    std::memcpy(static_cast<void *>(std::addressof(dest)), static_cast<const void *>(std::addressof(source)),
        sizeof(dest));
    return dest;
}

} // namespace common

} // namespace nmd
} // namespace OHOS

#endif //!__INCLUDE_BITCAST_H__