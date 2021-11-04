#ifndef __INCLUDE_UTILS_H__
#define __INCLUDE_UTILS_H__

#include <chrono>

namespace OHOS {
namespace nmd {
namespace common {
namespace utils {
std::time_t getCurrentTime();
int removeDirectory(const char *path);

template<typename T>
class auto_destroyer {
    typedef void (*Action)(T);

public:
    auto_destroyer(T res, Action action) : res_(res), action_(action) {}
    ~auto_destroyer()
    {
        if (nullptr != action_) {
            action_(res_);
        }
    }

private:
    T res_;
    Action action_;
};
} // namespace utils
} // namespace common
} // namespace nmd
} // namespace OHOS

#endif //!__INCLUDE_UTILS_H__