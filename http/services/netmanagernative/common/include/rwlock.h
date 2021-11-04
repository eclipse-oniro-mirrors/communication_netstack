#ifndef __INCLUDE_RWLOCK_H__
#define __INCLUDE_RWLOCK_H__

#ifndef _MSC_VER
#define NOEXCEPT noexcept
#else
#define NOEXCEPT
#endif

#include "raii.h"
#include <atomic>
#include <cassert>
#include <cstdlib>
#include <thread>

namespace OHOS {
namespace nmd {
namespace common {

class rwlock {
#define WRITE_LOCK_STATUS -1
#define FREE_STATUS 0
private:
    static const std::thread::id NULL_THEAD;
    const bool WRITE_FIRST;
    std::thread::id m_write_thread_id;
    std::atomic_int m_lockCount;
    std::atomic_uint m_writeWaitCount;

public:
    rwlock(const rwlock &) = delete;
    rwlock &operator=(const rwlock &) = delete;
    explicit rwlock(bool writeFirst = false);
    virtual ~rwlock() = default;
    int readLock();
    int readUnlock();
    int writeLock();
    int writeUnlock();
    raii read_guard() const noexcept
    {
        return make_raii(*this, &rwlock::readUnlock, &rwlock::readLock);
    }
    raii write_guard() noexcept
    {
        return make_raii(*this, &rwlock::writeUnlock, &rwlock::writeLock);
    }
};

} // namespace common
} // namespace nmd
} // namespace OHOS
#endif //!__INCLUDE_RWLOCK_H__