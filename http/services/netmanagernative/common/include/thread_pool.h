#ifndef __INCLUDE_THREAD_POOL_H__
#define __INCLUDE_THREAD_POOL_H__

#include "blocking_queue.h"
#include "job.h"
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>
namespace OHOS {
namespace nmd {
class thread_pool {
private:
    unsigned int threadNums_;
    unsigned int queueSize_;

    bool running_ = false;

    std::vector<std::thread *> workers_;
    nmd::blocking_queue<nmd::job *> *workQueue_;

    std::mutex mutex_;
    std::condition_variable cond_;

    void threadLoop();

    nmd::job *takeJobFromQueue();

public:
    thread_pool(unsigned int threadNums, unsigned int queueSize);

    void execute(nmd::job *job);

    ~thread_pool();
};

} // namespace nmd
} // namespace OHOS
#endif //!__INCLUDE_THREAD_POOL_H__