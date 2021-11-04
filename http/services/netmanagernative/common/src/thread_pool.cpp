#include "thread_pool.h"
#include <functional>
namespace OHOS {
namespace nmd {
thread_pool::thread_pool(unsigned int threadNums, unsigned int queueSize)
    : threadNums_(threadNums), queueSize_(queueSize)
{
    this->workQueue_ = new blocking_queue<nmd::job *>(this->queueSize_);

    for (unsigned int i = 0; i < this->threadNums_; ++i) {
        this->workers_.push_back(new std::thread(std::bind(&thread_pool::threadLoop, this)));
    }

    this->running_ = true;
}

thread_pool::~thread_pool()
{
    this->running_ = false;
    cond_.notify_all();
    for (unsigned int i = 0; i < this->threadNums_; ++i) {
        auto &thread = this->workers_[i];
        thread->join();
        delete thread;
    }

    if (nullptr != this->workQueue_) {
        delete this->workQueue_;
    }
}

nmd::job *thread_pool::takeJobFromQueue()
{
    std::unique_lock<std::mutex> lock(this->mutex_);
    while (this->workQueue_->isEmpty() && this->running_) {
        this->cond_.wait(lock);
    }
    nmd::job *j = nullptr;
    if (!this->workQueue_->isEmpty() && this->running_) {
        j = this->workQueue_->pop();
    }
    return j;
}

void thread_pool::threadLoop()
{
    while (this->running_) {
        nmd::job *j = takeJobFromQueue();
        if (j) {
            j->run();
            delete j;
        }
    }
}

void thread_pool::execute(nmd::job *j)
{
    std::unique_lock<std::mutex> lock(this->mutex_);
    while (this->workQueue_->isFull()) {
    }
    this->workQueue_->push(j);
    this->cond_.notify_one();
}

} // namespace nmd
} // namespace OHOS