#ifndef __INCLUDE_BLOCKING_QUEUE_H__
#define __INCLUDE_BLOCKING_QUEUE_H__

#include <condition_variable>
#include <mutex>
#include <vector>
namespace OHOS {
namespace nmd {
template<typename T>
class blocking_queue {
private:
    std::mutex mutex_;
    std::condition_variable notFull_;
    std::condition_variable notEmpty_;
    unsigned int start_;
    unsigned int end_;
    unsigned int capacity_;
    std::vector<T> vt_;

public:
    explicit blocking_queue(unsigned int capacity) : start_(0), end_(0), capacity_(capacity), vt_(capacity + 1) {};
    ~blocking_queue() {};

    bool isEmpty()
    {
        return this->end_ == this->start_;
    }

    bool isFull()
    {
        return (this->start_ + this->capacity_ - this->end_) % (this->capacity_ + 1) == 0;
    }

    void push(const T &e)
    {
        std::unique_lock<std::mutex> lock(this->mutex_);
        while (this->isFull()) {
            this->notFull_.wait(lock);
        }

        this->vt_[this->end_++] = e;
        this->end_ %= (this->capacity_ + 1);
        this->notEmpty_.notify_one();
    }

    T pop()
    {
        std::unique_lock<std::mutex> lock(this->mutex_);
        while (this->isEmpty()) {
            this->notEmpty_.wait(lock);
        }

        auto res = this->vt_[this->start_++];
        this->start_ %= (this->capacity_ + 1);
        this->notFull_.notify_one();
        return res;
    }
};

} // namespace nmd
} // namespace OHOS
#endif //!__INCLUDE_BLOCKING_QUEUE_H__