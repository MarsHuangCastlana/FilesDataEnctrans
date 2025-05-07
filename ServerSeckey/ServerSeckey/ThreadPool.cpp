#include "ThreadPool.h"

ThreadPool::~ThreadPool()
{
    {
        std::unique_lock<std::mutex> lock(mutex_);
        stop_ = true;
    }
    condition_.notify_all();
    for (auto& t : threads_) {
        if (t.joinable()) t.join();
    }
}

void ThreadPool::worker_thread()
{
    while (true) {
        std::function<void()> task;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            condition_.wait(lock, [this]() { return stop_ || !tasks_.empty(); });
            if (stop_ && tasks_.empty()) {
                return;
            }
            task = std::move(tasks_.front());
            tasks_.pop();
        }
        task();
    }
}

void ThreadPool::try_expand()
{
    std::unique_lock<std::mutex> lock(mutex_);
    size_t current_threads = threads_.size();
    size_t task_count = tasks_.size();
    if (task_count > current_threads * load_factor_ &&
        current_threads < max_threads_) {
        create_worker_thread();
    }
}



void ThreadPool::create_worker_thread()
{
    try {
        threads_.emplace_back(&ThreadPool::worker_thread, this);
    }
    catch (...) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!stop_) {
            // 尝试清理已完成的线程并再次创建
            clean_finished_threads();
            try {
                threads_.emplace_back(&ThreadPool::worker_thread, this);
            }
            catch (...) {
                // 若仍然失败，暂时不做更多处理
            }
        }
    }
}

void ThreadPool::clean_finished_threads()
{
    auto it = std::remove_if(threads_.begin(), threads_.end(), [](std::thread& t) {
        return t.joinable() && t.get_id() == std::this_thread::get_id();
        });
    threads_.erase(it, threads_.end());
}
