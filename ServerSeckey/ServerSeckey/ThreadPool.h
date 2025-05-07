#include <stdexcept>
#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <chrono>
#include <algorithm>

class ThreadPool {
public:
    ThreadPool(size_t min_threads = 1,
        size_t max_threads = std::thread::hardware_concurrency(),
        size_t load_factor = 2)
        : min_threads_(min_threads),
        max_threads_(max_threads),
        load_factor_(load_factor),
        stop_(false) {
        for (size_t i = 0; i < min_threads_; ++i) {
            create_worker_thread();
        }
    }

    ~ThreadPool();

    template <typename Func, typename... Args>
    void enqueue(Func&& func, Args&&... args);

private:
    void worker_thread();

    void try_expand();

    void create_worker_thread();

    void clean_finished_threads();

    std::vector<std::thread> threads_;
    std::queue<std::function<void()>> tasks_;
    std::mutex mutex_;
    std::condition_variable condition_;
    bool stop_;

    const size_t min_threads_;
    const size_t max_threads_;
    const size_t load_factor_;
};

template<typename Func, typename ...Args>
inline void ThreadPool::enqueue(Func&& func, Args && ...args)
{
    auto task = std::bind(std::forward<Func>(func), std::forward<Args>(args)...);
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (stop_) {
            throw std::runtime_error("enqueue on stopped ThreadPool");
        }
        tasks_.emplace([task]() { task(); });
    }
    condition_.notify_one();
    try_expand();
}
