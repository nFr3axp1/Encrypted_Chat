#pragma once
#include<mutex>
#include<thread>
#include<future>
#include<condition_variable>
#include<queue>
#include<functional>
#include<type_traits>
#include<memory>
#include<vector>

class ThreadsPool {
public:
    ThreadsPool(const ThreadsPool& Args)=delete;
    ThreadsPool(ThreadsPool&& Args)=delete;
    ThreadsPool& operator=(const ThreadsPool& Args)=delete;
    ThreadsPool& operator=(ThreadsPool&& Args)=delete;

    std::stop_source StopSource;

    std::vector<std::jthread>ThreadsQueue;
    std::queue<std::function<void()>> TasksQueue;
    std::mutex Mutex;
    std::condition_variable_any ConditionVariable;

    ~ThreadsPool() {
        StopThreadsPool();
    }

    static ThreadsPool& InitThreadPool(const unsigned int& num) {
        static ThreadsPool MyThreadPool(std::ref(num));
        return MyThreadPool;
    }

    template<typename Func,typename ...Args>
    auto AddTask(Func&& func, Args&&... args)->std::future<std::invoke_result_t<Func, Args...>>  {
        using Ret = std::invoke_result_t<Func, Args...>;
        using PkgType = std::packaged_task<Ret()>;

        std::shared_ptr<PkgType>PACKAGE_ptr=std::make_shared<PkgType>(std::bind_front(std::forward<Func>(func), std::forward<Args>(args)...));
        auto future=PACKAGE_ptr->get_future();

        std::unique_lock<std::mutex> lock(Mutex);
        TasksQueue.emplace([PACKAGE_ptr]() {
            (*PACKAGE_ptr)();
        });
        lock.unlock();
        ConditionVariable.notify_one();
        return future;
    }

    void StopThreadsPool() {
        StopSource.request_stop();
        for (auto& i:ThreadsQueue) {
            if (i.joinable()) {
                i.join();
            }
        }
    }

private:
    ThreadsPool(const unsigned int& PoolNum){
        for (unsigned int i = 0; i < PoolNum; i++) {
            ThreadsQueue.emplace_back([this]() {
                while (true) {
                    std::stop_token st=StopSource.get_token();
                    std::unique_lock<std::mutex> lock(Mutex);
                    if (!ConditionVariable.wait(lock,st,[this]() {if(!TasksQueue.empty()) {return true;}return false;})) {
                        return true;
                    }
                    std::function<void()> ThisThreadTask=TasksQueue.front();
                    TasksQueue.pop();
                    lock.unlock();
                    ThisThreadTask();
                }
            });
        }
    }
};