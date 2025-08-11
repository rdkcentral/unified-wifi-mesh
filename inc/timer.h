
#ifndef THREADED_TIMER_H
#define THREADED_TIMER_H

#include <iostream>
#include <thread>
#include <functional>
#include <chrono>
#include <atomic>
#include <memory>

class ThreadedTimer {
public:
    ThreadedTimer();
    ~ThreadedTimer();

    /**
     * @brief Call `callback` after `delay` milliseconds
     * 
     * @param delay The delay for the callback
     * @param callback The callback
     */
    void execute_after(std::chrono::milliseconds delay, std::function<void()> callback);

    /**
     * @brief Starts a timer which calls `callback` with periodicity `interval`
     * 
     * @param interval The periodicity at which to call the callback
     * @param callback The callback.
     */
    void start_periodic(std::chrono::milliseconds interval, std::function<void()> callback);

    /**
     * @brief Cancel this timer.
     * 
     */
    void stop();

private:
    std::unique_ptr<std::thread> timer_thread;
    std::atomic<bool> running;
};

#endif // THREADED_TIMER_H
