#include "timer.h"

ThreadedTimer::ThreadedTimer() : running(false) {}

ThreadedTimer::~ThreadedTimer() {
    stop();
}

void ThreadedTimer::execute_after(std::chrono::milliseconds delay, std::function<void()> callback) {
    stop();
    running = true;
    timer_thread = std::make_unique<std::thread>([this, delay, callback]() {
        std::this_thread::sleep_for(delay);
        if (running.load()) {
            callback();
        }
    });
}

void ThreadedTimer::start_periodic(std::chrono::milliseconds interval, std::function<void()> callback) {
    stop();
    running = true;
    timer_thread = std::make_unique<std::thread>([this, interval, callback]() {
        while (running.load()) {
            std::this_thread::sleep_for(interval);
            if (running.load()) {
                callback();
            }
        }
    });
}

void ThreadedTimer::stop() {
    running = false;
    if (timer_thread && timer_thread->joinable()) {
        timer_thread->join();
    }
}
