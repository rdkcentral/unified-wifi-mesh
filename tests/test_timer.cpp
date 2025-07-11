#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <thread>
#include "timer.h"

using namespace std::chrono_literals;

TEST(ThreadedTimerTest, FiresAfterDelay) {
    ThreadedTimer timer;
    std::atomic<bool> fired = false;

    timer.execute_after(100ms, [&]() {
        fired = true;
    });

    std::this_thread::sleep_for(150ms);
    EXPECT_TRUE(fired.load());
}

TEST(ThreadedTimerTest, StopPreventsFiring) {
    ThreadedTimer timer;
    std::atomic<bool> fired = false;

    timer.execute_after(200ms, [&]() {
        fired = true;
    });

    std::this_thread::sleep_for(50ms);
    timer.stop();

    std::this_thread::sleep_for(200ms);
    EXPECT_FALSE(fired.load());
}

TEST(ThreadedTimerTest, PeriodicRunsMultipleTimes) {
    ThreadedTimer timer;
    std::atomic<int> counter{0};

    timer.start_periodic(50ms, [&]() {
        counter++;
    });

    std::this_thread::sleep_for(220ms);
    timer.stop();

    EXPECT_GE(counter.load(), 3);
}

TEST(ThreadedTimerTest, StopIsIdempotent) {
    ThreadedTimer timer;
    timer.execute_after(50ms, []{});
    timer.stop();
    timer.stop();
    // Checks that a double stop doesn't deadlock. If we get here, we've passed.
    SUCCEED();
}
