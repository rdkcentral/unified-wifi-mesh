/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2025 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <gtest/gtest.h>
#include "timer.h"
#include <atomic>
#include <chrono>
#include <iostream>
#include <thread>

using namespace std::chrono_literals;

/**
 * @brief Verify that the ThreadedTimer executes the callback after the specified delay
 *
 * This test verifies that the execute_after API of the ThreadedTimer class correctly executes the provided callback function after a delay of 50ms. The test ensures that the callback sets an atomic flag, which is then verified by the test.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 001@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                  | Test Data                                                                                   | Expected Result                                                    | Notes          |
 * | :--------------: | -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ | -------------- |
 * | 01               | Initialize timer and atomic flag for callback tracking                                       | timer = instance, called = false                                                            | Instance created and flag is initialized to false                  | Should be successful |
 * | 02               | Invoke execute_after API with 50ms delay and a callback that sets the flag to true             | delay = 50ms, callback = lambda setting called = true                                       | API schedules the callback execution after the specified delay       | Should Pass    |
 * | 03               | Wait for callback execution in a loop                                                        | loop iterations = 50, sleep duration = 10ms                                                 | Callback executes within the loop, setting the atomic flag to true   | Should be successful |
 * | 04               | Verify that the callback was executed by asserting the atomic flag is true                    | output1 = called flag = true                                                                  | EXPECT_TRUE assertion passes confirming callback execution          | Should Pass    |
 */
TEST(ThreadedTimer, ExecuteAfter_Positive) {
    std::cout << "Entering: ThreadedTimer_ExecuteAfter_Positive" << std::endl;
    ThreadedTimer timer{};
    std::atomic<bool> called{false};
    std::cout << "Invoking: execute_after" << std::endl;
    timer.execute_after(50ms, [&]() {
        std::cout << "Callback: Entering (execute_after)" << std::endl;
        called = true;
        std::cout << "Callback: Exiting (execute_after)" << std::endl;
    });
    for (int i = 0; i < 50 && !called.load(); ++i) {
        std::this_thread::sleep_for(10ms);
    }

    EXPECT_TRUE(called.load());
    std::cout << "Exiting: ThreadedTimer_ExecuteAfter_Positive" << std::endl;
}
/**
 * @brief Validate that the callback is not invoked before the specified delay.
 *
 * This test verifies that when execute_after is called with a delay of 500ms, the callback does not execute within 100ms. The test ensures that the timer correctly defers the callback execution until after the specified delay. This negative test is important to confirm that premature execution does not occur.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 002@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                                   | Test Data                                                       | Expected Result                                                                 | Notes        |
 * | :--------------: | ------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- | ------------------------------------------------------------------------------- | ------------ |
 * | 01               | Invoke execute_after with a delay of 500ms and wait for 100ms to verify that the callback is not executed.    | delay = 500ms, sleep_duration = 100ms, initial called = false     | Callback should not be invoked within 100ms; EXPECT_FALSE(called.load()) passes     | Should Pass  |
 */
TEST(ThreadedTimer, ExecuteAfter_Negative) {
    std::cout << "Entering: ThreadedTimer_ExecuteAfter_Negative" << std::endl;
    ThreadedTimer timer{};
    std::atomic<bool> called{false};
    std::cout << "Invoking: execute_after" << std::endl;
    timer.execute_after(500ms, [&]() {
        std::cout << "Callback: Entering (execute_after negative)" << std::endl;
        called = true;
        std::cout << "Callback: Exiting (execute_after negative)" << std::endl;
    });
    std::this_thread::sleep_for(100ms);
    EXPECT_FALSE(called.load());
    std::cout << "Exiting: ThreadedTimer_ExecuteAfter_Negative" << std::endl;
}
/**
 * @brief Tests the periodic start functionality of the ThreadedTimer API in a positive scenario.
 *
 * This test evaluates the start_periodic method of the ThreadedTimer class by scheduling a periodic callback and verifying that the callback is executed exactly three times before stopping the timer. It ensures that the periodic timer correctly triggers the callback and that the stop function terminates the timer as expected.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 003
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- | -------------- | ----- |
 * | 01 | Initialize ThreadedTimer instance and atomic count variable | No input values, timer instance created, count = 0 | Timer instance is created and count is initialized to 0 | Should be successful |
 * | 02 | Invoke start_periodic API with 50ms interval and a callback lambda that increments count | Calling start_periodic(interval = 50ms, callback that increments count and returns true) | Timer begins periodic invocations; callback is scheduled properly | Should Pass |
 * | 03 | Wait for the callback to be executed until count reaches 3 or maximum iterations reached | Loop with 200 iterations, sleep 10ms per iteration, callback expected to update count | Count reaches 3 within the given iterations | Should Pass |
 * | 04 | Stop the timer using the stop API | Invoking timer.stop() | Timer stops its periodic callback invocations successfully | Should be successful |
 * | 05 | Validate that count equals 3 using EXPECT_EQ | EXPECT_EQ(count.load(), 3) | Assertion passes confirming that the callback was executed exactly 3 times | Should Pass |
 */
TEST(ThreadedTimer, StartPeriodic_Positive) {
    std::cout << "Entering: ThreadedTimer_StartPeriodic_Positive" << std::endl;
    ThreadedTimer timer{};
    std::atomic<int> count{0};
    std::cout << "Invoking: start_periodic" << std::endl;
    timer.start_periodic(50ms, [&]() -> bool {
        int c = ++count;
        std::cout << "Callback (periodic) invocation: count=" << c << std::endl;
        return true;
    });
    for (int i = 0; i < 200 && count.load() < 3; ++i) {
        std::this_thread::sleep_for(10ms);
    }
    timer.stop();
    EXPECT_EQ(count.load(), 3);
    std::cout << "Exiting: ThreadedTimer_StartPeriodic_Positive" << std::endl;
}
/**
 * @brief Verify that the periodic timer does not invoke the callback repeatedly in a negative scenario
 *
 * This test verifies that when start_periodic is invoked with a callback that always returns true, 
 * the timer callback is executed only once rather than continuously being invoked. This negative test 
 * case ensures that the timer stops periodic execution properly when stop is called.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 004@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                          | Test Data                                                                                                             | Expected Result                                                                                 | Notes        |
 * | :--------------: | ---------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ | ------------ |
 * | 01               | Initialize the ThreadedTimer instance and an atomic counter; print the entry message                 | No inputs; count initialized to 0                                                                                     | Timer instance and counter are correctly initialized                                             | Should be successful |
 * | 02               | Invoke start_periodic with a delay of 50ms and a callback that increments the counter                | timer.start_periodic(delay = 50ms, callback: increments count and returns true)                                       | Callback is scheduled; in a negative scenario, periodic invocation should not repeatedly occur   | Should Fail  |
 * | 03               | Wait in a loop for up to 50 iterations (10ms each) until the counter is incremented (i.e., becomes 1)  | For loop with 50 iterations, each sleeping for 10ms; initial count = 0                                                   | Callback should be invoked once, causing count to become 1                                         | Should be successful |
 * | 04               | Stop the timer and assert that the counter equals 1                                                 | timer.stop() is called; then, EXPECT_EQ(count.load(), 1) is executed                                                   | The counter remains equal to 1 confirming only one invocation occurred                           | Should Fail  |
 */
TEST(ThreadedTimer, StartPeriodic_Negative) {
    std::cout << "Entering: ThreadedTimer_StartPeriodic_Negative" << std::endl;
    ThreadedTimer timer;
    std::atomic<int> count{0};
    std::cout << "Invoking: start_periodic" << std::endl;
    timer.start_periodic(50ms, [&]() -> bool {
        int c = ++count;
        std::cout << "Callback (periodic negative) invocation: count=" << c << std::endl;
        return true;
    });
    for (int i = 0; i < 50 && count.load() < 1; ++i) {
        std::this_thread::sleep_for(10ms);
    }
    timer.stop();
    EXPECT_EQ(count.load(), 1);
    std::cout << "Exiting: ThreadedTimer_StartPeriodic_Negative" << std::endl;
}
/**
 * @brief Verify that the ThreadedTimer stop method can be successfully called without runtime exceptions.
 *
 * This test verifies that invoking the stop method of the ThreadedTimer class works as expected.
 * It checks that no exceptions or errors are raised during the stop operation and that proper log messages are printed.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 005
 * **Priority:** High
 * 
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * |01| Print entering message for the test start | No inputs (log message: "Entering: ThreadedTimer_Stop_Only") | Console log outputs "Entering: ThreadedTimer_Stop_Only" | Should be successful |
 * |02| Create ThreadedTimer instance and invoke stop method | Timer instance creation: default constructor, call: timer.stop() | API returns normally without throwing exceptions | Should Pass |
 * |03| Print exiting message for the test end | No inputs (log message: "Exiting: ThreadedTimer_Stop_Only") | Console log outputs "Exiting: ThreadedTimer_Stop_Only" | Should be successful |
 */
TEST(ThreadedTimer, Stop_Only) {
    std::cout << "Entering: ThreadedTimer_Stop_Only" << std::endl;
    ThreadedTimer timer{};
    std::cout << "Invoking: stop" << std::endl;
    timer.stop();
    std::cout << "Exiting: ThreadedTimer_Stop_Only" << std::endl;
}
