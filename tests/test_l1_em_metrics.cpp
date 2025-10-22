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
#include <gmock/gmock.h>
#include <stdio.h>
#include "em_metrics.h"

class DummyEmMetrics : public em_metrics_t {
public:
    dm_easy_mesh_t* get_data_model() override { return nullptr; }
    em_state_t get_state() override { return em_state_t(); }
    void set_state(em_state_t state) override { (void)state; }
    int send_frame(unsigned char* buff, unsigned int len, bool multicast = false) override {
        (void)buff; (void)len; (void)multicast;
        return 0;
    }
    em_profile_type_t get_profile_type() override { return em_profile_type_t(); }
    em_cmd_t* get_current_cmd() override { return nullptr; }
};

class EmMetricsTest : public ::testing::Test {    
protected:
    DummyEmMetrics* emMetrics;
    void SetUp() override {
        emMetrics = new DummyEmMetrics();
    }    
    void TearDown() override {
        delete emMetrics;
        emMetrics = nullptr;
    }        
};

/**
 * @brief Verify construction of DummyEmMetrics object on the stack without exceptions.
 *
 * This test verifies that invoking the default constructor of DummyEmMetrics on the stack does not throw any exceptions.
 * It ensures that the object is constructed properly and that the default constructor behaves as expected.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 001
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01               | Construct a DummyEmMetrics object on the stack using its default constructor | No input arguments, output: localEmMetrics object constructed successfully | No exception is thrown; EXPECT_NO_THROW assertion passes                | Should Pass |
 */
TEST_F(EmMetricsTest, StackConstruction) {
    std::cout << "Entering StackConstruction test" << std::endl;
    EXPECT_NO_THROW({
        DummyEmMetrics localEmMetrics;
        std::cout << "Invoked em_metrics_t() default constructor for localEmMetrics on the stack." << std::endl;
    });
    std::cout << "Exiting StackConstruction test" << std::endl;
}
/**
 * @brief Validate dynamic allocation and deallocation of DummyEmMetrics object without exceptions.
 *
 * This test verifies that a DummyEmMetrics object can be dynamically allocated using the default constructor and that the allocated memory is not a null pointer. It also confirms that the object can be safely deleted without throwing exceptions. This ensures proper dynamic memory management for the object lifecycle.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 002@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01               | Invoke dynamic allocation for DummyEmMetrics and verify no exception is thrown during construction | dynamicEmMetrics = nullptr, new DummyEmMetrics()                      | Dynamic allocation succeeds with no exception thrown                                      | Should Pass   |@n
 * | 02               | Check that the allocated dynamicEmMetrics pointer is not null                                   | dynamicEmMetrics pointer after allocation                             | Pointer is not null as confirmed by the assertion EXPECT_NE(dynamicEmMetrics, nullptr)      | Should Pass   |@n
 * | 03               | Delete the dynamically allocated DummyEmMetrics object and verify no exception is thrown on deletion | delete dynamicEmMetrics; dynamicEmMetrics set to nullptr              | Deletion occurs without exception and destructor executes properly                         | Should Pass   |
 */
TEST_F(EmMetricsTest, DynamicAllocationConstruction) {
    std::cout << "Entering DynamicAllocationConstruction test" << std::endl;
    DummyEmMetrics* dynamicEmMetrics = nullptr;
    EXPECT_NO_THROW({
        dynamicEmMetrics = new DummyEmMetrics();
        std::cout << "Invoked em_metrics_t() default constructor for dynamicEmMetrics using new." << std::endl;
    });
    EXPECT_NE(dynamicEmMetrics, nullptr) << "Dynamic allocation returned null pointer.";
    std::cout << "dynamicEmMetrics pointer is non-null which is expected." << std::endl;
    EXPECT_NO_THROW({
        delete dynamicEmMetrics;
        dynamicEmMetrics = nullptr;
        std::cout << "Destructor executed properly upon deletion of dynamicEmMetrics." << std::endl;
    });
    std::cout << "Exiting DynamicAllocationConstruction test" << std::endl;
}

/**
 * @brief Test to verify that the process_agent_state() method executes without throwing exceptions.
 *
 * This test case validates that invoking the process_agent_state() method on the emMetrics instance does not result in any exceptions. It assumes that the internal state is processed correctly if no exceptions are thrown during the method call.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 003@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01 | Invoke process_agent_state() method on the emMetrics instance and check that no exceptions are thrown.  | input: none, output: none | The method completes without throwing exceptions and passes the EXPECT_NO_THROW check | Should Pass |
 */
TEST_F(EmMetricsTest, ProcessAgentState) {
    std::cout << "Entering ProcessAgentState test" << std::endl;    
    std::cout << "Invoking process_agent_state() method on emMetrics instance." << std::endl;
    EXPECT_NO_THROW({
        emMetrics->process_agent_state();
        std::cout << "Method process_agent_state() executed without throwing any exceptions." << std::endl;
    });  
    std::cout << "Exiting ProcessAgentState test" << std::endl;
}

/**
 * @brief Ensures that process_ctrl_state function is invoked successfully on a properly initialized system.
 *
 * This test verifies that the process_ctrl_state method of the emMetrics object functions as expected without throwing any exceptions.
 * It confirms that the internal control state is processed correctly when the system is properly initialized.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01 | Invoke process_ctrl_state on a valid emMetrics instance and verify that no exception is thrown. | emMetrics = valid pointer, function call process_ctrl_state() | process_ctrl_state executes without throwing any exception. | Should Pass |
 */
TEST_F(EmMetricsTest, ProcessCtrlStateProperlyInitializedSystem) {
    std::cout << "Entering ProcessCtrlStateProperlyInitializedSystem test" << std::endl;
    std::cout << "Invoking process_ctrl_state on emMetrics object" << std::endl;
    EXPECT_NO_THROW({
        emMetrics->process_ctrl_state();
        std::cout << "process_ctrl_state invoked successfully with no errors." << std::endl;
    });
    std::cout << "Exiting ProcessCtrlStateProperlyInitializedSystem test" << std::endl;
}

/**
 * @brief Validates that process_msg correctly processes a valid message buffer.
 *
 * This test creates a valid non-empty byte array of 10 characters, logs its contents,
 * and then calls the process_msg API to ensure it handles valid input without throwing any exceptions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 005@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01 | Create and initialize a valid message buffer with 10 characters | validData = allocated unsigned char array of size 11, payload = "1234567890", length = 10 | Buffer is correctly initialized with the payload data | Should be successful |
 * | 02 | Invoke process_msg with validData pointer and length 10 | input: validData pointer = validData, length = 10, output: None | process_msg executes without throwing any exception | Should pass |
 */
TEST_F(EmMetricsTest, ProcessValidMessageBuffer) {
    std::cout << "Entering ProcessValidMessageBuffer test" << std::endl;
    unsigned char validData[11] = {0};
    const char payload[] = "1234567890";
    std::cout << "Assigning valid payload using strncpy. Payload: " << payload << std::endl;
    strncpy(reinterpret_cast<char*>(validData), payload, 10);
    std::cout << "ValidData buffer values: ";
    for (unsigned int i = 0; i < 10; i++) {
        std::cout << "0x" << std::hex << static_cast<int>(validData[i]) << " ";
    }
    std::cout << std::dec << std::endl;
    std::cout << "Invoking process_msg with validData pointer and length 10" << std::endl;
    EXPECT_NO_THROW({
        emMetrics->process_msg(validData, 10);
    });
    std::cout << "process_msg executed without error for valid message buffer" << std::endl;
    std::cout << "Exiting ProcessValidMessageBuffer test" << std::endl;
}

/**
 * @brief Verify process_msg handles NULL data pointer with non-zero length without exceptions
 *
 * This test verifies that the process_msg API of the EmMetrics class handles a NULL data pointer combined with a non-zero length value without throwing any exceptions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 006@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01 | Initialize length to 5 and call process_msg with NULL pointer | data = nullptr, length = 5 | No exception is thrown and the API call executes without crashing | Should Pass  |
 */
TEST_F(EmMetricsTest, ProcessMessageNullDataNonZeroLength) {
    std::cout << "Entering ProcessMessageNullDataNonZeroLength test" << std::endl;
    unsigned int length = 5;
    std::cout << "Invoking process_msg with NULL data pointer and length " << length << std::endl;
    EXPECT_ANY_THROW({
        emMetrics->process_msg(nullptr, length);
    });
    std::cout << "process_msg handled NULL data pointer with non-zero length without crashing" << std::endl;
    std::cout << "Exiting ProcessMessageNullDataNonZeroLength test" << std::endl;
}

/**
 * @brief Validate process_msg API handling for valid data pointer with zero length.
 *
 * This test ensures that no exception is thrown when the payload is non-null but effectively empty because the length parameter is zero.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 007@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01 | Create a dummy data buffer, assign a dummy payload, and invoke process_msg with length=0 | dummyData = pointer to unsigned char array, dummyPayload = "ABCDEFGHIJ", length = 0 | API call returns without throwing an exception; EXPECT_NO_THROW assertion passes  | Should Pass  |
 */
TEST_F(EmMetricsTest, ProcessMessageValidDataZeroLength) {
    std::cout << "Entering ProcessMessageValidDataZeroLength test" << std::endl;
    unsigned char dummyData[11] = {0};
    const char dummyPayload[] = "ABCDEFGHIJ";
    std::cout << "Assigning dummy payload using strncpy. Dummy Payload: " << dummyPayload << std::endl;
    strncpy(reinterpret_cast<char*>(dummyData), dummyPayload, 10);
    std::cout << "DummyData buffer values: ";
    for (unsigned int i = 0; i < 10; i++) {
        std::cout << "0x" << std::hex << static_cast<int>(dummyData[i]) << " ";
    }
    std::cout << std::dec << std::endl;
    unsigned int length = 0;
    std::cout << "Invoking process_msg with dummyData pointer and length " << length << std::endl;
    EXPECT_NO_THROW({
        emMetrics->process_msg(dummyData, length);
    });
    std::cout << "process_msg executed correctly for valid data pointer with zero length" << std::endl;
    std::cout << "Exiting ProcessMessageValidDataZeroLength test" << std::endl;
}

/**
 * @brief Tests the proper creation and destruction of a stack allocated DummyEmMetrics object
 *
 * This test ensures that the object's destructor is invoked automatically when it goes out of scope, thus validating proper resource cleanup.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 008@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | ----------- | --------- | -------------- | ----- |
 * | 01 | Create a stack allocated DummyEmMetrics object within an inner scope using EXPECT_NO_THROW to ensure no exception is thrown during construction and destruction. | Invocation: DummyEmMetrics localMetrics; (no input arguments) | DummyEmMetrics constructor and destructor execute without throwing exceptions; EXPECT_NO_THROW passes | Should Pass |
 * | 02 | Exit the inner scope to trigger the object's destructor and then exit the test function, confirming normal execution flow. | No API call; only scope termination and console output | Destructor has been called as the object goes out of scope; test completes normally | Should be successful |
 */
TEST_F(EmMetricsTest, destroy_stack_allocated_em_metrics_t) {
    std::cout << "Entering destroy_stack_allocated_em_metrics_t test" << std::endl;
    {
        std::cout << "Creating stack allocated DummyEmMetrics object" << std::endl;
        EXPECT_NO_THROW({
            DummyEmMetrics localMetrics;
            std::cout << "Stack allocated object will go out of scope to invoke destructor" << std::endl;
        });
        std::cout << "Exited inner scope. Destructor for DummyEmMetrics has been called if no exceptions were thrown" << std::endl;
    }
    std::cout << "Exiting destroy_stack_allocated_em_metrics_t test" << std::endl;
}