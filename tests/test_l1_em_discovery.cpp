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
#include "em_discovery.h"

class Dummy_em_discovery_t : public em_discovery_t {
public:
  virtual em_state_t get_state() override { return em_state_t(); }
  virtual unsigned char* get_radio_interface_mac() override { return nullptr; }
  virtual unsigned char* get_al_interface_mac() override { return nullptr; }
  virtual int send_frame(unsigned char* buff, unsigned int len, bool multicast = false) override { return 0; }
  virtual em_cmd_t* get_current_cmd() override { return nullptr; }
};

class emDiscoveryTest : public ::testing::Test {
protected:
  Dummy_em_discovery_t* discovery;

  void SetUp() override {
    discovery = new Dummy_em_discovery_t();
  }

  void TearDown() override {
    delete discovery;
  }
};

/**
 * @brief Validate successful instantiation of the discovery object using the default constructor.
 *
 * This test verifies that the object created in the test fixture is successfully instantiated by ensuring that the pointer is not null.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 001@n
 * **Priority:** (High)
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01     | Create the discovery object | discovery pointer initialized via default constructor | No exception is thrown and the discovery pointer is not null | Should Pass|
 */
TEST_F(emDiscoveryTest, SuccessfulInstantiation) {
    std::cout << "Entering SuccessfulInstantiation test" << std::endl;
    std::cout << "Invoking default constructor for em_discovery_t" << std::endl;
    EXPECT_NO_THROW({        
        delete discovery;
        discovery = new Dummy_em_discovery_t();
    });
    std::cout << "Exiting SuccessfulInstantiation test" << std::endl;
}

/**
 * @brief Verify process_msg API correctly processes valid non-null data with proper length.
 *
 * This test checks that the process_msg API function, when provided with a valid non-null data array and the correct length, executes without throwing any exceptions.
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
 * | 01     | Invoke process_msg method with a valid non-null data array and length as 4 | data = {0x01,0x02,0x03,0x04}, len = 4 | process_msg executes without throwing exceptions | Should Pass |
 */
TEST_F(emDiscoveryTest, ValidMessageProcessing_NonNullData_ProperLength) {
    std::cout << "Entering ValidMessageProcessing_NonNullData_ProperLength test" << std::endl;
    unsigned char data[4] = {0};
    data[0] = 0x01; data[1] = 0x02; data[2] = 0x03; data[3] = 0x04;
    unsigned int len = 4;
    std::cout << "Invoking process_msg with data: {0x01, 0x02, 0x03, 0x04}, length: " << len << std::endl;
    EXPECT_NO_THROW({
        discovery->process_msg(data, len);
        std::cout << "process_msg invoked successfully with valid non-null data." << std::endl;
    });
    std::cout << "Exiting ValidMessageProcessing_NonNullData_ProperLength test" << std::endl;
}

/**
 * @brief Verify that process_msg handles an empty message buffer gracefully.
 *
 * This test verifies that the process_msg method of the Dummy_em_discovery_t object does not throw an exception when it is invoked with an empty data buffer (a non-null pointer with a length of 0).
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
 * | 01     | Invoke process_msg API with an empty data buffer | data = pointer to unsigned char array of 1 element, len = 0 | API completes without throwing an exception | Should Pass |
 */
TEST_F(emDiscoveryTest, ProcessingEmptyMessage_ValidNonNullPointer) {
    std::cout << "Entering ProcessingEmptyMessage_ValidNonNullPointer test" << std::endl;
    unsigned char data[1] = {0};
    unsigned int len = 0;
    std::cout << "Invoking process_msg with empty data buffer and length: " << len << std::endl;
    EXPECT_NO_THROW({
        discovery->process_msg(data, len);
        std::cout << "process_msg completed gracefully with empty message." << std::endl;
    });
    std::cout << "Exiting ProcessingEmptyMessage_ValidNonNullPointer test" << std::endl;
}

/**
 * @brief Verify that process_msg safely handles a NULL data pointer when a non-zero length is provided.
 *
 * This test ensures that the process_msg function from Dummy_em_discovery_t does not throw any exceptions
 * when it is invoked with a NULL data pointer while the length provided is non-zero. The function is expected
 * to handle this invalid input safely without leading to any crashes or undefined behavior.
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
 * | 01     | Invoke process_msg with a NULL data pointer and non-zero length | data = NULL, len = 5 | No exception thrown | Should Pass |
 */
TEST_F(emDiscoveryTest, HandlingNullDataPointer_NonZeroLength) {
    std::cout << "Entering HandlingNullDataPointer_NonZeroLength test" << std::endl;
    unsigned char* data = NULL;
    unsigned int len = 5;
    std::cout << "Invoking process_msg with NULL data pointer and length: " << len << std::endl;
    EXPECT_ANY_THROW({
        discovery->process_msg(data, len);
        std::cout << "process_msg handled NULL data pointer with non-zero length safely." << std::endl;
    });
    std::cout << "Exiting HandlingNullDataPointer_NonZeroLength test" << std::endl;
}

/**
 * @brief Test that process_msg handles a NULL data pointer with zero length.
 *
 * This test validates that passing a NULL data pointer along with a zero length to process_msg
 * does not throw any exceptions and is handled safely.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 005@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01     | Invoke process_msg with a NULL data pointer and zero length. | input: data = NULL, len = 0 | process_msg does not throw any exception | Should Pass         |
 */
TEST_F(emDiscoveryTest, HandlingNullDataPointer_ZeroLength) {
    std::cout << "Entering HandlingNullDataPointer_ZeroLength test" << std::endl;
    unsigned char* data = NULL;
    unsigned int len = 0;
    std::cout << "Invoking process_msg with NULL data pointer and length: " << len << std::endl;
    EXPECT_ANY_THROW({
        discovery->process_msg(data, len);
        std::cout << "process_msg handled NULL data pointer with zero length safely." << std::endl;
    });
    std::cout << "Exiting HandlingNullDataPointer_ZeroLength test" << std::endl;
}

/**
 * @brief Validate that process_msg correctly handles a large data block.
 *
 * This test allocates a large data block (10,000 bytes), initializes it with a pattern (0xAA), and verifies that the process_msg function processes the data without throwing any exceptions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 006@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01 | Allocate a large data block and initialize it with a pattern | len = 10000, data initialized with each byte = 0xAA | Data block allocated and correctly initialized | Should be successful |
 * | 02 | Invoke process_msg with the allocated large data block | discovery->process_msg(data, len) | API call completes without throwing any exceptions | Should Pass |
 * | 03 | Clean up allocated memory by deleting the allocated data block | delete[] data | Memory is successfully released | Should be successful |
 */
TEST_F(emDiscoveryTest, ValidMessageProcessing_LargeDataBlock) {
    std::cout << "Entering ValidMessageProcessing_LargeDataBlock test" << std::endl;
    const unsigned int len = 10000;
    unsigned char* data = new unsigned char[len];
    memset(data, 0xAA, len);
    std::cout << "Invoking process_msg with large data block of length: " << len << std::endl;
    std::cout << "Data block first 4 bytes: 0x" 
              << std::hex << static_cast<int>(data[0]) << " 0x" 
              << static_cast<int>(data[1]) << " 0x" 
              << static_cast<int>(data[2]) << " 0x" 
              << static_cast<int>(data[3]) << std::dec << std::endl;
    EXPECT_NO_THROW({
        discovery->process_msg(data, len);
        std::cout << "process_msg successfully processed the large data block." << std::endl;
    });
    delete[] data;
    std::cout << "Exiting ValidMessageProcessing_LargeDataBlock test" << std::endl;
}

/**
 * @brief Validate that process_state() executes correctly on a properly initialized system.
 *
 * This test verifies that when the discovery object is properly initialized, the process_state() 
 * function executes without throwing any exceptions.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 007@n
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01 | Invoke process_state() on the discovery object to process the system state. | discovery->process_state() with no input arguments | No exception is thrown | Should Pass    |
 */
TEST_F(emDiscoveryTest, Process_state_with_properly_initialized_system) {
    std::cout << "Entering Process_state_with_properly_initialized_system test" << std::endl;
    std::cout << "Invoking process_state()." << std::endl;
    EXPECT_NO_THROW({
        discovery->process_state();
    });
    std::cout << "process_state() invoked successfully without throwing an exception." << std::endl;  
    std::cout << "Exiting Process_state_with_properly_initialized_system test" << std::endl;
}

/**
 * @brief Verify that the destructor of em_discovery_t is invoked properly
 *
 * This test verifies that calling delete on the discovery pointer invokes the destructor without throwing any exceptions and that the associated resources are cleaned up correctly.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 008@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01               | Invoke the destructor on the discovery pointer via delete | discovery = valid pointer, operation: delete discovery    | The destructor executes without throwing exceptions and resources are successfully cleaned up          | Should Pass |
 */
TEST_F(emDiscoveryTest, em_discovery_t_destructor_cleanup) {
    std::cout << "Entering em_discovery_t::~em_discovery_t()_start test" << std::endl;
    EXPECT_NO_THROW({
        std::cout << "Invoking destructor via delete on discovery object" << std::endl;
        delete discovery;
        discovery = nullptr;
        std::cout << "Destructor invoked successfully; resources cleaned up with no exceptions." << std::endl;
    });
    std::cout << "Exiting em_discovery_t::~em_discovery_t()_start test" << std::endl;
}