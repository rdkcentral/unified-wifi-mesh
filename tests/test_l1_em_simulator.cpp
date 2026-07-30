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
#include <cstring>
#include "em_simulator.h"

/**
* @brief Test to verify the configuration of the simulator with valid parameters
*
* This test checks if the simulator can be configured correctly using valid parameters. It ensures that the configuration function works as expected when provided with valid input data.@n
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 001@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Initialize parameters and call configure function | dm = {}, params = { {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, 1, { {1, 1, {36}} } } | Configuration should be successful | Should Pass |
*/
TEST(EmSimulatorTest, ConfigureWithValidParameters) {
    std::cout << "Entering ConfigureWithValidParameters" << std::endl;
    em_simulator_t simulator{};
    dm_easy_mesh_agent_t dm{};
    em_scan_params_t params = { {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, 1, { {1, 1, {36}} } };
    simulator.configure(dm, &params);
    std::cout << "Exiting ConfigureWithValidParameters" << std::endl;
}



/**
* @brief Test the configuration of the simulator with null scan parameters.
*
* This test verifies the behavior of the `configure` method when it is provided with null scan parameters. 
* It ensures that the method can handle null input gracefully without causing any unexpected behavior or crashes.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 002@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Initialize the scan parameters to null and configure the simulator | dm = <default>, params = nullptr | No crash or unexpected behavior | Should Pass |
*/
TEST(EmSimulatorTest, ConfigureWithNullScanParameters) {
    std::cout << "Entering ConfigureWithNullScanParameters" << std::endl;
    em_simulator_t simulator{};
    dm_easy_mesh_agent_t dm{};
    em_scan_params_t* params = nullptr;
    simulator.configure(dm, params);
    std::cout << "Exiting ConfigureWithNullScanParameters" << std::endl;
}


/**
* @brief Test the configuration of the simulator with maximum operational classes.
*
* This test verifies that the simulator can be configured with the maximum number of operational classes allowed. It ensures that the configuration process handles the maximum limit correctly without errors.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 003@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Initialize parameters and configure simulator | dm = dm_easy_mesh_agent_t, params = { {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, EM_MAX_OP_CLASS, { {1, 1, {36}}, {2, 1, {40}} } } | Configuration should be successful | Should Pass |
*/
TEST(EmSimulatorTest, ConfigureWithMaxOperationalClasses) {
    std::cout << "Entering ConfigureWithMaxOperationalClasses" << std::endl;
    em_simulator_t simulator{};
    dm_easy_mesh_agent_t dm{};
    em_scan_params_t params = { {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, EM_MAX_OP_CLASS, { {1, 1, {36}}, {2, 1, {40}} } };
    simulator.configure(dm, &params);
    std::cout << "Exiting ConfigureWithMaxOperationalClasses" << std::endl;
}



/**
* @brief Test the configuration of the simulator with an invalid MAC address
*
* This test verifies that the simulator handles the configuration with an invalid MAC address correctly. The objective is to ensure that the system can detect and handle invalid MAC addresses gracefully.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 004@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Initialize the scan parameters with an invalid MAC address | params = { {0x00, 0x11, 0x22, 0x33, 0x44}, 1, { {1, 1, {36}} } } | None | Should be successful |
* | 02| Call the configure method with the invalid MAC address | dm, &params | None | Should Fail |
*/
TEST(EmSimulatorTest, ConfigureWithInvalidMacAddress) {
    std::cout << "Entering ConfigureWithInvalidMacAddress" << std::endl;
    em_simulator_t simulator{};
    dm_easy_mesh_agent_t dm{};
    em_scan_params_t params = { {0x00, 0x11, 0x22, 0x33, 0x44}, 1, { {1, 1, {36}} } };
    simulator.configure(dm, &params);
    std::cout << "Exiting ConfigureWithInvalidMacAddress" << std::endl;
}



/**
* @brief Test the configuration with an invalid number of operational classes
*
* This test verifies that the configuration function handles the case where the number of operational classes exceeds the maximum allowed value. This is important to ensure that the system can gracefully handle invalid input parameters.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 005@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Initialize scan parameters with invalid number of operational classes | params = { {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, EM_MAX_OP_CLASS + 1, { {1, 1, {36}} } } | Should handle invalid input gracefully | Should Pass |
* | 02| Call configure method with invalid scan parameters | em_simulator.configure(dm, &params) | Should handle invalid input gracefully | Should Pass |
*/
TEST(EmSimulatorTest, ConfigureWithInvalidNumOperationalClasses) {
    std::cout << "Entering ConfigureWithInvalidNumOperationalClasses" << std::endl;

    em_simulator_t simulator{};
    dm_easy_mesh_agent_t dm{};

    em_scan_params_t params = { {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, EM_MAX_OP_CLASS + 1, { {1, 1, {36}} } };

    simulator.configure(dm, &params);

    std::cout << "Exiting ConfigureWithInvalidNumOperationalClasses" << std::endl;
}



/**
* @brief Test to configure the simulator with an invalid channel number
*
* This test verifies the behavior of the simulator when it is configured with an invalid channel number. The objective is to ensure that the simulator handles invalid input gracefully and does not crash or behave unexpectedly.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 006@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Initialize scan parameters with invalid channel number | dm = {}, params = { {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, 1, { {1, 1, {255}} } } | Simulator should handle invalid channel number without crashing | Should Pass |
* | 02 | Call configure method with invalid channel number | em_simulator.configure(dm, &params) | No exceptions or crashes, proper handling of invalid input | Should Pass |
*/
TEST(EmSimulatorTest, ConfigureWithInvalidChannelNumber) {
    std::cout << "Entering ConfigureWithInvalidChannelNumber" << std::endl;
    em_simulator_t simulator{};
    dm_easy_mesh_agent_t dm{};
    em_scan_params_t params = { {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, 1, { {1, 1, {255}} } };
    simulator.configure(dm, &params);
    std::cout << "Exiting ConfigureWithInvalidChannelNumber" << std::endl;
}



/**
* @brief Test the configuration of the simulator with the maximum number of channels in the list.
*
* This test verifies that the simulator can be configured with the maximum number of channels in the list without any issues. It ensures that the system can handle the upper limit of channel configurations correctly.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 007@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Initialize the scan parameters with maximum channels | dm_easy_mesh_agent_t dm, em_scan_params_t params = { {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, 1, { {1, EM_MAX_CHANNELS_IN_LIST, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}} } } | Parameters should be initialized successfully | Should be successful |
* | 02 | Configure the simulator with the initialized parameters | em_simulator.configure(dm, &params) | Configuration should be successful | Should Pass |
*/
TEST(EmSimulatorTest, ConfigureWithMaxChannelsInList) {
    std::cout << "Entering ConfigureWithMaxChannelsInList" << std::endl;
    em_simulator_t simulator{};
    dm_easy_mesh_agent_t dm{};
    em_scan_params_t params = { {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, 1, { {1, EM_MAX_CHANNELS_IN_LIST, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}} } };
    simulator.configure(dm, &params);
    std::cout << "Exiting ConfigureWithMaxChannelsInList" << std::endl;
}



/**
* @brief Test the configuration of the simulator with zero operational classes
*
* This test verifies the behavior of the `configure` method in the `em_simulator` class when provided with zero operational classes. The objective is to ensure that the method handles this edge case correctly without errors.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 008@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Initialize parameters | dm_easy_mesh_agent_t dm; em_scan_params_t params = { {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, 0, { {0, 0, {0}} } }; | Parameters initialized | Should be successful |
* | 02 | Call configure method | em_simulator.configure(dm, &params); | Method should execute without errors | Should Pass |
*/
TEST(EmSimulatorTest, ConfigureWithZeroOperationalClasses) {
    std::cout << "Entering ConfigureWithZeroOperationalClasses" << std::endl;
    em_simulator_t simulator{};
    dm_easy_mesh_agent_t dm{};
    em_scan_params_t params = { {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, 0, { {0, 0, {0}} } };
    simulator.configure(dm, &params);
    std::cout << "Exiting ConfigureWithZeroOperationalClasses" << std::endl;
}



/**
* @brief Test the configuration of the EasyMesh agent with a null pointer
*
* This test verifies the behavior of the `em_simulator.configure` method when provided with a null pointer for the EasyMesh agent. This is to ensure that the method handles null pointers gracefully and does not cause unexpected behavior or crashes.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 009@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Initialize EasyMesh agent to null and configure with parameters | dm = nullptr, params = { {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, 1, { {1, 1, {36}} } } | Method should handle null pointer gracefully | Should Fail |
*/
TEST(EmSimulatorTest, ConfigureWithNullEasyMeshAgent) {
    std::cout << "Entering ConfigureWithNullEasyMeshAgent" << std::endl;
    em_simulator_t simulator{};
    dm_easy_mesh_agent_t* dm = nullptr;
    em_scan_params_t params = { {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, 1, { {1, 1, {36}} } };
    simulator.configure(*dm, &params);
    std::cout << "Exiting ConfigureWithNullEasyMeshAgent" << std::endl;
}


/**
* @brief Test to verify the retrieval of command parameters after modifications
*
* This test checks if the command parameters retrieved from the simulator are correctly modified and stored. 
* It ensures that the modifications made to the command parameters are accurately reflected when retrieved again.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 010@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Retrieve few of the command parameters | cmd_params->u.args.num_args, cmd_params->u.args.fixed_args, cmd_params->u.steer_params.request_mode, cmd_params->u.btm_report_params.status_code, cmd_params->u.disassoc_params.num, scan_params.num_op_classes | cmd_params should be retrieved successfully | Should be successful |
*/
TEST(EmSimulatorTest, RetrieveCmdParamsAfterModifications) {
    std::cout << "Entering RetrieveCmdParamsAfterModifications" << std::endl;
    em_simulator_t simulator{};
    em_cmd_params_t* cmd_params = simulator.get_cmd_param();
    std::cout << "num_args: " << cmd_params->u.args.num_args << std::endl;
    std::cout << "fixed_args: " << cmd_params->u.args.fixed_args << std::endl;
    std::cout << "request_mode: " << cmd_params->u.steer_params.request_mode << std::endl;
    std::cout << "btm_report_params.status_code: " << static_cast<int>(cmd_params->u.btm_report_params.status_code) << std::endl;
    std::cout << "disassoc_params.num: " << cmd_params->u.disassoc_params.num << std::endl;
    std::cout << "scan_params.num_op_classes: " << cmd_params->u.scan_params.num_op_classes << std::endl;
    std::cout << "Exiting RetrieveCmdParamsAfterModifications" << std::endl;
}



/**
* @brief Test the run function of em_simulator_t with a properly initialized dm_easy_mesh_agent_t
*
* This test verifies that the run function of the em_simulator_t class works correctly when provided with a properly initialized dm_easy_mesh_agent_t object. The test ensures that the function returns true, indicating successful execution.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 011@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Initialize dm_easy_mesh_agent_t object | dm_easy_mesh_agent_t dm | dm is properly initialized | Should be successful |
* | 02 | Initialize em_simulator_t object | em_simulator_t simulator | simulator is properly initialized | Should be successful |
* | 03 | Call run function with initialized dm | simulator.run(dm) | result = true | Should Pass |
* | 04 | Verify the result | EXPECT_TRUE(result) | result = true | Should Pass |
*/
TEST(EmSimulatorTest, RunWithProperlyInitializedDmEasyMeshAgent) {
    std::cout << "Entering RunWithProperlyInitializedDmEasyMeshAgent test";
    dm_easy_mesh_agent_t dm{};
    em_simulator_t simulator{};
    bool result = simulator.run(dm);
    EXPECT_TRUE(result);
    std::cout << "Exiting RunWithProperlyInitializedDmEasyMeshAgent test";
}



/**
* @brief Test to verify the behavior of the simulator when run with an invalid configuration.
*
* This test checks if the simulator correctly handles an invalid configuration by returning false. This is important to ensure that the simulator does not proceed with invalid settings, which could lead to undefined behavior or crashes.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 012@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Initialize invalid configuration | dm_easy_mesh_agent_t dm; dm.m_device.intf.mac = {0xFA, 0xFB, 0xFC, 0x00, 0x00, 0x00} | dm is invalid | Should be successful |
* | 02 | Initialize simulator | em_simulator_t simulator; | simulator initialized | Should be successful |
* | 03 | Run simulator with invalid configuration | result = simulator.run(dm); | result = false | Should Pass |
* | 04 | Check result | EXPECT_FALSE(result); | result is false | Should Pass |
*/
TEST(EmSimulatorTest, RunWithInvalidConfiguration) {
    std::cout << "Entering RunWithInvalidConfiguration test";
    dm_easy_mesh_agent_t dm{};
    unsigned char invalid_mac[6] = {0xFA, 0xFB, 0xFC, 0x00, 0x00, 0x00};
    memcpy(dm.m_device.m_device_info.intf.mac, invalid_mac, sizeof(invalid_mac));
    em_simulator_t simulator{};
    bool result = simulator.run(dm);
    EXPECT_FALSE(result);
    std::cout << "Exiting RunWithInvalidConfiguration test";
}

/**
 * @brief Validate construction of em_simulator_t through API invocation
 *
 * This test validates that instantiation of the em_simulator_t object using its default constructor does not throw any exceptions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 013@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke em_simulator_t constructor within EXPECT_NO_THROW block | input: None | Constructor call completes without throwing exceptions | Should Pass |
 */
TEST(EmSimulatorTest, ValidConstructionOf_em_simulator_t)
{
    std::cout << "Entering ValidConstructionOf_em_simulator_t test" << std::endl;
    
    EXPECT_NO_THROW({
        std::cout << "Invoking em_simulator_t constructor." << std::endl;
        em_simulator_t simulator{};
        std::cout << "Constructor invoked successfully." << std::endl;
    });
    
    std::cout << "Exiting ValidConstructionOf_em_simulator_t test" << std::endl;
}

/**
 * @brief Test the destructor cleans up a em_simulator_t instance without throwing exceptions.
 *
 * The test verifies that a fully initialized instance of em_simulator_t, is properly cleaned up when it goes out of scope, and its destructor does not throw any exceptions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 014@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**  
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create an instance using the default constructor and allow the instance to go out of scope to trigger the destructor. | input: default constructor invocation; output: destructor invocation | The destructor completes without throwing any exceptions and cleans up the instance successfully. | Should Pass |
 */
TEST(EmSimulatorTest, Destructor_cleans_up_a_fully_initialized_em_simulator_t_instance) {
    std::cout << "Entering Destructor_cleans_up_a_fully_initialized_em_simulator_t_instance test" << std::endl;
    
    // Create the em_simulator_t instance using the default constructor.
    EXPECT_NO_THROW({
        {
            std::cout << "Invoking em_simulator_t default constructor." << std::endl;
            em_simulator_t instance{};
            std::cout << "em_simulator_t instance created successfully." << std::endl;            
            // Destructor will be invoked when 'instance' goes out of scope.
            std::cout << "About to exit internal block; destructor of em_simulator_t will be invoked." << std::endl;
        }
        std::cout << "em_simulator_t instance has been destroyed; destructor invocation should have completed without exception." << std::endl;
    });
    
    std::cout << "Exiting Destructor_cleans_up_a_fully_initialized_em_simulator_t_instance test" << std::endl;
}
