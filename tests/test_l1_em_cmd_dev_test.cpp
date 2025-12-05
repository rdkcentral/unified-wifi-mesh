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
#include "em_cmd_dev_test.h"



/**
 * @brief Validate that em_cmd_dev_test_t is constructed properly with valid parameters
 *
 * This test verifies that the em_cmd_dev_test_t constructor correctly initializes all object members when provided with valid parameters. The test checks the type, name, service type, fixed_args, num_args, and the orchestration descriptor values. This ensures that the object is instantiated as expected for further processing in the module.
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
 * | Variation / Step | Description                                                                              | Test Data                                                                                                              | Expected Result                                                                                                                                                 | Notes       |
 * | :--------------: | ---------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
 * | 01               | Initialize parameters, invoke constructor, and validate object members                   | param.u.args.fixed_args = DeviceTest, param.u.args.num_args = 1, dm.m_network.m_net_info.id = NetConfig01, dm.m_device.m_device_info.manufacturer = TestManufacturer | m_type equals em_cmd_type_dev_test, m_name equals "dev_test", m_svc equals em_service_type_ctrl, fixed_args equals "DeviceTest", num_args equals 1, m_orch_desc[0].op equals dm_orch_type_db_cfg, m_orch_desc[0].submit equals false | Should Pass |
 */
TEST(em_cmd_dev_test_t, em_cmd_dev_test_t_valid_parameters)
{
    std::cout << "Entering em_cmd_dev_test_t_valid_parameters test" << std::endl;
    em_cmd_params_t param{};
    strncpy(param.u.args.fixed_args, "DeviceTest", sizeof(param.u.args.fixed_args));
    param.u.args.fixed_args[sizeof(param.u.args.fixed_args)-1] = '\0';
    param.u.args.num_args = 1;
    dm_easy_mesh_t dm{};
    strncpy(dm.m_network.m_net_info.id, "NetConfig01", sizeof(dm.m_network.m_net_info.id));
    dm.m_network.m_net_info.id[sizeof(dm.m_network.m_net_info.id)-1] = '\0';
    strncpy(dm.m_device.m_device_info.manufacturer, "TestManufacturer", sizeof(dm.m_device.m_device_info.manufacturer));
    dm.m_device.m_device_info.manufacturer[sizeof(dm.m_device.m_device_info.manufacturer)-1] = '\0';
    std::cout << "Invoking constructor..." << std::endl;
    em_cmd_dev_test_t cmd(param, dm);
    EXPECT_EQ(cmd.m_type, em_cmd_type_dev_test);
    EXPECT_STREQ(cmd.m_name, "dev_test");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "DeviceTest");
    EXPECT_EQ(cmd.m_param.u.args.num_args, 1);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_db_cfg);
    EXPECT_FALSE(cmd.m_orch_desc[0].submit);
    cmd.deinit();
    std::cout << "Exiting em_cmd_dev_test_t_valid_parameters test" << std::endl;
}
/**
 * @brief Validate device test command initialization with empty parameters.
 *
 * This test verifies that the em_cmd_dev_test_t object is initialized correctly when provided with empty parameters.
 * It checks that the command type, name, service, parameter arguments, and orchestration descriptor fields match the expected defaults.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize em_cmd_params_t structure with empty arguments. | param.u.args.fixed_args = '\0', param.u.args.num_args = 0 | Parameter structure is properly initialized with empty values. | Should be successful |
 * | 02 | Instantiate dm_easy_mesh_t and create em_cmd_dev_test_t object. | Input: param (with empty arguments), dm (default instance) | Command object is created successfully with provided configuration. | Should Pass |
 * | 03 | Validate command object's fields for correct initialization. | m_type = em_cmd_type_dev_test, m_name = "dev_test", m_svc = em_service_type_ctrl, m_param.u.args.fixed_args = "", m_param.u.args.num_args = 0, m_orch_desc[0].op = dm_orch_type_db_cfg, m_orch_desc[0].submit = false | All command fields exactly match expected values. | Should Pass |
 * | 04 | Deinitialize the command object by calling deinit(). | Invocation of cmd.deinit() | Resources are released and object is deinitialized correctly without error. | Should be successful |
 */
TEST(em_cmd_dev_test_t, em_cmd_dev_test_t_empty_parameters)
{
    std::cout << "Entering em_cmd_dev_test_t_empty_parameters test" << std::endl;
    em_cmd_params_t param{};
    param.u.args.fixed_args[0] = '\0';
    param.u.args.num_args = 0;
    dm_easy_mesh_t dm{};
    em_cmd_dev_test_t cmd(param, dm);
    EXPECT_EQ(cmd.m_type, em_cmd_type_dev_test);
    EXPECT_STREQ(cmd.m_name, "dev_test");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "");
    EXPECT_EQ(cmd.m_param.u.args.num_args, 0);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_db_cfg);
    EXPECT_FALSE(cmd.m_orch_desc[0].submit);
    cmd.deinit();
    std::cout << "Exiting em_cmd_dev_test_t_empty_parameters test" << std::endl;
}
/**
 * @brief Verify that the device test command correctly handles maximum length fixed arguments
 *
 * This test verifies that when a maximum length string is provided for the fixed arguments field in the command parameters,
 * the command object initializes and stores the string correctly. It checks that all associated attributes such as command type,
 * name, service, and orchestration descriptor are properly set in the command after initialization.
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
 * | Variation / Step | Description                                                                                                  | Test Data                                                                                                                                                                                                                                                                        | Expected Result                                                                                                                                                                                                                                               | Notes      |
 * | :--------------: | ------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
 * | 01               | Set a maximum length fixed argument string, initialize parameters and device test command, then verify attributes. | param.u.args.fixed_args = "A" repeated 127 times, num_args = 2, dm.m_network.m_net_info.id = "MaxLenNetwork", dm.m_device.m_device_info.manufacturer = "MaxLenManufacturer"                                                                                                    | cmd.m_type equals em_cmd_type_dev_test, cmd.m_name equals "dev_test", cmd.m_svc equals em_service_type_ctrl, cmd.m_param.u.args.fixed_args matches the maximum length string, cmd.m_param.u.args.num_args equals 2, and cmd.m_orch_desc[0].op equals dm_orch_type_db_cfg with cmd.m_orch_desc[0].submit false | Should Pass |
 */
TEST(em_cmd_dev_test_t, em_cmd_dev_test_t_max_length_fixed_args)
{
    std::cout << "Entering em_cmd_dev_test_t_max_length_fixed_args test" << std::endl;
    em_cmd_params_t param{};
    char maxStr[128] = {0};
    for (int i = 0; i < 127; ++i) {
        maxStr[i] = 'A';
    }
    maxStr[127] = '\0';
    strncpy(param.u.args.fixed_args, maxStr, sizeof(param.u.args.fixed_args));
    param.u.args.fixed_args[sizeof(param.u.args.fixed_args)-1] = '\0';
    param.u.args.num_args = 2;
    dm_easy_mesh_t dm{};
    strncpy(dm.m_network.m_net_info.id, "MaxLenNetwork", sizeof(dm.m_network.m_net_info.id));
    dm.m_network.m_net_info.id[sizeof(dm.m_network.m_net_info.id)-1] = '\0';
    strncpy(dm.m_device.m_device_info.manufacturer, "MaxLenManufacturer", sizeof(dm.m_device.m_device_info.manufacturer));
    dm.m_device.m_device_info.manufacturer[sizeof(dm.m_device.m_device_info.manufacturer)-1] = '\0';
    em_cmd_dev_test_t cmd(param, dm);
    EXPECT_EQ(cmd.m_type, em_cmd_type_dev_test);
    EXPECT_STREQ(cmd.m_name, "dev_test");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, maxStr);
    EXPECT_EQ(cmd.m_param.u.args.num_args, 2);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_db_cfg);
    EXPECT_FALSE(cmd.m_orch_desc[0].submit);
    cmd.deinit();
    std::cout << "Exiting em_cmd_dev_test_t_max_length_fixed_args test" << std::endl;
}
/**
 * @brief Validates that the command object is correctly initialized with arbitrary valid input data.
 *
 * This test checks that the em_cmd_dev_test_t object is properly constructed with a given set of valid inputs.
 * The test verifies that the object's type, name, service type, arguments data, and orchestrator descriptor are
 * correctly set according to predefined expectations. Additionally, it ensures that deinitialization is successfully
 * performed.
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
 * | Variation / Step | Description                                                                                           | Test Data                                                                                                                                                                  | Expected Result                                                                                                                 | Notes           |
 * | :--------------: | ----------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | --------------- |
 * | 01               | Print entering message to stdout.                                                                     | N/A                                                                                                                                                                        | "Entering em_cmd_dev_test_t_arbitrary_valid_data test" printed to stdout.                                                      | Should be successful |
 * | 02               | Initialize the command parameters structure.                                                        | em_cmd_params_t param initialized to default values.                                                                                                                       | param is successfully created with default values.                                                                            | Should be successful |
 * | 03               | Set arbitrary string and number of arguments in the parameters.                                       | fixed_args = "Abc123!@#_TestData", num_args = 3                                                                                                                             | param.u.args.fixed_args equals "Abc123!@#_TestData" and num_args equals 3.                                                       | Should Pass     |
 * | 04               | Initialize the network structure with a network ID.                                                 | dm.m_network.m_net_info.id = "ArbitraryNetwork"                                                                                                                             | dm.m_network.m_net_info.id is set to "ArbitraryNetwork".                                                                         | Should be successful |
 * | 05               | Create command object with parameters and validate its fields.                                      | Input: param with fixed_args and num_args, dm with network ID; Output: m_type = em_cmd_type_dev_test, m_name = "dev_test", m_svc = em_service_type_ctrl, fixed_args, num_args, orch_desc[0].op = dm_orch_type_db_cfg, orch_desc[0].submit = false | All EXPECT assertions pass validating m_type, m_name, m_svc, fixed_args, num_args, and orch_desc descriptor values.               | Should Pass     |
 * | 06               | Deinitialize the command object.                                                                    | Invocation: cmd.deinit()                                                                                                                                                     | deinit executed without error.                                                                                                  | Should Pass     |
 * | 07               | Print exit message to stdout.                                                                       | N/A                                                                                                                                                                        | "Exiting em_cmd_dev_test_t_arbitrary_valid_data test" printed to stdout.                                                       | Should be successful |
 */
TEST(em_cmd_dev_test_t, em_cmd_dev_test_t_arbitrary_valid_data)
{
    std::cout << "Entering em_cmd_dev_test_t_arbitrary_valid_data test" << std::endl;
    em_cmd_params_t param{};
    const char* arbitraryStr = "Abc123!@#_TestData";
    strncpy(param.u.args.fixed_args, arbitraryStr, sizeof(param.u.args.fixed_args));
    param.u.args.fixed_args[sizeof(param.u.args.fixed_args)-1] = '\0';
    param.u.args.num_args = 3;
    dm_easy_mesh_t dm{};
    strncpy(dm.m_network.m_net_info.id, "ArbitraryNetwork", sizeof(dm.m_network.m_net_info.id));
    dm.m_network.m_net_info.id[sizeof(dm.m_network.m_net_info.id)-1] = '\0';
    em_cmd_dev_test_t cmd(param, dm);
    EXPECT_EQ(cmd.m_type, em_cmd_type_dev_test);
    EXPECT_STREQ(cmd.m_name, "dev_test");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, arbitraryStr);
    EXPECT_EQ(cmd.m_param.u.args.num_args, 3);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_db_cfg);
    EXPECT_FALSE(cmd.m_orch_desc[0].submit);
    cmd.deinit();
    std::cout << "Exiting em_cmd_dev_test_t_arbitrary_valid_data test" << std::endl;
}
