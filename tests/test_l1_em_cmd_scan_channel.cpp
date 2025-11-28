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
#include "em_cmd_scan_channel.h"



/**
 * @brief Validate the construction and initialization of em_cmd_scan_channel_t with typical parameters.
 *
 * This test ensures that the em_cmd_scan_channel_t API properly initializes its command parameters based on the provided input. The test validates that the fixed arguments, operational parameters, command type, service type, and orchestration details are correctly set in the constructed object, ensuring overall integrity of command creation functionality.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize test parameters and set fixed_args | params.u.args.fixed_args = "SCAN_TEST" | The fixed_args field in params is correctly populated with "SCAN_TEST" | Should be successful |
 * | 02 | Invoke em_cmd_scan_channel_t constructor and verify initialization | input: fixed_args = "SCAN_TEST", num_channels = 5; output: m_param.u.args.fixed_args, m_param.u.scan_params.op_class[0].num_channels, m_type, m_name, m_svc, m_orch_op_idx, m_num_orch_desc, m_orch_desc, m_data_model.m_cmd_ctx.type | All cmd object fields match the expected values; fixed_args equals "SCAN_TEST", num_channels equals 5, command type equals em_cmd_type_scan_channel, name equals "scan_channel", service type equals em_service_type_ctrl, and orchestration details are set correctly | Should Pass |
 * | 03 | Call deinit method to clean up the command object | No input data | deinit executes without errors and cleans up resources | Should Pass |
 */
TEST(em_cmd_scan_channel_t, em_cmd_scan_channel_t_valid_typical_parameters)
{
    std::cout << "Entering em_cmd_scan_channel_t_valid_typical_parameters test" << std::endl;
    em_cmd_params_t params;
    const char *testFixedArgs = "SCAN_TEST";
    strncpy(params.u.args.fixed_args, testFixedArgs, sizeof(params.u.args.fixed_args)-1);
    params.u.args.fixed_args[sizeof(params.u.args.fixed_args)-1] = '\0';
    params.u.scan_params.op_class[0].num_channels = 5;
    dm_easy_mesh_t dm;
    em_cmd_scan_channel_t cmd(params, dm);
    std::cout << "Invoked em_cmd_scan_channel_t with fixed_args: " << params.u.args.fixed_args << std::endl;
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "SCAN_TEST");
    EXPECT_EQ(cmd.m_param.u.scan_params.op_class[0].num_channels, 5);
    EXPECT_EQ(cmd.m_type, em_cmd_type_scan_channel);
    EXPECT_STREQ(cmd.m_name, "scan_channel");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 1);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_channel_scan_req);
    EXPECT_TRUE(cmd.m_orch_desc[0].submit);
    EXPECT_EQ(cmd.m_data_model.m_cmd_ctx.type, dm_orch_type_channel_scan_req);
    cmd.deinit();
    std::cout << "Exiting em_cmd_scan_channel_t_valid_typical_parameters test" << std::endl;
}
/**
 * @brief Validate em_cmd_scan_channel_t initialization with valid boundary parameters.
 *
 * This test verifies that the em_cmd_scan_channel_t API correctly initializes its parameters 
 * using valid boundary values. The test ensures that the command object accurately sets its internal 
 * parameters such as fixed argument string, number of channels, command type, service type, and 
 * orchestrator details when provided with boundary (minimal) input values.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 002
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                | Test Data                                                                                                          | Expected Result                                                                                                 | Notes               |
 * | :--------------: | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------- | ------------------- |
 * | 01               | Initialize parameters with boundary values.                                                | params.u.args.num_args = 0, params.u.args.fixed_args = "", params.u.scan_params.op_class[0].num_channels = 0         | Parameter structure is initialized with the provided boundary values.                                          | Should be successful|
 * | 02               | Instantiate the em_cmd_scan_channel_t command object using the initialized parameters.       | Input: params structure and dm instance                                                                            | Command object is created and assigns the boundary values correctly.                                           | Should Pass         |
 * | 03               | Validate the command object's properties via assertions.                                   | Expected outputs: fixed_args as "", num_channels as 0, m_type as em_cmd_type_scan_channel, m_name as "scan_channel", m_svc as em_service_type_ctrl, etc. | All assertions pass confirming that the object's properties match the expected configuration for boundary parameters. | Should Pass         |
 * | 04               | Call deinit() to clean up the command object's resources.                                  | Command object: cmd (invoking cmd.deinit())                                                                          | Resources are cleaned up successfully without issues.                                                          | Should be successful|
 */
TEST(em_cmd_scan_channel_t, em_cmd_scan_channel_t_valid_boundary_parameters)
{
    std::cout << "Entering em_cmd_scan_channel_t_valid_boundary_parameters test" << std::endl;
    em_cmd_params_t params;
    params.u.args.num_args = 0;
    strncpy(params.u.args.fixed_args, "", sizeof(params.u.args.fixed_args)-1);
    params.u.args.fixed_args[sizeof(params.u.args.fixed_args)-1] = '\0';
    params.u.scan_params.op_class[0].num_channels = 0;
    dm_easy_mesh_t dm;
    std::cout << "Invoking em_cmd_scan_channel_t with fixed_args: \"" << params.u.args.fixed_args << "\"" << std::endl;
    em_cmd_scan_channel_t cmd(params, dm);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "");
    EXPECT_EQ(cmd.m_param.u.scan_params.op_class[0].num_channels, 0);
    EXPECT_EQ(cmd.m_type, em_cmd_type_scan_channel);
    EXPECT_STREQ(cmd.m_name, "scan_channel");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 1);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_channel_scan_req);
    EXPECT_TRUE(cmd.m_orch_desc[0].submit);
    EXPECT_EQ(cmd.m_data_model.m_cmd_ctx.type, dm_orch_type_channel_scan_req);
    cmd.deinit();
    std::cout << "Exiting em_cmd_scan_channel_t_valid_boundary_parameters test" << std::endl;
}
/**
 * @brief Test the em_cmd_scan_channel_t constructor with maximum fixed and argument string lengths.
 *
 * This test verifies that the em_cmd_scan_channel_t constructor populates the command object correctly when provided with maximum permitted fixed arguments and argument strings. The test sets the fixed_args and args buffer with maximal allowed characters and validates that all the fields in the resulting object are correctly initialized. This ensures that the class handles boundary conditions for input parameters.
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
 * | Variation / Step | Description                                                                                   | Test Data                                                                                                                                                           | Expected Result                                                                                                              | Notes          |
 * | :--------------: | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- | -------------- |
 * | 01               | Initialize test parameters with maximum allowed values for fixed_args and args array           | fixed_args = maxStr (128 characters, 'X'), num_args = 5, args[0] = maxArg (128 characters, 'Y')                                                                     | Parameters are properly set with the specified max values                                                                   | Should be successful |
 * | 02               | Invoke the constructor of em_cmd_scan_channel_t using the initialized parameters              | Input: em_cmd_params_t param, dm_easy_mesh_t dm                                                                                                                     | em_cmd_scan_channel_t object is created with fields set based on input parameters                                             | Should Pass    |
 * | 03               | Validate the initialized object fields through assertions                                     | Output comparisons: num_args check, fixed_args string, args[0] string, and other related field values of the created object                                             | All assertions pass verifying that the object's fields match the expected values and types                                   | Should Pass    |
 */
TEST(em_cmd_scan_channel_t, em_cmd_scan_channel_t_ctor_max_fixed_args)
{
    std::cout << "Entering em_cmd_scan_channel_t_ctor_max_fixed_args test" << std::endl;
    em_cmd_params_t param{};
    char maxStr[128];
    memset(maxStr, 'X', sizeof(maxStr) - 1);
    maxStr[sizeof(maxStr) - 1] = '\0';
    strncpy(param.u.args.fixed_args, maxStr, sizeof(param.u.args.fixed_args) - 1);
    param.u.args.fixed_args[sizeof(param.u.args.fixed_args) - 1] = '\0';
    param.u.args.num_args = 5;
    char maxArg[128];
    memset(maxArg, 'Y', sizeof(maxArg) - 1);
    maxArg[sizeof(maxArg) - 1] = '\0';
    strncpy(param.u.args.args[0], maxArg, sizeof(param.u.args.args[0]) - 1);
    param.u.args.args[0][sizeof(param.u.args.args[0]) - 1] = '\0';
    dm_easy_mesh_t dm;
    std::cout << "Invoking em_cmd_scan_channel_t with fixed_args: " << param.u.args.fixed_args << std::endl;
    em_cmd_scan_channel_t cmd(param, dm);
    EXPECT_EQ(cmd.m_param.u.args.num_args, 5);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, param.u.args.fixed_args);
    EXPECT_STREQ(cmd.m_param.u.args.args[0], param.u.args.args[0]);
    EXPECT_EQ(cmd.m_type, em_cmd_type_scan_channel);
    EXPECT_STREQ(cmd.m_name, "scan_channel");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 1);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_channel_scan_req);
    EXPECT_TRUE(cmd.m_orch_desc[0].submit);
    EXPECT_EQ(cmd.m_data_model.m_cmd_ctx.type, dm_orch_type_channel_scan_req);
    cmd.deinit();
    std::cout << "Exiting em_cmd_scan_channel_t_ctor_max_fixed_args test" << std::endl;
}
