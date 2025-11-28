
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
#include "em_cmd_scan_result.h"



/**
 * @brief Test initialization of em_cmd_scan_result_t object with valid parameters
 *
 * This test verifies that the em_cmd_scan_result_t constructor correctly initializes the object fields using the provided parameters and environment. It sets specific values for fixed_args and num_channels, then uses assertions to check that these values and other object attributes are properly initialized.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize test parameters, set fixed_args to "TestFixedArgsValue" and op_class[0].num_channels to 5 | params.u.args.fixed_args = "TestFixedArgsValue", params.u.scan_params.op_class[0].num_channels = 5 | Parameters structure is initialized with the expected values | Should be successful |
 * | 02 | Instantiate dm_easy_mesh_t and prepare for object construction | dm_easy_mesh_t instance created, no input arguments required | dm instance is successfully created | Should be successful |
 * | 03 | Construct em_cmd_scan_result_t object with the prepared parameters and dm instance | Input: params (with fixed_args = "TestFixedArgsValue", num_channels = 5), dm instance; Output: cmd object initialized | Object fields: m_param.u.args.fixed_args equals "TestFixedArgsValue", m_param.u.scan_params.op_class[0].num_channels equals 5, m_type equals em_cmd_type_scan_result, m_name equals "scan_result", m_svc equals em_service_type_ctrl, m_orch_op_idx equals 0, m_num_orch_desc equals 1, m_orch_desc[0].op equals dm_orch_type_channel_scan_res, m_orch_desc[0].submit is true, m_data_model.m_cmd_ctx.type equals dm_orch_type_channel_scan_res | Should Pass |
 * | 04 | Deinitialize the em_cmd_scan_result_t object using deinit() | Invocation of cmd.deinit(), no additional test data | Resources are released and deinitialization completes without error | Should be successful |
 */
TEST(em_cmd_scan_result_t, em_cmd_scan_result_t_valid_initialization) {
    std::cout << "Entering em_cmd_scan_result_t_valid_initialization test" << std::endl;
    em_cmd_params_t params;
    memset(&params, 0, sizeof(em_cmd_params_t));
    const char testFixedArgs[] = "TestFixedArgsValue";
    params.u.scan_params.op_class[0].num_channels = 5;
    strncpy(params.u.args.fixed_args, testFixedArgs, sizeof(params.u.args.fixed_args) - 1);
    params.u.args.fixed_args[sizeof(params.u.args.fixed_args) - 1] = '\0';
    dm_easy_mesh_t dm;
    std::cout << "dm_easy_mesh_t instance created." << std::endl;
    std::cout << "Invoking constructor with parameters set with fixed_args value: " << params.u.args.fixed_args << std::endl;
    em_cmd_scan_result_t cmd(params, dm);
    std::cout << "em_cmd_scan_result_t object constructed successfully." << std::endl;
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "TestFixedArgsValue");
    EXPECT_EQ(cmd.m_param.u.scan_params.op_class[0].num_channels, 5);
    EXPECT_EQ(cmd.m_type, em_cmd_type_scan_result);
    EXPECT_STREQ(cmd.m_name, "scan_result");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 1);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_channel_scan_res);
    EXPECT_TRUE(cmd.m_orch_desc[0].submit);
    EXPECT_EQ(cmd.m_data_model.m_cmd_ctx.type, dm_orch_type_channel_scan_res);
    cmd.deinit();
    std::cout << "Exiting em_cmd_scan_result_t_valid_initialization test" << std::endl;
}
/**
 * @brief Validate the construction and properties of em_cmd_scan_result_t with empty parameters
 *
 * This test verifies that when an em_cmd_scan_result_t object is instantiated with empty parameters,
 * its internal members are correctly initialized. It tests that the fixed arguments are empty, the number
 * of channels is zero, and that the object's type, name, service, and descriptor fields are set to the expected values.
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
 * | 01 | Initialize parameters (num_args=0, fixed_args set to empty string, and number of channels set to 0) | input1 = params.u.args.num_args = 0, input2 = params.u.args.fixed_args = "", input3 = params.u.scan_params.op_class[0].num_channels = 0 | Parameters are initialized to empty values | Should be successful |
 * | 02 | Instantiate the dm object and invoke the constructor of em_cmd_scan_result_t with empty parameters | input1 = params (empty parameters), input2 = dm (default constructed) | A new em_cmd_scan_result_t object is constructed with proper default values | Should Pass |
 * | 03 | Validate that the constructed object's properties match the expected values using assertions | output1 = cmd.m_param.u.args.fixed_args = "", output2 = cmd.m_param.u.scan_params.op_class[0].num_channels = 0, output3 = cmd.m_type = em_cmd_type_scan_result, output4 = cmd.m_name = "scan_result", output5 = cmd.m_svc = em_service_type_ctrl, output6 = cmd.m_orch_op_idx = 0, output7 = cmd.m_num_orch_desc = 1, output8 = cmd.m_orch_desc[0].op = dm_orch_type_channel_scan_res, output9 = cmd.m_orch_desc[0].submit = true, output10 = cmd.m_data_model.m_cmd_ctx.type = dm_orch_type_channel_scan_res | All assertions pass confirming each property of the object | Should Pass |
 * | 04 | Invoke the deinit method to clean up the em_cmd_scan_result_t object | input1 = cmd object undergoing deinitialization | Resources are released and no errors occur during deinitialization | Should be successful |
 */
TEST(em_cmd_scan_result_t, em_cmd_scan_result_t_empty_parameters) {
    std::cout << "Entering em_cmd_scan_result_t_empty_parameters test" << std::endl;
    em_cmd_params_t params;
    params.u.args.num_args = 0;
    strncpy(params.u.args.fixed_args, "", sizeof(params.u.args.fixed_args)-1);
    params.u.args.fixed_args[sizeof(params.u.args.fixed_args)-1] = '\0';
    params.u.scan_params.op_class[0].num_channels = 0;
    dm_easy_mesh_t dm;
    std::cout << "Invoking constructor with empty parameters prepared with fixed_args: \"" << params.u.args.fixed_args << "\"" << std::endl;    
    em_cmd_scan_result_t cmd(params, dm);
    std::cout << "em_cmd_scan_result_t object constructed with empty parameters." << std::endl;
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "");
    EXPECT_EQ(cmd.m_param.u.scan_params.op_class[0].num_channels, 0);
    EXPECT_EQ(cmd.m_type, em_cmd_type_scan_result);
    EXPECT_STREQ(cmd.m_name, "scan_result");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 1);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_channel_scan_res);
    EXPECT_TRUE(cmd.m_orch_desc[0].submit);
    EXPECT_EQ(cmd.m_data_model.m_cmd_ctx.type, dm_orch_type_channel_scan_res);
    cmd.deinit();
    std::cout << "Exiting em_cmd_scan_result_t_empty_parameters test" << std::endl;
}
/**
 * @brief Test the constructor of em_cmd_scan_result_t with maximum fixed arguments
 *
 * This test verifies that the em_cmd_scan_result_t constructor correctly initializes the object when provided with maximum fixed arguments. It checks that all string copies and integer assignments are properly set, and validates that the internal fields of the constructed object match the expected values.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Initialize param.u.args.fixed_args with a maximum length string of 'X' characters | input: fixed_args = "X repeated to fill the buffer up to 127 characters, null terminated" | The fixed_args string is correctly copied and null terminated | Should be successful |
 * | 02 | Set param.u.args.num_args to 5 and initialize param.u.args.args[0] with a maximum length string of 'Y' characters | input: num_args = 5, args[0] = "Y repeated to fill the buffer up to its maximum length, null terminated" | The num_args and args[0] are correctly set | Should be successful |
 * | 03 | Create a dm_easy_mesh_t instance and invoke the em_cmd_scan_result_t constructor with the initialized param and dm | input: param (with fixed_args, num_args, args[0]), dm object | The em_cmd_scan_result_t object is instantiated with proper initialization of its members | Should Pass |
 * | 04 | Validate the fields of the created object using assertions | input: expected: num_args = 5, fixed_args same as param, args[0] same as param, m_type = em_cmd_type_scan_result, m_name = "scan_result", m_svc = em_service_type_ctrl, m_orch_op_idx = 0, m_num_orch_desc = 1, orch_desc[0].op = dm_orch_type_channel_scan_res, orch_desc[0].submit = true, m_data_model.m_cmd_ctx.type = dm_orch_type_channel_scan_res | All assertions pass confirming correct field values | Should Pass |
 * | 05 | Invoke the deinit method on the object | input: cmd.deinit() | Resources are released and the object is cleaned up successfully | Should be successful |
 */
TEST(em_cmd_scan_result_t, em_cmd_scan_result_t_ctor_max_fixed_args)
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
    std::cout << "Invoking em_cmd_scan_result_t with fixed_args: " << param.u.args.fixed_args << std::endl;
    em_cmd_scan_result_t cmd(param, dm);
    EXPECT_EQ(cmd.m_param.u.args.num_args, 5);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, param.u.args.fixed_args);
    EXPECT_STREQ(cmd.m_param.u.args.args[0], param.u.args.args[0]);
    EXPECT_EQ(cmd.m_type, em_cmd_type_scan_result);
    EXPECT_STREQ(cmd.m_name, "scan_result");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 1);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_channel_scan_res);
    EXPECT_TRUE(cmd.m_orch_desc[0].submit);
    EXPECT_EQ(cmd.m_data_model.m_cmd_ctx.type, dm_orch_type_channel_scan_res);
    cmd.deinit();
    std::cout << "Exiting em_cmd_scan_channel_t_ctor_max_fixed_args test" << std::endl;
}
