
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
#include "em_cmd_set_radio.h"



/**
 * @brief Validates that the set_radio command is properly constructed with valid parameters.
 *
 * This test verifies that when the em_cmd_set_radio_t is constructed with valid radio parameters, all member variables are initialized correctly. It checks that the command object is properly configured with the correct parameter values and that the associated assertions pass.
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
 * | Variation / Step | Description                                                     | Test Data                                                                                                                                                          | Expected Result                                                                                                                            | Notes           |
 * | :--------------: | --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------- | --------------- |
 * | 01               | Initialize command parameters with valid radio values           | fixed_args = set_radio, num_args = 2, args[0] = radio1, args[1] = radio2                                                                                           | Parameters are correctly assigned                                                                                                         | Should be successful |
 * | 02               | Invoke em_cmd_set_radio_t constructor with initialized parameters | params (fixed_args = set_radio, num_args = 2, args[0] = radio1, args[1] = radio2), dm type = dm_easy_mesh_t object                                                     | Command object is created with proper member initializations                                                                              | Should Pass     |
 * | 03               | Validate the constructed command object's properties            | Expected values: m_param.u.args.num_args = 2, fixed_args = set_radio, args[0] = radio1, args[1] = radio2, m_type = em_cmd_type_set_radio, m_name = set_radio, m_svc = em_service_type_ctrl, m_orch_op_idx = 0, m_num_orch_desc = 1, orch_desc[0].op = dm_orch_type_em_update, orch_desc[0].submit = true, m_data_model.m_cmd_ctx.type = dm_orch_type_em_update | All assertions pass confirming correct initialization of all member variables                                                         | Should Pass     |
 * | 04               | Deinitialize the command object and log test exit               | cmd.deinit()                                                                                                                                                       | Command object is deinitialized and test exit log is printed                                                                               | Should be successful |
 */
TEST(em_cmd_set_radio_t, em_cmd_set_radio_t_valid_set_radio_parameters) {
    std::cout << "Entering em_cmd_set_radio_t_valid_set_radio_parameters test" << std::endl;
    em_cmd_params_t params;
    strncpy(params.u.args.fixed_args, "set_radio", sizeof(params.u.args.fixed_args)-1);
    params.u.args.fixed_args[sizeof(params.u.args.fixed_args)-1] = '\0';
    params.u.args.num_args = 2;
    strncpy(params.u.args.args[0], "radio1", sizeof(params.u.args.args[0])-1);
    params.u.args.args[0][sizeof(params.u.args.args[0])-1] = '\0';
    strncpy(params.u.args.args[1], "radio2", sizeof(params.u.args.args[1])-1);
    params.u.args.args[1][sizeof(params.u.args.args[1])-1] = '\0';
    std::cout << "Invoking em_cmd_set_radio_t constructor with:" << std::endl;
    std::cout << "  fixed_args: " << params.u.args.fixed_args << std::endl;
    std::cout << "  num_args: " << params.u.args.num_args << std::endl;
    std::cout << "  args[0]: " << params.u.args.args[0] << std::endl;
    std::cout << "  args[1]: " << params.u.args.args[1] << std::endl;
    dm_easy_mesh_t dm;
    em_cmd_set_radio_t cmd(params, dm);
    std::cout << "After invoking em_cmd_set_radio_t constructor:" << std::endl;
    EXPECT_EQ(cmd.m_param.u.args.num_args, 2);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "set_radio");
    EXPECT_STREQ(cmd.m_param.u.args.args[0], "radio1");
    EXPECT_STREQ(cmd.m_param.u.args.args[1], "radio2");
    EXPECT_EQ(cmd.m_type, em_cmd_type_set_radio);
    EXPECT_STREQ(cmd.m_name, "set_radio");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 1);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_em_update);
    EXPECT_TRUE(cmd.m_orch_desc[0].submit);
    EXPECT_EQ(cmd.m_data_model.m_cmd_ctx.type, dm_orch_type_em_update);
    cmd.deinit();
    std::cout << "Exiting em_cmd_set_radio_t_valid_set_radio_parameters test" << std::endl;
}
/**
 * @brief Verify that the em_cmd_set_radio_t constructor initializes parameters correctly for empty arguments
 *
 * This test case validates that when the em_cmd_set_radio_t API is supplied with empty arguments,
 * the object is correctly initialized with default values. The test ensures that all relevant fields are set as expected,
 * thus confirming the correct behavior of the API when minimal input is provided.
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
 * | Variation / Step | Description                                                                                                     | Test Data                                                                                                                       | Expected Result                                                                                                                                                                            | Notes           |
 * | :--------------: | --------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------- |
 * | 01               | Initialize an instance of em_cmd_params_t with empty fixed_args and num_args set to 0                            | input: fixed_args = "", num_args = 0                                                                                              | The em_cmd_params_t object is correctly initialized with an empty string for fixed_args and a value of 0 for num_args                                                                          | Should be successful |
 * | 02               | Invoke the em_cmd_set_radio_t constructor using the initialized parameters and a dm_easy_mesh_t instance           | input: params (with fixed_args = "", num_args = 0), dm: instance of dm_easy_mesh_t                                                 | The constructed object should have: m_param.u.args.num_args = 0; m_param.u.args.fixed_args = ""; m_type = em_cmd_type_set_radio; m_name = "set_radio"; m_svc = em_service_type_ctrl; m_orch_op_idx = 0; m_num_orch_desc = 1; m_orch_desc[0].op = dm_orch_type_em_update; m_orch_desc[0].submit = true; m_data_model.m_cmd_ctx.type = dm_orch_type_em_update | Should Pass    |
 * | 03               | Call the deinit() method on the command object to release or cleanup resources                                    | input: command object (cmd)                                                                                                       | The deinit() function executes without error, and the object cleans up its resources properly                                                                                              | Should be successful |
 */
TEST(em_cmd_set_radio_t, em_cmd_set_radio_t_minimal_empty_arguments) {
    std::cout << "Entering em_cmd_set_radio_t_minimal_empty_arguments test" << std::endl;
    em_cmd_params_t params{};
    strncpy(params.u.args.fixed_args, "", sizeof(params.u.args.fixed_args));
    params.u.args.num_args = 0;
    std::cout << "Invoking em_cmd_set_radio_t constructor with:" << std::endl;
    std::cout << "  fixed_args: " << params.u.args.fixed_args << std::endl;
    std::cout << "  num_args: " << params.u.args.num_args << std::endl;
    dm_easy_mesh_t dm;
    em_cmd_set_radio_t cmd(params, dm);
    EXPECT_EQ(cmd.m_param.u.args.num_args, 0);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "");
    EXPECT_EQ(cmd.m_type, em_cmd_type_set_radio);
    EXPECT_STREQ(cmd.m_name, "set_radio");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 1);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_em_update);
    EXPECT_TRUE(cmd.m_orch_desc[0].submit);
    EXPECT_EQ(cmd.m_data_model.m_cmd_ctx.type, dm_orch_type_em_update);
    cmd.deinit();
    std::cout << "Exiting em_cmd_set_radio_t_minimal_empty_arguments test" << std::endl;
}
/**
 * @brief Verify that em_cmd_set_radio_t constructor initializes object correctly with maximum fixed arguments.
 *
 * Tests that when maximum length strings are provided for fixed_args and args[0], and num_args is set to 5,
 * the em_cmd_set_radio_t object is correctly initialized, including proper assignment of command type, service type,
 * operation indexes, and update types in the data model.
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
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call em_cmd_set_radio_t constructor with maximum fixed_args and first argument provided | input: fixed_args = 127 'X' characters followed by null, num_args = 5, args[0] = 127 'Y' characters followed by null, dm = valid dm_easy_mesh_t instance | All object members (m_param.u.args.num_args, fixed_args, args[0], m_type, m_name, m_svc, m_orch_op_idx, m_num_orch_desc, m_orch_desc[0].op, m_orch_desc[0].submit, and m_data_model.m_cmd_ctx.type) are correctly initialized as expected | Should Pass |
 * | 02 | Invoke deinit method to clean up the resources of the constructed object | output: deinit() invocation with the object previously constructed | Resources are deinitialized without error | Should be successful |
 */
TEST(em_cmd_set_radio_t, em_cmd_set_radio_t_ctor_max_fixed_args)
{
    std::cout << "Entering em_cmd_set_radio_t_ctor_max_fixed_args test" << std::endl;
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
    em_cmd_set_radio_t cmd(param, dm);
    EXPECT_EQ(cmd.m_param.u.args.num_args, 5);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, param.u.args.fixed_args);
    EXPECT_STREQ(cmd.m_param.u.args.args[0], param.u.args.args[0]);
    EXPECT_EQ(cmd.m_type, em_cmd_type_set_radio);
    EXPECT_STREQ(cmd.m_name, "set_radio");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 1);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_em_update);
    EXPECT_TRUE(cmd.m_orch_desc[0].submit);
    EXPECT_EQ(cmd.m_data_model.m_cmd_ctx.type, dm_orch_type_em_update);
    cmd.deinit();
    std::cout << "Exiting em_cmd_set_radio_t_ctor_max_fixed_args test" << std::endl;
}
