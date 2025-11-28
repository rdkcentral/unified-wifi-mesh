
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
#include "em_cmd_sta_list.h"



/**
 * @brief Test valid parameters for em_cmd_sta_list_t
 *
 * This test verifies that the em_cmd_sta_list_t object is correctly constructed when provided with valid parameters. It initializes the command parameters with a fixed argument and an argument array, constructs a dm_easy_mesh_t object, and then creates an em_cmd_sta_list_t object. The test asserts that all member variables of the constructed object are set to the expected values.
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
 * | 01 | Initialize test parameters, including fixed_args with "TestFixedArgValue", num_args with 1, and args[0] with "Argument0", and create a dm_easy_mesh_t instance. | params.u.args.fixed_args = TestFixedArgValue, params.u.args.num_args = 1, params.u.args.args[0] = Argument0, dm instance created | Test parameters and dm instance are correctly initialized. | Should Pass |
 * | 02 | Construct em_cmd_sta_list_t with the initialized parameters and assert all object member values including type, name, service, and orchestrator details. | cmd constructed using params and dm; expected values: m_type = em_cmd_type_sta_list, m_name = sta_list, m_svc = em_service_type_agent, orch_op_idx = 0, m_num_orch_desc = 2, appropriate orch_desc values. | The object properties match the expected valid parameters. | Should Pass |
 * | 03 | Call deinit() on the em_cmd_sta_list_t object to release resources. | cmd.deinit() invoked | Resources are deinitialized without errors. | Should be successful |
 */
TEST(em_cmd_sta_list_t, em_cmd_sta_list_t_valid_parameters) {
    std::cout << "Entering em_cmd_sta_list_t_valid_parameters test" << std::endl;
    em_cmd_params_t params;
    const char *testFixedArg = "TestFixedArgValue";
    strncpy(params.u.args.fixed_args, testFixedArg, sizeof(params.u.args.fixed_args));
    params.u.args.num_args = 1;
    const char *arg0 = "Argument0";
    strncpy(params.u.args.args[0], arg0, sizeof(params.u.args.args[0]));
    dm_easy_mesh_t dm;
    std::cout << "Invoking constructor with params.u.args.fixed_args as " << params.u.args.fixed_args << " and params.u.args.args[0] as " << params.u.args.args[0] << std::endl;
    em_cmd_sta_list_t cmd(params, dm);
    std::cout << "em_cmd_sta_list_t object created successfully." << std::endl;
    EXPECT_EQ(cmd.m_param.u.args.num_args, 1);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "TestFixedArgValue");
    EXPECT_STREQ(cmd.m_param.u.args.args[0], "Argument0");
    EXPECT_EQ(cmd.m_type, em_cmd_type_sta_list);
    EXPECT_STREQ(cmd.m_name, "sta_list");
    EXPECT_EQ(cmd.m_svc, em_service_type_agent);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 2);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_ctrl_notify);
    EXPECT_EQ(cmd.m_orch_desc[1].op, dm_orch_type_sta_aggregate);
    EXPECT_TRUE(cmd.m_orch_desc[0].submit);
    EXPECT_EQ(cmd.m_data_model.m_cmd_ctx.type, dm_orch_type_ctrl_notify);
    cmd.deinit();
    std::cout << "Exiting em_cmd_sta_list_t_valid_parameters test" << std::endl;
}
/**
 * @brief Test to validate the minimal valid parameters for the em_cmd_sta_list_t API
 *
 * This test verifies that when minimal valid parameters are provided, em_cmd_sta_list_t initializes all its members correctly. It ensures that the fixed arguments and associated fields are set to their default or expected values, and that the command object's internal orchestration descriptors are properly configured. This is essential to confirm that the system behaves correctly even when minimal input is supplied.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize parameters by setting fixed_args to empty and num_args to 0. | fixed_args = "", num_args = 0 | Parameters correctly initialized. | Should be successful |
 * | 02 | Create and initialize the dm_easy_mesh_t instance. | N/A | Instance created successfully. | Should be successful |
 * | 03 | Invoke em_cmd_sta_list_t with minimal parameters and check default fields. | cmd.m_param.u.args.num_args = 0, cmd.m_param.u.args.fixed_args = "", cmd.m_type = em_cmd_type_sta_list, cmd.m_name = "sta_list", cmd.m_svc = em_service_type_agent, cmd.m_orch_op_idx = 0, cmd.m_num_orch_desc = 2 | All expected values are correctly set and assertions pass. | Should Pass |
 * | 04 | Verify the orchestration description fields. | cmd.m_orch_desc[0].op = dm_orch_type_ctrl_notify, cmd.m_orch_desc[1].op = dm_orch_type_sta_aggregate, cmd.m_orch_desc[0].submit = true, cmd.m_data_model.m_cmd_ctx.type = dm_orch_type_ctrl_notify | Proper orchestration descriptor values are assigned. | Should Pass |
 * | 05 | Clean up by calling deinit on the command. | N/A | Command object cleaned up. | Should be successful |
 */
TEST(em_cmd_sta_list_t, em_cmd_sta_list_t_valid_minimal_parameters)
{
    std::cout << "Entering em_cmd_sta_list_t_valid_minimal_parameters test" << std::endl;
    em_cmd_params_t param{};
    strncpy(param.u.args.fixed_args, "", sizeof(param.u.args.fixed_args));
    param.u.args.num_args = 0;
    dm_easy_mesh_t dm;
    std::cout << "Invoking em_cmd_sta_list_t with fixed_args: " << param.u.args.fixed_args << std::endl;
    em_cmd_sta_list_t cmd(param, dm);
    std::cout << "Minimal sta list update completed successfully." << std::endl;
    EXPECT_EQ(cmd.m_param.u.args.num_args, 0);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "");
    EXPECT_EQ(cmd.m_type, em_cmd_type_sta_list);
    EXPECT_STREQ(cmd.m_name, "sta_list");
    EXPECT_EQ(cmd.m_svc, em_service_type_agent);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 2);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_ctrl_notify);
    EXPECT_EQ(cmd.m_orch_desc[1].op, dm_orch_type_sta_aggregate);
    EXPECT_TRUE(cmd.m_orch_desc[0].submit);
    EXPECT_EQ(cmd.m_data_model.m_cmd_ctx.type, dm_orch_type_ctrl_notify);
    cmd.deinit();
    std::cout << "Exiting em_cmd_sta_list_t_valid_minimal_parameters test" << std::endl;
}
/**
 * @brief Test to verify the construction of em_cmd_sta_list_t with maximum fixed arguments
 *
 * This test verifies that the em_cmd_sta_list_t constructor correctly initializes the command object when provided with maximum fixed argument strings and values. It sets up the parameters with maximum valid string lengths for both fixed_args and the first argument in args, invokes the constructor, and validates that all object members are set as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 003@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                  | Test Data                                                                                                                           | Expected Result                                                                          | Notes          |
 * | :--------------: | -------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | -------------- |
 * | 01               | Initialize em_cmd_params_t with max string values for fixed_args and first argument.           | fixed_args: maxStr ('X' repeated to fill 127 characters), num_args: 5, args[0]: maxArg ('Y' repeated to fill 127 characters)       | Parameters are initialized properly                                                       | Should be successful |
 * | 02               | Invoke the em_cmd_sta_list_t constructor using the prepared parameters and a dm instance.        | Input: param (with above initialized values), dm: default constructed dm_easy_mesh_t                                               | The command object is constructed successfully                                           | Should Pass    |
 * | 03               | Verify the constructed object's member values using assertion checks.                        | Check values: m_param.u.args.num_args, m_param.u.args.fixed_args, m_param.u.args.args[0], m_type, m_name, m_svc, orch_desc fields | All assertions pass confirming the object state matches the expected configuration       | Should Pass    |
 */
TEST(em_cmd_set_policy_t, em_cmd_sta_list_t_ctor_max_fixed_args)
{
    std::cout << "Entering em_cmd_sta_list_t_ctor_max_fixed_args test" << std::endl;
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
    em_cmd_sta_list_t cmd(param, dm);
    EXPECT_EQ(cmd.m_param.u.args.num_args, 5);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, param.u.args.fixed_args);
    EXPECT_STREQ(cmd.m_param.u.args.args[0], param.u.args.args[0]);
    EXPECT_EQ(cmd.m_type, em_cmd_type_sta_list);
    EXPECT_STREQ(cmd.m_name, "sta_list");
    EXPECT_EQ(cmd.m_svc, em_service_type_agent);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 2);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_ctrl_notify);
    EXPECT_EQ(cmd.m_orch_desc[1].op, dm_orch_type_sta_aggregate);
    EXPECT_TRUE(cmd.m_orch_desc[0].submit);
    EXPECT_EQ(cmd.m_data_model.m_cmd_ctx.type, dm_orch_type_ctrl_notify);
    cmd.deinit();
    std::cout << "Exiting em_cmd_sta_list_t_ctor_max_fixed_args test" << std::endl;
}
/**
 * @brief Test em_cmd_sta_list_t API for proper initialization with a null network node.
 *
 * This test verifies that the em_cmd_sta_list_t object is correctly initialized when the network node pointer is null. It checks that the fixed arguments, additional arguments, and other fields are set as expected, ensuring that the API handles a null network node without issues.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize em_cmd_params_t and dm_easy_mesh_t, set number of args, fixed_args, args[0] and network node to nullptr | em_cmd_params_t: num_args = 1, fixed_args = "STA_LIST", args[0] = "Param1", net_node = nullptr; dm_easy_mesh_t: default constructed | Parameters are correctly initialized for API invocation | Should be successful |
 * | 02 | Instantiate em_cmd_sta_list_t object using the initialized parameters and dm_easy_mesh_t instance | Invocation: em_cmd_sta_list_t cmd(param, dm) | Command object is created with m_param values copied, m_type = em_cmd_type_sta_list, m_name = "sta_list", m_svc = em_service_type_agent, and proper orchestration descriptor values | Should Pass |
 * | 03 | Validate object initialization through assertions comparing fixed_args, args[0], net_node, command type, name, service, and orchestration indices/descriptors | EXPECT_STREQ and EXPECT_EQ assertions using: cmd.m_param, cmd.m_type, cmd.m_name, cmd.m_svc, cmd.m_orch_op_idx, cmd.m_num_orch_desc, cmd.m_orch_desc values | All assertions should pass confirming proper initialization of the command object | Should Pass |
 * | 04 | Deinitialize the command object by calling deinit() | Invocation: cmd.deinit() | The command object is deinitialized correctly without errors | Should be successful |
 */
TEST(em_cmd_get_network_t, em_cmd_sta_list_t_NullNetworkNode)
{
    std::cout << "Entering em_cmd_sta_list_t_NullNetworkNode test" << std::endl;
    em_cmd_params_t param;
    param.u.args.num_args = 1;
    strncpy(param.u.args.fixed_args, "STA_LIST", sizeof(param.u.args.fixed_args));
    strncpy(param.u.args.args[0], "Param1", sizeof(param.u.args.args[0]));
    param.net_node = nullptr;
    dm_easy_mesh_t dm;
    em_cmd_sta_list_t cmd(param, dm);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, param.u.args.fixed_args);
    EXPECT_STREQ(cmd.m_param.u.args.args[0], param.u.args.args[0]);
    EXPECT_EQ(cmd.m_param.net_node, nullptr);
    EXPECT_EQ(cmd.m_type, em_cmd_type_sta_list);
    EXPECT_STREQ(cmd.m_name, "sta_list");
    EXPECT_EQ(cmd.m_svc, em_service_type_agent);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 2);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_ctrl_notify);
    EXPECT_EQ(cmd.m_orch_desc[1].op, dm_orch_type_sta_aggregate);
    EXPECT_TRUE(cmd.m_orch_desc[0].submit);
    EXPECT_EQ(cmd.m_data_model.m_cmd_ctx.type, dm_orch_type_ctrl_notify);
    cmd.deinit();
    std::cout << "Exiting em_cmd_sta_list_t_NullNetworkNode test" << std::endl;
}
