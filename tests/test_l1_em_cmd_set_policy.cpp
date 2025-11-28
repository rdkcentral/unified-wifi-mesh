
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
#include "em_cmd_set_policy.h"



/**
 * @brief Tests the em_cmd_set_policy_t API with complete valid parameters.
 *
 * Tests that the API correctly assigns all fields in the command structure when provided with complete valid parameter values. This ensures that the fixed arguments, individual arguments, command type, and orchestration details are set as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 001@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize em_cmd_params_t with valid complete parameters | fixed_args = "policy_set_complete", num_args = 2, args[0] = "Arg0", args[1] = "Arg1" | Parameters structure initialized with valid values | Should be successful |
 * | 02 | Construct dm_easy_mesh_t instance | N/A | dm instance created | Should be successful |
 * | 03 | Create command instance by invoking em_cmd_set_policy_t with the parameters and dm instance | Input: param, dm | Command instance created with initialized values | Should Pass |
 * | 04 | Validate all fields in the command instance using assertions | Output: num_args=2, fixed_args="policy_set_complete", args[0]="Arg0", args[1]="Arg1", type=em_cmd_type_set_policy, name="set_policy", svc=em_service_type_ctrl, orch_op_idx=0, num_orch_desc=1, orch_desc[0].op=dm_orch_type_policy_cfg, orch_desc[0].submit=true, m_cmd_ctx.type=dm_orch_type_policy_cfg | All EXPECT assertions pass | Should Pass |
 * | 05 | Deinitialize the command object by invoking deinit() | Input: cmd.deinit() called | deinit executed without errors | Should be successful |
 */
TEST(em_cmd_set_policy_t, em_cmd_set_policy_t_valid_complete_parameters)
{
    std::cout << "Entering em_cmd_set_policy_t_valid_complete_parameters test" << std::endl;
    em_cmd_params_t param{};
    const char *policyCommand = "policy_set_complete";
    strncpy(param.u.args.fixed_args, policyCommand, sizeof(param.u.args.fixed_args));
    param.u.args.num_args = 2;
    strncpy(param.u.args.args[0], "Arg0", sizeof(param.u.args.args[0]));
    strncpy(param.u.args.args[1], "Arg1", sizeof(param.u.args.args[1]));
    dm_easy_mesh_t dm;
    std::cout << "Invoking em_cmd_set_policy_t with fixed_args: " << param.u.args.fixed_args << std::endl;
    em_cmd_set_policy_t cmd(param, dm);
    std::cout << "Policy update completed successfully (complete parameters)." << std::endl;
    EXPECT_EQ(cmd.m_param.u.args.num_args, 2);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "policy_set_complete");
    EXPECT_STREQ(cmd.m_param.u.args.args[0], "Arg0");
    EXPECT_STREQ(cmd.m_param.u.args.args[1], "Arg1");
    EXPECT_EQ(cmd.m_type, em_cmd_type_set_policy);
    EXPECT_STREQ(cmd.m_name, "set_policy");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 1);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_policy_cfg);
    EXPECT_TRUE(cmd.m_orch_desc[0].submit);
    EXPECT_EQ(cmd.m_data_model.m_cmd_ctx.type, dm_orch_type_policy_cfg);
    cmd.deinit();
    std::cout << "Exiting em_cmd_set_policy_t_valid_complete_parameters test" << std::endl;
}
/**
 * @brief Verify that the em_cmd_set_policy_t function behaves as expected with minimal parameters
 *
 * This test checks the functionality of the em_cmd_set_policy_t API when invoked with minimal valid inputs.
 * It verifies that all internal fields of the command object are correctly set and that the minimal policy
 * update succeeds as expected.
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
 * | 01 | Initialize minimal parameters and display the entering test log | param.u.args.fixed_args = "", param.u.args.num_args = 0, dm is default constructed | Parameters initialized and entering log printed | Should be successful |
 * | 02 | Invoke the em_cmd_set_policy_t constructor with minimal parameters | input: param (with fixed_args = "", num_args = 0), dm | Command object is created with correctly assigned minimal parameters | Should Pass |
 * | 03 | Validate the initialized command object using assertions | output: m_param.u.args.num_args = 0, m_param.u.args.fixed_args = "", m_type = em_cmd_type_set_policy, m_name = "set_policy", m_svc = em_service_type_ctrl, m_orch_op_idx = 0, m_num_orch_desc = 1, m_orch_desc[0].op = dm_orch_type_policy_cfg, m_orch_desc[0].submit = true, m_data_model.m_cmd_ctx.type = dm_orch_type_policy_cfg | All assertions pass with expected field values | Should Pass |
 * | 04 | Call deinit on the command object and display the exiting test log | cmd.deinit() | Command object is deinitialized and exit log printed | Should be successful |
 */
TEST(em_cmd_set_policy_t, em_cmd_set_policy_t_valid_minimal_parameters)
{
    std::cout << "Entering em_cmd_set_policy_t_valid_minimal_parameters test" << std::endl;
    em_cmd_params_t param{};
    strncpy(param.u.args.fixed_args, "", sizeof(param.u.args.fixed_args));
    param.u.args.num_args = 0;
    dm_easy_mesh_t dm;
    std::cout << "Invoking em_cmd_set_policy_t with fixed_args: " << param.u.args.fixed_args << std::endl;
    em_cmd_set_policy_t cmd(param, dm);
    std::cout << "Minimal policy update completed successfully." << std::endl;
    EXPECT_EQ(cmd.m_param.u.args.num_args, 0);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "");
    EXPECT_EQ(cmd.m_type, em_cmd_type_set_policy);
    EXPECT_STREQ(cmd.m_name, "set_policy");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 1);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_policy_cfg);
    EXPECT_TRUE(cmd.m_orch_desc[0].submit);
    EXPECT_EQ(cmd.m_data_model.m_cmd_ctx.type, dm_orch_type_policy_cfg);
    cmd.deinit();
    std::cout << "Exiting em_cmd_set_policy_t_valid_minimal_parameters test" << std::endl;
}
/**
 * @brief Verify the correct construction and initialization of em_cmd_set_policy_t with maximum fixed argument lengths.
 *
 * This test case verifies that the constructor of the em_cmd_set_policy_t class correctly initializes all internal members using maximum length input strings for fixed arguments and a single argument. It ensures correct string handling, boundary condition management, and proper assignment of command type, name, service type, and orchestrator parameters.
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
 * | Variation / Step | Description | Test Data | Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize em_cmd_params_t with maximum fixed argument and first argument values, then construct em_cmd_set_policy_t and verify its member fields | param.u.args.fixed_args = maxStr (127 'X's), param.u.args.num_args = 5, param.u.args.args[0] = maxArg (127 'Y's) | All member fields of cmd (m_param, m_type, m_name, m_svc, m_orch_op_idx, m_num_orch_desc, m_orch_desc, m_data_model) are properly initialized matching expected constants and assertions pass | Should Pass |
 */
TEST(em_cmd_set_policy_t, em_cmd_set_policy_t_ctor_max_fixed_args)
{
    std::cout << "Entering em_cmd_set_policy_t_ctor_max_fixed_args test" << std::endl;
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
    em_cmd_set_policy_t cmd(param, dm);
    EXPECT_EQ(cmd.m_param.u.args.num_args, 5);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, param.u.args.fixed_args);
    EXPECT_STREQ(cmd.m_param.u.args.args[0], param.u.args.args[0]);
    EXPECT_EQ(cmd.m_type, em_cmd_type_set_policy);
    EXPECT_STREQ(cmd.m_name, "set_policy");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 1);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_policy_cfg);
    EXPECT_TRUE(cmd.m_orch_desc[0].submit);
    EXPECT_EQ(cmd.m_data_model.m_cmd_ctx.type, dm_orch_type_policy_cfg);
    cmd.deinit();
    std::cout << "Exiting em_cmd_set_policy_t_ctor_max_fixed_args test" << std::endl;
}
