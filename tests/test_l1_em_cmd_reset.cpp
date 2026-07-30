
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
#include "em_cmd_reset.h"


/**
 * @brief Validate that em_cmd_reset_t is constructed correctly with valid parameters
 *
 * This test verifies that the em_cmd_reset_t constructor correctly initializes the command object when provided with valid parameters.
 * It checks that the object's members such as m_type, m_orch_op_idx, m_num_orch_desc, m_orch_desc array, m_name, m_svc, m_param, and m_data_model are set as expected.
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
 * | 01 | Initialize em_cmd_params_t structure by zeroing and setting fixed_args to "ResetCommand", num_args to 1 and args[0] to "Arg0". | fixedArgs = "ResetCommand", num_args = 1, args[0] = "Arg0" | em_cmd_params_t structure is correctly initialized. | Should be successful |
 * | 02 | Instantiate dm_easy_mesh_t object required for command creation. | No input | dm_easy_mesh_t object is created. | Should be successful |
 * | 03 | Construct em_cmd_reset_t object using the initialized test parameters and dm instance. | testParam, dm | cmd object is created with proper initialization: m_type equals em_cmd_type_reset, m_orch_op_idx equals 0, m_num_orch_desc equals 4, and m_orch_desc array properly set. | Should Pass |
 * | 04 | Validate the command object's member variables using assertions (e.g., m_name equals "reset", m_param fields, and m_data_model type). | cmd.m_type, cmd.m_orch_op_idx, cmd.m_orch_desc, cmd.m_name, cmd.m_svc, cmd.m_param, cmd.m_data_model | All EXPECT_EQ and EXPECT_STREQ assertions pass. | Should Pass |
 * | 05 | Invoke the deinit method on the command object to clean up resources. | cmd.deinit() | Resource deinitialization is executed without errors. | Should be successful |
 */
TEST(em_cmd_reset_t, em_cmd_reset_t_valid_construction) {
    std::cout << "Entering em_cmd_reset_t_valid_construction test" << std::endl;
    em_cmd_params_t testParam;
    memset(&testParam, 0, sizeof(testParam));
    const char *fixedArgs = "ResetCommand";
    strncpy(testParam.u.args.fixed_args, fixedArgs, sizeof(testParam.u.args.fixed_args) - 1);
    testParam.u.args.fixed_args[sizeof(testParam.u.args.fixed_args) - 1] = '\0';
    testParam.u.args.num_args = 1;
    strncpy(testParam.u.args.args[0], "Arg0", sizeof(testParam.u.args.args[0]));
    std::cout << "Preparing em_cmd_params_t with fixed_args: " << testParam.u.args.fixed_args << " and num_args: " << testParam.u.args.num_args << std::endl;
    dm_easy_mesh_t dm; 
    em_cmd_reset_t cmd(testParam, dm);
    EXPECT_EQ(cmd.m_type, em_cmd_type_reset);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
	EXPECT_EQ(cmd.m_num_orch_desc, 4);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_em_reset);
    EXPECT_EQ(cmd.m_orch_desc[1].op, dm_orch_type_dm_delete_all);
    EXPECT_EQ(cmd.m_orch_desc[2].op, dm_orch_type_db_reset);
    EXPECT_EQ(cmd.m_orch_desc[3].op, dm_orch_type_db_cfg);
	EXPECT_STREQ(cmd.m_name, "reset");
   	EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "ResetCommand");
    EXPECT_EQ(cmd.m_param.u.args.num_args, 1);
    EXPECT_STREQ(cmd.m_param.u.args.args[0], "Arg0");
    EXPECT_EQ(cmd.m_data_model.m_cmd_ctx.type, dm_orch_type_em_reset);
    cmd.deinit();
    std::cout << "Exiting em_cmd_reset_t_valid_construction test" << std::endl;
}
/**
 * @brief Validate proper initialization of em_cmd_reset_t with empty parameters.
 *
 * This test verifies that the em_cmd_reset_t constructor correctly initializes the command object when provided with empty parameters. The test checks the internal fields such as parameters copy, command type, orchestrator descriptors, name, service type, and data model context, ensuring that they are set to their expected values.
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
 * | 01 | Create default parameters and dm instance, then invoke em_cmd_reset_t constructor. | params = default, dm = instance | Command object created with initialized fields. | Should be successful |
 * | 02 | Verify that command parameters are copied correctly using memcmp. | input1 = cmd.m_param, input2 = params, size = sizeof(params) | Return value 0 indicating parameters are equal. | Should Pass |
 * | 03 | Verify command type is set to em_cmd_type_reset. | cmd.m_type = em_cmd_type_reset | cmd.m_type equals em_cmd_type_reset. | Should Pass |
 * | 04 | Verify orchestrator operation index is 0. | cmd.m_orch_op_idx = 0 | cmd.m_orch_op_idx equals 0. | Should Pass |
 * | 05 | Verify number of orchestrator descriptors equals 4. | cmd.m_num_orch_desc = 4 | cmd.m_num_orch_desc equals 4. | Should Pass |
 * | 06 | Verify first orchestrator descriptor operation. | cmd.m_orch_desc[0].op = dm_orch_type_em_reset | cmd.m_orch_desc[0].op equals dm_orch_type_em_reset. | Should Pass |
 * | 07 | Verify second orchestrator descriptor operation. | cmd.m_orch_desc[1].op = dm_orch_type_dm_delete_all | cmd.m_orch_desc[1].op equals dm_orch_type_dm_delete_all. | Should Pass |
 * | 08 | Verify third orchestrator descriptor operation. | cmd.m_orch_desc[2].op = dm_orch_type_db_reset | cmd.m_orch_desc[2].op equals dm_orch_type_db_reset. | Should Pass |
 * | 09 | Verify fourth orchestrator descriptor operation. | cmd.m_orch_desc[3].op = dm_orch_type_db_cfg | cmd.m_orch_desc[3].op equals dm_orch_type_db_cfg. | Should Pass |
 * | 10 | Verify command name is set to "reset". | cmd.m_name = "reset" | cmd.m_name equals "reset". | Should Pass |
 * | 11 | Verify service type is set to em_service_type_ctrl. | cmd.m_svc = em_service_type_ctrl | cmd.m_svc equals em_service_type_ctrl. | Should Pass |
 * | 12 | Verify data model command context type is set to dm_orch_type_em_reset. | cmd.m_data_model.m_cmd_ctx.type = dm_orch_type_em_reset | cmd.m_data_model.m_cmd_ctx.type equals dm_orch_type_em_reset. | Should Pass |
 * | 13 | Invoke deinit() to clean up command object. | Method: cmd.deinit() | Resources cleaned up without error. | Should Pass |
 * | 14 | Log exit message indicating the end of the test. | std::cout message | Exit message logged. | Should be successful |
 */
TEST(em_cmd_reset_t, em_cmd_reset_t_empty_params)
{
    std::cout << "Entering em_cmd_reset_t_empty_params test" << std::endl;
    em_cmd_params_t params{};
    dm_easy_mesh_t dm;
    em_cmd_reset_t cmd(params, dm);
    EXPECT_EQ(memcmp(&cmd.m_param, &params, sizeof(params)), 0);
    EXPECT_EQ(cmd.m_type, em_cmd_type_reset);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 4);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_em_reset);
    EXPECT_EQ(cmd.m_orch_desc[1].op, dm_orch_type_dm_delete_all);
    EXPECT_EQ(cmd.m_orch_desc[2].op, dm_orch_type_db_reset);
    EXPECT_EQ(cmd.m_orch_desc[3].op, dm_orch_type_db_cfg);
    EXPECT_STREQ(cmd.m_name, "reset");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_EQ(cmd.m_data_model.m_cmd_ctx.type, dm_orch_type_em_reset);
    cmd.deinit();
    std::cout << "Exiting em_cmd_reset_t_empty_params test" << std::endl;
}
/**
 * @brief Test the em_cmd_reset_t class initialization using maximum allowed parameter values.
 *
 * This test verifies that the em_cmd_reset_t object is properly initialized when provided with maximum parameter values.
 * It checks that all the internal fields are correctly set, including the command type, name, service type, data model context,
 * parameter values, and operator descriptors. This ensures robust operation under maximum load conditions.
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
 * | 01 | Initialize the em_cmd_params_t structure by zeroing its memory and setting the fixed argument to "reset" with maximum argument count. | input: resetDeviceStr = "reset", num_args = EM_CLI_MAX_ARGS; output: params structure zeroed and fixed_args set | The params structure is correctly initialized with fixed_args and num_args. | Should be successful |
 * | 02 | Populate each argument in the params structure. For index 0, set the argument to "RESET"; for all other indexes, fill with 'X'. | input: for index 0, args[0] = "RESET", for i>0, args[i] = "XXXXXXXXX..."; output: params.u.args.args array filled as specified | All args in the params structure are correctly populated with "RESET" for the first and "X" for the rest. | Should be successful |
 * | 03 | Construct the em_cmd_reset_t object using the populated params and a dm_easy_mesh_t instance. | input: params, dm instance; output: em_cmd_reset_t object creation | The em_cmd_reset_t object is created with internal state set based on provided input. | Should Pass |
 * | 04 | Verify the internal state of the em_cmd_reset_t object by asserting its type, name, service type, data model context, parameter values, and operator descriptor details. | input: none additional; output: Multiple EXPECT_EQ and EXPECT_STREQ assertions | All assertions pass confirming correct initialization of em_cmd_reset_t object fields. | Should Pass |
 * | 05 | Call the deinit() function on the em_cmd_reset_t object to clean up allocated resources. | input: em_cmd_reset_t object; output: deinitialization of the object | The command object is deinitialized properly without errors. | Should be successful |
 */
TEST(em_cmd_reset_t, em_cmd_reset_t_max_params)
{
    std::cout << "Entering em_cmd_reset_t_max_params test" << std::endl;
    em_cmd_params_t params;
    memset(&params, 0, sizeof(params));
    const char* resetDeviceStr = "reset";
    strncpy(params.u.args.fixed_args, resetDeviceStr, sizeof(params.u.args.fixed_args)-1);
    params.u.args.num_args = EM_CLI_MAX_ARGS;
    for (unsigned int i = 0; i < params.u.args.num_args; i++) {
        char longId[128];
        memset(longId, 'X', sizeof(longId)-1);
        longId[127] = '\0';
        if(i == 0) {
            strncpy(longId, "RESET", 10);
        }
        strncpy(params.u.args.args[i], longId, sizeof(params.u.args.args[i])-1);
    }
    dm_easy_mesh_t dm;
    em_cmd_reset_t cmd(params, dm);
    EXPECT_EQ(cmd.m_type, em_cmd_type_reset);
    EXPECT_STREQ(cmd.m_name, "reset");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_EQ(cmd.m_data_model.m_cmd_ctx.type, dm_orch_type_em_reset);
    EXPECT_EQ(cmd.m_param.u.args.num_args, params.u.args.num_args);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, params.u.args.fixed_args);
    for (unsigned int i = 0; i < params.u.args.num_args; i++) {
        EXPECT_STREQ(cmd.m_param.u.args.args[i], params.u.args.args[i]);
    }
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 4);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_em_reset);
    EXPECT_EQ(cmd.m_orch_desc[1].op, dm_orch_type_dm_delete_all);
    EXPECT_EQ(cmd.m_orch_desc[2].op, dm_orch_type_db_reset);
    EXPECT_EQ(cmd.m_orch_desc[3].op, dm_orch_type_db_cfg);
    cmd.deinit();
    std::cout << "Exiting em_cmd_reset_t_max_params test" << std::endl;
}
