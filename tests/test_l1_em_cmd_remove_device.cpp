
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
#include "em_cmd_remove_device.h"


/**
 * @brief Test valid removal of a device command
 *
 * This test validates that the "remove_device" command is correctly initialized, has all expected member values, and cleans up properly. It ensures that setting the parameters, creating the command object, and invoking the deinitialization function operate as expected.
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
 * | 01 | Initialize test parameters and device context for remove device command. | params.u.args.fixed_args = "remove_device", params.u.args.num_args = 1, params.u.args.args[0] = "Arg0" | Parameters and context are set correctly. | Should be successful |
 * | 02 | Instantiate em_cmd_remove_device_t object and verify that all command properties are correctly set. | m_type = em_cmd_type_remove_device, m_orch_op_idx = 0, m_num_orch_desc = 3, m_orch_desc[0].op = dm_orch_type_db_delete, m_orch_desc[1].op = dm_orch_type_em_delete, m_orch_desc[2].op = dm_orch_type_dm_delete, m_name = "remove_device", m_svc = em_service_type_ctrl, m_param.u.args.fixed_args = "remove_device", m_param.u.args.num_args = 1, m_param.u.args.args[0] = "Arg0", m_data_model.m_cmd_ctx.type = dm_orch_type_db_delete | All EXPECT_EQ and EXPECT_STREQ assertions pass. | Should Pass |
 * | 03 | Cleanup command object by calling deinit. | cmd.deinit() | Deinitialization completes without errors. | Should be successful |
 */
TEST(em_cmd_remove_device_t, em_cmd_remove_device_t_valid_remove)
{
    std::cout << "Entering em_cmd_remove_device_t_valid_remove test" << std::endl;
    em_cmd_params_t params;
    memset(&params, 0, sizeof(params));
    strncpy(params.u.args.fixed_args, "remove_device", sizeof(params.u.args.fixed_args)-1);
    params.u.args.num_args = 1;
    strncpy(params.u.args.args[0], "Arg0", sizeof(params.u.args.args[0]));
    dm_easy_mesh_t dm;
    em_cmd_remove_device_t cmd(params, dm);
    EXPECT_EQ(cmd.m_type, em_cmd_type_remove_device);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 3);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_db_delete);
    EXPECT_EQ(cmd.m_orch_desc[1].op, dm_orch_type_em_delete);
    EXPECT_EQ(cmd.m_orch_desc[2].op, dm_orch_type_dm_delete);
    EXPECT_STREQ(cmd.m_name, "remove_device");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "remove_device");
    EXPECT_EQ(cmd.m_param.u.args.num_args, 1);
    EXPECT_STREQ(cmd.m_param.u.args.args[0], "Arg0");
    EXPECT_EQ(cmd.m_data_model.m_cmd_ctx.type, dm_orch_type_db_delete);
    cmd.deinit();
    std::cout << "Exiting em_cmd_remove_device_t_valid_remove test" << std::endl;
}
/**
 * @brief Verifies that the em_cmd_remove_device_t constructor correctly initializes the object with empty parameters.
 *
 * This test verifies that when an em_cmd_remove_device_t object is instantiated with default (empty) parameters,
 * all its internal member variables including type, name, service, parameter memory, orchestration indexes,
 * orchestration descriptors, and command context are initialized to their expected default values.
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
 * | 01 | Print entering message and initialize default parameters and dm instance. | N/A | Console displays "Entering em_cmd_remove_device_t_empty_params test" and instances of params and dm are created with default values. | Should be successful |
 * | 02 | Invoke em_cmd_remove_device_t constructor with empty params and dm instance. | params = {} (default), dm = default constructed | Command object created with m_type equal to em_cmd_type_remove_device, m_name equal to "remove_device", and m_svc equal to em_service_type_ctrl. | Should Pass |
 * | 03 | Verify the initialization of internal members including m_param, orchestration operation index, number of orchestration descriptors, and the values of all orchestration descriptors along with the command context type. | m_param compared to params, m_orch_op_idx = 0, m_num_orch_desc = 3, m_orch_desc = [dm_orch_type_db_delete, dm_orch_type_em_delete, dm_orch_type_dm_delete], m_data_model.m_cmd_ctx.type = dm_orch_type_db_delete | All EXPECT_EQ and EXPECT_STREQ assertions pass confirming proper field initialization. | Should Pass |
 * | 04 | Invoke the deinit method to clean up the command object and print the exiting message. | cmd.deinit() called | Resources are cleaned up successfully and console displays "Exiting em_cmd_remove_device_t_empty_params test". | Should Pass |
 */
TEST(em_cmd_remove_device_t, em_cmd_remove_device_t_empty_params)
{
    std::cout << "Entering em_cmd_remove_device_t_empty_params test" << std::endl;
    em_cmd_params_t params{};
    dm_easy_mesh_t dm;
    em_cmd_remove_device_t cmd(params, dm);
    EXPECT_EQ(cmd.m_type, em_cmd_type_remove_device);
    EXPECT_STREQ(cmd.m_name, "remove_device");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_EQ(memcmp(&cmd.m_param, &params, sizeof(params)), 0);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 3);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_db_delete);
    EXPECT_EQ(cmd.m_orch_desc[1].op, dm_orch_type_em_delete);
    EXPECT_EQ(cmd.m_orch_desc[2].op, dm_orch_type_dm_delete);
    EXPECT_EQ(cmd.m_data_model.m_cmd_ctx.type, dm_orch_type_db_delete);
    cmd.deinit();
    std::cout << "Exiting em_cmd_remove_device_t_empty_params test" << std::endl;
}
/**
 * @brief Validate that em_cmd_remove_device_t correctly initializes all parameters when maximum argument count is used.
 *
 * This test verifies that the em_cmd_remove_device_t API correctly copies the fixed command string and each argument when the maximum allowed number of arguments (EM_CLI_MAX_ARGS) is provided. It ensures that the command object's properties, including service type and orchestration details, are correctly set based on the input parameters.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize em_cmd_params_t with fixed_args set to "remove_device", num_args set to EM_CLI_MAX_ARGS, and populate each argument with a long string, with the first argument set to "MAX_DEVICE". | params.u.args.fixed_args = "remove_device", params.u.args.num_args = EM_CLI_MAX_ARGS, params.u.args.args[0] = "MAX_DEVICE", params.u.args.args[i] = a 127-character string of 'X' for i ≥ 1 | Parameters structure is correctly initialized with the expected string values and argument count | Should be successful |
 * | 02 | Instantiate dm_easy_mesh_t and create em_cmd_remove_device_t object using the parameters; validate all internal fields of the command object. | Construct cmd with (params, dm) | cmd.m_type equals em_cmd_type_remove_device, cmd.m_name equals "remove_device", cmd.m_svc equals em_service_type_ctrl, m_param fields match the input parameters, m_orch_desc[0].op equals dm_orch_type_db_delete, m_orch_desc[1].op equals dm_orch_type_em_delete, m_orch_desc[2].op equals dm_orch_type_dm_delete, and m_data_model.m_cmd_ctx.type equals dm_orch_type_db_delete | Should Pass |
 * | 03 | Call the deinit() method on the command object to perform cleanup. | cmd.deinit() | The deinit() function is executed without errors and cleans up the object properly | Should be successful |
 */
TEST(em_cmd_remove_device_t, em_cmd_remove_device_t_max_params)
{
    std::cout << "Entering em_cmd_remove_device_t_max_params test" << std::endl;
    em_cmd_params_t params;
    memset(&params, 0, sizeof(params));
    const char* removeDeviceStr = "remove_device";
    strncpy(params.u.args.fixed_args, removeDeviceStr, sizeof(params.u.args.fixed_args)-1);
    params.u.args.num_args = EM_CLI_MAX_ARGS;
    for (unsigned int i = 0; i < params.u.args.num_args; i++) {
        char longId[128];
        memset(longId, 'X', sizeof(longId)-1);
        longId[127] = '\0';
        if(i == 0) {
            strncpy(longId, "MAX_DEVICE", 10);
        }
        strncpy(params.u.args.args[i], longId, sizeof(params.u.args.args[i])-1);
    }
    dm_easy_mesh_t dm;
    em_cmd_remove_device_t cmd(params, dm);
    EXPECT_EQ(cmd.m_type, em_cmd_type_remove_device);
    EXPECT_STREQ(cmd.m_name, "remove_device");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_EQ(cmd.m_param.u.args.num_args, params.u.args.num_args);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, params.u.args.fixed_args);
    for (unsigned int i = 0; i < params.u.args.num_args; i++) {
        EXPECT_STREQ(cmd.m_param.u.args.args[i], params.u.args.args[i]);
    }
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 3);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_db_delete);
    EXPECT_EQ(cmd.m_orch_desc[1].op, dm_orch_type_em_delete);
    EXPECT_EQ(cmd.m_orch_desc[2].op, dm_orch_type_dm_delete);
    EXPECT_EQ(cmd.m_data_model.m_cmd_ctx.type, dm_orch_type_db_delete);
    cmd.deinit();
    std::cout << "Exiting em_cmd_remove_device_t_max_params test" << std::endl;
}
