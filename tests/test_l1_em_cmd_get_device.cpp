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
#include "em_cmd_get_device.h"


/**
 * @brief Verify that em_cmd_get_device_t object is initialized correctly with fully-populated input.
 *
 * This test verifies that when fully populated input parameters are provided to the em_cmd_get_device_t constructor,
 * the resulting object's internal state (including num_args, fixed_args, individual arguments, type, name, service type,
 * and orchestration indices) is set as expected. It ensures that the command parameter initialization and subsequent assertions
 * align with predefined expectations for a positive scenario.
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
 * | Variation / Step | Description                                                                                                   | Test Data                                                                                                                             | Expected Result                                                                                                                                                                                             | Notes           |
 * | :--------------: | ------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------- |
 * | 01               | Initialize command parameters with fully populated values (num_args, fixed_args, and argument strings).       | input: num_args = 3, fixed_args = "fixed_parameters", args[0] = "argument_one", args[1] = "argument_two", args[2] = "argument_three" | Command parameter structure is populated with the provided values.                                                                                                                                        | Should be successful |
 * | 02               | Create em_cmd_get_device_t object using the fully populated input parameters.                                | input: cmdParams structure and dm object                                                                                              | em_cmd_get_device_t object is created successfully with all internal members initialized as per inputs.                                                                                                     | Should Pass     |
 * | 03               | Validate the properties of the created em_cmd_get_device_t object using assertions.                           | output: m_param.u.args.num_args = 3, m_param.u.args.fixed_args = "fixed_parameters", m_param.u.args.args[0] = "argument_one", m_param.u.args.args[1] = "argument_two", m_param.u.args.args[2] = "argument_three", m_type = em_cmd_type_get_device, m_name = "get_device", m_svc = em_service_type_ctrl, m_orch_op_idx = 0, m_num_orch_desc = 0 | All assertion checks (EXPECT_EQ, EXPECT_STREQ) pass confirming proper field values.                                                                                  | Should Pass     |
 * | 04               | Clean up resources by invoking the deinit() method on the command object.                                     | invocation: cmd.deinit()                                                                                                                | Resources associated with the command object are cleaned up successfully.                                                                                                                                  | Should be successful |
 */
TEST(em_cmd_get_device_t, em_cmd_get_device_t_FullyPopulatedInput) {
    std::cout << "Entering em_cmd_get_device_t_FullyPopulatedInput test" << std::endl;
    em_cmd_params_t cmdParams;
    cmdParams.u.args.num_args = 3;
    const char *fixedStr = "fixed_parameters";
    std::cout << "Setting fixed_args: " << fixedStr << std::endl;
    strncpy(cmdParams.u.args.fixed_args, fixedStr, sizeof(cmdParams.u.args.fixed_args));
    const char *arg0 = "argument_one";
    const char *arg1 = "argument_two";
    const char *arg2 = "argument_three";
    std::cout << "Setting args[0]: " << arg0 << std::endl;
    strncpy(cmdParams.u.args.args[0], arg0, sizeof(cmdParams.u.args.args[0]));
    std::cout << "Setting args[1]: " << arg1 << std::endl;
    strncpy(cmdParams.u.args.args[1], arg1, sizeof(cmdParams.u.args.args[1]));
    std::cout << "Setting args[2]: " << arg2 << std::endl;
    strncpy(cmdParams.u.args.args[2], arg2, sizeof(cmdParams.u.args.args[2]));
    dm_easy_mesh_t dm;
    em_cmd_get_device_t cmd(cmdParams, dm);
    std::cout << "em_cmd_get_device_t object created successfully with fully-populated input." << std::endl;
    EXPECT_EQ(cmd.m_param.u.args.num_args, 3);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "fixed_parameters");
    EXPECT_STREQ(cmd.m_param.u.args.args[0], "argument_one");
    EXPECT_STREQ(cmd.m_param.u.args.args[1], "argument_two");
    EXPECT_STREQ(cmd.m_param.u.args.args[2], "argument_three");
    EXPECT_EQ(cmd.m_type, em_cmd_type_get_device);
    EXPECT_STREQ(cmd.m_name, "get_device");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 0);
    cmd.deinit();
    std::cout << "Exiting em_cmd_get_device_t_FullyPopulatedInput test" << std::endl;
}
/**
 * @brief Test to verify the initialization of em_cmd_get_device_t with minimal empty inputs
 *
 * This test verifies that the em_cmd_get_device_t API properly initializes its internal parameters when provided with minimal (empty) input values. It ensures that the num_args, fixed_args, and args fields are set to empty, and that other command properties such as type, name, service, and orchestration indices are correctly assigned.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize em_cmd_params_t structure with num_args set to 0, and clear fixed_args as well as each element in the args array. | cmdParams.u.args.num_args = 0, cmdParams.u.args.fixed_args = empty (all zeros), for i in 0..(EM_CLI_MAX_ARGS-1): cmdParams.u.args.args[i] = empty (all zeros) | The structure fields are correctly set to empty values | Should be successful |
 * | 02 | Create a dm_easy_mesh_t instance and construct the em_cmd_get_device_t object using the empty parameters. | dm_easy_mesh_t dm instance created; call: em_cmd_get_device_t cmd(cmdParams, dm) | The command object is created successfully with the provided minimal inputs | Should Pass |
 * | 03 | Validate that the em_cmd_get_device_t object's fields match the initialized parameters including command type, name, service, and orchestration indices. | Expected: m_param.u.args.num_args = 0, m_param.u.args.fixed_args = empty, m_param.u.args.args[] = empty, m_type = em_cmd_type_get_device, m_name = "get_device", m_svc = em_service_type_ctrl, m_orch_op_idx = 0, m_num_orch_desc = 0 | All assertions (EXPECT_EQ, EXPECT_STREQ) pass, confirming correct initialization | Should Pass |
 * | 04 | Deinitialize the command object by invoking its deinit() method. | Call: cmd.deinit() | The command object is deinitialized properly without any errors | Should be successful |
 */
TEST(em_cmd_get_device_t, em_cmd_get_device_t_MinimalEmptyInput) {
    std::cout << "Entering em_cmd_get_device_t_MinimalEmptyInput test" << std::endl;
    em_cmd_params_t cmdParams;
    cmdParams.u.args.num_args = 0;
    std::cout << "Setting fixed_args to empty string." << std::endl;
    memset(cmdParams.u.args.fixed_args, 0, sizeof(cmdParams.u.args.fixed_args));
    for (unsigned int i = 0; i < EM_CLI_MAX_ARGS; i++) {
        memset(cmdParams.u.args.args[i], 0, sizeof(cmdParams.u.args.args[i]));
    }
    dm_easy_mesh_t dm;
    em_cmd_get_device_t cmd(cmdParams, dm);
    std::cout << "em_cmd_get_device_t object created successfully with minimal (empty) inputs." << std::endl;
    EXPECT_EQ(cmd.m_param.u.args.num_args, 0);
    EXPECT_EQ(memcmp(cmd.m_param.u.args.fixed_args, cmdParams.u.args.fixed_args, sizeof(cmdParams.u.args.fixed_args)), 0);
    for (unsigned int i = 0; i < EM_CLI_MAX_ARGS; i++) {
        EXPECT_EQ(memcmp(cmd.m_param.u.args.args[i], cmdParams.u.args.args[i], sizeof(cmdParams.u.args.args[i])), 0);
    }
    EXPECT_EQ(cmd.m_type, em_cmd_type_get_device);
    EXPECT_STREQ(cmd.m_name, "get_device");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 0);
    cmd.deinit();
    std::cout << "Exiting em_cmd_get_device_t_MinimalEmptyInput test" << std::endl;
}
/**
 * @brief Test boundary conditions for maximum argument sizes for em_cmd_get_device_t object creation
 *
 * This test verifies that the em_cmd_get_device_t object can correctly handle the maximum allowed sizes for fixed arguments and an array of argument strings. It initializes the command parameters with the maximum argument count and maximum length strings, creates the em_cmd_get_device_t object, and then validates that all the properties are set as expected.
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
 * | Variation / Step | Description                                                       | Test Data                                                                                         | Expected Result                                                                                              | Notes           |
 * | :--------------: | ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ | --------------- |
 * | 01               | Initialize command parameters and prepare a maximum length string   | cmdParams.u.args.num_args = EM_CLI_MAX_ARGS, maxStr = 'A' repeated (127 times) followed by '\0'     | cmdParams and maxStr are initialized correctly                                                               | Should be successful |
 * | 02               | Set fixed_args in command parameters with the maximum length string  | fixed_args = maxStr                                                                               | cmdParams.u.args.fixed_args contains the expected maximum length string                                       | Should be successful |
 * | 03               | Populate each element in args array with the maximum length string     | For each index i in [0, EM_CLI_MAX_ARGS-1], args[i] = maxStr                                        | Each cmdParams.u.args.args[i] contains the expected maximum length string                                     | Should be successful |
 * | 04               | Instantiate em_cmd_get_device_t object using the command parameters   | Input: cmdParams (with maximum strings), dm instance                                              | em_cmd_get_device_t object is created successfully with boundary max argument sizes                           | Should Pass     |
 * | 05               | Validate object properties including type, name, service, and strings   | m_type = em_cmd_type_get_device, m_name = "get_device", m_svc = em_service_type_ctrl, fixed_args and args array as set in cmdParams | All assertions pass confirming proper initialization of the object                                            | Should Pass     |
 * | 06               | Invoke deinit() on the command object for cleanup                     | Call cmd.deinit()                                                                                 | Object deinitialization is executed successfully                                                              | Should be successful |
 */
TEST(em_cmd_get_device_t, em_cmd_get_device_t_BoundaryMaxArgumentSizes) {
    std::cout << "Entering em_cmd_get_device_t_BoundaryMaxArgumentSizes test" << std::endl;
    em_cmd_params_t cmdParams{};
    cmdParams.u.args.num_args = EM_CLI_MAX_ARGS;
    char maxStr[128];
    memset(maxStr, 'A', sizeof(maxStr) - 1);
    maxStr[sizeof(maxStr) - 1] = '\0';
    std::cout << "Setting fixed_args with maximum length string: " << maxStr << std::endl;
    strncpy(cmdParams.u.args.fixed_args, maxStr, sizeof(cmdParams.u.args.fixed_args));
    for (unsigned int i = 0; i < cmdParams.u.args.num_args; i++) {
        std::cout << "Setting args[" << i << "] with maximum length string." << std::endl;
        strncpy(cmdParams.u.args.args[i], maxStr, sizeof(cmdParams.u.args.args[i]));
    }
    dm_easy_mesh_t dm;
    em_cmd_get_device_t cmd(cmdParams, dm);
    std::cout << "em_cmd_get_device_t object created successfully with boundary max argument sizes." << std::endl;
    EXPECT_EQ(cmd.m_type, em_cmd_type_get_device);
    EXPECT_STREQ(cmd.m_name, "get_device");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, cmdParams.u.args.fixed_args);
    for (unsigned int i = 0; i < EM_CLI_MAX_ARGS; i++) {
        EXPECT_STREQ(cmd.m_param.u.args.args[i], cmdParams.u.args.args[i]);
    }
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 0);
    EXPECT_EQ(cmd.m_param.u.args.num_args, EM_CLI_MAX_ARGS);
    cmd.deinit();
    std::cout << "Exiting em_cmd_get_device_t_BoundaryMaxArgumentSizes test" << std::endl;
}
