
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
#include "em_cmd_get_mld_config.h"


/**
 * @brief Verify that the em_cmd_get_mld_config_t constructor properly initializes all member variables with fully-populated input parameters.
 *
 * This test validates the initialization of the command object em_cmd_get_mld_config_t using a fully-populated parameter structure.
 * It ensures that the fixed arguments and the variable argument list are correctly set and that the command type, name, service type,
 * and related indices are assigned as expected.
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
 * | Variation / Step | Description                                                                   | Test Data                                                                                                                       | Expected Result                                                                                                                        | Notes         |
 * | :--------------: | ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- | ------------- |
 * | 01               | Initialize the parameter structure with fully-populated test data.           | input: fixed_args = "FullPopulatedFixedArg", num_args = 3, args[0] = "Arg0", args[1] = "Arg1", args[2] = "Arg2"                  | Parameter structure is correctly initialized with the given values.                                                                    | Should be successful |
 * | 02               | Invoke the constructor of em_cmd_get_mld_config_t with initialized parameters.| input: param (populated as above), dm (default-initialized instance)                                                              | Command object is constructed with properly assigned member variables including command type, name, service type, and indices.             | Should Pass   |
 * | 03               | Validate the command object’s members using EXPECT_* assertions.             | input: Accessed object members: num_args, fixed_args, args[0], args[1], args[2], m_type, m_name, m_svc, m_orch_op_idx, m_num_orch_desc | All assertions pass confirming that each member is correctly set according to the input test data and expected defaults.                 | Should Pass   |
 * | 04               | Invoke the deinit() function to clean up the command object.                 | input: cmd.deinit()                                                                                                              | deinit() completes successfully without errors.                                                                                        | Should Pass   |
 */
TEST(em_cmd_get_mld_config_t, ctor_full_populated) {
    std::cout << "Entering em_cmd_get_mld_config_t_ctor_full_populated test" << std::endl;
    em_cmd_params_t param;
    strncpy(param.u.args.fixed_args, "FullPopulatedFixedArg", sizeof(param.u.args.fixed_args));
    param.u.args.num_args = 3;
    strncpy(param.u.args.args[0], "Arg0", sizeof(param.u.args.args[0]));
    strncpy(param.u.args.args[1], "Arg1", sizeof(param.u.args.args[1]));
    strncpy(param.u.args.args[2], "Arg2", sizeof(param.u.args.args[2]));
    std::cout << "Param fixed_args: " << param.u.args.fixed_args << std::endl;
    std::cout << "Param num_args: " << param.u.args.num_args << std::endl;
    std::cout << "Param arg[0]: " << param.u.args.args[0] << std::endl;
    std::cout << "Param arg[1]: " << param.u.args.args[1] << std::endl;
    std::cout << "Param arg[2]: " << param.u.args.args[2] << std::endl;
    dm_easy_mesh_t dm;
    em_cmd_get_mld_config_t cmd(param, dm);
    std::cout << "Invoked em_cmd_get_mld_config_t constructor with fully-populated parameters" << std::endl;
    EXPECT_EQ(cmd.m_param.u.args.num_args, 3);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "FullPopulatedFixedArg");
    EXPECT_STREQ(cmd.m_param.u.args.args[0], "Arg0");
    EXPECT_STREQ(cmd.m_param.u.args.args[1], "Arg1");
    EXPECT_STREQ(cmd.m_param.u.args.args[2], "Arg2");
    EXPECT_EQ(cmd.m_type, em_cmd_type_get_mld_config);
    EXPECT_STREQ(cmd.m_name, "get_mld_config");
    EXPECT_EQ(cmd.m_svc, em_service_type_agent);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
	EXPECT_EQ(cmd.m_num_orch_desc, 0);
    cmd.deinit();
    std::cout << "Exiting em_cmd_get_mld_config_t_ctor_full_populated test" << std::endl;
}
/**
 * @brief Verify that em_cmd_get_mld_config_t constructor properly initializes the command object with maximum fixed arguments.
 *
 * This test verifies that the constructor of em_cmd_get_mld_config_t correctly assigns and initializes all member variables when provided with maximum fixed arguments and a valid argument array. It ensures proper string termination, correct numeric assignments, and proper command identification.
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
 * | 01 | Initialize test parameters with maximum fixed arguments and argument array. | fixed_args = string of 127 'X', num_args = 5, args[0] = string of 127 'Y' | Parameters are correctly populated and null-terminated. | Should Pass |
 * | 02 | Construct the command object using the initialized parameters and a dummy dm instance. | param (with above values), dm object | Command object is created; m_type, m_name, and m_svc are correctly set. | Should Pass |
 * | 03 | Validate command object attributes using assertions. | Expected: m_type = em_cmd_type_get_mld_config, m_name = "get_mld_config", m_svc = em_service_type_agent, num_args = 5, fixed_args and args[0] matching initialized values | All assertions pass confirming proper initialization. | Should Pass |
 * | 04 | Invoke deinit on the command object to clean up resources. | cmd.deinit() call | Object is deinitialized without errors. | Should be successful |
 */
TEST(em_cmd_get_mld_config_t, ctor_max_fixed_args) {
    std::cout << "Entering em_cmd_get_mld_config_t_ctor_max_fixed_args test" << std::endl;
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
    em_cmd_get_mld_config_t cmd(param, dm);
    EXPECT_EQ(cmd.m_type, em_cmd_type_get_mld_config);
    EXPECT_STREQ(cmd.m_name, "get_mld_config");
    EXPECT_EQ(cmd.m_svc, em_service_type_agent);
    EXPECT_EQ(cmd.m_param.u.args.num_args, 5);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, param.u.args.fixed_args);
    EXPECT_STREQ(cmd.m_param.u.args.args[0], param.u.args.args[0]);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 0);
    cmd.deinit();
    std::cout << "Exiting em_cmd_get_mld_config_t_ctor_max_fixed_args test" << std::endl;
}
/**
 * @brief Verify that the em_cmd_get_mld_config_t constructor correctly initializes object members using the alternative union field (steer_params)
 *
 * This test verifies that when an em_cmd_get_mld_config_t object is constructed using a parameter structure with the steer_params union fields set, 
 * all the corresponding object members (including m_type, m_name, m_svc, m_param, m_orch_op_idx, and m_num_orch_desc) are properly initialized. 
 * The test confirms that the values supplied (request_mode = 42 and target_channel = 6) are correctly transferred to the new object.
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
 * | Variation / Step | Description                                                                                          | Test Data                                                                                                              | Expected Result                                                                                                          | Notes       |
 * | :--------------: | ---------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | ----------- |
 * | 01               | Set steer_params fields in em_cmd_params_t (request_mode = 42, target_channel = 6) and invoke the constructor of em_cmd_get_mld_config_t  | input: request_mode = 42, target_channel = 6; expected: m_type = em_cmd_type_get_mld_config, m_name = get_mld_config, m_svc = em_service_type_agent, m_param.steer_params.request_mode = 42, m_param.steer_params.target_channel = 6, m_orch_op_idx = 0, m_num_orch_desc = 0  | The em_cmd_get_mld_config_t object is initialized with the correct values and all assertion checks pass                          | Should Pass |
 */
TEST(em_cmd_get_mld_config_t, ctor_alternative_union_field) {
    std::cout << "Entering em_cmd_get_mld_config_t_ctor_alternative_union_field test" << std::endl;
    em_cmd_params_t param;
    param.u.steer_params.request_mode = 42;
    param.u.steer_params.target_channel = 6;
    std::cout << "Param steer_params.request_mode: " << param.u.steer_params.request_mode << std::endl;
    std::cout << "Param steer_params.target_channel: " << param.u.steer_params.target_channel << std::endl;
    dm_easy_mesh_t dm;
    em_cmd_get_mld_config_t cmd(param, dm);
    std::cout << "Invoked em_cmd_get_mld_config_t constructor using alternative union field (steer_params)" << std::endl;
    EXPECT_EQ(cmd.m_type, em_cmd_type_get_mld_config);
    EXPECT_STREQ(cmd.m_name, "get_mld_config");
    EXPECT_EQ(cmd.m_svc, em_service_type_agent);
    EXPECT_EQ(cmd.m_param.u.steer_params.request_mode, 42);
    EXPECT_EQ(cmd.m_param.u.steer_params.target_channel, 6);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 0);
    cmd.deinit();
    std::cout << "Exiting em_cmd_get_mld_config_t_ctor_alternative_union_field test" << std::endl;
}
/**
 * @brief Verifies that the em_cmd_get_mld_config_t constructor properly initializes its members with a minimally initialized dm_easy_mesh_t.
 *
 * This test ensures that when the constructor is invoked with a zeroed em_cmd_params_t and a minimally initialized dm_easy_mesh_t, 
 * the em_cmd_get_mld_config_t object is assigned the expected type, name, service type, and indices. It also verifies that deinit() works properly.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 004@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01 | Initialize the parameter structure and dm object; call the constructor with these minimal values | param = em_cmd_params_t (all fields zeroed), dm = minimally initialized dm_easy_mesh_t | The constructor is called and returns a valid object instance with default field values | Should Pass |@n
 * | 02 | Validate that the object's fields match the expected initialization values using assertions | input: cmd object with: m_type, m_name, m_svc, m_orch_op_idx, m_num_orch_desc; expected: m_type = em_cmd_type_get_mld_config, m_name = "get_mld_config", m_svc = em_service_type_agent, m_orch_op_idx = 0, m_num_orch_desc = 0 | Each assertion passes, confirming the expected state of the object | Should Pass |@n
 * | 03 | Call deinit() on the object to clean up resources | input: cmd.deinit() invocation | deinit() completes without error | Should be successful |
 */
TEST(em_cmd_get_mld_config_t, ctor_minimally_initialized_dm) {
    std::cout << "Entering em_cmd_get_mld_config_t_ctor_minimally_initialized_dm test" << std::endl;
    em_cmd_params_t param;
    memset(&param, 0, sizeof(em_cmd_params_t));
    dm_easy_mesh_t dm;
    em_cmd_get_mld_config_t cmd(param, dm);
    std::cout << "Invoked em_cmd_get_mld_config_t constructor with minimally initialized dm_easy_mesh_t" << std::endl;
    EXPECT_EQ(cmd.m_type, em_cmd_type_get_mld_config);
    EXPECT_STREQ(cmd.m_name, "get_mld_config");
    EXPECT_EQ(cmd.m_svc, em_service_type_agent);        
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 0);
    cmd.deinit();
    std::cout << "Exiting em_cmd_get_mld_config_t_ctor_minimally_initialized_dm test" << std::endl;
}
