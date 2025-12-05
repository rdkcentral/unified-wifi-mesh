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
#include "em_cmd_em_config.h"


/**
 * @brief Tests the full valid configuration of em_cmd_em_config_t API
 *
 * This test verifies that when valid parameters for configuration are provided, the em_cmd_em_config_t 
 * object is initialized correctly and all its member variables are set with the expected values. This 
 * includes proper assignments for the fixed arguments, individual argument values, orchestration descriptor, 
 * and service type.
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
 * | 01 | Initialize parameters with valid test network and argument values. | fixed_args = "TestNetwork", args[0] = "ArgValue1", args[1] = "ArgValue2", num_args = 2 | Parameters should be correctly stored in the params structure | Should Pass |
 * | 02 | Create an instance of dm_easy_mesh_t and then initialize em_cmd_em_config_t using the parameters. | params as initialized above, dm_easy_mesh_t object | The instance should have m_type set to em_cmd_type_em_config and m_name set to "em_config" along with correct configuration of args. | Should Pass |
 * | 03 | Validate instance member variables using assertions. | m_type, m_name, fixed_args, num_args, args[], m_num_orch_desc, orch_desc[0].op, orch_desc[0].submit, m_svc | All EXPECT_EQ and EXPECT_STREQ assertions pass indicating correct initialization. | Should Pass |
 * | 04 | Call the deinit() method on the em_cmd_em_config_t instance to cleanup. | Function call: configCmd.deinit() | deinit() executes without errors, releasing or cleaning up resources as expected. | Should be successful |
 */
TEST(em_cmd_em_config_t, em_cmd_em_config_t_full_valid) {
    std::cout << "Entering em_cmd_em_config_t_full_valid test\n";
    const char* testNetwork = "TestNetwork";
    const char* arg0 = "ArgValue1";
    const char* arg1 = "ArgValue2";
    em_cmd_params_t params{};
    strncpy(params.u.args.fixed_args, testNetwork,
            sizeof(params.u.args.fixed_args) - 1);
    params.u.args.num_args = 2;
    strncpy(params.u.args.args[0], arg0, sizeof(params.u.args.args[0]) - 1);
    strncpy(params.u.args.args[1], arg1, sizeof(params.u.args.args[1]) - 1);
    dm_easy_mesh_t dm{};
    em_cmd_em_config_t configCmd(params, dm);
    EXPECT_EQ(configCmd.m_type, em_cmd_type_em_config);
    EXPECT_STREQ(configCmd.m_name, "em_config");
    EXPECT_STREQ(configCmd.m_param.u.args.fixed_args, testNetwork);
    EXPECT_EQ(configCmd.m_param.u.args.num_args, 2);
    EXPECT_STREQ(configCmd.m_param.u.args.args[0], arg0);
    EXPECT_STREQ(configCmd.m_param.u.args.args[1], arg1);
    EXPECT_EQ(configCmd.m_num_orch_desc, 8);
    EXPECT_EQ(configCmd.m_orch_desc[0].op, dm_orch_type_bss_delete);
    EXPECT_FALSE(configCmd.m_orch_desc[0].submit);
    EXPECT_EQ(configCmd.m_svc, em_service_type_ctrl);
    configCmd.deinit();
    std::cout << "Exiting em_cmd_em_config_t_full_valid test\n";
}
/**
 * @brief Verify the initialization of em_cmd_em_config_t with empty configuration.
 *
 * This test validates that constructing an em_cmd_em_config_t object with default parameters results in correctly set type, name, parameter arguments, and orchestration descriptor. It also confirms that the deinit method cleans up the object appropriately.
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
 * | 01 | Initialize empty em_cmd_params_t and dm_easy_mesh_t objects, then create an instance of em_cmd_em_config_t using these parameters. | params = {}, dm = {} | Instance is created with m_type set to em_cmd_type_em_config, m_name set to "em_config", fixed_args as an empty string, and num_args as 0. | Should Pass |
 * | 02 | Validate that the orchestration fields are correctly initialized. | m_num_orch_desc = 8, orch_desc[0].op = dm_orch_type_bss_delete, orch_desc[0].submit = false, m_svc = em_service_type_ctrl | All field values match the expected configuration. | Should Pass |
 * | 03 | Invoke configCmd.deinit() to release resources. | No input | deinit completes without errors. | Should be successful |
 */
TEST(em_cmd_em_config_t, em_cmd_em_config_t_empty) {
    std::cout << "Entering em_cmd_em_config_t_empty test\n";
    em_cmd_params_t params{};
    dm_easy_mesh_t dm{};
    em_cmd_em_config_t configCmd(params, dm);
    EXPECT_EQ(configCmd.m_type, em_cmd_type_em_config);
    EXPECT_STREQ(configCmd.m_name, "em_config");
    EXPECT_STREQ(configCmd.m_param.u.args.fixed_args, "");
    EXPECT_EQ(configCmd.m_param.u.args.num_args, 0);
    EXPECT_EQ(configCmd.m_num_orch_desc, 8);
    EXPECT_EQ(configCmd.m_orch_desc[0].op, dm_orch_type_bss_delete);
    EXPECT_FALSE(configCmd.m_orch_desc[0].submit);
    EXPECT_EQ(configCmd.m_svc, em_service_type_ctrl);
    configCmd.deinit();
    std::cout << "Exiting em_cmd_em_config_t_empty test\n";
}
/**
 * @brief Verify maximum boundary conditions for em_cmd_em_config_t
 *
 * This test checks that when em_cmd_em_config_t is constructed using maximum boundary-length inputs,
 * all internal fields are correctly initialized. It verifies that fixed argument strings and argument arrays
 * are properly null-terminated and that the configuration command's type, name, and other parameters match the expected values.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize maxFixed buffer with 'A's for maximum boundary test | maxFixed: 127 'A's followed by '\0' | maxFixed is filled with 'A' characters and null terminated | Should be successful |
 * | 02 | Initialize maxArg buffer with 'B's for maximum boundary test | maxArg: 127 'B's followed by '\0' | maxArg is filled with 'B' characters and null terminated | Should be successful |
 * | 03 | Copy maxFixed into params.u.args.fixed_args and set num_args to 2 | fixed_args = maxFixed, num_args = 2 | params.u.args.fixed_args is set to maxFixed and num_args is correctly updated | Should be successful |
 * | 04 | Copy maxArg into params.u.args.args[0] and params.u.args.args[1] | args[0] = maxArg, args[1] = maxArg | args[0] and args[1] are correctly filled with maxArg and null terminated | Should be successful |
 * | 05 | Construct em_cmd_em_config_t object with params and dm context | params (with fixed_args and args), dm (default constructed) | configCmd object is initialized with proper m_type, m_name, and parameter values | Should Pass |
 * | 06 | Validate all fields of configCmd using EXPECT assertions | m_type, m_name, fixed_args, num_args, args, orch descriptor and service type | All EXPECT checks pass confirming that configCmd fields match expected values | Should Pass |
 * | 07 | Call deinit method on configCmd instance | configCmd instance | configCmd is de-initialized properly | Should be successful |
 */
TEST(em_cmd_em_config_t, em_cmd_em_config_t_max_boundary) {
    std::cout << "Entering em_cmd_em_config_t_max_boundary test\n";
    char maxFixed[128];
    for (size_t i = 0; i < sizeof(maxFixed) - 1; ++i) {
        maxFixed[i] = 'A';
    }
    maxFixed[sizeof(maxFixed) - 1] = '\0';
    char maxArg[128];
    for (size_t i = 0; i < sizeof(maxArg) - 1; ++i) {
        maxArg[i] = 'B';
    }
    maxArg[sizeof(maxArg) - 1] = '\0';
    em_cmd_params_t params{};
    std::cout << "Preparing max-length arguments\n";
    strncpy(params.u.args.fixed_args, maxFixed, sizeof(params.u.args.fixed_args) - 1);
    params.u.args.fixed_args[sizeof(params.u.args.fixed_args) - 1] = '\0';
    params.u.args.num_args = 2;
    strncpy(params.u.args.args[0], maxArg, sizeof(params.u.args.args[0]) - 1);
    params.u.args.args[0][sizeof(params.u.args.args[0]) - 1] = '\0';
    strncpy(params.u.args.args[1], maxArg, sizeof(params.u.args.args[1]) - 1);
    params.u.args.args[1][sizeof(params.u.args.args[1]) - 1] = '\0';
    dm_easy_mesh_t dm{};
    em_cmd_em_config_t configCmd(params, dm);
    EXPECT_EQ(configCmd.m_type, em_cmd_type_em_config);
    EXPECT_STREQ(configCmd.m_name, "em_config");
    EXPECT_STREQ(configCmd.m_param.u.args.fixed_args, maxFixed);
    EXPECT_EQ(configCmd.m_param.u.args.num_args, 2);
    EXPECT_STREQ(configCmd.m_param.u.args.args[0], maxArg);
    EXPECT_STREQ(configCmd.m_param.u.args.args[1], maxArg);
    EXPECT_EQ(configCmd.m_num_orch_desc, 8);
    EXPECT_EQ(configCmd.m_orch_desc[0].op, dm_orch_type_bss_delete);
    EXPECT_FALSE(configCmd.m_orch_desc[0].submit);
    EXPECT_EQ(configCmd.m_svc, em_service_type_ctrl);
    configCmd.deinit();
    std::cout << "Exiting em_cmd_em_config_t_max_boundary test\n";
}
