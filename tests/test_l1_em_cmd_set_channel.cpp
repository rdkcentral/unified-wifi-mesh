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
#include "em_cmd_set_channel.h"


/**
 * @brief Validate em_cmd_set_channel_t creation with a valid channel value "6"
 *
 * This test verifies that the em_cmd_set_channel_t instance is correctly initialized when provided with a valid channel number ("6"). The test checks that the command type, name, fixed arguments, number of arguments, service type, number of orchestrator descriptors, and individual orchestrator descriptor properties are set as expected.
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
 * | Variation / Step | Description                                                                | Test Data                                                                                                                                                                                                                          | Expected Result                                                                                                                                                                     | Notes      |
 * | :--------------: | -------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
 * | 01               | Initialize parameters and environment, then invoke em_cmd_set_channel_t API with fixed_args set to "6" | input: param.u.args.fixed_args = "6", dm_easy_mesh_t instance; output: cmd.m_type, cmd.m_name, cmd.m_param.u.args.fixed_args, cmd.m_param.u.args.num_args, cmd.m_svc, cmd.m_num_orch_desc, cmd.m_orch_desc[0].op, cmd.m_orch_desc[0].submit | Command object has m_type equal to em_cmd_type_set_channel, m_name equal to "set_channel", fixed_args equal to "6", num_args equal to 0, m_svc equal to em_service_type_ctrl, m_num_orch_desc equal to 2, orch_desc[0].op equal to dm_orch_type_channel_sel, orch_desc[0].submit equal to true | Should Pass |
 */
TEST(em_cmd_set_channel_t, em_cmd_set_channel_t_valid_channel_6) {
    std::cout << "Entering em_cmd_set_channel_t_valid_channel_6 test" << std::endl;
    em_cmd_params_t param{};
    strncpy(param.u.args.fixed_args, "6", sizeof(param.u.args.fixed_args) - 1);
    param.u.args.fixed_args[sizeof(param.u.args.fixed_args)-1] = '\0';
    dm_easy_mesh_t dm{};
    std::cout << "Invoking em_cmd_set_channel_t with fixed_args = \"" << param.u.args.fixed_args << "\"" << std::endl;
    em_cmd_set_channel_t cmd(param, dm);
    EXPECT_EQ(cmd.m_type, em_cmd_type_set_channel);
    EXPECT_STREQ(cmd.m_name, "set_channel");
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "6");
    EXPECT_EQ(cmd.m_param.u.args.num_args, 0);
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_EQ(cmd.m_num_orch_desc, 2);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_channel_sel);
    EXPECT_TRUE(cmd.m_orch_desc[0].submit);
    cmd.deinit();
    std::cout << "Exiting em_cmd_set_channel_t_valid_channel_6 test" << std::endl;
}
/**
 * @brief Validate that em_cmd_set_channel_t correctly processes a valid channel identifier.
 *
 * This test verifies that the em_cmd_set_channel_t constructor properly initializes the command object when provided with a valid channel "11". It checks that the command type, name, fixed argument, service type, and orchestrator descriptors are set as expected. This is critical to ensure that subsequent operations relying on channel settings function correctly.
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
 * | Variation / Step | Description                                                                                          | Test Data                                                                                        | Expected Result                                                                                                                                         | Notes      |
 * | :--------------: | ---------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
 * | 01               | Initialize the command parameters with fixed_args set to "11", invoke em_cmd_set_channel_t, and verify property values | param.u.args.fixed_args = "11", dm_easy_mesh_t dm = default, output: m_type, m_name, fixed_args, m_svc, m_num_orch_desc, m_orch_desc[0].op, m_orch_desc[0].submit | m_type equals em_cmd_type_set_channel, m_name equals "set_channel", fixed_args equals "11", m_svc equals em_service_type_ctrl, m_num_orch_desc equals 2, m_orch_desc[0].op equals dm_orch_type_channel_sel, m_orch_desc[0].submit is true | Should Pass |
 */
TEST(em_cmd_set_channel_t, em_cmd_set_channel_t_valid_channel_11) {
    std::cout << "Entering em_cmd_set_channel_t_valid_channel_11 test" << std::endl;
    em_cmd_params_t param{};
    strncpy(param.u.args.fixed_args, "11", sizeof(param.u.args.fixed_args) - 1);
    param.u.args.fixed_args[sizeof(param.u.args.fixed_args)-1] = '\0';
    dm_easy_mesh_t dm{};
    std::cout << "Invoking em_cmd_set_channel_t with fixed_args = \"" << param.u.args.fixed_args << "\"" << std::endl;
    em_cmd_set_channel_t cmd(param, dm);
    EXPECT_EQ(cmd.m_type, em_cmd_type_set_channel);
    EXPECT_STREQ(cmd.m_name, "set_channel");
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "11");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_EQ(cmd.m_num_orch_desc, 2);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_channel_sel);
    EXPECT_TRUE(cmd.m_orch_desc[0].submit);
    cmd.deinit();
    std::cout << "Exiting em_cmd_set_channel_t_valid_channel_11 test" << std::endl;
}
/**
 * @brief Verify the API behavior for empty channel input
 *
 * This test validates that when an empty channel input (empty fixed_args array) is provided to the 
 * em_cmd_set_channel_t constructor, the resulting command object is correctly initialized. The test 
 * ensures that all internal fields of the command (type, name, parameters, service type, orchestration 
 * descriptor count, and orchestration descriptor values) match the expected values. This is critical 
 * to ensure that the API correctly handles edge cases and does not lead to undefined behavior or memory issues.
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
 * | Variation / Step | Description | Test Data | Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize input parameters with empty channel string and default dm object | param.u.args.fixed_args[0] = '\0', param.u.args.fixed_args[last] = '\0', dm = default constructed dm_easy_mesh_t | Parameters initialized without errors; no output produced | Should be successful |
 * | 02 | Call em_cmd_set_channel_t constructor with the prepared parameters | input: param (with empty fixed_args), dm object | cmd.m_type equals em_cmd_type_set_channel, cmd.m_name equals "set_channel", cmd.m_param.u.args.fixed_args equals empty string, cmd.m_svc equals em_service_type_ctrl, cmd.m_num_orch_desc equals 2, cmd.m_orch_desc[0].op equals dm_orch_type_channel_sel, cmd.m_orch_desc[0].submit equals true | Should Pass |
 * | 03 | Deinitialize the command object | API call: cmd.deinit() | Resources associated with cmd are freed successfully | Should be successful |
 */
TEST(em_cmd_set_channel_t, em_cmd_set_channel_t_empty_channel_input) {
    std::cout << "Entering em_cmd_set_channel_t_empty_channel_input test" << std::endl;
    em_cmd_params_t param{};
    param.u.args.fixed_args[0] = '\0';
    param.u.args.fixed_args[sizeof(param.u.args.fixed_args)-1] = '\0';
    dm_easy_mesh_t dm{};
    std::cout << "Invoking em_cmd_set_channel_t with empty fixed_args" << std::endl;
    em_cmd_set_channel_t cmd(param, dm);
    EXPECT_EQ(cmd.m_type, em_cmd_type_set_channel);
    EXPECT_STREQ(cmd.m_name, "set_channel");
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_EQ(cmd.m_num_orch_desc, 2);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_channel_sel);
    EXPECT_TRUE(cmd.m_orch_desc[0].submit);
    cmd.deinit();
    std::cout << "Exiting em_cmd_set_channel_t_empty_channel_input test" << std::endl;
}
/**
 * @brief Test em_cmd_set_channel_t API with non-numeric channel input.
 *
 * This test verifies that the em_cmd_set_channel_t API correctly processes a non-numeric input ("abc") for the channel parameter. The test ensures that the command object is initialized with the expected type, name, parameter values, service type, and orchestration descriptors even when the channel input is not in a numeric format.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 004
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                                          | Test Data                                                                                                                                                 | Expected Result                                                                                                                                                    | Notes      |
 * | :--------------: | -------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
 * | 01               | Invoke em_cmd_set_channel_t with fixed_args set to a non-numeric string "abc".                                       | input: fixed_args = "abc", dm_easy_mesh_t = default, output: m_type = em_cmd_type_set_channel, m_name = "set_channel", m_param.u.args.fixed_args = "abc", m_svc = em_service_type_ctrl, m_num_orch_desc = 2, m_orch_desc[0].op = dm_orch_type_channel_sel, m_orch_desc[0].submit = true | The command object should be initialized correctly; all EXPECT assertions in the test should pass confirming the expected behavior when a non-numeric channel is provided. | Should Pass |
 */
TEST(em_cmd_set_channel_t, em_cmd_set_channel_t_non_numeric_channel_input) {
    std::cout << "Entering em_cmd_set_channel_t_non_numeric_channel_input test" << std::endl;
    em_cmd_params_t param{};
    strncpy(param.u.args.fixed_args, "abc", sizeof(param.u.args.fixed_args) - 1);
    param.u.args.fixed_args[sizeof(param.u.args.fixed_args)-1] = '\0';
    dm_easy_mesh_t dm{};
    std::cout << "Invoking em_cmd_set_channel_t with fixed_args = \"" << param.u.args.fixed_args << "\"" << std::endl;
    em_cmd_set_channel_t cmd(param, dm);
    EXPECT_EQ(cmd.m_type, em_cmd_type_set_channel);
    EXPECT_STREQ(cmd.m_name, "set_channel");
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "abc");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_EQ(cmd.m_num_orch_desc, 2);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_channel_sel);
    EXPECT_TRUE(cmd.m_orch_desc[0].submit);
    cmd.deinit();
    std::cout << "Exiting em_cmd_set_channel_t_non_numeric_channel_input test" << std::endl;
}
