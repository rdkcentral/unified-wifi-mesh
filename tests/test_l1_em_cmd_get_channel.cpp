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
#include "em_cmd_get_channel.h"


/**
 * @brief Validate that em_cmd_get_channel_t handles numeric fixed arguments correctly
 *
 * This test verifies that when the fixed_args field of em_cmd_params_t is set to "11", the constructor of em_cmd_get_channel_t correctly initializes the internal fields of the command object. It checks that the command type, name, service type, and additional parameters are set as expected, ensuring proper functioning of the API handling numeric fixed arguments.
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
 * | Variation / Step | Description                                                                                     | Test Data                                                                                                    | Expected Result                                                     | Notes            |
 * | :--------------: | ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------- | ---------------- |
 * | 01               | Log the entry into the test                                                                     | None                                                                                                         | Console output displays "Entering em_cmd_get_channel_t_fixed_args_numeric test" | Should be successful |
 * | 02               | Initialize em_cmd_params_t by setting its fixed_args field to "11"                                | param.u.args.fixed_args = 11                                                                                 | Parameter fixed_args field contains "11"                           | Should be successful |
 * | 03               | Create a dm_easy_mesh_t instance and invoke the em_cmd_get_channel_t constructor with param and dm | param.u.args.fixed_args = 11, dm instance; Output: cmd instance                                                | Command object created with proper initialization of attributes      | Should Pass      |
 * | 04               | Log the command invocation message                                                              | Output: cmd.m_param.u.args.fixed_args = 11                                                                   | Console output displays fixed_args value "11"                        | Should be successful |
 * | 05               | Validate that cmd.m_type equals em_cmd_type_dev_init                                            | cmd.m_type = em_cmd_type_dev_init                                                                              | Return value equals em_cmd_type_dev_init                             | Should Pass      |
 * | 06               | Validate that cmd.m_name equals "get_channel"                                                   | cmd.m_name = "get_channel"                                                                                   | Return value equals "get_channel"                                    | Should Pass      |
 * | 07               | Validate that cmd.m_svc equals em_service_type_ctrl                                             | cmd.m_svc = em_service_type_ctrl                                                                               | Return value equals em_service_type_ctrl                             | Should Pass      |
 * | 08               | Validate that cmd.m_param.u.args.fixed_args equals "11"                                         | cmd.m_param.u.args.fixed_args = "11"                                                                            | Return value equals "11"                                               | Should Pass      |
 * | 09               | Validate that cmd.m_orch_op_idx equals 0                                                         | cmd.m_orch_op_idx = 0                                                                                           | Return value equals 0                                                  | Should Pass      |
 * | 10               | Validate that cmd.m_num_orch_desc equals 0                                                       | cmd.m_num_orch_desc = 0                                                                                         | Return value equals 0                                                  | Should Pass      |
 * | 11               | Invoke cmd.deinit to clean up resources                                                         | None                                                                                                         | Resources are released without error                                 | Should Pass      |
 * | 12               | Log the exit from the test                                                                      | None                                                                                                         | Console output displays "Exiting em_cmd_get_channel_t_fixed_args_numeric test" | Should be successful |
 */
TEST(em_cmd_get_channel_t, em_cmd_get_channel_t_fixed_args_numeric) {
    std::cout << "Entering em_cmd_get_channel_t_fixed_args_numeric test" << std::endl;
    em_cmd_params_t param{};
    strncpy(param.u.args.fixed_args, "11", sizeof(param.u.args.fixed_args) - 1);
    dm_easy_mesh_t dm{};
    em_cmd_get_channel_t cmd(param, dm);
    std::cout << "Invoked em_cmd_get_channel_t with fixed_args: "
              << cmd.m_param.u.args.fixed_args << std::endl;
    EXPECT_EQ(cmd.m_type, em_cmd_type_dev_init);
    EXPECT_STREQ(cmd.m_name, "get_channel");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "11");
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 0);
    cmd.deinit();
    std::cout << "Exiting em_cmd_get_channel_t_fixed_args_numeric test" << std::endl;
}
/**
 * @brief Tests the initialization of the em_cmd_get_channel_t API with empty fixed_args.
 *
 * This test verifies that the em_cmd_get_channel_t API is initialized correctly when an empty string is provided for fixed_args.
 * It checks that the default values are properly set for the command type, name, service type, and other members.
 * This test ensures the API handles empty fixed_args correctly, ensuring robustness of parameter handling.
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
 * | Variation / Step | Description                                                                                       | Test Data                                                                                           | Expected Result                                                                                                                                         | Notes        |
 * | :--------------: | ------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
 * | 01               | Invoke em_cmd_get_channel_t API with empty fixed_args                                             | param.u.args.fixed_args = "", dm object with default values                                          | API returns m_type = em_cmd_type_dev_init, m_name = "get_channel", m_svc = em_service_type_ctrl, m_param.u.args.fixed_args = "", m_orch_op_idx = 0, m_num_orch_desc = 0 | Should Pass  |
 */
TEST(em_cmd_get_channel_t, em_cmd_get_channel_t_fixed_args_empty) {
    std::cout << "Entering em_cmd_get_channel_t_fixed_args_empty test" << std::endl;
    em_cmd_params_t param{};
    strncpy(param.u.args.fixed_args, "", sizeof(param.u.args.fixed_args) - 1);
    dm_easy_mesh_t dm{};
    em_cmd_get_channel_t cmd(param, dm);
    std::cout << "Invoked em_cmd_get_channel_t with fixed_args: '"
              << cmd.m_param.u.args.fixed_args << "'" << std::endl;
    EXPECT_EQ(cmd.m_type, em_cmd_type_dev_init);
    EXPECT_STREQ(cmd.m_name, "get_channel");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "");
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 0);
    cmd.deinit();
    std::cout << "Exiting em_cmd_get_channel_t_fixed_args_empty test" << std::endl;
}
/**
 * @brief Test to verify em_cmd_get_channel_t API handles non-numeric fixed_args input correctly.
 *
 * This test checks whether the em_cmd_get_channel_t API correctly processes a fixed_args parameter containing non-numeric characters. 
 * It verifies that the internal values (m_type, m_name, m_svc, m_param.u.args.fixed_args, m_orch_op_idx, and m_num_orch_desc) are set as expected.
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
 * | Variation / Step | Description                                                                                                             | Test Data                                                                                                                       | Expected Result                                                                                                                                         | Notes      |
 * | :--------------: | ----------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
 * | 01               | Invoke em_cmd_get_channel_t with fixed_args set to "abc" to check processing of non-numeric fixed arguments             | param.u.args.fixed_args = "abc", dm default, expected: m_type = em_cmd_type_dev_init, m_name = "get_channel", m_svc = em_service_type_ctrl, m_param.u.args.fixed_args = "abc", m_orch_op_idx = 0, m_num_orch_desc = 0 | m_type equals em_cmd_type_dev_init, m_name equals "get_channel", m_svc equals em_service_type_ctrl, m_param.u.args.fixed_args equals "abc", m_orch_op_idx equals 0, m_num_orch_desc equals 0 | Should Pass |
 */
TEST(em_cmd_get_channel_t, em_cmd_get_channel_t_fixed_args_non_numeric) {
    std::cout << "Entering em_cmd_get_channel_t_fixed_args_non_numeric test" << std::endl;
    em_cmd_params_t param{};
    strncpy(param.u.args.fixed_args, "abc", sizeof(param.u.args.fixed_args) - 1);
    dm_easy_mesh_t dm{};
    em_cmd_get_channel_t cmd(param, dm);
    std::cout << "Invoked em_cmd_get_channel_t with fixed_args: "
              << cmd.m_param.u.args.fixed_args << std::endl;
    EXPECT_EQ(cmd.m_type, em_cmd_type_dev_init);
    EXPECT_STREQ(cmd.m_name, "get_channel");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "abc");
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 0);
    cmd.deinit();
    std::cout << "Exiting em_cmd_get_channel_t_fixed_args_non_numeric test" << std::endl;
}
