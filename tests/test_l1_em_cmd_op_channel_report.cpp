
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
#include "em_cmd_op_channel_report.h"



/**
 * @brief Test valid initialization and member verification of em_cmd_op_channel_report_t
 *
 * This test function verifies that the em_cmd_op_channel_report_t object is correctly initialized with a set of provided parameters.
 * It sets the fixed arguments and additional argument values in the command parameters, invokes the constructor,
 * and validates that all member variables are correctly assigned using a series of EXPECT_* assertions.
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
 * | 01 | Set up test parameters by populating num_args, fixed_args, and args array in em_cmd_params_t | num_args = 3, fixed_args = "TestChannelReport", args[0] = "argument_one", args[1] = "argument_two", args[2] = "argument_three" | Parameters are correctly assigned | Should Pass |
 * | 02 | Create an instance of dm_easy_mesh_t and invoke the em_cmd_op_channel_report_t constructor | Input: param (populated structure), dm (instance of dm_easy_mesh_t) | Object is initialized with member variables aligned with the inputs | Should Pass |
 * | 03 | Validate the initialized object's members using EXPECT_* checks | Validate: fixed_args, args[0-2], m_type, m_name, m_svc, m_orch_op_idx, m_num_orch_desc, m_orch_desc, m_data_model.m_cmd_ctx.type | All EXPECT_* assertions pass confirming valid assignment | Should Pass |
 * | 04 | Call the deinit method to perform cleanup | Call deinit() on the created object | Object cleaned up without errors | Should be successful |
 */
TEST(em_cmd_op_channel_report_t, em_cmd_op_channel_report_t_valid)
{
    std::cout << "Entering em_cmd_op_channel_report_t_valid test" << std::endl;
    em_cmd_params_t param;
    param.u.args.num_args = 3;
    strncpy(param.u.args.fixed_args, "TestChannelReport", sizeof(param.u.args.fixed_args));
    const char *arg0 = "argument_one";
    const char *arg1 = "argument_two";
    const char *arg2 = "argument_three";
    std::cout << "Setting args[0]: " << arg0 << std::endl;
    strncpy(param.u.args.args[0], arg0, sizeof(param.u.args.args[0]));
    std::cout << "Setting args[1]: " << arg1 << std::endl;
    strncpy(param.u.args.args[1], arg1, sizeof(param.u.args.args[1]));
    std::cout << "Setting args[2]: " << arg2 << std::endl;
    strncpy(param.u.args.args[2], arg2, sizeof(param.u.args.args[2]));
    dm_easy_mesh_t dm;
    std::cout << "Invoking em_cmd_op_channel_report_t constructor with fixed_args = " << param.u.args.fixed_args << std::endl;
    em_cmd_op_channel_report_t cmd(param, dm);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "TestChannelReport");
    EXPECT_STREQ(cmd.m_param.u.args.args[0], "argument_one");
    EXPECT_STREQ(cmd.m_param.u.args.args[1], "argument_two");
    EXPECT_STREQ(cmd.m_param.u.args.args[2], "argument_three");
    EXPECT_EQ(cmd.m_type, em_cmd_type_op_channel_report);
    EXPECT_STREQ(cmd.m_name, "channel_report");
    EXPECT_EQ(cmd.m_svc, em_service_type_agent);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 1);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_op_channel_report);
    EXPECT_EQ(cmd.m_orch_desc[0].submit, true);
    EXPECT_EQ(cmd.m_data_model.m_cmd_ctx.type, dm_orch_type_op_channel_report);
    cmd.deinit();
    std::cout << "Exiting em_cmd_op_channel_report_t_valid test" << std::endl;
}
/**
 * @brief Verify that the em_cmd_op_channel_report_t constructor correctly initializes fields when provided with empty fixed_args
 *
 * This test verifies that the constructor of em_cmd_op_channel_report_t properly initializes all internal fields when the fixed_args parameter is empty. It checks that the fixed_args string is empty, num_args is zero, and other class members are set to their expected default or specified values. It also verifies that the deinit method successfully releases any allocated resources without causing crashes.
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
 * | 01 | Initialize an empty em_cmd_params_t structure and a dm_easy_mesh_t object, then create an em_cmd_op_channel_report_t object with these parameters | param = zero initialization using memset, dm: unmodified instance of dm_easy_mesh_t | The constructed object has m_param.u.args.fixed_args as an empty string, num_args as 0, m_type as em_cmd_type_op_channel_report, m_name as "channel_report", m_svc as em_service_type_agent, m_orch_op_idx as 0, m_num_orch_desc as 1, m_orch_desc[0].op as dm_orch_type_op_channel_report, m_orch_desc[0].submit as true, and m_data_model.m_cmd_ctx.type as dm_orch_type_op_channel_report | Should Pass |
 * | 02 | Call the deinit method on the em_cmd_op_channel_report_t object to clean up resources | API call: cmd.deinit() | deinit completes without errors, ensuring proper resource cleanup | Should be successful |
 */
TEST(em_cmd_op_channel_report_t, em_cmd_op_channel_report_t_empty)
{
    std::cout << "Entering em_cmd_op_channel_report_t_empty test" << std::endl;
    em_cmd_params_t param;
    memset(&param, 0, sizeof(param));
    dm_easy_mesh_t dm;
    std::cout << "Invoking em_cmd_op_channel_report_t constructor with empty fixed_args" << std::endl;
    em_cmd_op_channel_report_t cmd(param, dm);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "");
    EXPECT_EQ(cmd.m_param.u.args.num_args, 0);
    EXPECT_EQ(cmd.m_type, em_cmd_type_op_channel_report);
    EXPECT_STREQ(cmd.m_name, "channel_report");
    EXPECT_EQ(cmd.m_svc, em_service_type_agent);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 1);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_op_channel_report);
    EXPECT_EQ(cmd.m_orch_desc[0].submit, true);
    EXPECT_EQ(cmd.m_data_model.m_cmd_ctx.type, dm_orch_type_op_channel_report);
    cmd.deinit();
    std::cout << "Exiting em_cmd_op_channel_report_t_empty test" << std::endl;
}
