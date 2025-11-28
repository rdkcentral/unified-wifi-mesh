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
#include "em_cmd_ap_metrics_report.h"



/**
 * @brief Verify that em_cmd_ap_metrics_report_t is constructed correctly with valid parameters.
 *
 * This test verifies that when valid parameters are provided for constructing an em_cmd_ap_metrics_report_t object,
 * the internal state of the object (such as fixed_args, number of arguments, argument values, and other properties)
 * is correctly set as expected. This ensures the object initialization process meets functional requirements.
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
 * | Variation / Step | Description                                                                                                                                                         | Test Data                                                                                      | Expected Result                                                                                                       | Notes       |
 * | :--------------: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ----------- |
 * | 01               | Construct em_cmd_ap_metrics_report_t with valid parameters: args[0] set to "APMetricsReport", fixed_args set to "TestFixedArgs", and num_args equal to 1.        | input: args[0 = "APMetricsReport"], fixed_args = "TestFixedArgs", num_args = 1; output: object properties | All object properties are correctly initialized with the expected string values, numerical values, and flags; assertions pass | Should Pass |
 */
TEST(em_cmd_ap_metrics_report_t, em_cmd_ap_metrics_report_t_valid_parameters) {
    std::cout << "Entering em_cmd_ap_metrics_report_t_valid_parameters test" << std::endl;
    em_cmd_params_t params{};
    params.u.args.num_args = 1;
    strncpy(params.u.args.args[0], "APMetricsReport", sizeof(params.u.args.args[0]) );
    const char *testFixedStr = "TestFixedArgs";
    strncpy(params.u.args.fixed_args, testFixedStr, sizeof(params.u.args.fixed_args));
    std::cout << "Passed fixed_args: " << params.u.args.fixed_args << std::endl;
    dm_easy_mesh_t dm;
    std::cout << "dm_easy_mesh_t object created" << std::endl;
    em_cmd_ap_metrics_report_t cmd(params, dm);
    std::cout << "em_cmd_ap_metrics_report_t object constructed successfully" << std::endl;
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "TestFixedArgs");
    EXPECT_EQ(cmd.m_param.u.args.num_args, 1);
    EXPECT_STREQ(cmd.m_param.u.args.args[0], "APMetricsReport");
    EXPECT_EQ(cmd.m_type, em_cmd_type_ap_metrics_report);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 1);
    EXPECT_TRUE(cmd.m_orch_desc[0].submit);
    EXPECT_STREQ(cmd.m_name, "ap_metrics_report");
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_none);
    EXPECT_EQ(cmd.m_svc, em_service_type_agent);
    EXPECT_EQ(cmd.m_data_model.m_cmd_ctx.type, dm_orch_type_none);
    cmd.deinit();
    std::cout << "Exiting em_cmd_ap_metrics_report_t_valid_parameters test" << std::endl;
}
/**
 * @brief Validate construction and field assignment for em_cmd_ap_metrics_report_t with empty fixed_args
 *
 * This test verifies that constructing an em_cmd_ap_metrics_report_t object using a parameter structure 
 * with zero arguments and an empty fixed_args string correctly initializes all relevant fields and meets 
 * the expected assertion outcomes.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 002@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize em_cmd_params_t with 0 arguments and empty fixed_args | num_args = 0, fixed_args = "" | Parameters initialized with num_args set to 0 and fixed_args as an empty string | Should be successful |
 * | 02 | Instantiate dm_easy_mesh_t object | - | dm_easy_mesh_t object created successfully | Should be successful |
 * | 03 | Construct em_cmd_ap_metrics_report_t with provided parameters and dm object | params, dm object | em_cmd_ap_metrics_report_t object constructed successfully with empty fixed_args | Should Pass |
 * | 04 | Validate command object fields using assertions | fixed_args = "", num_args = 0, m_type = em_cmd_type_ap_metrics_report, m_orch_op_idx = 0, m_num_orch_desc = 1, m_orch_desc[0].submit = true, m_name = "ap_metrics_report", m_orch_desc[0].op = dm_orch_type_none, m_svc = em_service_type_agent, m_data_model.m_cmd_ctx.type = dm_orch_type_none | All assertion checks pass as expected | Should Pass |
 * | 05 | Deinitialize the command object | cmd.deinit() | Resources deinitialized without error | Should be successful |
 */
TEST(em_cmd_ap_metrics_report_t, em_cmd_ap_metrics_report_t_empty_fixed_args) {
    std::cout << "Entering em_cmd_ap_metrics_report_t_empty_fixed_args test" << std::endl;
    em_cmd_params_t params{};
    params.u.args.num_args = 0;
    const char *emptyStr = "";
    strncpy(params.u.args.fixed_args, emptyStr, sizeof(params.u.args.fixed_args));
    std::cout << "Passed fixed_args (expected empty): '" << params.u.args.fixed_args << "'" << std::endl;
    dm_easy_mesh_t dm;
    std::cout << "dm_easy_mesh_t object created" << std::endl;
    em_cmd_ap_metrics_report_t cmd(params, dm);
    std::cout << "em_cmd_ap_metrics_report_t object constructed successfully with empty fixed_args" << std::endl;
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "");
    EXPECT_EQ(cmd.m_param.u.args.num_args, 0);
    EXPECT_EQ(cmd.m_type, em_cmd_type_ap_metrics_report);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 1);
    EXPECT_TRUE(cmd.m_orch_desc[0].submit);
    EXPECT_STREQ(cmd.m_name, "ap_metrics_report");
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_none);
    EXPECT_EQ(cmd.m_svc, em_service_type_agent);
    EXPECT_EQ(cmd.m_data_model.m_cmd_ctx.type, dm_orch_type_none);
    cmd.deinit();
    std::cout << "Exiting em_cmd_ap_metrics_report_t_empty_fixed_args test" << std::endl;
}
/**
 * @brief Test constructing an em_cmd_ap_metrics_report_t object with maximum SSID length.
 *
 * This test verifies that the em_cmd_ap_metrics_report_t constructor correctly initializes the command structure when provided with a maximum length SSID (127 characters) for fixed_args. The test ensures that the object’s member variables are set appropriately and that the command operation behaves as expected.
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
 * | 01 | Prepare maximum length SSID (127 'a's) and initialize command parameters | maxSsid = 127 x 'a', params.u.args.num_args = 1, params.u.args.args[0] = maxSsid, params.u.args.fixed_args = maxSsid | Parameters are set with a null-terminated string of length 127 | Should be successful |
 * | 02 | Construct em_cmd_ap_metrics_report_t object using the parameters and a dm_easy_mesh_t instance | API: em_cmd_ap_metrics_report_t(params, dm) | Object is constructed with valid initialization of m_param, m_type, m_orch_op_idx, m_num_orch_desc, m_orch_desc, m_name, m_svc, and m_data_model.m_cmd_ctx.type | Should Pass |
 * | 03 | Check that fixed_args in the object has the correct length and matches the input string | cmd.m_param.u.args.fixed_args, strlen(cmd.m_param.u.args.fixed_args) compared to 127 and maxSsid | The fixed_args string has length 127 and exactly matches maxSsid | Should Pass |
 * | 04 | Validate additional members: num_args, command type, orch descriptors, service type, etc. | num_args = 1, m_type = em_cmd_type_ap_metrics_report, m_orch_op_idx = 0, m_num_orch_desc = 1, m_orch_desc[0].submit = true, m_name = "ap_metrics_report", m_orch_desc[0].op = dm_orch_type_none, m_svc = em_service_type_agent, m_data_model.m_cmd_ctx.type = dm_orch_type_none | All member variables are correctly set as expected | Should Pass |
 * | 05 | Call deinit on the command object to clean up resources | cmd.deinit() | Resources are cleaned up without any errors | Should be successful |
 */
TEST(em_cmd_ap_metrics_report_t, em_cmd_ap_metrics_report_t_ConstructWithMaxSSIDLength)
{
    std::cout << "Entering em_cmd_ap_metrics_report_t_ConstructWithMaxSSIDLength test" << std::endl;
    char maxSsid[128];
    memset(maxSsid, 'a', 127);
    maxSsid[127] = '\0';
    em_cmd_params_t params;
    params.u.args.num_args = 1;
    strncpy(params.u.args.args[0], maxSsid, sizeof(params.u.args.args[0]));
    strncpy(params.u.args.fixed_args, maxSsid, sizeof(params.u.args.fixed_args));
    dm_easy_mesh_t dm;
    em_cmd_ap_metrics_report_t cmd(params, dm);
    std::cout << "Invoked em_cmd_ap_metrics_report_t with fixed_args of length " << strlen(params.u.args.fixed_args) << std::endl;
    EXPECT_EQ(strlen(cmd.m_param.u.args.fixed_args), 127);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, maxSsid);
    EXPECT_EQ(cmd.m_param.u.args.num_args, 1);
    EXPECT_EQ(cmd.m_type, em_cmd_type_ap_metrics_report);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 1);
    EXPECT_TRUE(cmd.m_orch_desc[0].submit);
    EXPECT_STREQ(cmd.m_name, "ap_metrics_report");
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_none);
    EXPECT_EQ(cmd.m_svc, em_service_type_agent);
    EXPECT_EQ(cmd.m_data_model.m_cmd_ctx.type, dm_orch_type_none);
    cmd.deinit();
    std::cout << "Exiting em_cmd_ap_metrics_report_t_ConstructWithMaxSSIDLength test" << std::endl;
}
