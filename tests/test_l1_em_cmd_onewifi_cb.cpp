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
#include "em_cmd_onewifi_cb.h"



/**
 * @brief Verify that the em_cmd_ow_cb_t constructor creates a valid instance and initializes all parameters correctly
 *
 * This test validates the proper initialization of an em_cmd_ow_cb_t object using custom fixed arguments and argument strings.
 * The test ensures that all member variables are set to expected values after construction and that the object's deinitialization is successful.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 001@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                 | Test Data                                                                                                                                                                                                                          | Expected Result                                                                                                            | Notes      |
 * | :--------------: | --------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | ---------- |
 * | 01               | Invoke the em_cmd_ow_cb_t constructor with custom fixed_args and args values | param.u.args.fixed_args = TestCommand, param.u.args.args[0] = Arg1, param.u.args.num_args = 1, m_type = em_cmd_type_onewifi_cb, m_orch_op_idx = 0, m_num_orch_desc = 1, m_orch_desc[0].submit = true, m_name = onewifi_cnf, m_orch_desc[0].op = dm_orch_type_owconfig_cnf, m_svc = em_service_type_agent, m_data_model.m_cmd_ctx.type = dm_orch_type_owconfig_cnf | Object is constructed with all members correctly initialized and all assertions pass | Should Pass |
 */
TEST(em_cmd_ow_cb_t, em_cmd_ow_cb_t_valid_instance_creation)
{
    std::cout << "Entering em_cmd_ow_cb_t_em_cmd_ow_cb_t_valid_instance_creation test" << std::endl;
    em_cmd_params_t param{};
    const char* fixedStr = "TestCommand";
    strncpy(param.u.args.fixed_args, fixedStr, sizeof(param.u.args.fixed_args) - 1);
    param.u.args.fixed_args[sizeof(param.u.args.fixed_args) - 1] = '\0';
    param.u.args.num_args = 1;
    const char* argStr = "Arg1";
    strncpy(param.u.args.args[0], argStr, sizeof(param.u.args.args[0]) - 1);
    param.u.args.args[0][sizeof(param.u.args.args[0]) - 1] = '\0';
    dm_easy_mesh_t dm;
    std::cout << "Invoking em_cmd_ow_cb_t constructor with custom fixed_args: " << param.u.args.fixed_args << " and args[0]: " << param.u.args.args[0] << std::endl;
    em_cmd_ow_cb_t obj(param, dm);
    std::cout << "em_cmd_ow_cb_t object constructed successfully with custom arguments" << std::endl;
    EXPECT_STREQ(obj.m_param.u.args.fixed_args, "TestCommand");
    EXPECT_STREQ(obj.m_param.u.args.args[0], "Arg1");
    EXPECT_EQ(obj.m_param.u.args.num_args, 1);
    EXPECT_EQ(obj.m_type, em_cmd_type_onewifi_cb);
    EXPECT_EQ(obj.m_orch_op_idx, 0);
    EXPECT_EQ(obj.m_num_orch_desc, 1);
    EXPECT_TRUE(obj.m_orch_desc[0].submit);
    EXPECT_STREQ(obj.m_name, "onewifi_cnf");
    EXPECT_EQ(obj.m_orch_desc[0].op, dm_orch_type_owconfig_cnf);
    EXPECT_EQ(obj.m_svc, em_service_type_agent);
    EXPECT_EQ(obj.m_data_model.m_cmd_ctx.type, dm_orch_type_owconfig_cnf);
    obj.deinit();
    std::cout << "Exiting em_cmd_ow_cb_t_em_cmd_ow_cb_t_valid_instance_creation test" << std::endl;
}
/**
 * @brief Test case that verifies the initialization of em_cmd_ow_cb_t with empty fixed arguments.
 *
 * This test verifies that the em_cmd_ow_cb_t object is correctly initialized when the fixed arguments field is empty.
 * It tests that all the object members are assigned the expected values when provided with an empty string for fixed arguments,
 * ensuring that the constructor handles empty inputs gracefully.
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
 * | 01 | Initialize the test parameters by setting num_args to 0 and fixed_args to an empty string in em_cmd_params_t structure. | param.u.args.num_args = 0, fixed_args = "" | Parameter structure is correctly initialized. | Should be successful |
 * | 02 | Create a dm_easy_mesh_t instance required for the command constructor. | dm instance created | dm_easy_mesh_t object is successfully created. | Should be successful |
 * | 03 | Invoke the em_cmd_ow_cb_t constructor with the initialized parameters and dm instance. | input: param, dm | em_cmd_ow_cb_t object is created with expected initialization. | Should Pass |
 * | 04 | Verify the properties of the constructed object, including fixed_args, num_args, type, orch_op_idx, orch_desc values, name, and svc type. | output: m_param.u.args.fixed_args = "", m_param.u.args.num_args = 0, m_type = em_cmd_type_onewifi_cb, m_orch_op_idx = 0, m_num_orch_desc = 1, m_orch_desc[0].submit = true, m_name = "onewifi_cnf", m_orch_desc[0].op = dm_orch_type_owconfig_cnf, m_svc = em_service_type_agent, m_data_model.m_cmd_ctx.type = dm_orch_type_owconfig_cnf | All EXPECT_ assertions pass confirming correct object initialization. | Should Pass |
 * | 05 | Call deinit() on the constructed object to clean up any allocated resources. | deinit() invoked on object | Resources deinitialized successfully without errors. | Should be successful |
 */
TEST(em_cmd_ow_cb_t, em_cmd_ow_cb_t_empty_fixed_args)
{
    std::cout << "Entering em_cmd_ow_cb_t_empty_fixed_args test" << std::endl;
    em_cmd_params_t param{};
    param.u.args.num_args = 0;
    const char *emptyStr = "";
    strncpy(param.u.args.fixed_args, emptyStr, sizeof(param.u.args.fixed_args));
    dm_easy_mesh_t dm;
    std::cout << "Invoking em_cmd_ow_cb_t constructor with param.u.args.fixed_args: " << param.u.args.fixed_args << std::endl;
    em_cmd_ow_cb_t obj(param, dm);
    std::cout << "em_cmd_ow_cb_t object constructed successfully" << std::endl;
    EXPECT_STREQ(obj.m_param.u.args.fixed_args, "");
    EXPECT_EQ(obj.m_param.u.args.num_args, 0);
    EXPECT_EQ(obj.m_type, em_cmd_type_onewifi_cb);
    EXPECT_EQ(obj.m_orch_op_idx, 0);
    EXPECT_EQ(obj.m_num_orch_desc, 1);
    EXPECT_TRUE(obj.m_orch_desc[0].submit);
    EXPECT_STREQ(obj.m_name, "onewifi_cnf");
    EXPECT_EQ(obj.m_orch_desc[0].op, dm_orch_type_owconfig_cnf);
    EXPECT_EQ(obj.m_svc, em_service_type_agent);
    EXPECT_EQ(obj.m_data_model.m_cmd_ctx.type, dm_orch_type_owconfig_cnf);
    obj.deinit();
    std::cout << "Exiting em_cmd_ow_cb_t_empty_fixed_args test" << std::endl;
}
/**
 * @brief Test the construction of em_cmd_ow_cb_t with maximum SSID length
 *
 * This test validates that the em_cmd_ow_cb_t constructor correctly initializes the object when provided with a maximum-length SSID (127 characters). It verifies that all attributes, including fixed_args, number of arguments, command type, and other internal properties, are properly set, ensuring that the maximum boundary condition for SSID is handled as expected.
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
 * | 01 | Set up a SSID string with maximum allowed length (127 characters) and proper null termination | maxSsid = "a,a,a,...,a" (127 times 'a', then '\0') | The SSID string length is 127 and is properly null terminated | Should be successful |
 * | 02 | Initialize em_cmd_params_t with the maximum SSID and invoke the em_cmd_ow_cb_t constructor | params: num_args = 1, args[0] = maxSsid, fixed_args = maxSsid; dm: instance of dm_easy_mesh_t | The constructor receives the parameters and creates the object with correct initialization | Should Pass |
 * | 03 | Verify that the constructed object's attributes match the expected values via assertions | Object attributes: fixed_args length = 127, num_args = 1, m_type = em_cmd_type_onewifi_cb, orch_op_idx = 0, num_orch_desc = 1, orch_desc[0].submit true, m_name = "onewifi_cnf", orch_desc[0].op = dm_orch_type_owconfig_cnf, m_svc = em_service_type_agent, m_cmd_ctx.type = dm_orch_type_owconfig_cnf | All EXPECT_EQ and EXPECT_STREQ assertions pass confirming correct initialization of the object | Should be successful |
 */
TEST(em_cmd_ow_cb_t, em_cmd_ow_cb_t_ConstructWithMaxSSIDLength)
{
    std::cout << "Entering em_cmd_ow_cb_t_ConstructWithMaxSSIDLength test" << std::endl;
    char maxSsid[128];
    memset(maxSsid, 'a', 127);
    maxSsid[127] = '\0';
    em_cmd_params_t params;
    params.u.args.num_args = 1;
    strncpy(params.u.args.args[0], maxSsid, sizeof(params.u.args.args[0]));
    strncpy(params.u.args.fixed_args, maxSsid, sizeof(params.u.args.fixed_args));
    dm_easy_mesh_t dm;
    em_cmd_ow_cb_t obj(params, dm);
    std::cout << "Invoked em_cmd_ap_metrics_report_t with fixed_args of length " << strlen(params.u.args.fixed_args) << std::endl;
    EXPECT_EQ(strlen(obj.m_param.u.args.fixed_args), 127);
    EXPECT_STREQ(obj.m_param.u.args.fixed_args, maxSsid);
    EXPECT_EQ(obj.m_param.u.args.num_args, 1);
    EXPECT_EQ(obj.m_type, em_cmd_type_onewifi_cb);
    EXPECT_EQ(obj.m_orch_op_idx, 0);
    EXPECT_EQ(obj.m_num_orch_desc, 1);
    EXPECT_TRUE(obj.m_orch_desc[0].submit);
    EXPECT_STREQ(obj.m_name, "onewifi_cnf");
    EXPECT_EQ(obj.m_orch_desc[0].op, dm_orch_type_owconfig_cnf);
    EXPECT_EQ(obj.m_svc, em_service_type_agent);
    EXPECT_EQ(obj.m_data_model.m_cmd_ctx.type, dm_orch_type_owconfig_cnf);
    obj.deinit();
    std::cout << "Exiting em_cmd_ow_cb_t_ConstructWithMaxSSIDLength test" << std::endl;
}
