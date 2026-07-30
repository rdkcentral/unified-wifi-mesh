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
#include "em_cmd_bsta_cap.h"



/**
 * @brief Validate correct construction of em_cmd_bsta_cap_t object
 *
 * This test verifies that the em_cmd_bsta_cap_t object is constructed properly when provided with valid parameters.
 * It checks that each member of the object is initialized to the expected value, ensuring that the constructor
 * and assignment operations perform as intended.
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
 * | 01 | Invoke the constructor of em_cmd_bsta_cap_t with valid input parameters and verify member assignments | num_args = 3, fixed_args = ValidFixedArgsValue, net_node->value_int = 3, dm instance initialized | All object members should match the input parameters and expected defaults: m_param.u.args.num_args equals 3, m_param.u.args.fixed_args equals "ValidFixedArgsValue", m_param.net_node->value_int equals 3, m_type equals em_cmd_type_bsta_cap, m_orch_op_idx equals 0, m_num_orch_desc equals 1, m_orch_desc[0].submit is true, m_name equals "bsta_cap", m_orch_desc[0].op equals dm_orch_type_bsta_cap_query, m_svc equals em_service_type_ctrl, and m_data_model.m_cmd_ctx.type equals dm_orch_type_bsta_cap_query | Should Pass |
 */
TEST(em_cmd_bsta_cap_t, em_cmd_bsta_cap_t_ValidConstruction)
{
    std::cout << "Entering em_cmd_bsta_cap_t_ValidConstruction test" << std::endl;
    em_cmd_params_t param;
    param.u.args.num_args = 3;
    const char* validFixedArgs = "ValidFixedArgsValue";
    strncpy(param.u.args.fixed_args, validFixedArgs, sizeof(param.u.args.fixed_args) - 1);
    param.u.args.fixed_args[sizeof(param.u.args.fixed_args) - 1] = '\0';
    em_network_node_t netnode{};
    param.net_node = &netnode;
    param.net_node->value_int = 3;
    dm_easy_mesh_t dm;
    std::cout << "Parameter num_args: " << param.u.args.num_args << std::endl;
    std::cout << "Parameter fixed_args: " << param.u.args.fixed_args << std::endl;
    std::cout << "Parameter net_node: " << param.net_node << std::endl;
    em_cmd_bsta_cap_t obj(param, dm);
    EXPECT_EQ(obj.m_param.u.args.num_args, param.u.args.num_args);
    EXPECT_STREQ(obj.m_param.u.args.fixed_args, validFixedArgs);
    EXPECT_EQ(obj.m_type, em_cmd_type_bsta_cap);
    EXPECT_EQ(obj.m_param.net_node->value_int, 3);
    EXPECT_EQ(obj.m_orch_op_idx, 0);
    EXPECT_EQ(obj.m_num_orch_desc, 1);
    EXPECT_TRUE(obj.m_orch_desc[0].submit);
    EXPECT_STREQ(obj.m_name, "bsta_cap");
    EXPECT_EQ(obj.m_orch_desc[0].op, dm_orch_type_bsta_cap_query);
    EXPECT_EQ(obj.m_svc, em_service_type_ctrl);
    EXPECT_EQ(obj.m_data_model.m_cmd_ctx.type, dm_orch_type_bsta_cap_query);
    obj.deinit();
    std::cout << "Exiting em_cmd_bsta_cap_t_ValidConstruction test" << std::endl;
}
/**
 * @brief Validate em_cmd_bsta_cap_t object initialization with a null network node.
 *
 * This test verifies that the em_cmd_bsta_cap_t object correctly initializes its internal members when the 
 * net_node parameter is provided as nullptr. The test ensures that the object holds the expected values for 
 * the number of arguments, fixed arguments, command type, and other operational descriptors after construction.
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
 * | 01 | Initialize em_cmd_params_t with num_args = 2, fixed_args = "NonEmptyFixedArgs", and net_node set to nullptr; create a dm_easy_mesh_t instance. | num_args = 2, fixed_args = "NonEmptyFixedArgs", net_node = nullptr, dm instance created | Parameters are correctly initialized with provided values. | Should be successful |
 * | 02 | Construct the em_cmd_bsta_cap_t object with the initialized parameters and dm instance, then verify all member values via assertions. | Input: param and dm; Output: m_param.num_args, m_param.fixed_args, m_param.net_node, m_type, m_orch_op_idx, m_num_orch_desc, m_orch_desc[0].submit, m_name, m_orch_desc[0].op, m_svc, m_data_model.m_cmd_ctx.type | All EXPECT_* checks pass; object members match expected values. | Should Pass |
 * | 03 | Invoke the deinit method on the em_cmd_bsta_cap_t object. | No additional input; method call: obj.deinit() | Object deinitializes without error. | Should be successful |
 */
TEST(em_cmd_bsta_cap_t, em_cmd_bsta_cap_t_NullNetNode)
{
    std::cout << "Entering em_cmd_bsta_cap_t_NullNetNode test" << std::endl;
    em_cmd_params_t param;
    param.u.args.num_args = 2;
    const char* validFixedArgs = "NonEmptyFixedArgs";
    strncpy(param.u.args.fixed_args, validFixedArgs, sizeof(param.u.args.fixed_args) - 1);
    param.u.args.fixed_args[sizeof(param.u.args.fixed_args) - 1] = '\0';
    param.net_node = nullptr;
    dm_easy_mesh_t dm;
    std::cout << "Parameter net_node is: " << param.net_node << std::endl;
    em_cmd_bsta_cap_t obj(param, dm);
    EXPECT_EQ(obj.m_param.u.args.num_args, 2);
    EXPECT_STREQ(obj.m_param.u.args.fixed_args, "NonEmptyFixedArgs");
    EXPECT_EQ(obj.m_param.net_node, nullptr);
    EXPECT_EQ(obj.m_type, em_cmd_type_bsta_cap);
    EXPECT_EQ(obj.m_orch_op_idx, 0);
    EXPECT_EQ(obj.m_num_orch_desc, 1);
    EXPECT_TRUE(obj.m_orch_desc[0].submit);
    EXPECT_STREQ(obj.m_name, "bsta_cap");
    EXPECT_EQ(obj.m_orch_desc[0].op, dm_orch_type_bsta_cap_query);
    EXPECT_EQ(obj.m_svc, em_service_type_ctrl);
    EXPECT_EQ(obj.m_data_model.m_cmd_ctx.type, dm_orch_type_bsta_cap_query);
    obj.deinit();
    std::cout << "Exiting em_cmd_bsta_cap_t_NullNetNode test" << std::endl;
}
/**
 * @brief Validates that creating em_cmd_bsta_cap_t with empty fixed arguments initializes the object correctly.
 *
 * This test verifies that when the fixed_args parameter is provided as an empty string and num_args is set to 0, the object's fields are initialized to expected default values. This ensures that the API can gracefully handle cases with empty fixed arguments.
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
 * | 01 | Initialize test parameters with empty fixed_args and zero num_args | param.u.args.num_args = 0, param.u.args.fixed_args = "" | Parameters are correctly set with 0 arguments and an empty fixed_args string | Should be successful |
 * | 02 | Construct em_cmd_bsta_cap_t object with provided parameters and verify all fields | Input: param with num_args = 0 and fixed_args = "", dm object of type dm_easy_mesh_t; Output: m_param.u.args.num_args = 0, m_param.u.args.fixed_args = "", m_type = em_cmd_type_bsta_cap, m_orch_op_idx = 0, m_num_orch_desc = 1, m_orch_desc[0].submit = true, m_name = "bsta_cap", m_orch_desc[0].op = dm_orch_type_bsta_cap_query, m_svc = em_service_type_ctrl, m_data_model.m_cmd_ctx.type = dm_orch_type_bsta_cap_query | Object fields are initialized exactly as expected | Should Pass |
 * | 03 | Deinitialize the em_cmd_bsta_cap_t object | Call obj.deinit() | Resources are released without error | Should be successful |
 */
TEST(em_cmd_bsta_cap_t, em_cmd_bsta_cap_t_EmptyFixedArgs)
{
    std::cout << "Entering em_cmd_bsta_cap_t_EmptyFixedArgs test" << std::endl;
    em_cmd_params_t param;
    param.u.args.num_args = 0;
    strncpy(param.u.args.fixed_args, "", sizeof(param.u.args.fixed_args) - 1);
    param.u.args.fixed_args[sizeof(param.u.args.fixed_args) - 1] = '\0';
    dm_easy_mesh_t dm;
    std::cout << "Parameter fixed_args (length): " << std::strlen(param.u.args.fixed_args) << std::endl;
    em_cmd_bsta_cap_t obj(param, dm);
    EXPECT_EQ(obj.m_param.u.args.num_args, 0);
    EXPECT_STREQ(obj.m_param.u.args.fixed_args, "");
    EXPECT_EQ(obj.m_type, em_cmd_type_bsta_cap);
    EXPECT_EQ(obj.m_orch_op_idx, 0);
    EXPECT_EQ(obj.m_num_orch_desc, 1);
    EXPECT_TRUE(obj.m_orch_desc[0].submit);
    EXPECT_STREQ(obj.m_name, "bsta_cap");
    EXPECT_EQ(obj.m_orch_desc[0].op, dm_orch_type_bsta_cap_query);
    EXPECT_EQ(obj.m_svc, em_service_type_ctrl);
    EXPECT_EQ(obj.m_data_model.m_cmd_ctx.type, dm_orch_type_bsta_cap_query);
    obj.deinit();
    std::cout << "Exiting em_cmd_bsta_cap_t_EmptyFixedArgs test" << std::endl;    
}
/**
 * @brief Validate maximum length of fixed arguments in em_cmd_bsta_cap_t initialization
 *
 * This test verifies that the fixed_args field in the em_cmd_bsta_cap_t object can successfully store a string with the maximum allowed length (127 characters) without truncation. It checks the initialization values, such as num_args, fixed_args, and various object fields, ensuring that they are set as expected. The test confirms that the object is initialized correctly and that deinitialization works properly.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Set num_args to 5 in the parameters object | num_args = 5 | num_args is correctly set to 5 | Should be successful |
 * | 02 | Fill fixed_args with a maximum string of 127 'A' characters and proper null termination | fixed_args = "AAAA...A" (127 times 'A', null terminated) | fixed_args length is exactly 127 and null terminated | Should Pass |
 * | 03 | Initialize dm object and create em_cmd_bsta_cap_t instance using the parameters | param = { num_args = 5, fixed_args = maxString }, dm = default instance | Object is constructed with proper initialization of fields | Should Pass |
 * | 04 | Verify object attributes including num_args, fixed_args, m_type, m_orch_op_idx, m_num_orch_desc, orch_desc submit flag, m_name, orch_desc op, m_svc, and m_data_model command context type | num_args = 5, fixed_args length = 127, m_type = em_cmd_type_bsta_cap, m_orch_op_idx = 0, m_num_orch_desc = 1, m_orch_desc[0].submit = true, m_name = "bsta_cap", m_orch_desc[0].op = dm_orch_type_bsta_cap_query, m_svc = em_service_type_ctrl, m_data_model.m_cmd_ctx.type = dm_orch_type_bsta_cap_query | All assertions pass as expected | Should Pass |
 * | 05 | Call deinit to release resources and finish the test | Call obj.deinit() | Resources are properly released and no errors occur | Should be successful |
 */
TEST(em_cmd_bsta_cap_t, em_cmd_bsta_cap_t_MaxLengthFixedArgs)
{
    std::cout << "Entering em_cmd_bsta_cap_t_MaxLengthFixedArgs test" << std::endl;
    em_cmd_params_t param;
    param.u.args.num_args = 5;
    char maxStr[128] = {0};
    memset(maxStr, 'A', 127);
    maxStr[127] = '\0';
    strncpy(param.u.args.fixed_args, maxStr, sizeof(param.u.args.fixed_args) - 1);
    param.u.args.fixed_args[sizeof(param.u.args.fixed_args) - 1] = '\0';
    dm_easy_mesh_t dm;
    std::cout << "Parameter fixed_args length: " << std::strlen(param.u.args.fixed_args) << std::endl;
    em_cmd_bsta_cap_t obj(param, dm);
    EXPECT_EQ(obj.m_param.u.args.num_args, 5);
    EXPECT_EQ(strlen(obj.m_param.u.args.fixed_args), 127u);
    EXPECT_STREQ(obj.m_param.u.args.fixed_args, maxStr);
    EXPECT_EQ(obj.m_type, em_cmd_type_bsta_cap);
    EXPECT_EQ(obj.m_orch_op_idx, 0);
    EXPECT_EQ(obj.m_num_orch_desc, 1);
    EXPECT_TRUE(obj.m_orch_desc[0].submit);
    EXPECT_STREQ(obj.m_name, "bsta_cap");
    EXPECT_EQ(obj.m_orch_desc[0].op, dm_orch_type_bsta_cap_query);
    EXPECT_EQ(obj.m_svc, em_service_type_ctrl);
    EXPECT_EQ(obj.m_data_model.m_cmd_ctx.type, dm_orch_type_bsta_cap_query);
    obj.deinit();
    std::cout << "Exiting em_cmd_bsta_cap_t_MaxLengthFixedArgs test" << std::endl;
}
