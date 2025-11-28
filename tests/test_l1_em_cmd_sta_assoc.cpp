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
#include "em_cmd_sta_assoc.h"


/**
 * @brief Validate em_cmd_sta_assoc_t API with valid parameters
 *
 * This test case verifies that the em_cmd_sta_assoc_t API correctly initializes its internal members when provided with valid parameters. It checks that the input parameters are accurately reflected in the object's attributes, including argument values, command type, service type, and orchestration descriptors. The test ensures that both the constructor and the deinitialization procedure work as expected.
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
 * | 01 | Set up valid parameters for the API call | validParam.u.args.num_args = 1, validParam.u.args.args[0] = "ValidArg", validParam.u.args.fixed_args = "FixedValid", dm instance of dm_easy_mesh_t | Parameters are set correctly and ready for use | Should be successful |
 * | 02 | Construct the em_cmd_sta_assoc_t object using valid parameters | Input: validParam and dm | Object's members m_param reflect the provided valid parameters; m_type equals em_cmd_type_sta_assoc; m_name equals "sta_assoc"; m_svc equals em_service_type_ctrl; m_orch_op_idx equals 0; m_num_orch_desc equals 1; m_orch_desc[0].op equals dm_orch_type_sta_cap; m_orch_desc[0].submit equals true; m_data_model.m_cmd_ctx.type equals dm_orch_type_sta_cap | Should Pass |
 * | 03 | Validate object properties using assertions | Comparisons: em_cmd_sta_assoc_t object's members against expected values | EXPECT_EQ and EXPECT_STREQ assertions confirm correct initialization | Should Pass |
 * | 04 | Invoke deinit to cleanup the object | API call: assoc.deinit() | Successful deinitialization without errors | Should Pass |
 */
TEST(em_cmd_sta_assoc_t, em_cmd_sta_assoc_t_valid_parameters) {
    std::cout << "Entering em_cmd_sta_assoc_t_valid_parameters test" << std::endl;
    em_cmd_params_t validParam;
    validParam.u.args.num_args = 1;
    strncpy(validParam.u.args.args[0], "ValidArg", sizeof(validParam.u.args.args[0]));
    strncpy(validParam.u.args.fixed_args, "FixedValid", sizeof(validParam.u.args.fixed_args));
    dm_easy_mesh_t dm;
    std::cout << "Invoking em_cmd_sta_assoc_t fixed_args: " << validParam.u.args.fixed_args << std::endl;
    em_cmd_sta_assoc_t assoc(validParam, dm);
    EXPECT_EQ(assoc.m_param.u.args.num_args, 1);
    EXPECT_STREQ(assoc.m_param.u.args.fixed_args, "FixedValid");
    EXPECT_STREQ(assoc.m_param.u.args.args[0], "ValidArg");
    EXPECT_EQ(assoc.m_type, em_cmd_type_sta_assoc);
    EXPECT_STREQ(assoc.m_name, "sta_assoc");
    EXPECT_EQ(assoc.m_svc, em_service_type_ctrl);
    EXPECT_EQ(assoc.m_orch_op_idx, 0);
    EXPECT_EQ(assoc.m_num_orch_desc, 1);
    EXPECT_EQ(assoc.m_orch_desc[0].op, dm_orch_type_sta_cap);
    EXPECT_TRUE(assoc.m_orch_desc[0].submit);
    EXPECT_EQ(assoc.m_data_model.m_cmd_ctx.type, dm_orch_type_sta_cap);
    assoc.deinit();
    std::cout << "Exiting em_cmd_sta_assoc_t_valid_parameters test" << std::endl;
}
/**
 * @brief Verify that em_cmd_sta_assoc_t initialized with minimal parameters functions correctly
 *
 * This test validates that the em_cmd_sta_assoc_t object, when constructed with minimal parameters (i.e., num_args set to 0 and an empty string for fixed_args), initializes all the member fields as expected. This includes verifying that service type, orchestration index, orchestration descriptor, and data model context are correctly assigned.
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
 * | 01 | Initialize em_cmd_params_t with minimal parameters | num_args = 0, fixed_args = "" | Structure initialized with zero arguments and empty fixed_args | Should be successful |
 * | 02 | Instantiate dm_easy_mesh_t object | None | dm object created successfully | Should be successful |
 * | 03 | Invoke em_cmd_sta_assoc_t constructor with minimal parameters | param (num_args = 0, fixed_args = ""), dm instance | em_cmd_sta_assoc_t object constructed with default values | Should Pass |
 * | 04 | Validate initialized fields of em_cmd_sta_assoc_t object | assoc.m_param.u.args.num_args = 0, assoc.m_param.u.args.fixed_args = "", assoc.m_type = em_cmd_type_sta_assoc, assoc.m_name = "sta_assoc", assoc.m_svc = em_service_type_ctrl, assoc.m_orch_op_idx = 0, assoc.m_num_orch_desc = 1, assoc.m_orch_desc[0].op = dm_orch_type_sta_cap, assoc.m_orch_desc[0].submit = true, assoc.m_data_model.m_cmd_ctx.type = dm_orch_type_sta_cap | Each field matches expected value as per the API design | Should Pass |
 * | 05 | Cleanup by invoking deinit() method on the em_cmd_sta_assoc_t object | None | Object deinitialized successfully | Should be successful |
 */
TEST(em_cmd_sta_assoc_t, em_cmd_sta_assoc_t_valid_minimal_parameters) {
    std::cout << "Entering em_cmd_sta_assoc_t_valid_minimal_parameters test" << std::endl;
    em_cmd_params_t param{};
    param.u.args.num_args = 0;
    strncpy(param.u.args.fixed_args, "", sizeof(param.u.args.fixed_args));
    dm_easy_mesh_t dm;
    std::cout << "Invoking em_cmd_sta_assoc_t with fixed_args: " << param.u.args.fixed_args << std::endl;
    em_cmd_sta_assoc_t assoc(param, dm);
    std::cout << "Minimal sta assoc constructor invoked successfully." << std::endl;
    EXPECT_EQ(assoc.m_param.u.args.num_args, 0);
    EXPECT_STREQ(assoc.m_param.u.args.fixed_args, "");
    EXPECT_EQ(assoc.m_type, em_cmd_type_sta_assoc);
    EXPECT_STREQ(assoc.m_name, "sta_assoc");
    EXPECT_EQ(assoc.m_svc, em_service_type_ctrl);
    EXPECT_EQ(assoc.m_orch_op_idx, 0);
    EXPECT_EQ(assoc.m_num_orch_desc, 1);
    EXPECT_EQ(assoc.m_orch_desc[0].op, dm_orch_type_sta_cap);
    EXPECT_TRUE(assoc.m_orch_desc[0].submit);
    EXPECT_EQ(assoc.m_data_model.m_cmd_ctx.type, dm_orch_type_sta_cap);
    assoc.deinit();
    std::cout << "Exiting em_cmd_sta_assoc_t_valid_minimal_parameters test" << std::endl;
}
/**
 * @brief Test the constructor of em_cmd_sta_assoc_t using maximum fixed arguments.
 *
 * This test verifies that the em_cmd_sta_assoc_t constructor properly initializes its member variables when provided with maximum sized fixed arguments and arguments. It checks that the fixed_args and args[0] strings are correctly set, that the number of arguments is correctly assigned, and that the other member attributes (such as m_type, m_name, m_svc, m_orch_op_idx, m_num_orch_desc, m_orch_desc, and m_data_model) are appropriately initialized based on the input parameters and dm instance.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize fixed_args in the parameter structure with maximum characters. | fixed_args = 127 'X' characters, null-terminated | The fixed_args string in param is correctly set and null-terminated. | Should be successful |
 * | 02 | Initialize the first argument in args array with maximum characters. | args[0] = 127 'Y' characters, null-terminated | The args[0] string in param is correctly set and null-terminated. | Should be successful |
 * | 03 | Set num_args value and prepare the parameter structure before constructor invocation. | num_args = 5 | The num_args field in param is set to 5. | Should be successful |
 * | 04 | Call the em_cmd_sta_assoc_t constructor with the parameter structure and dm instance. | Input: param structure and dm instance | A new assoc instance is created with its members initialized according to the input parameters, including m_param.u.args, m_type, m_name, m_svc, m_orch_op_idx, m_num_orch_desc, m_orch_desc, and m_data_model fields. | Should Pass |
 * | 05 | Verify the initialization by asserting each member's value and then deinitialize the instance. | Expected values: num_args = 5, fixed_args, args[0] match, m_type = em_cmd_type_sta_assoc, m_name = "sta_assoc", m_svc = em_service_type_ctrl, m_orch_op_idx = 0, m_num_orch_desc = 1, m_orch_desc[0].op = dm_orch_type_sta_cap, m_orch_desc[0].submit true, m_data_model.m_cmd_ctx.type = dm_orch_type_sta_cap. | All assertions pass confirming the proper initialization. | Should Pass |
 */
TEST(em_cmd_sta_assoc_t, em_cmd_sta_assoc_t_ctor_max_fixed_args) {
    std::cout << "Entering em_cmd_sta_assoc_t_ctor_max_fixed_args test" << std::endl;
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
    em_cmd_sta_assoc_t assoc(param, dm);
    EXPECT_EQ(assoc.m_param.u.args.num_args, 5);
    EXPECT_STREQ(assoc.m_param.u.args.fixed_args, param.u.args.fixed_args);
    EXPECT_STREQ(assoc.m_param.u.args.args[0], param.u.args.args[0]);
    EXPECT_EQ(assoc.m_type, em_cmd_type_sta_assoc);
    EXPECT_STREQ(assoc.m_name, "sta_assoc");
    EXPECT_EQ(assoc.m_svc, em_service_type_ctrl);
    EXPECT_EQ(assoc.m_orch_op_idx, 0);
    EXPECT_EQ(assoc.m_num_orch_desc, 1);
    EXPECT_EQ(assoc.m_orch_desc[0].op, dm_orch_type_sta_cap);
    EXPECT_TRUE(assoc.m_orch_desc[0].submit);
    EXPECT_EQ(assoc.m_data_model.m_cmd_ctx.type, dm_orch_type_sta_cap);
    assoc.deinit();
    std::cout << "Exiting em_cmd_sta_assoc_t_ctor_max_fixed_args test" << std::endl;
}
