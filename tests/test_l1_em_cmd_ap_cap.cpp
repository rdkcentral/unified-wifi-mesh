
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
#include "em_cmd_ap_cap.h"

/**
 * @brief Validate that em_cmd_ap_cap_report_t initializes correctly with valid input parameters.
 *
 * This test verifies that the em_cmd_ap_cap_report_t API correctly assigns the provided command parameters and 
 * initializes its internal state with valid input values. It ensures that the object creation, parameter passing, and 
 * subsequent assertions work as expected for a positive scenario.
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
 * | Variation / Step | Description                                                                                              | Test Data                                                                                                            | Expected Result                                                                                       | Notes          |
 * | :--------------: | -------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ | -------------- |
 * | 01               | Initialize command parameters by setting num_args to 1, fixed_args to "TestAPCapReport", and args[0] to "Arg1". | param.u.args.num_args = 1, param.u.args.fixed_args = "TestAPCapReport", param.u.args.args[0] = "Arg1"                   | Parameters are set correctly.                                                                          | Should be successful |
 * | 02               | Create an instance of dm_easy_mesh_t.                                                                    | N/A                                                                                                                  | dm instance is created successfully.                                                                  | Should be successful |
 * | 03               | Instantiate em_cmd_ap_cap_report_t with the initialized parameters and dm instance.                      | Input: param (with valid values), dm instance                                                                       | report.m_param contains num_args = 1, fixed_args = "TestAPCapReport", and args[0] = "Arg1".              | Should Pass    |
 * | 04               | Validate the report's member values using EXPECT_EQ and EXPECT_STREQ assertions.                         | Expected: num_args = 1, fixed_args = "TestAPCapReport", args[0] = "Arg1"                                                | Assertions pass verifying the parameter values are correctly assigned.                               | Should Pass    |
 * | 05               | Deinitialize the report object by calling report.deinit().                                              | N/A                                                                                                                  | report is deinitialized without error.                                                                 | Should be successful |
 */
TEST(em_cmd_ap_cap_report_t, valid_input)
{
    std::cout << "Entering valid_input test" << std::endl;
    em_cmd_params_t param{};
    param.u.args.num_args = 1;
    strncpy(param.u.args.fixed_args, "TestAPCapReport", sizeof(param.u.args.fixed_args));
    strncpy(param.u.args.args[0], "Arg1", sizeof(param.u.args.args[0]));
    dm_easy_mesh_t dm;
    em_cmd_ap_cap_report_t report(param, dm);
    EXPECT_EQ(report.m_param.u.args.num_args, 1);
    EXPECT_STREQ(report.m_param.u.args.fixed_args, "TestAPCapReport");
    EXPECT_STREQ(report.m_param.u.args.args[0], "Arg1");
    report.deinit();
    std::cout << "Exiting valid_input test" << std::endl;
}
/**
 * @brief Verify that the report object properly handles an empty input scenario.
 *
 * This test case is designed to check that when the em_cmd_params_t structure is initialized with zero arguments and its fixed_args field is reset, the em_cmd_ap_cap_report_t object correctly reflects these empty input values. The test further ensures that the deinitialization method cleans up properly.
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
 * | 01 | Initialize command parameters with no arguments, invoke the API to create the report object, verify parameter values, and deinitialize the object. | param.u.args.num_args = 0, fixed_args zeroed using memset, dm initialized as default instance, report created with param and dm | report.m_param.u.args.num_args equals 0 and report.m_param.u.args.fixed_args equals an empty string; deinit completes successfully | Should Pass |
 */
TEST(em_cmd_ap_cap_report_t, empty_input)
{
    std::cout << "Entering empty_input test" << std::endl;
    em_cmd_params_t param{};
    param.u.args.num_args = 0;
    memset(param.u.args.fixed_args, 0, sizeof(param.u.args.fixed_args));
    dm_easy_mesh_t dm;
    em_cmd_ap_cap_report_t report(param, dm);
    EXPECT_EQ(report.m_param.u.args.num_args, 0);
    EXPECT_STREQ(report.m_param.u.args.fixed_args, "");
    report.deinit();
    std::cout << "Exiting empty_input test" << std::endl;
}
/**
 * @brief Validate multiple argument handling in em_cmd_ap_cap_report_t
 *
 * This test verifies that multiple arguments are correctly handled and stored in em_cmd_ap_cap_report_t.
 * It ensures that the num_args, fixed_args, and args array elements are properly set based on the provided input.
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
 * | Variation / Step | Description                                                                 | Test Data                                                                                                           | Expected Result                                                                                           | Notes             |
 * | :--------------: | --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | ----------------- |
 * | 01               | Invoke API with valid multiple argument data                                | input: num_args = 3, fixed_args = "MultiArgReport", args[0] = "Arg1", args[1] = "Arg2", args[2] = "Arg3"             | API creates report object with all fields initialized to the provided values                              | Should Pass       |
 * | 02               | Validate num_args field in the report object                                | output: m_param.u.args.num_args = 3                                                                                 | EXPECT_EQ(report.m_param.u.args.num_args, 3) passes                                                       | Should Pass       |
 * | 03               | Validate fixed_args field in the report object                               | output: m_param.u.args.fixed_args = "MultiArgReport"                                                                | EXPECT_STREQ(report.m_param.u.args.fixed_args, "MultiArgReport") passes                                     | Should Pass       |
 * | 04               | Validate args array elements in the report object (Arg1, Arg2, Arg3 respectively) | output: m_param.u.args.args[0] = "Arg1", m_param.u.args.args[1] = "Arg2", m_param.u.args.args[2] = "Arg3"              | EXPECT_STREQ for each args element passes (for Arg1, Arg2, and Arg3 respectively)                           | Should Pass       |
 * | 05               | Invoke deinit to clean up the report object                                 | output: report.deinit() invoked                                                                                     | deinit method executes without error                                                                     | Should be successful |
 */
TEST(em_cmd_ap_cap_report_t, multiple_arguments)
{
    std::cout << "Entering multiple_arguments test" << std::endl;
    em_cmd_params_t param{};
    param.u.args.num_args = 3;
    strncpy(param.u.args.fixed_args, "MultiArgReport", sizeof(param.u.args.fixed_args));
    const char* argsArr[] = {"Arg1", "Arg2", "Arg3"};
    for (int i = 0; i < 3; i++)
        strncpy(param.u.args.args[i], argsArr[i], sizeof(param.u.args.args[i]));
    dm_easy_mesh_t dm;
    em_cmd_ap_cap_report_t report(param, dm);
    EXPECT_EQ(report.m_param.u.args.num_args, 3);
    EXPECT_STREQ(report.m_param.u.args.fixed_args, "MultiArgReport");
    EXPECT_STREQ(report.m_param.u.args.args[0], "Arg1");
    EXPECT_STREQ(report.m_param.u.args.args[1], "Arg2");
    EXPECT_STREQ(report.m_param.u.args.args[2], "Arg3");
    report.deinit();
    std::cout << "Exiting multiple_arguments test" << std::endl;
}
/**
 * @brief Test the initialization and validation of em_cmd_ap_cap_report_t with zero additional arguments and a non-empty fixed argument.
 *
 * This test verifies that when the number of arguments is set to zero and a valid fixed argument is provided ("OnlyFixedArg"), 
 * the em_cmd_ap_cap_report_t object is correctly instantiated with the expected parameter values. The test then validates the integrity of the parameters 
 * using EXPECT_EQ and EXPECT_STREQ assertions, and finally ensures that the deinitialization function executes without error.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 004@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                   | Test Data                                                                                     | Expected Result                                                              | Notes          |
 * | :--------------: | --------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | -------------- |
 * | 01               | Initialize the em_cmd_params_t object setting num_args to 0 and fixed_args to "OnlyFixedArg".   | param.u.args.num_args = 0, param.u.args.fixed_args = "OnlyFixedArg"                             | Parameters are assigned correctly.                                         | Should be successful |
 * | 02               | Create dm_easy_mesh_t object and instantiate em_cmd_ap_cap_report_t with the given parameters.   | Input: param (with above values), dm (default constructed)                                    | em_cmd_ap_cap_report_t object is created with m_param reflecting input values.| Should Pass    |
 * | 03               | Validate that report.m_param.u.args.num_args equals 0 using EXPECT_EQ.                         | Actual: report.m_param.u.args.num_args, Expected: 0                                            | The num_args value in the report matches 0.                                  | Should Pass    |
 * | 04               | Validate that report.m_param.u.args.fixed_args equals "OnlyFixedArg" using EXPECT_STREQ.         | Actual: report.m_param.u.args.fixed_args, Expected: "OnlyFixedArg"                               | The fixed_args string in the report matches "OnlyFixedArg".                  | Should Pass    |
 * | 05               | Deinitialize the report object by calling report.deinit().                                    | Method invocation: report.deinit()                                                             | Object deinitialization completes successfully.                            | Should be successful |
 */
TEST(em_cmd_ap_cap_report_t, zero_args_nonempty_fixed)
{
    std::cout << "Entering zero_args_nonempty_fixed test" << std::endl;
    em_cmd_params_t param{};
    param.u.args.num_args = 0;
    strncpy(param.u.args.fixed_args, "OnlyFixedArg", sizeof(param.u.args.fixed_args));
    dm_easy_mesh_t dm;
    em_cmd_ap_cap_report_t report(param, dm);
    EXPECT_EQ(report.m_param.u.args.num_args, 0);
    EXPECT_STREQ(report.m_param.u.args.fixed_args, "OnlyFixedArg");
    report.deinit();
    std::cout << "Exiting zero_args_nonempty_fixed test" << std::endl;
}
/**
 * @brief Verify that the AP capability report constructor initializes its orchestration descriptor correctly
 *
 * This test verifies that the em_cmd_ap_cap_report_t constructor properly initializes its orchestration descriptor fields.
 * It ensures that the operator index is set to 0, the number of orchestration descriptors is set to 1, the operation type is
 * correctly defined as dm_orch_type_ap_cap_report, and the submit flag is set to true.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 005
 * **Priority:** High
 * 
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call the em_cmd_ap_cap_report_t constructor with default em_cmd_params_t and dm_easy_mesh_t and verify initialized values | param = default, dm = default, m_orch_op_idx = 0, m_num_orch_desc = 1, m_orch_desc[0].op = dm_orch_type_ap_cap_report, m_orch_desc[0].submit = true | m_orch_op_idx equals 0, m_num_orch_desc equals 1, m_orch_desc[0].op equals dm_orch_type_ap_cap_report, and m_orch_desc[0].submit is true | Should Pass |
 */
TEST(em_cmd_ap_cap_report_t, orch_desc_initialization)
{
    std::cout << "Entering orch_desc_initialization test" << std::endl;
    em_cmd_params_t param{};
    dm_easy_mesh_t dm;
    em_cmd_ap_cap_report_t report(param, dm);
    EXPECT_EQ(report.m_orch_op_idx, 0);
    EXPECT_EQ(report.m_num_orch_desc, 1);
    EXPECT_EQ(report.m_orch_desc[0].op, dm_orch_type_ap_cap_report);
    EXPECT_TRUE(report.m_orch_desc[0].submit);
    report.deinit();
    std::cout << "Exiting orch_desc_initialization test" << std::endl;
}
/**
 * @brief Verify that the AP capability report has the correct name and service type.
 *
 * This test instantiates an em_cmd_ap_cap_report_t object using default parameters 
 * and verifies that the m_name member is set to "ap_cap" and the m_svc member is set 
 * to em_service_type_agent. The test ensures the object's construction initializes 
 * the internal fields as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 006@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:** 
 * | Variation / Step | Description                                                       | Test Data                                                                                     | Expected Result                                                                | Notes          |
 * | :--------------: | ----------------------------------------------------------------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ | -------------- |
 * | 01               | Initialize test parameters and objects (param and dm)             | input: param = default, dm = default                                                            | em_cmd_ap_cap_report_t object is created successfully                          | Should be successful |
 * | 02               | Verify m_name field is set correctly                              | output: report.m_name, expected = "ap_cap"                                                      | report.m_name equals "ap_cap" as verified by EXPECT_STREQ                        | Should Pass    |
 * | 03               | Verify m_svc field is set correctly                               | output: report.m_svc, expected = em_service_type_agent                                          | report.m_svc equals em_service_type_agent as verified by EXPECT_EQ               | Should Pass    |
 * | 04               | Invoke deinit() to clean up resources                             | method call: report.deinit()                                                                    | Resources are cleaned up without issues                                         | Should be successful |
 */
TEST(em_cmd_ap_cap_report_t, name_and_service_set)
{
    std::cout << "Entering name_and_service_set test" << std::endl;
    em_cmd_params_t param{};
    dm_easy_mesh_t dm;
    em_cmd_ap_cap_report_t report(param, dm);
    EXPECT_STREQ(report.m_name, "ap_cap");
    EXPECT_EQ(report.m_svc, em_service_type_agent);
    report.deinit();
    std::cout << "Exiting name_and_service_set test" << std::endl;
}
