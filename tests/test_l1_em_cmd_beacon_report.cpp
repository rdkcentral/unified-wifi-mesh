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
#include "em_cmd_beacon_report.h"



/**
 * @brief Verify that em_cmd_beacon_report_t is created correctly with valid parameters.
 *
 * This test verifies that the em_cmd_beacon_report_t API initializes all members with the expected valid parameter values. 
 * It checks that the fixed argument, the first argument value, the number of arguments, and various object properties 
 * (such as command type, operation index, descriptor, name, and service type) are correctly set upon construction. 
 * @n
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Log the entering test message | None | "Entering em_cmd_beacon_report_t_create_valid_parameters test" printed | Should be successful |
 * | 02 | Initialize the fixed_args field with a valid string | param.u.args.fixed_args = "ValidFixedArguments" | fixed_args is set correctly with a null terminator | Should be successful |
 * | 03 | Initialize the first argument in args array with a valid string | param.u.args.args[0] = "Argument1" | args[0] is set correctly with a null terminator | Should be successful |
 * | 04 | Set the number of arguments | param.u.args.num_args = 1 | num_args equals 1 | Should be successful |
 * | 05 | Log the API invocation details with fixed_args and argument value | Printed message with param.u.args.fixed_args and param.u.args.args[0] values | Correct invocation message is printed | Should be successful |
 * | 06 | Create the em_cmd_beacon_report_t object with valid parameters | Invocation using: fixed_args = "ValidFixedArguments", args[0] = "Argument1", num_args = 1, dm instance | Object is instantiated with proper member initialization | Should Pass |
 * | 07 | Validate object member values using assertions | Expected: fixed_args = "ValidFixedArguments", num_args = 1, args[0] = "Argument1", m_type = em_cmd_type_beacon_report, m_orch_op_idx = 0, m_num_orch_desc = 1, m_orch_desc[0].submit = true, m_name = "beacon_report", m_orch_desc[0].op = dm_orch_type_beacon_report, m_svc = em_service_type_ctrl, m_data_model.m_cmd_ctx.type = dm_orch_type_beacon_report | All assertions pass confirming correct values | Should Pass |
 * | 08 | Deinitialize the command object | Call cmd.deinit() | Resources are released and object is deinitialized properly | Should be successful |
 * | 09 | Log the exiting test message | None | "Exiting em_cmd_beacon_report_t_create_valid_parameters test" printed | Should be successful |
 */
TEST(em_cmd_beacon_report_t, em_cmd_beacon_report_t_create_valid_parameters) {
    std::cout << "Entering em_cmd_beacon_report_t_create_valid_parameters test" << std::endl;
    em_cmd_params_t param;
    const char *fixedStr = "ValidFixedArguments";
    strncpy(param.u.args.fixed_args, fixedStr, sizeof(param.u.args.fixed_args) - 1);
    param.u.args.fixed_args[sizeof(param.u.args.fixed_args) - 1] = '\0';
    const char *arg0 = "Argument1";
    strncpy(param.u.args.args[0], arg0, sizeof(param.u.args.args[0]) - 1);
    param.u.args.args[0][sizeof(param.u.args.args[0]) - 1] = '\0';
    param.u.args.num_args = 1;
    dm_easy_mesh_t dm;
    std::cout << "Invoking em_cmd_beacon_report_t with fixed_args: " << param.u.args.fixed_args << " and argument[0]: " << param.u.args.args[0] << std::endl;
    em_cmd_beacon_report_t cmd(param, dm);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "ValidFixedArguments");
    EXPECT_EQ(cmd.m_param.u.args.num_args, 1);
    EXPECT_STREQ(cmd.m_param.u.args.args[0], "Argument1");
    EXPECT_EQ(cmd.m_type, em_cmd_type_beacon_report);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 1);
    EXPECT_TRUE(cmd.m_orch_desc[0].submit);
    EXPECT_STREQ(cmd.m_name, "beacon_report");
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_beacon_report);
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_EQ(cmd.m_data_model.m_cmd_ctx.type, dm_orch_type_beacon_report);
    cmd.deinit();
    std::cout << "Exiting em_cmd_beacon_report_t_create_valid_parameters test" << std::endl;
}
/**
 * @brief Test the creation of a beacon_report command with edge case parameter lengths
 *
 * This test confirms that the em_cmd_beacon_report_t command is properly initialized when provided with edge-case parameter lengths.
 * Specifically, it verifies that the fixed argument string and each argument in the args array are correctly set to their maximum edge-case values,
 * and that all member fields of the beacon report command match the expected values after initialization.
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
 * | 01 | Initialize test parameters by filling fixed_args with 'X' and each argument in args with 'Y', and setting num_args to EM_CLI_MAX_ARGS | fixed_args = 'X' repeated (sizeof(fixed_args)-1), args = 'Y' repeated (sizeof(each args element)-1), num_args = EM_CLI_MAX_ARGS | All parameters are correctly initialized with edge-case lengths | Should be successful |
 * | 02 | Invoke the em_cmd_beacon_report_t constructor with the initialized param and dm instance | Input: param (with fixed_args and args as set above), dm instance | beaconReport instance is created with proper initialization of its internal fields | Should Pass |
 * | 03 | Validate beaconReport fields using assertions (m_type, m_orch_op_idx, m_num_orch_desc, m_name, m_orch_desc, m_svc, m_data_model, and parameter consistency) | Expected: m_type = em_cmd_type_beacon_report, m_orch_op_idx = 0, m_num_orch_desc = 1, m_name = "beacon_report", m_orch_desc[0].submit = true, m_orch_desc[0].op = dm_orch_type_beacon_report, m_svc = em_service_type_ctrl, m_data_model.m_cmd_ctx.type = dm_orch_type_beacon_report, and parameters match input | All member fields satisfy the expected conditions and assertions pass | Should Pass |
 * | 04 | Deinitialize the beaconReport instance by calling deinit() | N/A | Resources are properly released without error | Should be successful |
 */
TEST(em_cmd_beacon_report_t, em_cmd_beacon_report_t_create_edge_case_parameter_lengths) {
    std::cout << "Entering em_cmd_beacon_report_t_create_edge_case_parameter_lengths test" << std::endl;
    em_cmd_params_t param;
    memset(param.u.args.fixed_args, 'X', sizeof(param.u.args.fixed_args) - 1);
    param.u.args.fixed_args[sizeof(param.u.args.fixed_args) - 1] = '\0';
    const int maxArgs = EM_CLI_MAX_ARGS;
    for (int i = 0; i < maxArgs; i++) {
        memset(param.u.args.args[i], 'Y', sizeof(param.u.args.args[i]) - 1);
        param.u.args.args[i][sizeof(param.u.args.args[i]) - 1] = '\0';
    }
    param.u.args.num_args = maxArgs;
    dm_easy_mesh_t dm;
    std::cout << "Invoking em_cmd_beacon_report_t with fixed_args (first 20 chars): "  << std::string(param.u.args.fixed_args, 20) << "..." << std::endl;
    em_cmd_beacon_report_t beaconReport(param, dm);
    EXPECT_EQ(beaconReport.m_type, em_cmd_type_beacon_report);
    EXPECT_EQ(beaconReport.m_orch_op_idx, 0);
    EXPECT_EQ(beaconReport.m_num_orch_desc, 1);
    EXPECT_TRUE(beaconReport.m_orch_desc[0].submit);
    EXPECT_STREQ(beaconReport.m_name, "beacon_report");
    EXPECT_EQ(beaconReport.m_orch_desc[0].op, dm_orch_type_beacon_report);
    EXPECT_EQ(beaconReport.m_svc, em_service_type_ctrl);
    EXPECT_EQ(beaconReport.m_data_model.m_cmd_ctx.type, dm_orch_type_beacon_report);
    EXPECT_EQ(memcmp(beaconReport.m_param.u.args.fixed_args, param.u.args.fixed_args, sizeof(param.u.args.fixed_args)), 0);
    EXPECT_EQ(beaconReport.m_param.u.args.num_args, maxArgs);
    for (int i = 0; i < maxArgs; i++) {
        EXPECT_EQ(
            memcmp(beaconReport.m_param.u.args.args[i],
                   param.u.args.args[i],
                   sizeof(param.u.args.args[i])),
            0
        );
    }
    beaconReport.deinit();
    std::cout << "Exiting em_cmd_beacon_report_t_create_edge_case_parameter_lengths test" << std::endl;
}
/**
 * @brief Validates that the em_cmd_beacon_report_t object initializes correctly with minimal valid parameters.
 *
 * This test verifies that when the minimal valid fixed arguments ("a") and a minimal command argument ("b") are provided,
 * the em_cmd_beacon_report_t constructor correctly initializes the associated member variables. It ensures all fields are set as expected,
 * matching the provided inputs and default values, and that the proper command type and service are assigned.
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
 * | 01 | Initialize minimal fixed_args and argument values; assign num_args. | fixed_args = "a", args[0] = "b", num_args = 1 | The parameters structure is populated with minimal valid values. | Should be successful |
 * | 02 | Instantiate the dm_easy_mesh_t object required by the command. | dm instance created with default initialization | dm_easy_mesh_t object created successfully. | Should be successful |
 * | 03 | Invoke the em_cmd_beacon_report_t constructor with the minimal valid parameters and dm instance. | param (with fixed_args "a", args[0] "b", num_args = 1), dm | A beaconReport object is created with member variables set based on the input parameters and default configurations. | Should Pass |
 * | 04 | Validate that fixed_args in beaconReport matches the minimal fixed_args "a". | input: m_param.u.args.fixed_args = "a" | EXPECT_STREQ confirms "a" equals the stored fixed_args. | Should Pass |
 * | 05 | Validate that the number of arguments is set to 1. | input: m_param.u.args.num_args = 1 | EXPECT_EQ confirms num_args equals 1. | Should Pass |
 * | 06 | Validate that the argument passed (args[0]) matches the minimal argument "b". | input: m_param.u.args.args[0] = "b" | EXPECT_STREQ confirms "b" equals the stored argument. | Should Pass |
 * | 07 | Validate that the command type is correctly set to em_cmd_type_beacon_report. | input: m_type = em_cmd_type_beacon_report | EXPECT_EQ confirms m_type matches em_cmd_type_beacon_report. | Should Pass |
 * | 08 | Validate that the operational index is set to 0. | input: m_orch_op_idx = 0 | EXPECT_EQ confirms m_orch_op_idx equals 0. | Should Pass |
 * | 09 | Validate that the number of orchestrator descriptors is set to 1. | input: m_num_orch_desc = 1 | EXPECT_EQ confirms m_num_orch_desc equals 1. | Should Pass |
 * | 10 | Validate that the first orchestrator descriptor is marked for submission. | input: m_orch_desc[0].submit = true | EXPECT_TRUE confirms m_orch_desc[0].submit is true. | Should Pass |
 * | 11 | Validate that the command name is set to "beacon_report". | input: m_name = "beacon_report" | EXPECT_STREQ confirms m_name equals "beacon_report". | Should Pass |
 * | 12 | Validate that the orchestrator operation type is set to dm_orch_type_beacon_report. | input: m_orch_desc[0].op = dm_orch_type_beacon_report | EXPECT_EQ confirms m_orch_desc[0].op matches dm_orch_type_beacon_report. | Should Pass |
 * | 13 | Validate that the service type is set to em_service_type_ctrl. | input: m_svc = em_service_type_ctrl | EXPECT_EQ confirms m_svc equals em_service_type_ctrl. | Should Pass |
 * | 14 | Validate that the command context type in the data model matches dm_orch_type_beacon_report. | input: m_data_model.m_cmd_ctx.type = dm_orch_type_beacon_report | EXPECT_EQ confirms the type is dm_orch_type_beacon_report. | Should Pass |
 */
TEST(em_cmd_beacon_report_t, em_cmd_beacon_report_t_create_minimal_valid_parameters) {
    std::cout << "Entering em_cmd_beacon_report_t_create_minimal_valid_parameters test" << std::endl;
    em_cmd_params_t param;
    const char *minFixed = "a";
    strncpy(param.u.args.fixed_args, minFixed, sizeof(param.u.args.fixed_args) - 1);
    param.u.args.fixed_args[sizeof(param.u.args.fixed_args)-1] = '\0';
    const char *minArg = "b";
    strncpy(param.u.args.args[0], minArg, sizeof(param.u.args.args[0]) - 1);
    param.u.args.args[0][sizeof(param.u.args.args[0])-1] = '\0';
    param.u.args.num_args = 1;
    dm_easy_mesh_t dm;
    std::cout << "Invoking em_cmd_beacon_report_t with minimal fixed_args: " << param.u.args.fixed_args << " and minimal argument: " << param.u.args.args[0] << std::endl;
    em_cmd_beacon_report_t beaconReport(param, dm);
    EXPECT_STREQ(beaconReport.m_param.u.args.fixed_args, minFixed);
    EXPECT_EQ(beaconReport.m_param.u.args.num_args, 1);
    EXPECT_STREQ(beaconReport.m_param.u.args.args[0], minArg);
    EXPECT_EQ(beaconReport.m_type, em_cmd_type_beacon_report);
    EXPECT_EQ(beaconReport.m_orch_op_idx, 0);
    EXPECT_EQ(beaconReport.m_num_orch_desc, 1);
    EXPECT_TRUE(beaconReport.m_orch_desc[0].submit);
    EXPECT_STREQ(beaconReport.m_name, "beacon_report");
    EXPECT_EQ(beaconReport.m_orch_desc[0].op, dm_orch_type_beacon_report);
    EXPECT_EQ(beaconReport.m_svc, em_service_type_ctrl);
    EXPECT_EQ(beaconReport.m_data_model.m_cmd_ctx.type, dm_orch_type_beacon_report);
    beaconReport.deinit();
    std::cout << "Exiting em_cmd_beacon_report_t_create_minimal_valid_parameters test" << std::endl;
}
/**
 * @brief Verify the construction of em_cmd_beacon_report_t object with empty fixed_args
 *
 * This test validates that when the input fixed_args is an empty string and num_args is set to 0,
 * the em_cmd_beacon_report_t API correctly initializes the internal parameters of the command object.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Set num_args to 0 and copy an empty string into fixed_args of params. | params.u.args.num_args = 0, params.u.args.fixed_args = "" | params.u.args.fixed_args is empty and num_args is 0 | Should Pass |
 * | 02 | Create a dm_easy_mesh_t object. | dm_easy_mesh_t dm instantiated | dm object is created successfully | Should be successful |
 * | 03 | Construct an em_cmd_beacon_report_t object using params and dm. | params (num_args = 0, fixed_args = ""), dm | em_cmd_beacon_report_t object is constructed and its internal parameters are initialized | Should Pass |
 * | 04 | Validate the internal member values of the constructed object using assertions. | cmd.m_param.u.args.fixed_args = "", cmd.m_param.u.args.num_args = 0, cmd.m_type = em_cmd_type_beacon_report, cmd.m_orch_op_idx = 0, cmd.m_num_orch_desc = 1, cmd.m_orch_desc[0].submit = true, cmd.m_name = "beacon_report", cmd.m_orch_desc[0].op = dm_orch_type_beacon_report, cmd.m_svc = em_service_type_ctrl, cmd.m_data_model.m_cmd_ctx.type = dm_orch_type_beacon_report | All internal members are set as expected | Should Pass |
 * | 05 | Call deinit to release any allocated resources. | cmd.deinit() | Resources are released without error | Should be successful |
 */
TEST(em_cmd_beacon_report_t, em_cmd_beacon_report_t_empty_fixed_args) {
    std::cout << "Entering em_cmd_beacon_report_t_empty_fixed_args test" << std::endl;
    em_cmd_params_t params{};
    params.u.args.num_args = 0;
    const char *emptyStr = "";
    strncpy(params.u.args.fixed_args, emptyStr, sizeof(params.u.args.fixed_args));
    std::cout << "Passed fixed_args (expected empty): '" << params.u.args.fixed_args << "'" << std::endl;
    dm_easy_mesh_t dm;
    std::cout << "dm_easy_mesh_t object created" << std::endl;
    em_cmd_beacon_report_t cmd(params, dm);
    std::cout << "em_cmd_beacon_report_t object constructed successfully with empty fixed_args" << std::endl;
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "");
    EXPECT_EQ(cmd.m_param.u.args.num_args, 0);
    EXPECT_EQ(cmd.m_type, em_cmd_type_beacon_report);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 1);
    EXPECT_TRUE(cmd.m_orch_desc[0].submit);
    EXPECT_STREQ(cmd.m_name,  "beacon_report");
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_beacon_report);
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_EQ(cmd.m_data_model.m_cmd_ctx.type, dm_orch_type_beacon_report);
    cmd.deinit();
    std::cout << "Exiting em_cmd_beacon_report_t_empty_fixed_args test" << std::endl;
}