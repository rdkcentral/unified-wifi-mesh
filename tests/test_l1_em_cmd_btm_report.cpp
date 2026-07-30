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
#include "em_cmd_btm_report.h"

static void set_mac_field(const char* str, mac_address_t &field) {
    unsigned int bytes[6];
    if (sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
               &bytes[0], &bytes[1], &bytes[2],
               &bytes[3], &bytes[4], &bytes[5]) == 6) {
        for (int i = 0; i < 6; i++)
	    field[i] = static_cast<uint8_t>(bytes[i]);
    } else {
        memset(field, 0, sizeof(field));
    }
}

/**
 * @brief Verify that the em_cmd_btm_report_t object is correctly initialized with valid standard parameters.
 *
 * This test verifies that when valid parameters are provided to initialize an em_cmd_btm_report_t object, the object’s
 * internal parameters (MAC addresses and status code) correctly reflect the input values. It also ensures that the
 * deinitialization function completes successfully.
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
 * | Variation / Step | Description                                                         | Test Data                                                                                                    | Expected Result                                           | Notes              |
 * | :--------------: | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------- | ------------------ |
 * | 01               | Initialize parameters, set MAC addresses and status code            | input: source = "AA:BB:CC:DD:EE:FF", sta_mac = "11:22:33:44:55:66", status_code = 1, target = "FF:EE:DD:CC:BB:AA" | Params structure is properly initialized with correct values | Should be successful |
 * | 02               | Create the report object using the initialized parameters             | input: params (with the above values)                                                                         | Report instance is created with matching parameter values  | Should Pass        |
 * | 03               | Validate the 'source' MAC address in the report object                | input: compare report.m_param.u.btm_report_params.source with params.source                                    | memcmp returns 0, indicating both MAC addresses are equal  | Should Pass        |
 * | 04               | Validate the 'sta_mac' field in the report object                     | input: compare report.m_param.u.btm_report_params.sta_mac with params.sta_mac                                  | memcmp returns 0, indicating both MAC addresses are equal  | Should Pass        |
 * | 05               | Validate the status code in the report object                         | input: report.m_param.u.btm_report_params.status_code, expected = 1                                            | status_code equals 1                                       | Should Pass        |
 * | 06               | Validate the 'target' MAC address in the report object                | input: compare report.m_param.u.btm_report_params.target with params.target                                    | memcmp returns 0, indicating both MAC addresses are equal  | Should Pass        |
 * | 07               | Call the deinitialization function for the report object              | input: Call report.deinit()                                                                                     | Report object is deinitialized without error               | Should be successful |
 */
TEST(em_cmd_btm_report_t, valid_standard) {
    std::cout << "Entering valid_standard test\n";
    em_cmd_btm_report_params_t params;
    memset(&params, 0, sizeof(params));
    set_mac_field("AA:BB:CC:DD:EE:FF", params.source);
    set_mac_field("11:22:33:44:55:66", params.sta_mac);
    params.status_code = 1;
    set_mac_field("FF:EE:DD:CC:BB:AA", params.target);
    em_cmd_btm_report_t report(params);
    EXPECT_EQ(memcmp(report.m_param.u.btm_report_params.source, params.source, 6), 0);
    EXPECT_EQ(memcmp(report.m_param.u.btm_report_params.sta_mac, params.sta_mac, 6), 0);
    EXPECT_EQ(report.m_param.u.btm_report_params.status_code, 1);
    EXPECT_EQ(memcmp(report.m_param.u.btm_report_params.target, params.target, 6), 0);
    report.deinit();
    std::cout << "Exiting valid_standard test\n";
}
/**
 * @brief Test verifying initialization with zero-filled MAC addresses
 *
 * This test verifies that the em_cmd_btm_report_t API correctly initializes its internal parameters when provided with zero-filled MAC addresses and a status code of 1. It ensures that the internal arrays for source, sta_mac, and target are set correctly to zero, and checks that the status code is properly stored. The test also confirms that the deinitialization routine functions as expected.
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
 * | 01 | Initialize report parameters with zero-filled source, sta_mac, and target arrays and set status_code to 1 | params.source = 0, params.sta_mac = 0, params.target = 0, params.status_code = 1 | Parameters are initialized with zero values and status_code equals 1 | Should be successful |
 * | 02 | Create an instance of em_cmd_btm_report_t with the initialized parameters | Input: params as above | Report object is created with matching internal parameters | Should Pass |
 * | 03 | Validate that the source, sta_mac, and target arrays in the report match the initialized arrays and that the status_code equals 1 | Check using memcmp for arrays and direct equality for status_code | memcmp returns 0 for all arrays and status_code is 1 | Should Pass |
 * | 04 | Invoke deinit() on the report object | Call report.deinit() | Report object is deinitialized without error | Should be successful |
 */
TEST(em_cmd_btm_report_t, zero_mac_addresses)
{
    std::cout << "Entering zero_mac_addresses test" << std::endl;
    em_cmd_btm_report_params_t params{};
    memset(params.source, 0, sizeof(params.source));
    memset(params.sta_mac, 0, sizeof(params.sta_mac));
    memset(params.target, 0, sizeof(params.target));
    params.status_code = 1;
    em_cmd_btm_report_t report(params);
    EXPECT_EQ(memcmp(report.m_param.u.btm_report_params.source, params.source, 6), 0);
    EXPECT_EQ(memcmp(report.m_param.u.btm_report_params.sta_mac, params.sta_mac, 6), 0);
    EXPECT_EQ(report.m_param.u.btm_report_params.status_code, 1);
    EXPECT_EQ(memcmp(report.m_param.u.btm_report_params.target, params.target, 6), 0);
    report.deinit();
    std::cout << "Exiting zero_mac_addresses test" << std::endl;
}
/**
 * @brief Test the proper initialization and deinitialization of the em_cmd_btm_report_t object.
 *
 * This test verifies that the em_cmd_btm_report_t object is correctly initialized with default parameters by checking that:
 * - m_orch_op_idx is set to 0
 * - m_num_orch_desc is set to 1
 * - m_orch_desc[0].op is assigned dm_orch_type_sta_steer_btm_report
 * - m_orch_desc[0].submit is true
 * After these verifications, the deinit method is invoked to ensure resources are properly cleaned up.
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
 * | Variation / Step | Description                                                                                           | Test Data                                                                                                                                               | Expected Result                                                                                                                    | Notes            |
 * | :--------------: | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- | ---------------- |
 * | 01               | Initialize em_cmd_btm_report_t with default parameters and verify the initialized member variables.   | params = default, em_cmd_btm_report_t(params): m_orch_op_idx = 0, m_num_orch_desc = 1, m_orch_desc[0].op = dm_orch_type_sta_steer_btm_report, m_orch_desc[0].submit = true | m_orch_op_idx equals 0, m_num_orch_desc equals 1, m_orch_desc[0].op equals dm_orch_type_sta_steer_btm_report, m_orch_desc[0].submit is true | Should Pass      |
 * | 02               | Call deinit() to ensure the object cleans up resources correctly.                                    | report.deinit()                                                                                                                                         | Object cleanup executed without errors                                                                                             | Should be successful |
 */
TEST(em_cmd_btm_report_t, orch_desc_initialization)
{
    std::cout << "Entering orch_desc_initialization test" << std::endl;
    em_cmd_btm_report_params_t params{};
    em_cmd_btm_report_t report(params);
    EXPECT_EQ(report.m_orch_op_idx, 0);
    EXPECT_EQ(report.m_num_orch_desc, 1);
    EXPECT_EQ(report.m_orch_desc[0].op, dm_orch_type_sta_steer_btm_report);
    EXPECT_TRUE(report.m_orch_desc[0].submit);
    report.deinit();
    std::cout << "Exiting orch_desc_initialization test" << std::endl;
}
/**
 * @brief Validate that the report object's name is correctly set to "btm_report"
 *
 * This test creates an instance of the em_cmd_btm_report_t class using default parameters and verifies that its m_name member is initialized to "btm_report". The test ensures that the construction process correctly sets the name value. The test first logs the entry message, constructs the necessary objects, performs the assertion on the name, and finally deinitializes the report object while logging the exit message.
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
 * | 01 | Log the test start message to the console. | No input and output. | "Entering name_set_correctly test" is printed to the console. | Should be successful |
 * | 02 | Initialize default parameters and create the report object. | input: params = {} ; output: report object is instantiated. | Report object is successfully created with default parameters. | Should be successful |
 * | 03 | Validate that the report name is set to "btm_report". | input: report.m_name actual value, expected: "btm_report" | EXPECT_STREQ assertion passes confirming that report.m_name equals "btm_report". | Should Pass |
 * | 04 | Deinitialize the report object and log the test exit message. | input: report reference; function: deinit() invoked. | Report object is deinitialized and "Exiting name_set_correctly test" is printed to the console. | Should be successful |
 */
TEST(em_cmd_btm_report_t, name_set_correctly)
{
    std::cout << "Entering name_set_correctly test" << std::endl;
    em_cmd_btm_report_params_t params{};
    em_cmd_btm_report_t report(params);
    EXPECT_STREQ(report.m_name, "btm_report");
    report.deinit();
    std::cout << "Exiting name_set_correctly test" << std::endl;
}
/**
 * @brief Verify that the service type is properly set during object initialization.
 *
 * This test validates the correct initialization of the service type for the em_cmd_btm_report_t object by checking that the member m_svc is equal to em_service_type_agent using the EXPECT_EQ assertion. The test ensures that the API correctly assigns the service type upon creation.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 005@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Construct the em_cmd_btm_report_t object with default parameters | params = {} (default), m_svc_expected = em_service_type_agent | Object is constructed with m_svc equal to em_service_type_agent | Should Pass |
 * | 02 | Verify that m_svc is set correctly using EXPECT_EQ | report.m_svc, expected value = em_service_type_agent | EXPECT_EQ confirms m_svc equals em_service_type_agent | Should Pass |
 * | 03 | Call the deinit method to clean up the object | None | deinit executes without errors | Should be successful |
 */
TEST(em_cmd_btm_report_t, service_type_set_correctly)
{
    std::cout << "Entering service_type_set_correctly test" << std::endl;
    em_cmd_btm_report_params_t params{};
    em_cmd_btm_report_t report(params);
    EXPECT_EQ(report.m_svc, em_service_type_agent);
    report.deinit();
    std::cout << "Exiting service_type_set_correctly test" << std::endl;
}
