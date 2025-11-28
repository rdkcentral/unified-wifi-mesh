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
#include <cstring>
#include "em_cmd_sta_steer.h"

// Helper function to convert a raw 6-byte MAC address to a colon-separated string.
static void parse_mac(const char* str, unsigned char out[6])
{
    unsigned int b[6];
    sscanf(str, "%02X:%02X:%02X:%02X:%02X:%02X",
           &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]);

    for (int i = 0; i < 6; i++)
        out[i] = (unsigned char)b[i];
}


/**
 * @brief Tests the creation of an em_cmd_sta_steer_t instance using valid standard parameters.
 *
 * This test verifies that the em_cmd_sta_steer_t constructor properly initializes an object when provided with valid,
 * standard parameters. It checks that no exceptions are thrown during object construction and that the parameters are set as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 001@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize the em_cmd_steer_params_t structure with valid standard values. | sta_mac = "00:11:22:33:44:55", source = "66:77:88:99:AA:BB", target = "CC:DD:EE:FF:00:11", request_mode = 1, disassoc_imminent = false, btm_abridged = false, link_removal_imminent = false, steer_opportunity_win = 100, btm_disassociation_timer = 30, target_op_class = 81, target_channel = 6 | Parameters structure is correctly initialized with the provided values. | Should be successful |
 * | 02 | Invoke the em_cmd_sta_steer_t constructor with the initialized parameters. | params = em_cmd_steer_params_t structure as defined in Step 01 | Instance is created successfully without throwing an exception. | Should Pass |
 */
TEST(em_cmd_sta_steer_t, em_cmd_sta_steer_t_valid_standard_parameters) {
    std::cout << "Entering em_cmd_sta_steer_t_valid_standard_parameters test" << std::endl;
    em_cmd_steer_params_t params{};
    const char* mac_sta    = "00:11:22:33:44:55";
    const char* mac_source = "66:77:88:99:AA:BB";
    const char* mac_target = "CC:DD:EE:FF:00:11";
    unsigned char sta_bytes[6];
    unsigned char source_bytes[6];
    unsigned char target_bytes[6];
    parse_mac(mac_sta,    sta_bytes);
    parse_mac(mac_source, source_bytes);
    parse_mac(mac_target, target_bytes);
    memcpy(params.sta_mac, sta_bytes, 6);
    memcpy(params.source,  source_bytes, 6);
    memcpy(params.target,  target_bytes, 6);
    params.request_mode = 1;
    params.disassoc_imminent = false;
    params.btm_abridged = false;
    params.link_removal_imminent = false;
    params.steer_opportunity_win = 100;
    params.btm_disassociation_timer = 30;
    params.target_op_class = 81;
    params.target_channel = 6;
    std::cout << "Invoking constructor with parameters:" << std::endl;
    std::cout << "sta_mac: " << mac_sta << std::endl;
    std::cout << "source: " << mac_source << std::endl;
    std::cout << "target: " << mac_target << std::endl;
    std::cout << "request_mode: " << params.request_mode << std::endl;
    std::cout << "disassoc_imminent: " << params.disassoc_imminent << std::endl;
    std::cout << "btm_abridged: " << params.btm_abridged << std::endl;
    std::cout << "link_removal_imminent: " << params.link_removal_imminent << std::endl;
    std::cout << "steer_opportunity_win: " << params.steer_opportunity_win << std::endl;
    std::cout << "btm_disassociation_timer: " << params.btm_disassociation_timer << std::endl;
    std::cout << "target_op_class: " << params.target_op_class << std::endl;
    std::cout << "target_channel: " << params.target_channel << std::endl;
    EXPECT_NO_THROW({
        em_cmd_sta_steer_t obj(params);
        std::cout << "Instance created successfully." << std::endl;
        EXPECT_EQ(obj.m_type, em_cmd_type_sta_steer);
        EXPECT_STREQ(obj.m_name, "steer_sta");
        EXPECT_EQ(obj.m_orch_op_idx, 0);
        EXPECT_EQ(obj.m_num_orch_desc, 1u);
        EXPECT_EQ(obj.m_orch_desc[0].op, dm_orch_type_sta_steer);
        EXPECT_EQ(obj.m_orch_desc[0].submit, true);
	EXPECT_EQ(memcmp(obj.m_param.u.steer_params.sta_mac, sta_bytes, 6), 0);
        EXPECT_EQ(memcmp(obj.m_param.u.steer_params.source,  source_bytes, 6), 0);
        EXPECT_EQ(memcmp(obj.m_param.u.steer_params.target,  target_bytes, 6), 0);
        EXPECT_EQ(obj.m_param.u.steer_params.request_mode, 1u);
        EXPECT_EQ(obj.m_param.u.steer_params.disassoc_imminent, false);
        EXPECT_EQ(obj.m_param.u.steer_params.btm_abridged, false);
        EXPECT_EQ(obj.m_param.u.steer_params.link_removal_imminent, false);
        EXPECT_EQ(obj.m_param.u.steer_params.steer_opportunity_win, 100u);
        EXPECT_EQ(obj.m_param.u.steer_params.btm_disassociation_timer, 30u);
        EXPECT_EQ(obj.m_param.u.steer_params.target_op_class, 81u);
        EXPECT_EQ(obj.m_param.u.steer_params.target_channel, 6u);
        EXPECT_EQ(obj.m_svc, em_service_type_agent);
        obj.deinit();
    });
    std::cout << "Exiting em_cmd_sta_steer_t_valid_standard_parameters test." << std::endl;
}

/**
 * @brief Validate successful creation of em_cmd_sta_steer_t instance with minimal parameters
 *
 * This test verifies that the em_cmd_sta_steer_t constructor operates correctly when provided with minimal valid parameters. It ensures that no exceptions are thrown and that the object is instantiated successfully with the provided default values.
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
 * | Variation / Step | Description                                                                                                 | Test Data                                                                                                                                                                                                                | Expected Result                                                                                                     | Notes       |
 * | :--------------: | ----------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------- | ----------- |
 * |      01        | Initialize parameters with minimal valid values and invoke the em_cmd_sta_steer_t constructor                | sta_mac = "00:00:00:00:00:00", source = "00:00:00:00:00:00", target = "00:00:00:00:00:00", request_mode = 0, disassoc_imminent = false, btm_abridged = false, link_removal_imminent = false, steer_opportunity_win = 0, btm_disassociation_timer = 0, target_op_class = 0, target_channel = 0 | Instance is created successfully without exceptions; EXPECT_NO_THROW assertion passes | Should Pass |
 */
TEST(em_cmd_sta_steer_t, em_cmd_sta_steer_t_valid_minimal_parameters) {
    std::cout << "Entering em_cmd_sta_steer_t_valid_minimal_parameters test" << std::endl;

    em_cmd_steer_params_t params{};

    const char* mac = "00:00:00:00:00:00";
    memcpy(params.sta_mac, mac, strlen(mac) + 1);
    memcpy(params.source,  mac, strlen(mac) + 1);
    memcpy(params.target,  mac, strlen(mac) + 1);

    params.request_mode = 0;
    params.disassoc_imminent = false;
    params.btm_abridged = false;
    params.link_removal_imminent = false;
    params.steer_opportunity_win = 0;
    params.btm_disassociation_timer = 0;
    params.target_op_class = 0;
    params.target_channel = 0;

    std::cout << "Invoking em_cmd_sta_steer_t constructor with minimal parameters:" << std::endl;
    std::cout << "sta_mac: " << reinterpret_cast<char*>(params.sta_mac) << std::endl;
    std::cout << "source: " << reinterpret_cast<char*>(params.source) << std::endl;
    std::cout << "target: " << reinterpret_cast<char*>(params.target) << std::endl;
    std::cout << "request_mode: " << params.request_mode << std::endl;
    std::cout << "disassoc_imminent: " << params.disassoc_imminent << std::endl;
    std::cout << "btm_abridged: " << params.btm_abridged << std::endl;
    std::cout << "link_removal_imminent: " << params.link_removal_imminent << std::endl;
    std::cout << "steer_opportunity_win: " << params.steer_opportunity_win << std::endl;
    std::cout << "btm_disassociation_timer: " << params.btm_disassociation_timer << std::endl;
    std::cout << "target_op_class: " << params.target_op_class << std::endl;
    std::cout << "target_channel: " << params.target_channel << std::endl;

    EXPECT_NO_THROW({
        em_cmd_sta_steer_t obj(params);
        std::cout << "Instance created successfully." << std::endl;

	    EXPECT_EQ(obj.m_type, em_cmd_type_sta_steer);
        EXPECT_STREQ(obj.m_name, "steer_sta");
        EXPECT_EQ(obj.m_orch_op_idx, 0);
        EXPECT_EQ(obj.m_num_orch_desc, 1u);
        EXPECT_EQ(obj.m_orch_desc[0].op, dm_orch_type_sta_steer);
        EXPECT_EQ(obj.m_orch_desc[0].submit, true);

        EXPECT_EQ(obj.m_type, em_cmd_type_sta_steer);
        EXPECT_STREQ(obj.m_name, "steer_sta");
        EXPECT_EQ(obj.m_param.u.steer_params.request_mode, 0u);
        EXPECT_EQ(obj.m_param.u.steer_params.disassoc_imminent, false);
        EXPECT_EQ(obj.m_param.u.steer_params.btm_abridged, false);
        EXPECT_EQ(obj.m_param.u.steer_params.link_removal_imminent, false);
        EXPECT_EQ(obj.m_param.u.steer_params.steer_opportunity_win, 0u);
        EXPECT_EQ(obj.m_param.u.steer_params.btm_disassociation_timer, 0u);
        EXPECT_EQ(obj.m_param.u.steer_params.target_op_class, 0u);
        EXPECT_EQ(obj.m_param.u.steer_params.target_channel, 0u);

        obj.deinit();
    });

    std::cout << "Exiting em_cmd_sta_steer_t_valid_minimal_parameters test" << std::endl;
}

/**
 * @brief Tests the successful creation of an em_cmd_sta_steer_t instance with all boolean flags set to true
 *
 * This test verifies that the em_cmd_sta_steer_t constructor initializes the instance correctly when all boolean parameters
 * (disassoc_imminent, btm_abridged, link_removal_imminent) are set to true and other parameters are provided with valid values.
 * It ensures that no exceptions are thrown during the construction and that all assigned parameter values are logged accurately.
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
 * | 01 | Initialize the parameters structure and zero out the memory. | params: memory zeroed | params structure initialized with zeros. | Should be successful |
 * | 02 | Set the MAC address fields (sta_mac, source, target) with valid values. | sta_mac = "AA:BB:CC:DD:EE:FF", source = "11:22:33:44:55:66", target = "77:88:99:AA:BB:CC" | MAC fields correctly populated. | Should be successful |
 * | 03 | Assign the numeric and boolean values including request_mode, disassoc_imminent, btm_abridged, link_removal_imminent, steer_opportunity_win, btm_disassociation_timer, target_op_class, and target_channel. | request_mode = 2, disassoc_imminent = true, btm_abridged = true, link_removal_imminent = true, steer_opportunity_win = 50, btm_disassociation_timer = 60, target_op_class = 115, target_channel = 11 | Numeric and boolean fields are correctly set in the parameters structure. | Should be successful |
 * | 04 | Log all the parameter values to the console before invoking the constructor. | Console printouts of sta_mac, source, target, request_mode, disassoc_imminent, btm_abridged, link_removal_imminent, steer_opportunity_win, btm_disassociation_timer, target_op_class, target_channel | Parameter values correctly printed. | Should be successful |
 * | 05 | Invoke the em_cmd_sta_steer_t constructor inside EXPECT_NO_THROW block to ensure no exception is thrown. | Input: params structure (all fields set as above) | em_cmd_sta_steer_t instance created successfully without throwing an exception. | Should Pass |
 * | 06 | Log the completion of the test to the console. | Console log stating test exit | Test completion message printed. | Should be successful |
 */
TEST(em_cmd_sta_steer_t, em_cmd_sta_steer_t_valid_all_booleans_true) {
    std::cout << "Entering em_cmd_sta_steer_t_valid_all_booleans_true test" << std::endl;

    em_cmd_steer_params_t params{};

    const char* mac_sta    = "AA:BB:CC:DD:EE:FF";
    const char* mac_source = "11:22:33:44:55:66";
    const char* mac_target = "77:88:99:AA:BB:CC";

    memcpy(params.sta_mac, mac_sta,    strlen(mac_sta) + 1);
    memcpy(params.source,  mac_source, strlen(mac_source) + 1);
    memcpy(params.target,  mac_target, strlen(mac_target) + 1);

    params.request_mode = 2;
    params.disassoc_imminent = true;
    params.btm_abridged = true;
    params.link_removal_imminent = true;
    params.steer_opportunity_win = 50;
    params.btm_disassociation_timer = 60;
    params.target_op_class = 115;
    params.target_channel = 11;

    std::cout << "Invoking em_cmd_sta_steer_t constructor with all booleans true:" << std::endl;
    std::cout << "sta_mac: " << reinterpret_cast<char*>(params.sta_mac) << std::endl;
    std::cout << "source: " << reinterpret_cast<char*>(params.source) << std::endl;
    std::cout << "target: " << reinterpret_cast<char*>(params.target) << std::endl;
    std::cout << "request_mode: " << params.request_mode << std::endl;
    std::cout << "disassoc_imminent: " << params.disassoc_imminent << std::endl;
    std::cout << "btm_abridged: " << params.btm_abridged << std::endl;
    std::cout << "link_removal_imminent: " << params.link_removal_imminent << std::endl;
    std::cout << "steer_opportunity_win: " << params.steer_opportunity_win << std::endl;
    std::cout << "btm_disassociation_timer: " << params.btm_disassociation_timer << std::endl;
    std::cout << "target_op_class: " << params.target_op_class << std::endl;
    std::cout << "target_channel: " << params.target_channel << std::endl;

    EXPECT_NO_THROW({
        em_cmd_sta_steer_t obj(params);
        std::cout << "Instance created successfully." << std::endl;

	    EXPECT_EQ(obj.m_type, em_cmd_type_sta_steer);
        EXPECT_STREQ(obj.m_name, "steer_sta");
        EXPECT_EQ(obj.m_orch_op_idx, 0);
        EXPECT_EQ(obj.m_num_orch_desc, 1u);
        EXPECT_EQ(obj.m_orch_desc[0].op, dm_orch_type_sta_steer);
        EXPECT_EQ(obj.m_orch_desc[0].submit, true);

        EXPECT_EQ(obj.m_param.u.steer_params.request_mode, 2u);
        EXPECT_EQ(obj.m_param.u.steer_params.disassoc_imminent, true);
        EXPECT_EQ(obj.m_param.u.steer_params.btm_abridged, true);
        EXPECT_EQ(obj.m_param.u.steer_params.link_removal_imminent, true);
        EXPECT_EQ(obj.m_param.u.steer_params.target_channel, 11u);
        EXPECT_EQ(obj.m_param.u.steer_params.steer_opportunity_win, 50u);
        EXPECT_EQ(obj.m_param.u.steer_params.btm_disassociation_timer, 60u);
        EXPECT_EQ(obj.m_param.u.steer_params.target_op_class, 115u);


        obj.deinit();
    });

    std::cout << "Exiting em_cmd_sta_steer_t_valid_all_booleans_true test" << std::endl;
}

/**
 * @brief Verify that the em_cmd_sta_steer_t constructor properly detects an out-of-range target_channel value.
 *
 * This test sets up a valid parameter structure except for the target_channel which is intentionally given an out-of-range value (999). The objective is to ensure that the constructor of em_cmd_sta_steer_t throws a std::invalid_argument exception when invalid input is provided, thereby preventing further processing of erroneous data.
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
 * | Variation / Step | Description                                                                                  | Test Data                                                                                                                                                                             | Expected Result                                         | Notes       |
 * | :--------------: | -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- | ----------- |
 * | 01               | Invoke the em_cmd_sta_steer_t constructor with parameters containing an out-of-range target_channel | sta_mac = 00:11:22:33:44:55, source = 66:77:88:99:AA:BB, target = CC:DD:EE:FF:00:11, request_mode = 1, disassoc_imminent = false, btm_abridged = false, link_removal_imminent = false, steer_opportunity_win = 100, btm_disassociation_timer = 30, target_op_class = 81, target_channel = 999 | std::invalid_argument exception is thrown | Should Fail |
 */
TEST(em_cmd_sta_steer_t, em_cmd_sta_steer_t_invalid_target_channel_out_of_range) {
    std::cout << "Entering em_cmd_sta_steer_t_invalid_target_channel_out_of_range test" << std::endl;
    em_cmd_steer_params_t params{};
    const char* mac_sta    = "00:11:22:33:44:55";
    const char* mac_source = "66:77:88:99:AA:BB";
    const char* mac_target = "CC:DD:EE:FF:00:11";
    memcpy(params.sta_mac, mac_sta, strlen(mac_sta) + 1);
    memcpy(params.source,  mac_source, strlen(mac_source) + 1);
    memcpy(params.target,  mac_target, strlen(mac_target) + 1);
    params.request_mode = 1;
    params.disassoc_imminent = false;
    params.btm_abridged = false;
    params.link_removal_imminent = false;
    params.steer_opportunity_win = 100;
    params.btm_disassociation_timer = 30;
    params.target_op_class = 81;
    params.target_channel = 999;
    std::cout << "Invoking em_cmd_sta_steer_t constructor with out-of-range target_channel:" << std::endl;
    std::cout << "target_channel: " << params.target_channel << std::endl;
    EXPECT_ANY_THROW({
	em_cmd_sta_steer_t obj(params);
        std::cout << "Instance created successfully." << std::endl;
        obj.deinit();
    });

    std::cout << "Exiting em_cmd_sta_steer_t_invalid_target_channel_out_of_range test" << std::endl;
}

/**
 * @brief Test the handling of an out-of-bound request_mode value in the em_cmd_sta_steer_t constructor.
 *
 * This test verifies that the em_cmd_sta_steer_t constructor correctly handles an invalid request_mode parameter that is set beyond its defined limits. The test aims to ensure that the constructor appropriately throws an std::invalid_argument exception when presented with out-of-bound values, thereby maintaining robustness and preventing unpredictable behavior in the system.
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
 * | 01 | Initialize em_cmd_steer_params_t with valid MAC addresses and set request_mode to an out-of-bound value while configuring other fields appropriately; then invoke the em_cmd_sta_steer_t constructor. | sta_mac = "00:11:22:33:44:55", source = "66:77:88:99:AA:BB", target = "CC:DD:EE:FF:00:11", request_mode = 999999, disassoc_imminent = false, btm_abridged = false, link_removal_imminent = false, steer_opportunity_win = 100, btm_disassociation_timer = 30, target_op_class = 81, target_channel = 6 | Expect std::invalid_argument exception to be thrown indicating the invalid request_mode value; assertion check passes. | Should Fail |
 */
TEST(em_cmd_sta_steer_t, em_cmd_sta_steer_t_invalid_request_mode_out_of_bound) {
    std::cout << "Entering em_cmd_sta_steer_t_invalid_request_mode_out_of_bound test" << std::endl;
    em_cmd_steer_params_t params{};
    const char* mac_sta    = "00:11:22:33:44:55";
    const char* mac_source = "66:77:88:99:AA:BB";
    const char* mac_target = "CC:DD:EE:FF:00:11";
    memcpy(params.sta_mac, mac_sta, strlen(mac_sta) + 1);
    memcpy(params.source,  mac_source, strlen(mac_source) + 1);
    memcpy(params.target,  mac_target, strlen(mac_target) + 1);
    params.request_mode = 999999;
    params.disassoc_imminent = false;
    params.btm_abridged = false;
    params.link_removal_imminent = false;
    params.steer_opportunity_win = 100;
    params.btm_disassociation_timer = 30;
    params.target_op_class = 81;
    params.target_channel = 6;
    std::cout << "Invoking em_cmd_sta_steer_t constructor with out-of-bound request_mode:" << std::endl;
    std::cout << "request_mode: " << params.request_mode << std::endl;
    EXPECT_ANY_THROW({
	em_cmd_sta_steer_t obj(params);
        std::cout << "Instance created successfully." << std::endl;
        obj.deinit();
    });

    std::cout << "Exiting em_cmd_sta_steer_t_invalid_request_mode_out_of_bound test" << std::endl;
}

/**
 * @brief Validates the creation of an em_cmd_sta_steer_t instance using maximum boundary values.
 *
 * This test verifies that an em_cmd_sta_steer_t object can be successfully created when provided with maximum boundary numeric values and corresponding parameters. The test ensures that the constructor does not throw any exceptions and the instantiation process handles boundary conditions appropriately.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 006@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                                 | Test Data                                                                                                                                                                                                                                                             | Expected Result                                                                                                                        | Notes       |
 * | :--------------: | ----------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
 * | 01               | Initialize em_cmd_steer_params_t with maximum boundary values.                                              | sta_mac = "FF:FF:FF:FF:FF:FF", source = "FF:FF:FF:FF:FF:FF", target = "FF:FF:FF:FF:FF:FF", request_mode = 4294967295, disassoc_imminent = false, btm_abridged = false, link_removal_imminent = false, steer_opportunity_win = 4294967295, btm_disassociation_timer = 4294967295, target_op_class = 4294967295, target_channel = 4294967295 | em_cmd_steer_params_t structure is initialized correctly.                                          | Should be successful |
 * | 02               | Invoke the em_cmd_sta_steer_t constructor with the initialized parameters and verify no exception is thrown. | input: em_cmd_steer_params_t params with maximum boundary values; output: object instance creation                                                              | The constructor call does not throw; instance is created successfully and passes the EXPECT_NO_THROW assertion.                         | Should Pass |
 */
TEST(em_cmd_sta_steer_t, em_cmd_sta_steer_t_valid_max_boundary_values) {
    std::cout << "Entering em_cmd_sta_steer_t_valid_max_boundary_values test" << std::endl;

    em_cmd_steer_params_t params{};

    const char* mac_ff = "FF:FF:FF:FF:FF:FF";
    memcpy(params.sta_mac, mac_ff, strlen(mac_ff) + 1);
    memcpy(params.source,  mac_ff, strlen(mac_ff) + 1);
    memcpy(params.target,  mac_ff, strlen(mac_ff) + 1);

    params.request_mode = 4294967295U;
    params.disassoc_imminent = false;
    params.btm_abridged = false;
    params.link_removal_imminent = false;
    params.steer_opportunity_win = 4294967295U;
    params.btm_disassociation_timer = 4294967295U;
    params.target_op_class = 4294967295U;
    params.target_channel = 4294967295U;

    std::cout << "Invoking em_cmd_sta_steer_t constructor with maximum boundary numeric values:" << std::endl;
    std::cout << "request_mode: " << params.request_mode << std::endl;
    std::cout << "steer_opportunity_win: " << params.steer_opportunity_win << std::endl;
    std::cout << "btm_disassociation_timer: " << params.btm_disassociation_timer << std::endl;
    std::cout << "target_op_class: " << params.target_op_class << std::endl;
    std::cout << "target_channel: " << params.target_channel << std::endl;

    EXPECT_NO_THROW({
        em_cmd_sta_steer_t obj(params);
        std::cout << "Instance created successfully." << std::endl;

	    EXPECT_EQ(obj.m_type, em_cmd_type_sta_steer);
        EXPECT_STREQ(obj.m_name, "steer_sta");
        EXPECT_EQ(obj.m_orch_op_idx, 0);
        EXPECT_EQ(obj.m_num_orch_desc, 1u);
        EXPECT_EQ(obj.m_orch_desc[0].op, dm_orch_type_sta_steer);
        EXPECT_EQ(obj.m_orch_desc[0].submit, true);

	    EXPECT_EQ(obj.m_param.u.steer_params.request_mode, 4294967295u);
        EXPECT_EQ(obj.m_param.u.steer_params.disassoc_imminent, false);
        EXPECT_EQ(obj.m_param.u.steer_params.btm_abridged, false);
        EXPECT_EQ(obj.m_param.u.steer_params.link_removal_imminent, false);
        EXPECT_EQ(obj.m_param.u.steer_params.steer_opportunity_win, 4294967295u);
        EXPECT_EQ(obj.m_param.u.steer_params.btm_disassociation_timer, 4294967295u);
        EXPECT_EQ(obj.m_param.u.steer_params.target_op_class, 4294967295u);
        EXPECT_EQ(obj.m_param.u.steer_params.target_channel, 4294967295u);
	
        obj.deinit();
    });

    std::cout << "Exiting em_cmd_sta_steer_t_valid_max_boundary_values test" << std::endl;
}
