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
#include "em_cmd_sta_disassoc.h"

static void parse_mac(const char *str, mac_address_t &mac)
{
    unsigned int bytes[6];
    sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
           &bytes[0], &bytes[1], &bytes[2],
           &bytes[3], &bytes[4], &bytes[5]);
    for (int i = 0; i < 6; i++)
        mac[i] = static_cast<uint8_t>(bytes[i]);
}

/**
 * @brief Verify that em_cmd_sta_disassoc_t correctly processes disassociation for one valid station
 *
 * This test verifies that the em_cmd_sta_disassoc_t API correctly processes a disassociation command for a single valid station.
 * It constructs the disassociation parameters with one station MAC address, invokes the API, and validates that the internal parameters are set correctly.
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
 * | Variation / Step | Description                                                                      | Test Data                                                                                   | Expected Result                                                                                                    | Notes      |
 * | :--------------: | -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | ---------- |
 * | 01               | Invoke em_cmd_sta_disassoc_t with one valid station MAC for disassociation        | params.num = 1, macStr = "00:11:22:33:44:55", expectedMac = parsed value from macStr          | API sets m_param.u.disassoc_params.num to 1 and memcmp returns 0 indicating the MAC addresses match                 | Should Pass|
 */
TEST(em_cmd_sta_disassoc_t, em_cmd_sta_disassoc_t_valid_disassoc_one_station)
{
    std::cout << "Entering em_cmd_sta_disassoc_t_valid_disassoc_one_station test" << std::endl;
    em_cmd_disassoc_params_t params {};
    params.num = 1;
    const char *macStr = "00:11:22:33:44:55";
    mac_address_t expectedMac;
    parse_mac(macStr, expectedMac);
    memcpy(params.params[0].sta_mac, expectedMac, sizeof(mac_address_t));
    em_cmd_sta_disassoc_t cmd(params);
    EXPECT_EQ(cmd.m_param.u.disassoc_params.num, 1u);
    EXPECT_EQ(memcmp(cmd.m_param.u.disassoc_params.params[0].sta_mac, expectedMac, sizeof(mac_address_t)),0);
    cmd.deinit();
    std::cout << "Exiting em_cmd_sta_disassoc_t_valid_disassoc_one_station test" << std::endl;
}
/**
 * @brief Validates multiple station disassociation functionality.
 *
 * This test verifies that the em_cmd_sta_disassoc_t API correctly handles disassociation requests for multiple stations by ensuring that the provided MAC addresses are accurately set in the disassociation parameters and that the number of stations is correctly processed.
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
 * | Variation / Step | Description                                                                       | Test Data                                                                                                              | Expected Result                                                         | Notes       |
 * | :--------------: | --------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- | ----------- |
 * | 01               | Initialize disassociation parameters with three valid station MAC addresses       | params.num = 3, macs[0] = "00:11:22:33:44:01", macs[1] = "00:11:22:33:44:02", macs[2] = "00:11:22:33:44:03"             | Disassociation parameters are set with number = 3                      | Should Pass |
 * | 02               | Validate that each MAC address is correctly assigned in the command parameters      | expected[i] computed from parse_mac, cmd.m_param.u.disassoc_params.params[i].sta_mac compared using memcmp                | memcmp returns 0 for each index confirming MAC addresses are correctly stored | Should Pass |
 * | 03               | Invoke deinit on the command to release any allocated resources                   | cmd.deinit()                                                                                                           | Resources are deinitialized without error                               | Should Pass |
 */
TEST(em_cmd_sta_disassoc_t, em_cmd_sta_disassoc_t_valid_disassoc_multiple_stations)
{
    std::cout << "Entering em_cmd_sta_disassoc_t_valid_disassoc_multiple_stations test" << std::endl;
    em_cmd_disassoc_params_t params {};
    params.num = 3;
    const char *macs[] = {
        "00:11:22:33:44:01",
        "00:11:22:33:44:02",
        "00:11:22:33:44:03"
    };
    mac_address_t expected[3];
    for (size_t i = 0; i < 3; i++) {
        parse_mac(macs[i], expected[i]);
        memcpy(params.params[i].sta_mac, expected[i], sizeof(mac_address_t));
    }
    em_cmd_sta_disassoc_t cmd(params);
    EXPECT_EQ(cmd.m_param.u.disassoc_params.num, 3u);

    for (size_t i = 0; i < 3; i++) {
        EXPECT_EQ(memcmp(cmd.m_param.u.disassoc_params.params[i].sta_mac, expected[i], sizeof(mac_address_t)), 0) << "MAC mismatch at index " << i;
    }
    cmd.deinit();
    std::cout << "Exiting em_cmd_sta_disassoc_t_valid_disassoc_multiple_stations test" << std::endl;
}
/**
 * @brief Validate that the command correctly handles zero station disassociation.
 *
 * This test verifies that when the number of stations is set to zero, the
 * em_cmd_sta_disassoc_t object initializes correctly with the num field equal to 0.
 * It ensures that the constructor properly sets up the internal parameter and that
 * the deinitialization function operates without error.
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
 * | 01 | Create and initialize disassociation parameters with zero stations | input: num = 0 | em_cmd_disassoc_params_t object is created with num set to 0 | Should Pass |
 * | 02 | Instantiate em_cmd_sta_disassoc_t using the initialized parameters and verify the parameter | input: params.num = 0, output: cmd.m_param.u.disassoc_params.num | EXPECT_EQ(cmd.m_param.u.disassoc_params.num, 0u) passes | Should Pass |
 * | 03 | Call deinit on the command object to cleanup | operation: cmd.deinit() | deinit completes without error | Should be successful |
 */
TEST(em_cmd_sta_disassoc_t, em_cmd_sta_disassoc_t_zero_stations)
{
    std::cout << "Entering em_cmd_sta_disassoc_t_zero_stations test" << std::endl;
    em_cmd_disassoc_params_t params {};
    params.num = 0;
    em_cmd_sta_disassoc_t cmd(params);
    EXPECT_EQ(cmd.m_param.u.disassoc_params.num, 0u);
    cmd.deinit();
    std::cout << "Exiting em_cmd_sta_disassoc_t_zero_stations test" << std::endl;
}
/**
 * @brief Test the maximum station disassociation in em_cmd_sta_disassoc_t.
 *
 * This test verifies that the em_cmd_sta_disassoc_t class correctly initializes and handles the maximum number of disassociation parameters. It ensures that the number of stations is set to MAX_STA_TO_DISASSOC and that each station's MAC address is properly assigned and verified against the expected values. This is critical for confirming correct handling of boundary conditions for station disassociation.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 004
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | --------------------------- |-------------- | ----- |
 * | 01 | Initialize parameters and expected MAC addresses for maximum stations | params.num = MAX_STA_TO_DISASSOC, MAC addresses generated using "00:11:22:33:44:%02zu" format | Expected MAC addresses array is correctly populated | Should be successful |
 * | 02 | Instantiate em_cmd_sta_disassoc_t and verify station count | Input: em_cmd_sta_disassoc_t with disassoc_params containing max station count | m_param.u.disassoc_params.num equals MAX_STA_TO_DISASSOC | Should Pass |
 * | 03 | Verify each station MAC address stored in the command object | Input: Expected MAC array and object's MAC addresses | Each memcmp returns 0 (pass signature) | Should Pass |
 * | 04 | Deinitialize the command object | Call cmd.deinit() | Command object deinitializes without error | Should be successful |
 */
TEST(em_cmd_sta_disassoc_t, em_cmd_sta_disassoc_t_max_stations)
{
    std::cout << "Entering em_cmd_sta_disassoc_t_max_stations test" << std::endl;
    em_cmd_disassoc_params_t params {};
    params.num = MAX_STA_TO_DISASSOC;
    mac_address_t expected[MAX_STA_TO_DISASSOC];
    for (size_t i = 0; i < MAX_STA_TO_DISASSOC; i++) {
        char macStr[32];
        snprintf(macStr, sizeof(macStr), "00:11:22:33:44:%02zu", i);
        parse_mac(macStr, expected[i]);
        memcpy(params.params[i].sta_mac, expected[i], sizeof(mac_address_t));
    }
    em_cmd_sta_disassoc_t cmd(params);
    EXPECT_EQ(cmd.m_param.u.disassoc_params.num, MAX_STA_TO_DISASSOC);
    for (size_t i = 0; i < MAX_STA_TO_DISASSOC; i++) {
        EXPECT_EQ(memcmp(cmd.m_param.u.disassoc_params.params[i].sta_mac, expected[i], sizeof(mac_address_t)), 0) << "MAC mismatch at index " << i;
    }
    cmd.deinit();
    std::cout << "Exiting em_cmd_sta_disassoc_t_max_stations test" << std::endl;
}
/**
 * @brief Validate proper initialization of em_cmd_sta_disassoc_t object
 *
 * This test verifies that the em_cmd_sta_disassoc_t object is correctly initialized using the provided em_cmd_disassoc_params_t.
 * It checks that the operational index, number of descriptors, descriptor operation type, and submission flag are all set to their expected default values.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 005@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                           | Test Data                                                                                                                 | Expected Result                                                                          | Notes       |
 * | :--------------: | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ----------- |
 * | 01               | Initialize em_cmd_sta_disassoc_t with parameter num = 1 and verify that all orch_desc fields are set as expected | input: params.num = 1, output: m_orch_op_idx = 0, m_num_orch_desc = 1, m_orch_desc[0].op = dm_orch_type_sta_disassoc, m_orch_desc[0].submit = true | The object is initialized with the correct default operational index and descriptor values; assertions pass | Should Pass |
 */
TEST(em_cmd_sta_disassoc_t, em_cmd_sta_disassoc_t_orch_desc_initialization)
{
    std::cout << "Entering em_cmd_sta_disassoc_t_orch_desc_initialization test" << std::endl;
    em_cmd_disassoc_params_t params {};
    params.num = 1;
    em_cmd_sta_disassoc_t cmd(params);
    EXPECT_EQ(cmd.m_orch_op_idx, 0u);
    EXPECT_EQ(cmd.m_num_orch_desc, 1u);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_sta_disassoc);
    EXPECT_TRUE(cmd.m_orch_desc[0].submit);
    cmd.deinit();
    std::cout << "Exiting em_cmd_sta_disassoc_t_orch_desc_initialization test" << std::endl;
}
/**
 * @brief Verify that em_cmd_sta_disassoc_t sets the command name correctly
 *
 * This test verifies that when an instance of em_cmd_sta_disassoc_t is created with valid parameters, 
 * the command name (m_name) is set to "disassoc_sta". This ensures that the object initializes its internal 
 * state as expected. The test confirms the proper functioning of the constructor and deinitialization method.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Initialize the disassociation parameters, create the command object, and verify the command name | input: params.num = 1, output: cmd.m_name, expected: "disassoc_sta" | cmd.m_name should equal "disassoc_sta" as verified by EXPECT_STREQ | Should Pass |
 */
TEST(em_cmd_sta_disassoc_t, em_cmd_sta_disassoc_t_name_set)
{
    std::cout << "Entering em_cmd_sta_disassoc_t_name_set test" << std::endl;
    em_cmd_disassoc_params_t params {};
    params.num = 1;
    em_cmd_sta_disassoc_t cmd(params);
    EXPECT_STREQ(cmd.m_name, "disassoc_sta");
    cmd.deinit();
    std::cout << "Exiting em_cmd_sta_disassoc_t_name_set test" << std::endl;
}
/**
 * @brief Verify correct service type initialization in em_cmd_sta_disassoc_t test
 *
 * This test verifies that the em_cmd_sta_disassoc_t object is instantiated with the correct service type.
 * It initializes the disassociation parameters, creates an instance of em_cmd_sta_disassoc_t, and checks if the member m_svc
 * is set to em_service_type_agent. Finally, deinitialization is performed to ensure proper cleanup of the object.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 007@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                  | Test Data                                        | Expected Result                                                        | Notes       |
 * | :--------------: | -------------------------------------------------------------------------------------------- | ------------------------------------------------ | ---------------------------------------------------------------------- | ----------- |
 * | 01               | Initialize disassociation parameters, create em_cmd_sta_disassoc_t instance, and verify m_svc  | params.num = 1, expected m_svc = em_service_type_agent | cmd.m_svc equals em_service_type_agent and deinit is successfully invoked | Should Pass |
 */
TEST(em_cmd_sta_disassoc_t, em_cmd_sta_disassoc_t_service_type)
{
    std::cout << "Entering em_cmd_sta_disassoc_t_service_type test" << std::endl;
    em_cmd_disassoc_params_t params {};
    params.num = 1;
    em_cmd_sta_disassoc_t cmd(params);
    EXPECT_EQ(cmd.m_svc, em_service_type_agent);
    cmd.deinit();
    std::cout << "Exiting em_cmd_sta_disassoc_t_service_type test" << std::endl;
}
