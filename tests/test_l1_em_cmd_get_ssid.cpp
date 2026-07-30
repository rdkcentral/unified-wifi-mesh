
/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2025 RDK Management
 *
g* Licensed under the Apache License, Version 2.0 (the "License");
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
#include "em_cmd_get_ssid.h"

/**
 * @brief Verify valid parameters for em_cmd_get_ssid_t test
 *
 * This test validates that the em_cmd_get_ssid_t API properly handles valid SSID parameters by initializing the parameters,
 * invoking the constructor, and verifying that the configured SSID matches the expected "TestSSID".
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
 * | Variation / Step | Description                                                                                         | Test Data                                                                                           | Expected Result                                                    | Notes      |
 * | :--------------: | --------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ | ---------- |
 * |01| Initialize the test parameters, copy "TestSSID" into the command parameters, create a dm_easy_mesh_t instance, invoke the em_cmd_get_ssid_t constructor, and verify that the fixed_args matches "TestSSID". | param.u.args.fixed_args = "TestSSID", dm = default instance, output: cmd.m_param.u.args.fixed_args expected = "TestSSID" | The output SSID string should exactly match "TestSSID" and the EXPECT_STREQ assertion should pass | Should Pass |
 */
TEST(em_cmd_get_ssid_t, em_cmd_get_ssid_t_valid_parameters)
{
    std::cout << "Entering em_cmd_get_ssid_t_valid_parameters test" << std::endl;
    em_cmd_params_t param;
    const char* testSsid = "TestSSID";
    strncpy(param.u.args.fixed_args, testSsid, sizeof(param.u.args.fixed_args));
    dm_easy_mesh_t dm;
    em_cmd_get_ssid_t cmd(param, dm);
    EXPECT_STREQ("TestSSID", cmd.m_param.u.args.fixed_args);
    cmd.deinit();
    std::cout << "Exiting em_cmd_get_ssid_t_valid_parameters test" << std::endl;
}
/**
 * @brief Test to verify that em_cmd_get_ssid_t correctly handles an empty string input for fixed_args.
 *
 * This test verifies that when an empty string is provided in the fixed_args field of em_cmd_params_t,
 * the em_cmd_get_ssid_t API processes the input correctly and stores an empty string in the resulting object.
 *
 * **Test Group ID:** Basic: 01 / Module (L2): 02 / Stress (L2): 03
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
 * |01| Initialize test by setting fixed_args to an empty string in the em_cmd_params_t object and creating an em_cmd_get_ssid_t instance. | param.u.args.fixed_args = "" | The em_cmd_get_ssid_t object should store an empty string in m_param.u.args.fixed_args. | Should Pass |
 * |02| Call the deinit() method on the em_cmd_get_ssid_t instance to clean up resources. | N/A | Resources freed without error. | Should be successful |
 */
TEST(em_cmd_get_ssid_t, em_cmd_get_ssid_t_empty_string)
{
    std::cout << "Entering em_cmd_get_ssid_t_empty_string test" << std::endl;
    em_cmd_params_t param;
    strncpy(param.u.args.fixed_args, "", sizeof(param.u.args.fixed_args));
    dm_easy_mesh_t dm;
    em_cmd_get_ssid_t cmd(param, dm);
    EXPECT_STREQ("", cmd.m_param.u.args.fixed_args);
    cmd.deinit();
    std::cout << "Exiting em_cmd_get_ssid_t_empty_string test" << std::endl;
}
/**
 * @brief To verify that the em_cmd_get_ssid_t command handles maximum length SSID correctly
 *
 * This test verifies that when a maximum length SSID string (127 characters) is provided,
 * the command properly copies it into its parameter structure without truncation or errors.
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
 * | 01 | Initialize a maximum length SSID by filling a char array with 127 'A's, copy it into the command parameters, invoke the command constructor, and verify the SSID field using EXPECT_STREQ. | input: fixed_args = 127 'A's, longSsid = 127 'A's; output: m_param.u.args.fixed_args should be identical to longSsid | The API should correctly copy the maximum length SSID so that EXPECT_STREQ compares equal | Should Pass |
 */
TEST(em_cmd_get_ssid_t, em_cmd_get_ssid_t_max_length)
{
    std::cout << "Entering em_cmd_get_ssid_t_max_length test" << std::endl;
    char longSsid[128];
    memset(longSsid, 'A', 127);
    longSsid[127] = '\0';
    em_cmd_params_t param;
    strncpy(param.u.args.fixed_args, longSsid, sizeof(param.u.args.fixed_args));
    dm_easy_mesh_t dm;
    em_cmd_get_ssid_t cmd(param, dm);
    EXPECT_STREQ(longSsid, cmd.m_param.u.args.fixed_args);
    cmd.deinit();
    std::cout << "Exiting em_cmd_get_ssid_t_max_length test" << std::endl;
}
