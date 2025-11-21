
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
#include "em_cmd_client_cap.h"


// Test case 1: Valid client capability report.
/**
 * @brief Validates the em_cmd_client_cap_report_t constructor using valid client capability details
 *
 * This test verifies that the em_cmd_client_cap_report_t object is correctly instantiated with valid parameters.
 * It checks that the fixed_args field is properly initialized to "ValidClientCap" after constructing the object,
 * ensuring that the constructor correctly processes the provided client capability information.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize and populate em_cmd_params_t with valid client capability details | fixed_args = "ValidClientCap", num_args = 3, args[0] = "Arg1", args[1] = "Arg2", args[2] = "Arg3" | em_cmd_params_t structure is correctly populated with client capability data | Should be successful |
 * | 02 | Create dm_easy_mesh_t instance and retrieve initial network id | Call dm.get_network_id() | dm_easy_mesh_t instance is created; network id is retrieved (could be empty) | Should be successful |
 * | 03 | Invoke em_cmd_client_cap_report_t constructor with test parameters | Construct em_cmd_client_cap_report_t using the populated param and dm instance | em_cmd_client_cap_report_t object is successfully instantiated | Should be successful |
 * | 04 | Retrieve fixed_args from the constructed object and verify its value | Retrieve fixedArgs = clientCapReport.get_param()->u.args.fixed_args | fixedArgs equals "ValidClientCap" as verified by EXPECT_STREQ | Should Pass |
 */
TEST(em_cmd_client_cap_report_t, em_cmd_client_cap_report_t_valid_client_cap_report) {
    std::cout << "Entering em_cmd_client_cap_report_t_valid_client_cap_report test" << std::endl;

    em_cmd_params_t param = {};
    strncpy(param.u.args.fixed_args, "ValidClientCap", sizeof(param.u.args.fixed_args));
    param.u.args.num_args = 3;
    strncpy(param.u.args.args[0], "Arg1", sizeof(param.u.args.args[0]));
    strncpy(param.u.args.args[1], "Arg2", sizeof(param.u.args.args[1]));
    strncpy(param.u.args.args[2], "Arg3", sizeof(param.u.args.args[2]));

    dm_easy_mesh_t dm{};
    char* netIdBefore = dm.m_network.m_net_info.id;
    std::cout << "Pre-construction dm network SSID: "
              << (netIdBefore ? netIdBefore : "empty") << std::endl;

    em_cmd_client_cap_report_t clientCapReport(param, dm);
    std::cout << "Called em_cmd_client_cap_report_t constructor." << std::endl;

    const char *fixedArgs = clientCapReport.get_param()->u.args.fixed_args;
    std::cout << "Client capability fixed_args value: " << fixedArgs << std::endl;

    EXPECT_STREQ(fixedArgs, "ValidClientCap");

    std::cout << "Exiting em_cmd_client_cap_report_t_valid_client_cap_report test" << std::endl;
}

/**
 * @brief Tests the minimal instantiation of em_cmd_client_cap_report_t using default parameters.
 *
 * This test validates that the em_cmd_client_cap_report_t object can be correctly constructed with minimal (default/empty) parameter values.
 * The test ensures that the num_args field remains 0 and that fixed_args is an empty string after object initialization.
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
 * | 01 | Initialize minimal em_cmd_params_t and dm_easy_mesh_t instances, then create an em_cmd_client_cap_report_t object using these parameters. Retrieve the fixed_args field and perform assertion checks. | param: {u.args.num_args = 0, u.args.fixed_args = ""}, dm: default-initialized instance, clientCapReport: object created from param and dm | The fixed_args field is an empty string and num_args remains 0; assertion checks pass. | Should Pass |
 */
TEST(em_cmd_client_cap_report_t, em_cmd_client_cap_report_t_minimal_client_cap_report) {
    std::cout << "Entering em_cmd_client_cap_report_t_minimal_client_cap_report test" << std::endl;
    
    // Create an em_cmd_params_t instance with minimal (default/empty) values.
    em_cmd_params_t param = {};
    // Keep num_args zero and ensure fixed_args is empty.
    param.u.args.num_args = 0;
    param.u.args.fixed_args[0] = '\0';
    
    // Create a dm_easy_mesh_t instance using the default constructor.
    dm_easy_mesh_t dm{};
    dm.m_network.m_net_info.id[0] = '\0';
			
    
    // Invoke the constructor for em_cmd_client_cap_report_t using the minimal parameters.
    em_cmd_client_cap_report_t clientCapReport(param, dm);
    std::cout << "Called em_cmd_client_cap_report_t constructor with minimal parameters." << std::endl;
    
    // Retrieve and log the fixed_args field.
    const char *fixedArgs = clientCapReport.get_param()->u.args.fixed_args;
    std::cout << "Client capability fixed_args value (expected empty): \"" 
              << fixedArgs << "\"" << std::endl;
    
    // Validate that num_args remains 0 and fixed_args is an empty string.
    EXPECT_EQ(clientCapReport.get_param()->u.args.num_args, 0);
    EXPECT_STREQ(fixedArgs, "");
    
    std::cout << "Exiting em_cmd_client_cap_report_t_minimal_client_cap_report test" << std::endl;
}

