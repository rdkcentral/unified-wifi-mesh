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
#include "em_cmd_dev_init.h"



/**
 * @brief Verify valid initialization of em_cmd_dev_init_t object with valid parameters
 *
 * This test verifies that the em_cmd_dev_init_t object is initialized correctly when provided with valid input parameters.
 * The test sets up a parameter structure with a fixed argument, creates a dm_easy_mesh_t object, invokes the constructor of em_cmd_dev_init_t,
 * and then validates that the object's attributes are correctly assigned. This ensures that the initialization logic is functioning as expected.
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
 * | Variation / Step | Description                                                                                      | Test Data                                                                                                                              | Expected Result                                                                                                                                                                   | Notes          |
 * | :--------------: | ------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------- |
 * | 01               | Initialize em_cmd_params_t and copy "TestFixedArg" to fixed_args                                | input: testFixedArg = "TestFixedArg", param = em_cmd_params_t instance                                                                | Parameter structure (param) is initialized with fixed_args set to "TestFixedArg"                                                                                                  | Should be successful |
 * | 02               | Create dm_easy_mesh_t object                                                                     | dm: new dm_easy_mesh_t instance                                                                                                        | dm_easy_mesh_t object is created successfully with a valid memory address                                                                                                          | Should be successful |
 * | 03               | Invoke the em_cmd_dev_init_t constructor using param and dm                                     | input: param (with fixed_args = "TestFixedArg"), dm (dm_easy_mesh_t instance)                                                            | em_cmd_dev_init_t object (instance) is constructed successfully                                                                                                                  | Should Pass    |
 * | 04               | Assert that the instance fields are correctly set                                               | expected: m_type = em_cmd_type_dev_init, m_name = "dev_init", fixed_args = "TestFixedArg", m_num_orch_desc = 2, m_orch_desc[0].op = dm_orch_type_al_insert, m_orch_desc[0].submit = false, m_svc = em_service_type_agent | All ASSERT checks pass verifying that the object fields are initialized with the expected values                                                                                       | Should Pass    |
 * | 05               | Invoke the deinit method on the instance                                                        | input: instance.deinit()                                                                                                               | The deinit method executes successfully without errors                                                                                                                         | Should be successful |
 */
TEST(em_cmd_dev_init_t, em_cmd_dev_init_t_valid_initialization) {
    std::cout << "Entering em_cmd_dev_init_t_valid_initialization test" << std::endl;
    em_cmd_params_t param{};
    const char *testFixedArg = "TestFixedArg";
    strncpy(param.u.args.fixed_args, testFixedArg,
            sizeof(param.u.args.fixed_args) - 1);
    param.u.args.fixed_args[sizeof(param.u.args.fixed_args) - 1] = '\0';
    std::cout << "Parameter fixed_args set to: " << param.u.args.fixed_args << std::endl;
    dm_easy_mesh_t dm{};
    std::cout << "dm_easy_mesh_t object created at address: " << &dm << std::endl;
    std::cout << "Invoking em_cmd_dev_init_t constructor with parameter and dm object." << std::endl;
    em_cmd_dev_init_t instance(param, dm);
    std::cout << "em_cmd_dev_init_t constructor invoked successfully." << std::endl;
    EXPECT_EQ(instance.m_type, em_cmd_type_dev_init);
    EXPECT_STREQ(instance.m_name, "dev_init");
    EXPECT_STREQ(instance.m_param.u.args.fixed_args, testFixedArg);
    EXPECT_EQ(instance.m_num_orch_desc, 2);
    EXPECT_EQ(instance.m_orch_desc[0].op, dm_orch_type_al_insert);
    EXPECT_FALSE(instance.m_orch_desc[0].submit);
    EXPECT_EQ(instance.m_svc, em_service_type_agent);
    instance.deinit();
    std::cout << "Exiting em_cmd_dev_init_t_valid_initialization test" << std::endl;
}
/**
 * @brief Test to verify the default initialization values of em_cmd_dev_init_t when provided with empty parameters
 *
 * This test case verifies that when em_cmd_dev_init_t is constructed with empty parameters, all members are properly initialized to their expected default values. It checks the type, name, fixed arguments, number of orchestration descriptors, individual orchestration descriptor values, and the service type.
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
 * | Variation / Step | Description                                                                      | Test Data                                                                                                                                                                  | Expected Result                                                                                                                                                                                                                                                             | Notes      |
 * | :--------------: | -------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
 * | 01               | Invoke em_cmd_dev_init_t constructor with empty parameters and validate member initializations | input param = {} , input dm = {}, output m_type = em_cmd_type_dev_init, output m_name = dev_init, output fixed_args = "", output num_orch_desc = 2, output orch_desc[0].op = dm_orch_type_al_insert, output orch_desc[0].submit = false, output svc = em_service_type_agent | instance.m_type equals em_cmd_type_dev_init, instance.m_name equals "dev_init", instance.m_param.u.args.fixed_args equals "", instance.m_num_orch_desc equals 2, instance.m_orch_desc[0].op equals dm_orch_type_al_insert, instance.m_orch_desc[0].submit equals false, instance.m_svc equals em_service_type_agent | Should Pass |
 */
TEST(em_cmd_dev_init_t, em_cmd_dev_init_t_empty_params) {
    std::cout << "Entering em_cmd_dev_init_t_empty_params test" << std::endl;
    em_cmd_params_t param{};
    dm_easy_mesh_t dm{};
    std::cout << "Invoking em_cmd_dev_init_t with empty params..." << std::endl;
    em_cmd_dev_init_t instance(param, dm);
    EXPECT_EQ(instance.m_type, em_cmd_type_dev_init);
    EXPECT_STREQ(instance.m_name, "dev_init");
    EXPECT_STREQ(instance.m_param.u.args.fixed_args, "");
    EXPECT_EQ(instance.m_num_orch_desc, 2);
    EXPECT_EQ(instance.m_orch_desc[0].op, dm_orch_type_al_insert);
    EXPECT_FALSE(instance.m_orch_desc[0].submit);
    EXPECT_EQ(instance.m_svc, em_service_type_agent);
    instance.deinit();
    std::cout << "Exiting em_cmd_dev_init_t_empty_params test" << std::endl;
}
/**
 * @brief Verify device initialization with maximum boundary fixed argument length.
 *
 * This test verifies that the em_cmd_dev_init_t constructor correctly handles the maximum allowed length for fixed_args in the parameter structure.
 * The test constructs a string of maximum size (fixedSize - 1) to populate the fixed_args field, invokes the constructor, and then validates that all member fields are
 * set as expected. This ensures proper boundary checking and string termination in the API.
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
 * | 01 | Calculate fixed arguments buffer size and create a maximum boundary string | fixedSize = sizeof(static_cast<em_cmd_args_t*>(nullptr)->fixed_args), maxFixed = string('X', fixedSize - 1) | Buffer size correctly determined and maxFixed string created with (fixedSize - 1) 'X' characters | Should be successful |
 * | 02 | Populate the parameter structure with the maximum boundary fixed_args | param.u.args.fixed_args set using strncpy with maxFixed; ensuring null termination | The fixed_args field in param holds the maxFixed string with proper null termination | Should be successful |
 * | 03 | Invoke the em_cmd_dev_init_t constructor with the prepared parameters and dummy dm object | Input: param (with fixed_args), dm (instance of dm_easy_mesh_t) | Instance created where: m_type == em_cmd_type_dev_init, m_name equals "dev_init", fixed_args equal to maxFixed, m_num_orch_desc == 2, orch_desc[0].op equals dm_orch_type_al_insert, orch_desc[0].submit is false, and m_svc equals em_service_type_agent | Should Pass |
 * | 04 | Call the deinit method on the created instance | instance.deinit() | Instance deinitialized and resources released properly | Should be successful |
 */
TEST(em_cmd_dev_init_t, em_cmd_dev_init_t_max_boundary) {
    std::cout << "Entering em_cmd_dev_init_t_max_boundary test" << std::endl;
    const size_t fixedSize =
        sizeof(static_cast<em_cmd_args_t*>(nullptr)->fixed_args);
    std::string maxFixed(fixedSize - 1, 'X');
    em_cmd_params_t param{};
    std::cout << "Setting max-length fixed_args (" << maxFixed.size() << " chars)" << std::endl;
    strncpy(param.u.args.fixed_args, maxFixed.c_str(), fixedSize - 1);
    param.u.args.fixed_args[fixedSize - 1] = '\0';
    dm_easy_mesh_t dm{};
    std::cout << "Invoking constructor..." << std::endl;
    em_cmd_dev_init_t instance(param, dm);
    EXPECT_EQ(instance.m_type, em_cmd_type_dev_init);
    EXPECT_STREQ(instance.m_name, "dev_init");
    EXPECT_STREQ(instance.m_param.u.args.fixed_args, maxFixed.c_str());
    EXPECT_EQ(instance.m_num_orch_desc, 2);
    EXPECT_EQ(instance.m_orch_desc[0].op, dm_orch_type_al_insert);
    EXPECT_FALSE(instance.m_orch_desc[0].submit);
    EXPECT_EQ(instance.m_svc, em_service_type_agent);
    instance.deinit();
    std::cout << "Exiting em_cmd_dev_init_t_max_boundary test" << std::endl;
}
