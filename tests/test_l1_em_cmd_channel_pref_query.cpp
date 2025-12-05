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
#include "em_cmd_channel_pref_query.h"



/**
 * @brief Test the initialization of em_cmd_channel_pref_query_t with service type em_service_type_ctrl
 *
 * This test verifies that the em_cmd_channel_pref_query_t class correctly initializes its members when provided with the em_service_type_ctrl, fixed arguments ("FixedArgsCtrl"), and a dm_easy_mesh_t object. The test validates that the command type, command name, service type, fixed arguments, and orchestration descriptor are correctly set as per the expected values.
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
 * | Variation / Step | Description                                                                                     | Test Data                                                                                                                     | Expected Result                                                                                                                                   | Notes          |
 * | :--------------: | ----------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | -------------- |
 * | 01               | Initialize variables and construct em_cmd_channel_pref_query_t object with given parameters.    | service = em_service_type_ctrl, param.u.args.fixed_args = "FixedArgsCtrl", dm = default object                                | The query object is constructed successfully with the provided service type and fixed arguments.                                                 | Should Pass    |
 * | 02               | Validate command type and command name of the query object.                                     | query.m_type, query.m_name                                                                                                    | query.m_type equals em_cmd_type_channel_pref_query and query.m_name equals "channel_pref_query".                                                   | Should Pass    |
 * | 03               | Verify service type, fixed arguments and orchestration descriptor details of the query object.   | query.m_svc, query.m_param.u.args.fixed_args, query.m_num_orch_desc, query.m_orch_desc[0].op, query.m_orch_desc[0].submit         | query.m_svc equals em_service_type_ctrl; fixed args string matches "FixedArgsCtrl"; one orchestration descriptor with op equal to dm_orch_type_channel_pref and submit flag true. | Should Pass    |
 * | 04               | Call deinit method to clean up the query object.                                               | Invocation of query.deinit()                                                                                                   | deinit method executes without error.                                                                                                            | Should be successful |
 */
TEST(em_cmd_channel_pref_query_t, em_cmd_channel_pref_query_t_em_service_type_ctrl) {
    std::cout << "Entering em_cmd_channel_pref_query_t_em_service_type_ctrl test" << std::endl;
    em_service_type_t service = em_service_type_ctrl;
    em_cmd_params_t param{};
    const char *ctrlFixedArg = "FixedArgsCtrl";
    strncpy(param.u.args.fixed_args, ctrlFixedArg,
            sizeof(param.u.args.fixed_args) - 1);
    dm_easy_mesh_t dm{};
    em_cmd_channel_pref_query_t query(service, param, dm);
    std::cout << "Constructed with service type (after override): " << static_cast<int>(query.get_svc()) << std::endl;
    std::cout << "Fixed args passed: " << param.u.args.fixed_args << std::endl;
    EXPECT_EQ(query.m_type, em_cmd_type_channel_pref_query);
    EXPECT_STREQ(query.m_name, "channel_pref_query");
    EXPECT_EQ(query.m_svc, em_service_type_ctrl);
    EXPECT_STREQ(query.m_param.u.args.fixed_args, ctrlFixedArg);
    EXPECT_EQ(query.m_num_orch_desc, 1);
    EXPECT_EQ(query.m_orch_desc[0].op, dm_orch_type_channel_pref);
    EXPECT_TRUE(query.m_orch_desc[0].submit);
    query.deinit();
    std::cout << "Exiting em_cmd_channel_pref_query_t_em_service_type_ctrl test" << std::endl;
}
/**
 * @brief Verifies the construction and initialization of the em_cmd_channel_pref_query_t object using service type agent.
 *
 * This test ensures that when an em_cmd_channel_pref_query_t object is created with the em_service_type_agent,
 * the constructor correctly overrides the service type, copies the fixed arguments, and properly initializes the
 * object attributes. It validates that all expected values such as m_type, m_name, m_svc, fixed_args, number of orchestration
 * descriptors, and their properties are set as per the design specification.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 002@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                  | Test Data                                                                                                                               | Expected Result                                                                                                               | Notes         |
 * | :--------------: | ----------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ------------- |
 * | 01               | Initialize service type, command parameters, and fixed arguments              | service = em_service_type_agent, param.u.args.fixed_args = FixedArgsAgent                                                                | Variables are set correctly                                                                                                    | Should be successful |
 * | 02               | Invoke constructor of em_cmd_channel_pref_query_t with parameters             | Input: service, param, dm                                                                                                               | Instance created with service type overridden to em_service_type_ctrl                                                          | Should Pass   |
 * | 03               | Perform assertion checks on instance attributes                               | m_type = em_cmd_type_channel_pref_query, m_name = "channel_pref_query", m_svc = em_service_type_ctrl, m_param.u.args.fixed_args = FixedArgsAgent, m_num_orch_desc = 1, orch_desc[0].op = dm_orch_type_channel_pref, orch_desc[0].submit = true | All EXPECT_EQ and EXPECT_STREQ checks pass                                                                                    | Should Pass   |
 * | 04               | Call deinit to clean up the instance                                          | Calling query.deinit()                                                                                                                  | Instance deinitialized                                                                                                           | Should be successful |
 */
TEST(em_cmd_channel_pref_query_t, em_cmd_channel_pref_query_t_em_service_type_agent) {
    std::cout << "Entering em_cmd_channel_pref_query_t_em_service_type_agent test" << std::endl;
    em_service_type_t service = em_service_type_agent;
    em_cmd_params_t param{};
    const char *agentFixedArg = "FixedArgsAgent";
    strncpy(param.u.args.fixed_args, agentFixedArg,
            sizeof(param.u.args.fixed_args) - 1);
    dm_easy_mesh_t dm{};
    em_cmd_channel_pref_query_t query(service, param, dm);
    std::cout << "Constructed with service type (after override): " << query.get_svc() << std::endl;
    std::cout << "Fixed args passed: " << param.u.args.fixed_args << std::endl;
    EXPECT_EQ(query.m_type, em_cmd_type_channel_pref_query);
    EXPECT_STREQ(query.m_name, "channel_pref_query");
    EXPECT_EQ(query.m_svc, em_service_type_ctrl);
    EXPECT_STREQ(query.m_param.u.args.fixed_args, agentFixedArg);
    EXPECT_EQ(query.m_num_orch_desc, 1);
    EXPECT_EQ(query.m_orch_desc[0].op, dm_orch_type_channel_pref);
    EXPECT_TRUE(query.m_orch_desc[0].submit);
    query.deinit();
    std::cout << "Exiting em_cmd_channel_pref_query_t_em_service_type_agent test" << std::endl;
}
/**
 * @brief Verify correct initialization and parameter override for channel preference query.
 *
 * This test verifies that when a command channel preference query object is constructed using the CLI service type,
 * the input fixed arguments are correctly set and the object's internal fields are properly overridden according to the design.
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
 * | 01 | Initialize test parameters and service variable. | service = em_service_type_cli, fixed_args = FixedArgsCLI | Parameters are initialized correctly. | Should be successful |
 * | 02 | Construct the em_cmd_channel_pref_query_t object and verify its fields. | service = em_service_type_cli, param.u.args.fixed_args = FixedArgsCLI, dm = default constructed dm_easy_mesh_t | query.m_type equals em_cmd_type_channel_pref_query, query.m_name equals "channel_pref_query", query.m_svc equals em_service_type_ctrl, query.m_param.u.args.fixed_args equals FixedArgsCLI, query.m_num_orch_desc equals 1, query.m_orch_desc[0].op equals dm_orch_type_channel_pref, query.m_orch_desc[0].submit is true | Should Pass |
 * | 03 | Deinitialize the query object to clean up. | query.deinit() | Query object deinitialized without errors. | Should be successful |
 */
TEST(em_cmd_channel_pref_query_t, em_cmd_channel_pref_query_t_em_service_type_cli) {
    std::cout << "Entering em_cmd_channel_pref_query_t_em_service_type_cli test" << std::endl;
    em_service_type_t service = em_service_type_cli;
    em_cmd_params_t param{};
    const char *cliFixedArg = "FixedArgsCLI";
    strncpy(param.u.args.fixed_args, cliFixedArg,
            sizeof(param.u.args.fixed_args) - 1);
    dm_easy_mesh_t dm{};
    em_cmd_channel_pref_query_t query(service, param, dm);
    std::cout << "Constructed with service type (after override): " << query.get_svc() << std::endl;
    std::cout << "Fixed args passed: " << param.u.args.fixed_args << std::endl;
    EXPECT_EQ(query.m_type, em_cmd_type_channel_pref_query);
    EXPECT_STREQ(query.m_name, "channel_pref_query");
    EXPECT_EQ(query.m_svc, em_service_type_ctrl);
    EXPECT_STREQ(query.m_param.u.args.fixed_args, cliFixedArg);
    EXPECT_EQ(query.m_num_orch_desc, 1);
    EXPECT_EQ(query.m_orch_desc[0].op, dm_orch_type_channel_pref);
    EXPECT_TRUE(query.m_orch_desc[0].submit);
    query.deinit();
    std::cout << "Exiting em_cmd_channel_pref_query_t_em_service_type_cli test" << std::endl;
}
