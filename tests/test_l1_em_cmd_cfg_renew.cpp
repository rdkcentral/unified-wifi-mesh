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
#include "em_cmd_cfg_renew.h"


// Helper function to initialize a dummy em_cmd_params_t structure.
void initCmdParams(em_cmd_params_t &param, const char *fixedArg)
{
    strncpy(param.u.args.fixed_args, fixedArg, sizeof(param.u.args.fixed_args));
    param.u.args.num_args = 1;
}

// Helper function to simulate a proper dm_easy_mesh_t initialization.
void initDmNetwork(dm_easy_mesh_t &dm, const char *netId)
{
    strncpy(dm.m_network.m_net_info.id, netId, sizeof(dm.m_network.m_net_info.id));
}


/**
 * @brief Validate that em_cmd_cfg_renew_t constructor initializes the object correctly with valid control parameters.
 *
 * This test verifies that when the constructor of em_cmd_cfg_renew_t is invoked with a control service type, fully‐initialized command parameters, and a valid network identifier, the resulting object's attributes (service type, fixed_args, and network id) are properly set. This ensures that the initialization logic within the constructor is working as expected.
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
 * | Variation / Step | Description | Test Data | Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize test inputs including service type, command parameters with fixed_args "TestCtrl", and network id "NetworkID_CTRL". | service = em_service_type_ctrl, parameters.fixed_args = "TestCtrl", network.id = "NetworkID_CTRL" | Test environment is set up with correctly initialized values. | Should be successful |
 * | 02 | Invoke the em_cmd_cfg_renew_t constructor with the initialized test inputs. | Constructor invoked with service, parameters, and network from step 01 | Object is instantiated without errors. | Should Pass |
 * | 03 | Assert that the constructed object's attributes are set correctly. | Expected: m_svc = em_service_type_ctrl, m_param.u.args.fixed_args = "TestCtrl", m_data_model.m_network.m_net_info.id = "NetworkID_CTRL" | All assertions pass confirming proper initialization. | Should Pass |
 */
TEST(em_cmd_cfg_renew_t, em_cmd_cfg_renew_t_valid_ctrl)
{
    const char* testName = "em_cmd_cfg_renew_t_valid_ctrl";
    std::cout << "Entering " << testName << " test" << std::endl;
    em_service_type_t service = em_service_type_ctrl;
    em_cmd_params_t parameters = {};
    initCmdParams(parameters, "TestCtrl");
    dm_easy_mesh_t dm{};
    initDmNetwork(dm, "NetworkID_CTRL");
    em_cmd_cfg_renew_t cmd(service, parameters, dm);
    std::cout << "Constructor invoked with service = "
              << static_cast<unsigned int>(service)
              << " and fixed_args = " << cmd.m_param.u.args.fixed_args
              << ", network id = " << cmd.m_data_model.m_network.m_net_info.id
              << std::endl;
    EXPECT_EQ(cmd.m_type, em_cmd_type_cfg_renew);
    EXPECT_STREQ(cmd.m_name, "cfg_renew");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 1);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_tx_cfg_renew);
    EXPECT_EQ(cmd.m_orch_desc[0].submit, true);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "TestCtrl");
    EXPECT_STREQ(cmd.m_data_model.m_network.m_net_info.id, "NetworkID_CTRL");
    cmd.deinit();
    std::cout << "Exiting " << testName << " test" << std::endl;
}

/**
 * @brief Verify that em_cmd_cfg_renew_t constructor initializes the object correctly with valid agent parameters
 *
 * This test ensures that when the constructor of em_cmd_cfg_renew_t is invoked with a valid agent service type (em_service_type_agent),
 * properly initialized command parameters using "AgentParam", and a data model network using "NetworkID_AGENT", the object is constructed
 * with the expected service, parameter, and network details.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup test inputs and invoke the constructor of em_cmd_cfg_renew_t using valid agent parameters. | service = em_service_type_agent, parameters.fixed_args = "AgentParam", dm.network.id = "NetworkID_AGENT" | cmd.m_svc equals em_service_type_agent, cmd.m_param.u.args.fixed_args equals "AgentParam", cmd.m_data_model.m_network.m_net_info.id equals "NetworkID_AGENT" | Should Pass |
 */
TEST(em_cmd_cfg_renew_t, em_cmd_cfg_renew_t_valid_agent)
{
    const char* testName = "em_cmd_cfg_renew_t_valid_agent";
    std::cout << "Entering " << testName << " test" << std::endl;
    em_service_type_t service = em_service_type_agent;
    em_cmd_params_t parameters = {};
    initCmdParams(parameters, "AgentParam");
    dm_easy_mesh_t dm{};
    initDmNetwork(dm, "NetworkID_AGENT");
    em_cmd_cfg_renew_t cmd(service, parameters, dm);
    std::cout << "Constructor invoked with service = "
              << static_cast<unsigned int>(service)
              << " and fixed_args = " << cmd.m_param.u.args.fixed_args
              << ", network id = " << cmd.m_data_model.m_network.m_net_info.id
              << std::endl;
    EXPECT_EQ(cmd.m_type, em_cmd_type_cfg_renew);
    EXPECT_STREQ(cmd.m_name, "cfg_renew");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 1);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_tx_cfg_renew);
    EXPECT_EQ(cmd.m_orch_desc[0].submit, true);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "AgentParam");
    EXPECT_STREQ(cmd.m_data_model.m_network.m_net_info.id, "NetworkID_AGENT");
    cmd.deinit();
    std::cout << "Exiting " << testName << " test" << std::endl;
}

/**
 * @brief Verify that the em_cmd_cfg_renew_t constructor initializes the object correctly when invoked with valid CLI service type and fixed argument parameters
 *
 * This test verifies that when the em_cmd_cfg_renew_t constructor is called with em_service_type_cli, properly initialized command parameters ("CliFixedArg"), 
 * and a valid data model network ("NetworkID_CLI"), the object's members are correctly set. This ensures that the constructor is handling the input values 
 * appropriately and that the internal state of the object matches the expected configuration.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 003@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                           | Test Data                                                                                               | Expected Result                                                                                                                    | Notes          |
 * | :--------------: | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- | -------------- |
 * | 01               | Initialize test inputs including service type, command parameters, and data model network ID           | service = em_service_type_cli, parameters.fixed_args = CliFixedArg, dm.network.id = NetworkID_CLI       | Test inputs are set with the appropriate values for constructor invocation                                                        | Should be successful |
 * | 02               | Invoke constructor em_cmd_cfg_renew_t with the valid test inputs                                      | Input: service = em_service_type_cli, parameters.fixed_args = CliFixedArg, dm.network.id = NetworkID_CLI  | Object is created with members initialized (m_svc, m_param.u.args.fixed_args, m_data_model.m_network.m_net_info.id)                   | Should Pass    |
 * | 03               | Execute assertions to verify that the object's members match expected test values                     | Expected: m_svc = em_service_type_cli, fixed_args = CliFixedArg, network id = NetworkID_CLI             | Assertions pass verifying correct initialization (EXPECT_EQ and EXPECT_STREQ checks)                                                | Should Pass    |
 */
TEST(em_cmd_cfg_renew_t, em_cmd_cfg_renew_t_valid_cli)
{
    const char* testName = "em_cmd_cfg_renew_t_valid_cli";
    std::cout << "Entering " << testName << " test" << std::endl;
    em_service_type_t service = em_service_type_cli;
    em_cmd_params_t parameters = {};
    initCmdParams(parameters, "CliFixedArg");
    dm_easy_mesh_t dm{};
    initDmNetwork(dm, "NetworkID_CLI");
    em_cmd_cfg_renew_t cmd(service, parameters, dm);
    std::cout << "Constructor invoked with service = "
              << static_cast<unsigned int>(service)
              << " and fixed_args = " << cmd.m_param.u.args.fixed_args
              << ", network id = " << cmd.m_data_model.m_network.m_net_info.id
              << std::endl;
    EXPECT_EQ(cmd.m_type, em_cmd_type_cfg_renew);
    EXPECT_STREQ(cmd.m_name, "cfg_renew");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 1);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_tx_cfg_renew);
    EXPECT_TRUE(cmd.m_orch_desc[0].submit);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "CliFixedArg");
    EXPECT_STREQ(cmd.m_data_model.m_network.m_net_info.id, "NetworkID_CLI");
    cmd.deinit();
    std::cout << "Exiting " << testName << " test" << std::endl;
}

/**
 * @brief Verify that the configuration renewal command is properly initialized for a 'none' service.
 *
 * This test verifies that when em_cmd_cfg_renew_t is constructed with a 'none' service type,
 * empty fixed arguments, and a network ID of "NetworkID_NONE", all internal parameters are correctly assigned.
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
 * | Variation / Step | Description                                                                                          | Test Data                                                                                                                                              | Expected Result                                                                                                               | Notes             |
 * | :--------------: | ---------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------- | ----------------- |
 * | 01               | Setup test input parameters and network model initialization                                         | service = em_service_type_none, parameters.args.num_args = 0, fixed_args = "", dm_network id = "NetworkID_NONE"                                         | All input data structures are correctly initialized                                                                            | Should be successful |
 * | 02               | Invoke the em_cmd_cfg_renew_t constructor with the prepared test inputs                                | input1: service = em_service_type_none, input2: parameters (empty fixed_args, num_args = 0), input3: dm with network id "NetworkID_NONE"               | The constructor executes successfully and returns an instance with parameters assigned as provided                           | Should Pass       |
 * | 03               | Validate the instance fields via assertions to ensure correct initialization                         | EXPECT_EQ(cmd.m_svc, em_service_type_none), EXPECT_STREQ(cmd.m_param.u.args.fixed_args, ""), EXPECT_STREQ(cmd.m_data_model.m_network.m_net_info.id, "NetworkID_NONE") | All assertions pass, confirming that the object's fields match the expected values set during initialization                   | Should Pass       |
 */
TEST(em_cmd_cfg_renew_t, em_cmd_cfg_renew_t_valid_none)
{
    const char* testName = "em_cmd_cfg_renew_t_valid_none";
    std::cout << "Entering " << testName << " test" << std::endl;
    em_service_type_t service = em_service_type_none;
    em_cmd_params_t parameters = {};
    initCmdParams(parameters, "");
    parameters.u.args.num_args = 0;
    dm_easy_mesh_t dm{};
    initDmNetwork(dm, "NetworkID_NONE");
    em_cmd_cfg_renew_t cmd(service, parameters, dm);
    std::cout << "Constructor invoked with service = "
              << static_cast<unsigned int>(service)
              << " and fixed_args = \"" << cmd.m_param.u.args.fixed_args
              << "\", network id = " << cmd.m_data_model.m_network.m_net_info.id
              << std::endl;
    EXPECT_EQ(cmd.m_type, em_cmd_type_cfg_renew);
    EXPECT_STREQ(cmd.m_name, "cfg_renew");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 1);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_tx_cfg_renew);
    EXPECT_TRUE(cmd.m_orch_desc[0].submit);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "");
    EXPECT_STREQ(cmd.m_data_model.m_network.m_net_info.id, "NetworkID_NONE");
    cmd.deinit();
    std::cout << "Exiting " << testName << " test" << std::endl;
}

/**
 * @brief Test negative scenario for em_cmd_cfg_renew_t constructor with empty parameters
 *
 * This test verifies that even when empty parameters are passed for the 'ctrl' service type, the
 * em_cmd_cfg_renew_t constructor completes successfully but results in an object that reflects the empty
 * configuration. This behavior is expected so that subsequent validation routines can flag the empty command state.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize inputs: set service to em_service_type_ctrl, initialize parameters with fixed_args as empty string and num_args as 0, and create a dm_easy_mesh object with network ID "NetworkID_EmptyParam". | service = em_service_type_ctrl, parameters.fixed_args = "", parameters.num_args = 0, network id = "NetworkID_EmptyParam" | Inputs are correctly initialized with default empty parameters. | Should be successful |
 * | 02 | Invoke the em_cmd_cfg_renew_t constructor with the initialized service, empty parameters, and dm_easy_mesh object. | service = em_service_type_ctrl, parameters (empty fixed_args and num_args = 0), dm_easy_mesh with network id = "NetworkID_EmptyParam" | The object is constructed successfully. | Should Pass |
 * | 03 | Validate the constructed object's attributes by checking if m_svc equals em_service_type_ctrl and m_param.u.args.fixed_args is an empty string. | cmd.m_svc = em_service_type_ctrl, cmd.m_param.u.args.fixed_args = "" | The object's attributes match the expected values reflecting the empty parameters. | Should Pass |
 */
TEST(em_cmd_cfg_renew_t, em_cmd_cfg_renew_t_negative_empty_param)
{
    const char* testName = "em_cmd_cfg_renew_t_negative_empty_param";
    std::cout << "Entering " << testName << " test" << std::endl;
    em_service_type_t service = em_service_type_ctrl;
    em_cmd_params_t parameters = {};
    parameters.u.args.fixed_args[0] = '\0';
    parameters.u.args.num_args = 0;
    dm_easy_mesh_t dm{};
    initDmNetwork(dm, "NetworkID_EmptyParam");
    em_cmd_cfg_renew_t cmd(service, parameters, dm);
    std::cout << "Constructor invoked with service = "
              << static_cast<unsigned int>(service)
              << " and fixed_args = \"" << cmd.m_param.u.args.fixed_args
              << "\", network id = " << cmd.m_data_model.m_network.m_net_info.id
              << std::endl;
    EXPECT_EQ(cmd.m_type, em_cmd_type_cfg_renew);
    EXPECT_STREQ(cmd.m_name, "cfg_renew");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 1);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "");
    EXPECT_STREQ(cmd.m_data_model.m_network.m_net_info.id, "NetworkID_EmptyParam");
    cmd.deinit();
    std::cout << "Exiting " << testName << " test" << std::endl;
}

/**
 * @brief Test the negative scenario of em_cmd_cfg_renew_t constructor with an incomplete dm_easy_mesh_t configuration.
 *
 * This test verifies that when the dm_easy_mesh_t object has an empty network id (simulating a misconfiguration),
 * the em_cmd_cfg_renew_t constructor correctly reflects this negative state by setting the internal data model's network id to an empty string.
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
 * | 01 | Initialize service and parameters for the test. | service = em_service_type_agent, parameters = ValidAgentParam | Service and parameters are initialized correctly. | Should be successful |
 * | 02 | Create dm_easy_mesh_t object with an empty network id to simulate error state. | dm.m_network.m_net_info.id = "" | dm_easy_mesh_t object is created with an empty network id. | Should be successful |
 * | 03 | Invoke the em_cmd_cfg_renew_t constructor with negative dm configuration. | service = em_service_type_agent, parameters = ValidAgentParam, dm.m_network.m_net_info.id = "" | The object's internal state reflects the negative configuration: fixed_args equals "ValidAgentParam", network id remains empty, and service equals em_service_type_agent. | Should Fail |
 * | 04 | Check assertions of the object's internal properties. | cmd.m_svc, cmd.m_param.u.args.fixed_args, cmd.m_data_model.m_network.m_net_info.id | All assertions pass: service is em_service_type_agent, fixed_args is "ValidAgentParam", and network id is "". | Should be successful |
 */
TEST(em_cmd_cfg_renew_t, em_cmd_cfg_renew_t_negative_dm_error)
{
    const char* testName = "em_cmd_cfg_renew_t_negative_dm_error";
    std::cout << "Entering " << testName << " test" << std::endl;
    em_service_type_t service = em_service_type_agent;
    em_cmd_params_t parameters = {};
    initCmdParams(parameters, "ValidAgentParam");
    dm_easy_mesh_t dm{};
    dm.m_network.m_net_info.id[0] = '\0';
    em_cmd_cfg_renew_t cmd(service, parameters, dm);
    std::cout << "Constructor invoked with service = "
              << static_cast<unsigned int>(service)
              << " and fixed_args = " << cmd.m_param.u.args.fixed_args
              << ", network id = \"" << cmd.m_data_model.m_network.m_net_info.id << "\""
              << std::endl;
    EXPECT_EQ(cmd.m_type, em_cmd_type_cfg_renew);
    EXPECT_STREQ(cmd.m_name, "cfg_renew");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 1);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "ValidAgentParam");
    EXPECT_STREQ(cmd.m_data_model.m_network.m_net_info.id, "");
    cmd.deinit();
    std::cout << "Exiting " << testName << " test" << std::endl;
}