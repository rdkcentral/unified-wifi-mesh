
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
#include "em_cmd_get_network.h"


#ifndef EM_CLI_MAX_ARGS
#define EM_CLI_MAX_ARGS 5
#endif

/**
 * @brief Validate valid input construction for em_cmd_get_network_t
 *
 * This test validates that providing valid inputs to the em_cmd_get_network_t constructor results in correct object initialization. It verifies that the fixed argument and the network node pointer are set as expected.
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
 * | Variation / Step | Description                                                                                 | Test Data: input1 = num_args: 1, input2 = fixed_args: "GET_NETWORK", input3 = args[0]: "Param1", input4 = network node key: "dummy_node", output1 = fixed_args: "GET_NETWORK", output2 = net_node: not null | Expected Result: Constructor sets fixed_args field to "GET_NETWORK" and net_node pointer is valid | Should Pass |
 * | 02               | Call deinit method on the em_cmd_get_network_t instance to clean up resources                | Test Data: No additional arguments, output: deinit() execution                                | Expected Result: deinit executes without error                                               | Should be successful |
 */
TEST(em_cmd_get_network_t, em_cmd_get_network_t_ValidInputConstruction)
{
    std::cout << "Entering em_cmd_get_network_t_ValidInputConstruction test" << std::endl;
    em_cmd_params_t param;
    param.u.args.num_args = 1;
    strncpy(param.u.args.fixed_args, "GET_NETWORK", sizeof(param.u.args.fixed_args));
    strncpy(param.u.args.args[0], "Param1", sizeof(param.u.args.args[0]));
    em_network_node_t dummy_node;
    strncpy(dummy_node.key, "dummy_node", sizeof(dummy_node.key));
    param.net_node = &dummy_node;
    dm_easy_mesh_t dm;
    em_cmd_get_network_t cmd(param, dm);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "GET_NETWORK");
    EXPECT_TRUE(cmd.m_param.net_node != nullptr);
    cmd.deinit();
    std::cout << "Exiting em_cmd_get_network_t_ValidInputConstruction test" << std::endl;
}
/**
 * @brief Validate em_cmd_get_network_t with minimal valid input.
 *
 * This test verifies that the em_cmd_get_network_t API behaves correctly when provided with the minimal required input. It ensures that the command instance is initialized with default values and that the expected assertions pass for a minimal configuration.
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
 * | 01 | Invoke API with minimal valid input values including num_args=0, empty fixed_args, and a valid network node pointer | num_args = 0, fixed_args = "", net_node.key = "min_node", dm_easy_mesh_t instance created | API initializes command with fixed_args equal to "", num_args equals 0, and a non-null net_node pointer as verified by assertions | Should Pass |
 * | 02 | Deinitialize the command instance post testing | Call cmd.deinit() | Resources cleaned up successfully with no errors | Should be successful |
 */
TEST(em_cmd_get_network_t, em_cmd_get_network_t_ValidMinimalInput)
{
    std::cout << "Entering em_cmd_get_network_t_ValidMinimalInput test" << std::endl;
    em_cmd_params_t param;
    param.u.args.num_args = 0;
    strncpy(param.u.args.fixed_args, "", sizeof(param.u.args.fixed_args));
    em_network_node_t dummy_nodeMin;
    strncpy(dummy_nodeMin.key, "min_node", sizeof(dummy_nodeMin.key));
    param.net_node = &dummy_nodeMin;
    dm_easy_mesh_t dm;
    em_cmd_get_network_t cmd(param, dm);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "");
    EXPECT_EQ(cmd.m_param.u.args.num_args, 0);
    EXPECT_TRUE(cmd.m_param.net_node != nullptr);
    cmd.deinit();
    std::cout << "Exiting em_cmd_get_network_t_ValidMinimalInput test" << std::endl;
}
/**
 * @brief Verify that em_cmd_get_network_t correctly handles a null network node.
 *
 * This test checks that when the network node pointer is set to nullptr in the parameters, 
 * the em_cmd_get_network_t API correctly stores the null value and handles it gracefully without any crash.
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
 * | Variation / Step | Description                                                                                   | Test Data                                                                                                     | Expected Result                                                | Notes            |
 * | :--------------: | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- | ---------------- |
 * | 01               | Initialize parameters with 1 argument and set fixed args to "GET_NETWORK", argument to "Param1". | num_args = 1, fixed_args = "GET_NETWORK", args[0] = "Param1"                                                   | Parameters are initialized correctly                           | Should be successful  |
 * | 02               | Set the network node pointer to nullptr.                                                    | net_node = nullptr                                                                                            | The network node pointer is set to nullptr                      | Should be successful  |
 * | 03               | Create the em_cmd_get_network_t object with the given parameters and dm object, and verify net_node. | param with net_node = nullptr; dm object; output: cmd.m_param.net_node                                          | cmd.m_param.net_node is equal to nullptr                        | Should Pass      |
 * | 04               | Call deinit on the command object to clean up.                                                | Call to cmd.deinit()                                                                                          | Object is deinitialized successfully                           | Should be successful  |
 */
TEST(em_cmd_get_network_t, em_cmd_get_network_t_NullNetworkNode)
{
    std::cout << "Entering em_cmd_get_network_t_NullNetworkNode test" << std::endl;
    em_cmd_params_t param;
    param.u.args.num_args = 1;
    strncpy(param.u.args.fixed_args, "GET_NETWORK", sizeof(param.u.args.fixed_args));
    strncpy(param.u.args.args[0], "Param1", sizeof(param.u.args.args[0]));
    param.net_node = nullptr;
    dm_easy_mesh_t dm;
    em_cmd_get_network_t cmd(param, dm);
    EXPECT_EQ(cmd.m_param.net_node, nullptr);
    cmd.deinit();
    std::cout << "Exiting em_cmd_get_network_t_NullNetworkNode test" << std::endl;
}
/**
 * @brief Validate that em_cmd_get_network_t correctly handles the maximum boundary of arguments.
 *
 * This test verifies that the em_cmd_get_network_t API can properly initialize and process
 * a command structure when provided with the maximum allowed number of arguments. It ensures
 * that the API sets the fixed argument value correctly, allocates and assigns all provided arguments,
 * and properly handles a valid network node pointer.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 004@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                                                          | Test Data                                                                                                                                               | Expected Result                                                                                                   | Notes           |
 * | :--------------: | ------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- | --------------- |
 * | 01               | Initialize test parameters by setting num_args to EM_CLI_MAX_ARGS, fixed argument to "GET_NETWORK", assigning args "Arg0" to "ArgN", and setting the network node key to "boundary_node". | num_args = EM_CLI_MAX_ARGS, fixed_args = GET_NETWORK, args[0...EM_CLI_MAX_ARGS-1] = Arg0, Arg1,...,net_node->key = boundary_node                              | em_cmd_params_t structure is correctly initialized with the maximum number of arguments                           | Should be successful |
 * | 02               | Create an instance of em_cmd_get_network_t using the initialized parameters and check that the internal state is as expected.       | Constructor input: param (initialized as above), dm (instance of dm_easy_mesh_t)                                                                         | cmd.m_param.u.args.num_args equals EM_CLI_MAX_ARGS, fixed_args equals "GET_NETWORK", and net_node pointer is not null | Should Pass     |
 * | 03               | Call the deinitialization method to clean up the command object.                                                                      | Function call: cmd.deinit()                                                                                                                              | Command object cleans up without error                                                                            | Should be successful |
 */
TEST(em_cmd_get_network_t, em_cmd_get_network_t_BoundaryMaxArguments)
{
    std::cout << "Entering em_cmd_get_network_t_BoundaryMaxArguments test" << std::endl;

    em_cmd_params_t param;
    param.u.args.num_args = EM_CLI_MAX_ARGS;
    strncpy(param.u.args.fixed_args, "GET_NETWORK", sizeof(param.u.args.fixed_args));
    for (unsigned int i = 0; i < EM_CLI_MAX_ARGS; i++) {
        char arg[128];
        std::snprintf(arg, sizeof(arg), "Arg%d", i);
        strncpy(param.u.args.args[i], arg, sizeof(param.u.args.args[i]));
    }
    em_network_node_t dummy_nodeBoundary;
    strncpy(dummy_nodeBoundary.key, "boundary_node", sizeof(dummy_nodeBoundary.key));
    param.net_node = &dummy_nodeBoundary;
    dm_easy_mesh_t dm;
    em_cmd_get_network_t cmd(param, dm);
    EXPECT_EQ(cmd.m_param.u.args.num_args, EM_CLI_MAX_ARGS);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "GET_NETWORK");
    EXPECT_TRUE(cmd.m_param.net_node != nullptr);
    cmd.deinit();
    std::cout << "Exiting em_cmd_get_network_t_BoundaryMaxArguments test" << std::endl;
}
