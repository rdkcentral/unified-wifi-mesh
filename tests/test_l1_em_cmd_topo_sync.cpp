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
#include "em_cmd_topo_sync.h"




/**
 * @brief Validate the em_cmd_topo_sync_t constructor and its member initialization
 *
 * This test verifies that the em_cmd_topo_sync_t object is correctly constructed when provided with valid parameters.
 * It ensures that:
 * - The fixed arguments are set correctly.
 * - The network is initialized with the expected network id.
 * - The object's properties (such as m_type, m_name, m_svc, orchestration operation index, and descriptor) match the expected values.
 * - The deinitialization functions execute without error.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 001
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                                               | Test Data                                                                                                                         | Expected Result                                                                                                                                        | Notes           |
 * | :--------------: | ------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------- |
 * | 01               | Initialize command parameters and network info with fixed values                                                        | input: cmdParam.u.args.fixed_args = "topo_sync", netInfo.id = "net1"                                                              | em_cmd_params_t and em_network_info_t objects are initialized with the given values                                                                     | Should be successful |
 * | 02               | Create network and mesh objects using the initialized network info                                                        | input: network constructed with netInfo, dm_easy_mesh constructed with network                                                    | dm_network_t and dm_easy_mesh_t objects are created successfully                                                                                        | Should be successful |
 * | 03               | Invoke the constructor of em_cmd_topo_sync_t with the prepared parameters and mesh object                                  | input: cmdParam with fixed_args = "topo_sync", dm object                                                                          | em_cmd_topo_sync_t object is constructed with m_param.u.args.fixed_args set to "topo_sync"                                                              | Should Pass     |
 * | 04               | Validate the properties of the created em_cmd_topo_sync_t object using assertions                                          | Expected inputs: m_type = em_cmd_type_topo_sync, m_name = "topo_sync", m_svc = em_service_type_ctrl, m_orch_op_idx = 0,           | All EXPECT_EQ and EXPECT_STREQ assertions pass verifying the object's internal state as per the valid parameters                                        | Should Pass     |
 * |                  |                                                                                                                           | m_num_orch_desc = 1, m_orch_desc[0].op = dm_orch_type_topo_sync, m_orch_desc[0].submit = true, m_param.u.args.fixed_args = "topo_sync" |                                                                                                                                                        |                 |
 * | 05               | Clean up the objects by calling their deinitialization methods                                                           | input: Call topo.deinit(), dm.deinit()                                                                                            | The objects are deinitialized without error                                                                                                            | Should be successful |
 */
TEST(em_cmd_topo_sync_t, em_cmd_topo_sync_t_valid_parameters)
{
    const char* testName = "em_cmd_topo_sync_t_valid_parameters";
    std::cout << "Entering " << testName << " test" << std::endl;
    em_cmd_params_t cmdParam{};
    strncpy(cmdParam.u.args.fixed_args, "topo_sync", sizeof(cmdParam.u.args.fixed_args) - 1);
    em_network_info_t netInfo{};
    strncpy(netInfo.id, "net1", sizeof(netInfo.id) - 1);
    dm_network_t network(&netInfo);
    dm_easy_mesh_t dm(network);
    std::cout << "Command param fixed_args: " << cmdParam.u.args.fixed_args << std::endl;
    std::cout << "Network id prepared = net1" << std::endl;
    em_cmd_topo_sync_t topo(cmdParam, dm);
    std::cout << "Constructor invoked with fixed_args: " << topo.m_param.u.args.fixed_args << std::endl;
    EXPECT_EQ(topo.m_type, em_cmd_type_topo_sync);
    EXPECT_STREQ(topo.m_name, "topo_sync");
    EXPECT_EQ(topo.m_svc, em_service_type_ctrl);
    EXPECT_EQ(topo.m_orch_op_idx, 0);
    EXPECT_EQ(topo.m_num_orch_desc, 1);
    EXPECT_EQ(topo.m_orch_desc[0].op, dm_orch_type_topo_sync);
    EXPECT_EQ(topo.m_orch_desc[0].submit, true);
    EXPECT_STREQ(topo.m_param.u.args.fixed_args, "topo_sync");
    topo.deinit();
    dm.deinit();
    std::cout << "Exiting " << testName << " test" << std::endl;
}
/**
 * @brief Tests the creation and initialization of em_cmd_topo_sync_t object using minimal parameters
 *
 * This test verifies that the em_cmd_topo_sync_t object is correctly constructed with minimal/default parameters.
 * It initializes the command parameters and network information, creates necessary objects, invokes the constructor,
 * and then checks various member values using assertions to ensure the object is initialized as expected.
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
 * | :----: | --------- | ----------------------------- | ------------------------------------------ | --------------- |
 * | 01 | Print entering test message | testName = "em_cmd_topo_sync_t_minimal_parameters" | Expected console output indicating test entry | Should be successful |
 * | 02 | Initialize command parameters and network info with empty fixed_args | cmdParam.u.args.fixed_args = '\0', netInfo.id = '\0' | Initialization completes without error | Should be successful |
 * | 03 | Construct network, dm_easy_mesh_t, and invoke em_cmd_topo_sync_t constructor with minimal parameters | Inputs: cmdParam, dm instance (constructed with netInfo) | topo object created with m_type = em_cmd_type_topo_sync, m_name = "topo_sync", m_svc = em_service_type_ctrl, m_orch_op_idx = 0, m_num_orch_desc = 1, orch descriptor with op = dm_orch_type_topo_sync and submit = true; fixed_args as empty string | Should Pass |
 * | 04 | Perform assertions to validate object properties | Assertions: EXPECT_EQ and EXPECT_STREQ on topo’s member variables | All assertions pass confirming correct initialization | Should Pass |
 * | 05 | Deinitialize topo and dm objects and print exiting test message | Call topo.deinit() and dm.deinit() | Resources are released and console output indicates test exit | Should be successful |
 */
TEST(em_cmd_topo_sync_t, em_cmd_topo_sync_t_minimal_parameters)
{
    const char* testName = "em_cmd_topo_sync_t_minimal_parameters";
    std::cout << "Entering " << testName << " test" << std::endl;
    em_cmd_params_t cmdParam{};
    cmdParam.u.args.fixed_args[0] = '\0';
    em_network_info_t netInfo{};
    netInfo.id[0] = '\0';
    dm_network_t network(&netInfo);
    dm_easy_mesh_t dm(network);
    em_cmd_topo_sync_t topo(cmdParam, dm);
    std::cout << "Constructor invoked with empty fixed_args." << std::endl;
    EXPECT_EQ(topo.m_type, em_cmd_type_topo_sync);
    EXPECT_STREQ(topo.m_name, "topo_sync");
    EXPECT_EQ(topo.m_svc, em_service_type_ctrl);
    EXPECT_EQ(topo.m_orch_op_idx, 0);
    EXPECT_EQ(topo.m_num_orch_desc, 1);
    EXPECT_EQ(topo.m_orch_desc[0].op, dm_orch_type_topo_sync);
    EXPECT_EQ(topo.m_orch_desc[0].submit, true);
    EXPECT_STREQ(topo.m_param.u.args.fixed_args, "");
    EXPECT_STREQ(topo.m_param.u.args.fixed_args, "");
    topo.deinit();
    dm.deinit();
    std::cout << "Exiting " << testName << " test" << std::endl;
}
/**
 * @brief Validate the correct initialization and configuration of the custom network topology sync command
 *
 * This test verifies that the em_cmd_topo_sync_t API correctly initializes its member variables using the provided
 * command parameters and network information. It checks for proper assignment of command type, name, service type, and
 * orchestration description.
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
 * | 01 | Initialize test parameters and create objects using the constructor | cmdParam.u.args.fixed_args = "topo_sync", netInfo.id = "myNetwork42" | Objects are constructed successfully with provided parameters | Should Pass |
 * | 02 | Verify the command type, name, and service type assignment in the constructor | topo.m_type, topo.m_name, topo.m_svc with expected values "em_cmd_type_topo_sync", "topo_sync", "em_service_type_ctrl" | m_type equals em_cmd_type_topo_sync, m_name equals "topo_sync", and m_svc equals em_service_type_ctrl | Should Pass |
 * | 03 | Validate orchestration operation index and orchestration descriptor values | topo.m_orch_op_idx = 0, topo.m_num_orch_desc = 1, orch_desc[0].op = dm_orch_type_topo_sync, orch_desc[0].submit = true | m_orch_op_idx is 0, m_num_orch_desc is 1, orch_desc[0] has op equal to dm_orch_type_topo_sync and submit true | Should Pass |
 * | 04 | Confirm that the fixed argument in the m_param structure matches the input parameter | topo.m_param.u.args.fixed_args = "topo_sync" | m_param.u.args.fixed_args equals "topo_sync" | Should Pass |
 * | 05 | Deinitialize the created objects to clean up resources | Invocation of topo.deinit() and dm.deinit() | Resources are deinitialized without causing errors | Should be successful |
 */
TEST(em_cmd_topo_sync_t, em_cmd_topo_sync_t_custom_network)
{
    const char* testName = "em_cmd_topo_sync_t_custom_network";
    std::cout << "Entering " << testName << " test" << std::endl;
    em_cmd_params_t cmdParam{};
    strncpy(cmdParam.u.args.fixed_args, "topo_sync", sizeof(cmdParam.u.args.fixed_args) - 1);
    em_network_info_t netInfo{};
    strncpy(netInfo.id, "myNetwork42", sizeof(netInfo.id) - 1);
    dm_network_t network(&netInfo);
    dm_easy_mesh_t dm(network);
    em_cmd_topo_sync_t topo(cmdParam, dm);
    std::cout << "Constructor invoked with fixed_args = topo_sync"
              << " and network id = myNetwork42" << std::endl;
    EXPECT_EQ(topo.m_type, em_cmd_type_topo_sync);
    EXPECT_STREQ(topo.m_name, "topo_sync");
    EXPECT_EQ(topo.m_svc, em_service_type_ctrl);
    EXPECT_EQ(topo.m_orch_op_idx, 0);
    EXPECT_EQ(topo.m_num_orch_desc, 1);
    EXPECT_EQ(topo.m_orch_desc[0].op, dm_orch_type_topo_sync);
    EXPECT_EQ(topo.m_orch_desc[0].submit, true);
    EXPECT_STREQ(topo.m_param.u.args.fixed_args, "topo_sync");
    topo.deinit();
    dm.deinit();
    std::cout << "Exiting " << testName << " test" << std::endl;
}
