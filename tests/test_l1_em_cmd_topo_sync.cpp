
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


// Test for em_cmd_topo_sync_t::em_cmd_topo_sync_t(em_cmd_params_t param, dm_easy_mesh_t & dm)
//
// Test Case: Create em_cmd_topo_sync_t with valid non‐empty command parameters and a properly initialized dm_easy_mesh_t object.
// - param: an em_cmd_params_t with fixed_args set to "topo_sync"
// - dm: a dm_easy_mesh_t instance initialized with a valid network configuration (using the parameterized constructor)
//
// Expected Output: The em_cmd_topo_sync_t object is created successfully and its member values match the provided inputs.

/**
 * @brief Validates that em_cmd_topo_sync_t constructor behaves correctly with valid parameters.
 *
 * This test verifies that the em_cmd_topo_sync_t object is properly constructed when provided with valid command parameters and network information, ensuring that the fixed_args and network id are correctly set.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Prepare command parameter and set fixed_args with "topo_sync" | cmdParam.u.args.fixed_args = "topo_sync" | The command parameter's fixed_args should be initialized with "topo_sync" | Should be successful |
 * | 02 | Prepare network information and initialize dm_network_t with network id "net1" | netInfo.id = "net1" | The network info's id should be set to "net1" | Should be successful |
 * | 03 | Initialize dm_easy_mesh_t object using the dm_network_t instance | dm_easy_mesh_t constructed with network instance containing network id "net1" | dm_easy_mesh_t should reflect the correct network configuration | Should be successful |
 * | 04 | Construct em_cmd_topo_sync_t with the command parameters and dm object | topoSyncCmd constructed with cmdParam and dm | The object should store fixed_args "topo_sync" and associate the correct network configuration | Should Pass |
 * | 05 | Validate fixed_args inside the created command object using EXPECT_STREQ | API: EXPECT_STREQ(topoSyncCmd.m_param.u.args.fixed_args, "topo_sync") | The fixed_args value should be "topo_sync" | Should Pass |
 * | 06 | Validate network id in the data model via EXPECT_STREQ | API: EXPECT_STREQ(topoSyncCmd.m_data_model.get_network().get_network_id(), "net1") | The network id should be "net1" | Should Pass |
 */
TEST(em_cmd_topo_sync_t, em_cmd_topo_sync_t_valid_parameters) {
    std::cout << "Entering em_cmd_topo_sync_t_valid_parameters test" << std::endl;

    // Prepare command parameters
    em_cmd_params_t cmdParam{}; // zero-initialize safely

    const char *syncStr = "topo_sync";
    strncpy(cmdParam.u.args.fixed_args, syncStr, sizeof(cmdParam.u.args.fixed_args) - 1);
    cmdParam.u.args.fixed_args[sizeof(cmdParam.u.args.fixed_args) - 1] = '\0';

    // Create a dummy network info structure (no memset)
    em_network_info_t netInfo{};  // safely zero-initialized

    const char* netId = "net1";
    strncpy(netInfo.id, netId, sizeof(netInfo.id) - 1);
    netInfo.id[sizeof(netInfo.id) - 1] = '\0';

    dm_network_t network(&netInfo);

    dm_easy_mesh_t dm(network);

    std::cout << "Command param fixed_args: " << cmdParam.u.args.fixed_args << std::endl;
    std::cout << "Network id in dm: " << network.get_network_id() << std::endl;

    // Create command object
    em_cmd_topo_sync_t topoSyncCmd(cmdParam, dm);

    std::cout << "Invoked em_cmd_topo_sync_t constructor with fixed_args: "
              << topoSyncCmd.m_param.u.args.fixed_args << std::endl;

    EXPECT_STREQ(topoSyncCmd.m_param.u.args.fixed_args, "topo_sync");
    EXPECT_STREQ(topoSyncCmd.m_data_model.get_network()->get_network_id(), "net1");

    std::cout << "Exiting em_cmd_topo_sync_t_valid_parameters test" << std::endl;
}


