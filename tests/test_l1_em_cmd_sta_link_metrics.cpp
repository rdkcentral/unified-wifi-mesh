
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
#include "em_cmd_sta_link_metrics.h"

/**
 * @brief Verify default construction of em_cmd_sta_link_metrics_t initializes members correctly
 *
 * This test creates an instance of em_cmd_sta_link_metrics_t using a default dm_easy_mesh_t object and verifies that all member variables are set to their expected default values. It ensures that the constructor and associated methods perform as intended under normal conditions.
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
 * | 01 | Instantiate a dm_easy_mesh_t object named default_dm. | default_dm: created with default constructor | Object default_dm is instantiated successfully | Should be successful |
 * | 02 | Invoke the constructor of em_cmd_sta_link_metrics_t using default_dm. | input: default_dm, output: cmd object | cmd object is created with default values | Should Pass |
 * | 03 | Call get_type() on cmd and verify it returns em_cmd_type_sta_link_metrics. | output1 = cmd.get_type(), expected = em_cmd_type_sta_link_metrics | get_type() returns em_cmd_type_sta_link_metrics | Should Pass |
 * | 04 | Verify that m_num_orch_desc equals 1. | output1 = cmd.m_num_orch_desc, expected = 1 | m_num_orch_desc is 1 | Should Pass |
 * | 05 | Verify that m_orch_op_idx equals 0. | output1 = cmd.m_orch_op_idx, expected = 0 | m_orch_op_idx is 0 | Should Pass |
 * | 06 | Verify that m_orch_desc[0].op equals dm_orch_type_sta_link_metrics. | output1 = cmd.m_orch_desc[0].op, expected = dm_orch_type_sta_link_metrics | m_orch_desc[0].op matches dm_orch_type_sta_link_metrics | Should Pass |
 * | 07 | Verify that m_orch_desc[0].submit is true. | output1 = cmd.m_orch_desc[0].submit, expected = true | m_orch_desc[0].submit is true | Should Pass |
 * | 08 | Verify that m_name equals "sta_link_metrics". | output1 = cmd.m_name, expected = sta_link_metrics | m_name matches "sta_link_metrics" | Should Pass |
 * | 09 | Verify that m_svc equals em_service_type_ctrl. | output1 = cmd.m_svc, expected = em_service_type_ctrl | m_svc equals em_service_type_ctrl | Should Pass |
 * | 10 | Invoke the deinit() method on cmd. | input: cmd.deinit(), output: deinitialization performed | cmd is deinitialized successfully | Should Pass |
 */
TEST(em_cmd_sta_link_metrics_t, DefaultConstruction)
{
    std::cout << "Entering DefaultConstruction test" << std::endl;
    dm_easy_mesh_t default_dm;
    std::cout << "Invoking em_cmd_sta_link_metrics_t(default_dm)" << std::endl;
    em_cmd_sta_link_metrics_t cmd(default_dm);
    EXPECT_EQ(cmd.get_type(), em_cmd_type_sta_link_metrics);
    std::cout << "Verified command type: " << cmd.get_type() << std::endl;
    EXPECT_EQ(cmd.m_num_orch_desc, 1);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_sta_link_metrics);
    EXPECT_TRUE(cmd.m_orch_desc[0].submit);
    EXPECT_STREQ(cmd.m_name, "sta_link_metrics");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    cmd.deinit();
    std::cout << "Exiting DefaultConstruction test" << std::endl;
}
/**
 * @brief Validate correct behavior of em_cmd_sta_link_metrics_t for a custom network configuration
 *
 * This test verifies that the em_cmd_sta_link_metrics_t API correctly initializes the command object with a custom network configuration. It ensures that the network ID and control interface name are properly assigned, and that the command object's internal fields and orchestration descriptor are correctly set.
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
 * | 01 | Set custom network identifier and control interface name in dm_easy_mesh_t object. | custom_dm, m_network.m_net_info.id = "CustomNetID", m_network.m_net_info.ctrl_id.name = "CtrlInterface" | custom_dm holds the correct network ID and control interface name | Should be successful |
 * | 02 | Invoke em_cmd_sta_link_metrics_t constructor with custom_dm. | custom_dm passed to em_cmd_sta_link_metrics_t constructor | Command object is created with custom_dm settings | Should Pass |
 * | 03 | Validate command type using get_type() method. | cmd.get_type() = em_cmd_type_sta_link_metrics | Command type matches em_cmd_type_sta_link_metrics | Should Pass |
 * | 04 | Check orchestration descriptor default values: m_num_orch_desc, m_orch_op_idx, op, submit flag. | cmd.m_num_orch_desc = 1, cmd.m_orch_op_idx = 0, cmd.m_orch_desc[0].op = dm_orch_type_sta_link_metrics, cmd.m_orch_desc[0].submit = true | The orchestration descriptor fields are properly set | Should Pass |
 * | 05 | Verify command name and service type. | cmd.m_name = "sta_link_metrics", cmd.m_svc = em_service_type_ctrl | Command name is "sta_link_metrics" and service type is em_service_type_ctrl | Should Pass |
 * | 06 | Deinitialize the command object. | Invocation of cmd.deinit() | Command object is deinitialized successfully | Should be successful |
 */
TEST(em_cmd_sta_link_metrics_t, CustomNetworkConfiguration)
{
    std::cout << "Entering CustomNetworkConfiguration test" << std::endl;

    dm_easy_mesh_t custom_dm;
    const char* customNetID = "CustomNetID";
    strncpy(custom_dm.m_network.m_net_info.id, customNetID,
            sizeof(custom_dm.m_network.m_net_info.id) - 1);
    custom_dm.m_network.m_net_info.id[sizeof(custom_dm.m_network.m_net_info.id) - 1] = '\0';

    const char* customCtrlIfName = "CtrlInterface";
    strncpy(custom_dm.m_network.m_net_info.ctrl_id.name, customCtrlIfName,
            sizeof(custom_dm.m_network.m_net_info.ctrl_id.name) - 1);
    custom_dm.m_network.m_net_info.ctrl_id.name[sizeof(custom_dm.m_network.m_net_info.ctrl_id.name) - 1] = '\0';

    std::cout << "Invoking em_cmd_sta_link_metrics_t(custom_dm)" << std::endl;
    em_cmd_sta_link_metrics_t cmd(custom_dm);
    EXPECT_EQ(cmd.get_type(), em_cmd_type_sta_link_metrics);
    std::cout << "Verified command type: " << cmd.get_type() << std::endl;
    EXPECT_EQ(cmd.m_num_orch_desc, 1);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_sta_link_metrics);
    EXPECT_TRUE(cmd.m_orch_desc[0].submit);
    EXPECT_STREQ(cmd.m_name, "sta_link_metrics");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    cmd.deinit();
    std::cout << "Exiting CustomNetworkConfiguration test" << std::endl;
}
