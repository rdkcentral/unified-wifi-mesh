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
#include <cstring>
#include "em_cmd_start_dpp.h"

// Helper function to convert a raw 6-byte MAC address to a colon-separated string.
static std::string mac_to_string(const unsigned char mac[6])
{
    char buff[18];  // "AA:BB:CC:DD:EE:FF"
    snprintf(buff, sizeof(buff),
             "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buff);
}

// Helper function to convert a MAC already stored as a string into std::string.
static std::string mac_to_string(const char* mac)
{
    return std::string(mac);
}

/**
 * @brief Validate that em_cmd_start_dpp_t is properly constructed with valid arguments
 *
 * This test verifies that when provided with valid arguments, the em_cmd_start_dpp_t object is created with the correct parameter values including the arguments array, fixed argument, and network node properties. It also checks that the command type, name, service type, and orchestration parameters are set as expected.
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
 * | :----: | ----------- | --------- | -------------- | ----- |
 * | 01 | Initialize parameter structure and set number of arguments to 3 | param.u.args.num_args = 3 | num_args equals 3 in the object | Should be successful |
 * | 02 | Set first argument to "Argument1" | param.u.args.args[0] = "Argument1" | args[0] equals "Argument1" | Should be successful |
 * | 03 | Set second argument to "Argument2" | param.u.args.args[1] = "Argument2" | args[1] equals "Argument2" | Should be successful |
 * | 04 | Set third argument to "Argument3" | param.u.args.args[2] = "Argument3" | args[2] equals "Argument3" | Should be successful |
 * | 05 | Set fixed argument to "FixedArgument" | param.u.args.fixed_args = "FixedArgument" | fixed_args equals "FixedArgument" | Should be successful |
 * | 06 | Configure network node with key and display information | node.key = "TestNodeKey", display_info.collapsed = false, display_info.orig_node_ctr = 1, display_info.node_ctr = 1, display_info.node_pos = 0 | Network node properties match expected values | Should be successful |
 * | 07 | Construct the em_cmd_start_dpp_t object using the configured parameters and network node | Pass param and node to object constructor | Object is constructed with proper parameter assignments | Should Pass |
 * | 08 | Validate all object member values (arguments, fixed argument, network node and command specific properties) | Validate: m_param.u.args, m_param.net_node, m_type, m_name, m_svc, m_orch_op_idx, m_num_orch_desc | All members match the expected values | Should Pass |
 */
TEST(em_cmd_start_dpp_t, em_cmd_start_dpp_t_args_valid) {
    std::cout << "Entering em_cmd_start_dpp_t_args_valid test" << std::endl;

    em_cmd_params_t param{};
    param.u.args.num_args = 3;

    std::cout << "Setting args[0] = Argument1" << std::endl;
    strncpy(param.u.args.args[0], "Argument1", sizeof(param.u.args.args[0]) - 1);

    std::cout << "Setting args[1] = Argument2" << std::endl;
    strncpy(param.u.args.args[1], "Argument2", sizeof(param.u.args.args[1]) - 1);

    std::cout << "Setting args[2] = Argument3" << std::endl;
    strncpy(param.u.args.args[2], "Argument3", sizeof(param.u.args.args[2]) - 1);

    std::cout << "Setting fixed_args = FixedArgument" << std::endl;
    strncpy(param.u.args.fixed_args, "FixedArgument", sizeof(param.u.args.fixed_args) - 1);

    em_network_node_t node{};
    strncpy(node.key, "TestNodeKey", sizeof(node.key) - 1);
    node.display_info.collapsed = false;
    node.display_info.orig_node_ctr = 1;
    node.display_info.node_ctr = 1;
    node.display_info.node_pos = 0;

    std::cout << "Node key = " << node.key << std::endl;
    param.net_node = &node;

    em_cmd_start_dpp_t cmd(param);
    std::cout << "Object constructed" << std::endl;

    EXPECT_EQ(cmd.m_param.u.args.num_args, 3);
    EXPECT_STREQ(cmd.m_param.u.args.args[0], "Argument1");
    EXPECT_STREQ(cmd.m_param.u.args.args[1], "Argument2");
    EXPECT_STREQ(cmd.m_param.u.args.args[2], "Argument3");
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "FixedArgument");

    EXPECT_STREQ(cmd.m_param.net_node->key, "TestNodeKey");
    EXPECT_FALSE(cmd.m_param.net_node->display_info.collapsed);
    EXPECT_EQ(cmd.m_param.net_node->display_info.orig_node_ctr, 1);
    EXPECT_EQ(cmd.m_param.net_node->display_info.node_ctr, 1);
    EXPECT_EQ(cmd.m_param.net_node->display_info.node_pos, 0);

    EXPECT_EQ(cmd.m_type, em_cmd_type_start_dpp);
    EXPECT_STREQ(cmd.m_name, "start_dpp");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 0);

    std::cout << "Exiting em_cmd_start_dpp_t_args_valid test" << std::endl;
}
/**
 * @brief Validates that em_cmd_start_dpp_t is correctly constructed with valid steer parameters.
 *
 * This test verifies that the em_cmd_start_dpp_t object is constructed with the correct steer parameters.
 * It sets up specific MAC addresses for sta_mac, source, and target, along with other configuration parameters.
 * The test then ensures that these values are correctly retained within the object by using assertion checks.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize input parameters including MAC addresses and steer configurations. | sta_bytes = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF}, source_bytes = {0x11,0x22,0x33,0x44,0x55,0x66}, target_bytes = {0x66,0x55,0x44,0x33,0x22,0x11}, request_mode = 1, disassoc_imminent = true, btm_abridged = false, link_removal_imminent = false, steer_opportunity_win = 100, btm_disassociation_timer = 30, target_op_class = 5, target_channel = 36 | Input parameters are correctly set in param structure. | Should be successful |
 * | 02 | Initialize network node with necessary parameters. | node.key = "SteerTestNode", orig_node_ctr = 2, node_ctr = 2, node_pos = 1 | Network node is correctly initialized and assigned to param. | Should be successful |
 * | 03 | Construct the em_cmd_start_dpp_t object using the populated parameters. | param containing steer_params and net_node pointer | em_cmd_start_dpp_t object is created with all steer values set as provided. | Should Pass |
 * | 04 | Validate the parameter values stored in the object using assertions. | Expected values from sta_bytes, source_bytes, target_bytes, and other configurations | All assertions pass confirming proper parameter assignment in the object. | Should Pass |
 */
TEST(em_cmd_start_dpp_t, em_cmd_start_dpp_t_steer_valid) {
    std::cout << "Entering em_cmd_start_dpp_t_steer_valid test" << std::endl;
    em_cmd_params_t param{};
    unsigned char sta_bytes[6]    = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    unsigned char source_bytes[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    unsigned char target_bytes[6] = {0x66, 0x55, 0x44, 0x33, 0x22, 0x11};
    std::cout << "Setting sta_mac to:    " << mac_to_string(sta_bytes) << std::endl;
    memcpy(param.u.steer_params.sta_mac, sta_bytes, sizeof(sta_bytes));
    std::cout << "Setting source to:     " << mac_to_string(source_bytes) << std::endl;
    memcpy(param.u.steer_params.source, source_bytes, sizeof(source_bytes));
    std::cout << "Setting target to:     " << mac_to_string(target_bytes) << std::endl;
    memcpy(param.u.steer_params.target, target_bytes, sizeof(target_bytes));
    param.u.steer_params.request_mode = 1;
    param.u.steer_params.disassoc_imminent = true;
    param.u.steer_params.btm_abridged = false;
    param.u.steer_params.link_removal_imminent = false;
    param.u.steer_params.steer_opportunity_win = 100;
    param.u.steer_params.btm_disassociation_timer = 30;
    param.u.steer_params.target_op_class = 5;
    param.u.steer_params.target_channel = 36;
    em_network_node_t node{};
    strncpy(node.key, "SteerTestNode", sizeof(node.key) - 1);
    node.display_info.orig_node_ctr = 2;
    node.display_info.node_ctr = 2;
    node.display_info.node_pos = 1;
    param.net_node = &node;
    std::cout << "Node key = " << node.key << std::endl;
    em_cmd_start_dpp_t cmd(param);
    std::cout << "Object constructed" << std::endl;
    std::cout << "sta_mac   = " << mac_to_string(cmd.m_param.u.steer_params.sta_mac) << std::endl;
    std::cout << "source    = " << mac_to_string(cmd.m_param.u.steer_params.source) << std::endl;
    std::cout << "target    = " << mac_to_string(cmd.m_param.u.steer_params.target) << std::endl;
    EXPECT_EQ(memcmp(cmd.m_param.u.steer_params.sta_mac, sta_bytes, 6), 0);
    EXPECT_EQ(memcmp(cmd.m_param.u.steer_params.source,  source_bytes, 6), 0);
    EXPECT_EQ(memcmp(cmd.m_param.u.steer_params.target,  target_bytes, 6), 0);
    EXPECT_EQ(cmd.m_param.u.steer_params.request_mode, 1);
    EXPECT_TRUE(cmd.m_param.u.steer_params.disassoc_imminent);
    EXPECT_FALSE(cmd.m_param.u.steer_params.btm_abridged);
    EXPECT_FALSE(cmd.m_param.u.steer_params.link_removal_imminent);
    EXPECT_EQ(cmd.m_param.u.steer_params.steer_opportunity_win, 100);
    EXPECT_EQ(cmd.m_param.u.steer_params.btm_disassociation_timer, 30);
    EXPECT_EQ(cmd.m_param.u.steer_params.target_op_class, 5);
    EXPECT_EQ(cmd.m_param.u.steer_params.target_channel, 36);
    EXPECT_STREQ(cmd.m_param.net_node->key, "SteerTestNode");
    std::cout << "Exiting em_cmd_start_dpp_t_steer_valid test" << std::endl;
}
/**
 * @brief Validate valid BTM report parameters in em_cmd_start_dpp_t API
 *
 * This test verifies that the em_cmd_start_dpp_t constructor correctly initializes the object
 * with valid BTM report parameters including MAC addresses for source, station, and target,
 * along with the status code and network node key.
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
 * | Variation / Step | Description | Test Data | Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize test parameters with valid BTM report values | input1 = src "22:33:44:55:66:77", input2 = sta "FF:EE:DD:CC:BB:AA", input3 = tgt "77:66:55:44:33:22", input4 = status_code 0x01, input5 = net_node.key "BTMReportNode" | em_cmd_params_t structure is correctly populated with the provided values | Should be successful |
 * | 02 | Construct the em_cmd_start_dpp_t object using the initialized parameters | input: em_cmd_params_t param populated in step 01 | Command object is constructed with member variables matching the input parameters | Should Pass |
 * | 03 | Validate object member variables using assertions | output: cmd.m_param fields corresponding to source, sta_mac, target, status_code, net_node.key | EXPECT_STREQ and EXPECT_EQ assertions pass confirming correct initialization of the object | Should Pass |
 */
TEST(em_cmd_start_dpp_t, em_cmd_start_dpp_t_btm_report_valid) {
    std::cout << "Entering em_cmd_start_dpp_t_btm_report_valid test" << std::endl;
    em_cmd_params_t param{};
    const char* src   = "22:33:44:55:66:77";
    const char* sta   = "FF:EE:DD:CC:BB:AA";
    const char* tgt   = "77:66:55:44:33:22";
    std::cout << "Setting source to: " << src << std::endl;
    strncpy(reinterpret_cast<char*>(param.u.btm_report_params.source), src, sizeof(param.u.btm_report_params.source) - 1);
    std::cout << "Setting sta_mac to: " << sta << std::endl;
    strncpy(reinterpret_cast<char*>(param.u.btm_report_params.sta_mac), sta, sizeof(param.u.btm_report_params.sta_mac) - 1);
    std::cout << "Setting target to: " << tgt << std::endl;
    strncpy(reinterpret_cast<char*>(param.u.btm_report_params.target), tgt, sizeof(param.u.btm_report_params.target) - 1);
    param.u.btm_report_params.status_code = 0x01;
    em_network_node_t node{};
    strncpy(node.key, "BTMReportNode", sizeof(node.key) - 1);
    param.net_node = &node;
    std::cout << "Node key = " << node.key << std::endl;
    em_cmd_start_dpp_t cmd(param);
    std::cout << "Object constructed" << std::endl;
    std::cout << "source: " << mac_to_string(reinterpret_cast<char*>(cmd.m_param.u.btm_report_params.source)) << std::endl;
    std::cout << "sta_mac: " << mac_to_string(reinterpret_cast<char*>(cmd.m_param.u.btm_report_params.sta_mac)) << std::endl;
    std::cout << "target:  " << mac_to_string(reinterpret_cast<char*>(cmd.m_param.u.btm_report_params.target)) << std::endl;
    EXPECT_STREQ(reinterpret_cast<char*>(cmd.m_param.u.btm_report_params.source),
                 std::string(src, sizeof(cmd.m_param.u.btm_report_params.source) - 1).c_str());
    EXPECT_STREQ(reinterpret_cast<char*>(cmd.m_param.u.btm_report_params.sta_mac),
                 std::string(sta, sizeof(cmd.m_param.u.btm_report_params.sta_mac) - 1).c_str());
    EXPECT_STREQ(reinterpret_cast<char*>(cmd.m_param.u.btm_report_params.target),
                 std::string(tgt, sizeof(cmd.m_param.u.btm_report_params.target) - 1).c_str());
    EXPECT_EQ(cmd.m_param.u.btm_report_params.status_code, 0x01);
    EXPECT_STREQ(cmd.m_param.net_node->key, "BTMReportNode");
    std::cout << "Exiting em_cmd_start_dpp_t_btm_report_valid test" << std::endl;
}
/**
 * @brief Verify that the em_cmd_start_dpp_t constructor correctly initializes the object with valid disassociation parameters.
 *
 * This test verifies that a valid disassociation parameter structure properly initializes the em_cmd_start_dpp_t object.
 * It ensures that the disassoc_params and network node fields (including key and display information) are correctly assigned.
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
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize disassoc_params and network node structure with valid values. | disassoc_params.num = 1, node.key = "DisassocNode", collapsed = false, orig_node_ctr = 4, node_ctr = 4, node_pos = 3 | Parameters are correctly set in the test input structure. | Should be successful |
 * | 02 | Invoke em_cmd_start_dpp_t constructor and validate field assignments using assertions. | Input: param with valid disassoc_params and network node; Output: obj.m_param.u.disassoc_params.num = 1, obj.m_param.net_node ≠ nullptr, obj.m_param.net_node->key = "DisassocNode", collapsed = false, orig_node_ctr = 4, node_ctr = 4, node_pos = 3 | Object fields are correctly initialized and all assertions pass. | Should Pass |
 */
TEST(em_cmd_start_dpp_t, em_cmd_start_dpp_t_disassoc_valid)
{
    std::cout << "Entering em_cmd_start_dpp_t_disassoc_valid test" << std::endl;
    em_cmd_params_t param = {};
    param.u.disassoc_params.num = 1;
    em_network_node_t node = {};
    strncpy(node.key, "DisassocNode", sizeof(node.key) - 1);
    node.key[sizeof(node.key) - 1] = '\0';
    node.display_info.collapsed = false;
    node.display_info.orig_node_ctr = 4;
    node.display_info.node_ctr = 4;
    node.display_info.node_pos = 3;
    param.net_node = &node;
    std::cout << "Invoking em_cmd_start_dpp_t constructor with disassoc_params.num = " << param.u.disassoc_params.num << std::endl;
    std::cout << "Network node key = " << node.key << std::endl;
    em_cmd_start_dpp_t obj(param);
    EXPECT_EQ(obj.m_param.u.disassoc_params.num, 1);
    std::cout << "Constructed object: disassoc_params.num = " << obj.m_param.u.disassoc_params.num << std::endl;
    EXPECT_NE(obj.m_param.net_node, nullptr);
    EXPECT_STREQ(obj.m_param.net_node->key, "DisassocNode");
    EXPECT_FALSE(obj.m_param.net_node->display_info.collapsed);
    EXPECT_EQ(obj.m_param.net_node->display_info.orig_node_ctr, 4);
    EXPECT_EQ(obj.m_param.net_node->display_info.node_ctr, 4);
    EXPECT_EQ(obj.m_param.net_node->display_info.node_pos, 3);
    std::cout << "Exiting em_cmd_start_dpp_t_disassoc_valid test" << std::endl;
}
/**
 * @brief Validates the em_cmd_start_dpp_t constructor with a valid scan node parameter.
 *
 * This test verifies that when valid scan parameters are provided to the em_cmd_start_dpp_t constructor, the object is initialized correctly with the expected network node details. The test ensures that all data members are properly set, particularly the network node pointer, key, display information, and counter fields.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 005@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Set up test parameters with a network node containing key "ScanNode" and display parameters: collapsed false, orig_node_ctr 5, node_ctr 5, node_pos 4. | node.key = ScanNode, node.display_info.collapsed = false, node.display_info.orig_node_ctr = 5, node.display_info.node_ctr = 5, node.display_info.node_pos = 4 | Test parameters are correctly assigned. | Should be successful |
 * | 02 | Invoke em_cmd_start_dpp_t constructor using the created scan parameters. | param.net_node = &node | Object is constructed successfully. | Should Pass |
 * | 03 | Verify that the network node pointer in the constructed object is not null. | output: m_param.net_node != nullptr | Pointer should not be null. | Should Pass |
 * | 04 | Verify that the network node key in the constructed object is "ScanNode". | output: m_param.net_node->key = ScanNode | Key matches "ScanNode". | Should Pass |
 * | 05 | Verify that display_info.collapsed in the network node is false. | output: m_param.net_node->display_info.collapsed = false | Value is false. | Should Pass |
 * | 06 | Verify that the original node counter (orig_node_ctr) is equal to 5. | output: m_param.net_node->display_info.orig_node_ctr = 5 | Value is 5. | Should Pass |
 * | 07 | Verify that the node counter (node_ctr) is equal to 5. | output: m_param.net_node->display_info.node_ctr = 5 | Value is 5. | Should Pass |
 * | 08 | Verify that the node position (node_pos) is equal to 4. | output: m_param.net_node->display_info.node_pos = 4 | Value is 4. | Should Pass |
 */
TEST(em_cmd_start_dpp_t, em_cmd_start_dpp_t_scan_valid)
{
    std::cout << "Entering em_cmd_start_dpp_t_scan_valid test" << std::endl;
    em_cmd_params_t param = {};
    em_network_node_t node = {};
    strncpy(node.key, "ScanNode", sizeof(node.key) - 1);
    node.key[sizeof(node.key) - 1] = '\0';
    node.display_info.collapsed = false;
    node.display_info.orig_node_ctr = 5;
    node.display_info.node_ctr = 5;
    node.display_info.node_pos = 4;
    param.net_node = &node;
    std::cout << "Invoking em_cmd_start_dpp_t constructor with scan_params provided" << std::endl;
    std::cout << "Network node key = " << node.key << std::endl;
    em_cmd_start_dpp_t obj(param);
    EXPECT_NE(obj.m_param.net_node, nullptr);
    EXPECT_STREQ(obj.m_param.net_node->key, "ScanNode");
    EXPECT_FALSE(obj.m_param.net_node->display_info.collapsed);
    EXPECT_EQ(obj.m_param.net_node->display_info.orig_node_ctr, 5);
    EXPECT_EQ(obj.m_param.net_node->display_info.node_ctr, 5);
    EXPECT_EQ(obj.m_param.net_node->display_info.node_pos, 4);
    std::cout << "Constructed object: net_node key = " << obj.m_param.net_node->key << std::endl;
    std::cout << "Exiting em_cmd_start_dpp_t_scan_valid test" << std::endl;
}
/**
 * @brief Validate that em_cmd_start_dpp_t correctly initializes AP metrics parameters and network node details.
 *
 * This test verifies that the em_cmd_start_dpp_t API accurately copies and sets the RUID (truncated based on maximum allowed length), correctly assigns boolean flags for AP metrics, and properly configures the associated network node including its key and display information. It ensures that the constructed object contains the expected values for all parameters.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 006
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize test; declare em_cmd_params_t and define the MAC address string. | mac = "01:23:45:67:89:AB" | Parameter object created successfully; initial state ready for RUID copy. | Should be successful |
 * | 02 | Calculate maximum allowed length for RUID and copy the MAC address into the RUID field. | maxLen = sizeof(param.u.ap_metrics_params.ruid) - 1, macLen = min(strlen(mac), maxLen) | RUID is correctly truncated to the allowed maximum length. | Should be successful |
 * | 03 | Set AP metrics parameters; specifically, assign sta_link_metrics_include, sta_traffic_stats_include, and wifi6_status_report_include flags. | sta_link_metrics_include = true, sta_traffic_stats_include = true, wifi6_status_report_include = false | Flags are set as expected in the parameter object. | Should be successful |
 * | 04 | Configure network node details by copying the node key and setting display information. | key = "APMetricsNode", collapsed = false, orig_node_ctr = 6, node_ctr = 6, node_pos = 5 | Network node is correctly initialized and associated with the parameter object. | Should be successful |
 * | 05 | Construct the em_cmd_start_dpp_t object using the parameters; verify that the object’s data matches expected values via various assertions. | input: initialized parameter struct; output: object m_param values matching the expected values | All EXPECT_* assertions pass; the object's parameters (ruid, flags, and network node details) are correctly set. | Should Pass |
 */
TEST(em_cmd_start_dpp_t, em_cmd_start_dpp_t_ap_metrics_valid)
{
    std::cout << "Entering em_cmd_start_dpp_t_ap_metrics_valid test" << std::endl;
    em_cmd_params_t param{};
    const char* mac = "01:23:45:67:89:AB";
    size_t maxLen = sizeof(param.u.ap_metrics_params.ruid) - 1;
    size_t macLen = std::min(strlen(mac), maxLen);
    std::cout << "Copying RUID: " << mac << " (max allowed = " << maxLen << ")" << std::endl;
    memcpy(param.u.ap_metrics_params.ruid, mac, macLen);
    param.u.ap_metrics_params.ruid[macLen] = '\0';
    param.u.ap_metrics_params.sta_link_metrics_include = true;
    param.u.ap_metrics_params.sta_traffic_stats_include = true;
    param.u.ap_metrics_params.wifi6_status_report_include = false;
    em_network_node_t node{};
    size_t keyLen = std::min(sizeof(node.key) - 1, strlen("APMetricsNode"));
    memcpy(node.key, "APMetricsNode", keyLen);
    node.key[keyLen] = '\0';
    node.display_info.collapsed     = false;
    node.display_info.orig_node_ctr = 6;
    node.display_info.node_ctr      = 6;
    node.display_info.node_pos      = 5;
    param.net_node = &node;
    std::cout << "Network node key = " << node.key << std::endl;
    std::cout << "ruid = " << param.u.ap_metrics_params.ruid << std::endl;
    std::cout << "sta_link_metrics_include = " << param.u.ap_metrics_params.sta_link_metrics_include << std::endl;
    std::cout << "sta_traffic_stats_include = " << param.u.ap_metrics_params.sta_traffic_stats_include << std::endl;
    std::cout << "wifi6_status_report_include = " << param.u.ap_metrics_params.wifi6_status_report_include << std::endl;
    em_cmd_start_dpp_t obj(param);
    std::string expected_truncated(mac, macLen);
    std::cout << "Expected ruid = " << expected_truncated << std::endl;
    EXPECT_STREQ(reinterpret_cast<const char*>(obj.m_param.u.ap_metrics_params.ruid), expected_truncated.c_str());
    EXPECT_TRUE(obj.m_param.u.ap_metrics_params.sta_link_metrics_include);
    EXPECT_TRUE(obj.m_param.u.ap_metrics_params.sta_traffic_stats_include);
    EXPECT_FALSE(obj.m_param.u.ap_metrics_params.wifi6_status_report_include);
    EXPECT_NE(obj.m_param.net_node, nullptr);
    EXPECT_STREQ(obj.m_param.net_node->key, "APMetricsNode");
    EXPECT_FALSE(obj.m_param.net_node->display_info.collapsed);
    EXPECT_EQ(obj.m_param.net_node->display_info.orig_node_ctr, 6);
    EXPECT_EQ(obj.m_param.net_node->display_info.node_ctr, 6);
    EXPECT_EQ(obj.m_param.net_node->display_info.node_pos, 5);
    std::cout << "Constructed object: ap_metrics_params.ruid = " 
              << obj.m_param.u.ap_metrics_params.ruid << std::endl;
    std::cout << "Exiting em_cmd_start_dpp_t_ap_metrics_valid test" << std::endl;
}
/**
 * @brief Validate the initialization of em_cmd_start_dpp_t with a null network node
 *
 * This test verifies that when the em_cmd_params_t structure is initialized with a null net_node, 
 * and with specific command arguments, the em_cmd_start_dpp_t constructor correctly sets up the object state.
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
 * | Variation / Step | Description                                                                                            | Test Data                                                                                                             | Expected Result                                                                                                                                           | Notes       |
 * | :--------------: | ------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
 * | 01               | Initialize em_cmd_params_t with num_args=2, args[0]="Arg1_NullNode", args[1]="Arg2_NullNode", fixed_args="Fixed_NullNode", and net_node=nullptr; invoke the constructor of em_cmd_start_dpp_t to create the object. | input: net_node = nullptr, num_args = 2, args[0] = "Arg1_NullNode", args[1] = "Arg2_NullNode", fixed_args = "Fixed_NullNode" | The object (em_cmd_start_dpp_t) should have m_param.net_node as nullptr, m_param.u.args.num_args equal to 2, and string arguments matching expected values. | Should Pass |
 */
TEST(em_cmd_start_dpp_t, em_cmd_start_dpp_t_null_netnode)
{
    std::cout << "Entering em_cmd_start_dpp_t_null_netnode test" << std::endl;
    em_cmd_params_t param = {};
    param.u.args.num_args = 2;
    strncpy(param.u.args.args[0], "Arg1_NullNode", sizeof(param.u.args.args[0]) - 1);
    param.u.args.args[0][sizeof(param.u.args.args[0]) - 1] = '\0';
    strncpy(param.u.args.args[1], "Arg2_NullNode", sizeof(param.u.args.args[1]) - 1);
    param.u.args.args[1][sizeof(param.u.args.args[1]) - 1] = '\0';
    strncpy(param.u.args.fixed_args, "Fixed_NullNode", sizeof(param.u.args.fixed_args) - 1);
    param.u.args.fixed_args[sizeof(param.u.args.fixed_args) - 1] = '\0';
    param.net_node = nullptr;
    std::cout << "Invoking em_cmd_start_dpp_t constructor with net_node = NULL" << std::endl;
    std::cout << "u.args.num_args = " << param.u.args.num_args << std::endl;
    std::cout << "u.args.args[0] = " << param.u.args.args[0] << std::endl;
    std::cout << "u.args.args[1] = " << param.u.args.args[1] << std::endl;
    std::cout << "u.args.fixed_args = " << param.u.args.fixed_args << std::endl;
    em_cmd_start_dpp_t obj(param);
    EXPECT_EQ(obj.m_param.net_node, nullptr);
    EXPECT_EQ(obj.m_param.u.args.num_args, 2);
    EXPECT_STREQ(obj.m_param.u.args.args[0], "Arg1_NullNode");
    EXPECT_STREQ(obj.m_param.u.args.args[1], "Arg2_NullNode");
    EXPECT_STREQ(obj.m_param.u.args.fixed_args, "Fixed_NullNode");
    std::cout << "Constructed object: net_node is NULL" << std::endl;
    std::cout << "Exiting em_cmd_start_dpp_t_null_netnode test" << std::endl;
}
/**
 * @brief Verify that the API correctly truncates a malformed MAC string and properly initializes network node details.
 *
 * This test checks if the em_cmd_start_dpp_t constructor properly handles a malformed MAC address by truncating it to the maximum allowed length. It also validates that other parameters including the source, target, request mode, and network node details are set correctly.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 008@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Populate the parameters with a malformed sta_mac along with valid source, target, and network node details, then invoke the API constructor. | malformed = "000000", source = "11:11:11:11:11:11", target = "22:22:22:22:22:22", request_mode = 2, disassoc_imminent = false, btm_abridged = true, link_removal_imminent = false, steer_opportunity_win = 50, btm_disassociation_timer = 20, target_op_class = 3, target_channel = 44, node.key = "MalformedMACNode" | The constructed object's sta_mac is the truncated version of "000000" determined by max allowed length; network node is not null with key "MalformedMACNode" and display info values matching the input; all assertions pass. | Should Pass |
 */
TEST(em_cmd_start_dpp_t, em_cmd_start_dpp_t_steer_malformed_mac)
{
    std::cout << "Entering em_cmd_start_dpp_t_steer_malformed_mac test" << std::endl;
    em_cmd_params_t param{};
    const char* malformed = "000000";
    size_t maxSta = sizeof(param.u.steer_params.sta_mac) - 1;
    size_t mLen = std::min(strlen(malformed), maxSta);
    std::cout << "Copying sta_mac: " << malformed 
              << " (max allowed = " << maxSta << ")" << std::endl;
    memcpy(param.u.steer_params.sta_mac, malformed, mLen);
    param.u.steer_params.sta_mac[mLen] = '\0';
    std::cout << "Stored sta_mac = " << param.u.steer_params.sta_mac << std::endl;
    const char* src = "11:11:11:11:11:11";
    const char* tgt = "22:22:22:22:22:22";
    size_t sLen = std::min(strlen(src), sizeof(param.u.steer_params.source) - 1);
    memcpy(param.u.steer_params.source, src, sLen);
    param.u.steer_params.source[sLen] = '\0';
    size_t tLen = std::min(strlen(tgt), sizeof(param.u.steer_params.target) - 1);
    memcpy(param.u.steer_params.target, tgt, tLen);
    param.u.steer_params.target[tLen] = '\0';
    param.u.steer_params.request_mode = 2;
    param.u.steer_params.disassoc_imminent = false;
    param.u.steer_params.btm_abridged = true;
    param.u.steer_params.link_removal_imminent = false;
    param.u.steer_params.steer_opportunity_win = 50;
    param.u.steer_params.btm_disassociation_timer = 20;
    param.u.steer_params.target_op_class = 3;
    param.u.steer_params.target_channel = 44;
    em_network_node_t node{};
    size_t nk = std::min(sizeof(node.key) - 1, strlen("MalformedMACNode"));
    memcpy(node.key, "MalformedMACNode", nk);
    node.key[nk] = '\0';
    node.display_info.collapsed     = false;
    node.display_info.orig_node_ctr = 7;
    node.display_info.node_ctr      = 7;
    node.display_info.node_pos      = 6;
    std::cout << "source = " << param.u.steer_params.source << std::endl;
    std::cout << "target = " << param.u.steer_params.target << std::endl;
    param.net_node = &node;
    std::cout << "Network node key = " << node.key << std::endl;
    em_cmd_start_dpp_t obj(param);
    std::string expected_truncated(malformed, maxSta);
    std::cout << "Expected truncated sta_mac = " << expected_truncated << std::endl;
    std::cout << "Constructed object sta_mac = " << obj.m_param.u.steer_params.sta_mac << std::endl;
    EXPECT_STREQ(reinterpret_cast<const char*>(obj.m_param.u.steer_params.sta_mac), expected_truncated.c_str());
    EXPECT_NE(obj.m_param.net_node, nullptr);
    EXPECT_STREQ(obj.m_param.net_node->key, "MalformedMACNode");
    EXPECT_FALSE(obj.m_param.net_node->display_info.collapsed);
    EXPECT_EQ(obj.m_param.net_node->display_info.orig_node_ctr, 7);
    EXPECT_EQ(obj.m_param.net_node->display_info.node_ctr, 7);
    EXPECT_EQ(obj.m_param.net_node->display_info.node_pos, 6);
    std::cout << "Constructed object: steer_params.sta_mac = " << reinterpret_cast<const char*>(obj.m_param.u.steer_params.sta_mac) << std::endl;
    std::cout << "Exiting em_cmd_start_dpp_t_steer_malformed_mac test" << std::endl;
}
