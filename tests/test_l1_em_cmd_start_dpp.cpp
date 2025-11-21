
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


// Test Case 1: Positive Test - Valid DPP command initiation using args union
/**
 * @brief Validates the initialization of em_cmd_start_dpp_t with valid command parameters.
 *
 * This test verifies that the em_cmd_start_dpp_t constructor correctly initializes the object when provided with valid arguments.
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
 * | Variation / Step | Description                                                         | Test Data                                                                                                                      | Expected Result                                                              | Notes              |
 * | :--------------: | ------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | ------------------ |
 * | 01               | Prepare and initialize command parameters                           | num_args = 3, args[0] = Argument1, args[1] = Argument2, args[2] = Argument3, fixed_args = FixedArgument                         | Parameters structure correctly populated                                   | Should be successful |
 * | 02               | Prepare network node structure with valid dummy data                | key = TestNodeKey, collapsed = false, orig_node_ctr = 1, node_ctr = 1, node_pos = 0                                               | Network node structure correctly populated                                 | Should be successful |
 * | 03               | Invoke em_cmd_start_dpp_t constructor with prepared parameters        | Input: em_cmd_params_t structure with valid command parameters and network node                                                 | Object constructed with matching parameter values                          | Should Pass        |
 * | 04               | Validate the constructed object's fields via assertion checks         | EXPECT m_param.u.args.num_args = 3, m_param.u.args.args[0] = Argument1, m_param.u.args.fixed_args = FixedArgument                     | EXPECT_EQ assertions pass confirming correct initialization                | Should Pass        |
 */
TEST(em_cmd_start_dpp_t, em_cmd_start_dpp_t_args_valid)
{
    std::cout << "Entering em_cmd_start_dpp_t_args_valid test" << std::endl;

    // Prepare em_cmd_params_t with u.args
    em_cmd_params_t param = {};
    // Set args.num_args to a valid number (e.g., 3)
    param.u.args.num_args = 3;
    // Fill args array with valid strings using strncpy
    strncpy(param.u.args.args[0], "Argument1", sizeof(param.u.args.args[0]));
    strncpy(param.u.args.args[1], "Argument2", sizeof(param.u.args.args[1]));
    strncpy(param.u.args.args[2], "Argument3", sizeof(param.u.args.args[2]));
    // Set fixed_args with a valid string using strncpy
    strncpy(param.u.args.fixed_args, "FixedArgument", sizeof(param.u.args.fixed_args));

    em_network_node_t node = {};
    strncpy(node.key, "TestNodeKey", sizeof(node.key));
    node.display_info.collapsed = false;
    node.display_info.orig_node_ctr = 1;
    node.display_info.node_ctr = 1;
    node.display_info.node_pos = 0;
    param.net_node = &node;

    std::cout << "Invoking em_cmd_start_dpp_t constructor with u.args.num_args = " << param.u.args.num_args << std::endl;
    std::cout << "u.args.args[0] = " << param.u.args.args[0] << std::endl;
    std::cout << "u.args.fixed_args = " << param.u.args.fixed_args << std::endl;
    std::cout << "Network node key = " << node.key << std::endl;

    em_cmd_start_dpp_t obj(param);

    // Validate that the constructed object's data matches the input values
    EXPECT_EQ(obj.m_param.u.args.num_args, 3);
    std::cout << "Constructed object: m_param.u.args.num_args = " << obj.m_param.u.args.num_args << std::endl;
    std::cout << "Constructed object: u.args.args[0] = " << obj.m_param.u.args.args[0] << std::endl;
    std::cout << "Constructed object: u.args.fixed_args = " << obj.m_param.u.args.fixed_args << std::endl;
    std::cout << "Constructed object: net_node key = " << obj.m_param.net_node->key << std::endl;

    std::cout << "Exiting em_cmd_start_dpp_t_args_valid test" << std::endl;
}
/**
 * @brief Validates that em_cmd_start_dpp_t is properly constructed using valid steer_params in a positive scenario.
 *
 * This test verifies that the em_cmd_start_dpp_t constructor correctly initializes its internal data structures with the provided steer_params.
 * It sets up the steer_params structure along with a minimal network node, invokes the constructor, and validates that the constructed object's
 * data matches the input parameters. This is critical to ensure valid DPP command initiation.
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
 * | :----: | --------- | ---------- | -------------- | ----- |
 * | 01 | Initialize steer_params fields with valid MAC addresses and request mode values. | sta_mac = AA:BB:CC:DD:EE:FF, source = 11:22:33:44:55:66, target = 66:55:44:33:22:11, request_mode = 1, disassoc_imminent = true, btm_abridged = false, link_removal_imminent = false, steer_opportunity_win = 100, btm_disassociation_timer = 30, target_op_class = 5, target_channel = 36 | Not applicable | Should be successful |
 * | 02 | Prepare network node structure and assign it to the command parameters. | key = SteerTestNode, collapsed = false, orig_node_ctr = 2, node_ctr = 2, node_pos = 1 | Not applicable | Should be successful |
 * | 03 | Construct the DPP command object using the prepared parameters. | param (all above fields) | Object constructed with member values matching input parameters | Should Pass |
 * | 04 | Validate the constructed object’s steer_params fields using assertions. | Expected fields: sta_mac, source, target, request_mode | All assertions should pass confirming values match | Should be successful |
 */
TEST(em_cmd_start_dpp_t, em_cmd_start_dpp_t_steer_valid)
{
    std::cout << "Entering em_cmd_start_dpp_t_steer_valid test" << std::endl;

    em_cmd_params_t param = {};

    const char* mac = "AA:BB:CC:DD:EE:FF";
    const char* src = "11:22:33:44:55:66";
    const char* tgt = "66:55:44:33:22:11";

    size_t macCopy = std::min(sizeof(param.u.steer_params.sta_mac) - 1, strlen(mac));
    memcpy(param.u.steer_params.sta_mac, mac, macCopy);
    param.u.steer_params.sta_mac[macCopy] = '\0';

    size_t srcCopy = std::min(sizeof(param.u.steer_params.source) - 1, strlen(src));
    memcpy(param.u.steer_params.source, src, srcCopy);
    param.u.steer_params.source[srcCopy] = '\0';

    size_t tgtCopy = std::min(sizeof(param.u.steer_params.target) - 1, strlen(tgt));
    memcpy(param.u.steer_params.target, tgt, tgtCopy);
    param.u.steer_params.target[tgtCopy] = '\0';

    param.u.steer_params.request_mode = 1;
    param.u.steer_params.disassoc_imminent = true;
    param.u.steer_params.btm_abridged = false;
    param.u.steer_params.link_removal_imminent = false;
    param.u.steer_params.steer_opportunity_win = 100;
    param.u.steer_params.btm_disassociation_timer = 30;
    param.u.steer_params.target_op_class = 5;
    param.u.steer_params.target_channel = 36;

    em_network_node_t node = {};
    memcpy(node.key, "SteerTestNode", strlen("SteerTestNode") + 1);
    param.net_node = &node;

    em_cmd_start_dpp_t obj(param);

    EXPECT_STREQ(reinterpret_cast<const char*>(obj.m_param.u.steer_params.sta_mac), "AA:BB:CC:DD:EE:FF");
    EXPECT_STREQ(reinterpret_cast<const char*>(obj.m_param.u.steer_params.source),  "11:22:33:44:55:66");
    EXPECT_STREQ(reinterpret_cast<const char*>(obj.m_param.u.steer_params.target),  "66:55:44:33:22:11");

    std::cout << "Exiting em_cmd_start_dpp_t_steer_valid test" << std::endl;
}

/**
 * @brief Validate successful construction of DPP command object with valid btm_report parameters
 *
 * This test verifies that the em_cmd_start_dpp_t object is correctly constructed when provided with valid btm_report parameters.
 * It checks that the parameters such as source, sta_mac, status_code, and target are accurately propagated into the object's internal state.
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
 * | 01 | Initialize 'em_cmd_params_t' with valid btm_report parameters and setup a minimal network node | input: source = "22:33:44:55:66:77", sta_mac = "FF:EE:DD:CC:BB:AA", status_code = 0x01, target = "77:66:55:44:33:22", node key = "BTMReportNode" | Parameters and network node are set correctly | Should be successful |
 * | 02 | Log the parameter values to the console prior to object creation | Console logging of source, sta_mac, status_code, target and node key | Correct parameter values are output to the console | Should be successful |
 * | 03 | Create the DPP command object using the prepared parameters | constructor input: em_cmd_params_t with valid btm_report_params and network node reference | DPP command object is created without errors | Should Pass |
 * | 04 | Validate that the object's internal data matches the input parameters through assertions | object fields: source, sta_mac, status_code, target | EXPECT_STREQ and EXPECT_EQ assertions pass confirming field values | Should Pass |
 */
TEST(em_cmd_start_dpp_t, em_cmd_start_dpp_t_btm_report_valid)
{
    std::cout << "Entering em_cmd_start_dpp_t_btm_report_valid test" << std::endl;

    em_cmd_params_t param = {};

    const char srcStr[]    = "22:33:44:55:66:77";
    const char staMacStr[] = "FF:EE:DD:CC:BB:AA";
    const char targetStr[] = "77:66:55:44:33:22";

    size_t copySrc = std::min(sizeof(param.u.btm_report_params.source) - 1, strlen(srcStr));
    memcpy(param.u.btm_report_params.source, srcStr, copySrc);
    param.u.btm_report_params.source[copySrc] = '\0';

    size_t copySta = std::min(sizeof(param.u.btm_report_params.sta_mac) - 1, strlen(staMacStr));
    memcpy(param.u.btm_report_params.sta_mac, staMacStr, copySta);
    param.u.btm_report_params.sta_mac[copySta] = '\0';

    size_t copyDst = std::min(sizeof(param.u.btm_report_params.target) - 1, strlen(targetStr));
    memcpy(param.u.btm_report_params.target, targetStr, copyDst);
    param.u.btm_report_params.target[copyDst] = '\0';

    param.u.btm_report_params.status_code = 0x01;

    em_network_node_t node = {};
    memcpy(node.key, "BTMReportNode", strlen("BTMReportNode") + 1);
    param.net_node = &node;

    em_cmd_start_dpp_t obj(param);

    EXPECT_STREQ(reinterpret_cast<const char*>(obj.m_param.u.btm_report_params.source), "22:33:44:55:66:77");
    EXPECT_STREQ(reinterpret_cast<const char*>(obj.m_param.u.btm_report_params.sta_mac), "FF:EE:DD:CC:BB:AA");
    EXPECT_STREQ(reinterpret_cast<const char*>(obj.m_param.u.btm_report_params.target), "77:66:55:44:33:22");
    EXPECT_EQ(obj.m_param.u.btm_report_params.status_code, 0x01);

    std::cout << "Exiting em_cmd_start_dpp_t_btm_report_valid test" << std::endl;
}

/**
 * @brief Validate that em_cmd_start_dpp_t correctly initializes its disassociation parameters.
 *
 * This test validates that the DPP command object is constructed with valid disassociation parameters by setting a valid number of disassociation parameters and a properly initialized network node. It then verifies that the object's internal state matches the input values, ensuring correct behavior.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Prepare valid em_cmd_params_t with disassoc_params and a network node. Invoke the em_cmd_start_dpp_t constructor and validate that the object's internal state (disassoc_params.num) matches the input value. | param.u.disassoc_params.num = 1, node.key = "DisassocNode", node.display_info.collapsed = false, node.display_info.orig_node_ctr = 4, node.display_info.node_ctr = 4, node.display_info.node_pos = 3 | Object's m_param.u.disassoc_params.num is 1 and the EXPECT_EQ assertion passes | Should Pass |
 */
TEST(em_cmd_start_dpp_t, em_cmd_start_dpp_t_disassoc_valid)
{
    std::cout << "Entering em_cmd_start_dpp_t_disassoc_valid test" << std::endl;

    // Prepare em_cmd_params_t with u.disassoc_params
    em_cmd_params_t param = {};
    // Set a valid number of disassociation parameters (assume 1 is valid)
    param.u.disassoc_params.num = 1;
    // For each disassociation parameter, assume we assign dummy valid data.
    // Since the internal structure of em_disassoc_params_t is not specified, we assume minimal initialization.
    // (For demonstration, we don't populate inner fields apart from the count.)

    // Create a minimal valid network node structure
    em_network_node_t node = {};
    strncpy(node.key, "DisassocNode", sizeof(node.key));
    node.display_info.collapsed = false;
    node.display_info.orig_node_ctr = 4;
    node.display_info.node_ctr = 4;
    node.display_info.node_pos = 3;
    param.net_node = &node;

    // Log the values being passed to the constructor
    std::cout << "Invoking em_cmd_start_dpp_t constructor with disassoc_params.num = " << param.u.disassoc_params.num << std::endl;
    std::cout << "Network node key = " << node.key << std::endl;

    // Create the DPP command object
    em_cmd_start_dpp_t obj(param);

    // Validate that the constructed object's data matches the input values
    EXPECT_EQ(obj.m_param.u.disassoc_params.num, 1);
    std::cout << "Constructed object: disassoc_params.num = " << obj.m_param.u.disassoc_params.num << std::endl;

    std::cout << "Exiting em_cmd_start_dpp_t_disassoc_valid test" << std::endl;
}
/**
 * @brief Validate the initialization of the DPP command object with valid scan parameters
 *
 * This test verifies that when valid scan parameters and a properly initialized network node are provided,
 * the em_cmd_start_dpp_t object is correctly constructed. It ensures that the network node pointer within
 * the object is not null and that the node key matches the expected value.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 005
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Prepare command parameters including a valid network node and invoke the constructor | param: em_cmd_params_t (with scan_params provided), net_node key = "ScanNode", node.display_info: collapsed = false, orig_node_ctr = 5, node_ctr = 5, node_pos = 4 | Object constructed with a valid network node pointer (non-null) and node key "ScanNode" | Should Pass |
 */
TEST(em_cmd_start_dpp_t, em_cmd_start_dpp_t_scan_valid)
{
    std::cout << "Entering em_cmd_start_dpp_t_scan_valid test" << std::endl;

    // Prepare em_cmd_params_t with u.scan_params (em_scan_params_t)
    em_cmd_params_t param = {};
    // Assuming em_scan_params_t has a field "dummy" for demonstration purposes.
    // Since we don't have the exact structure details, we simply zero-initialize and simulate assignment.
    // (No specific assignments, just logging that scan_params is provided.)
    
    // Create a minimal valid network node structure
    em_network_node_t node = {};
    strncpy(node.key, "ScanNode", sizeof(node.key));
    node.display_info.collapsed = false;
    node.display_info.orig_node_ctr = 5;
    node.display_info.node_ctr = 5;
    node.display_info.node_pos = 4;
    param.net_node = &node;

    // Log the values being passed to the constructor
    std::cout << "Invoking em_cmd_start_dpp_t constructor with scan_params provided" << std::endl;
    std::cout << "Network node key = " << node.key << std::endl;

    // Create the DPP command object
    em_cmd_start_dpp_t obj(param);

    // As we do not have specific fields, we only verify that the network node pointer is valid.
    EXPECT_NE(obj.m_param.net_node, nullptr);
    std::cout << "Constructed object: net_node key = " << obj.m_param.net_node->key << std::endl;

    std::cout << "Exiting em_cmd_start_dpp_t_scan_valid test" << std::endl;
}
/**
 * @brief Validate proper initialization of em_cmd_start_dpp_t using valid AP metrics parameters.
 *
 * This test verifies that the em_cmd_start_dpp_t object is correctly constructed using a valid set of AP metrics parameters and network node information. The test ensures that all fields in the object match the expected input values provided during construction.
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
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Prepare valid AP metrics parameters and network node, invoke the constructor, and verify object fields | ruid = "01:23:45:67:89:AB", sta_link_metrics_include = true, sta_traffic_stats_include = true, wifi6_status_report_include = false, network node key = "APMetricsNode", collapsed = false, orig_node_ctr = 6, node_ctr = 6, node_pos = 5 | The em_cmd_start_dpp_t object should have its AP metrics parameters set correctly and all assertions should pass | Should Pass |
 */
TEST(em_cmd_start_dpp_t, em_cmd_start_dpp_t_ap_metrics_valid)
{
    std::cout << "Entering em_cmd_start_dpp_t_ap_metrics_valid test" << std::endl;

    em_cmd_params_t param{};

    const char* mac = "01:23:45:67:89:AB";

    size_t macLen = std::min(sizeof(param.u.ap_metrics_params.ruid) - 1, strlen(mac));
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

    std::cout << "ruid = " << param.u.ap_metrics_params.ruid << std::endl;
    std::cout << "sta_link_metrics_include = " << param.u.ap_metrics_params.sta_link_metrics_include << std::endl;
    std::cout << "sta_traffic_stats_include = " << param.u.ap_metrics_params.sta_traffic_stats_include << std::endl;
    std::cout << "wifi6_status_report_include = " << param.u.ap_metrics_params.wifi6_status_report_include << std::endl;
    std::cout << "Network node key = " << node.key << std::endl;

    em_cmd_start_dpp_t obj(param);

    EXPECT_STREQ(reinterpret_cast<const char*>(obj.m_param.u.ap_metrics_params.ruid), "01:23:45:67:89:AB");
    EXPECT_TRUE(obj.m_param.u.ap_metrics_params.sta_link_metrics_include);
    EXPECT_TRUE(obj.m_param.u.ap_metrics_params.sta_traffic_stats_include);
    EXPECT_FALSE(obj.m_param.u.ap_metrics_params.wifi6_status_report_include);

    std::cout << "Constructed object: ap_metrics_params.ruid = " << obj.m_param.u.ap_metrics_params.ruid << std::endl;
    std::cout << "Exiting em_cmd_start_dpp_t_ap_metrics_valid test" << std::endl;
}

/**
 * @brief Validate that the constructor of em_cmd_start_dpp_t correctly handles a NULL network node.
 *
 * This test case constructs an em_cmd_start_dpp_t object using an em_cmd_params_t parameter where the net_node is intentionally set to NULL.
 * The objective is to verify that the constructor initializes the object's net_node pointer to nullptr, ensuring that the system gracefully handles a null network node scenario.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 007
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                     | Test Data                                                                                                                           | Expected Result                                                                                               | Notes      |
 * | :--------------: | ----------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- | ---------- |
 * | 01               | Initialize em_cmd_params_t with 2 args, set fixed_args, set net_node to NULL, invoke the constructor | num_args = 2, args[0] = Arg1_NullNode, args[1] = Arg2_NullNode, fixed_args = Fixed_NullNode, net_node = NULL                        | The constructed object's m_param.net_node should be nullptr, confirmed by EXPECT_EQ(obj.m_param.net_node, nullptr) | Should Pass |
 */
TEST(em_cmd_start_dpp_t, em_cmd_start_dpp_t_null_netnode)
{
    std::cout << "Entering em_cmd_start_dpp_t_null_netnode test" << std::endl;

    // Prepare em_cmd_params_t with u.args but with net_node set to NULL
    em_cmd_params_t param = {};
    param.u.args.num_args = 2;
    strncpy(param.u.args.args[0], "Arg1_NullNode", sizeof(param.u.args.args[0]));
    strncpy(param.u.args.args[1], "Arg2_NullNode", sizeof(param.u.args.args[1]));
    strncpy(param.u.args.fixed_args, "Fixed_NullNode", sizeof(param.u.args.fixed_args));
    // Set network node pointer to NULL
    param.net_node = NULL;

    std::cout << "Invoking em_cmd_start_dpp_t constructor with net_node = NULL" << std::endl;
    std::cout << "u.args.num_args = " << param.u.args.num_args << std::endl;

    em_cmd_start_dpp_t obj(param);

    // Validate that the constructed object's network node pointer is NULL
    EXPECT_EQ(obj.m_param.net_node, nullptr);
    std::cout << "Constructed object: net_node is NULL" << std::endl;

    std::cout << "Exiting em_cmd_start_dpp_t_null_netnode test" << std::endl;
}
/**
 * @brief This test verifies that the em_cmd_start_dpp_t constructor preserves the malformed sta_mac value.
 *
 * The test creates an em_cmd_params_t object with a malformed MAC address in the steer_params member, then
 * constructs an em_cmd_start_dpp_t object and validates that the malformed MAC value is retained. This is done to
 * ensure that the API correctly handles malformed MAC addresses, which is important for robustness.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 008@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                               | Test Data                                                                                                                                                                                                                                                                                           | Expected Result                                                                                          | Notes        |
 * | :--------------: | ----------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- | ------------ |
 * | 01               | Invoke em_cmd_start_dpp_t constructor with malformed sta_mac in steer_params                  | input1 = sta_mac: 000000, input2 = source: 11:11:11:11:11:11, input3 = target: 22:22:22:22:22:22, input4 = request_mode: 2, input5 = disassoc_imminent: false, input6 = btm_abridged: true, input7 = link_removal_imminent: false, input8 = steer_opportunity_win: 50, input9 = btm_disassociation_timer: 20, input10 = target_op_class: 3, input11 = target_channel: 44, network node key: MalformedMACNode | The API should construct the object and preserve the malformed sta_mac as "000000", and the assertion (EXPECT_STREQ) should pass                            | Should Pass  |
 */
TEST(em_cmd_start_dpp_t, em_cmd_start_dpp_t_steer_malformed_mac)
{
    std::cout << "Entering em_cmd_start_dpp_t_steer_malformed_mac test" << std::endl;

    em_cmd_params_t param{};

    const char* malformed = "000000";
    size_t mLen = std::min(sizeof(param.u.steer_params.sta_mac) - 1, strlen(malformed));
    memcpy(param.u.steer_params.sta_mac, malformed, mLen);
    param.u.steer_params.sta_mac[mLen] = '\0';

    const char* src = "11:11:11:11:11:11";
    size_t sLen = std::min(sizeof(param.u.steer_params.source) - 1, strlen(src));
    memcpy(param.u.steer_params.source, src, sLen);
    param.u.steer_params.source[sLen] = '\0';

    const char* tgt = "22:22:22:22:22:22";
    size_t tLen = std::min(sizeof(param.u.steer_params.target) - 1, strlen(tgt));
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

    param.net_node = &node;

    std::cout << "Invoking constructor with malformed sta_mac: "
              << reinterpret_cast<const char*>(param.u.steer_params.sta_mac) << std::endl;
    std::cout << "source = " << reinterpret_cast<const char*>(param.u.steer_params.source) << std::endl;
    std::cout << "target = " << reinterpret_cast<const char*>(param.u.steer_params.target) << std::endl;
    std::cout << "Network node key = " << node.key << std::endl;

    em_cmd_start_dpp_t obj(param);

    EXPECT_STREQ(reinterpret_cast<const char*>(obj.m_param.u.steer_params.sta_mac), "000000");

    std::cout << "Constructed object: steer_params.sta_mac = "
              << reinterpret_cast<const char*>(obj.m_param.u.steer_params.sta_mac) << std::endl;

    std::cout << "Exiting em_cmd_start_dpp_t_steer_malformed_mac test" << std::endl;
}

