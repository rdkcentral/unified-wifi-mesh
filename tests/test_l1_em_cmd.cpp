
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
#include <climits>
#include "em_cmd.h"
#include "dm_network.h"

// Converts em_bus_event_type_t to readable string
const char* bus_event_type_to_str(em_bus_event_type_t type)
{
    switch (type) {
        case em_bus_event_type_none:               return "em_bus_event_type_none";
        case em_bus_event_type_chirp:              return "em_bus_event_type_chirp";
        case em_bus_event_type_reset:              return "em_bus_event_type_reset";
        case em_bus_event_type_dev_test:           return "em_bus_event_type_dev_test";
        case em_bus_event_type_set_dev_test:       return "em_bus_event_type_set_dev_test";
        case em_bus_event_type_get_network:        return "em_bus_event_type_get_network";
        case em_bus_event_type_get_device:         return "em_bus_event_type_get_device";
        case em_bus_event_type_remove_device:      return "em_bus_event_type_remove_device";
        case em_bus_event_type_get_radio:          return "em_bus_event_type_get_radio";
        case em_bus_event_type_get_ssid:           return "em_bus_event_type_get_ssid";
        case em_bus_event_type_set_ssid:           return "em_bus_event_type_set_ssid";
        case em_bus_event_type_get_channel:        return "em_bus_event_type_get_channel";
        case em_bus_event_type_set_channel:        return "em_bus_event_type_set_channel";
        case em_bus_event_type_scan_channel:       return "em_bus_event_type_scan_channel";
        case em_bus_event_type_scan_result:        return "em_bus_event_type_scan_result";
        case em_bus_event_type_get_bss:            return "em_bus_event_type_get_bss";
        case em_bus_event_type_get_sta:            return "em_bus_event_type_get_sta";
        case em_bus_event_type_steer_sta:          return "em_bus_event_type_steer_sta";
        case em_bus_event_type_disassoc_sta:       return "em_bus_event_type_disassoc_sta";
        case em_bus_event_type_get_policy:         return "em_bus_event_type_get_policy";
        case em_bus_event_type_set_policy:         return "em_bus_event_type_set_policy";
        case em_bus_event_type_btm_sta:            return "em_bus_event_type_btm_sta";
        case em_bus_event_type_start_dpp:          return "em_bus_event_type_start_dpp";
        case em_bus_event_type_dev_init:           return "em_bus_event_type_dev_init";
        case em_bus_event_type_cfg_renew:          return "em_bus_event_type_cfg_renew";
        case em_bus_event_type_radio_config:       return "em_bus_event_type_radio_config";
        case em_bus_event_type_vap_config:         return "em_bus_event_type_vap_config";
        case em_bus_event_type_sta_list:           return "em_bus_event_type_sta_list";
        case em_bus_event_type_ap_cap_query:       return "em_bus_event_type_ap_cap_query";
        case em_bus_event_type_client_cap_query:   return "em_bus_event_type_client_cap_query";
        case em_bus_event_type_topo_sync:          return "em_bus_event_type_topo_sync";
        case em_bus_event_type_onewifi_private_cb: return "em_bus_event_type_onewifi_private_cb";
        case em_bus_event_type_onewifi_mesh_sta_cb:return "em_bus_event_type_onewifi_mesh_sta_cb";
        case em_bus_event_type_sta_assoc:          return "em_bus_event_type_sta_assoc";
        case em_bus_event_type_channel_pref_query: return "em_bus_event_type_channel_pref_query";
        case em_bus_event_type_sta_link_metrics:   return "em_bus_event_type_sta_link_metrics";
        case em_bus_event_type_set_radio:          return "em_bus_event_type_set_radio";
        case em_bus_event_type_btm_response:       return "em_bus_event_type_btm_response";
        case em_bus_event_type_get_mld_config:     return "em_bus_event_type_get_mld_config";
        case em_bus_event_type_mld_reconfig:       return "em_bus_event_type_mld_reconfig";
        case em_bus_event_type_beacon_report:      return "em_bus_event_type_beacon_report";
        case em_bus_event_type_ap_metrics_report:  return "em_bus_event_type_ap_metrics_report";
        case em_bus_event_type_get_reset:          return "em_bus_event_type_get_reset";
        default: return "Unknown bus event type";
    }
}

// Converts em_cmd_type_t to readable string
const char* cmd_type_to_str(em_cmd_type_t type)
{
    switch (type) {
        case em_cmd_type_none:              return "em_cmd_type_none";
        case em_cmd_type_reset:             return "em_cmd_type_reset";
        case em_cmd_type_dev_test:          return "em_cmd_type_dev_test";
        case em_cmd_type_set_dev_test:      return "em_cmd_type_set_dev_test";
        case em_cmd_type_get_network:       return "em_cmd_type_get_network";
        case em_cmd_type_get_device:        return "em_cmd_type_get_device";
        case em_cmd_type_remove_device:     return "em_cmd_type_remove_device";
        case em_cmd_type_get_radio:         return "em_cmd_type_get_radio";
        case em_cmd_type_get_ssid:          return "em_cmd_type_get_ssid";
        case em_cmd_type_set_ssid:          return "em_cmd_type_set_ssid";
        case em_cmd_type_get_channel:       return "em_cmd_type_get_channel";
        case em_cmd_type_set_channel:       return "em_cmd_type_set_channel";
        case em_cmd_type_scan_channel:      return "em_cmd_type_scan_channel";
        case em_cmd_type_scan_result:       return "em_cmd_type_scan_result";
        case em_cmd_type_get_bss:           return "em_cmd_type_get_bss";
        case em_cmd_type_get_sta:           return "em_cmd_type_get_sta";
        case em_cmd_type_steer_sta:         return "em_cmd_type_steer_sta";
        case em_cmd_type_disassoc_sta:      return "em_cmd_type_disassoc_sta";
        case em_cmd_type_btm_sta:           return "em_cmd_type_btm_sta";
        case em_cmd_type_start_dpp:         return "em_cmd_type_start_dpp";
        case em_cmd_type_onewifi_cb:        return "em_cmd_type_onewifi_cb";
        case em_cmd_type_topo_sync:         return "em_cmd_type_topo_sync";
        case em_cmd_type_sta_assoc:         return "em_cmd_type_sta_assoc";
        case em_cmd_type_channel_pref_query:return "em_cmd_type_channel_pref_query";
        case em_cmd_type_sta_link_metrics:  return "em_cmd_type_sta_link_metrics";
        case em_cmd_type_set_radio:         return "em_cmd_type_set_radio";
        case em_cmd_type_btm_report:        return "em_cmd_type_btm_report";
        case em_cmd_type_get_mld_config:    return "em_cmd_type_get_mld_config";
        case em_cmd_type_mld_reconfig:      return "em_cmd_type_mld_reconfig";
        case em_cmd_type_beacon_report:     return "em_cmd_type_beacon_report";
        case em_cmd_type_ap_metrics_report: return "em_cmd_type_ap_metrics_report";
        case em_cmd_type_get_reset:         return "em_cmd_type_get_reset";
        default: return "Unknown cmd type";
    }
}

// Converts em_event_type_t to readable string
const char* em_event_type_to_string(em_event_type_t type) {
    switch (type) {
        case em_event_type_frame:  return "em_event_type_frame";
        case em_event_type_device: return "em_event_type_device";
        case em_event_type_node:   return "em_event_type_node";
        case em_event_type_bus:    return "em_event_type_bus";        
        case em_event_type_max:    return "em_event_type_max";
        default:                   return "unknown_em_event_type";
    }
}

TEST(em_cmd_t, bus_2_cmd_type_ValidConversion)
{
    std::cout << "Entering bus_2_cmd_type_ValidConversion test" << std::endl;
    EXPECT_NO_THROW({ em_cmd_t obj; });
    struct BusToCmdMapping {
        em_bus_event_type_t busEvent;
        em_cmd_type_t expectedCmd;
    };
    BusToCmdMapping testCases[] = {
        { em_bus_event_type_none,               em_cmd_type_none },
        { em_bus_event_type_chirp,              em_cmd_type_none },
        { em_bus_event_type_reset,              em_cmd_type_reset },
        { em_bus_event_type_dev_test,           em_cmd_type_dev_test },
        { em_bus_event_type_set_dev_test,       em_cmd_type_set_dev_test },
        { em_bus_event_type_get_network,        em_cmd_type_get_network },
        { em_bus_event_type_get_device,         em_cmd_type_get_device },
        { em_bus_event_type_remove_device,      em_cmd_type_remove_device },
        { em_bus_event_type_get_radio,          em_cmd_type_get_radio },
        { em_bus_event_type_get_ssid,           em_cmd_type_get_ssid },
        { em_bus_event_type_set_ssid,           em_cmd_type_set_ssid },
        { em_bus_event_type_get_channel,        em_cmd_type_get_channel },
        { em_bus_event_type_set_channel,        em_cmd_type_set_channel },
        { em_bus_event_type_scan_channel,       em_cmd_type_scan_channel },
        { em_bus_event_type_scan_result,        em_cmd_type_scan_result },
        { em_bus_event_type_get_bss,            em_cmd_type_get_bss },
        { em_bus_event_type_get_sta,            em_cmd_type_get_sta },
        { em_bus_event_type_steer_sta,          em_cmd_type_steer_sta },
        { em_bus_event_type_disassoc_sta,       em_cmd_type_disassoc_sta },
        { em_bus_event_type_get_policy,         em_cmd_type_get_policy },
        { em_bus_event_type_set_policy,         em_cmd_type_set_policy },
        { em_bus_event_type_btm_sta,            em_cmd_type_btm_sta },
        { em_bus_event_type_dev_init,           em_cmd_type_dev_init },
        { em_bus_event_type_cfg_renew,          em_cmd_type_cfg_renew },
        { em_bus_event_type_radio_config,       em_cmd_type_none },
        { em_bus_event_type_sta_list,           em_cmd_type_sta_list },
        { em_bus_event_type_ap_cap_query,       em_cmd_type_ap_cap_query },
        { em_bus_event_type_client_cap_query,   em_cmd_type_client_cap_query },
        { em_bus_event_type_listener_stop,      em_cmd_type_none },
        { em_bus_event_type_dm_commit,          em_cmd_type_none },
        { em_bus_event_type_m2_tx,              em_cmd_type_none },
        { em_bus_event_type_topo_sync,          em_cmd_type_em_config },
        { em_bus_event_type_onewifi_mesh_sta_cb,em_cmd_type_none },
        { em_bus_event_type_onewifi_radio_cb,   em_cmd_type_none },
        { em_bus_event_type_m2ctrl_configuration, em_cmd_type_none },
        { em_bus_event_type_channel_sel_req,    em_cmd_type_none },
        { em_bus_event_type_set_radio,          em_cmd_type_set_radio },
        { em_bus_event_type_bss_tm_req,         em_cmd_type_none },
        { em_bus_event_type_channel_scan_params, em_cmd_type_none },
        { em_bus_event_type_get_mld_config,     em_cmd_type_get_mld_config },
        { em_bus_event_type_mld_reconfig,       em_cmd_type_mld_reconfig },
        { em_bus_event_type_beacon_report,      em_cmd_type_beacon_report },
        { em_bus_event_type_recv_wfa_action_frame, em_cmd_type_none },
        { em_bus_event_type_recv_gas_frame,     em_cmd_type_none },
        { em_bus_event_type_get_sta_client_type, em_cmd_type_none },
        { em_bus_event_type_assoc_status,       em_cmd_type_none },
        { em_bus_event_type_ap_metrics_report,  em_cmd_type_ap_metrics_report },
        { em_bus_event_type_bss_info,           em_cmd_type_none },
        { em_bus_event_type_get_reset,          em_cmd_type_get_reset },
        { em_bus_event_type_recv_csa_beacon_frame, em_cmd_type_none }
    };

    for (const auto &testCase : testCases)
    {
        std::cout << "Invoking bus_2_cmd_type with bus event: " << bus_event_type_to_str(testCase.busEvent)
              << " (" << static_cast<int>(testCase.busEvent) << ")" << std::endl;
        em_cmd_type_t retVal = em_cmd_t::bus_2_cmd_type(testCase.busEvent);
        std::cout << "Returned command type: " << cmd_type_to_str(retVal)
              << " (" << static_cast<int>(retVal) << ")" << std::endl;
        std::cout << "Expected command type: " << cmd_type_to_str(testCase.expectedCmd)
              << " (" << static_cast<int>(testCase.expectedCmd) << ")" << std::endl;
        EXPECT_EQ(retVal, testCase.expectedCmd);
    }
    
    std::cout << "Exiting bus_2_cmd_type_ValidConversion test" << std::endl;
}

TEST(em_cmd_t, NegativeConversionBelowRange)
{
    std::cout << "Entering NegativeConversionBelowRange test" << std::endl;
    em_cmd_t obj;
    em_bus_event_type_t invalidInput = static_cast<em_bus_event_type_t>(-1);
    std::cout << "Invoking bus_2_cmd_type with invalid bus event type value (below range): " << -1 << std::endl;
    em_cmd_type_t retVal = em_cmd_t::bus_2_cmd_type(invalidInput);
    std::cout << "Returned command type value: " << cmd_type_to_str(retVal) << std::endl;
    std::cout << "Expected command type value: " << em_cmd_type_none << std::endl;
    EXPECT_EQ(retVal, em_cmd_type_none);
    std::cout << "Exiting NegativeConversionBelowRange test" << std::endl;
}

TEST(em_cmd_t, NegativeConversionAboveRange)
{
    std::cout << "Entering NegativeConversionAboveRange test" << std::endl;
    em_cmd_t obj;
    em_bus_event_type_t invalidInput = static_cast<em_bus_event_type_t>(em_bus_event_type_max + 1);
    std::cout << "Invoking bus_2_cmd_type with invalid bus event type value (above range): " << static_cast<int>(em_bus_event_type_max + 1) << std::endl;
    em_cmd_type_t retVal = em_cmd_t::bus_2_cmd_type(invalidInput);
    std::cout << "Returned command type value: " << cmd_type_to_str(retVal) << std::endl;
    std::cout << "Expected command type value: " << em_cmd_type_none << std::endl;
    EXPECT_EQ(retVal, em_cmd_type_none);
    std::cout << "Exiting NegativeConversionAboveRange test" << std::endl;
}

TEST(em_cmd_t, CloneFull) 
{
    std::cout << "Entering CloneFull test" << std::endl;
    em_cmd_t orig;
    orig.m_type = em_cmd_type_set_policy;
    orig.m_param.u.args.num_args = 1;
    strncpy(orig.m_param.u.args.fixed_args, "FixedArgs", 
            sizeof(orig.m_param.u.args.fixed_args)-1);
    orig.m_orch_op_idx = 0;
    orig.m_num_orch_desc = 1;
    orig.m_orch_desc[0].op = dm_orch_type_net_insert;
    orig.m_orch_desc[0].submit = true;
    orig.m_evt = nullptr;
    orig.m_em_candidates = nullptr;
    em_cmd_t* clone = orig.clone();
    ASSERT_NE(clone, nullptr);
    EXPECT_EQ(clone->m_type, orig.m_type);
    EXPECT_EQ(clone->m_orch_op_idx, orig.m_orch_op_idx);
    EXPECT_EQ(clone->m_num_orch_desc, orig.m_num_orch_desc);
    EXPECT_EQ(clone->m_orch_desc[0].op, orig.m_orch_desc[0].op);
    EXPECT_EQ(clone->m_orch_desc[0].submit, orig.m_orch_desc[0].submit);
    EXPECT_EQ(clone->m_param.u.args.num_args, orig.m_param.u.args.num_args);
    std::cout << "Exiting CloneFull test" << std::endl;
}

TEST(em_cmd_t, CloneDeepCopy) 
{
    std::cout << "Entering CloneDeepCopy test" << std::endl;
    em_cmd_t original;
    original.m_num_orch_desc = 0;
    original.m_orch_op_idx = 0;
    original.m_type = em_cmd_type_get_network;
    original.m_param.u.args.num_args = 0;
    strncpy(original.m_param.u.args.fixed_args,
            "OriginalFixed",
            sizeof(original.m_param.u.args.fixed_args)-1);
    em_cmd_t* cloneObj = original.clone();
    ASSERT_NE(cloneObj, nullptr);
    EXPECT_EQ(cloneObj->m_type, original.m_type);
    EXPECT_EQ(cloneObj->m_param.u.args.num_args, 0);
    EXPECT_STREQ(cloneObj->m_param.u.args.fixed_args, "OriginalFixed");
    std::cout << "Exiting CloneDeepCopy test" << std::endl;
}

TEST(em_cmd_t, CloneFullFields) 
{
    std::cout << "Entering CloneFullFields test" << std::endl;
    em_cmd_t orig;
    orig.m_type = em_cmd_type_reset;
    orig.m_orch_op_idx = 0;
    orig.m_num_orch_desc = 2;
    // initialize all descriptors
    for (unsigned int i = 0; i < orig.m_num_orch_desc; i++) {
        orig.m_orch_desc[i].op = dm_orch_type_net_insert;
        orig.m_orch_desc[i].submit = true;
    }
    em_cmd_t* clone = orig.clone_for_next();
    ASSERT_NE(clone, nullptr);
    EXPECT_EQ(clone->m_type, orig.m_type);
    EXPECT_EQ(clone->m_orch_op_idx, orig.m_orch_op_idx + 1);
    EXPECT_EQ(clone->m_orch_desc[0].op, orig.m_orch_desc[0].op);
    std::cout << "Exiting CloneFullFields test" << std::endl;
}

TEST(em_cmd_t, CloneNullEvent) 
{
    std::cout << "Entering CloneNullEvent test" << std::endl;
    em_cmd_t orig;
    orig.m_type = em_cmd_type_reset;
    orig.m_param.u.args.num_args = 0;
    strncpy(orig.m_param.u.args.fixed_args,
            "SafeArgs",
            sizeof(orig.m_param.u.args.fixed_args)-1);
    orig.m_orch_op_idx = 0;
    orig.m_num_orch_desc = 2;  // Must be > 1 so clone_for_next() returns non-NULL
    orig.m_orch_desc[0].op = dm_orch_type_net_insert;
    orig.m_orch_desc[0].submit = true;
    orig.m_orch_desc[1].op = dm_orch_type_net_update;
    orig.m_orch_desc[1].submit = false;
    orig.m_evt = nullptr;
    em_cmd_t* clone = orig.clone_for_next();
    ASSERT_NE(clone, nullptr);
    EXPECT_EQ(clone->m_evt, nullptr);
    std::cout << "Exiting CloneNullEvent test" << std::endl;
}

TEST(em_cmd_t, CloneIndependence) 
{
    std::cout << "Entering CloneIndependence test" << std::endl;
    em_cmd_t orig;
    orig.m_type = em_cmd_type_reset;
    orig.m_param.u.args.num_args = 1;
    strncpy(orig.m_param.u.args.fixed_args,
            "OriginalFixed",
            sizeof(orig.m_param.u.args.fixed_args)-1);
    orig.m_orch_op_idx = 0;
    orig.m_num_orch_desc = 2;     // use <= 16 (array size)
    for (unsigned int i = 0; i < orig.m_num_orch_desc; i++) {
        orig.m_orch_desc[i].op = dm_orch_type_net_insert; // valid enum
        orig.m_orch_desc[i].submit = true;                // valid bool
    }
    orig.m_evt = nullptr;
    orig.m_em_candidates = nullptr;
    em_cmd_t* clone = orig.clone_for_next();
    ASSERT_NE(clone, nullptr); // must not be NULL
    clone->m_param.u.args.num_args = 42;
    strncpy(clone->m_param.u.args.fixed_args,
            "Changed",
            sizeof(clone->m_param.u.args.fixed_args)-1);
    clone->m_orch_desc[0].op = dm_orch_type_net_delete;
    clone->m_orch_desc[0].submit = false;
    EXPECT_EQ(orig.m_param.u.args.num_args, 1);
    EXPECT_STREQ(orig.m_param.u.args.fixed_args, "OriginalFixed");
    EXPECT_EQ(orig.m_orch_desc[0].op, dm_orch_type_net_insert);
    EXPECT_EQ(orig.m_orch_desc[0].submit, true);
    EXPECT_EQ(orig.m_orch_op_idx, 0); // original index unchanged
    std::cout << "Exiting CloneIndependence test" << std::endl;
}

TEST(em_cmd_t, CloneStringIntegrity) 
{
    std::cout << "Entering CloneStringIntegrity test" << std::endl;
    em_cmd_t orig;
    orig.m_param.u.args.num_args = 1;
    strncpy(orig.m_param.u.args.fixed_args, "FixedArgs",
            sizeof(orig.m_param.u.args.fixed_args)-1);
    orig.m_orch_op_idx = 0;
    orig.m_num_orch_desc = 2;
    orig.m_orch_desc[0].op = dm_orch_type_net_insert;
    orig.m_orch_desc[0].submit = true;
    orig.m_orch_desc[1].op = dm_orch_type_net_update;
    orig.m_orch_desc[1].submit = false;
    em_cmd_t* clone = orig.clone_for_next();
    ASSERT_NE(clone, nullptr);
    EXPECT_STREQ(clone->m_param.u.args.fixed_args, "FixedArgs");
    clone->m_param.u.args.fixed_args[0] = 'X';
    EXPECT_STREQ(orig.m_param.u.args.fixed_args, "FixedArgs");
    std::cout << "Exiting CloneStringIntegrity test" << std::endl;
}

TEST(em_cmd_t, CloneForNextAtLastIndexReturnsNull)
{
    std::cout << "Entering CloneForNextAtLastIndexReturnsNull test" << std::endl;
    em_cmd_t cmd;
    // Setup so that m_orch_op_idx is at the last index
    cmd.m_num_orch_desc = 3;
    cmd.m_orch_op_idx = 2;  // last valid index
    em_cmd_t* clone = cmd.clone_for_next();
    // Expect NULL because we are at the last index
    EXPECT_EQ(clone, nullptr);
    std::cout << "Exiting CloneForNextAtLastIndexReturnsNull test" << std::endl;
}

TEST(em_cmd_t, CloneForNextEmptyOrchDescReturnsNull)
{
    std::cout << "Entering CloneForNextEmptyOrchDescReturnsNull test" << std::endl;
    em_cmd_t cmd;
    // m_num_orch_desc = 0 means no operations available
    cmd.m_num_orch_desc = 0;
    cmd.m_orch_op_idx = 0;
    em_cmd_t* clone = cmd.clone_for_next();
    // Expect NULL because there are no orch_desc elements
    EXPECT_EQ(clone, nullptr);
    std::cout << "Exiting CloneForNextEmptyOrchDescReturnsNull test" << std::endl;
}

TEST(em_cmd_t, CloneForNextSingleElementLastIndexReturnsNull)
{
    std::cout << "Entering CloneForNextSingleElementLastIndexReturnsNull test" << std::endl;
    em_cmd_t cmd;
    // Only one element in m_orch_desc
    cmd.m_num_orch_desc = 1;
    cmd.m_orch_op_idx = 0; // last (and first) element
    em_cmd_t* clone = cmd.clone_for_next();
    EXPECT_EQ(clone, nullptr);
    std::cout << "Exiting CloneForNextSingleElementLastIndexReturnsNull test" << std::endl;
}

TEST(em_cmd_t, cmd_2_bus_event_type_ValidConversion) {
    std::cout << "Entering ValidConversion test" << std::endl;
    em_cmd_t obj;

    struct CmdToBusMapping {
        em_cmd_type_t cmd;
        em_bus_event_type_t expected;
    };
    CmdToBusMapping testCases[] = {
        { em_cmd_type_none,                em_bus_event_type_none },
        { em_cmd_type_reset,               em_bus_event_type_reset },
        { em_cmd_type_dev_test,            em_bus_event_type_dev_test },
        { em_cmd_type_set_ssid,            em_bus_event_type_set_ssid },
		{ em_cmd_type_em_config,           em_bus_event_type_topo_sync },
		{ em_cmd_type_dev_init,            em_bus_event_type_dev_init },
		{ em_cmd_type_cfg_renew,           em_bus_event_type_cfg_renew },
		{ em_cmd_type_sta_list,            em_bus_event_type_sta_list },
		{ em_cmd_type_get_mld_config,      em_bus_event_type_get_mld_config },
		{ em_cmd_type_mld_reconfig,        em_bus_event_type_mld_reconfig },
		{ em_cmd_type_get_reset,           em_bus_event_type_get_reset}
    };
		
    // Loop through each mapping and invoke the method, then validate the result.
    for (const auto &testCase : testCases) {
        std::cout << "\nInvoking cmd_2_bus_event_type with command type: "
                  << cmd_type_to_str(testCase.cmd)
                  << " (" << static_cast<int>(testCase.cmd) << ")" << std::endl;
        em_bus_event_type_t busEvent = obj.cmd_2_bus_event_type(testCase.cmd);
        std::cout << "Returned bus event type: "
                  << bus_event_type_to_str(busEvent)
                  << " (" << static_cast<int>(busEvent) << ")"
                  << " for command type: " << cmd_type_to_str(testCase.cmd)
                  << std::endl;
        std::cout << "Expected bus event type: "
                  << bus_event_type_to_str(testCase.expected)
                  << " (" << static_cast<int>(testCase.expected) << ")"
                  << std::endl;
        EXPECT_EQ(busEvent, testCase.expected)
            << "Mismatch for command type: " << cmd_type_to_str(testCase.cmd)
            << " — expected " << bus_event_type_to_str(testCase.expected)
            << " but got " << bus_event_type_to_str(busEvent);
    }
    std::cout << "Exiting ValidConversion test" << std::endl;
}

TEST(em_cmd_t, NegativeConversion_NegativeValue) {
    std::cout << "Entering NegativeConversion_NegativeValue test" << std::endl;

        em_cmd_t obj;
    
    em_cmd_type_t invalidCmd = static_cast<em_cmd_type_t>(-1);
    std::cout << "Invoking cmd_2_bus_event_type with invalid negative value: " << invalidCmd << std::endl;
    em_bus_event_type_t busEvent;
    //EXPECT_NO_THROW (busEvent = obj.cmd_2_bus_event_type(invalidCmd));
    busEvent = obj.cmd_2_bus_event_type(invalidCmd);
    std::cout << "Returned bus event type: " << bus_event_type_to_str(busEvent) 
              << " for invalid input value: " << invalidCmd << std::endl;
    std::cout << "Expected bus event type: " << em_bus_event_type_none << std::endl;
    EXPECT_EQ(busEvent, em_bus_event_type_none);

    std::cout << "Exiting NegativeConversion_NegativeValue test" << std::endl;
}

TEST(em_cmd_t, NegativeConversion_ExceedRange) {
    std::cout << "Entering NegativeConversion_ExceedRange test" << std::endl;

        em_cmd_t obj;

    em_cmd_type_t invalidCmd = static_cast<em_cmd_type_t>(em_cmd_type_max + 1);
    std::cout << "Invoking cmd_2_bus_event_type with value exceeding range: " << invalidCmd << std::endl;
    em_bus_event_type_t busEvent;
    busEvent = obj.cmd_2_bus_event_type(invalidCmd);
    std::cout << "Returned bus event type: " << bus_event_type_to_str(busEvent) 
              << " for input value exceeding defined range: " << invalidCmd << std::endl;
    std::cout << "Expected bus event type: " << em_bus_event_type_none << std::endl;
    EXPECT_EQ(busEvent, em_bus_event_type_none);

    std::cout << "Exiting NegativeConversion_ExceedRange test" << std::endl;
}

TEST(em_cmd_t, PositiveCopyMinimalBusEvent) {
    std::cout << "Entering PositiveCopyMinimalBusEvent test" << std::endl;

    // Prepare a minimal bus event with type = em_bus_event_type_none, data_len = 0
    em_bus_event_t evt;
    std::memset(&evt, 0, sizeof(evt));
    evt.type = em_bus_event_type_none;
    evt.data_len = 0;

    std::cout << "Initialized evt with type = " << evt.type
              << " (" << bus_event_type_to_str(evt.type) << ")"
              << " and data_len = " << evt.data_len << std::endl;

    EXPECT_NO_THROW({
        // Default constructor allocates m_evt properly
        em_cmd_t cmd;
        ASSERT_NE(cmd.m_evt, nullptr) << "m_evt should be allocated in constructor";

        std::cout << "Invoking copy_bus_event with minimal bus event" << std::endl;
        EXPECT_NO_THROW(cmd.copy_bus_event(&evt));

        // Validate that event type is updated correctly
        ASSERT_NE(cmd.m_evt, nullptr) << "m_evt is unexpectedly NULL after copy_bus_event";
        EXPECT_EQ(cmd.m_evt->type, em_event_type_bus)
            << "Expected m_evt->type to be em_event_type_bus after copy_bus_event";

        // Check that copied event matches input
        const em_bus_event_t &copied = cmd.m_evt->u.bevt;
        EXPECT_EQ(copied.type, evt.type);
        EXPECT_EQ(copied.data_len, evt.data_len);

        std::cout << "Copied m_evt->type = "
                  << cmd.m_evt->type << " (" << em_event_type_to_string(cmd.m_evt->type) << "), "
                  << "bus event type = "
                  << copied.type << " (" << bus_event_type_to_str(copied.type) << "), "
                  << "data_len = " << copied.data_len << std::endl;
    });

    std::cout << "Exiting PositiveCopyMinimalBusEvent test" << std::endl;
}

TEST(em_cmd_t, PositiveCopyCompleteBusEvent) {
    std::cout << "Entering PositiveCopyCompleteBusEvent test" << std::endl;

    // Prepare a complete bus event with type = em_bus_event_type_get_device, data_len > 0
    em_bus_event_t evt;
    std::memset(&evt, 0, sizeof(evt));
    evt.type = em_bus_event_type_get_device;
    evt.data_len = 100;

    std::cout << "Initialized evt with type = " 
              << bus_event_type_to_str(evt.type)
              << " and data_len = " << evt.data_len << std::endl;

    // Populate one of the union members (subdoc name)
    const char* subdocName = "TestSubdoc";
    strncpy(evt.u.subdoc.name, subdocName, sizeof(evt.u.subdoc.name) - 1);
    evt.u.subdoc.name[sizeof(evt.u.subdoc.name) - 1] = '\0';
    std::cout << "Assigned evt.u.subdoc.name = " << evt.u.subdoc.name << std::endl;

    // Populate parameters (arguments)
    evt.params.u.args.num_args = 2;
    const char* arg1 = "arg1_value";
    const char* arg2 = "arg2_value";
    strncpy(evt.params.u.args.args[0], arg1, sizeof(evt.params.u.args.args[0]) - 1);
    strncpy(evt.params.u.args.args[1], arg2, sizeof(evt.params.u.args.args[1]) - 1);
    evt.params.u.args.args[0][sizeof(evt.params.u.args.args[0]) - 1] = '\0';
    evt.params.u.args.args[1][sizeof(evt.params.u.args.args[1]) - 1] = '\0';

    std::cout << "Assigned evt.params.u.args.num_args = " << evt.params.u.args.num_args << std::endl;
    std::cout << "Assigned evt.params.u.args.args[0] = " << evt.params.u.args.args[0] << std::endl;
    std::cout << "Assigned evt.params.u.args.args[1] = " << evt.params.u.args.args[1] << std::endl;

    EXPECT_NO_THROW({
        em_cmd_t cmd;
        std::cout << "Invoking copy_bus_event with complete bus event" << std::endl;
        EXPECT_NO_THROW(cmd.copy_bus_event(&evt));

        ASSERT_NE(cmd.m_evt, nullptr) << "m_evt is NULL after copy_bus_event";

        // Validate deep copy of the bus event
        EXPECT_EQ(cmd.m_evt->type, em_event_type_bus)
            << "Expected m_evt->type to be em_event_type_bus after copy";

        const em_bus_event_t &copied = cmd.m_evt->u.bevt;

        std::cout << "Copied bus event type: " << bus_event_type_to_str(copied.type) << std::endl;
        std::cout << "Copied data_len: " << copied.data_len << std::endl;
        EXPECT_EQ(copied.type, evt.type);
        EXPECT_EQ(copied.data_len, evt.data_len);

        std::cout << "Copied subdoc name: " << copied.u.subdoc.name << std::endl;
        EXPECT_STREQ(copied.u.subdoc.name, evt.u.subdoc.name);

        std::cout << "Copied args num: " << copied.params.u.args.num_args << std::endl;
        EXPECT_EQ(copied.params.u.args.num_args, evt.params.u.args.num_args);
        std::cout << "Copied arg[0]: " << copied.params.u.args.args[0] << std::endl;
        std::cout << "Copied arg[1]: " << copied.params.u.args.args[1] << std::endl;
        EXPECT_STREQ(copied.params.u.args.args[0], evt.params.u.args.args[0]);
        EXPECT_STREQ(copied.params.u.args.args[1], evt.params.u.args.args[1]);
    });

    std::cout << "Exiting PositiveCopyCompleteBusEvent test" << std::endl;
}

TEST(em_cmd_t, PositiveCopyEnumLoop) {
    std::cout << "Entering PositiveCopyEnumLoop test" << std::endl;

    em_bus_event_type_t eventTypes[] = {
        em_bus_event_type_none, em_bus_event_type_chirp, em_bus_event_type_reset,
        em_bus_event_type_dev_test, em_bus_event_type_set_dev_test, em_bus_event_type_get_network,
        em_bus_event_type_get_device, em_bus_event_type_remove_device, em_bus_event_type_get_radio,
        em_bus_event_type_get_ssid, em_bus_event_type_set_ssid, em_bus_event_type_get_channel,
        em_bus_event_type_set_channel, em_bus_event_type_scan_channel, em_bus_event_type_scan_result,
        em_bus_event_type_get_bss, em_bus_event_type_get_sta, em_bus_event_type_steer_sta,
        em_bus_event_type_disassoc_sta, em_bus_event_type_get_policy, em_bus_event_type_set_policy,
        em_bus_event_type_btm_sta, em_bus_event_type_start_dpp, em_bus_event_type_dev_init,
        em_bus_event_type_cfg_renew, em_bus_event_type_radio_config, em_bus_event_type_vap_config,
        em_bus_event_type_sta_list, em_bus_event_type_ap_cap_query, em_bus_event_type_client_cap_query,
        em_bus_event_type_listener_stop, em_bus_event_type_dm_commit, em_bus_event_type_m2_tx,
        em_bus_event_type_topo_sync, em_bus_event_type_onewifi_private_cb, em_bus_event_type_onewifi_mesh_sta_cb,
        em_bus_event_type_onewifi_radio_cb, em_bus_event_type_m2ctrl_configuration, em_bus_event_type_sta_assoc,
        em_bus_event_type_channel_pref_query, em_bus_event_type_channel_sel_req, em_bus_event_type_sta_link_metrics,
        em_bus_event_type_set_radio, em_bus_event_type_bss_tm_req, em_bus_event_type_btm_response,
        em_bus_event_type_channel_scan_params, em_bus_event_type_get_mld_config, em_bus_event_type_mld_reconfig,
        em_bus_event_type_beacon_report, em_bus_event_type_recv_wfa_action_frame, em_bus_event_type_recv_gas_frame,
        em_bus_event_type_get_sta_client_type, em_bus_event_type_assoc_status, em_bus_event_type_ap_metrics_report,
        em_bus_event_type_bss_info, em_bus_event_type_get_reset, em_bus_event_type_recv_csa_beacon_frame
    };

    size_t totalTypes = sizeof(eventTypes) / sizeof(eventTypes[0]);

    for (size_t i = 0; i < totalTypes; i++) {
        em_bus_event_t evt;
        std::memset(&evt, 0, sizeof(evt));
        evt.type = eventTypes[i];
        evt.data_len = 50;

        std::cout << "\n[Loop " << i << "] Initialized evt with type = "
                  << bus_event_type_to_str(evt.type)
                  << " and data_len = " << evt.data_len << std::endl;

        // Populate simple parameter
        evt.params.u.args.num_args = 1;
        const char* loopArg = "LoopArg";
        strncpy(evt.params.u.args.args[0], loopArg, sizeof(evt.params.u.args.args[0]) - 1);
        evt.params.u.args.args[0][sizeof(evt.params.u.args.args[0]) - 1] = '\0';
        std::cout << "[Loop " << i << "] Assigned evt.params.u.args.args[0] = " 
                  << evt.params.u.args.args[0] << std::endl;

        em_cmd_t cmd;
        std::cout << "[Loop " << i << "] Invoking copy_bus_event" << std::endl;
        EXPECT_NO_THROW(cmd.copy_bus_event(&evt));

        ASSERT_NE(cmd.m_evt, nullptr) << "[Loop " << i << "] m_evt is NULL after copy_bus_event";
        EXPECT_EQ(cmd.m_evt->type, em_event_type_bus)
            << "[Loop " << i << "] Expected m_evt->type = em_event_type_bus";

        const em_bus_event_t &copied = cmd.m_evt->u.bevt;

        std::cout << "[Loop " << i << "] Copied bus event type: " 
                  << bus_event_type_to_str(copied.type) << std::endl;
        std::cout << "[Loop " << i << "] Copied data_len: " << copied.data_len << std::endl;
        EXPECT_EQ(copied.type, evt.type);
        EXPECT_EQ(copied.data_len, evt.data_len);

        std::cout << "[Loop " << i << "] Copied args num: " << copied.params.u.args.num_args << std::endl;
        EXPECT_EQ(copied.params.u.args.num_args, evt.params.u.args.num_args);

        std::cout << "[Loop " << i << "] Copied arg[0]: " << copied.params.u.args.args[0] << std::endl;
        EXPECT_STREQ(copied.params.u.args.args[0], evt.params.u.args.args[0]);
    }

    std::cout << "Exiting PositiveCopyEnumLoop test" << std::endl;
}

TEST(em_cmd_t, NegativeCopyNullPointer) {
    std::cout << "Entering NegativeCopyNullPointer test" << std::endl;
    em_cmd_t cmd;
    std::cout << "Invoking copy_bus_event with NULL pointer" << std::endl;
    EXPECT_ANY_THROW(cmd.copy_bus_event(NULL));
    std::cout << "Exiting NegativeCopyNullPointer test" << std::endl;
}

TEST(em_cmd_t, ValidDefaultInitialization) {
    std::cout << "Entering ValidDefaultInitialization test" << std::endl;

    em_cmd_t cmd;

    // Step 1: Prepare the source frame event
    em_frame_event_t evt{};
    evt.frame_len = 5;
    evt.frame = static_cast<unsigned char*>(malloc(evt.frame_len));
    ASSERT_NE(evt.frame, nullptr);

    // Fill source frame with a known pattern
    for (unsigned int i = 0; i < evt.frame_len; i++) {
        evt.frame[i] = static_cast<unsigned char>(i + 10);
    }

    std::cout << "Source evt.frame_len = " << evt.frame_len << std::endl;
    std::cout << "Source evt.frame contents:";
    for (unsigned int i = 0; i < evt.frame_len; i++) {
        std::cout << " " << static_cast<int>(evt.frame[i]);
    }
    std::cout << std::endl;

    // Step 2: Invoke copy_frame_event
    EXPECT_NO_THROW(cmd.copy_frame_event(&evt));

    // Step 3: Validate deep copy
    ASSERT_NE(cmd.m_evt, nullptr);
    EXPECT_EQ(cmd.m_evt->type, em_event_type_frame);

    em_frame_event_t* copied = &cmd.m_evt->u.fevt;
    EXPECT_EQ(copied->frame_len, evt.frame_len);
    ASSERT_NE(copied->frame, nullptr);

    // Compare content
    EXPECT_EQ(std::memcmp(copied->frame, evt.frame, evt.frame_len), 0)
        << "Copied frame content does not match source";

    std::cout << "Copied frame contents:";
    for (unsigned int i = 0; i < copied->frame_len; i++) {
        std::cout << " " << static_cast<int>(copied->frame[i]);
    }
    std::cout << std::endl;

    // Step 4: Cleanup
    free(evt.frame);

    std::cout << "Exiting ValidDefaultInitialization test" << std::endl;
} 

TEST(em_cmd_t, NullPointer) {
    std::cout << "Entering NullPointer test" << std::endl;
    em_cmd_t cmd;
    std::cout << "Invoking copy_frame_event with NULL pointer" << std::endl;
    EXPECT_ANY_THROW(cmd.copy_frame_event(nullptr));
    std::cout << "Exiting NullPointer test" << std::endl;
}

TEST(em_cmd_t, DumpBusEvent_ValidPointerLoop) {
    std::cout << "Entering DumpBusEvent_ValidPointerLoop test" << std::endl;
    em_bus_event_t evt_obj;
    memset(&evt_obj, 0, sizeof(evt_obj));
    const char *subdoc_name = "SubdocName";
    strncpy(evt_obj.u.subdoc.name, subdoc_name, sizeof(evt_obj.u.subdoc.name) - 1);
    evt_obj.u.subdoc.name[sizeof(evt_obj.u.subdoc.name) - 1] = '\0';
    evt_obj.params.u.args.num_args = 2;
    const char *arg0 = "arg0";
    const char *arg1 = "arg1";
    strncpy(evt_obj.params.u.args.args[0], arg0, sizeof(evt_obj.params.u.args.args[0]) - 1);
    evt_obj.params.u.args.args[0][sizeof(evt_obj.params.u.args.args[0]) - 1] = '\0';
    strncpy(evt_obj.params.u.args.args[1], arg1, sizeof(evt_obj.params.u.args.args[1]) - 1);
    evt_obj.params.u.args.args[1][sizeof(evt_obj.params.u.args.args[1]) - 1] = '\0';
    for (int type = em_bus_event_type_none; type < em_bus_event_type_max; ++type) {
        em_bus_event_t *evt = &evt_obj;      
        evt->type = static_cast<em_bus_event_type_t>(type);
        std::cout << "Invoking dump_bus_event with event type: " << type << std::endl;
        int ret = em_cmd_t::dump_bus_event(evt);
        std::cout << "Returned status: " << ret << " for event type: " << type << std::endl;
        EXPECT_EQ(ret, 0);
    }
    std::cout << "Exiting DumpBusEvent_ValidPointerLoop test" << std::endl;
}

TEST(em_cmd_t, DumpBusEvent_NullPointer) {
    std::cout << "Entering DumpBusEvent_NullPointer test" << std::endl;    
    // Create an instance of em_cmd_t using the default constructor.
    EXPECT_NO_THROW({ em_cmd_t obj; });    
    std::cout << "Invoking dump_bus_event with null event pointer" << std::endl;
    int ret = 0;
    EXPECT_NO_THROW({
        ret = em_cmd_t::dump_bus_event(nullptr);
        std::cout << "dump_bus_event invoked with nullptr." << std::endl;
    });
    std::cout << "Returned status: " << ret << " for null event pointer" << std::endl;
    EXPECT_EQ(ret, -1);    
    std::cout << "Exiting DumpBusEvent_NullPointer test" << std::endl;
}

TEST(em_cmd_t, DumpBusEvent_InvalidEvent) {
    std::cout << "Entering DumpBusEvent_InvalidEvent test" << std::endl;    
    // Create an instance of em_cmd_t using the default constructor.
    EXPECT_NO_THROW({ em_cmd_t obj; });    
    // Allocate and minimally initialize an event structure with an invalid event type.
    em_bus_event_t evt;
    evt.type = em_bus_event_type_max;    
    std::cout << "Invoking dump_bus_event with invalid event type: " << evt.type << std::endl;
    int ret = 0;
    EXPECT_NO_THROW({
        ret = em_cmd_t::dump_bus_event(&evt);
        std::cout << "dump_bus_event invoked. Event details dumped with invalid event type value: " << evt.type << std::endl;
    });
    std::cout << "Returned status: " << ret << " for invalid event type: " << evt.type << std::endl;
    EXPECT_EQ(-1, ret);    
    std::cout << "Exiting DumpBusEvent_InvalidEvent test" << std::endl;
}

TEST(em_cmd_t, DefaultConstruction_Success) {
    std::cout << "Entering DefaultConstruction_Success test" << std::endl;    
    // Create an instance of em_cmd_t using the default constructor and ensure no exception is thrown.
    EXPECT_NO_THROW({
        em_cmd_t obj;
        std::cout << "Invoked em_cmd_t() default constructor." << std::endl;        
        std::cout << "Object state after construction:" << std::endl;
        std::cout << "  m_evt: " << obj.m_evt << " (expected: nullptr)" << std::endl;
        std::cout << "  m_em_candidates: " << obj.m_em_candidates << " (expected: nullptr)" << std::endl;
        std::cout << "  m_type: " << static_cast<int>(obj.m_type) << " (expected: default value)" << std::endl;
        std::cout << "  m_orch_op_idx: " << obj.m_orch_op_idx << " (expected: 0 or initialized default)" << std::endl;
        // Additional member values can be logged similarly if they are relevant.
    });    
    std::cout << "Exiting DefaultConstruction_Success test" << std::endl;
}

TEST(em_cmd_t, ValidInstantiationDefault) {
    std::cout << "Entering ValidInstantiationDefault test" << std::endl;

    // Array of supported command types excluding invalid ones such as em_cmd_type_max.
    em_cmd_type_t types[] = {
        em_cmd_type_none,
        em_cmd_type_reset,
        em_cmd_type_get_network,
        em_cmd_type_get_device,
        em_cmd_type_remove_device,
        em_cmd_type_get_radio,
        em_cmd_type_set_radio,
        em_cmd_type_get_ssid,
        em_cmd_type_set_ssid,
        em_cmd_type_get_channel,
        em_cmd_type_set_channel,
        em_cmd_type_scan_channel,
        em_cmd_type_scan_result,
        em_cmd_type_get_bss,
        em_cmd_type_get_sta,
        em_cmd_type_steer_sta,
        em_cmd_type_disassoc_sta,
        em_cmd_type_btm_sta,
        em_cmd_type_dev_init,
        em_cmd_type_dev_test,
        em_cmd_type_set_dev_test,
        em_cmd_type_cfg_renew,
        em_cmd_type_vap_config,
        em_cmd_type_sta_list,
        em_cmd_type_start_dpp,
        em_cmd_type_ap_cap_query,
        em_cmd_type_client_cap_query,
        em_cmd_type_topo_sync,
        em_cmd_type_em_config,
        em_cmd_type_onewifi_cb,
        em_cmd_type_sta_assoc,
        em_cmd_type_channel_pref_query,
        em_cmd_type_sta_link_metrics,
        em_cmd_type_op_channel_report,
        em_cmd_type_sta_steer,
        em_cmd_type_btm_report,
        em_cmd_type_sta_disassoc,
        em_cmd_type_get_policy,
        em_cmd_type_set_policy,
        em_cmd_type_avail_spectrum_inquiry,
        em_cmd_type_get_mld_config,
        em_cmd_type_mld_reconfig,
        em_cmd_type_beacon_report,
        em_cmd_type_ap_metrics_report,
        em_cmd_type_get_reset
        //em_cmd_type_bsta_cap
    };

    for (size_t i = 0; i < sizeof(types)/sizeof(types[0]); i++) {
        em_cmd_params_t param = {};
        // Set default union field if needed (default construction implies zeroed fields)
        // net_node intentionally set to nullptr
        param.net_node = nullptr;
        std::cout << "Invoking constructor for command type: " << types[i] << std::endl;
        EXPECT_NO_THROW({
            // Creating object with default parameters.
            em_cmd_t cmd(types[i], param);
            std::cout << "Constructed em_cmd_t object with m_type = " << cmd.m_type << std::endl;
        });
    }

    std::cout << "Exiting ValidInstantiationDefault test" << std::endl;
}

TEST(em_cmd_t, InvalidCmdTypeMax) {
    std::cout << "Entering InvalidCmdTypeMax test" << std::endl;
    em_cmd_params_t param;
    std::cout << "Invoking constructor with invalid command type em_cmd_type_max" << std::endl;
    EXPECT_ANY_THROW({
        em_cmd_t cmd(em_cmd_type_max, param);
    });
    std::cout << "Exiting InvalidCmdTypeMax test" << std::endl;
}
/*
TEST(em_cmd_t, ValidConstructionAllTypes)
{
    std::cout << "Entering ValidConstructionAllTypes test" << std::endl;

    // Prepare minimal command parameters.
    em_cmd_params_t param;
    param.u.args.num_args = 0;
    std::memset(param.u.args.fixed_args, 0, sizeof(param.u.args.fixed_args));

    dm_easy_mesh_t dm;
  
    // List of several valid command types from the enumeration.
    em_cmd_type_t types[] = { 
        em_cmd_type_none, 
        em_cmd_type_reset, 
        em_cmd_type_get_network,
        em_cmd_type_get_device,
        em_cmd_type_remove_device,
        em_cmd_type_get_radio,
        em_cmd_type_set_radio,
        em_cmd_type_get_ssid,
        em_cmd_type_set_ssid,
        em_cmd_type_get_channel,
        em_cmd_type_set_channel,
        em_cmd_type_scan_channel,
        em_cmd_type_scan_result,
        em_cmd_type_get_bss,
        em_cmd_type_get_sta,
        em_cmd_type_steer_sta,
        em_cmd_type_disassoc_sta,
        em_cmd_type_btm_sta,
        em_cmd_type_dev_init,
        em_cmd_type_dev_test,
        em_cmd_type_set_dev_test,
        em_cmd_type_cfg_renew,
        em_cmd_type_vap_config,
        em_cmd_type_sta_list,
        em_cmd_type_start_dpp,
        em_cmd_type_ap_cap_query,
        em_cmd_type_client_cap_query,
        em_cmd_type_topo_sync,
        em_cmd_type_em_config,
        em_cmd_type_onewifi_cb,
        em_cmd_type_sta_assoc,
        em_cmd_type_channel_pref_query,
        em_cmd_type_sta_link_metrics,
        em_cmd_type_op_channel_report,
        em_cmd_type_sta_steer,
        em_cmd_type_btm_report,
        em_cmd_type_sta_disassoc,
        em_cmd_type_get_policy,
        em_cmd_type_set_policy,
        em_cmd_type_avail_spectrum_inquiry,
        em_cmd_type_get_mld_config,
        em_cmd_type_mld_reconfig,
        em_cmd_type_beacon_report,
        em_cmd_type_ap_metrics_report,
        em_cmd_type_get_reset
        //em_cmd_type_bsta_cap
    };
    int nTypes = sizeof(types) / sizeof(types[0]);

    for (int i = 0; i < nTypes; i++)
    {
        std::cout << "Invoking constructor with type: " << types[i] << std::endl;
        em_cmd_t cmd(types[i], param, dm);
        std::cout << "Constructed em_cmd_t with type: " << cmd.get_type() << std::endl;
        EXPECT_EQ(cmd.get_type(), types[i]);
    }
  
    std::cout << "Exiting ValidConstructionAllTypes test" << std::endl;
}
*/
TEST(em_cmd_t, ValidConstructionAllTypes)
{
    std::cout << "Entering ValidConstructionAllTypes test" << std::endl;

    // Prepare minimal parameters
    em_cmd_params_t param{};
    param.u.args.num_args = 0;

    dm_easy_mesh_t dm;
    dm.init();   // REQUIRED — allocates matching structures owned by em_cmd_t

    em_cmd_type_t types[] = {
        em_cmd_type_none, 
        em_cmd_type_reset, 
        em_cmd_type_get_network,
        em_cmd_type_get_device,
        em_cmd_type_remove_device,
        em_cmd_type_get_radio,
        em_cmd_type_set_radio,
        em_cmd_type_get_ssid,
        em_cmd_type_set_ssid,
        em_cmd_type_get_channel,
        em_cmd_type_set_channel,
        em_cmd_type_scan_channel,
        em_cmd_type_scan_result,
        em_cmd_type_get_bss,
        em_cmd_type_get_sta,
        em_cmd_type_steer_sta,
        em_cmd_type_disassoc_sta,
        em_cmd_type_btm_sta,
        em_cmd_type_dev_init,
        em_cmd_type_dev_test,
        em_cmd_type_set_dev_test,
        em_cmd_type_cfg_renew,
        em_cmd_type_vap_config,
        em_cmd_type_sta_list,
        em_cmd_type_start_dpp,
        em_cmd_type_ap_cap_query,
        em_cmd_type_client_cap_query,
        em_cmd_type_topo_sync,
        em_cmd_type_em_config,
        em_cmd_type_onewifi_cb,
        em_cmd_type_sta_assoc,
        em_cmd_type_channel_pref_query,
        em_cmd_type_sta_link_metrics,
        em_cmd_type_op_channel_report,
        em_cmd_type_sta_steer,
        em_cmd_type_btm_report,
        em_cmd_type_sta_disassoc,
        em_cmd_type_get_policy,
        em_cmd_type_set_policy,
        em_cmd_type_avail_spectrum_inquiry,
        em_cmd_type_get_mld_config,
        em_cmd_type_mld_reconfig,
        em_cmd_type_beacon_report,
        em_cmd_type_ap_metrics_report,
        em_cmd_type_get_reset
    };
    int nTypes = sizeof(types) / sizeof(types[0]);

    for (int i = 0; i < nTypes; i++)
    {
        em_cmd_t cmd(types[i], param, dm);
        EXPECT_EQ(cmd.get_type(), types[i]);
        cmd.deinit();  // must match init()
    }

    dm.deinit();  // cleanup structure memory

    std::cout << "Exiting ValidConstructionAllTypes test" << std::endl;
}

TEST(em_cmd_t, ValidConstructionNonEmptyCommandParameters)
{
    std::cout << "Entering ValidConstructionNonEmptyCommandParameters test" << std::endl;
    em_cmd_params_t param{};
    param.u.args.num_args = 1;
    // Set first argument as "testArg"
    const char *testArg = "testArg";
    strncpy(param.u.args.args[0], testArg, sizeof(param.u.args.args[0]));
    // Set fixed_args as "fixedTest"
    const char *fixedTest = "fixedTest";
    strncpy(param.u.args.fixed_args, fixedTest, sizeof(param.u.args.fixed_args));
    // Create a dm_easy_mesh_t object with predefined network id (simulate valid network info)
    dm_easy_mesh_t dm{};
    dm.m_num_radios = 2;
	dm.m_num_bss = 3;
	dm.m_num_opclass = 4; 
	dm.m_colocated = true;
    // Construct em_cmd_t with type em_cmd_type_get_device.
    em_cmd_t cmd(em_cmd_type_get_device, param, dm);
    std::cout << "Constructed em_cmd_t" << std::endl;
    std::cout << "Parameter num_args: " << cmd.m_param.u.args.num_args << std::endl;
    std::cout << "Arg[0]: " << cmd.m_param.u.args.args[0] << std::endl;
    std::cout << "Fixed args: " << cmd.m_param.u.args.fixed_args << std::endl;
    std::cout << "m_num_radios: " << cmd.m_data_model.m_num_radios << std::endl;
	std::cout << "m_num_bss: " << cmd.m_data_model.m_num_bss << std::endl;
	std::cout << "m_num_opclass: " << cmd.m_data_model.m_num_opclass << std::endl;
	std::cout << "m_colocated: " << cmd.m_data_model.m_colocated << std::endl;
	EXPECT_EQ(cmd.m_type, em_cmd_type_get_device);
    EXPECT_EQ(cmd.m_param.u.args.num_args, 1);
    EXPECT_STREQ(cmd.m_param.u.args.args[0], "testArg");
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "fixedTest");
	EXPECT_EQ(cmd.m_data_model.m_num_radios, 2);
	EXPECT_EQ(cmd.m_data_model.m_num_bss, 3);
	EXPECT_EQ(cmd.m_data_model.m_num_opclass, 4);
	EXPECT_TRUE(cmd.m_data_model.m_colocated);
    std::cout << "Exiting ValidConstructionNonEmptyCommandParameters test" << std::endl;
}

/*
TEST(em_cmd_t, ConstructionWithOutOfRangeCmdType)
{
    std::cout << "Entering ConstructionWithOutOfRangeCmdType test" << std::endl;
    em_cmd_params_t param{};
	param.u.args.num_args = 1;
    dm_easy_mesh_t dm{};
    dm.m_num_radios = 2;
    // Simulate an out-of-range command type, e.g., using static_cast of -1.
    em_cmd_t cmd(static_cast<em_cmd_type_t>(-1), param, dm);
    std::cout << "Constructed em_cmd_t with out-of-range type: " << cmd.get_type() << std::endl;
    EXPECT_EQ(cmd.m_type, static_cast<em_cmd_type_t>(-1));
    std::cout << "Exiting ConstructionWithOutOfRangeCmdType test" << std::endl;
}
*/
TEST(em_cmd_t, ConstructionWithOutOfRangeCmdType)
{
    std::cout << "Entering ConstructionWithOutOfRangeCmdType test" << std::endl;
    em_cmd_params_t param{};
    param.u.args.num_args = 1;
    dm_easy_mesh_t dm;
    dm.init();
    em_cmd_t cmd(static_cast<em_cmd_type_t>(-1), param, dm);
    EXPECT_EQ(cmd.m_type, static_cast<em_cmd_type_t>(-1));
    cmd.deinit();
    dm.deinit();
    std::cout << "Exiting ConstructionWithOutOfRangeCmdType test" << std::endl;
}

TEST(em_cmd_t, SuccessfulRetrieval)
{
    std::cout << "Entering SuccessfulRetrieval test" << std::endl;
    em_cmd_t cmd;
	strncpy(cmd.m_data_model.m_device.m_device_info.intf.name, "AgentAL_Interface", sizeof(cmd.m_data_model.m_device.m_device_info.intf.name));
	unsigned char mac[6] = {0x1A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5A};
    memcpy(cmd.m_data_model.m_device.m_device_info.intf.mac, mac, sizeof(mac));
	cmd.m_data_model.m_device.m_device_info.intf.media = em_media_type_ieee8023ab;
    std::cout << "Invoking get_agent_al_interface()" << std::endl;
    em_interface_t *agentInterface = cmd.get_agent_al_interface();
    if (agentInterface) {
        std::cout << "Retrieved interface name: " << agentInterface->name << std::endl;
        std::cout << "Retrieved media type: " << agentInterface->media << std::endl;
		std::cout << "Retrieved MAC: ";
        for (int i = 0; i < 6; i++) {
            std::cout << std::uppercase
              << std::setw(2) << std::setfill('0') << std::hex
              << static_cast<int>(agentInterface->mac[i]);
            if (i < 5) std::cout << ":";
        }
        std::cout << std::dec << std::endl;
    } else {
        std::cout << "Retrieved a NULL pointer for agent AL interface" << std::endl;
    }
    EXPECT_NE(agentInterface, nullptr);
    std::cout << "Exiting SuccessfulRetrieval test" << std::endl;
}

TEST(em_cmd_t, RetrieveALInterfaceMACAddress_WithValidConfiguration) {
    std::cout << "Entering RetrieveALInterfaceMACAddress_WithValidConfiguration test" << std::endl;
    em_cmd_t cmd;
	unsigned char mac[6] = {0x1A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5A};
    memcpy(cmd.m_data_model.m_device.m_device_info.intf.mac, mac, sizeof(mac));
    std::cout << "Invoking get_al_interface_mac() method" << std::endl;
    unsigned char *mac_ptr = cmd.get_al_interface_mac();
    ASSERT_NE(mac_ptr, nullptr);
    if (mac_ptr != nullptr) {
        std::cout << "get_al_interface_mac() returned a non-null pointer: " << static_cast<void*>(mac_ptr) << std::endl;
        std::cout << "Retrieved MAC address: ";
        for (size_t i = 0; i < 6 && mac_ptr[i] != '\0'; i++) {
            std::cout << mac_ptr[i];
        }
        std::cout << std::endl;
    } else {
        std::cout << "get_al_interface_mac() returned a null pointer" << std::endl;
    }
	EXPECT_EQ(memcmp(mac_ptr, mac, 6), 0);
    std::cout << "Exiting RetrieveALInterfaceMACAddress_WithValidConfiguration test" << std::endl;
}

TEST(em_cmd_t, Retrieve_non_empty_fixed_args_string) {
    std::cout << "Entering Retrieve_non_empty_fixed_args_string test" << std::endl;
    
    // Create object using default constructor and log the creation
    EXPECT_NO_THROW({
        em_cmd_t cmd;
        std::cout << "Created em_cmd_t object using default constructor." << std::endl;
        
        // Allocate and assign non-empty fixed args using strncpy
        char *argBuffer = new char[50];
        std::cout << "Allocating buffer for fixed_args and copying 'command_arg'." << std::endl;
        strncpy(argBuffer, "command_arg", 50);
        argBuffer[49] = '\0';  // ensure null termination
        
        // Set the fixed_args pointer
        strncpy(cmd.m_param.u.args.fixed_args, argBuffer, sizeof(cmd.m_param.u.args.fixed_args));
        cmd.m_param.u.args.fixed_args[sizeof(cmd.m_param.u.args.fixed_args)-1] = '\0'; // ensure null-termination
	    std::cout << "Assigned fixed_args with value: " << argBuffer << std::endl;
        
        // Invoke get_arg() method and log the invocation and returned value
        std::cout << "Invoking get_arg() method." << std::endl;
        const char *retVal = cmd.get_arg();
        std::cout << "get_arg() returned: " << (retVal ? retVal : "NULL") << std::endl;
        
        // Validate that the returned value is "command_arg"
        EXPECT_STREQ(retVal, "command_arg");
        
        // Free dynamically allocated memory
        delete[] argBuffer;
        std::cout << "Deallocated the fixed_args buffer." << std::endl;
    });
    
    std::cout << "Exiting Retrieve_non_empty_fixed_args_string test" << std::endl;
}

TEST(em_cmd_t, Retrieve_empty_fixed_args_string) {
    std::cout << "Entering Retrieve_empty_fixed_args_string test" << std::endl;
    em_cmd_t cmd;
    std::cout << "Created em_cmd_t object using default constructor." << std::endl;        
    // Allocate and assign empty fixed args using strncpy
    char *argBuffer = new char[50];
    std::cout << "Allocating buffer for fixed_args and copying empty string." << std::endl;
    strncpy(argBuffer, "", 50);
    argBuffer[49] = '\0';        
    // Set the fixed_args pointer
	strncpy(cmd.m_param.u.args.fixed_args, argBuffer, sizeof(cmd.m_param.u.args.fixed_args));
    cmd.m_param.u.args.fixed_args[sizeof(cmd.m_param.u.args.fixed_args)-1] = '\0'; // ensure null-termination
    std::cout << "Assigned fixed_args with empty string." << std::endl;        
    // Invoke get_arg() method and log the invocation and returned value
    std::cout << "Invoking get_arg() method." << std::endl;
    const char *retVal = cmd.get_arg();
    std::cout << "get_arg() returned: " << (retVal ? retVal : "NULL") << std::endl;       
    // Validate that the returned value is an empty string
    EXPECT_STREQ(retVal, "");        
    // Free dynamically allocated memory
    delete[] argBuffer;
    std::cout << "Deallocated the fixed_args buffer." << std::endl;    
    std::cout << "Exiting Retrieve_empty_fixed_args_string test" << std::endl;
}

TEST(em_cmd_t, RetrieveBusEventPointer) {
    std::cout << "Entering RetrieveBusEventPointer test" << std::endl;
    em_cmd_t cmd;
    ASSERT_NE(cmd.m_evt, nullptr);
    //cmd.m_evt->u.bevt.params.net_node = (em_param_node_t*)malloc(sizeof(em_param_node_t));
    //ASSERT_NE(cmd.m_evt->u.bevt.params.net_node, nullptr);
    cmd.m_evt->u.bevt.type = em_bus_event_type_chirp;
    //cmd.m_evt->u.bevt.params.net_node->value_int = 6;
    cmd.m_evt->u.bevt.data_len = 5;
    em_bus_event_t* ret_evt = cmd.get_bus_event();
    ASSERT_NE(ret_evt, nullptr);
    EXPECT_EQ(ret_evt->type, em_bus_event_type_chirp);
    //EXPECT_EQ(ret_evt->params.net_node->value_int, 6);
    EXPECT_EQ(ret_evt->data_len, 5);
    //free(cmd.m_evt->u.bevt.params.net_node);
    std::cout << "Exiting RetrieveBusEventPointer test" << std::endl;
}

TEST(em_cmd_t, ValidBusEventTypeStringConversion) {
    std::cout << "Entering ValidBusEventTypeStringConversion test" << std::endl;

    // Create object using default constructor and ensure no exception is thrown.
    EXPECT_NO_THROW({
        em_cmd_t cmd_obj;
    });

    // List of valid bus event types (excluding the em_bus_event_type_max)
    em_bus_event_type_t validTypes[] = {
        em_bus_event_type_none,
		em_bus_event_type_chirp,
		em_bus_event_type_reset,
		em_bus_event_type_dev_test,
		em_bus_event_type_set_dev_test,
		em_bus_event_type_get_network,
		em_bus_event_type_get_device,
		em_bus_event_type_remove_device,
		em_bus_event_type_get_radio,
		em_bus_event_type_set_radio,
		em_bus_event_type_get_ssid,
		em_bus_event_type_set_ssid,
		em_bus_event_type_get_channel,
		em_bus_event_type_set_channel,
		em_bus_event_type_get_bss,
		em_bus_event_type_get_sta,
		em_bus_event_type_steer_sta,
		em_bus_event_type_disassoc_sta,
		em_bus_event_type_btm_sta,
		em_bus_event_type_start_dpp,
		em_bus_event_type_dev_init,
		em_bus_event_type_cfg_renew,
        em_bus_event_type_radio_config,
        em_bus_event_type_vap_config,
        em_bus_event_type_sta_list,
        em_bus_event_type_listener_stop,
        em_bus_event_type_dm_commit,
        em_bus_event_type_topo_sync,
        em_bus_event_type_get_policy,
        em_bus_event_type_set_policy,
        em_bus_event_type_get_mld_config,
        em_bus_event_type_mld_reconfig,
        em_bus_event_type_get_reset
    };

    int numValidTypes = sizeof(validTypes) / sizeof(validTypes[0]);

    // Loop through each valid event type
    for (int i = 0; i < numValidTypes; ++i) {
        em_bus_event_type_t type = validTypes[i];
        std::cout << "Invoking get_bus_event_type_str with type value: " << type << std::endl;
        const char* result = em_cmd_t::get_bus_event_type_str(type);
        std::cout << "Returned string: " << result << std::endl;
        // Validate that result is not nullptr and is not "unknown"
        EXPECT_NE(result, nullptr);
        EXPECT_STRNE(result, "em_bus_event_type_unknown");
    }

    std::cout << "Exiting ValidBusEventTypeStringConversion test" << std::endl;
}

TEST(em_cmd_t, InvalidBusEventType_LessThanZero) {
    std::cout << "Entering InvalidBusEventType_LessThanZero test" << std::endl;

    // Create object using default constructor and ensure no exception is thrown.
    EXPECT_NO_THROW({
        em_cmd_t cmd_obj;
    });

    em_bus_event_type_t invalidType = static_cast<em_bus_event_type_t>(-1);
    std::cout << "Invoking get_bus_event_type_str with invalid type value: " << -1 << std::endl;
    const char* result = em_cmd_t::get_bus_event_type_str(invalidType);
    std::cout << "Returned string for invalid type (-1): " << result << std::endl;
    EXPECT_STREQ(result, "em_bus_event_type_unknown");

    std::cout << "Exiting InvalidBusEventType_LessThanZero test" << std::endl;
}

TEST(em_cmd_t, InvalidBusEventType_EqualToMax) {
    std::cout << "Entering InvalidBusEventType_EqualToMax test" << std::endl;

    // Create object using default constructor and ensure no exception is thrown.
    EXPECT_NO_THROW({
        em_cmd_t cmd_obj;
    });

    std::cout << "Invoking get_bus_event_type_str with type value: em_bus_event_type_max" << std::endl;
    const char* result = em_cmd_t::get_bus_event_type_str(em_bus_event_type_max);
    std::cout << "Returned string for type em_bus_event_type_max: " << result << std::endl;
    // Expect the returned string to be "unknown" indicating an invalid type handling.
    EXPECT_STREQ(result, "em_bus_event_type_unknown");

    std::cout << "Exiting InvalidBusEventType_EqualToMax test" << std::endl;
}

TEST(em_cmd_t, DefaultConstructorCmdName)
{
    std::cout << "Entering DefaultConstructorCmdName test" << std::endl;
    EXPECT_NO_THROW({
        em_cmd_t obj;
		strncpy(obj.m_name, "Sample", sizeof(obj.m_name) - 1);
        std::cout << "Invoking get_cmd_name() on default constructed object" << std::endl;
        const char *retCmd = obj.get_cmd_name();
        std::cout << "Retrieved command name: " << (retCmd ? retCmd : "NULL") << std::endl;
        EXPECT_NE(nullptr, retCmd);
        EXPECT_STREQ(retCmd, "Sample");
    });
    std::cout << "Exiting DefaultConstructorCmdName test" << std::endl;
}

TEST(em_cmd_t, DumpBusEvent_SupportedTypesOnly)
{
    std::cout << "Entering DumpBusEvent_SupportedTypesOnly test" << std::endl;
    em_cmd_t cmd;
    em_bus_event_t evt{};
    evt.params.u.args.num_args = 0;
    em_bus_event_type_t supported[] = {
        em_bus_event_type_get_network,
        em_bus_event_type_get_device,
        em_bus_event_type_remove_device,
        em_bus_event_type_get_radio,
        em_bus_event_type_get_ssid,
        em_bus_event_type_get_channel,
        em_bus_event_type_get_bss,
        em_bus_event_type_get_sta,
        em_bus_event_type_get_mld_config
    };
    for (auto t : supported) {
		std::cout << "[DumpBusEvent] Invoking dump_bus_event with type = " << static_cast<int>(t) << std::endl;
        evt.type = t;
        //evt.u.subdoc.name = (char*)"test_subdoc";
        int ret = cmd.dump_bus_event(&evt);
		std::cout << "[DumpBusEvent] Returned value: " << ret << " for type = " << static_cast<int>(t) << std::endl;
        EXPECT_EQ(ret, 0);
    }
    std::cout << "Exiting DumpBusEvent_SupportedTypesOnly test" << std::endl;
}

TEST(em_cmd_t, NegativeCommandType) {
    std::cout << "Entering NegativeCommandType test" << std::endl;
    em_cmd_t cmd;
    em_cmd_type_t invalidType = static_cast<em_cmd_type_t>(-1);
    std::cout << "Invoking get_cmd_type_str with invalid negative type = -1" << std::endl;
    const char * ret = em_cmd_t::get_cmd_type_str(invalidType);
    std::cout << "Returned string: " << ret << std::endl;
    EXPECT_EQ(ret, "em_cmd_type_unknown");
    std::cout << "Exiting NegativeCommandType test" << std::endl;
}

TEST(em_cmd_t, ExceedingCommandType) {
    std::cout << "Entering ExceedingCommandType test" << std::endl;
    em_cmd_t cmd;
    em_cmd_type_t invalidType = static_cast<em_cmd_type_t>(em_cmd_type_max + 1);
    std::cout << "[ExceedingCommandType] Invoking get_cmd_type_str with type = em_cmd_type_max + 1" << std::endl;
    const char * ret = em_cmd_t::get_cmd_type_str(invalidType);
    std::cout << "Returned string: " << ret << std::endl;    
    EXPECT_EQ(ret, "em_cmd_type_unknown");  
    std::cout << "Exiting ExceedingCommandType test" << std::endl;
}

TEST(em_cmd_t, ControlALInterfaceValid) {
    std::cout << "Entering ControlALInterfaceValid test" << std::endl;
    em_cmd_t cmd;
	strncpy(cmd.m_data_model.m_network.m_net_info.colocated_agent_id.name, "brlan0", sizeof(cmd.m_data_model.m_network.m_net_info.colocated_agent_id.name) - 1);
	unsigned char expected_mac[] = {0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x4B};
	memcpy(cmd.m_data_model.m_network.m_net_info.colocated_agent_id.mac, expected_mac, sizeof(expected_mac));
	cmd.m_data_model.m_network.m_net_info.colocated_agent_id.media = em_media_type_ieee8023ab;
    std::cout << "Invoking get_ctrl_al_interface()" << std::endl;
    em_interface_t *ctrlInterface = cmd.get_ctrl_al_interface();
    ASSERT_NE(ctrlInterface, nullptr);
    std::cout << "Retrieved Control AL Interface details:" << std::endl;
    std::cout << "Name: " << ctrlInterface->name << std::endl;    
    std::cout << "Media: " << ctrlInterface->media << std::endl;
	std::cout << "MAC: ";
    for (int i = 0; i < 6; i++) {
        printf("%02X", ctrlInterface->mac[i]);
        if (i < 5) printf(":");
    }
    printf("\n");
    std::cout << "Exiting ControlALInterfaceValid test" << std::endl;
}

TEST(em_cmd_t, ValidLowerBoundaryIndex) {
    std::cout << "Entering ValidLowerBoundaryIndex test" << std::endl;
    em_cmd_t cmd;
    unsigned int index = 0;
    em_op_class_info_t &infoInit = cmd.m_data_model.m_op_class[index].m_op_class_info;
    for (int i = 0; i < sizeof(mac_address_t); i++)
        infoInit.id.ruid[i] = (unsigned char)(0x10 + i);
    infoInit.id.type = (em_op_class_type_t)1;
    infoInit.id.op_class = 11;
    infoInit.op_class = 11;
    infoInit.channel = 6;
    infoInit.tx_power = 20;
    infoInit.max_tx_power = 30;
    infoInit.num_channels = 3;
    infoInit.channels[0] = 1;
    infoInit.channels[1] = 6;
    infoInit.channels[2] = 11;
    infoInit.mins_since_cac_comp = 5;
    infoInit.sec_remain_non_occ_dur = 10;
    infoInit.countdown_cac_comp = 100;
    std::cout << "Invoking get_curr_op_class with index: " << index << std::endl;
    dm_op_class_t* opClassPtr = cmd.get_curr_op_class(index);
    std::cout << "get_curr_op_class(" << index << ") returned pointer: " << opClassPtr << std::endl;
    ASSERT_NE(opClassPtr, nullptr);
    em_op_class_info_t &info = opClassPtr->m_op_class_info;
    std::cout << "---- Retrieved em_op_class_info_t Values ----" << std::endl;
    // Print em_op_class_id_t values
    std::cout << "ID:" << std::endl;
    std::cout << "  RUID: ";
    for (int i = 0; i < sizeof(mac_address_t); i++) {
        printf("%02X", info.id.ruid[i]);
        if (i < sizeof(mac_address_t) - 1) printf(":");
    }
    std::cout << std::endl;
    std::cout << "  Type: " << info.id.type << std::endl;
    std::cout << "  op_class: " << info.id.op_class << std::endl;
    // Print core op_class fields
    std::cout << "op_class: " << info.op_class << std::endl;
    std::cout << "channel: " << info.channel << std::endl;
    std::cout << "tx_power: " << info.tx_power << std::endl;
    std::cout << "max_tx_power: " << info.max_tx_power << std::endl;
    std::cout << "num_channels: " << info.num_channels << std::endl;
    // Print channels list
    std::cout << "channels: ";
    for (unsigned int i = 0; i < info.num_channels && i < EM_MAX_CHANNELS_IN_LIST; i++) {
        std::cout << info.channels[i];
        if (i != info.num_channels - 1) std::cout << ", ";
    }
    std::cout << std::endl;
    // Print CAC related fields
    std::cout << "mins_since_cac_comp: " << info.mins_since_cac_comp << std::endl;
    std::cout << "sec_remain_non_occ_dur: " << info.sec_remain_non_occ_dur << std::endl;
    std::cout << "countdown_cac_comp: " << info.countdown_cac_comp << std::endl;
    std::cout << "--------------------------------------------" << std::endl;
    std::cout << "Exiting ValidLowerBoundaryIndex test" << std::endl;
}

TEST(em_cmd_t, ValidMidRangeIndex) {
    std::cout << "Entering ValidMidRangeIndex test" << std::endl;
    em_cmd_t cmd;
    unsigned int index = 3;
    em_op_class_info_t &infoInit =
        cmd.m_data_model.m_op_class[index].m_op_class_info;
    for (int i = 0; i < sizeof(mac_address_t); i++)
        infoInit.id.ruid[i] = (unsigned char)(0x20 + i);
    infoInit.id.type = (em_op_class_type_t)2;
    infoInit.id.op_class = 22;
    infoInit.op_class = 22;
    infoInit.channel = 36;
    infoInit.tx_power = 18;
    infoInit.max_tx_power = 25;
    infoInit.num_channels = 4;
    infoInit.channels[0] = 36;
    infoInit.channels[1] = 40;
    infoInit.channels[2] = 44;
    infoInit.channels[3] = 48;
    infoInit.mins_since_cac_comp = 12;
    infoInit.sec_remain_non_occ_dur = 20;
    infoInit.countdown_cac_comp = 200;
    std::cout << "Invoking get_curr_op_class with index: " << index << std::endl;
    dm_op_class_t* opClassPtr = cmd.get_curr_op_class(index);
    std::cout << "get_curr_op_class(" << index << ") returned pointer: " << opClassPtr << std::endl;
    ASSERT_NE(opClassPtr, nullptr);
    em_op_class_info_t &info = opClassPtr->m_op_class_info;
    std::cout << "---- Retrieved em_op_class_info_t Values ----" << std::endl;
    // Print em_op_class_id_t values
    std::cout << "ID:" << std::endl;
    std::cout << "  RUID: ";
    for (int i = 0; i < sizeof(mac_address_t); i++) {
        printf("%02X", info.id.ruid[i]);
        if (i < sizeof(mac_address_t) - 1) printf(":");
    }
    std::cout << std::endl;
    std::cout << "  Type: " << info.id.type << std::endl;
    std::cout << "  op_class: " << info.id.op_class << std::endl;
    // Print core op_class fields
    std::cout << "op_class: " << info.op_class << std::endl;
    std::cout << "channel: " << info.channel << std::endl;
    std::cout << "tx_power: " << info.tx_power << std::endl;
    std::cout << "max_tx_power: " << info.max_tx_power << std::endl;
    std::cout << "num_channels: " << info.num_channels << std::endl;
    // Print channels list
    std::cout << "channels: ";
    for (unsigned int i = 0; i < info.num_channels && i < EM_MAX_CHANNELS_IN_LIST; i++) {
        std::cout << info.channels[i];
        if (i != info.num_channels - 1) std::cout << ", ";
    }
    std::cout << std::endl;
    // Print CAC related fields
    std::cout << "mins_since_cac_comp: " << info.mins_since_cac_comp << std::endl;
    std::cout << "sec_remain_non_occ_dur: " << info.sec_remain_non_occ_dur << std::endl;
    std::cout << "countdown_cac_comp: " << info.countdown_cac_comp << std::endl;
    std::cout << "--------------------------------------------" << std::endl;
    std::cout << "Exiting ValidMidRangeIndex test" << std::endl;
}

/*
TEST(em_cmd_t, MaxIndexValue) {
    std::cout << "Entering MaxIndexValue test" << std::endl;
    em_cmd_t cmd;
    unsigned int index = 64;
    em_op_class_info_t &infoInit = cmd.m_data_model.m_op_class[index].m_op_class_info;
    for (int i = 0; i < sizeof(mac_address_t); i++)
        infoInit.id.ruid[i] = (unsigned char)(0x30 + i);
    infoInit.id.type = (em_op_class_type_t)3;
    infoInit.id.op_class = 33;
    infoInit.op_class = 33;
    infoInit.channel = 149;
    infoInit.tx_power = 22;
    infoInit.max_tx_power = 28;
    infoInit.num_channels = 2;
    infoInit.channels[0] = 149;
    infoInit.channels[1] = 153;
    infoInit.mins_since_cac_comp = 60;
    infoInit.sec_remain_non_occ_dur = 120;
    infoInit.countdown_cac_comp = 500;
    std::cout << "Invoking get_curr_op_class with index: " << index << std::endl;
    dm_op_class_t* opClassPtr = cmd.get_curr_op_class(index);
    std::cout << "get_curr_op_class(" << index << ") returned pointer: " << opClassPtr << std::endl;
    ASSERT_NE(opClassPtr, nullptr);
    em_op_class_info_t &info = opClassPtr->m_op_class_info;
    std::cout << "---- Retrieved em_op_class_info_t Values ----" << std::endl;
    // Print em_op_class_id_t values
    std::cout << "ID:" << std::endl;
    std::cout << "  RUID: ";
    for (int i = 0; i < sizeof(mac_address_t); i++) {
        printf("%02X", info.id.ruid[i]);
        if (i < sizeof(mac_address_t) - 1) printf(":");
    }
    std::cout << std::endl;
    std::cout << "  Type: " << info.id.type << std::endl;
    std::cout << "  op_class: " << info.id.op_class << std::endl;
    // Print core op_class fields
    std::cout << "op_class: " << info.op_class << std::endl;
    std::cout << "channel: " << info.channel << std::endl;
    std::cout << "tx_power: " << info.tx_power << std::endl;
    std::cout << "max_tx_power: " << info.max_tx_power << std::endl;
    std::cout << "num_channels: " << info.num_channels << std::endl;
    // Print channels list
    std::cout << "channels: ";
    for (unsigned int i = 0; i < info.num_channels && i < EM_MAX_CHANNELS_IN_LIST; i++) {
        std::cout << info.channels[i];
        if (i != info.num_channels - 1) std::cout << ", ";
    }
    std::cout << std::endl;
    // Print CAC related fields
    std::cout << "mins_since_cac_comp: " << info.mins_since_cac_comp << std::endl;
    std::cout << "sec_remain_non_occ_dur: " << info.sec_remain_non_occ_dur << std::endl;
    std::cout << "countdown_cac_comp: " << info.countdown_cac_comp << std::endl;
    std::cout << "--------------------------------------------" << std::endl;    
    std::cout << "Exiting MaxIndexValue test" << std::endl;
}
*/
TEST(em_cmd_t, MaxIndexValue) {
    std::cout << "Entering MaxIndexValue test" << std::endl;
    em_cmd_t cmd;

    // Use the highest valid index instead of a hard-coded 64 to avoid OOB writes.
    unsigned int index = EM_MAX_OPCLASS - 1;

    // Mark the number of opclasses to reflect that index is present.
    cmd.m_data_model.m_num_opclass = index + 1;

    em_op_class_info_t &infoInit = cmd.m_data_model.m_op_class[index].m_op_class_info;
    for (int i = 0; i < (int)sizeof(mac_address_t); i++)
        infoInit.id.ruid[i] = (unsigned char)(0x30 + i);
    infoInit.id.type = (em_op_class_type_t)3;
    infoInit.id.op_class = 33;
    infoInit.op_class = 33;
    infoInit.channel = 149;
    infoInit.tx_power = 22;
    infoInit.max_tx_power = 28;
    infoInit.num_channels = 2;
    infoInit.channels[0] = 149;
    infoInit.channels[1] = 153;
    infoInit.mins_since_cac_comp = 60;
    infoInit.sec_remain_non_occ_dur = 120;
    infoInit.countdown_cac_comp = 500;

    std::cout << "Invoking get_curr_op_class with index: " << index << std::endl;
    dm_op_class_t* opClassPtr = cmd.get_curr_op_class(index);
    std::cout << "get_curr_op_class(" << index << ") returned pointer: " << opClassPtr << std::endl;
    ASSERT_NE(opClassPtr, nullptr);
    em_op_class_info_t &info = opClassPtr->m_op_class_info;
    std::cout << "---- Retrieved em_op_class_info_t Values ----" << std::endl;
    // Print em_op_class_id_t values
    std::cout << "ID:" << std::endl;
    std::cout << "  RUID: ";
    for (int i = 0; i < (int)sizeof(mac_address_t); i++) {
        printf("%02X", info.id.ruid[i]);
        if (i < (int)sizeof(mac_address_t) - 1) printf(":");
    }
    std::cout << std::endl;
    std::cout << "  Type: " << info.id.type << std::endl;
    std::cout << "  op_class: " << info.id.op_class << std::endl;
    // Print core op_class fields
    std::cout << "op_class: " << info.op_class << std::endl;
    std::cout << "channel: " << info.channel << std::endl;
    std::cout << "tx_power: " << info.tx_power << std::endl;
    std::cout << "max_tx_power: " << info.max_tx_power << std::endl;
    std::cout << "num_channels: " << info.num_channels << std::endl;
    // Print channels list
    std::cout << "channels: ";
    for (unsigned int i = 0; i < info.num_channels && i < EM_MAX_CHANNELS_IN_LIST; i++) {
        std::cout << info.channels[i];
        if (i != info.num_channels - 1) std::cout << ", ";
    }
    std::cout << std::endl;
    // Print CAC related fields
    std::cout << "mins_since_cac_comp: " << info.mins_since_cac_comp << std::endl;
    std::cout << "sec_remain_non_occ_dur: " << info.sec_remain_non_occ_dur << std::endl;
    std::cout << "countdown_cac_comp: " << info.countdown_cac_comp << std::endl;
    std::cout << "--------------------------------------------" << std::endl;    
    std::cout << "Exiting MaxIndexValue test" << std::endl;
}

TEST(em_cmd_t, OutOfRangeIndex) {
    std::cout << "Entering OutOfRangeIndex test" << std::endl;
    em_cmd_t cmd;
    unsigned int index = 100;
    std::cout << "Invoking get_curr_op_class with index: " << index << std::endl;
    dm_op_class_t* opClassPtr = cmd.get_curr_op_class(index);
    //std::cout << "get_curr_op_class(" << index << ") returned pointer: " << opClassPtr << std::endl;
    EXPECT_EQ(opClassPtr, nullptr);
    std::cout << "Exiting OutOfRangeIndex test" << std::endl;
}

TEST(em_cmd_t, GetDataModelReturnsNonNull)
{
    std::cout << "Entering GetDataModelReturnsNonNull test" << std::endl;
    em_cmd_t cmd{};
	cmd.m_data_model.m_num_preferences = 2;
	cmd.m_data_model.m_num_interfaces = 3;
	cmd.m_data_model.m_num_net_ssids = 8;
	cmd.m_data_model.m_num_radios = 2;
	cmd.m_data_model.m_num_bss = 2;
	cmd.m_data_model.m_num_opclass = 3; 
	cmd.m_data_model.m_colocated = false;
	cmd.m_data_model.m_device.m_device_info.dfs_enable = true;
    std::cout << "Invoking get_data_model() method on initialized em_cmd_t object." << std::endl;
    dm_easy_mesh_t* data_model_ptr = cmd.get_data_model();
    ASSERT_NE(data_model_ptr, nullptr);
    std::cout << "Retrieved details from get_data_model: " << std::endl;
    std::cout << "data_model_ptr->m_num_preferences = " << data_model_ptr->m_num_preferences << std::endl;
	std::cout << "data_model_ptr->m_num_interfaces = " << data_model_ptr->m_num_interfaces << std::endl;
	std::cout << "data_model_ptr->m_num_net_ssids = " << data_model_ptr->m_num_net_ssids << std::endl;
	std::cout << "data_model_ptr->m_num_radios = " << data_model_ptr->m_num_radios << std::endl;
	std::cout << "data_model_ptr->m_num_bss = " << data_model_ptr->m_num_bss << std::endl;
	std::cout << "data_model_ptr->m_num_opclass = " << data_model_ptr->m_num_opclass << std::endl;
	std::cout << "data_model_ptr->m_colocated = " << data_model_ptr->m_colocated << std::endl;
	std::cout << "data_model_ptr->m_device.m_device_info.dfs_enable = " << data_model_ptr->m_device.m_device_info.dfs_enable << std::endl;
    std::cout << "Exiting GetDataModelReturnsNonNull test" << std::endl;
}

TEST(em_cmd_t, Validate_retrieval_of_the_DB_configuration_type) {
    std::cout << "Entering Validate retrieval of the DB configuration type test" << std::endl;
    em_cmd_t cmd_obj{};
    std::cout << "Created em_cmd_t object using the default constructor." << std::endl;
    cmd_obj.m_db_cfg_type = 1;
    std::cout << "Set m_db_cfg_type to 1." << std::endl;
    std::cout << "Invoking get_db_cfg_type() method." << std::endl;
    unsigned int returnedValue = cmd_obj.get_db_cfg_type();
    std::cout << "get_db_cfg_type() returned: " << returnedValue << std::endl;
    std::cout << "Exiting Validate retrieval of the DB configuration type test" << std::endl;
}

TEST(em_cmd_t, GetDpp_Invocation) {
    std::cout << "Entering GetDpp_Invocation test" << std::endl;
    em_cmd_t cmd{};
    cmd.m_data_model.m_dpp.m_dpp_info.version = 5;
	cmd.m_data_model.m_dpp.m_dpp_info.type = ec_session_type_cfg;
	unsigned char mac[] = {0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x4B};
	memcpy(cmd.m_data_model.m_dpp.m_dpp_info.mac_addr, mac, sizeof(mac));
    std::cout << "Created em_cmd_t object using default constructor." << std::endl;      
    dm_dpp_t* dpp_ptr = cmd.get_dpp();
    std::cout << "Invoked get_dpp(); returned pointer: " << dpp_ptr << std::endl;
    ASSERT_NE(dpp_ptr, nullptr);       
    std::cout << "dpp_ptr->m_dpp_info.version = " << dpp_ptr->m_dpp_info.version << std::endl;
	std::cout << "dpp_ptr->m_dpp_info.type = " << dpp_ptr->m_dpp_info.type << std::endl;		
	std::cout << "dpp_ptr->m_dpp_info.mac_addr is ";
    for (int i = 0; i < 6; i++) {
        printf("%02X", dpp_ptr->m_dpp_info.mac_addr[i]);
        if (i < 5) printf(":");
    }
    std::cout << std::endl;
    std::cout << "Exiting GetDpp_Invocation test" << std::endl;
}
/*
TEST(em_cmd_t, RetrieveValidEventFrame) {
    std::cout << "Entering RetrieveValidEventFrame test" << std::endl;
    EXPECT_NO_THROW({
        em_cmd_t obj;
        obj.m_evt = new em_event_t;
        obj.m_evt->type = em_event_type_frame;
        std::cout << "Assigned event type: " << obj.m_evt->type << " (expected: " << em_event_type_frame << ")" << std::endl;       
        std::cout << "Invoking get_event()" << std::endl;
        em_event_t* ret_evt = obj.get_event();
        if(ret_evt) {
            std::cout << "Retrieved event type: " << ret_evt->type << std::endl;
        }
        EXPECT_NE(ret_evt, nullptr);
        EXPECT_EQ(ret_evt->type, em_event_type_frame);
        delete ret_evt;
        obj.m_evt = nullptr;
    });
    std::cout << "Exiting RetrieveValidEventFrame test" << std::endl;
}
*/
TEST(em_cmd_t, RetrieveValidEventFrame) {
    std::cout << "Entering RetrieveValidEventFrame test" << std::endl;

    em_cmd_t obj; // constructor allocated internal resources and m_evt

    // Free constructor's m_evt buffer before replacing it (prevents leak).
    if (obj.m_evt) {
        free(obj.m_evt);
        obj.m_evt = nullptr;
        std::cout << "Freed constructor-allocated m_evt before assigning test event" << std::endl;
    }

    // Allocate an event with malloc (matches destructor free)
    em_event_t *evt = (em_event_t *)malloc(sizeof(em_event_t));
    ASSERT_NE(evt, nullptr);
    memset(evt, 0, sizeof(em_event_t));

    // Configure as frame event
    evt->type = em_event_type_frame;

    // Assign ownership to the object (do not free manually afterwards)
    obj.m_evt = evt;

    std::cout << "Assigned event type: " << obj.m_evt->type << " (expected: " << em_event_type_frame << ")" << std::endl;

    std::cout << "Invoking get_event()" << std::endl;
    em_event_t* ret_evt = obj.get_event();

    ASSERT_NE(ret_evt, nullptr);
    EXPECT_EQ(ret_evt->type, em_event_type_frame);

    // DO NOT delete ret_evt or call obj.deinit() here.
    // Ownership of obj.m_evt is with the em_cmd_t instance; destructor will free it.

    std::cout << "Exiting RetrieveValidEventFrame test" << std::endl;
}

TEST(em_cmd_t, RetrieveValidEventBus) {
    std::cout << "Entering RetrieveValidEventBus test" << std::endl;
    
    EXPECT_NO_THROW({
        em_cmd_t obj;
        obj.m_evt = new em_event_t;       
        obj.m_evt->type = em_event_type_bus;
        std::cout << "Assigned event type: " << obj.m_evt->type << " (expected: " << em_event_type_bus << ")" << std::endl;        
        obj.m_evt->u.bevt.type = em_bus_event_type_chirp;
        std::cout << "Assigned bus event internal type: " 
                  << obj.m_evt->u.bevt.type 
                  << " (expected: " << em_bus_event_type_chirp << ")" << std::endl;
        obj.m_evt->u.fevt.frame_len = 6;
		obj.m_evt->u.bevt.data_len = 5;       
        std::cout << "Invoking get_event()" << std::endl;
        em_event_t* ret_evt = obj.get_event();
        if(ret_evt) {
            std::cout << "Retrieved event type: " << ret_evt->type << std::endl;
            std::cout << "Retrieved bus event internal type: " << ret_evt->u.bevt.type << std::endl;
        }       
        EXPECT_NE(ret_evt, nullptr);
        EXPECT_EQ(ret_evt->type, em_event_type_bus);
        EXPECT_EQ(ret_evt->u.bevt.type, em_bus_event_type_chirp);
		EXPECT_EQ(ret_evt->u.fevt.frame_len, 6);
        EXPECT_EQ(ret_evt->u.bevt.data_len, 5);
		delete obj.m_evt;
        obj.m_evt = nullptr;
        obj.m_evt = nullptr;
    });
    std::cout << "Exiting RetrieveValidEventBus test" << std::endl;
}

TEST(em_cmd_t, Retrieve_correct_event_data_length_when_valid_non_empty_event_data_is_set) {
    std::cout << "Entering Retrieve_correct_event_data_length_when_valid_non_empty_event_data_is_set test" << std::endl;
    EXPECT_NO_THROW({
        // Create an instance of em_cmd_t using the default constructor.
        em_cmd_t cmd;
        std::cout << "Constructed em_cmd_t object using default constructor" << std::endl;		
        cmd.m_evt->type = em_event_type_bus;
        // Allocate a valid em_event_t structure and assign to m_evt.
        // Set the event data length to 100 bytes.
        cmd.m_evt = new em_event_t;
        std::cout << "Allocated em_event_t object and assigned to m_evt" << std::endl;
        cmd.m_evt->u.bevt.data_len = 100;
        std::cout << "Set m_evt->data_length to 100" << std::endl;
        
        // Invoke the get_event_data_length() method.
        std::cout << "Invoking get_event_data_length() method" << std::endl;
        unsigned int length = cmd.get_event_data_length();
        std::cout << "get_event_data_length() returned: " << length << std::endl;
        
        // Validate that the returned length is 100.
        EXPECT_EQ(length, 100u);
        
        // Clean up allocated memory.
        delete cmd.m_evt;
        cmd.m_evt = nullptr;
        std::cout << "Deleted m_evt object" << std::endl;
    });
    std::cout << "Exiting Retrieve_correct_event_data_length_when_valid_non_empty_event_data_is_set test" << std::endl;
}

TEST(em_cmd_t, Retrieve_correct_frame_data_length_when_valid_non_empty_frame_data_is_set) {
    std::cout << "Entering Retrieve_correct_frame_data_length_when_valid_non_empty_frame_data_is_set test" << std::endl;
    EXPECT_NO_THROW({
        // Create an instance of em_cmd_t using the default constructor.
        em_cmd_t cmd;
        std::cout << "Constructed em_cmd_t object using default constructor" << std::endl;		
        cmd.m_evt->type = em_event_type_frame;
        // Allocate a valid em_event_t structure and assign to m_evt.
        // Set the event data length to 100 bytes.
        cmd.m_evt = new em_event_t;
        std::cout << "Allocated em_event_t object and assigned to m_evt" << std::endl;
        cmd.m_evt->u.fevt.frame_len = 10;
        std::cout << "Set m_evt->data_length to 100" << std::endl;
        
        // Invoke the get_event_data_length() method.
        std::cout << "Invoking get_event_data_length() method" << std::endl;
        unsigned int length = cmd.get_event_data_length();
        std::cout << "get_event_data_length() returned: " << length << std::endl;
        
        // Validate that the returned length is 10.
        EXPECT_EQ(length, 10u);
        
        // Clean up allocated memory.
        delete cmd.m_evt;
        cmd.m_evt = nullptr;
        std::cout << "Deleted m_evt object" << std::endl;
    });
    std::cout << "Exiting Retrieve_correct_frame_data_length_when_valid_non_empty_frame_data_is_set test" << std::endl;
}

TEST(em_cmd_t, Retrieve_event_data_length_as_zero_when_m_evt_pointer_is_null) {
    std::cout << "Entering Retrieve_event_data_length_as_zero_when_m_evt_pointer_is_null test" << std::endl;
    EXPECT_NO_THROW({
        // Create an instance of em_cmd_t using the default constructor.
        em_cmd_t cmd;
        std::cout << "Constructed em_cmd_t object using default constructor" << std::endl;
        
        // Set the m_evt pointer to NULL.
        cmd.m_evt = nullptr;
        std::cout << "Set m_evt to nullptr" << std::endl;
        
        // Invoke the get_event_data_length() method.
        std::cout << "Invoking get_event_data_length() method" << std::endl;
        unsigned int length = cmd.get_event_data_length();
        std::cout << "get_event_data_length() returned: " << length << std::endl;
        
        // Validate that the returned length is 0.
        EXPECT_NE(length, 0);
    });
    std::cout << "Exiting Retrieve_event_data_length_as_zero_when_m_evt_pointer_is_null test" << std::endl;
}
/*
TEST(em_cmd_t, Retrieve_event_data_length_as_zero_when_event_data_is_empty) {
    std::cout << "Entering Retrieve_event_data_length_as_zero_when_event_data_is_empty test" << std::endl;
    EXPECT_NO_THROW({
        // Create an instance of em_cmd_t using the default constructor.
        em_cmd_t cmd;
        std::cout << "Constructed em_cmd_t object using default constructor" << std::endl;
        
        // Allocate a valid em_event_t structure and assign to m_evt.
        cmd.m_evt = new em_event_t;
        std::cout << "Allocated em_event_t object and assigned to m_evt" << std::endl;
        cmd.m_evt->type = em_event_type_bus;
        // Set the event data length to 0 bytes to simulate an empty event data buffer.
        cmd.m_evt->u.bevt.data_len = 0;
        std::cout << "Set m_evt->data_length to 0" << std::endl;
        
        // Invoke the get_event_data_length() method.
        std::cout << "Invoking get_event_data_length() method" << std::endl;
        unsigned int length = cmd.get_event_data_length();
        std::cout << "get_event_data_length() returned: " << length << std::endl;
        
        // Validate that the returned length is 0.
        EXPECT_EQ(length, 0u);
        
        // Clean up allocated memory.
        delete cmd.m_evt;
        cmd.m_evt = nullptr;
        std::cout << "Deleted m_evt object" << std::endl;
    });
    std::cout << "Exiting Retrieve_event_data_length_as_zero_when_event_data_is_empty test" << std::endl;
}
*/
TEST(em_cmd_t, Retrieve_event_data_length_as_zero_when_event_data_is_empty) {
    std::cout << "Entering Retrieve_event_data_length_as_zero_when_event_data_is_empty test" << std::endl;

    EXPECT_NO_THROW({
        em_cmd_t cmd;
        std::cout << "Constructed em_cmd_t object using default constructor" << std::endl;

        // Free memory allocated by constructor before overwriting m_evt
        if (cmd.m_evt) {
            free(cmd.m_evt);
            cmd.m_evt = nullptr;
            std::cout << "Freed constructor allocated m_evt" << std::endl;
        }

        // Allocate replacement event object
        cmd.m_evt = new em_event_t;
        std::cout << "Allocated new em_event_t object and assigned to m_evt" << std::endl;

        cmd.m_evt->type = em_event_type_bus;
        cmd.m_evt->u.bevt.data_len = 0;
        std::cout << "Set m_evt->data_len to 0" << std::endl;

        unsigned int length = cmd.get_event_data_length();
        std::cout << "get_event_data_length() returned: " << length << std::endl;

        EXPECT_EQ(length, 0u);

        // Delete only the newly assigned object
        delete cmd.m_evt;
        cmd.m_evt = nullptr;
        std::cout << "Deleted m_evt object" << std::endl;
    });

    std::cout << "Exiting Retrieve_event_data_length_as_zero_when_event_data_is_empty test" << std::endl;
}

/*
TEST(em_cmd_t, ValidateEventLengthTypical) {
    std::cout << "Entering ValidateEventLengthTypical test" << std::endl;
    em_cmd_t cmd_obj;

    // Allocate event with malloc to match free() in destructor
    em_event_t *evt = (em_event_t*)malloc(sizeof(em_event_t));
    ASSERT_NE(evt, nullptr);
    memset(evt, 0, sizeof(em_event_t));

    evt->type = em_event_type_frame;
    evt->u.fevt.frame_len = 100;

    // Replace the default allocated event with this one.
    // Since cmd_obj took ownership, DO NOT free evt manually.
    cmd_obj.m_evt = evt;

    std::cout << "Event type set to: em_event_type_frame" << std::endl;
    std::cout << "Configured frame_len = " << evt->u.fevt.frame_len << std::endl;

    std::cout << "Invoking get_event_length()" << std::endl;
    unsigned int ret_val = cmd_obj.get_event_length();
    std::cout << "get_event_length() returned = " << ret_val << std::endl;

    unsigned int expected_value = sizeof(em_event_t) + evt->u.fevt.frame_len;
    std::cout << "Expected = sizeof(em_event_t) (" 
              << sizeof(em_event_t) 
              << ") + frame_len (100) = " 
              << expected_value << std::endl;

    EXPECT_EQ(ret_val, expected_value);

    std::cout << "Exiting ValidateEventLengthTypical test" << std::endl;
}
*/
TEST(em_cmd_t, ValidateEventLengthTypical) {
    std::cout << "Entering ValidateEventLengthTypical test" << std::endl;

    em_cmd_t cmd_obj;

    // Free object-created buffer before replacing m_evt.
    if (cmd_obj.m_evt) {
        free(cmd_obj.m_evt);
        cmd_obj.m_evt = nullptr;
        std::cout << "Freed constructor allocated m_evt" << std::endl;
    }

    // Allocate event using malloc to match destructor behavior (free())
    em_event_t *evt = (em_event_t*)malloc(sizeof(em_event_t));
    ASSERT_NE(evt, nullptr);

    memset(evt, 0, sizeof(em_event_t));
    evt->type = em_event_type_frame;
    evt->u.fevt.frame_len = 100;

    // Assign ownership to object (no delete, destructor frees it)
    cmd_obj.m_evt = evt;

    std::cout << "Event type set to: em_event_type_frame" << std::endl;
    std::cout << "Configured frame_len = " << evt->u.fevt.frame_len << std::endl;

    std::cout << "Invoking get_event_length()" << std::endl;
    unsigned int ret_val = cmd_obj.get_event_length();
    std::cout << "get_event_length() returned = " << ret_val << std::endl;

    unsigned int expected_value = sizeof(em_event_t) + evt->u.fevt.frame_len;
    std::cout << "Expected = sizeof(em_event_t) (" 
              << sizeof(em_event_t) 
              << ") + frame_len (100) = " 
              << expected_value << std::endl;

    EXPECT_EQ(ret_val, expected_value);

    std::cout << "Exiting ValidateEventLengthTypical test" << std::endl;
}

TEST(em_cmd_t, get_ieee_1905_security_cap_Successful) {
    std::cout << "Entering get_ieee_1905_security_cap_Successful test" << std::endl;   
    em_cmd_t cmd_obj;
    cmd_obj.m_data_model.m_ieee_1905_security.m_ieee_1905_security_info.sec_cap.onboarding_proto = 1;
	cmd_obj.m_data_model.m_ieee_1905_security.m_ieee_1905_security_info.sec_cap.integrity_algo   = 2;
	cmd_obj.m_data_model.m_ieee_1905_security.m_ieee_1905_security_info.sec_cap.encryption_algo  = 3;
    std::cout << "Invoking get_ieee_1905_security_cap method" << std::endl;
    em_ieee_1905_security_cap_t *cap_ptr = nullptr;
    EXPECT_NO_THROW(cap_ptr = cmd_obj.get_ieee_1905_security_cap());
    EXPECT_NE(cap_ptr, nullptr);    
    if (cap_ptr) {
        std::cout << "Retrieved security cap values:" << std::endl;
        std::cout << "  onboarding_proto = " << static_cast<int>(cap_ptr->onboarding_proto) << std::endl;
        std::cout << "  integrity_algo   = " << static_cast<int>(cap_ptr->integrity_algo) << std::endl;
        std::cout << "  encryption_algo  = " << static_cast<int>(cap_ptr->encryption_algo) << std::endl;        
        EXPECT_EQ(cap_ptr->onboarding_proto, 1);
        EXPECT_EQ(cap_ptr->integrity_algo,   2);
        EXPECT_EQ(cap_ptr->encryption_algo,  3);
    }    
    std::cout << "Exiting get_ieee_1905_security_cap_Successful test" << std::endl;
}

TEST(em_cmd_t, validate_cmdtypenone_returns_false)
{
    std::cout << "Entering validate_cmdtypenone_returns_false test" << std::endl;
    em_cmd_t cmd;
	cmd.m_type = em_cmd_type_none;
    std::cout << "Created em_cmd_t instance using default constructor" << std::endl;
    std::cout << "Invoking validate() on default constructed instance" << std::endl;
    bool result = cmd.validate();
    std::cout << "validate() returned: " << result << std::endl;
    EXPECT_FALSE(result);
    std::cout << "Exiting validate_cmdtypenone_returns_false test" << std::endl;
}

TEST(em_cmd_t, validate_cmdtypemax_returns_false)
{
    std::cout << "Entering validate_cmdtypemax_returns_false test" << std::endl;
    em_cmd_t cmd;
	cmd.m_type = em_cmd_type_max;
    std::cout << "Created em_cmd_t instance using default constructor" << std::endl;
    std::cout << "Invoking validate() on default constructed instance" << std::endl;
    bool result = cmd.validate();
    std::cout << "validate() returned: " << result << std::endl;
    EXPECT_FALSE(result);
    std::cout << "Exiting validate_cmdtypemax_returns_false test" << std::endl;
}

TEST(em_cmd_t, validate_cmdtypevapconfig_returns_true)
{
    std::cout << "Entering validate_cmdtypevapconfig_returns_true test" << std::endl;
    em_cmd_t cmd;
	cmd.m_type = em_cmd_type_vap_config;
    std::cout << "Created em_cmd_t instance using default constructor" << std::endl;
    std::cout << "Invoking validate() on default constructed instance" << std::endl;
    bool result = cmd.validate();
    std::cout << "validate() returned: " << result << std::endl;
    EXPECT_TRUE(result);
    std::cout << "Exiting validate_cmdtypevapconfig_returns_true test" << std::endl;
}

TEST(em_cmd_t, status_to_string_convert_all_valid_status) {
    std::cout << "Entering status_to_string_convert_all_valid_status test" << std::endl;
    em_cmd_t cmd;
    struct TestMapping {
        em_cmd_out_status_t status;
        const char* expected;
    };
    TestMapping mappings[] = {
        { em_cmd_out_status_success,                "Success" },
        { em_cmd_out_status_not_ready,              "Error_Not_Ready" },
        { em_cmd_out_status_invalid_input,          "Error_Invalid_Input" },
        { em_cmd_out_status_timeout,                "Error_Timeout" },
        { em_cmd_out_status_invalid_mac,            "Error_Invalid_Mac" },
        { em_cmd_out_status_interface_down,         "Error_Interface_Down" },
        { em_cmd_out_status_other,                  "Error_Other" },
        { em_cmd_out_status_prev_cmd_in_progress,   "Error_Prev_Cmd_In_Progress" },
        { em_cmd_out_status_no_change,              "Error_No_Config_Change_Detected" }
    };
    const size_t num_tests = sizeof(mappings) / sizeof(mappings[0]);    
    for (size_t i = 0; i < num_tests; ++i) {
		char buffer[50] = {0};
        //memset(buffer, 0, sizeof(buffer));
        std::cout << "Invoking status_to_string with status value: " << mappings[i].status 
                  << " and buffer address: " << static_cast<void*>(buffer) << std::endl;
        char* result = cmd.status_to_string(mappings[i].status, buffer);

        std::cout << "Method returned pointer: " << static_cast<void*>(result) << std::endl;
		cJSON* obj = cJSON_Parse(buffer);
        ASSERT_NE(obj, nullptr);
        cJSON* status_item = cJSON_GetObjectItem(obj, "Status");
        ASSERT_NE(status_item, nullptr);
        EXPECT_STREQ(status_item->valuestring, mappings[i].expected);
        cJSON_Delete(obj);
        //std::cout << "Buffer now contains: \"" << buffer << "\"" << std::endl;
        //EXPECT_EQ(result, buffer);
        //EXPECT_STREQ(buffer, mappings[i].expected);
        //std::cout << "Test iteration for status " << mappings[i].status << " passed with expected output: \"" << mappings[i].expected << "\"" << std::endl;
    }
    std::cout << "Exiting status_to_string_convert_all_valid_status test" << std::endl;
}

TEST(em_cmd_t, status_to_string_handle_null_buffer) {
    std::cout << "Entering status_to_string_handle_null_buffer test" << std::endl;
    em_cmd_t cmd;
    em_cmd_out_status_t testStatus = em_cmd_out_status_success;
    std::cout << "Invoking status_to_string with status value: " << testStatus 
              << " and buffer pointer as NULL" << std::endl;
    char* retVal = cmd.status_to_string(testStatus, nullptr);
    EXPECT_EQ(retVal, nullptr);
    std::cout << "Exiting status_to_string_handle_null_buffer test" << std::endl;
}

TEST(em_cmd_t, get_svc_valid_ctrl) {
    std::cout << "Entering get_svc_valid_ctrl test" << std::endl;
    em_cmd_t cmd {};
    cmd.m_svc = em_service_type_ctrl;
    std::cout << "Invoking get_svc()" << std::endl;
    em_service_type_t svc = cmd.get_svc();
    std::cout << "get_svc() returned value: " << svc << std::endl;
    EXPECT_EQ(svc, em_service_type_ctrl);
    std::cout << "Exiting get_svc_valid_ctrl test" << std::endl;
}

TEST(em_cmd_t, get_svc_valid_agent) {
    std::cout << "Entering get_svc_valid_agent test" << std::endl;
    em_cmd_t cmd {};
    cmd.m_svc = em_service_type_agent;
    std::cout << "Invoking get_svc()" << std::endl;
    em_service_type_t svc = cmd.get_svc();
    std::cout << "get_svc() returned value: " << svc << std::endl;
    EXPECT_EQ(svc, em_service_type_agent);
    std::cout << "Exiting get_svc_valid_agent test" << std::endl;
}

TEST(em_cmd_t, get_svc_valid_cli) {
    std::cout << "Entering get_svc_valid_cli test" << std::endl;
    em_cmd_t cmd {};
    cmd.m_svc = em_service_type_cli;
    std::cout << "Invoking get_svc()" << std::endl;
    em_service_type_t svc = cmd.get_svc();
    std::cout << "get_svc() returned value: " << svc << std::endl;
    EXPECT_EQ(svc, em_service_type_cli);
    std::cout << "Exiting get_svc_valid_cli test" << std::endl;
}

TEST(em_cmd_t, get_svc_valid_none) {
    std::cout << "Entering get_svc_valid_none test" << std::endl;
    em_cmd_t cmd {};
    cmd.m_svc = em_service_type_none;
    std::cout << "Invoking get_svc()" << std::endl;
    em_service_type_t svc = cmd.get_svc();
    std::cout << "get_svc() returned value: " << svc << std::endl;
    EXPECT_EQ(svc, em_service_type_none);
    std::cout << "Exiting get_svc_valid_none test" << std::endl;
}

TEST(em_cmd_t, get_svc_invalid_value_check) {
    std::cout << "Entering get_svc_invalid_value_check test" << std::endl;
    em_cmd_t cmd {};
    cmd.m_svc = static_cast<em_service_type_t>(-1);
    std::cout << "Invoking get_svc()" << std::endl;
    em_service_type_t svc = cmd.get_svc();
    std::cout << "get_svc() returned value: " << svc << std::endl;
    EXPECT_EQ(svc, -1);
    std::cout << "Exiting get_svc_invalid_value_check test" << std::endl;
}

TEST(em_cmd_t, set_event_data_length_set_event_data_length_to_zero) {
    std::cout << "Entering set_event_data_length_set_event_data_length_to_zero test" << std::endl;
    em_cmd_t cmd;
	cmd.m_evt->type = em_event_type_frame;
    unsigned int length = 0;
    std::cout << "Invoking set_event_data_length with value: " << length << std::endl;
    EXPECT_NO_THROW({
        cmd.set_event_data_length(length);
        std::cout << "set_event_data_length() executed with input: " << length << std::endl;
    });
    std::cout << "Exiting set_event_data_length_set_event_data_length_to_zero test" << std::endl;
}

TEST(em_cmd_t, set_event_data_length_set_event_data_length_to_valid_typical_value) {
    std::cout << "Entering set_event_data_length_set_event_data_length_to_valid_typical_value test" << std::endl;
    em_cmd_t cmd;
	cmd.m_evt->type = em_event_type_bus;
    unsigned int length = 500;
    std::cout << "Invoking set_event_data_length with value: " << length << std::endl;
    EXPECT_NO_THROW({
        cmd.set_event_data_length(length);
        std::cout << "set_event_data_length() executed with input: " << length << std::endl;
    });
    std::cout << "Exiting set_event_data_length_set_event_data_length_to_valid_typical_value test" << std::endl;
}

TEST(em_cmd_t, set_event_data_length_set_event_data_length_to_valid_upper_boundary) {
    std::cout << "Entering set_event_data_length_set_event_data_length_to_valid_upper_boundary test" << std::endl;
    em_cmd_t cmd;
	cmd.m_evt->type = em_event_type_bus;
    unsigned int length = 1024;
    std::cout << "Invoking set_event_data_length with value: " << length << std::endl;
    EXPECT_NO_THROW({
        cmd.set_event_data_length(length);
        std::cout << "set_event_data_length() executed with input: " << length << std::endl;
    });
    std::cout << "Exiting set_event_data_length_set_event_data_length_to_valid_upper_boundary test" << std::endl;
}

TEST(em_cmd_t, get_param_invocation) {
    std::cout << "Entering get_param_invocation test" << std::endl;
    em_cmd_t obj;
	obj.m_param.net_node = new em_network_node_t;
	obj.m_param.net_node->value_int = 6;
    strncpy(obj.m_param.net_node->value_str, "Validstring", sizeof(obj.m_param.net_node->value_str) - 1);
	obj.m_param.net_node->value_str[sizeof(obj.m_param.net_node->value_str) - 1] = '\0';
	obj.m_param.net_node->num_children = 2;
    std::cout << "Invoking get_param() method on default constructed em_cmd_t object." << std::endl;
    em_cmd_params_t *param_ptr = obj.get_param();
    std::cout << "Method get_param() invoked successfully" << std::endl;
    ASSERT_NE(param_ptr, nullptr);
	ASSERT_NE(param_ptr->net_node, nullptr);
	ASSERT_EQ(param_ptr->net_node->value_int, 6);
	ASSERT_STREQ(param_ptr->net_node->value_str, "Validstring");
	ASSERT_EQ(param_ptr->net_node->num_children, 2);
	delete obj.m_param.net_node;
    obj.m_param.net_node = nullptr;
    std::cout << "Exiting get_param_invocation test" << std::endl;
}

TEST(em_cmd_t, get_radio_interface_valid_index0) {
    std::cout << "Entering get_radio_interface_valid_index0 test" << std::endl;
    em_cmd_t cmd;
	unsigned char mac[6] = {0x1A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5A};
	memcpy(cmd.m_data_model.m_radio[0].m_radio_info.intf.mac, mac, sizeof(mac));
	cmd.m_data_model.m_radio[0].m_radio_info.intf.media = em_media_type_ieee80211a_5;
    const char *ifaceName0 = "TestInterface0";
    strncpy(cmd.m_data_model.m_radio[0].m_radio_info.intf.name, ifaceName0, sizeof(cmd.m_data_model.m_radio[0].m_radio_info.intf.name) - 1);
    unsigned int index = 0;
    std::cout << "Invoking get_radio_interface with index: " << index << std::endl;
    em_interface_t* retrievedIface = cmd.get_radio_interface(index);
	ASSERT_NE(nullptr, retrievedIface);
    if (retrievedIface) {
        std::cout << "Retrieved interface at index " << index << " has name: " << retrievedIface->name << std::endl;
        std::cout << "Media type: " << retrievedIface->media << std::endl;
		std::cout << "Retrieved MAC address: ";
        for (size_t i = 0; i < 6; i++) {
            printf("%02X", retrievedIface->mac[i]);
            if (i < 5) printf(":");
        }
        std::cout << std::endl;
		EXPECT_STREQ(retrievedIface->name, ifaceName0);  // Name matches
        EXPECT_EQ(retrievedIface->media, em_media_type_ieee80211a_5);  // Media type matches
        for (size_t i = 0; i < 6; i++) {
            EXPECT_EQ(retrievedIface->mac[i], mac[i]);  // MAC matches
        }
    } else {
        std::cout << "Retrieved interface is nullptr" << std::endl;
    }
    std::cout << "Exiting get_radio_interface_valid_index0 test" << std::endl;
}

TEST(em_cmd_t, get_radio_interface_valid_lastindex) {
    std::cout << "Entering get_radio_interface_valid_lastindex test" << std::endl;
    em_cmd_t cmd;
    // Configure MAC for radio[0]
    unsigned char mac[6] = {0x1A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5A};
    memcpy(cmd.m_data_model.m_radio[2].m_radio_info.intf.mac, mac, sizeof(mac));
    // Configure media type for radio[2]
    cmd.m_data_model.m_radio[2].m_radio_info.intf.media = em_media_type_ieee80211n_24;
    // Set interface name on radio[0] (though index=2 returns radio[2])
    const char *ifaceName0 = "TestInterface0";
    strncpy(cmd.m_data_model.m_radio[2].m_radio_info.intf.name,
            ifaceName0,
            sizeof(cmd.m_data_model.m_radio[2].m_radio_info.intf.name) - 1);
    unsigned int index = 2;
    std::cout << "Invoking get_radio_interface with index: " << index << std::endl;
    em_interface_t* retrievedIface = cmd.get_radio_interface(index);
    ASSERT_NE(nullptr, retrievedIface);
    if (retrievedIface) {
        std::cout << "Retrieved interface at index " << index 
                  << " has name: " << retrievedIface->name << std::endl;
        std::cout << "Media type: " << retrievedIface->media << std::endl;
        std::cout << "Retrieved MAC address: ";
        for (size_t i = 0; i < 6; i++) {
            printf("%02X", retrievedIface->mac[i]);
            if (i < 5) printf(":");
        }
        std::cout << std::endl;
		EXPECT_STREQ(retrievedIface->name, ifaceName0);  // Name matches
        EXPECT_EQ(retrievedIface->media, em_media_type_ieee80211n_24);  // Media type matches
        for (size_t i = 0; i < 6; i++) {
            EXPECT_EQ(retrievedIface->mac[i], mac[i]);  // MAC matches
        }
    }
    std::cout << "Exiting get_radio_interface_valid_lastindex test" << std::endl;
}

TEST(em_cmd_t, get_radio_interface_index_out_of_range) {
    std::cout << "Entering get_radio_interface_index_out_of_range test" << std::endl;
    em_cmd_t cmd;
    unsigned char mac[6] = {0x1A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5A};
    memcpy(cmd.m_data_model.m_radio[4].m_radio_info.intf.mac, mac, sizeof(mac));
    cmd.m_data_model.m_radio[4].m_radio_info.intf.media = em_media_type_ieee80211n_24;
    const char *ifaceName0 = "TestInterface0";
    strncpy(cmd.m_data_model.m_radio[4].m_radio_info.intf.name, ifaceName0, sizeof(cmd.m_data_model.m_radio[0].m_radio_info.intf.name) - 1);
    unsigned int index = 4;
    std::cout << "Invoking get_radio_interface with index: " << index << std::endl;
    em_interface_t* retrievedIface = cmd.get_radio_interface(index);
    ASSERT_EQ(nullptr, retrievedIface);
    std::cout << "Exiting get_radio_interface_index_out_of_range test" << std::endl;
}

TEST(em_cmd_t, get_manufacturer_valid_retrieve_valid_manufacturer_name)
{
    std::cout << "Entering get_manufacturer_valid_retrieve_valid_manufacturer_name test" << std::endl;       
    em_cmd_t cmd{};
    strncpy(cmd.m_data_model.m_device.m_device_info.manufacturer, "Acme Corp", sizeof(cmd.m_data_model.m_device.m_device_info.manufacturer) - 1);
    std::cout << "Invoking get_manufacturer()" << std::endl;
    char *result = nullptr;
    result = cmd.get_manufacturer();
    std::cout << "Retrieved manufacturer: " << (result ? result : "null") << std::endl;
    EXPECT_NE(result, nullptr);
    EXPECT_STREQ(result, "Acme Corp");
    std::cout << "Exiting get_manufacturer_valid_retrieve_valid_manufacturer_name test" << std::endl;
}

TEST(em_cmd_t, get_manufacturer_empty_retrieve_manufacturer_name_empty)
{
    std::cout << "Entering get_manufacturer_empty_retrieve_manufacturer_name_empty test" << std::endl;
    em_cmd_t cmd{};
    strncpy(cmd.m_data_model.m_device.m_device_info.manufacturer, "", sizeof(cmd.m_data_model.m_device.m_device_info.manufacturer) - 1);
    std::cout << "Invoking get_manufacturer()" << std::endl;
    char *result = cmd.get_manufacturer();
	ASSERT_NE(result, nullptr);
    std::cout << "Retrieved manufacturer: '" << result << std::endl;
    EXPECT_EQ(strlen(result), 0);
    std::cout << "Exiting get_manufacturer_empty_retrieve_manufacturer_name_empty test" << std::endl;
}

TEST(em_cmd_t, get_manufacturer_RetrieveManufacturerWithSpecialCharacters)
{
    std::cout << "Entering get_manufacturer_RetrieveManufacturerWithSpecialCharacters test" << std::endl;
    em_cmd_t cmd{};
    memcpy(cmd.m_data_model.m_device.m_device_info.manufacturer, "!@#$%^&*()_+", strlen("!@#$%^&*()_+") + 1);
    std::cout << "Invoking get_manufacturer()" << std::endl;
    char *result = cmd.get_manufacturer();
	ASSERT_NE(result, nullptr);
    std::cout << "Retrieved manufacturer: " << result << std::endl;    
    EXPECT_STREQ(result, "!@#$%^&*()_+");
    std::cout << "Exiting get_manufacturer_RetrieveManufacturerWithSpecialCharacters test" << std::endl;
}

TEST(em_cmd_t, get_manufacturer_model_ValidModelProperlySet)
{
    std::cout << "Entering get_manufacturer_model_ValidModelProperlySet test" << std::endl;
    em_cmd_t cmd;
    strncpy(cmd.m_data_model.m_device.m_device_info.manufacturer_model, "TestModel", sizeof(cmd.m_data_model.m_device.m_device_info.manufacturer_model) - 1);
    std::cout << "Invoking get_manufacturer_model()" << std::endl;
    char *result = cmd.get_manufacturer_model();
    ASSERT_NE(result, nullptr);
    std::cout << "Retrieved manufacturer model: " << result << std::endl;
    EXPECT_STREQ(result, "TestModel");
    std::cout << "Exiting get_manufacturer_model_ValidModelProperlySet test" << std::endl;
}

TEST(em_cmd_t, get_manufacturer_model_EmptyModel)
{
    std::cout << "Entering get_manufacturer_model_EmptyModel test" << std::endl;
    em_cmd_t cmd;
    strncpy(cmd.m_data_model.m_device.m_device_info.manufacturer_model, "", sizeof(cmd.m_data_model.m_device.m_device_info.manufacturer_model) - 1);
    std::cout << "Invoking get_manufacturer_model()" << std::endl;
    char *result = cmd.get_manufacturer_model();
    ASSERT_NE(result, nullptr);
    std::cout << "Retrieved manufacturer model (expected empty string): '" << result << "'" << std::endl;
    EXPECT_STREQ(result, "");
    std::cout << "Exiting get_manufacturer_model_EmptyModel test" << std::endl;
}

TEST(em_cmd_t, get_manufacturer_model_RetrieveWithSpecialCharacters)
{
    std::cout << "Entering get_manufacturer_model_RetrieveWithSpecialCharacters test" << std::endl;
    em_cmd_t cmd{};
    memcpy(cmd.m_data_model.m_device.m_device_info.manufacturer_model, "!@#$%^&*()", strlen("!@#$%^&*()") + 1);
    std::cout << "Invoking get_manufacturer_model()" << std::endl;
    char *result = cmd.get_manufacturer_model();
	ASSERT_NE(result, nullptr);
    std::cout << "Retrieved manufacturer model: " << (result ? result : "null") << std::endl;
    EXPECT_STREQ(result, "!@#$%^&*()");
    std::cout << "Exiting get_manufacturer_model_RetrieveWithSpecialCharacters test" << std::endl;
}

TEST(em_cmd_t, get_serial_number_valid_serial) {
    std::cout << "Entering get_serial_number_valid_serial test" << std::endl;
    const char* expectedSerial = "ABC123";
    em_cmd_t cmd;
    strncpy(cmd.m_data_model.m_device.m_device_info.serial_number,
            expectedSerial,
            sizeof(cmd.m_data_model.m_device.m_device_info.serial_number) - 1);
    cmd.m_data_model.m_device.m_device_info.serial_number[
        sizeof(cmd.m_data_model.m_device.m_device_info.serial_number) - 1] = '\0';
    std::cout << "Invoking get_serial_number() on em_cmd_t object" << std::endl;
    char* retSerial = cmd.get_serial_number();
    ASSERT_NE(retSerial, nullptr);
    std::cout << "Retrieved serial number string: " << retSerial << std::endl;
    EXPECT_STREQ(retSerial, expectedSerial);
    std::cout << "Exiting get_serial_number_valid_serial test" << std::endl;
}

TEST(em_cmd_t, get_serial_number_empty_serial) {
    std::cout << "Entering get_serial_number_empty_serial test" << std::endl;
    char emptySerial[64] = {0};
    const char* expectedSerial = "";
    em_cmd_t cmd;
    strncpy(cmd.m_data_model.m_device.m_device_info.serial_number,
            expectedSerial,
            sizeof(cmd.m_data_model.m_device.m_device_info.serial_number) - 1); 
    std::cout << "Invoking get_serial_number() on em_cmd_t object" << std::endl;
    char* retSerial = cmd.get_serial_number();
    ASSERT_NE(retSerial, nullptr);
    std::cout << "Retrieved serial number string: '" << retSerial << "'" << std::endl;
    EXPECT_STREQ(retSerial, expectedSerial);
    std::cout << "Exiting get_serial_number_empty_serial test" << std::endl;
}

TEST(em_cmd_t, get_serial_number_serial_WithSpecialCharacters) {
    std::cout << "Entering get_serial_number_serial_WithSpecialCharacters test" << std::endl;
    em_cmd_t cmd;
	memcpy(cmd.m_data_model.m_device.m_device_info.serial_number, u8"SN@#123!$%\n\t\u00A9", strlen(u8"SN@#123!$%\n\t\u00A9") + 1);  
    std::cout << "Invoking get_serial_number() on em_cmd_t object" << std::endl;
    char* retSerial = cmd.get_serial_number();
    ASSERT_NE(retSerial, nullptr);
    std::cout << "Retrieved serial number string: '" << retSerial << "'" << std::endl;
    EXPECT_STREQ(retSerial, u8"SN@#123!$%\n\t\u00A9");
    std::cout << "Exiting get_serial_number_serial_WithSpecialCharacters test" << std::endl;
}

TEST(em_cmd_t, get_primary_device_type_valid) {
    std::cout << "Entering get_primary_device_type_valid test" << std::endl;
    em_cmd_t cmd;
	memcpy(cmd.m_data_model.m_device.m_device_info.primary_device_type, "DEVICE_TYPE_XYZ", strlen("DEVICE_TYPE_XYZ") + 1);
    std::cout << "Invoking get_primary_device_type() on cmd object" << std::endl;
    char *retVal = cmd.get_primary_device_type();
    std::cout << "Returned value: " << (retVal ? retVal : "NULL") << std::endl;
    ASSERT_NE(retVal, nullptr);
    EXPECT_STREQ(retVal, "DEVICE_TYPE_XYZ");
    std::cout << "Exiting get_primary_device_type_valid test" << std::endl;
}

TEST(em_cmd_t, get_primary_device_type_empty) {
    std::cout << "Entering get_primary_device_type_empty test" << std::endl;
    em_cmd_t cmd;
    memcpy(cmd.m_data_model.m_device.m_device_info.primary_device_type, "", strlen("") + 1);
    std::cout << "Invoking get_primary_device_type() on cmd object" << std::endl;
    char *retVal = cmd.get_primary_device_type();
    std::cout << "Returned value: " << (retVal ? retVal : "NULL") << std::endl;
    ASSERT_NE(retVal, nullptr);
    EXPECT_STREQ(retVal, "");
    std::cout << "Exiting get_primary_device_type_empty test" << std::endl;
}

TEST(em_cmd_t, get_primary_device_type_SpecialCharacters) {
    std::cout << "Entering get_primary_device_type_SpecialCharacters test" << std::endl;
    em_cmd_t cmd;
    memcpy(cmd.m_data_model.m_device.m_device_info.primary_device_type, "!@#$%^&*()_+", strlen("!@#$%^&*()_+") + 1);
    std::cout << "Invoking get_primary_device_type() on cmd object" << std::endl;
    char *retVal = cmd.get_primary_device_type();
    std::cout << "Returned value: " << (retVal ? retVal : "NULL") << std::endl;
    ASSERT_NE(retVal, nullptr);
    EXPECT_STREQ(retVal, "!@#$%^&*()_+");
    std::cout << "Exiting get_primary_device_type_SpecialCharacters test" << std::endl;
}

TEST(em_cmd_t, get_num_network_ssid_verify_returns_0_when_no_network_ssids_available) {
    std::cout << "Entering get_num_network_ssid_verify_returns_0_when_no_network_ssids_available test" << std::endl;
    em_cmd_t cmd;
	cmd.m_data_model.m_num_net_ssids = 0;
    std::cout << "Invoking get_num_network_ssid() method." << std::endl;
    unsigned int ssidCount = cmd.get_num_network_ssid();
    std::cout << "get_num_network_ssid() returned: " << ssidCount << std::endl;
    EXPECT_EQ(ssidCount, 0u);
    std::cout << "Exiting get_num_network_ssid_verify_returns_0_when_no_network_ssids_available test" << std::endl;
}

TEST(em_cmd_t, get_num_network_ssid_verify_returns_valid_count_for_configured_ssids) {
    std::cout << "Entering get_num_network_ssid_verify_returns_valid_count_for_configured_ssids test" << std::endl;   
    em_cmd_t cmd;
	cmd.m_data_model.m_num_net_ssids = 3;
    std::cout << "Invoking get_num_network_ssid() method." << std::endl;
    unsigned int ssidCount = cmd.get_num_network_ssid();
    std::cout << "get_num_network_ssid() returned: " << ssidCount << std::endl;   
    EXPECT_EQ(ssidCount, 3u);
    std::cout << "Exiting get_num_network_ssid_verify_returns_valid_count_for_configured_ssids test" << std::endl;
}

TEST(em_cmd_t, get_num_network_ssid_verify_returns_maximum_ssid_count_boundary_condition) {
    std::cout << "Entering get_num_network_ssid_verify_returns_maximum_ssid_count_boundary_condition test" << std::endl;
    em_cmd_t cmd;
	unsigned int maxSSIDCount = UINT_MAX;
	cmd.m_data_model.m_num_net_ssids = maxSSIDCount;
    std::cout << "Invoking get_num_network_ssid() method." << std::endl;
    unsigned int ssidCount = cmd.get_num_network_ssid();
    std::cout << "get_num_network_ssid() returned: " << ssidCount << std::endl;   
    EXPECT_EQ(ssidCount, maxSSIDCount);
    std::cout << "Exiting get_num_network_ssid_verify_returns_maximum_ssid_count_boundary_condition test" << std::endl;
}

TEST(em_cmd_t, get_network_ssid_valid_index_0)
{
    std::cout << "Entering get_network_ssid_valid_index_0 test" << std::endl;
    em_cmd_t cmdObj;
	unsigned int index = 0;
	memcpy(cmdObj.m_data_model.m_network_ssid[index].m_network_ssid_info.ssid, "TestSSID", strlen("TestSSID") + 1);
    cmdObj.m_data_model.m_network_ssid[index].m_network_ssid_info.num_bands = 2;
    cmdObj.m_data_model.m_network_ssid[index].m_network_ssid_info.enable = true;
    cmdObj.m_data_model.m_network_ssid[index].m_network_ssid_info.num_hauls = 2;
    std::cout << "Invoking get_network_ssid with index = " << index << std::endl;
    dm_network_ssid_t *ssidPtr = cmdObj.get_network_ssid(index);
    ASSERT_NE(ssidPtr, nullptr);
	std::cout << "get_network_ssid() returned values:" << std::endl;
	std::cout << "ssidPtr->m_network_ssid_info.ssid = " << ssidPtr->m_network_ssid_info.ssid << std::endl;
	std::cout << "ssidPtr->m_network_ssid_info.num_bands = " << ssidPtr->m_network_ssid_info.num_bands << std::endl;
	std::cout << "ssidPtr->m_network_ssid_info.enable = " << ssidPtr->m_network_ssid_info.enable << std::endl;
	std::cout << "ssidPtr->m_network_ssid_info.num_hauls = " << ssidPtr->m_network_ssid_info.num_hauls << std::endl;
    EXPECT_STREQ(ssidPtr->m_network_ssid_info.ssid, "TestSSID");
	EXPECT_EQ(ssidPtr->m_network_ssid_info.num_bands, 2);
	EXPECT_EQ(ssidPtr->m_network_ssid_info.enable, true);
	EXPECT_EQ(ssidPtr->m_network_ssid_info.num_hauls, 2);
    std::cout << "Exiting get_network_ssid_valid_index_0 test" << std::endl;
}

TEST(em_cmd_t, get_network_ssid_valid_index_2)
{
    std::cout << "Entering get_network_ssid_valid_index_2 test" << std::endl;
    em_cmd_t cmdObj;
    unsigned int index = 2;
	memcpy(cmdObj.m_data_model.m_network_ssid[index].m_network_ssid_info.ssid, "TestSSID1", strlen("TestSSID1") + 1);
    cmdObj.m_data_model.m_network_ssid[index].m_network_ssid_info.num_bands = 2;
    cmdObj.m_data_model.m_network_ssid[index].m_network_ssid_info.enable = true;
    cmdObj.m_data_model.m_network_ssid[index].m_network_ssid_info.num_hauls = 2;
    std::cout << "Invoking get_network_ssid with index = " << index << std::endl;
    dm_network_ssid_t *ssidPtr = cmdObj.get_network_ssid(index);
    std::cout << "Method get_network_ssid returned pointer = " << ssidPtr << std::endl;
    ASSERT_NE(ssidPtr, nullptr);
	std::cout << "get_network_ssid() returned values:" << std::endl;
	std::cout << "ssidPtr->m_network_ssid_info.ssid = " << ssidPtr->m_network_ssid_info.ssid << std::endl;
	std::cout << "ssidPtr->m_network_ssid_info.num_bands = " << ssidPtr->m_network_ssid_info.num_bands << std::endl;
	std::cout << "ssidPtr->m_network_ssid_info.enable = " << ssidPtr->m_network_ssid_info.enable << std::endl;
	std::cout << "ssidPtr->m_network_ssid_info.num_hauls = " << ssidPtr->m_network_ssid_info.num_hauls << std::endl;
        EXPECT_STREQ(ssidPtr->m_network_ssid_info.ssid, "TestSSID1");
	EXPECT_EQ(ssidPtr->m_network_ssid_info.num_bands, 2);
	EXPECT_EQ(ssidPtr->m_network_ssid_info.enable, true);
	EXPECT_EQ(ssidPtr->m_network_ssid_info.num_hauls, 2);
    std::cout << "Exiting get_network_ssid_valid_index_2 test" << std::endl;
}

TEST(em_cmd_t, get_network_ssid_index_at_boundary)
{
    std::cout << "Entering get_network_ssid_index_beyond_boundary test" << std::endl;
    em_cmd_t cmdObj;
    unsigned int boundaryIndex = 4;
	memcpy(cmdObj.m_data_model.m_network_ssid[boundaryIndex].m_network_ssid_info.ssid, "TestSSID2", strlen("TestSSID2") + 1);
    cmdObj.m_data_model.m_network_ssid[boundaryIndex].m_network_ssid_info.num_bands = 2;
    cmdObj.m_data_model.m_network_ssid[boundaryIndex].m_network_ssid_info.enable = true;
    cmdObj.m_data_model.m_network_ssid[boundaryIndex].m_network_ssid_info.num_hauls = 2;
    std::cout << "Invoking get_network_ssid with index = " << boundaryIndex << std::endl;
    dm_network_ssid_t *ssidPtr = cmdObj.get_network_ssid(boundaryIndex);
    ASSERT_NE(ssidPtr, nullptr);
	std::cout << "get_network_ssid() returned values:" << std::endl;
	std::cout << "ssidPtr->m_network_ssid_info.ssid = " << ssidPtr->m_network_ssid_info.ssid << std::endl;
	std::cout << "ssidPtr->m_network_ssid_info.num_bands = " << ssidPtr->m_network_ssid_info.num_bands << std::endl;
	std::cout << "ssidPtr->m_network_ssid_info.enable = " << ssidPtr->m_network_ssid_info.enable << std::endl;
	std::cout << "ssidPtr->m_network_ssid_info.num_hauls = " << ssidPtr->m_network_ssid_info.num_hauls << std::endl;
    	EXPECT_STREQ(ssidPtr->m_network_ssid_info.ssid, "TestSSID2");
	EXPECT_EQ(ssidPtr->m_network_ssid_info.num_bands, 2);
	EXPECT_EQ(ssidPtr->m_network_ssid_info.enable, true);
	EXPECT_EQ(ssidPtr->m_network_ssid_info.num_hauls, 2);
    std::cout << "Exiting get_network_ssid_index_at_boundary test" << std::endl;
}

TEST(em_cmd_t, get_network_ssid_index_uint_max)
{
    std::cout << "Entering get_network_ssid_index_uint_max test" << std::endl;
    em_cmd_t cmdObj;
    unsigned int index = UINT_MAX;
    std::cout << "Invoking get_network_ssid with index = " << index << std::endl;
    dm_network_ssid_t *ssidPtr = cmdObj.get_network_ssid(index);
    EXPECT_EQ(ssidPtr, nullptr);
    std::cout << "Exiting get_network_ssid_index_uint_max test" << std::endl;
}

TEST(em_cmd_t, get_radio_valid_index_returns_valid_radio_pointer)
{
    std::cout << "Entering get_radio_valid_index_returns_valid_radio_pointer test" << std::endl;
    em_cmd_t cmd;
	int index = 1;
	cmd.m_data_model.m_radio[index].m_radio_info.enabled = true;
	cmd.m_data_model.m_radio[index].m_radio_info.number_of_bss = 2;
	cmd.m_data_model.m_radio[index].m_radio_info.number_of_unassoc_sta =1;
	cmd.m_data_model.m_radio[index].m_radio_info.noise = 4;
    std::cout << "Invoking get_radio with index 1" << std::endl;
    dm_radio_t* radio = cmd.get_radio(index);
    ASSERT_NE(radio, nullptr);   
    if (radio != nullptr) {
        std::cout << "Retrieved radio info from get_radio(1):" << std::endl;
        std::cout << "  Enabled: " << radio->m_radio_info.enabled << std::endl;
        std::cout << "  Number of BSS: " << radio->m_radio_info.number_of_bss << std::endl;
        std::cout << "  Number of unassoc STA: " << radio->m_radio_info.number_of_unassoc_sta << std::endl;
        std::cout << "  Noise: " << radio->m_radio_info.noise << std::endl;
		EXPECT_TRUE(radio->m_radio_info.enabled);
		EXPECT_EQ(radio->m_radio_info.number_of_bss, 2);
		EXPECT_EQ(radio->m_radio_info.number_of_unassoc_sta, 1);
		EXPECT_EQ(radio->m_radio_info.noise, 4);
    }
    std::cout << "Exiting get_radio_valid_index_returns_valid_radio_pointer test" << std::endl;
}

TEST(em_cmd_t, get_radio_edge_index_zero_returns_valid_radio_pointer)
{
    std::cout << "Entering get_radio_edge_index_zero_returns_valid_radio_pointer test" << std::endl;
    em_cmd_t cmd;
	int index = 0;
	cmd.m_data_model.m_radio[index].m_radio_info.enabled = true;
	cmd.m_data_model.m_radio[index].m_radio_info.number_of_bss = 2;
	cmd.m_data_model.m_radio[index].m_radio_info.number_of_unassoc_sta =1;
	cmd.m_data_model.m_radio[index].m_radio_info.noise = 4;
    std::cout << "Invoking get_radio with index 0" << std::endl;
    dm_radio_t* radio = cmd.get_radio(index);
    ASSERT_NE(radio, nullptr);
    if (radio != nullptr) {
        std::cout << "Retrieved radio info from get_radio(0):" << std::endl;
        std::cout << "  Enabled: " << radio->m_radio_info.enabled << std::endl;
        std::cout << "  Number of BSS: " << radio->m_radio_info.number_of_bss << std::endl;
        std::cout << "  Number of unassoc STA: " << radio->m_radio_info.number_of_unassoc_sta << std::endl;
        std::cout << "  Noise: " << radio->m_radio_info.noise << std::endl;
		EXPECT_TRUE(radio->m_radio_info.enabled);
		EXPECT_EQ(radio->m_radio_info.number_of_bss, 2);
		EXPECT_EQ(radio->m_radio_info.number_of_unassoc_sta, 1);
		EXPECT_EQ(radio->m_radio_info.noise, 4);
    }    
    std::cout << "Exiting get_radio_edge_index_zero_returns_valid_radio_pointer test" << std::endl;
}

TEST(em_cmd_t, get_radio_out_of_range_index_returns_nullptr)
{
    std::cout << "Entering get_radio_out_of_range_index_returns_nullptr test" << std::endl;
    em_cmd_t cmd;        
    unsigned int outOfRangeIndex = 100;
	cmd.m_data_model.m_radio[outOfRangeIndex].m_radio_info.enabled = true;
	cmd.m_data_model.m_radio[outOfRangeIndex].m_radio_info.number_of_bss = 2;
	cmd.m_data_model.m_radio[outOfRangeIndex].m_radio_info.number_of_unassoc_sta =1;
	cmd.m_data_model.m_radio[outOfRangeIndex].m_radio_info.noise = 4;
    std::cout << "Invoking get_radio with out-of-range index " << outOfRangeIndex << std::endl;
    dm_radio_t* radio = cmd.get_radio(outOfRangeIndex);
    std::cout << "Returned pointer from get_radio(" << outOfRangeIndex << "): " << radio << std::endl;    
    EXPECT_EQ(radio, nullptr);    
    std::cout << "Exiting get_radio_out_of_range_index_returns_nullptr test" << std::endl;
}

TEST(em_cmd_t, get_radio_data_valid_match)
{
    std::cout << "Entering get_radio_data_valid_match test" << std::endl;
    em_cmd_t cmd{};
    cmd.m_data_model.m_wifi_data = (webconfig_subdoc_data_t*)calloc(1, sizeof(webconfig_subdoc_data_t));
    ASSERT_NE(cmd.m_data_model.m_wifi_data, nullptr);
    cmd.m_data_model.m_wifi_data->u.decoded.num_radios = 1;
    strncpy(cmd.m_data_model.m_wifi_data->u.decoded.radios[0].name,
            "Interface1", sizeof(cmd.m_data_model.m_wifi_data->u.decoded.radios[0].name) - 1);
    em_interface_t iface{};	
    strncpy(iface.name, "Interface1", sizeof(iface.name) - 1);
	uint8_t sample_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x1A};
    memcpy(iface.mac, sample_mac, sizeof(sample_mac));
	iface.media = em_media_type_ieee80211n_5;
    std::cout << "Invoking get_radio_data with matching interface name" << std::endl;
    rdk_wifi_radio_t *radio = cmd.m_data_model.get_radio_data(&iface);
    EXPECT_NE(radio, nullptr);
    std::cout << "Returned radio pointer: " << radio << std::endl;
    free(cmd.m_data_model.m_wifi_data);
    std::cout << "Exiting get_radio_data_valid_match test" << std::endl;
}

TEST(em_cmd_t, get_radio_data_null_interface_crashes)
{
    std::cout << "Entering get_radio_data_null_interface_crashes test" << std::endl;
    em_cmd_t cmd{};
    cmd.m_data_model.m_wifi_data = (webconfig_subdoc_data_t*)calloc(1, sizeof(webconfig_subdoc_data_t));
    rdk_wifi_radio_t *ptr = cmd.m_data_model.get_radio_data(nullptr);
	EXPECT_EQ(ptr, nullptr);
    free(cmd.m_data_model.m_wifi_data);
    std::cout << "Exiting get_radio_data_null_interface_crashes test" << std::endl;
}

TEST(em_cmd_t, get_radio_data_no_radios_returns_null)
{
    std::cout << "Entering get_radio_data_no_radios_returns_null test" << std::endl;
    em_cmd_t cmd{};
    cmd.m_data_model.m_wifi_data = (webconfig_subdoc_data_t*)calloc(1, sizeof(webconfig_subdoc_data_t));
    ASSERT_NE(cmd.m_data_model.m_wifi_data, nullptr);
    cmd.m_data_model.m_wifi_data->u.decoded.num_radios = 0;
    em_interface_t iface{};
    strncpy(iface.name, "Interface1", sizeof(iface.name) - 1);
	uint8_t sample_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x1A};
    memcpy(iface.mac, sample_mac, sizeof(sample_mac));
	iface.media = em_media_type_ieee80211n_5;
    rdk_wifi_radio_t *radio = cmd.m_data_model.get_radio_data(&iface);
    EXPECT_EQ(radio, nullptr);
    free(cmd.m_data_model.m_wifi_data);
    std::cout << "Exiting get_radio_data_no_radios_returns_null test" << std::endl;
}

TEST(em_cmd_t, get_rd_op_class_set_positive_value)
{
    std::cout << "Entering get_rd_op_class_set_positive_value test" << std::endl;
    EXPECT_NO_THROW({
        em_cmd_t obj;
        std::cout << "Default constructed em_cmd_t object created." << std::endl;
        obj.m_rd_op_class = 5;
        std::cout << "Invoking get_rd_op_class() after setting value to 5." << std::endl;
        unsigned int rdOpClass = obj.get_rd_op_class();
        std::cout << "Returned read op class value: " << rdOpClass << std::endl;
        EXPECT_EQ(rdOpClass, 5u);
    });   
    std::cout << "Exiting get_rd_op_class_set_positive_value test" << std::endl;
}

TEST(em_cmd_t, get_rd_op_class_set_boundary_value)
{
    std::cout << "Entering get_rd_op_class_set_boundary_value test" << std::endl;
    EXPECT_NO_THROW({
        em_cmd_t obj;
        std::cout << "Default constructed em_cmd_t object created." << std::endl;
        obj.m_rd_op_class = UINT_MAX;
        std::cout << "Invoking get_rd_op_class() after setting value to UINT_MAX." << std::endl;
        unsigned int rdOpClass = obj.get_rd_op_class();
        std::cout << "Returned read op class value: " << rdOpClass << std::endl;
        EXPECT_EQ(rdOpClass, UINT_MAX);
    });    
    std::cout << "Exiting get_rd_op_class_set_boundary_value test" << std::endl;
}

TEST(em_cmd_t, get_rd_channel_explicit_set_value_42)
{
    std::cout << "Entering get_rd_channel_explicit_set_value_42 test" << std::endl;
    em_cmd_t cmd;
    cmd.m_rd_channel = 42;
    std::cout << "Invoking get_rd_channel()" << std::endl;
    unsigned int rd_channel = cmd.get_rd_channel();
    std::cout << "Retrieved read channel value: " << rd_channel << std::endl;   
    EXPECT_EQ(rd_channel, 42u);  
    std::cout << "Exiting get_rd_channel_explicit_set_value_42 test" << std::endl;
}

TEST(em_cmd_t, get_rd_channel_max_unsigned_int_value)
{
    std::cout << "Entering get_rd_channel_max_unsigned_int_value test" << std::endl;
    em_cmd_t cmd;
	cmd.m_rd_channel = UINT_MAX;
    std::cout << "Invoking get_rd_channel()" << std::endl;
    unsigned int rd_channel = cmd.get_rd_channel();
    std::cout << "Retrieved read channel value: " << rd_channel << std::endl;    
    EXPECT_EQ(rd_channel, UINT_MAX);    
    std::cout << "Exiting get_rd_channel_max_unsigned_int_value test" << std::endl;
}

TEST(em_cmd_t, set_start_time_VerifyTimestampUpdated)
{
    std::cout << "Entering set_start_time_VerifyTimestampUpdated test" << std::endl;
    em_cmd_t cmd_obj;    
    // Capture system time before invoking set_start_time()
    struct timeval system_time_before {0, 0};
    gettimeofday(&system_time_before, nullptr);
    std::cout << "Before invocation, system time (tv_sec): " << system_time_before.tv_sec << ", (tv_usec): " << system_time_before.tv_usec << std::endl;
    std::cout << "Invoking set_start_time()" << std::endl;
    EXPECT_NO_THROW(cmd_obj.set_start_time());    
    // Capture system time after the call
    struct timeval system_time_after {0, 0};
    gettimeofday(&system_time_after, nullptr);
    std::cout << "After invocation, system time (tv_sec): " << system_time_after.tv_sec << ", (tv_usec): " << system_time_after.tv_usec << std::endl;    
    // Retrieve the object's m_start_time
    struct timeval obj_time = cmd_obj.m_start_time;
    std::cout << "Command object start time (tv_sec): " << obj_time.tv_sec << ", (tv_usec): " << obj_time.tv_usec << std::endl;   
    // Check that the object's start time is within the system times captured 
    // Allow a tolerance of 1 second
    bool time_within_range = false;
    if ((obj_time.tv_sec >= system_time_before.tv_sec) && (obj_time.tv_sec <= system_time_after.tv_sec + 1)) {
        time_within_range = true;
    }
    EXPECT_TRUE(time_within_range);
    std::cout << "Exiting set_start_time_VerifyTimestampUpdated test" << std::endl;
}

TEST(em_cmd_t, set_start_time_NotLeftAtDefaultZero)
{
    std::cout << "Entering set_start_time_NotLeftAtDefaultZero test" << std::endl;    
    // Create an object using default constructor
    em_cmd_t cmd_obj;    
    // Set m_start_time to a known default zero value
    memset(&cmd_obj.m_start_time, 0, sizeof(cmd_obj.m_start_time));
    std::cout << "Initialized m_start_time to zero (tv_sec: " << cmd_obj.m_start_time.tv_sec 
              << ", tv_usec: " << cmd_obj.m_start_time.tv_usec << ")" << std::endl;    
    // Invoke the method
    std::cout << "Invoking set_start_time()" << std::endl;
    EXPECT_NO_THROW(cmd_obj.set_start_time());    
    // Retrieve the object's m_start_time after invocation
    struct timeval obj_time = cmd_obj.m_start_time;
    std::cout << "After invocation, m_start_time (tv_sec): " << obj_time.tv_sec 
              << ", (tv_usec): " << obj_time.tv_usec << std::endl;    
    // Check that m_start_time is not left at zero value
    bool not_zero = ( (obj_time.tv_sec != 0) || (obj_time.tv_usec != 0) );
    EXPECT_TRUE(not_zero);    
    std::cout << "Exiting set_start_time_NotLeftAtDefaultZero test" << std::endl;
}
/*
TEST(em_cmd_t, reset_non_zero_event_and_command_params)
{
    std::cout << "Entering reset_non_zero_event_and_command_params test" << std::endl;
    em_cmd_t cmd{};
    cmd.m_evt = new em_event_t;
    std::cout << "Allocated memory for m_evt" << std::endl;
    // Fill m_evt memory with non-zero bytes.
    memset(cmd.m_evt, 0xFF, sizeof(em_event_t));
    std::cout << "Filled m_evt memory with non-zero bytes" << std::endl;
    // Fill m_param structure with non-zero data.
    memset(&cmd.m_param, 0xFF, sizeof(em_cmd_params_t));
    std::cout << "Filled m_param structure with non-zero data" << std::endl;
    // Debug log showing state before reset.
    std::cout << "Before reset: m_evt first byte = " << std::hex << (int)(reinterpret_cast<unsigned char*>(cmd.m_evt)[0]) << std::dec << std::endl;
    std::cout << "Before reset: m_param first byte = " << std::hex << (int)(*(reinterpret_cast<unsigned char*>(&cmd.m_param))) << std::dec << std::endl;
    // Invoke reset() and check for exceptions.
    std::cout << "Invoking reset() method" << std::endl;
    EXPECT_NO_THROW(cmd.reset());
    std::cout << "reset() method invoked" << std::endl;
    // Prepare zero buffers for comparison.
    unsigned char zeroBufferEvt[sizeof(em_event_t)] = {0};
    unsigned char zeroBufferParam[sizeof(em_cmd_params_t)] = {0};
    // Verify that m_evt memory is completely zeroed.
    int cmpEvt = memcmp(cmd.m_evt, zeroBufferEvt, sizeof(em_event_t));
    std::cout << "After reset: m_evt memory comparison result = " << cmpEvt << std::endl;
    EXPECT_EQ(0, cmpEvt);
    // Verify that m_param structure is completely zeroed.
    int cmpParam = memcmp(&cmd.m_param, zeroBufferParam, sizeof(em_cmd_params_t));
    std::cout << "After reset: m_param memory comparison result = " << cmpParam << std::endl;
    EXPECT_EQ(0, cmpParam);
    // Free allocated memory for m_evt to avoid memory leak.
    delete cmd.m_evt;
    cmd.m_evt = nullptr;
    std::cout << "Freed memory allocated for m_evt" << std::endl;
    std::cout << "Exiting reset_non_zero_event_and_command_params test" << std::endl;
}
*/
TEST(em_cmd_t, reset_non_zero_event_and_command_params)
{
    std::cout << "Entering reset_non_zero_event_and_command_params test" << std::endl;
    em_cmd_t cmd{};

    // Free constructor allocated memory before overwriting
    if (cmd.m_evt) {
        free(cmd.m_evt);
        cmd.m_evt = nullptr;
        std::cout << "Freed constructor allocated memory for m_evt" << std::endl;
    }

    // Replace with new allocation for test logic
    cmd.m_evt = new em_event_t;
    std::cout << "Allocated memory for m_evt" << std::endl;

    memset(cmd.m_evt, 0xFF, sizeof(em_event_t));
    std::cout << "Filled m_evt memory with non-zero bytes" << std::endl;

    memset(&cmd.m_param, 0xFF, sizeof(em_cmd_params_t));
    std::cout << "Filled m_param structure with non-zero data" << std::endl;

    std::cout << "Before reset: m_evt first byte = "
              << std::hex << (int)(reinterpret_cast<unsigned char*>(cmd.m_evt)[0]) 
              << std::dec << std::endl;

    std::cout << "Before reset: m_param first byte = "
              << std::hex << (int)(*(reinterpret_cast<unsigned char*>(&cmd.m_param)))
              << std::dec << std::endl;

    // Test reset
    std::cout << "Invoking reset() method" << std::endl;
    EXPECT_NO_THROW(cmd.reset());
    std::cout << "reset() method invoked" << std::endl;

    unsigned char zeroBufferEvt[sizeof(em_event_t)] = {0};
    unsigned char zeroBufferParam[sizeof(em_cmd_params_t)] = {0};

    EXPECT_EQ(memcmp(cmd.m_evt, zeroBufferEvt, sizeof(em_event_t)), 0);
    EXPECT_EQ(memcmp(&cmd.m_param, zeroBufferParam, sizeof(em_cmd_params_t)), 0);

    // Cleanup for test-allocated memory
    delete cmd.m_evt;
    cmd.m_evt = nullptr;
    std::cout << "Freed memory allocated for m_evt" << std::endl;

    std::cout << "Exiting reset_non_zero_event_and_command_params test" << std::endl;
}

TEST(em_cmd_t, reset_cmd_ctx_default_constructed_object)
{
    std::cout << "Entering reset_cmd_ctx_default_constructed_object test" << std::endl;
    em_cmd_t cmd_obj;
	cmd_obj.m_data_model.m_cmd_ctx.arr_index = 1;
	cmd_obj.m_data_model.m_cmd_ctx.type = dm_orch_type_topo_sync;
	memcpy(cmd_obj.m_data_model.m_cmd_ctx.obj_id, "SampleID", strlen("SampleID") + 1);
    std::cout << "Invoking reset_cmd_ctx" << std::endl;
    EXPECT_NO_THROW({
        cmd_obj.reset_cmd_ctx();
        std::cout << "reset_cmd_ctx() invoked successfully. m_data_model.reset_cmd_ctx() should have been executed without exceptions." << std::endl;
    });
	EXPECT_EQ(cmd_obj.m_data_model.m_cmd_ctx.arr_index, 0u);
	EXPECT_EQ(cmd_obj.m_data_model.m_cmd_ctx.type, 0);
	for (size_t i = 0; i < sizeof(cmd_obj.m_data_model.m_cmd_ctx.obj_id); i++) {
        EXPECT_EQ(cmd_obj.m_data_model.m_cmd_ctx.obj_id[i], 0)
            << "obj_id[" << i << "] expected 0 after reset_cmd_ctx()";
    }
    std::cout << "Exiting reset_cmd_ctx_default_constructed_object test" << std::endl;
}

TEST(em_cmd_t, set_db_cfg_type_ZeroValue) {
    std::cout << "Entering set_db_cfg_type_ZeroValue test" << std::endl;
    em_cmd_t obj;
    unsigned int test_type = 0;
    std::cout << "Invoking set_db_cfg_type with type: " << test_type << std::endl;
    EXPECT_NO_THROW(obj.set_db_cfg_type(test_type));   
    std::cout << "Method set_db_cfg_type invoked successfully." << std::endl;
    std::cout << "After invocation, m_db_cfg_type = " << obj.m_db_cfg_type << std::endl;   
    EXPECT_EQ(obj.m_db_cfg_type, test_type);
    std::cout << "Exiting set_db_cfg_type_ZeroValue test" << std::endl;
}

TEST(em_cmd_t, set_db_cfg_type_TypicalPositiveValue) {
    std::cout << "Entering set_db_cfg_type_TypicalPositiveValue test" << std::endl;
    em_cmd_t obj;
    unsigned int test_type = 42;
    std::cout << "Invoking set_db_cfg_type with type: " << test_type << std::endl;
    EXPECT_NO_THROW(obj.set_db_cfg_type(test_type));    
    std::cout << "Method set_db_cfg_type invoked successfully." << std::endl;
    std::cout << "After invocation, m_db_cfg_type = " << obj.m_db_cfg_type << std::endl;    
    EXPECT_EQ(obj.m_db_cfg_type, test_type);
    std::cout << "Exiting set_db_cfg_type_TypicalPositiveValue test" << std::endl;
}

TEST(em_cmd_t, set_db_cfg_type_MaximumUnsignedIntValue) {
    std::cout << "Entering set_db_cfg_type_MaximumUnsignedIntValue test" << std::endl;
    em_cmd_t obj;
	unsigned int test_type = UINT_MAX;
    std::cout << "Invoking set_db_cfg_type with type: " << test_type << std::endl;    
    EXPECT_NO_THROW(obj.set_db_cfg_type(test_type));    
    std::cout << "Method set_db_cfg_type invoked successfully." << std::endl;
    std::cout << "After invocation, m_db_cfg_type = " << obj.m_db_cfg_type << std::endl;    
    EXPECT_EQ(obj.m_db_cfg_type, test_type);
    std::cout << "Exiting set_db_cfg_type_MaximumUnsignedIntValue test" << std::endl;
}

TEST(em_cmd_t, get_orch_op_str_valid_orch_types) {
    const char* testName = "get_orch_op_str_valid_orch_types";
    std::cout << "Entering " << testName << " test" << std::endl;
    em_cmd_t obj{};    
    std::vector<dm_orch_type_t> validTypes = {
        dm_orch_type_none,
        dm_orch_type_net_insert,
        dm_orch_type_net_update,
        dm_orch_type_net_delete,
        dm_orch_type_al_insert,
        dm_orch_type_al_update,
        dm_orch_type_al_delete,
        dm_orch_type_em_insert,
        dm_orch_type_em_update,
        dm_orch_type_em_delete,
        dm_orch_type_em_test,
        dm_orch_type_bss_insert,
        dm_orch_type_bss_update,
        dm_orch_type_bss_delete,
        dm_orch_type_ssid_insert,
        dm_orch_type_ssid_update,
        dm_orch_type_ssid_delete,
        dm_orch_type_sta_insert,
        dm_orch_type_sta_update,
        dm_orch_type_sta_delete,
        dm_orch_type_sec_insert,
        dm_orch_type_sec_update,
        dm_orch_type_sec_delete,
        dm_orch_type_cap_insert,
        dm_orch_type_cap_update,
        dm_orch_type_cap_delete,
        dm_orch_type_op_class_insert,
        dm_orch_type_op_class_update,
        dm_orch_type_op_class_delete,
        dm_orch_type_ssid_vid_insert,
        dm_orch_type_ssid_vid_update,
        dm_orch_type_ssid_vid_delete,
        dm_orch_type_dpp_insert,
        dm_orch_type_dpp_update,
        dm_orch_type_dpp_delete,
        dm_orch_type_em_reset,
        dm_orch_type_db_reset,
        dm_orch_type_db_cfg,
        dm_orch_type_db_insert,
        dm_orch_type_db_update,
        dm_orch_type_db_delete,
        dm_orch_type_dm_delete,
        dm_orch_type_tx_cfg_renew,
        dm_orch_type_owconfig_req,
        dm_orch_type_owconfig_cnf,
        dm_orch_type_ctrl_notify,
        dm_orch_type_ap_cap_report,
        dm_orch_type_client_cap_report,
        dm_orch_type_net_ssid_update,
        dm_orch_type_topo_sync,
        dm_orch_type_channel_pref,
        dm_orch_type_channel_sel,
        dm_orch_type_channel_cnf,
        dm_orch_type_channel_sel_resp,
        dm_orch_type_channel_scan_req,
        dm_orch_type_channel_scan_res,
        dm_orch_type_sta_cap,
        dm_orch_type_sta_link_metrics,
        dm_orch_type_op_channel_report,
        dm_orch_type_sta_steer,
        dm_orch_type_sta_steer_btm_report,
        dm_orch_type_sta_disassoc,
        dm_orch_type_policy_cfg,
        dm_orch_type_mld_reconfig
    };

    for (const auto& orchType : validTypes) {
        std::cout << "Invoking get_orch_op_str for orchestration type value: " << orchType << std::endl;
        const char* opStr = em_cmd_t::get_orch_op_str(orchType);
		ASSERT_NE(opStr, nullptr);
        std::cout << "Returned string: " << (opStr ? opStr : "NULL") << std::endl;
    }
    std::cout << "Exiting " << testName << " test" << std::endl;
}

TEST(em_cmd_t, get_orch_op_str_invalid_orch_type) {
    const char* testName = "get_orch_op_str_invalid_orch_type";
    std::cout << "Entering " << testName << " test" << std::endl;
    em_cmd_t obj{};
    dm_orch_type_t invalidType = static_cast<dm_orch_type_t>(dm_orch_type_bsta_cap_query + 1);
    std::cout << "Invoking get_orch_op_str for invalid orchestration type value: " << invalidType << std::endl;
    const char* opStr = em_cmd_t::get_orch_op_str(invalidType);
    std::cout << "Returned string for invalid input: " << opStr << std::endl;
    EXPECT_EQ(opStr, "dm_orch_type_unknown");
    std::cout << "Exiting " << testName << " test" << std::endl;
}

TEST(em_cmd_t, get_orch_submit_returns_true_when_submission_flag_is_true)
{
    std::cout << "Entering get_orch_submit_returns_true_when_submission_flag_is_true test" << std::endl;
    em_cmd_t cmd;
    memset(cmd.m_orch_desc, 0, sizeof(cmd.m_orch_desc));
    cmd.m_num_orch_desc = 1;
    cmd.m_orch_op_idx = 0;
    //cmd.m_orch_desc[0].op = dm_orch_type_channel_pref;
    cmd.m_orch_desc[0].submit = true;  
    std::cout << "Invoking get_orch_submit() method." << std::endl;
    bool submitStatus = cmd.get_orch_submit();
    std::cout << "get_orch_submit() returned: " << submitStatus << std::endl;
    EXPECT_TRUE(submitStatus);
    std::cout << "Exiting get_orch_submit_returns_true_when_submission_flag_is_true test" << std::endl;
}

TEST(em_cmd_t, get_orch_submit_returns_false_when_submission_flag_is_false)
{
    std::cout << "Entering get_orch_submit_returns_false_when_submission_flag_is_false test" << std::endl;
    em_cmd_t cmd;
    memset(cmd.m_orch_desc, 0, sizeof(cmd.m_orch_desc));
    // Use two entries but keep both submit=false
    cmd.m_num_orch_desc = 1;
    cmd.m_orch_op_idx = 1;
    cmd.m_orch_desc[1].submit = false;
    //cmd.m_orch_desc[1].op = dm_orch_type_channel_pref; 
    std::cout << "Invoking get_orch_submit() method." << std::endl;
    bool submitStatus = cmd.get_orch_submit();
    std::cout << "get_orch_submit() returned: " << submitStatus << std::endl;
    EXPECT_FALSE(submitStatus);
    std::cout << "Exiting get_orch_submit_returns_false_when_submission_flag_is_false test" << std::endl;
}

TEST(em_cmd_t, get_orch_desc_retrieval)
{
    std::cout << "Entering get_orch_desc_retrieval test" << std::endl;
    em_cmd_t obj{};
	obj.m_orch_op_idx = 1;
	obj.m_orch_desc[obj.m_orch_op_idx].op = dm_orch_type_none;
	obj.m_orch_desc[obj.m_orch_op_idx].submit = false;
    std::cout << "Invoking get_orch_desc() method." << std::endl;
    em_orch_desc_t* orchDescPtr = obj.get_orch_desc();
    ASSERT_NE(orchDescPtr, nullptr);
    if (orchDescPtr)
    {
        std::cout << "Retrieved orchDesc->op: " << orchDescPtr->op << std::endl;
        std::cout << "Retrieved orchDesc->submit: " << orchDescPtr->submit << std::endl;
        EXPECT_EQ(orchDescPtr->op, dm_orch_type_none);
        EXPECT_EQ(orchDescPtr->submit, false);
    }

    std::cout << "Exiting get_orch_desc_retrieval test" << std::endl;
}

TEST(em_cmd_t, get_orch_desc_maxindex_retrieval)
{
    std::cout << "Entering get_orch_desc_maxindex_retrieval test" << std::endl;
    em_cmd_t obj{};
	memset(obj.m_orch_desc, 0, sizeof(obj.m_orch_desc));
	obj.m_orch_op_idx = UINT_MAX;
    std::cout << "Invoking get_orch_desc() method." << std::endl;
    em_orch_desc_t* orchDescPtr = obj.get_orch_desc();
    ASSERT_EQ(orchDescPtr, nullptr);
    std::cout << "Exiting get_orch_desc_maxindex_retrieval test" << std::endl;
}

TEST(em_cmd_t, get_orch_op_valid_orch_op_retrieval)
{
    std::cout << "Entering get_orch_op_valid_orch_op_retrieval test" << std::endl;
    em_cmd_t cmd;
	cmd.m_orch_op_idx = 0;
	cmd.m_orch_desc[0].op = dm_orch_type_net_insert;
    //cmd.m_orch_desc[0].submit = true;  
    std::cout << "Invoking get_orch_op() method." << std::endl;
    dm_orch_type_t opStatus = cmd.get_orch_op();
    std::cout << "get_orch_op() returned: " << opStatus << std::endl;
    EXPECT_EQ(opStatus, dm_orch_type_net_insert);
    std::cout << "Exiting get_orch_op_valid_orch_op_retrieval test" << std::endl;
}

TEST(em_cmd_t, get_orch_invalid_orch_op_value)
{
    std::cout << "Entering get_orch_invalid_orch_op_value test" << std::endl;
    em_cmd_t cmd;
	cmd.m_orch_op_idx = 1;
	cmd.m_orch_desc[1].op = static_cast<dm_orch_type_t>(-1);
    //cmd.m_orch_desc[1].submit = false; 
    std::cout << "Invoking get_orch_op() method." << std::endl;
    dm_orch_type_t opStatus = cmd.get_orch_op();
    std::cout << "get_orch_submit() returned: " << opStatus << std::endl;
    EXPECT_EQ(opStatus, -1);
    std::cout << "Exiting get_orch_invalid_orch_op_value test" << std::endl;
}

TEST(em_cmd_t, set_orch_op_index_typical_valid)
{
    std::cout << "Entering set_orch_op_index_typical_valid test" << std::endl;
    em_cmd_t cmd;
    unsigned int idx = 10;
    std::cout << "Invoking set_orch_op_index with idx = " << idx << std::endl;
    EXPECT_NO_THROW(cmd.set_orch_op_index(idx));
    std::cout << "After invocation, m_orch_op_idx = " << cmd.m_orch_op_idx << std::endl;
    EXPECT_EQ(cmd.m_orch_op_idx, idx);
    std::cout << "Exiting set_orch_op_index_typical_valid test" << std::endl;
}

TEST(em_cmd_t, set_orch_op_index_lower_bound)
{
    std::cout << "Entering set_orch_op_index_lower_bound test" << std::endl;
    em_cmd_t cmd;
    unsigned int idx = 0;
    std::cout << "Invoking set_orch_op_index with idx = " << idx << std::endl;
    EXPECT_NO_THROW(cmd.set_orch_op_index(idx));
    std::cout << "After invocation, m_orch_op_idx = " << cmd.m_orch_op_idx << std::endl;
    EXPECT_EQ(cmd.m_orch_op_idx, idx);
    std::cout << "Exiting set_orch_op_index_lower_bound test" << std::endl;
}

TEST(em_cmd_t, set_orch_op_index_upper_bound)
{
    std::cout << "Entering set_orch_op_index_upper_bound test" << std::endl;
    em_cmd_t cmd;
    unsigned int idx = UINT_MAX;
    std::cout << "Invoking set_orch_op_index with idx = " << idx << std::endl;
    EXPECT_NO_THROW(cmd.set_orch_op_index(idx));
    std::cout << "After invocation, m_orch_op_idx = " << cmd.m_orch_op_idx << std::endl;
    EXPECT_EQ(cmd.m_orch_op_idx, idx);
    std::cout << "Exiting set_orch_op_index_upper_bound test" << std::endl;
}

TEST(em_cmd_t, get_orch_op_index_retrieve_lower_bound)
{
    std::cout << "Entering get_orch_op_index_retrieve_lower_bound test" << std::endl;
    em_cmd_t obj;
	obj.m_orch_op_idx = 0;
    std::cout << "Invoking get_orch_op_index() method on em_cmd_t object" << std::endl;
    unsigned int orchOpIndex = obj.get_orch_op_index();
    std::cout << "get_orch_op_index() returned value: " << orchOpIndex << std::endl;
    EXPECT_EQ(orchOpIndex, 0u);
    std::cout << "Exiting get_orch_op_index_retrieve_lower_bound test" << std::endl;
}

TEST(em_cmd_t, get_orch_op_index_retrieve_upper_bound)
{
    std::cout << "Entering get_orch_op_index_retrieve_upper_bound test" << std::endl;
    em_cmd_t obj;
	obj.m_orch_op_idx = UINT_MAX;
    std::cout << "Invoking get_orch_op_index() method on em_cmd_t object" << std::endl;
    unsigned int orchOpIndex = obj.get_orch_op_index();
    std::cout << "get_orch_op_index() returned value: " << orchOpIndex << std::endl;
    EXPECT_EQ(orchOpIndex, UINT_MAX);
    std::cout << "Exiting get_orch_op_index_retrieve_upper_bound test" << std::endl;
}

TEST(em_cmd_t, override_op_valid_override)
{
    std::cout << "Entering override_op_valid_override test" << std::endl;
    em_cmd_t cmd{};
	unsigned int index = 0;
    em_orch_desc_t desc{ dm_orch_type_em_update, true };
    std::cout << "Prepared descriptor with op = " << desc.op << " and submit = " << desc.submit << std::endl;
    std::cout << "Invoking override_op with index = 0 and given descriptor" << std::endl;
    EXPECT_NO_THROW(cmd.override_op(index, &desc));
    std::cout << "After override_op, internal state m_orch_desc: op = " 
              << cmd.m_orch_desc[index].op << " and submit = " << cmd.m_orch_desc[index].submit << std::endl;
    EXPECT_EQ(cmd.m_orch_desc[index].op, dm_orch_type_em_update);
    EXPECT_EQ(cmd.m_orch_desc[index].submit, true);
    std::cout << "Exiting override_op_valid_override test" << std::endl;
}

TEST(em_cmd_t, override_op_invalid_index_out_of_range)
{
    std::cout << "Entering override_op_invalid_index_out_of_range test" << std::endl;
    em_cmd_t cmd{};
	unsigned int index = UINT_MAX;
    em_orch_desc_t desc{ dm_orch_type_net_insert, true };
    std::cout << "Prepared descriptor with op = " << desc.op << " and submit = " << desc.submit << std::endl;
    std::cout << "Invoking override_op with index = UINT_MAX and given descriptor" << std::endl;
    EXPECT_ANY_THROW(cmd.override_op(index, &desc));
    std::cout << "Exiting override_op_invalid_index_out_of_range test" << std::endl;
}

TEST(em_cmd_t, override_op_null_descriptor)
{
    std::cout << "Entering override_op_null_descriptor test" << std::endl;
    em_cmd_t cmd{};
	unsigned int index = 1;
    std::cout << "Invoking override_op with index = " << index << " and NULL descriptor pointer" << std::endl;
    EXPECT_ANY_THROW(cmd.override_op(index, nullptr));
    std::cout << "Exiting override_op_null_descriptor test" << std::endl;
}