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
#include "em_msg.h"
#include <cstring>

#define TLV_HEADER_SIZE 3  // type (1) + len (2)
#define MAC_LEN 6

em_profile_type_t profiles[] = {
    em_profile_type_reserved,
    em_profile_type_1,
    em_profile_type_2,
    em_profile_type_3
};
em_tlv_type_t types[] = {
    em_tlv_type_eom,
    em_tlv_type_al_mac_address, 
    em_tlv_type_mac_address,
    em_tlv_type_device_info,
    em_tlv_type_device_bridging_cap,
    em_tlv_type_non1905_neigh_list,
    em_tlv_type_1905_neigh_list,
    em_tlv_type_link_metric,
    em_tlv_type_transmitter_link_metric,
    em_tlv_type_receiver_link_metric,
    em_tlv_type_vendor_specific,
    em_tlv_type_link_metric_result_code,
    em_tlv_type_searched_role,
    em_tlv_type_autoconf_freq_band,
    em_tlv_type_supported_role,
    em_tlv_type_supported_freq_band,
    em_tlv_type_wsc,
    em_tlv_type_supported_service,
    em_tlv_type_searched_service,
    em_tlv_type_radio_id,
    em_tlv_type_operational_bss,
    em_tlv_type_associated_clients,
    em_tlv_type_ap_radio_basic_cap,
    em_tlv_type_ht_cap,
    em_tlv_type_vht_cap,
    em_tlv_type_he_cap,
    em_tlv_type_steering_policy,
    em_tlv_type_metric_reporting_policy,
    em_tlv_type_channel_pref,
    em_tlv_type_radio_op_restriction,
    em_tlv_type_tx_power,
    em_tlv_type_channel_sel_resp,
    em_tlv_type_op_channel_report,
    em_tlv_type_client_info,
    em_tlv_type_client_cap_report,
    em_tlv_type_client_assoc_event,
    em_tlv_type_ap_metrics_query,
    em_tlv_type_ap_metrics,
    em_tlv_type_sta_mac_addr,
    em_tlv_type_assoc_sta_link_metric,
    em_tlv_type_unassoc_sta_link_metric_query,
    em_tlv_type_unassoc_sta_link_metric_rsp,
    em_tlv_type_bcon_metric_query,
    em_tlv_type_bcon_metric_rsp,
    em_tlv_type_steering_request,
    em_tlv_type_steering_btm_rprt,
    em_tlv_type_client_assoc_ctrl_req,
    em_tlv_type_bh_steering_req,
    em_tlv_type_bh_steering_rsp,
    em_tlv_type_higher_layer_data,
    em_tlv_type_ap_cap,
    em_tlv_type_assoc_sta_traffic_sts,
    em_tlv_type_error_code,
    em_tlv_type_channel_scan_rprt_policy,
    em_tlv_type_channel_scan_cap,
    em_tlv_type_channel_scan_req,
    em_tlv_type_channel_scan_rslt,
    em_tlv_type_timestamp,
    em_tlv_type_1905_layer_security_cap,
    em_tlv_type_ap_wifi6_cap,
    em_tlv_type_mic,
    em_tlv_type_encrypt_payload,
    em_tlv_type_cac_req,
    em_tlv_type_cac_term,
    em_tlv_type_cac_cmpltn_rprt,
    em_tlv_type_assoc_wifi6_sta_rprt,
    em_tlv_type_cac_sts_rprt,
    em_tlv_type_cac_cap,
    em_tlv_type_profile,
    em_tlv_type_profile_2_ap_cap,
    em_tlv_type_dflt_8021q_settings,
    em_tlv_type_traffic_separation_policy,
    em_tlv_type_bss_conf_rep,
    em_tlv_type_bssid,
    em_tlv_type_svc_prio_rule,
    em_tlv_type_dscp_map_tbl,
    em_tlv_type_bss_conf_req,
    em_tlv_type_profile_2_error_code,
    em_tlv_type_bss_conf_rsp,
    em_tlv_type_ap_radio_advanced_cap,
    em_tlv_type_assoc_sts_notif,
    em_tlv_type_src_info,
    em_tlv_type_tunneled_msg_type,
    em_tlv_type_tunneled,
    em_tlv_type_profile2_steering_request,
    em_tlv_type_unsucc_assoc_policy,
    em_tlv_type_metric_cltn_interval,
    em_tlv_type_radio_metric,
    em_tlv_type_ap_ext_metric,
    em_tlv_type_assoc_sta_ext_link_metric,
    em_tlv_type_status_code,
    em_tlv_type_reason_code,
    em_tlv_type_bh_sta_radio_cap,
    em_tlv_type_akm_suite,
    em_tlv_type_1905_encap_dpp,
    em_tlv_type_1905_encap_eapol,
    em_tlv_type_dpp_bootstrap_uri_notification,
    em_tlv_type_backhaul_bss_conf,
    em_tlv_type_dpp_msg,
    em_tlv_type_dpp_cce_indication,
    em_tlv_type_dpp_chirp_value,
    em_tlv_type_device_inventory,
    em_tlv_type_agent_list,
    em_tlv_type_anticipated_channel_pref,
    em_tlv_type_channel_usage,
    em_tlv_type_spatial_reuse_req,
    em_tlv_type_spatial_reuse_rep,
    em_tlv_type_spatial_reuse_cfg_rsp,
    em_tlv_type_qos_mgmt_policy,
    em_tlv_type_qos_mgmt_desc,
    em_tlv_type_ctrl_cap,
    em_tlv_type_wifi7_agent_cap,
    em_tlv_type_ap_mld_config,
    em_tlv_type_bsta_mld_config,
    em_tlv_type_assoc_sta_mld_conf_rep,
    em_tlv_type_tid_to_link_map_policy,
    em_tlv_eht_operations,
    em_tlv_type_avail_spectrum_inquiry_reg,
    em_tlv_type_avail_spectrum_inquiry_rsp,
    em_tlv_type_vendor_sta_metrics,
    em_tlv_vendor_plolicy_cfg,
    em_tlv_type_vendor_operational_bss,
};

#define TLV_TYPE_COUNT 123

inline void write_tlv(unsigned char *buf, unsigned char type, const unsigned char *value, unsigned short len)
{
    buf[0] = type;
    uint16_t be_len = htons(len);
    memcpy(buf + 1, &be_len, 2);
    if (len > 0 && value)
        memcpy(buf + TLV_HEADER_SIZE, value, len);
}

/**
 * @brief Test add_1905_header by validating the header creation for relay types
 *
 * This test verifies that the add_1905_header function properly constructs the 1905 header when provided with valid relay type parameters. 
 * It tests the correct copying of destination and source MAC addresses, setting of the ethertype, and the correct values in the em_cmdu_t structure.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke add_1905_header for each relay type and validate the header fields such as destination/source MAC addresses, ethertype, and em_cmdu_t structure fields (type, id, relay_ind) | dst = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, src = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66}, msg_id = 0x1234, relayTypes = {em_msg_type_topo_notif, em_msg_type_autoconf_search, em_msg_type_autoconf_renew} | Expected header length, pointer offset and field values match the specification: len equals expected_len, returned pointer equals buff+expected_len, MAC addresses, ethertype, and cmdu fields are correctly populated | Should Pass |
 */
TEST(em_msg_t, add_1905_header_valid_relay) {
    std::cout << "Entering add_1905_header_valid_relay test" << std::endl;
    em_msg_type_t relayTypes[] = {
        em_msg_type_topo_notif,
        em_msg_type_autoconf_search,
        em_msg_type_autoconf_renew
    };
    const int numRelayTypes = sizeof(relayTypes) / sizeof(relayTypes[0]);
    unsigned char dst[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    unsigned char src[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    unsigned short msg_id = 0x1234;
    for (int i = 0; i < numRelayTypes; i++) {
        unsigned char buff[256] = {0};
        unsigned int len = 0;
        em_msg_t obj;
        unsigned char* ret = obj.add_1905_header(buff, &len, dst, src, relayTypes[i], msg_id);
        unsigned int expected_len = 2 * sizeof(mac_address_t) + sizeof(uint16_t) + sizeof(em_cmdu_t);
        EXPECT_EQ(len, expected_len);
        EXPECT_EQ(ret, buff + expected_len);
        EXPECT_EQ(std::memcmp(buff, dst, sizeof(mac_address_t)), 0);
        EXPECT_EQ(std::memcmp(buff + sizeof(mac_address_t), src, sizeof(mac_address_t)), 0);
        uint16_t ethertype = *(reinterpret_cast<uint16_t*>(buff + 2*sizeof(mac_address_t)));
        EXPECT_EQ(ntohs(ethertype), ETH_P_1905);
        em_cmdu_t* cmdu = reinterpret_cast<em_cmdu_t*>(buff + 2*sizeof(mac_address_t) + sizeof(uint16_t));
        EXPECT_EQ(ntohs(cmdu->type), relayTypes[i]);
        EXPECT_EQ(ntohs(cmdu->id), msg_id);
        EXPECT_EQ(cmdu->relay_ind, 1); // relay types
    }
    std::cout << "Exiting add_1905_header_valid_relay test" << std::endl;
}
/**
 * @brief Test the add_1905_header API for valid non-relay message types
 *
 * This test verifies that the add_1905_header function correctly constructs a 1905 header
 * for various non-relay topology message types. It checks that the function correctly sets
 * the destination and source MAC addresses, the ethertype field, and the CMDU header fields including
 * the type, message ID, and relay indicator.
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
 * | 01 | Initialize test parameters including non-relay message types, destination MAC, source MAC, and message ID | nonRelayTypes = em_msg_type_topo_disc, em_msg_type_topo_query, em_msg_type_topo_resp; dst = {0xDE,0xAD,0xBE,0xEF,0x00,0x01}; src = {0xFE,0xED,0xFA,0xCE,0x02,0x03}; msg_id = 0x5678 | Test parameters are correctly initialized | Should be successful |
 * | 02 | Invoke add_1905_header API within a loop for each non-relay type | buff = 256-byte zero initialized array, len pointer, dst, src, current nonRelayTypes value, msg_id | API returns ret pointer equal to buff + expected length and sets len to expected length (2*sizeof(mac_address_t)+sizeof(uint16_t)+sizeof(em_cmdu_t)) | Should Pass |
 * | 03 | Validate the constructed header fields within the buffer | buff contents include: first mac_address_t = dst, second mac_address_t = src; ethertype field = ETH_P_1905; CMDU header with type = current nonRelayTypes, id = msg_id, relay_ind = 0 | Buffer header fields match the expected values using memcmp comparisons and ntohs conversions for numeric fields | Should Pass |
 */
TEST(em_msg_t, add_1905_header_valid_nonrelay) {
    std::cout << "Entering add_1905_header_valid_nonrelay test" << std::endl;
    em_msg_type_t nonRelayTypes[] = {
        em_msg_type_topo_disc,
        em_msg_type_topo_query,
        em_msg_type_topo_resp
    };
    const int numNonRelay = sizeof(nonRelayTypes) / sizeof(nonRelayTypes[0]);
    unsigned char dst[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
    unsigned char src[6] = {0xFE, 0xED, 0xFA, 0xCE, 0x02, 0x03};
    unsigned short msg_id = 0x5678;
    for (int i = 0; i < numNonRelay; i++) {
        unsigned char buff[256] = {0};
        unsigned int len = 0;
        em_msg_t obj;
        unsigned char* ret = obj.add_1905_header(buff, &len, dst, src, nonRelayTypes[i], msg_id);
        unsigned int expected_len = 2 * sizeof(mac_address_t) + sizeof(uint16_t) + sizeof(em_cmdu_t);
        EXPECT_EQ(len, expected_len);
        EXPECT_EQ(ret, buff + expected_len);
        EXPECT_EQ(std::memcmp(buff, dst, sizeof(mac_address_t)), 0);
        EXPECT_EQ(std::memcmp(buff + sizeof(mac_address_t), src, sizeof(mac_address_t)), 0);
        uint16_t ethertype = *(reinterpret_cast<uint16_t*>(buff + 2*sizeof(mac_address_t)));
        EXPECT_EQ(ntohs(ethertype), ETH_P_1905);
        em_cmdu_t* cmdu = reinterpret_cast<em_cmdu_t*>(buff + 2*sizeof(mac_address_t) + sizeof(uint16_t));
        EXPECT_EQ(ntohs(cmdu->type), nonRelayTypes[i]);
        EXPECT_EQ(ntohs(cmdu->id), msg_id);
        EXPECT_EQ(cmdu->relay_ind, 0); // non-relay types
    }
    std::cout << "Exiting add_1905_header_valid_nonrelay test" << std::endl;
}
/**
 * @brief Validate that add_1905_header returns nullptr when provided with a null buffer pointer
 *
 * This test case verifies that the em_msg_t::add_1905_header API handles a null destination buffer pointer appropriately by returning a nullptr. The test ensures that the function does not proceed with invalid input and that the assertion correctly identifies the null pointer return.
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
 * | Variation / Step | Description                                                       | Test Data                                                                                                  | Expected Result                                         | Notes         |
 * | :--------------: | ----------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | --------------------------------------------------------| ------------- |
 * | 01               | Call add_1905_header with a null destination buffer pointer       | buff = nullptr, len = 50, dst = {0x00,0x11,0x22,0x33,0x44,0x55}, src = {0x66,0x77,0x88,0x99,0xAA,0xBB}, msg_type = em_msg_type_topo_disc, msg_id = 0x0001 | Return value is nullptr and assertion confirms equality | Should Pass   |
 */
TEST(em_msg_t, add_1905_header_null_buff)
{
    std::cout << "Entering add_1905_header_null_buff test" << std::endl;
    unsigned int len = 50;
    unsigned char dst[6] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    unsigned char src[6] = { 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB };
    unsigned short msg_id = 0x0001;
    em_msg_t obj;
    unsigned char* ret = obj.add_1905_header(nullptr, &len, dst, src, em_msg_type_topo_disc, msg_id);
    ASSERT_EQ(ret, nullptr);
    std::cout << "Exiting add_1905_header_null_buff test" << std::endl;
}
/**
 * @brief Test add_1905_header API with a null length pointer to validate error handling
 *
 * This test verifies that the add_1905_header function properly returns a null pointer when the length parameter is passed as nullptr. The test confirms that the API can handle a missing length parameter by returning an error indicator (nullptr).
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize test variables including buffers and message ID. | buff = array of 30 zeros, dst = {0x10,0x20,0x30,0x40,0x50,0x60}, src = {0x60,0x50,0x40,0x30,0x20,0x10}, msg_id = 0x0001 | Variables are successfully initialized. | Should be successful |
 * | 02 | Invoke add_1905_header with a null pointer for the length parameter. | input: buff pointer, length pointer = nullptr, dst pointer, src pointer, msg_type = em_msg_type_topo_disc, msg_id = 0x0001 | API returns nullptr and assertion verifies the returned value is nullptr. | Should Pass |
 * | 03 | Log the test exit message. | N/A | Test execution completes with an exit log message. | Should be successful |
 */
TEST(em_msg_t, add_1905_header_null_len)
{
    std::cout << "Entering add_1905_header_null_len test" << std::endl;
    unsigned char buff[30] = {0};
    unsigned char dst[6] = { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60 };
    unsigned char src[6] = { 0x60, 0x50, 0x40, 0x30, 0x20, 0x10 };
    unsigned short msg_id = 0x0001;
    em_msg_t obj;
    unsigned char* ret = obj.add_1905_header(buff, nullptr, dst, src, em_msg_type_topo_disc, msg_id);
    ASSERT_EQ(ret, nullptr);
    std::cout << "Exiting add_1905_header_null_len test" << std::endl;
}
/**
 * @brief Validate that add_1905_header constructs the correct header when msg_id is zero
 *
 * This test verifies that the add_1905_header function correctly constructs the 1905 header using the provided source and destination MAC addresses, a message type, and a message ID of zero. It checks that the length, memory content, and header fields (including EtherType, message type, and message ID) are set as expected.
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
 * | Variation / Step | Description | Test Data | Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Print entry log message for the test case | N/A | "Entering add_1905_header_valid_msgid_zero test" is printed to stdout | Should be successful |
 * | 02 | Initialize buffers and variables including dst, src, msg_id, and msg_type | buff[30]={0}, dst={0x10, 0x20, 0x30, 0x40, 0x50, 0x60}, src={0x60, 0x50, 0x40, 0x30, 0x20, 0x10}, msg_id=0, msg_type=em_msg_type_topo_disc | Variables are initialized as expected | Should be successful |
 * | 03 | Call add_1905_header and capture the return pointer and updated length | input: buff, pointer to len, dst, src, msg_type, msg_id=0; output: ret pointer, len updated | Returned pointer equals buff plus expected length; len matches the calculated expected length | Should Pass |
 * | 04 | Compare the memory content of buff with dst and src arrays using memcmp | buff content vs dst and src values | memcmp returns 0 for both comparisons indicating correct copy | Should Pass |
 * | 05 | Validate header fields: EtherType, message type, message id, and relay indicator | expectedEtherType={0x89, 0x3a}, hdr_msg_type from buff, hdr_msg_id from buff, relay_ind from buff | EtherType, hdr_msg_type, hdr_msg_id and relay_ind match the expected values (msg_type equals provided, msg_id is 0, relay_ind equals 0) | Should Pass |
 * | 06 | Print exit log message for the test case | N/A | "Exiting add_1905_header_valid_msgid_zero test" is printed to stdout | Should be successful |
 */
TEST(em_msg_t, add_1905_header_valid_msgid_zero)
{
    std::cout << "Entering add_1905_header_valid_msgid_zero test" << std::endl;
    unsigned char buff[30] = {0};
    unsigned int len = 0;
    unsigned char dst[6] = { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60 };
    unsigned char src[6] = { 0x60, 0x50, 0x40, 0x30, 0x20, 0x10 };
    unsigned short msg_id = 0x0000; // msg_id = 0
    em_msg_type_t msg_type = em_msg_type_topo_disc;
    em_msg_t obj;
    unsigned char* ret = obj.add_1905_header(buff, &len, dst, src, msg_type, msg_id);
    unsigned int expected_len = 2 * sizeof(mac_address_t) + sizeof(uint16_t) + sizeof(em_cmdu_t);
    EXPECT_EQ(len, expected_len);
    EXPECT_EQ(ret, buff + expected_len);
    EXPECT_EQ(std::memcmp(buff, dst, 6), 0);
    EXPECT_EQ(std::memcmp(buff + 6, src, 6), 0);
    unsigned char expectedEtherType[2] = { 0x89, 0x3a };
    EXPECT_EQ(std::memcmp(buff + 12, expectedEtherType, 2), 0);
    uint16_t hdr_msg_type = ntohs(*(reinterpret_cast<uint16_t*>(buff + 14)));
    uint16_t hdr_msg_id   = ntohs(*(reinterpret_cast<uint16_t*>(buff + 16)));
    unsigned char relay_ind = *(buff + 18);
    EXPECT_EQ(hdr_msg_type, msg_type);
    EXPECT_EQ(hdr_msg_id, msg_id);
    EXPECT_EQ(relay_ind, 0);
    std::cout << "Exiting add_1905_header_valid_msgid_zero test" << std::endl;
}
/**
 * @brief Verify that the add_1905_header API correctly assembles a 1905 header with maximum valid message ID.
 *
 * This test verifies that the add_1905_header function creates a correctly formatted 1905 header when provided
 * with valid input parameters including the maximum possible message ID (0xFFFF). It checks that the correct data
 * is copied into the buffer, that the header length is correctly calculated, and that fields such as the EtherType,
 * message type, message ID, and relay indicator are properly set. The test ensures that the function returns the 
 * proper pointer into the buffer and that all header fields meet the expected values.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 006@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                           | Test Data                                                                                                                                                               | Expected Result                                                                          | Notes         |
 * | :--------------: | ----------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ------------- |
 * | 01               | Initialize test variables including buffers, MAC addresses, message type, and maximum message ID.     | buff = {0,...}, len = 0, dst = {0xAB,0xCD,0xEF,0x01,0x23,0x45}, src = {0x54,0x32,0x10,0xFE,0xDC,0xBA}, msg_id = 0xFFFF, msg_type = em_msg_type_topo_disc            | All variables are initialized correctly without errors.                                | Should be successful |
 * | 02               | Invoke the add_1905_header API to add the header to the buffer and update the length.                 | input: buff, pointer to len, dst, src, msg_type, msg_id                                                                                                                 | The API should return buff + expected_len and update len to expected_len.                | Should Pass   |
 * | 03               | Validate the header fields in the buffer using assertions (MAC address copy, EtherType, message type/id, relay indicator). | output: buff contents at offsets (dst copied at beginning, src following, EtherType at offset 12, msg_type and msg_id in header, relay_ind set to 0)                   | The header fields must match expected values confirmed via EXPECT_EQ and memcmp checks.    | Should Pass   |
 */
TEST(em_msg_t, add_1905_header_valid_max_msgid)
{
    std::cout << "Entering add_1905_header_valid_max_msgid test" << std::endl;
    unsigned char buff[30] = {0};
    unsigned int len = 0;
    unsigned char dst[6] = { 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45 };
    unsigned char src[6] = { 0x54, 0x32, 0x10, 0xFE, 0xDC, 0xBA };
    unsigned short msg_id = 0xFFFF;
    em_msg_type_t msg_type = em_msg_type_topo_disc;
    em_msg_t obj;
    unsigned char* ret = obj.add_1905_header(buff, &len, dst, src, msg_type, msg_id);
    unsigned int expected_len = 2*sizeof(mac_address_t) + sizeof(uint16_t) + sizeof(em_cmdu_t);
    EXPECT_EQ(ret, buff + expected_len);
    EXPECT_EQ(len, expected_len);
    EXPECT_EQ(std::memcmp(buff, dst, 6), 0);
    EXPECT_EQ(std::memcmp(buff + 6, src, 6), 0);
    unsigned char expectedEtherType[2] = { 0x89, 0x3a };
    EXPECT_EQ(std::memcmp(buff + 12, expectedEtherType, 2), 0);
    uint16_t hdr_msg_type =  ntohs(*reinterpret_cast<const uint16_t*>(buff + 16));
    uint16_t hdr_msg_id =  ntohs(*reinterpret_cast<const uint16_t*>(buff + 18));
    unsigned char relay_ind = *(buff + 22);
    EXPECT_EQ(hdr_msg_type, msg_type);
    EXPECT_EQ(hdr_msg_id, msg_id);
    EXPECT_EQ(relay_ind, 0);
    std::cout << "Exiting add_1905_header_valid_max_msgid test" << std::endl;
}
/**
 * @brief Tests the add_buff_element function with a valid non-zero element length.
 *
 * This test verifies that when a non-zero element is provided, the function correctly
 * appends the element to the given buffer, updates the total length, returns a non-null pointer
 * pointing immediately after the newly added element, and the buffer contains the element data.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 007@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke add_buff_element using an allocated buffer, a pointer to the initial length (0), and a non-zero length element; then verify the buffer update, length modification, and returned pointer adjustment. | input: buff_size = 10, buff = buffer initialized to 0, len = 0, element = {0x01, 0x02, 0x03}, element_len = 3; output: ret pointer | ret is not nullptr; len equals 3; buff contains {0x01, 0x02, 0x03}; ret equals buff + 3 | Should Pass |
 */
TEST(em_msg_t, add_buff_element_valid_non_zero_element_length) {
    std::cout << "Entering add_buff_element_valid_non_zero_element_length test" << std::endl;
    unsigned int buff_size = 10;
    unsigned char *buff = new unsigned char[buff_size];
    memset(buff, 0, buff_size);
    unsigned int len = 0;
    unsigned char element[3] = { 0x01, 0x02, 0x03 };
    unsigned int element_len = 3;
    em_msg_t obj;
    unsigned char *ret = obj.add_buff_element(buff, &len, element, element_len);
    ASSERT_NE(ret, nullptr);
    EXPECT_EQ(len, 3);
    EXPECT_EQ(memcmp(buff, element, element_len), 0);
    EXPECT_EQ(ret, buff + element_len);
    delete[] buff;
    std::cout << "Exiting add_buff_element_valid_non_zero_element_length test" << std::endl;
}
/**
 * @brief Validate that add_buff_element correctly appends an element to a buffer with an initial non-zero length.
 *
 * This test verifies that providing a valid element to be added into a buffer, which already contains an initial data length, updates the length accurately and returns a valid pointer. It ensures that the memory content of the buffer is correctly updated with the new element and that the function behaves as expected under normal operating conditions.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 008
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- | -------------- | ----- |
 * | 01 | Call add_buff_element with a buffer of size 10, initialized with zeros, and an initial length of 5, to append an element {0xAA, 0xBB} with length 2 | buff_size = 10, initial buff = zeros, len = 5, element = {0xAA, 0xBB}, element_len = 2 | Returns a non-null pointer; len is updated to 7 (5 + 2); the first 2 bytes of buff match the element; returned pointer equals buff + 2 | Should Pass |
 */
TEST(em_msg_t, add_buff_element_valid_non_zero_element_length_with_initial_len) {
    std::cout << "Entering add_buff_element_valid_non_zero_element_length_with_initial_len test" << std::endl;
    unsigned int buff_size = 10;
    unsigned char *buff = new unsigned char[buff_size];
    memset(buff, 0, buff_size);
    unsigned int len = 5;
    unsigned char element[2] = { 0xAA, 0xBB };
    unsigned int element_len = 2;
    em_msg_t obj;
    unsigned char *ret = obj.add_buff_element(buff, &len, element, element_len);
    ASSERT_NE(ret, nullptr);
    EXPECT_EQ(len, 7); // 5 + 2
    EXPECT_EQ(memcmp(buff, element, element_len), 0);
    EXPECT_EQ(ret, buff + element_len);
    delete[] buff;
    std::cout << "Exiting add_buff_element_valid_non_zero_element_length_with_initial_len test" << std::endl;
}
/**
 * @brief Validate that add_buff_element returns the original buffer when a zero-length element is provided
 *
 * This test verifies that when add_buff_element is invoked with a valid non-null element pointer but a zero element_len,
 * the function does not modify the input length and returns the original buffer pointer. This behavior is key to ensuring
 * that the function handles edge cases of zero-length inputs gracefully.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 009@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                                               | Test Data                                                                                                           | Expected Result                                                                                    | Notes         |
 * | :--------------: | ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- | ------------- |
 * | 01               | Invoke add_buff_element with a valid buffer and element pointer but zero length | buff_size = 10, buff = allocated and zero-initialized buffer, len = 10, element = pointer to dummy (0xFF), element_len = 0 | Return pointer should not be nullptr; len remains 10; returned pointer equals the original buff pointer | Should Pass   |
 */
TEST(em_msg_t, add_buff_element_zero_length_valid_element_pointer) {
    std::cout << "Entering add_buff_element_zero_length_valid_element_pointer test" << std::endl;
    unsigned int buff_size = 10;
    unsigned char *buff = new unsigned char[buff_size];
    memset(buff, 0, buff_size);
    unsigned int len = 10;
    unsigned char dummy = 0xFF;
    unsigned char *element = &dummy;
    unsigned int element_len = 0;
    em_msg_t obj;
    unsigned char *ret = obj.add_buff_element(buff, &len, element, element_len);
    ASSERT_NE(ret, nullptr);
    EXPECT_EQ(len, 10);
    EXPECT_EQ(ret, buff); // buff + 0
    delete[] buff;
    std::cout << "Exiting add_buff_element_zero_length_valid_element_pointer test" << std::endl;
}
/**
 * @brief Validate add_buff_element API's behavior when provided with a null buffer pointer.
 *
 * This test verifies that the add_buff_element API of the em_msg_t class correctly handles a scenario where the buffer pointer is null. 
 * The test invokes the API with a nullptr for the buffer, a valid element array, and checks that the return value is also a nullptr, ensuring that the API gracefully rejects invalid buffer input.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 010
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                         | Test Data                                                             | Expected Result                                                   | Notes      |
 * | :--------------: | ------------------------------------------------------------------- | --------------------------------------------------------------------- | ----------------------------------------------------------------- | ---------- |
 * | 01               | Invoke add_buff_element with a null pointer for the buffer parameter. | buff = nullptr, len = 0, element = {0x01, 0x02}, element_len = 2, output ret should be nullptr | API returns nullptr; ASSERT_EQ(ret, nullptr) is satisfied         | Should Fail |
 */
TEST(em_msg_t, add_buff_element_null_buff_pointer) {
    std::cout << "Entering add_buff_element_null_buff_pointer test" << std::endl;
    unsigned char *buff = nullptr;
    unsigned int len = 0;
    unsigned char element[2] = { 0x01, 0x02 };
    unsigned int element_len = 2;
    em_msg_t obj;
    unsigned char *ret = obj.add_buff_element(buff, &len, element, element_len);
    ASSERT_EQ(ret, nullptr);
    std::cout << "Exiting add_buff_element_null_buff_pointer test" << std::endl;
}
/**
 * @brief Test add_buff_element API with a null length pointer
 *
 * This test verifies that the add_buff_element API handles a null pointer for the length argument correctly by returning a nullptr. This ensures the API prevents undefined behavior when provided with invalid input.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 011@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**  
 * | Variation / Step | Description | Test Data | Expected Result | Notes |  
 * | :----: | --------- | ---------- |-------------- | ----- |  
 * | 01 | Initialize a buffer of size 10 with zeros, set len_ptr to nullptr, prepare element data, and invoke add_buff_element API | buff_size = 10, buff = allocated buffer with zeros, len_ptr = nullptr, element = {0x01, 0x02}, element_len = 2 | API returns nullptr; ASSERT_EQ(ret, nullptr) | Should Fail |
 */
TEST(em_msg_t, add_buff_element_null_len_pointer) {
    std::cout << "Entering add_buff_element_null_len_pointer test" << std::endl;
    unsigned int buff_size = 10;
    unsigned char *buff = new unsigned char[buff_size];
    memset(buff, 0, buff_size);
    unsigned int *len_ptr = nullptr;
    unsigned char element[2] = { 0x01, 0x02 };
    unsigned int element_len = 2;
    em_msg_t obj;
    unsigned char *ret = obj.add_buff_element(buff, len_ptr, element, element_len);
    ASSERT_EQ(ret, nullptr);
    delete[] buff;
    std::cout << "Exiting add_buff_element_null_len_pointer test" << std::endl;
}
/**
 * @brief Validate that add_buff_element returns nullptr when a null element pointer is provided with nonzero length
 *
 * Validate that the API correctly handles the scenario where a non-null buffer is provided, but the element pointer is NULL with a nonzero element length. This test ensures that error handling in the API prevents any buffer modifications under invalid input conditions.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 012
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize buffer and object; assign element pointer as NULL while setting a nonzero element length; call add_buff_element | buff_size = 10, element = NULL, element_len = 3, len = 0, buff initialized to zeros, obj instance created | The API should return a nullptr, confirmed by ASSERT_EQ(ret, nullptr) | Should Pass |
 */
TEST(em_msg_t, add_buff_element_null_element_pointer_nonzero_length) {
    std::cout << "Entering add_buff_element_null_element_pointer_nonzero_length test" << std::endl;
    unsigned int buff_size = 10;
    unsigned char *buff = new unsigned char[buff_size];
    memset(buff, 0, buff_size);
    unsigned int len = 0;
    unsigned char *element = NULL;
    unsigned int element_len = 3;
    em_msg_t obj;
    unsigned char *ret = obj.add_buff_element(buff, &len, element, element_len);
    ASSERT_EQ(ret, nullptr);
    delete[] buff;
    std::cout << "Exiting add_buff_element_null_element_pointer_nonzero_length test" << std::endl;
}
/**
 * @brief Validate that add_eom_tlv adds an end-of-message TLV to a valid buffer starting with an initial length of zero.
 *
 * This test verifies that the add_eom_tlv method correctly calculates the TLV length and updates both the buffer pointer and length when called with a valid buffer and an initial length of zero. It ensures that the end-of-message TLV is constructed properly.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 013@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- | -------------- | ----- |
 * | 01 | Invoke add_eom_tlv with a valid buffer with an initial length of zero and verify the returned pointer and updated length. | buffer = array of 10 zeros, len = 0, expected_len = sizeof(em_tlv_t) | ret_ptr equals (buffer + expected_len) and len equals expected_len | Should Pass |
 */
TEST(em_msg_t, add_eom_tlv_valid_buffer_initial_len_zero) {
    std::cout << "Entering add_eom_tlv_valid_buffer_initial_len_zero test" << std::endl;
    unsigned char buffer[10] = {0};
    unsigned int len = 0;
    em_msg_t msg;
    unsigned char * ret_ptr = msg.add_eom_tlv(buffer, &len);
    unsigned int expected_len = sizeof(em_tlv_t); // + value_len (0 for EOM)
    EXPECT_EQ(ret_ptr, buffer + expected_len);
    EXPECT_EQ(len, expected_len);
    std::cout << "Exiting add_eom_tlv_valid_buffer_initial_len_zero test" << std::endl;
}
/**
 * @brief Validate the correct addition of an End-Of-Message TLV to a valid buffer with a non-zero initial length
 *
 * This test verifies that the add_eom_tlv API correctly appends an EOM TLV to the provided buffer starting from a non-zero initial offset. It ensures that the returned pointer and the updated length are correctly computed by adding the size of the TLV to the initial length.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 014@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize a 20-byte zeroed buffer and an initial length of 10, then create an em_msg_t instance and call add_eom_tlv to append the TLV. | buffer = {0, 0, ...}, initial len = 10, API invocation: ret_ptr = msg.add_eom_tlv(buffer+10, &len), expected TLV size = sizeof(em_tlv_t) | ret_ptr should equal buffer + (initial len + sizeof(em_tlv_t)); len should be updated to initial len + sizeof(em_tlv_t) and both EXPECT_EQ assertions pass | Should Pass |
 */
TEST(em_msg_t, add_eom_tlv_valid_buffer_non_zero_initial_len) {
    std::cout << "Entering add_eom_tlv_valid_buffer_non_zero_initial_len test" << std::endl;
    unsigned char buffer[20] = {0};
    unsigned int len = 10;
    em_msg_t msg;
    unsigned char* ret_ptr = msg.add_eom_tlv(buffer + len, &len);
    unsigned int expected_len = 10 + sizeof(em_tlv_t); // add to existing length
    EXPECT_EQ(ret_ptr, buffer + expected_len);
    EXPECT_EQ(len, expected_len);
    std::cout << "Exiting add_eom_tlv_valid_buffer_non_zero_initial_len test" << std::endl;
}
/**
 * @brief Verify that add_eom_tlv handles null buffer input correctly
 *
 * This test ensures that when a null pointer is passed as the buffer to the add_eom_tlv API, the function returns a nullptr and does not modify the length parameter. This behavior is crucial to maintain robustness in scenarios where buffer allocation has not occurred or failed.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 015
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                         | Test Data                              | Expected Result                                | Notes      |
 * | :--------------: | --------------------------------------------------- | -------------------------------------- | ---------------------------------------------- | ---------- |
 * | 01               | Call add_eom_tlv with a null buffer input           | buffer = nullptr, len = 5              | Return value is nullptr and len remains 5      | Should Pass|
 */
TEST(em_msg_t, add_eom_tlv_null_buffer) {
    std::cout << "Entering add_eom_tlv_null_buffer test" << std::endl;
    unsigned int len = 5;
    em_msg_t msg;
    unsigned char * ret_ptr = msg.add_eom_tlv(nullptr, &len);
    ASSERT_EQ(ret_ptr, nullptr);
    EXPECT_EQ(len, 5u);
    std::cout << "Exiting add_eom_tlv_null_buffer test" << std::endl;
}
/**
 * @brief Validate add_eom_tlv function with null length pointer.
 *
 * This test verifies that the add_eom_tlv method correctly handles the scenario where a null pointer is passed for the TLV length argument, ensuring that it returns a null pointer under such conditions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 016@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                                                           | Test Data                                             | Expected Result                                                     | Notes       |
 * | :--------------: | ------------------------------------------------------------------------------------- | ----------------------------------------------------- | ------------------------------------------------------------------- | ----------- |
 * | 01               | Call add_eom_tlv with a valid buffer and a null pointer for the TLV length parameter.   | buffer = [0,0,0,0,0,0,0,0,0,0], len = nullptr          | The API returns a nullptr and the ASSERT_EQ check confirms the result| Should Pass |
 */
TEST(em_msg_t, add_eom_tlv_null_len) {
    std::cout << "Entering add_eom_tlv_null_len test" << std::endl;
    unsigned char buffer[10] = {0};
    em_msg_t msg;
    unsigned char * ret_ptr = msg.add_eom_tlv(buffer, nullptr);
    ASSERT_EQ(ret_ptr, nullptr);
    std::cout << "Exiting add_eom_tlv_null_len test" << std::endl;
}
/**
 * @brief Test adding a valid non-empty TLV to the message buffer.
 *
 * This test verifies that the function em_msg_t::add_tlv properly adds a non-empty TLV to the message buffer.
 * The function is invoked with valid parameters including a pointer to an offset in the buffer, an initial length,
 * a TLV type, and a non-empty value array representing a MAC address. The test ensures that the returned pointer
 * and the updated length are correct.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 017
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke the API em_msg_t::add_tlv with a valid, non-empty TLV value to add a MAC address to the message buffer. | input: buffer pointer offset = buffer+20, input: len pointer (initial value = 20), input: TLV type = em_tlv_type_mac_address, input: value array = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF}, input: value length = 6; output: ret_ptr, updated len | Return pointer equals (buffer+20 + sizeof(em_tlv_t)+6) and updated len equals (20 + sizeof(em_tlv_t)+6) | Should Pass |
 */
TEST(em_msg_t, add_tlv_valid_non_empty) {
    std::cout << "Entering add_tlv_valid_non_empty test" << std::endl;
    em_msg_t msg;
    unsigned char buffer[128] = {0};
    unsigned int initialLen = 20;
    unsigned int len = initialLen;
    unsigned char value[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    unsigned char* ret_ptr = em_msg_t::add_tlv(buffer + len, &len, em_tlv_type_mac_address, value, 6);
    const unsigned int tlv_size = sizeof(em_tlv_t) + 6; // header + value
    unsigned char* expected_ptr = buffer + initialLen + tlv_size;
    unsigned int expectedLen = initialLen + tlv_size;
    EXPECT_EQ(ret_ptr, expected_ptr);
    EXPECT_EQ(len, expectedLen);
    std::cout << "Exiting add_tlv_valid_non_empty test" << std::endl;
}
/**
 * @brief Validate adding a TLV with a valid type and zero value length
 *
 * This test verifies that invoking em_msg_t::add_tlv with a valid TLV type and a value length of zero correctly updates the buffer by inserting the TLV header and leaves the pointer to the buffer at the expected offset. It also ensures that the TLV type is set appropriately, and the length field is zero after conversion from network byte order.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 018@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call em_msg_t::add_tlv with a buffer, initial length of 50, TLV type as em_tlv_type_device_info, a null value pointer, and length 0 | buffer = zero-initialized unsigned char[128], initialLen = 50, type = em_tlv_type_device_info, value pointer = nullptr, value length = 0 | Function returns pointer set to (buffer + sizeof(em_tlv_t)) and len updated to (50 + sizeof(em_tlv_t)) | Should Pass |
 * | 02 | Validate the TLV header in the buffer by verifying the type and that TLV length equals zero after network-to-host conversion | tlv pointer = reinterpret_cast<em_tlv_t*>(buffer), expected type = em_tlv_type_device_info, expected length = 0 | TLV type equals em_tlv_type_device_info and ntohs(tlv->len) equals 0 | Should Pass |
 */
TEST(em_msg_t, add_tlv_valid_zero_value_length) {
    std::cout << "Entering add_tlv_valid_zero_value_length test" << std::endl;
    em_msg_t msg;
    unsigned char buffer[128] = {0};
    unsigned int initialLen = 50;
    unsigned int len = initialLen;
    unsigned char* ret_ptr = em_msg_t::add_tlv(buffer, &len, em_tlv_type_device_info, nullptr, 0);
    const unsigned int tlv_header_size = sizeof(em_tlv_t);
    unsigned int expectedLen = initialLen + tlv_header_size;
    unsigned char* expected_ptr = buffer + tlv_header_size;
    EXPECT_EQ(ret_ptr, expected_ptr);
    EXPECT_EQ(len, expectedLen);
    em_tlv_t* tlv = reinterpret_cast<em_tlv_t*>(buffer);
    EXPECT_EQ(tlv->type, em_tlv_type_device_info);
    EXPECT_EQ(ntohs(tlv->len), 0);
    std::cout << "Exiting add_tlv_valid_zero_value_length test" << std::endl;
}
/**
 * @brief Validate that add_tlv correctly handles a null length pointer.
 *
 * This test verifies that when a null pointer is passed as the length parameter to the add_tlv function,
 * the function returns a null pointer, thereby ensuring proper error handling for invalid input parameters.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 019@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke add_tlv with a null length pointer parameter. | buffer = [128 bytes of zeros], length pointer = nullptr, type = em_tlv_type_link_metric, value = [0x01, 0x02, 0x03], value length = 3 | Returns nullptr and ASSERT_EQ verifies the return value is nullptr. | Should Pass |
 */
TEST(em_msg_t, add_tlv_negative_null_len_pointer) {
    std::cout << "Entering add_tlv_negative_null_len_pointer test" << std::endl;
    em_msg_t msg;
    unsigned char buffer[128] = {0};
    unsigned char value[3] = {0x01, 0x02, 0x03};
    unsigned char* ret_ptr = em_msg_t::add_tlv(buffer, nullptr, em_tlv_type_link_metric, value, 3);
    ASSERT_EQ(ret_ptr, nullptr);
    std::cout << "Exiting add_tlv_negative_null_len_pointer test" << std::endl;
}
/**
 * @brief Test for verifying that add_tlv returns nullptr when provided a null buffer pointer
 *
 * This test verifies that the add_tlv API correctly handles a null buffer pointer. The test
 * initializes the necessary variables and attempts to invoke the add_tlv method with a null pointer 
 * for the buffer. It then checks whether the return value is nullptr, which is the expected behavior 
 * for this negative scenario.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 020@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                            | Test Data                                                                                                                      | Expected Result                               | Notes          |
 * | :--------------: | ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------- | -------------- |
 * | 01               | Invoke add_tlv with a null buffer pointer                              | input1 = buffer pointer = nullptr, input2 = pointer to len (30), input3 = em_tlv_type_operational_bss, input4 = value array {0x10,0x20,0x30,0x40,0x50}, input5 = value length = 5 | API returns nullptr                           | Should Fail    |
 * | 02               | Assert that the returned pointer is nullptr as expected from the API call | output1 = ret_ptr from add_tlv call = nullptr                                                                                  | ASSERT_EQ(ret_ptr, nullptr) passes the check  | Should be successful |
 */
TEST(em_msg_t, add_tlv_negative_null_buff_pointer) {
    std::cout << "Entering add_tlv_negative_null_buff_pointer test" << std::endl;
    em_msg_t msg;
    unsigned int initialLen = 30;
    unsigned int len = initialLen;
    unsigned char value[5] = { 0x10, 0x20, 0x30, 0x40, 0x50 };
    unsigned char* ret_ptr = em_msg_t::add_tlv(nullptr, &len, em_tlv_type_operational_bss, value, 5);
    ASSERT_EQ(ret_ptr, nullptr);
    std::cout << "Exiting add_tlv_negative_null_buff_pointer test" << std::endl;
}
/**
 * @brief Test that add_tlv returns nullptr when called with a null value pointer and a nonzero length.
 *
 * This test verifies that the add_tlv function in em_msg_t correctly handles an invalid input scenario where the TLV value pointer is null despite a nonzero length parameter. The function is expected to detect the invalid input and return a null pointer, ensuring robust error handling.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 021@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize test data with a valid buffer and set the initial length | buffer = array[128]={0}, initialLen = 75, len = 75 | Variables are initialized successfully | Should be successful |
 * | 02 | Invoke em_msg_t::add_tlv with a null TLV value pointer and nonzero TLV length | buffer = array[128]={0}, len pointer = address of len (75), type = em_tlv_type_wsc, value pointer = nullptr, TLV length = 4 | API returns nullptr and assertion passes | Should Fail |
 */
TEST(em_msg_t, add_tlv_negative_null_value_pointer_with_nonzero_length) {
    std::cout << "Entering add_tlv_negative_null_value_pointer_with_nonzero_length test" << std::endl;
    em_msg_t msg;
    unsigned char buffer[128] = {0};
    unsigned int initialLen = 75;
    unsigned int len = initialLen;
    unsigned char* ret_ptr = em_msg_t::add_tlv(buffer, &len, em_tlv_type_wsc, nullptr, 4);
    ASSERT_EQ(ret_ptr, nullptr);
    std::cout << "Exiting add_tlv_negative_null_value_pointer_with_nonzero_length test" << std::endl;
}
/**
 * @brief Verify that the agent_list API executes successfully for each available profile.
 *
 * This test iterates over all the profiles defined in the profiles array and creates an em_msg_t object for each profile with the message type em_msg_type_agent_list. It then calls the agent_list() method and asserts that no exceptions are thrown during its execution. The objective is to ensure that the agent_list functionality handles all variations of profiles correctly without any runtime errors.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 022@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                         | Test Data                                                                 | Expected Result                                                            | Notes       |
 * | :--------------: | ------------------------------------------------------------------- | ------------------------------------------------------------------------- | -------------------------------------------------------------------------- | ----------- |
 * | 01               | Iterate over all profiles, create a message instance, and invoke the agent_list() method | msgType = em_msg_type_agent_list, profile = profiles[i], tlvBuffer = {0}, bufferLength = 10 | No exception should be thrown when calling msg.agent_list()               | Should Pass |
 */
TEST(em_msg_t, agent_list_profileVariation_loopAllProfiles)
{
    std::cout << "Entering agent_list_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_agent_list;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.agent_list());
    }
    std::cout << "Exiting agent_list_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Validate the anticipated_channel_pref functionality for all profile variations.
 *
 * This test iterates over the available profiles and verifies that the anticipated_channel_pref() method executes without throwing an exception.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 023
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Iterate through each profile in the profiles array and call the anticipated_channel_pref() API for each. | profile = profiles[i] (from profiles array), msgType = em_msg_type_anticipated_channel_pref, tlvBuffer = {0,0,0,0,0,0,0,0,0,0}, bufferLength = 10 | anticipated_channel_pref() does not throw any exception for each profile | Should Pass |
 */
TEST(em_msg_t, anticipated_channel_pref_profileVariation_loopAllProfiles)
{
    std::cout << "Entering anticipated_channel_pref_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_anticipated_channel_pref;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.anticipated_channel_pref());
    }
    std::cout << "Exiting anticipated_channel_pref_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Test anticipated_channel_usage_rprt profile variation in a loop over all profiles
 *
 * This test iterates through all profile types in the profiles array. For each profile, it constructs an em_msg_t object with a given message type, a TLV buffer, and its length, then calls the anticipated_channel_usage_rprt() method. The objective is to ensure that the API does not throw any exceptions across different profile variations.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 024@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Loop over all profiles, create em_msg_t for each profile, and call anticipated_channel_usage_rprt() | profiles[i] = (each profile value), tlvBuffer = {0}, bufferLength = 10, msgType = em_msg_type_anticipated_channel_usage_rprt | No exception is thrown; EXPECT_NO_THROW assertion passes | Should Pass |
 */
TEST(em_msg_t, anticipated_channel_usage_rprt_profileVariation_loopAllProfiles)
{
    std::cout << "Entering anticipated_channel_usage_rprt_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_anticipated_channel_usage_rprt;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.anticipated_channel_usage_rprt());
    }
    std::cout << "Exiting anticipated_channel_usage_rprt_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Test the ap_cap_query function with all profile variations
 *
 * This test iterates over all available profiles and creates a message with the ap_cap_query type for each profile. It then calls the ap_cap_query method and asserts that no exceptions are thrown, ensuring that the API handles all valid profiles correctly.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 025
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Loop over all profiles and create a message for each profile, then invoke ap_cap_query | profiles[i] = each valid profile, tlvBuffer = {0,0,0,0,0,0,0,0,0,0}, bufferLength = 10, msgType = em_msg_type_ap_cap_query | ap_cap_query executes without throwing an exception | Should Pass |
 */
TEST(em_msg_t, ap_cap_query_profileVariation_loopAllProfiles)
{
    std::cout << "Entering ap_cap_query_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_ap_cap_query;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.ap_cap_query());
    }
    std::cout << "Exiting ap_cap_query_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Validate that the ap_cap_rprt API does not throw an exception for all profile variations.
 *
 * This test iterates through all available profiles. For each profile, it creates an em_msg_t object with a fixed 
 * TLV buffer and length, and a message type of em_msg_type_ap_cap_rprt. The API ap_cap_rprt() is then invoked.
 * The test asserts that no exception is thrown during each API invocation.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 026@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize test variables, including a TLV buffer of 10 bytes and a buffer length of 10. | tlvBuffer = {0,0,0,0,0,0,0,0,0,0}, bufferLength = 10 | Variables initialized successfully. | Should be successful |
 * | 02 | Loop through each profile from the profiles array, create a message, and invoke the ap_cap_rprt API. | For each iteration: profile = profiles[i], msgType = em_msg_type_ap_cap_rprt, tlvBuffer = {0,0,0,0,0,0,0,0,0,0}, bufferLength = 10 | API call completes without throwing an exception. | Should Pass |
 */
TEST(em_msg_t, ap_cap_rprt_profileVariation_loopAllProfiles)
{
    std::cout << "Entering ap_cap_rprt_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_ap_cap_rprt;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.ap_cap_rprt());
    }
    std::cout << "Exiting ap_cap_rprt_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Validate that the ap_metrics_query method does not throw exceptions for all valid profiles
 *
 * This test iterates through each profile in the profiles array, constructs an em_msg_t object with the 
 * appropriate parameters, and invokes the ap_metrics_query() method. The objective is to ensure that the API 
 * successfully processes every profile variation without throwing exceptions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 027@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                            | Test Data                                                                                                                       | Expected Result                                       | Notes      |
 * | :--------------: | ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- | ---------- |
 * | 01               | Iterate through all valid profiles, create an em_msg_t object, and call ap_metrics_query() | profile = profiles[i] (varies), msgType = em_msg_type_ap_metrics_query, tlvBuffer = [0,0,0,0,0,0,0,0,0,0], bufferLength = 10 | No exceptions thrown from ap_metrics_query()          | Should Pass |
 */
TEST(em_msg_t, ap_metrics_query_profileVariation_loopAllProfiles)
{
    std::cout << "Entering ap_metrics_query_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_ap_metrics_query;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.ap_metrics_query());
    }
    std::cout << "Exiting ap_metrics_query_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Validate ap_metrics_rsp execution for all profile variations
 *
 * This test iterates over all available profiles, creates a message using each profile
 * along with a predefined TLV buffer and buffer length, and then invokes the ap_metrics_rsp
 * method. The test ensures that no exceptions are thrown during the execution of the method
 * for any profile, thereby confirming proper handling of all supported profile variations.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 028@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                 | Test Data                                                                                                                 | Expected Result            | Notes      |
 * | :--------------: | --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | -------------------------- | ---------- |
 * | 01               | Loop through each profile, create a message, and call ap_metrics_rsp()      | tlvBuffer = [0,0,0,0,0,0,0,0,0,0], bufferLength = 10, profile = each element from profiles, msgType = em_msg_type_ap_metrics_rsp | No exception thrown from ap_metrics_rsp() | Should Pass |
 */
TEST(em_msg_t, ap_metrics_rsp_profileVariation_loopAllProfiles)
{
    std::cout << "Entering ap_metrics_rsp_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_ap_metrics_rsp;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.ap_metrics_rsp());
    }
    std::cout << "Exiting ap_metrics_rsp_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Verify that ap_mld_config_req processes each profile variation without throwing exceptions
 *
 * This test iterates over all valid profile variations defined in the profiles array and verifies that each call to
 * ap_mld_config_req using a valid set of configuration parameters completes without throwing an exception.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 029@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Iterate through each valid profile and invoke ap_mld_config_req with corresponding configuration parameters | msgType = em_msg_type_ap_mld_config_req, profile = each valid profile from profiles, tlvBuffer = [0,0,0,0,0,0,0,0,0,0], bufferLength = 10 | The API call should execute without throwing an exception | Should Pass |
 */
TEST(em_msg_t, ap_mld_config_req_profileVariation_loopAllProfiles)
{
    std::cout << "Entering ap_mld_config_req_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_ap_mld_config_req;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.ap_mld_config_req());
    }
    std::cout << "Exiting ap_mld_config_req_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Validates that the ap_mld_config_rsp() API function processes all profile variations without throwing exceptions.
 *
 * This test iterates over the profiles array. For each profile, it creates a message (em_msg_t) with a fixed TLV buffer and buffer length, then invokes the ap_mld_config_rsp() function. The test ensures that the function call does not throw any exceptions, thereby confirming correct behavior for each profile input.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 030@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Loop through all profiles, create a message instance, and invoke ap_mld_config_rsp() | profile = each value from profiles array, msgType = em_msg_type_ap_mld_config_resp, tlvBuffer = 0,0,0,0,0,0,0,0,0,0, bufferLength = 10 | The API call ap_mld_config_rsp() should execute without throwing an exception | Should Pass |
 */
TEST(em_msg_t, ap_mld_config_rsp_profileVariation_loopAllProfiles)
{
    std::cout << "Entering ap_mld_config_rsp_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_ap_mld_config_resp;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.ap_mld_config_rsp());
    }
    std::cout << "Exiting ap_mld_config_rsp_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Validates assoc_status_notif API for all profile variations in a loop
 *
 * This test iterates over the profiles array and invokes the assoc_status_notif API for each profile.
 * It ensures that no exceptions are thrown during the execution of the API, thereby verifying its stability across different input variations.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 031@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize test parameters: allocate tlvBuffer and set bufferLength | tlvBuffer = 0,0,0,0,0,0,0,0,0,0; bufferLength = 10 | Buffer variables set without error | Should be successful |
 * | 02 | Loop through all profiles and create msg object for each, then call assoc_status_notif | profile = current profile from profiles array, msgType = em_msg_type_assoc_status_notif, tlvBuffer = allocated buffer, bufferLength = 10 | EXPECT_NO_THROW; assoc_status_notif executes without throwing exceptions | Should Pass |
 * | 03 | Log test entry and exit messages to the console | Console output: "Entering assoc_status_notif_profileVariation_loopAllProfiles test", "Exiting assoc_status_notif_profileVariation_loopAllProfiles test" | Console displays the log messages correctly | Should be successful |
 */
TEST(em_msg_t, assoc_status_notif_profileVariation_loopAllProfiles)
{
    std::cout << "Entering assoc_status_notif_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_assoc_status_notif;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.assoc_status_notif());
    }
    std::cout << "Exiting assoc_status_notif_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Verify that autoconfig_renew function executes successfully for all profiles
 *
 * This test iterates over all profiles available in the profiles array, constructs an em_msg_t instance for each profile with a TLV buffer of fixed size, and calls the autoconfig_renew method. The test ensures that no exceptions are thrown during execution for any of the profiles.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 032@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:** 
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Iterate over each profile, instantiate em_msg_t with msgType = em_msg_type_autoconf_renew, tlvBuffer = [0,0,0,0,0,0,0,0,0,0] and bufferLength = 10, then call autoconfig_renew | input: profile from profiles array, msgType = em_msg_type_autoconf_renew, tlvBuffer = 0,0,0,0,0,0,0,0,0,0, bufferLength = 10; output: No output parameter | The function call should not throw any exception (EXPECT_NO_THROW passes) | Should Pass |
 */
TEST(em_msg_t, autoconfig_renew_profileVariation_loopAllProfiles)
{
    std::cout << "Entering autoconfig_renew_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_autoconf_renew;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.autoconfig_renew());
    }
    std::cout << "Exiting autoconfig_renew_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Verify that the autoconfig_resp() API executes correctly across all profile types.
 *
 * This test iterates over every profile variant stored in the profiles array. For each profile, it creates an em_msg_t instance with the autoconf response message type and invokes autoconfig_resp(), ensuring that no exceptions are thrown. This verifies that the API is robust and correctly handles every profile configuration.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 033
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Loop through each profile variant from the profiles array, construct an em_msg_t object, and invoke autoconfig_resp() | profile = each value in profiles array, tlvBuffer = {0,0,0,0,0,0,0,0,0,0}, bufferLength = 10, msgType = em_msg_type_autoconf_resp | autoconfig_resp() should execute without throwing an exception | Should Pass |
 */
TEST(em_msg_t, autoconfig_resp_profileVariation_loopAllProfiles)
{
    std::cout << "Entering autoconfig_resp_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_autoconf_resp;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.autoconfig_resp());
    }
    std::cout << "Exiting autoconfig_resp_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Verify that the autoconfig_search function executes without throwing exceptions for all profiles.
 *
 * This test validates the robustness of the autoconfig_search method by iterating through each profile available in the profiles array. For each profile, an em_msg_t object is constructed using a predefined message type, a buffer, and its length. The test then calls autoconfig_search() and ensures that no exception is thrown, confirming that the function can handle various profile variations reliably.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 034@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Iterate through each profile in the profiles array and invoke autoconfig_search() | profile = each element of profiles, msgType = em_msg_type_autoconf_search, tlvBuffer = {0,0,0,0,0,0,0,0,0,0}, bufferLength = 10, output: None | No exception thrown; EXPECT_NO_THROW assertion passes | Should Pass |
 */
TEST(em_msg_t, autoconfig_search_profileVariation_loopAllProfiles)
{
    std::cout << "Entering autoconfig_search_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_autoconf_search;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.autoconfig_search());
    }
    std::cout << "Exiting autoconfig_search_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Validate autoconfig_wsc_m1 API functionality across all profile variations.
 *
 * This test iterates through all available profile types, constructing a message object for each profile using the autoconf_wsc message type, and verifies that invoking the autoconfig_wsc_m1 method does not throw any exceptions. This ensures that the API correctly handles various profiles without error.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 035@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Iterate over each profile, create a message instance, and call autoconfig_wsc_m1. | profile = profiles[i], msgType = em_msg_type_autoconf_wsc, tlvBuffer = buffer of 100 zeros, bufferLength = 100 | The autoconfig_wsc_m1 method is executed without throwing any exceptions; EXPECT_NO_THROW passes | Should Pass |
 */
TEST(em_msg_t, autoconfig_wsc_m1_profileVariation_loopAllProfiles)
{
    std::cout << "Entering autoconfig_wsc_m1_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[100] = {0};
    unsigned int bufferLength = 100;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_autoconf_wsc;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.autoconfig_wsc_m1());
    }
    std::cout << "Exiting autoconfig_wsc_m1_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Verify that autoconfig_wsc_m2 method functions correctly across all profile types
 *
 * This test iterates over the profiles array and invokes the autoconfig_wsc_m2 method on each em_msg_t object.
 * It ensures that for every valid profile, the method execution does not throw any exceptions, validating the robustness of the API.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 036
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Iterate through each profile in the profiles array and call the autoconfig_wsc_m2 method on the em_msg_t object | profile = current profile (varies), tlvBuffer = array of 100 zeros, bufferLength = 100, msgType = em_msg_type_autoconf_wsc | No exception is thrown when calling autoconfig_wsc_m2 | Should Pass |
 */
TEST(em_msg_t, autoconfig_wsc_m2_profileVariation_loopAllProfiles)
{
    std::cout << "Entering autoconfig_wsc_m2_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[100] = {0};
    unsigned int bufferLength = 100;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_autoconf_wsc;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.autoconfig_wsc_m2());
    }
    std::cout << "Exiting autoconfig_wsc_m2_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Validate beacon_metrics_query for each profile without throwing exceptions
 *
 * This test iterates through all available profiles to ensure that the beacon_metrics_query API is invoked properly without throwing any exceptions. It checks the correct instantiation of the message object and validates the behavior across all supported profile types.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 037
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize test variables including tlvBuffer and bufferLength. | tlvBuffer = {0,0,0,0,0,0,0,0,0,0}, bufferLength = 10 | Variables are initialized correctly. | Should be successful |
 * | 02 | Loop over each profile in the profiles array. | profiles array elements, index i | Each profile is iterated over. | Should be successful |
 * | 03 | For each profile, create an em_msg_t instance and invoke beacon_metrics_query. | profile = profiles[i], msgType = em_msg_type_beacon_metrics_query, tlvBuffer, bufferLength | beacon_metrics_query executes without throwing an exception. | Should Pass |
 * | 04 | Log the start and end of the test execution. | Console output: "Entering beacon_metrics_query_profileVariation_loopAllProfiles test", "Exiting beacon_metrics_query_profileVariation_loopAllProfiles test" | Test messages are printed to the console successfully. | Should be successful |
 */
TEST(em_msg_t, beacon_metrics_query_profileVariation_loopAllProfiles)
{
    std::cout << "Entering beacon_metrics_query_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_beacon_metrics_query;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.beacon_metrics_query());
    }
    std::cout << "Exiting beacon_metrics_query_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Verify that the beacon_metrics_rsp function operates correctly for all profiles.
 *
 * This test iterates through a predefined array of profiles and, for each one, creates a beacon metrics response message. It then calls the beacon_metrics_rsp API/function to ensure that no exception is thrown. This test validates that the API handles all valid profile variations without error.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 038
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                          | Test Data                                                                                                         | Expected Result                                                             | Notes      |
 * | :--------------: | -------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- | ---------- |
 * | 01               | Loop through all available profiles and invoke beacon_metrics_rsp API. | profile = profiles[i], tlvBuffer = {0,0,0,0,0,0,0,0,0,0}, bufferLength = 10, msgType = em_msg_type_beacon_metrics_rsp | EXPECT_NO_THROW passes: function call should not throw any exception.       | Should Pass|
 */
TEST(em_msg_t, beacon_metrics_rsp_profileVariation_loopAllProfiles)
{
    std::cout << "Entering beacon_metrics_rsp_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_beacon_metrics_rsp;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.beacon_metrics_rsp());
    }
    std::cout << "Exiting beacon_metrics_rsp_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Verifies that bh_sta_cap_query does not throw any exceptions for all supported profiles.
 *
 * This test iterates through an array of supported profiles and for each profile, constructs an em_msg_t object with predefined parameters. It then calls the bh_sta_cap_query method to ensure that the API correctly processes all profile types without throwing exceptions.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 039
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                        | Test Data                                                                                 | Expected Result                           | Notes       |
 * | :--------------: | ------------------------------------------------------------------ | ----------------------------------------------------------------------------------------- | ----------------------------------------- | ----------- |
 * | 01               | Loop through each profile, construct em_msg_t, and call bh_sta_cap_query | msgType = em_msg_type_bh_sta_cap_query, profile = current profile, tlvBuffer = array[10] (all 0s), bufferLength = 10 | API call should not throw any exceptions   | Should Pass |
 */
TEST(em_msg_t, bh_sta_cap_query_profileVariation_loopAllProfiles)
{
    std::cout << "Entering bh_sta_cap_query_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_bh_sta_cap_query;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.bh_sta_cap_query());
    }
    std::cout << "Exiting bh_sta_cap_query_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Test the bh_steering_req API function for all supported profiles.
 *
 * This test iterates over all predefined profiles from the 'profiles' array and creates a message object for each profile using the provided buffer and message type. It then calls the bh_steering_req() method to verify that no exception is thrown for any profile variation.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 040@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                  | Test Data                                                                                                        | Expected Result                                             | Notes       |
 * | :--------------: | ------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- | ----------- |
 * | 01               | Iterate over all profiles, create the message object and invoke bh_steering_req() for each profile. | input: profile = profiles[i] (each element from array), input: tlvBuffer = {0,0,0,0,0,0,0,0,0,0}, input: bufferLength = 10, input: msgType = em_msg_type_bh_steering_req, output: none  | The API function bh_steering_req() should execute without throwing any exceptions. | Should Pass |
 */
TEST(em_msg_t, bh_steering_req_profileVariation_loopAllProfiles)
{
    std::cout << "Entering bh_steering_req_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_bh_steering_req;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.bh_steering_req());
    }
    std::cout << "Exiting bh_steering_req_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Tests the bh_steering_rsp API for all profile variations.
 *
 * This test iterates over all profiles available in the profiles array, creates an instance of em_msg_t 
 * with each profile along with a valid message type and a buffer, and then invokes the bh_steering_rsp method.
 * The objective is to confirm that the method executes without throwing any exceptions for every profile.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 041@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Iterate through each profile in the profiles array and create a message object with the respective profile, message type, buffer, and buffer length | profiles[i] = (each valid profile), msgType = em_msg_type_bh_steering_rsp, tlvBuffer = {0}, bufferLength = 10 | Message object is created without error | Should be successful |
 * | 02 | Invoke the bh_steering_rsp API on the created message instance and ensure no exception is thrown | Input: em_msg_t msg with corresponding profile and buffer parameters | bh_steering_rsp executes without throwing an exception | Should Pass |
 */
TEST(em_msg_t, bh_steering_rsp_profileVariation_loopAllProfiles)
{
    std::cout << "Entering bh_steering_rsp_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_bh_steering_rsp;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.bh_steering_rsp());
    }
    std::cout << "Exiting bh_steering_rsp_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Validate that the bss_config_req API call does not throw exceptions for all profile variations.
 *
 * This test iterates through the available profiles and constructs an em_msg_t object for each profile. It then calls the bss_config_req API and verifies that no exception is thrown. This ensures that the method behaves as expected across all supported profiles.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 042@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                     | Test Data                                                                                           | Expected Result                                           | Notes       |
 * | :--------------: | ----------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- | --------------------------------------------------------- | ----------- |
 * | 01               | Iterate over each profile in the profiles array, invoke the bss_config_req and check for exceptions | profile = each value in profiles, tlvBuffer = {0,0,0,0,0,0,0,0,0,0}, bufferLength = 10, msgType = em_msg_type_bss_config_req | API call completes without throwing exceptions (EXPECT_NO_THROW) | Should Pass |
 */
TEST(em_msg_t, bss_config_req_profileVariation_loopAllProfiles)
{
    std::cout << "Entering bss_config_req_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_bss_config_req;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.bss_config_req());
    }
    std::cout << "Exiting bss_config_req_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Verify that the bss_config_res() API call does not throw exceptions for all profile variations
 *
 * This test verifies that the bss_config_res() method of the em_msg_t class processes all available profile types without throwing any exceptions. It iterates through each profile in the predefined profiles array to ensure that every variation behaves correctly.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 043
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize TLV buffer and buffer length, and obtain the profiles array | tlvBuffer = {0,0,0,0,0,0,0,0,0,0}, bufferLength = 10, profiles = global profiles array | Variables are initialized correctly | Should be successful |
 * | 02 | For each profile, create an em_msg_t instance and invoke bss_config_res() to ensure no exception is thrown | profile = profiles[i], msgType = em_msg_type_bss_config_res, tlvBuffer = {0,0,0,0,0,0,0,0,0,0}, bufferLength = 10 | bss_config_res() does not throw an exception; EXPECT_NO_THROW passes | Should Pass |
 */
TEST(em_msg_t, bss_config_res_profileVariation_loopAllProfiles)
{
    std::cout << "Entering bss_config_res_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_bss_config_res;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.bss_config_res());
    }
    std::cout << "Exiting bss_config_res_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Test to validate the bss_config_rsp() method for each available profile
 *
 * This test iterates over all available profiles defined in the 'profiles' array, constructs an em_msg_t object using a given tlvBuffer, bufferLength, and the current profile. It then calls the bss_config_rsp() method to verify that no exception is thrown for any profile value. This is essential to ensure all profiles are handled correctly without errors.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 044@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                           | Test Data                                                                                                       | Expected Result                                                          | Notes       |
 * | :--------------: | --------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ | ----------- |
 * | 01               | Loop through all available profiles, create em_msg_t instance and invoke bss_config_rsp() | tlvBuffer = {0}, bufferLength = 10, profile = current profile from profiles, msgType = em_msg_type_bss_config_rsp | bss_config_rsp() should be invoked without throwing any exception | Should Pass |
 */
TEST(em_msg_t, bss_config_rsp_profileVariation_loopAllProfiles)
{
    std::cout << "Entering bss_config_rsp_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_bss_config_rsp;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.bss_config_rsp());
    }
    std::cout << "Exiting bss_config_rsp_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Verify that the cac_req() API does not throw exceptions for all supported profiles
 *
 * This test iterates over each available profile in the 'profiles' array and constructs an em_msg_t object with the
 * specified parameters. It then calls cac_req() on the message object, ensuring that no exceptions are thrown during
 * the call. This validates that the API performs correctly for all profile types provided.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 045
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                           | Test Data                                                                                          | Expected Result                                                    | Notes       |
 * | :--------------: | ------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ | ----------- |
 * | 01               | Iterate over each profile, create an em_msg_t object with tlvBuffer and invoke cac_req() | input: profile = profiles[i], msgType = em_msg_type_cac_req, tlvBuffer = {0,...}, bufferLength = 10 | cac_req() executes without throwing an exception; EXPECT_NO_THROW passes  | Should Pass |
 */
TEST(em_msg_t, cac_req_profileVariation_loopAllProfiles)
{
    std::cout << "Entering cac_req_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_cac_req;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.cac_req());
    }
    std::cout << "Exiting cac_req_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Verify that the cac_term API does not throw exceptions for each valid profile.
 *
 * This test iterates over all available profiles in the profiles array and constructs a message using each profile. It subsequently calls the cac_term() method on the constructed message, ensuring that no exceptions are thrown during the execution. This validates the robustness of the API when handling various valid profile configurations.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 046@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                     | Test Data                                                                                                                       | Expected Result                                                          | Notes      |
 * | :--------------: | ----------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ | ---------- |
 * | 01               | Loop through each profile in the profiles array, create an em_msg_t object and invoke cac_term() | profile = profiles[i] (each element), msgType = em_msg_type_cac_term, tlvBuffer = [0,0,0,0,0,0,0,0,0,0], bufferLength = 10 | No exception is thrown; EXPECT_NO_THROW check passes                      | Should Pass |
 */
TEST(em_msg_t, cac_term_profileVariation_loopAllProfiles)
{
    std::cout << "Entering cac_term_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_cac_term;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.cac_term());
    }
    std::cout << "Exiting cac_term_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Validate that channel_pref_query() executes without exceptions for all profile variations.
 *
 * This test iterates over all available profiles, creates an em_msg_t instance for each profile, and invokes the channel_pref_query() API method. The validation ensures that the method call does not throw exceptions for any valid profile input.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 047@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize test variables including the TLV buffer and its length. | tlvBuffer = [0,0,0,0,0,0,0,0,0,0], bufferLength = 10 | Variables are correctly initialized. | Should be successful |
 * | 02 | Iterate through each profile, create an em_msg_t object, and invoke channel_pref_query(). | For each iteration: profile = profiles[i], msgType = em_msg_type_channel_pref_query, tlvBuffer = [0,0,0,0,0,0,0,0,0,0], bufferLength = 10, output: none (no exception) | API call returns without throwing exceptions. | Should Pass |
 */
TEST(em_msg_t, channel_pref_query_profileVariation_loopAllProfiles)
{
    std::cout << "Entering channel_pref_query_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_channel_pref_query;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.channel_pref_query());
    }
    std::cout << "Exiting channel_pref_query_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Validates that channel_pref_rprt() works correctly for all profiles.
 *
 * This test iterates over all available profile types and creates an em_msg_t object with each profile.
 * It then calls the channel_pref_rprt() method to verify that no exception is thrown during the operation.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 048@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:** 
 * | Variation / Step | Description                                                                 | Test Data                                                                                                       | Expected Result                                                                 | Notes       |
 * | :--------------: | --------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- | ----------- |
 * | 01               | Loop over all profiles and invoke channel_pref_rprt() for each valid profile. | profile = each value from profiles array, msgType = em_msg_type_channel_pref_rprt, tlvBuffer = {0,0,0,0,0,0,0,0,0,0}, bufferLength = 10 | The channel_pref_rprt() API should not throw any exceptions and complete normally. | Should Pass |
 */
TEST(em_msg_t, channel_pref_rprt_profileVariation_loopAllProfiles)
{
    std::cout << "Entering channel_pref_rprt_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_channel_pref_rprt;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.channel_pref_rprt());
    }
    std::cout << "Exiting channel_pref_rprt_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Validate that channel_scan_req processes all provided profile configurations without throwing exceptions.
 *
 * This test iterates over all valid em_profile_type_t profiles and creates an em_msg_t object for each profile using the
 * channel_scan request message type. It then calls the channel_scan_req method for each object to ensure that the method
 * executes as expected without raising any exceptions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 049@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                            | Test Data                                                                                  | Expected Result                                                      | Notes      |
 * | :--------------: | ------------------------------------------------------ | ------------------------------------------------------------------------------------------ | -------------------------------------------------------------------- | ---------- |
 * | 01               | Loop through each profile and invoke channel_scan_req()| msgType = em_msg_type_channel_scan_req, profile = profiles[i], tlvBuffer = {0,0,0,0,0,0,0,0,0,0}, bufferLength = 10 | The channel_scan_req() function should execute without throwing an exception. | Should Pass|
 */
TEST(em_msg_t, channel_scan_req_profileVariation_loopAllProfiles)
{
    std::cout << "Entering channel_scan_req_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_channel_scan_req;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.channel_scan_req());
    }
    std::cout << "Exiting channel_scan_req_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Verifies that channel_scan_rprt API does not throw exceptions for each valid profile variation.
 *
 * This test iterates through each profile in the profiles array, creates a message instance using the 
 * channel_scan_rprt message type, and calls the channel_scan_rprt() function. It ensures that the API 
 * invocation does not throw an exception, thereby validating the expected positive behavior under normal conditions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 050@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- | -------------- | ----- |
 * | 01 | Initialize test buffer and parameters. | tlvBuffer = {0,0,0,0,0,0,0,0,0,0}, bufferLength = 10 | Buffer is correctly initialized with the given length. | Should be successful |
 * | 02 | Loop through all profiles, create message and invoke channel_scan_rprt API. | msgType = em_msg_type_channel_scan_rprt, profile = each profile from profiles array, tlvBuffer = {0,...,0}, bufferLength = 10 | API call does not throw exception (EXPECT_NO_THROW assertion passes). | Should Pass |
 */
TEST(em_msg_t, channel_scan_rprt_profileVariation_loopAllProfiles)
{
    std::cout << "Entering channel_scan_rprt_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_channel_scan_rprt;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.channel_scan_rprt());
    }
    std::cout << "Exiting channel_scan_rprt_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Test channel_sel_req API across all profile variations
 *
 * This test verifies that the channel_sel_req method on the message object executes without throwing an exception for each profile in the profiles array. It ensures that the API can handle every valid profile in a consistent and stable manner.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 051@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Loop through all profiles, create a message with a preset TLV buffer and message type, then invoke channel_sel_req for each profile | profile = each value from profiles array, msgType = em_msg_type_channel_sel_req, tlvBuffer = [0,0,0,0,0,0,0,0,0,0], bufferLength = 10 | The channel_sel_req method should execute without throwing any exceptions | Should Pass |
 */
TEST(em_msg_t, channel_sel_req_profileVariation_loopAllProfiles)
{
    std::cout << "Entering channel_sel_req_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_channel_sel_req;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.channel_sel_req());
    }
    std::cout << "Exiting channel_sel_req_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Tests the channel_sel_rsp method for all profile variations
 *
 * Verifies that for each valid profile in the predefined list, the em_msg_t::channel_sel_rsp method is executed without throwing exceptions, ensuring robust handling of profile-specific message responses.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 052
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                   | Test Data                                                                                                             | Expected Result                                         | Notes               |
 * | :--------------: | --------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- | ------------------- |
 * | 01               | Initialize test environment by setting up the TLV buffer and buffer length                      | tlvBuffer = {0,0,0,0,0,0,0,0,0,0}, bufferLength = 10                                                                  | Environment initialized successfully                     | Should be successful |
 * | 02               | Loop through each profile, create em_msg_t object and invoke channel_sel_rsp method             | For each iteration: profile = profiles[i], msgType = em_msg_type_channel_sel_rsp, tlvBuffer = {0,...,0} (10 zeros), bufferLength = 10  | channel_sel_rsp does not throw any exception             | Should Pass         |
 * | 03               | Log the exit message of the test execution                                                    | std::cout prints "Exiting channel_sel_rsp_profileVariation_loopAllProfiles test"                                      | Exit message is printed as expected                      | Should be successful |
 */
TEST(em_msg_t, channel_sel_rsp_profileVariation_loopAllProfiles)
{
    std::cout << "Entering channel_sel_rsp_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_channel_sel_rsp;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.channel_sel_rsp());
    }
    std::cout << "Exiting channel_sel_rsp_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Test chirp notification for all profile variations without exceptions
 *
 * This test iterates over all defined profiles in the profiles array. For each profile, a message object is created with the profile, message type set to em_msg_type_chirp_notif, a tlvBuffer of 10 zero-initialized bytes, and bufferLength set to 10. The test calls chirp_notif() on each message object and asserts that no exception is thrown, ensuring the API functions correctly across all profile variations.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 053
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Iterate over all profiles and invoke chirp_notif() method on the message object for each profile | profile = each value from profiles, msgType = em_msg_type_chirp_notif, tlvBuffer = 0,0,0,0,0,0,0,0,0,0, bufferLength = 10 | Function call returns without throwing an exception; EXPECT_NO_THROW assertion passes | Should Pass |
 */
TEST(em_msg_t, chirp_notif_profileVariation_loopAllProfiles)
{
    std::cout << "Entering chirp_notif_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_chirp_notif;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.chirp_notif());
    }
    std::cout << "Exiting chirp_notif_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Verify that client_assoc_ctrl_req processes all profiles without exceptions.
 *
 * This test iterates over each profile in the profiles array, constructs an em_msg_t object with the given parameters, and calls client_assoc_ctrl_req() to ensure that no exceptions are thrown. This confirms that the API handles different profile variations correctly.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 054
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Iterate over each profile; construct the message and invoke client_assoc_ctrl_req() | profiles[i] = current profile, msgType = em_msg_type_client_assoc_ctrl_req, tlvBuffer = {0,0,0,0,0,0,0,0,0,0}, bufferLength = 10 | No exception is thrown; EXPECT_NO_THROW passes | Should Pass |
 */
TEST(em_msg_t, client_assoc_ctrl_req_profileVariation_loopAllProfiles)
{
    std::cout << "Entering client_assoc_ctrl_req_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_client_assoc_ctrl_req;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.client_assoc_ctrl_req());
    }
    std::cout << "Exiting client_assoc_ctrl_req_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Test the client_cap_query API call for each available profile.
 *
 * This test iterates through all supported profiles stored in the profiles array and verifies that the client_cap_query API call does not throw an exception for each profile configuration.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 055@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                    | Test Data                                                                                          | Expected Result                                          | Notes      |
 * | :--------------: | ------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------- | -------------------------------------------------------- | ---------- |
 * | 01               | Invoke client_cap_query for each profile in the profiles array and verify that no exception is thrown. | profile = profiles[i] (varies for each iteration), msgType = em_msg_type_client_cap_query, tlvBuffer = unsigned char array of size 10, bufferLength = 10 | The client_cap_query API should be executed with no exceptions thrown. | Should Pass |
 */
TEST(em_msg_t, client_cap_query_profileVariation_loopAllProfiles)
{
    std::cout << "Entering client_cap_query_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_client_cap_query;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.client_cap_query());
    }
    std::cout << "Exiting client_cap_query_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Validate the client_cap_rprt functionality with all profile variations
 *
 * This test verifies that the client_cap_rprt method does not throw any exceptions
 * for any profile in the profiles array. It creates an instance of em_msg_t for each profile
 * with a predefined tlvBuffer and bufferLength, and then invokes the client_cap_rprt method.
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 056@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                                 | Test Data                                                                                                       | Expected Result                     | Notes      |
 * | :--------------: | ----------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | ----------------------------------- | ---------- |
 * | 01               | Iterate through each profile in the profiles array, create an em_msg_t object with a predefined message type, buffer, and buffer length, then invoke client_cap_rprt         | msgType = em_msg_type_client_cap_rprt, profile = current profile value, tlvBuffer = [0,0,0,0,0,0,0,0,0,0], bufferLength = 10 | No exception should be thrown       | Should Pass |
 */
TEST(em_msg_t, client_cap_rprt_profileVariation_loopAllProfiles)
{
    std::cout << "Entering client_cap_rprt_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_client_cap_rprt;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.client_cap_rprt());
    }
    std::cout << "Exiting client_cap_rprt_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Test to validate that client_disassoc_stats executes without throwing exceptions for each profile.
 *
 * This test iterates through all available profiles, constructs an em_msg_t object for each using a predefined buffer and message type,
 * and calls the client_disassoc_stats method. The objective is to ensure that the function works correctly for every valid profile without exceptions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 057@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01 | Iterate through all profiles, construct em_msg_t for each profile, and invoke client_disassoc_stats | input: tlvBuffer = {0,0,0,0,0,0,0,0,0,0}, bufferLength = 10, profile = profiles[i], msgType = em_msg_type_client_disassoc_stats | The client_disassoc_stats method should execute without throwing an exception | Should Pass |
 */
TEST(em_msg_t, client_disassoc_stats_profileVariation_loopAllProfiles)
{
    std::cout << "Entering client_disassoc_stats_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_client_disassoc_stats;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.client_disassoc_stats());
    }
    std::cout << "Exiting client_disassoc_stats_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Validate that client_steering_btm_rprt performs as expected for all profiles
 *
 * This test iterates through each profile in the profiles array. For each profile, it constructs an
 * em_msg_t object with the message type set to em_msg_type_client_steering_btm_rprt and a predefined
 * TLV buffer, then verifies that calling client_steering_btm_rprt does not throw an exception.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 058@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                         | Test Data                                                                                                          | Expected Result                                              | Notes      |
 * | :--------------: | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------ | ---------- |
 * | 01               | Iterate over each profile, create message, and invoke client_steering_btm_rprt | msgType = em_msg_type_client_steering_btm_rprt, profile = each profiles[i], tlvBuffer = array of 10 zeros, bufferLength = 10, output = none | The API call does not throw an exception; EXPECT_NO_THROW assertion passes | Should Pass |
 */
TEST(em_msg_t, client_steering_btm_rprt_profileVariation_loopAllProfiles)
{
    std::cout << "Entering client_steering_btm_rprt_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_client_steering_btm_rprt;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.client_steering_btm_rprt());
    }
    std::cout << "Exiting client_steering_btm_rprt_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Test the client_steering_req API for all supported profiles.
 *
 * This test iterates through all available profiles and creates a message with the client steering request type. It verifies that invoking client_steering_req() does not throw exceptions for any profile. This test ensures robustness of the API when handling profile variations.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 059
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- | -------------- | ----- |
 * | 01 | Initialize variables (tlvBuffer, bufferLength) and begin iterating over the profiles array. | tlvBuffer = [0,0,0,0,0,0,0,0,0,0], bufferLength = 10, profiles = defined array of em_profile_type_t values | Variables are correctly initialized and iteration starts over all profiles | Should be successful |
 * | 02 | For each profile, construct the message with msgType = em_msg_type_client_steering_req and invoke client_steering_req() API. | profile = current profiles[i], msgType = em_msg_type_client_steering_req, tlvBuffer, bufferLength | client_steering_req() is invoked without throwing any exceptions | Should Pass |
 */
TEST(em_msg_t, client_steering_req_profileVariation_loopAllProfiles)
{
    std::cout << "Entering client_steering_req_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_client_steering_req;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.client_steering_req());
    }
    std::cout << "Exiting client_steering_req_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Validate that the combined_infra_metrics API call handles all profile variations without throwing exceptions
 *
 * This test iterates through all available profile types present in the profiles array. For each profile, it creates an em_msg_t object with a predefined TLV buffer and buffer length, then calls combined_infra_metrics() to ensure that no exceptions are thrown. This confirms that the API can process all profiles robustly.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 060
 * **Priority:** High
 * 
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Loop through each profile, create an em_msg_t instance, and invoke combined_infra_metrics() | profile = profiles[i] (iterates per element), tlvBuffer = array of 10 unsigned char (all zero), bufferLength = 10, msgType = em_msg_type_combined_infra_metrics | No exception is thrown from combined_infra_metrics() | Should Pass |
 */
TEST(em_msg_t, combined_infra_metrics_profileVariation_loopAllProfiles)
{
    std::cout << "Entering combined_infra_metrics_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_combined_infra_metrics;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.combined_infra_metrics());
    }
    std::cout << "Exiting combined_infra_metrics_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Validate the direct_encap_dpp functionality for all profile variations.
 *
 * This test iterates through all available profiles and invokes the direct_encap_dpp() method
 * for each one to ensure that no exceptions are thrown when using valid input parameters.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 061
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                                   | Test Data                                                                                                                                                      | Expected Result                                                    | Notes       |
 * | :--------------: | ------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ | ----------- |
 * | 01               | Initialize the buffer, iterate over all profile values, create the message object, and invoke direct_encap_dpp() | input: tlvBuffer = {0,0,0,0,0,0,0,0,0,0}, bufferLength = 10, profile = profiles[i], msgType = em_msg_type_direct_encap_dpp, output: msg instance created | The API call direct_encap_dpp() does not throw any exceptions         | Should Pass |
 */
TEST(em_msg_t, direct_encap_dpp_profileVariation_loopAllProfiles)
{
    std::cout << "Entering direct_encap_dpp_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_direct_encap_dpp;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.direct_encap_dpp());
    }
    std::cout << "Exiting direct_encap_dpp_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Validates that dpp_bootstrap_uri_notif does not throw exceptions for all valid profile variations.
 *
 * This test iterates over all available profiles and invokes the dpp_bootstrap_uri_notif method of the em_msg_t object.
 * The objective is to ensure that for each valid profile, the API call completes successfully without throwing any exceptions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 062@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Loop through each profile in the profiles array and call the dpp_bootstrap_uri_notif API. | input: profile = each element in profiles, msgType = em_msg_type_dpp_bootstrap_uri_notif, tlvBuffer = {0,0,0,0,0,0,0,0,0,0}, bufferLength = 10; output: none | API call should not throw any exception. | Should Pass |
 */
TEST(em_msg_t, dpp_bootstrap_uri_notif_profileVariation_loopAllProfiles)
{
    std::cout << "Entering dpp_bootstrap_uri_notif_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_dpp_bootstrap_uri_notif;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.dpp_bootstrap_uri_notif());
    }
    std::cout << "Exiting dpp_bootstrap_uri_notif_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Verifies that invoking dpp_cce_ind on em_msg_t object does not throw for any valid profile
 *
 * This test iterates over all valid profiles in the profiles array and creates an em_msg_t object using
 * each profile along with a predefined tlvBuffer and bufferLength. It then calls the dpp_cce_ind method,
 * ensuring that no exception is thrown, which validates that the API handles all profile variations correctly@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 063@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Loop over profiles array and create em_msg_t object for each profile to test the dpp_cce_ind API | profiles[i] = <profile_value>, msgType = em_msg_type_dpp_cce_ind, tlvBuffer = {0,0,0,0,0,0,0,0,0,0}, bufferLength = 10, em_msg_t object creation | dpp_cce_ind() method should execute without throwing an exception (EXPECT_NO_THROW passes) | Should Pass |
 */
TEST(em_msg_t, dpp_cce_ind_profileVariation_loopAllProfiles)
{
    std::cout << "Entering dpp_cce_ind_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_dpp_cce_ind;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.dpp_cce_ind());
    }
    std::cout << "Exiting dpp_cce_ind_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Test the default constructor of em_msg_t to ensure that the instance is created without throwing exceptions.
 *
 * This test verifies that invoking the default constructor of the em_msg_t class does not throw any exceptions, ensuring basic object initialization works as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 064@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create an instance of em_msg_t using the default constructor and verify no exception is thrown. | constructor: default, no parameters | No exception is thrown and the instance is created successfully | Should Pass |
 */
TEST(em_msg_t, em_msg_t_default_constructor) {
    std::cout << "Entering em_msg_t_default_constructor test" << std::endl;
    EXPECT_NO_THROW({
        std::cout << "Creating em_msg_t instance." << std::endl;
        em_msg_t instance;
        std::cout << "Instance creation completed successfully" << &instance << std::endl;
    });
    std::cout << "Exiting em_msg_t_default_constructor test" << std::endl;
}
/**
 * @brief Validate that the default constructor of em_msg_t creates distinct valid instances.
 *
 * This test constructs two separate instances of em_msg_t using the default constructor.
 * It verifies that the two instances are distinct by comparing their memory addresses.
 * The objective is to ensure that each instantiation creates a unique object instance.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 065@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                                            | Test Data                                                                          | Expected Result                                                   | Notes      |
 * | :--------------: | ---------------------------------------------------------------------- | ---------------------------------------------------------------------------------- | ----------------------------------------------------------------- | ---------- |
 * | 01               | Invoke default constructor to create the first instance of em_msg_t     | input: none, output: instance1 created                                             | instance1 is successfully created                                 | Should Pass|
 * | 02               | Invoke default constructor to create the second instance of em_msg_t    | input: none, output: instance2 created                                             | instance2 is successfully created                                 | Should Pass|
 * | 03               | Validate that the addresses of instance1 and instance2 are distinct     | input: instance1 address, instance2 address; output: addresses comparison result     | The objects have different memory addresses; ASSERT_NE returns true | Should Pass|
 */
TEST(em_msg_t, em_msg_t_default_constructor_creates_valid_instances) {
    std::cout << "Entering em_msg_t_default_constructor_creates_valid_instances test" << std::endl;
    std::cout << "Invoking default constructor for first instance" << std::endl;
    em_msg_t instance1;
    std::cout << "Invoking default constructor for second instance" << std::endl;
    em_msg_t instance2;
    EXPECT_NE(&instance1, &instance2);
    std::cout << "Exiting em_msg_t_default_constructor_creates_valid_instances test" << std::endl;
}
/**
 * @brief Verify that the em_msg_t constructor does not throw an exception when provided with valid TLVs data
 *
 * This test verifies the proper initialization of the em_msg_t object by providing a valid TLVs data array. 
 * The test ensures that no exceptions are thrown during object creation with the specified TLVs data and length.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 066@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                                          | Test Data                                                                                                              | Expected Result                                                  | Notes      |
 * | :--------------: | -------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- | ---------- |
 * | 01               | Allocate a TLVs array of length 10, initialize it with sequential values, and invoke the em_msg_t constructor to ensure no exception is thrown. | input1 = em_msg_type_topo_disc, input2 = em_profile_type_1, input3 = tlvs array [0,1,2,3,4,5,6,7,8,9], input4 = len = 10, output = em_msg_t object created | The em_msg_t constructor should complete without throwing any exceptions. | Should Pass |
 */
TEST(em_msg_t, em_msg_t_ValidTLVsData)
{
    std::cout << "Entering em_msg_t_ValidTLVsData test" << std::endl;
    unsigned int len = 10;
    unsigned char* tlvs = new unsigned char[len];
    for (unsigned int i = 0; i < len; i++) {
        tlvs[i] = static_cast<unsigned char>(i);
    }
    EXPECT_NO_THROW({
        em_msg_t obj(em_msg_type_topo_disc, em_profile_type_1, tlvs, len);
    });
    delete[] tlvs;
    std::cout << "Exiting em_msg_t_ValidTLVsData test" << std::endl;
}
/**
 * @brief Verify that creating an em_msg_t object with null TLVs and zero length does not throw any exception
 *
 * This test creates an instance of em_msg_t using a null pointer for the TLVs and a length of zero. It aims to validate that the constructor handles this edge case without throwing an exception, ensuring robustness when dealing with potentially absent data.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 067@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                      | Test Data                                                                                                          | Expected Result                                                         | Notes         |
 * | :--------------: | ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------- | ------------- |
 * | 01               | Invoke em_msg_t constructor with null TLVs and zero length       | em_msg_type = em_msg_type_ap_cap_query, profile_type = em_profile_type_reserved, TLVs = nullptr, len = 0         | No exception is thrown; object is created successfully                  | Should Pass   |
 */
TEST(em_msg_t, em_msg_t_EdgeNullTLVsZeroLength)
{
    std::cout << "Entering em_msg_t_EdgeNullTLVsZeroLength test" << std::endl;
    unsigned int len = 0;
    EXPECT_NO_THROW({
        em_msg_t obj(em_msg_type_ap_cap_query, em_profile_type_reserved, nullptr, len);
    });
    std::cout << "Exiting em_msg_t_EdgeNullTLVsZeroLength test" << std::endl;
}
/**
 * @brief Validate the construction of em_msg_t objects for all supported message types.
 *
 * This test iterates over a list of various message types and invokes the em_msg_t constructor for each, ensuring that the object is instantiated without throwing any exceptions. This verifies the robustness of the em_msg_t initialization process using a predefined TLV buffer.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 068@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Iterate over a vector of all supported message types and invoke the em_msg_t constructor for each type. | input: msgTypes = em_msg_type_topo_disc, em_msg_type_topo_notif, em_msg_type_topo_query, em_msg_type_topo_resp, em_msg_type_topo_vendor, em_msg_type_link_metric_query, em_msg_type_link_metric_resp, em_msg_type_autoconf_search, em_msg_type_autoconf_resp, em_msg_type_autoconf_wsc, em_msg_type_autoconf_renew, em_msg_type_1905_ack, em_msg_type_ap_cap_query, em_msg_type_ap_cap_rprt, em_msg_type_map_policy_config_req, em_msg_type_channel_pref_query, em_msg_type_channel_pref_rprt, em_msg_type_channel_sel_req, em_msg_type_channel_sel_rsp, em_msg_type_op_channel_rprt, em_msg_type_client_cap_query, em_msg_type_client_cap_rprt, em_msg_type_ap_metrics_query, em_msg_type_ap_metrics_rsp, em_msg_type_assoc_sta_link_metrics_query, em_msg_type_assoc_sta_link_metrics_rsp, em_msg_type_unassoc_sta_link_metrics_query, em_msg_type_unassoc_sta_link_metrics_rsp, em_msg_type_beacon_metrics_query, em_msg_type_beacon_metrics_rsp, em_msg_type_combined_infra_metrics, em_msg_type_client_steering_req, em_msg_type_client_steering_btm_rprt, em_msg_type_client_assoc_ctrl_req, em_msg_type_steering_complete, em_msg_type_higher_layer_data, em_msg_type_bh_steering_req, em_msg_type_bh_steering_rsp, em_msg_type_channel_scan_req, em_msg_type_channel_scan_rprt, em_msg_type_dpp_cce_ind, em_msg_type_1905_rekey_req, em_msg_type_1905_decrypt_fail, em_msg_type_cac_req, em_msg_type_cac_term, em_msg_type_client_disassoc_stats, em_msg_type_svc_prio_req, em_msg_type_err_rsp, em_msg_type_assoc_status_notif, em_msg_type_tunneled, em_msg_type_bh_sta_cap_query, em_msg_type_bh_sta_cap_rprt, em_msg_type_proxied_encap_dpp, em_msg_type_direct_encap_dpp, em_msg_type_reconfig_trigger, em_msg_type_bss_config_req, em_msg_type_bss_config_rsp, em_msg_type_bss_config_res, em_msg_type_chirp_notif, em_msg_type_1905_encap_eapol, em_msg_type_dpp_bootstrap_uri_notif, em_msg_type_anticipated_channel_pref, em_msg_type_failed_conn, em_msg_type_agent_list, em_msg_type_anticipated_channel_usage_rprt, em_msg_type_qos_mgmt_notif, em_msg_type_ap_mld_config_req, em_msg_type_ap_mld_config_resp; profile = em_profile_type_1; tlvs = pointer to an unsigned char array of size 100 bytes (first two bytes represent htons(em_tlv_type_eom)). | The em_msg_t constructor completes without throwing any exception. | Should Pass |
 */
TEST(em_msg_t, em_msg_t_LoopAllMsgTypes)
{
    std::cout << "Entering em_msg_t_LoopAllMsgTypes test" << std::endl;
    std::vector<em_msg_type_t> msgTypes = {
         em_msg_type_topo_disc,
         em_msg_type_topo_notif,
         em_msg_type_topo_query,
         em_msg_type_topo_resp,
         em_msg_type_topo_vendor,
         em_msg_type_link_metric_query,
         em_msg_type_link_metric_resp,
         em_msg_type_autoconf_search,
         em_msg_type_autoconf_resp,
         em_msg_type_autoconf_wsc,
         em_msg_type_autoconf_renew,
         em_msg_type_1905_ack,
         em_msg_type_ap_cap_query,
         em_msg_type_ap_cap_rprt,
         em_msg_type_map_policy_config_req,
         em_msg_type_channel_pref_query,
         em_msg_type_channel_pref_rprt,
         em_msg_type_channel_sel_req,
         em_msg_type_channel_sel_rsp,
         em_msg_type_op_channel_rprt,
         em_msg_type_client_cap_query,
         em_msg_type_client_cap_rprt,
         em_msg_type_ap_metrics_query,
         em_msg_type_ap_metrics_rsp,
         em_msg_type_assoc_sta_link_metrics_query,
         em_msg_type_assoc_sta_link_metrics_rsp,
         em_msg_type_unassoc_sta_link_metrics_query,
         em_msg_type_unassoc_sta_link_metrics_rsp,
         em_msg_type_beacon_metrics_query,
         em_msg_type_beacon_metrics_rsp,
         em_msg_type_combined_infra_metrics,
         em_msg_type_client_steering_req,
         em_msg_type_client_steering_btm_rprt,
         em_msg_type_client_assoc_ctrl_req,
         em_msg_type_steering_complete,
         em_msg_type_higher_layer_data,
         em_msg_type_bh_steering_req,
         em_msg_type_bh_steering_rsp,
         em_msg_type_channel_scan_req,
         em_msg_type_channel_scan_rprt,
         em_msg_type_dpp_cce_ind,
         em_msg_type_1905_rekey_req,
         em_msg_type_1905_decrypt_fail,
         em_msg_type_cac_req,
         em_msg_type_cac_term,
         em_msg_type_client_disassoc_stats,
         em_msg_type_svc_prio_req,
         em_msg_type_err_rsp,
         em_msg_type_assoc_status_notif,
         em_msg_type_tunneled,
         em_msg_type_bh_sta_cap_query,
         em_msg_type_bh_sta_cap_rprt,
         em_msg_type_proxied_encap_dpp,
         em_msg_type_direct_encap_dpp,
         em_msg_type_reconfig_trigger,
         em_msg_type_bss_config_req,
         em_msg_type_bss_config_rsp,
         em_msg_type_bss_config_res,
         em_msg_type_chirp_notif,
         em_msg_type_1905_encap_eapol,
         em_msg_type_dpp_bootstrap_uri_notif,
         em_msg_type_anticipated_channel_pref,
         em_msg_type_failed_conn,
         em_msg_type_agent_list,
         em_msg_type_anticipated_channel_usage_rprt,
         em_msg_type_qos_mgmt_notif,
         em_msg_type_ap_mld_config_req,
         em_msg_type_ap_mld_config_resp,
    };
    unsigned int len = 100;
    unsigned char* tlvs = new unsigned char[len];
    memset(tlvs, 0, len);
    reinterpret_cast<uint16_t*>(tlvs)[0] = htons(em_tlv_type_eom);
    for (auto type : msgTypes) {
        EXPECT_NO_THROW({
            em_msg_t obj(type, em_profile_type_1, tlvs, len);
        });
    }
    delete[] tlvs;
    std::cout << "Exiting em_msg_t_LoopAllMsgTypes test" << std::endl;
}
/**
 * @brief Test the construction of em_msg_t objects for all profile types without exceptions
 *
 * This test allocates a TLVs array, populates it with incremental values, and iterates through a set of profiles.
 * For each profile, it invokes the em_msg_t constructor with a specific message type, profile, TLVs data, and length.
 * The test verifies that the object is instantiated without throwing an exception.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 069@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Allocate memory for TLVs and populate with values | len = 10, tlvs: allocated array with values [10,11,12,13,14,15,16,17,18,19] | Memory allocated and array populated correctly | Should be successful |
 * | 02 | Iterate over each profile; instantiate em_msg_t with parameters and verify no exception is thrown | Input: em_msg_type_link_metric_query, profile (from profiles), tlvs pointer, len = 10; Output: em_msg_t object | Object is created without throwing exceptions | Should Pass |
 * | 03 | Clean up allocated memory after test completion | Input: delete[] tlvs | Memory is successfully deallocated with no issues | Should be successful |
 */
TEST(em_msg_t, em_msg_t_LoopAllProfileTypes)
{
    std::cout << "Entering em_msg_t_LoopAllProfileTypes test" << std::endl;
    unsigned int len = 10;
    unsigned char* tlvs = new unsigned char[len];
    for (unsigned int i = 0; i < len; i++) {
        tlvs[i] = static_cast<unsigned char>(i + 10);
    }
    for (auto profile : profiles) {
        EXPECT_NO_THROW({
	    em_msg_t obj(em_msg_type_link_metric_query, profile, tlvs, len);
        });
    }
    delete[] tlvs;
    std::cout << "Exiting em_msg_t_LoopAllProfileTypes test" << std::endl;
}
/**
 * @brief Verify that the em_msg_t constructor does not throw when provided with valid non-null data and a non-zero length.
 *
 * This test checks that the em_msg_t constructor properly initializes an object using a valid TLV data array and a length greater than zero, and that it does not throw any exceptions. It ensures the API correctly handles typical valid input.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 070
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                          | Test Data                                    | Expected Result                                | Notes       |
 * | :--------------: | -------------------------------------------------------------------- | -------------------------------------------- | ---------------------------------------------- | ----------- |
 * | 01               | Invoke the constructor of em_msg_t with a valid non-null, non-zero length data array. | tlvData = { 0x01, 0x02, 0x03 }, len = 3       | Constructor completes without throwing any exceptions. | Should Pass |
 */
TEST(em_msg_t, em_msg_t_validNonNullNonZeroLength) {
    std::cout << "Entering em_msg_t_validNonNullNonZeroLength test" << std::endl;
    unsigned char tlvData[3] = { 0x01, 0x02, 0x03 };
    unsigned int len = 3;
    EXPECT_NO_THROW({
        em_msg_t obj(tlvData, len);
    });
    std::cout << "Exiting em_msg_t_validNonNullNonZeroLength test" << std::endl;
}
/**
 * @brief Test that em_msg_t properly handles a valid large TLV buffer without throwing exceptions.
 *
 * This test verifies that when a large TLV buffer of 1000 bytes, filled with cyclic sequential data (0-255),
 * is provided to the em_msg_t constructor, no exceptions are thrown. This ensures that the constructor can handle
 * large inputs and correctly processes the TLV buffer data.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 071@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                  | Test Data                                                              | Expected Result                            | Notes       |
 * | :--------------: | -------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- | ------------------------------------------- | ----------- |
 * | 01               | Create a 1000-byte TLV buffer, initialize each byte with (i % 256), and pass it to the constructor | len = 1000, largeTLV[0..999] with values (0, 1, 2, ..., 255 repeating), input to em_msg_t constructor | em_msg_t constructor does not throw any exception | Should Pass |
 */
TEST(em_msg_t, em_msg_t_validLargeTLVBuffer) {
    std::cout << "Entering em_msg_t_validLargeTLVBuffer test" << std::endl;
    const unsigned int len = 1000;
    unsigned char* largeTLV = new unsigned char[len];
    for (unsigned int i = 0; i < len; i++) {
        largeTLV[i] = static_cast<unsigned char>(i % 256);
    }
    EXPECT_NO_THROW({
        em_msg_t obj(largeTLV, len);
    });
    delete[] largeTLV;
    std::cout << "Exiting em_msg_t_validLargeTLVBuffer test" << std::endl;
}
/**
 * @brief Test for validating err_rsp() function across all profile variations.
 *
 * This test iterates over each profile in the profiles array and constructs an em_msg_t object with error response message type. It then verifies that calling the err_rsp() method does not throw an exception, ensuring proper error response handling for each profile.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 072
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                 | Test Data                                                                               | Expected Result                                               | Notes       |
 * | :----------------: | ----------------------------------------------------------- | --------------------------------------------------------------------------------------- | ------------------------------------------------------------- | ----------- |
 * | 01                 | Loop through each profile, create a message, and call err_rsp() | tlvBuffer = [0,0,0,0,0,0,0,0,0,0], bufferLength = 10, profile = current element from profiles, msgType = em_msg_type_err_rsp | err_rsp() executes without throwing an exception             | Should Pass |
 */
TEST(em_msg_t, err_rsp_profileVariation_loopAllProfiles)
{
    std::cout << "Entering err_rsp_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_err_rsp;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.err_rsp());
    }
    std::cout << "Exiting err_rsp_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Validate that the failed_conn() API call does not throw an exception for all supported profiles.
 *
 * This test iterates through all predefined profiles, creates an em_msg_t object with the message type set to em_msg_type_failed_conn, and calls the failed_conn() method. The objective is to verify that the API function handles each profile without throwing any exceptions.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 073
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                             | Test Data                                                                                                                             | Expected Result                                                        | Notes      |
 * | :--------------: | ------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- | ---------- |
 * | 01               | Loop through all predefined profiles, create an instance of em_msg_t with msgType set to em_msg_type_failed_conn, and invoke the failed_conn() method | profile = each value from profiles array, msgType = em_msg_type_failed_conn, tlvBuffer = {0,0,0,0,0,0,0,0,0,0}, bufferLength = 10 | The failed_conn() method should be executed without throwing any exceptions | Should Pass |
 */
TEST(em_msg_t, failed_conn_profileVariation_loopAllProfiles)
{
    std::cout << "Entering failed_conn_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_failed_conn;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.failed_conn());
    }
    std::cout << "Exiting failed_conn_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Verify that the AL MAC address TLV is correctly extracted from the message buffer when present
 *
 * This test constructs a buffer containing a valid AL MAC address TLV and a dummy EOM TLV. It then creates an em_msg_t object
 * with the buffer and calls the get_al_mac_address method to retrieve the AL MAC address. The test verifies that the AL MAC address
 * is correctly extracted and matches the expected value, ensuring proper parsing of AL MAC TLV from the message.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 074@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01 | Construct a buffer with a valid AL MAC address TLV and a dummy EOM TLV, then update the offset accordingly | buffer = { TLV_header, expected_mac = 0xAA,0xBB,0xCC,0xDD,0xEE,0xFF, TLV_header for EOM, dummy = 0 }, offset = calculated total size | Buffer correctly contains the AL MAC TLV with the expected MAC address and a dummy EOM TLV | Should be successful |@n
 * | 02 | Create an em_msg_t object from the buffer and invoke get_al_mac_address, then validate the return value and MAC address | input: msg (constructed from buffer and offset), expected_mac = 0xAA,0xBB,0xCC,0xDD,0xEE,0xFF, output: mac array | API returns true and the extracted MAC address matches the expected MAC address | Should Pass |
 */
TEST(em_msg_t, get_al_mac_address_valid_al_mac_tlv_found)
{
    std::cout << "Entering get_al_mac_address_valid_al_mac_tlv_found test" << std::endl;
    unsigned char buffer[TLV_HEADER_SIZE + MAC_LEN + TLV_HEADER_SIZE] = {};
    size_t offset = 0;
    unsigned char expected_mac[MAC_LEN] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    write_tlv(buffer + offset, em_tlv_type_al_mac_address, expected_mac, MAC_LEN);
    offset += TLV_HEADER_SIZE + MAC_LEN;
    unsigned char dummy = 0;
    write_tlv(buffer + offset, em_tlv_type_eom, &dummy, 0);
    offset += TLV_HEADER_SIZE;
    em_msg_t msg(buffer, offset);
    unsigned char mac[MAC_LEN] = {0};
    bool result = msg.get_al_mac_address(mac);
    EXPECT_TRUE(result);
    EXPECT_EQ(0, memcmp(mac, expected_mac, MAC_LEN));
    std::cout << "Exiting get_al_mac_address_valid_al_mac_tlv_found test" << std::endl;
}
/**
 * @brief Test that get_al_mac_address correctly returns false when the AL MAC TLV is missing.
 *
 * This test verifies that the get_al_mac_address method correctly handles the scenario where the AL MAC TLV is not present in the message buffer.
 * The function should not update the MAC address output and must return false.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 075@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                 | Test Data                                                                                                                  | Expected Result                                        | Notes          |
 * | :--------------: | --------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ | -------------- |
 * | 01               | Prepare the test buffer with a device info TLV containing a non-AL MAC and an EOM TLV, excluding the AL MAC TLV. | buffer = {device_info TLV: other_mac = 0x11,0x22,0x33,0x44,0x55,0x66; EOM TLV: dummy = 0}                                  | Buffer is set up with proper TLVs                      | Should be successful |
 * | 02               | Create the message instance and invoke get_al_mac_address with mac initialized to {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}. | input1 (mac) = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}; output1 (return) expected from API                                          | Return value is false                                  | Should Fail    |
 * | 03               | Validate that the mac buffer remains unchanged after API call.              | output1 (mac) = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}                                                                              | memcmp returns 0 indicating no change                  | Should be successful |
 */
TEST(em_msg_t, get_al_mac_address_al_mac_tlv_not_present)
{
    std::cout << "Entering get_al_mac_address_al_mac_tlv_not_present test" << std::endl;
    unsigned char buffer[TLV_HEADER_SIZE + MAC_LEN + TLV_HEADER_SIZE] = {};
    size_t offset = 0;
    unsigned char other_mac[MAC_LEN] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    write_tlv(buffer + offset, em_tlv_type_device_info, other_mac, MAC_LEN);
    offset += TLV_HEADER_SIZE + MAC_LEN;
    unsigned char dummy = 0;
    write_tlv(buffer + offset, em_tlv_type_eom, &dummy, 0);
    offset += TLV_HEADER_SIZE;
    em_msg_t msg(buffer, offset);
    unsigned char mac[MAC_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    bool result = msg.get_al_mac_address(mac);
    EXPECT_FALSE(result);
    unsigned char expected[MAC_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    EXPECT_EQ(0, memcmp(mac, expected, MAC_LEN));
    std::cout << "Exiting get_al_mac_address_al_mac_tlv_not_present test" << std::endl;
}
/**
 * @brief Validate get_al_mac_address behavior with an empty TLV payload.
 *
 * This test verifies that when the message buffer contains only an End-of-Message TLV header (i.e., an empty payload),
 * the get_al_mac_address API should return false and leave the MAC address buffer unmodified.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 076@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize an empty TLV buffer, write an End-of-Message TLV header, construct a message, and invoke get_al_mac_address with a predefined MAC address. | buffer: unsigned char array of size TLV_HEADER_SIZE (initialized to 0), offset: 0 increased by TLV_HEADER_SIZE after write_tlv, dummy: 0, mac: {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF} | API returns false and the mac buffer remains unchanged (equal to {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF}) | Should Pass |
 */
TEST(em_msg_t, get_al_mac_address_empty_buffer)
{
    std::cout << "Entering get_al_mac_address_empty_buffer test" << std::endl;
    unsigned char buffer[TLV_HEADER_SIZE] = {};
    size_t offset = 0;
    unsigned char dummy = 0;
    write_tlv(buffer + offset, em_tlv_type_eom, &dummy, 0);
    offset += TLV_HEADER_SIZE;
    em_msg_t msg(buffer, offset);
    unsigned char mac[MAC_LEN] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    bool result = msg.get_al_mac_address(mac);
    EXPECT_FALSE(result);
    unsigned char expected[MAC_LEN] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    EXPECT_EQ(0, memcmp(mac, expected, MAC_LEN));
    std::cout << "Exiting get_al_mac_address_empty_buffer test" << std::endl;
}
/**
 * @brief Validate retrieval of AL MAC address from multiple TLVs in a message
 *
 * This test verifies that the function get_al_mac_address correctly parses a message
 * containing multiple TLVs and correctly extracts the AL MAC address when present.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 077@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Setup TLVs in the buffer; add device info TLV, AL MAC address TLV, and EOM TLV. | buffer: TLV_HEADER_SIZE+3 + TLV_HEADER_SIZE+MAC_LEN + TLV_HEADER_SIZE, device info payload = {0x11, 0x22, 0x33}, AL MAC payload = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF}, EOM payload = dummy 0 | Buffer populated with correctly encoded TLVs in sequence. | Should be successful |
 * | 02 | Instantiate em_msg_t with the buffer containing the TLVs. | input buffer and computed offset. | em_msg_t object is constructed without error. | Should be successful |
 * | 03 | Call get_al_mac_address API with an initialized output buffer. | input: output array mac (initially zeros); expected_mac = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF} | API returns true and output MAC matches expected_mac. | Should Pass |
 */
TEST(em_msg_t, get_al_mac_address_multiple_tlvs)
{
    std::cout << "Entering get_al_mac_address_multiple_tlvs test" << std::endl;
    unsigned char buffer[TLV_HEADER_SIZE + 3 + TLV_HEADER_SIZE + MAC_LEN + TLV_HEADER_SIZE] = {};
    size_t offset = 0;
    unsigned char other_payload[3] = {0x11, 0x22, 0x33};
    write_tlv(buffer + offset, em_tlv_type_device_info, other_payload, sizeof(other_payload));
    offset += TLV_HEADER_SIZE + sizeof(other_payload);
    unsigned char expected_mac[MAC_LEN] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    write_tlv(buffer + offset, em_tlv_type_al_mac_address, expected_mac, MAC_LEN);
    offset += TLV_HEADER_SIZE + MAC_LEN;
    unsigned char dummy = 0;
    write_tlv(buffer + offset, em_tlv_type_eom, &dummy, 0);
    offset += TLV_HEADER_SIZE;
    em_msg_t msg(buffer, offset);
    unsigned char mac[MAC_LEN] = {0};
    bool result = msg.get_al_mac_address(mac);
    EXPECT_TRUE(result);
    EXPECT_EQ(0, memcmp(mac, expected_mac, MAC_LEN));
    std::cout << "Exiting get_al_mac_address_multiple_tlvs test" << std::endl;
}
/**
 * @brief Verify that get_bss_id returns true and populates the MAC address correctly from valid client info
 *
 * This test validates that when the em_msg_t object is constructed with a TLV buffer containing valid client info (MAC address), the get_bss_id API successfully extracts the correct MAC address into the provided memory location. It ensures the function returns true and that each byte of the MAC address matches the expected value.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 078@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create a TLV buffer containing valid client info and invoke get_bss_id on the em_msg_t object | input: tlv_buf (constructed using em_tlv_type_client_info and mac_bytes = 0xAA,0xBB,0xCC,0xDD,0xEE,0xFF), output: mac (initially zeros) | API returns true; the mac array contains 0xAA,0xBB,0xCC,0xDD,0xEE,0xFF exactly | Should Pass |
 */
TEST(em_msg_t, get_bss_id_valid_client_info_offset0) {
    std::cout << "Entering get_bss_id_valid_client_info_offset0 test" << std::endl;
    unsigned char mac_bytes[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    unsigned char tlv_buf[3 + 6];
    write_tlv(tlv_buf, em_tlv_type_client_info, mac_bytes, 6);
    em_msg_t message(tlv_buf, sizeof(tlv_buf));
    unsigned char mac[6] = {0};
    bool result = message.get_bss_id(reinterpret_cast<mac_address_t*>(mac));
    EXPECT_TRUE(result);
    for (int i = 0; i < 6; i++) {
        EXPECT_EQ(mac[i], mac_bytes[i]);
    }
    std::cout << "Exiting get_bss_id_valid_client_info_offset0 test" << std::endl;
}
/**
 * @brief Tests get_bss_id function with valid client association event offset6
 *
 * This test verifies that the get_bss_id API correctly extracts the BSS ID from a TLV buffer 
 * where the MAC address is placed at an offset of 6 bytes within the value portion. The test 
 * ensures that the function returns true and that the extracted MAC address matches the expected value.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 079@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                       | Test Data                                                                                                                               | Expected Result                                                                                                  | Notes             |
 * | :--------------: | ----------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | ----------------- |
 * | 01               | Setup TLV buffer with a MAC address at an offset of 6 bytes         | mac_bytes = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66}, value buffer of 12 bytes with MAC placed starting at offset 6, tlv_buf created with TLV_HEADER_SIZE + 12 | TLV buffer is correctly populated with the MAC at the specified offset                                             | Should be successful |
 * | 02               | Call get_bss_id and validate the extracted MAC address              | Input: message (constructed using tlv_buf), Output: mac array of size 6; Expected MAC = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66}                           | Function returns true and the extracted MAC address matches the expected MAC address                               | Should Pass       |
 */
TEST(em_msg_t, get_bss_id_valid_client_assoc_event_offset6) {
    std::cout << "Entering get_bss_id_valid_client_assoc_event_offset6 test" << std::endl;
    unsigned char mac_bytes[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    unsigned char value[12] = {0};
    memcpy(value + 6, mac_bytes, 6);  // put MAC at offset 6
    unsigned char tlv_buf[TLV_HEADER_SIZE + 12];    // header + value
    write_tlv(tlv_buf, em_tlv_type_client_assoc_event, value, 12);
    em_msg_t message(tlv_buf, sizeof(tlv_buf));
    unsigned char mac[6] = {0};
    bool result = message.get_bss_id(reinterpret_cast<mac_address_t*>(mac));
    EXPECT_TRUE(result);
    for (int i = 0; i < 6; i++) {
        EXPECT_EQ(mac[i], mac_bytes[i]);
    }
    std::cout << "Exiting get_bss_id_valid_client_assoc_event_offset6 test" << std::endl;
}
/**
 * @brief Verify that get_bss_id correctly parses and returns the BSS ID from the AP metrics TLV buffer.
 *
 * This test verifies that when the TLV buffer is initialized with a known MAC address, the get_bss_id
 * function returns true and correctly updates the provided MAC address buffer with the expected values.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 080@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                       | Test Data                                                                                                  | Expected Result                                   | Notes          |
 * | :--------------: | ----------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | ------------------------------------------------- | -------------- |
 * | 01               | Initialize TLV buffer with AP metrics including MAC address       | mac_bytes = 0xDE,0xAD,0xBE,0xEF,0x00,0x01, tlv_buf size = TLV_HEADER_SIZE + 6                                | Buffer written correctly by write_tlv API         | Should be successful |
 * | 02               | Create the message object from the TLV buffer                     | tlv_buf pointer, size = sizeof(tlv_buf)                                                                    | Message object instantiated successfully          | Should be successful |
 * | 03               | Retrieve BSS ID using get_bss_id API                              | message object, mac_address pointer = mac (initialized to zeros)                                             | get_bss_id returns true                             | Should Pass    |
 * | 04               | Validate the retrieved MAC address matches expected MAC           | mac (retrieved) vs mac_bytes (expected)                                                                      | All 6 bytes of MAC are identical                  | Should Pass    |
 */
TEST(em_msg_t, get_bss_id_valid_ap_metrics_offset0) {
    std::cout << "Entering get_bss_id_valid_ap_metrics_offset0 test" << std::endl;
    unsigned char mac_bytes[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
    unsigned char tlv_buf[TLV_HEADER_SIZE + 6];
    write_tlv(tlv_buf, em_tlv_type_ap_metrics, mac_bytes, 6);
    em_msg_t message(tlv_buf, sizeof(tlv_buf));
    unsigned char mac[6] = {0};
    bool result = message.get_bss_id(reinterpret_cast<mac_address_t*>(mac));
    EXPECT_TRUE(result);
    for (int i = 0; i < 6; i++) {
        EXPECT_EQ(mac[i], mac_bytes[i]);
    }
    std::cout << "Exiting get_bss_id_valid_ap_metrics_offset0 test" << std::endl;
}
/**
 * @brief Validate get_bss_id API behavior when no valid TLV is present
 *
 * This test verifies that the get_bss_id method of the em_msg_t class returns false and does not modify the MAC address when an invalid TLV type is provided in the data buffer.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 081@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                     | Test Data                                                                                                                                      | Expected Result                                                                          | Notes      |
 * | :--------------: | ----------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ---------- |
 * | 01               | Invoke get_bss_id with an invalid TLV buffer and verify that the MAC address remains unchanged   | tlv_buf = {0xFF, 0x06, 0x00, 0, 0, 0, 0, 0, 0}, mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}                                                    | API returns false; get_bss_id should not alter the original MAC address compared to the initial value | Should Pass |
 */
TEST(em_msg_t, get_bss_id_no_valid_tlv_found) {
    std::cout << "Entering get_bss_id_no_valid_tlv_found test" << std::endl;
    unsigned char tlv_buf[TLV_HEADER_SIZE + 6] = {0xFF, 0x06, 0x00, 0,0,0,0,0,0}; // invalid type
    em_msg_t message(tlv_buf, sizeof(tlv_buf));
    unsigned char mac[6] = {0x00,0x00,0x00,0x00,0x00,0x00};
    unsigned char original_mac[6]; 
    memcpy(original_mac, mac, 6);
    bool result = message.get_bss_id(reinterpret_cast<mac_address_t*>(mac));
    EXPECT_FALSE(result);
    for (int i = 0; i < 6; i++) 
        EXPECT_EQ(mac[i], original_mac[i]);
    std::cout << "Exiting get_bss_id_no_valid_tlv_found test" << std::endl;
}
/**
 * @brief Test for get_bss_id with a null MAC pointer.
 *
 * This test verifies that the get_bss_id API correctly handles a scenario where the MAC address pointer is null.
 * The test sets up TLV data with a valid MAC address, constructs an em_msg_t object with that data, and then calls
 * get_bss_id with a null pointer. The expected outcome is that the API returns false, demonstrating proper error handling.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 082
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Write TLV data into a buffer using pre-defined MAC address bytes | input: mac_bytes = 0xAB,0xCD,0xEF,0x12,0x34,0x56; output: tlv_buf containing TLV_HEADER_SIZE+6 bytes with TLV type em_tlv_type_client_info | TLV buffer is properly constructed with MAC address information | Should be successful |
 * | 02 | Construct an em_msg_t object using the TLV buffer | input: tlv_buf (size = TLV_HEADER_SIZE + 6) | em_msg_t object is created successfully | Should be successful |
 * | 03 | Call get_bss_id with a null MAC pointer | input: mac_ptr = nullptr | get_bss_id returns false, as expected for a null pointer | Should Pass |
 */
TEST(em_msg_t, get_bss_id_null_mac_pointer) {
    std::cout << "Entering get_bss_id_null_mac_pointer test" << std::endl;
    unsigned char mac_bytes[6] = {0xAB,0xCD,0xEF,0x12,0x34,0x56};
    unsigned char tlv_buf[TLV_HEADER_SIZE + 6];
    write_tlv(tlv_buf, em_tlv_type_client_info, mac_bytes, 6);
    em_msg_t message(tlv_buf, sizeof(tlv_buf));
    mac_address_t* mac_ptr = nullptr;
    bool result = message.get_bss_id(mac_ptr);
    EXPECT_FALSE(result);
    std::cout << "Exiting get_bss_id_null_mac_pointer test" << std::endl;
}
/**
 * @brief Tests that get_first_tlv returns nullptr when provided with a null buffer
 *
 * This test verifies that when the get_first_tlv function is invoked with a null buffer and a valid size,
 * it correctly handles the invalid input by returning a nullptr. This is important to ensure stable behavior
 * when encountering null pointer inputs.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 083@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                 | Test Data                                      | Expected Result                           | Notes       |
 * | :--------------: | ----------------------------------------------------------- | ---------------------------------------------- | ----------------------------------------- | ----------- |
 * | 01               | Invoke get_first_tlv with a null buffer and a size of 10      | input1 = nullptr, input2 = 10, output1 = nullptr| The function returns nullptr and the assertion passes  | Should Fail |
 */
TEST(em_msg_t, get_first_tlv_NullBufferInput) {
    std::cout << "Entering get_first_tlv_NullBufferInput test" << std::endl;
    em_tlv_t* tlv = em_msg_t::get_first_tlv(nullptr, 10);
    ASSERT_EQ(tlv, nullptr);
    std::cout << "Exiting get_first_tlv_NullBufferInput test" << std::endl;
}
/**
 * @brief Validate get_first_tlv returns nullptr when buffer length is zero
 *
 * This test verifies that the get_first_tlv API correctly handles the case when the provided buffer length is zero. The function is expected to not process any data and return a nullptr as a safeguard.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 084
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                  | Test Data                                                    | Expected Result                                              | Notes       |
 * | :--------------: | ----------------------------------------------------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ | ----------- |
 * | 01               | Call get_first_tlv with a buffer of TLV data but with buff_len set to 0 to ensure safe handling of an empty buffer | buffer = {0x01,0x00,0x01}, buff_len = 0, tlvs_buff pointer conversion to em_tlv_t* | get_first_tlv returns nullptr; ASSERT_EQ verifies the return value is nullptr | Should Pass |
 */
TEST(em_msg_t, get_first_tlv_ZeroBufferLength) {
    std::cout << "Entering get_first_tlv_ZeroBufferLength test" << std::endl;
    unsigned char buffer[3] = {0x01, 0x00, 0x01}; // type = 1, len = 1
    em_tlv_t* tlvs_buff = reinterpret_cast<em_tlv_t*>(buffer);
    em_tlv_t* tlv = em_msg_t::get_first_tlv(tlvs_buff, 0); // buff_len = 0
    ASSERT_EQ(tlv, nullptr);
    std::cout << "Exiting get_first_tlv_ZeroBufferLength test" << std::endl;
}
/**
 * @brief Verifies that get_first_tlv returns nullptr for a TLV with zero-length value.
 *
 * This test writes a TLV into a buffer using a zero-length value and then
 * calls get_first_tlv to ensure that it correctly handles the scenario by
 * returning a nullptr since the TLV is considered invalid.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 085
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                           | Test Data                                                            | Expected Result                                      | Notes           |
 * | :--------------: | --------------------------------------------------------------------- | -------------------------------------------------------------------- | ---------------------------------------------------- | --------------- |
 * | 01               | Initialize TLV buffer and dummy value, then write a TLV with zero-length value using write_tlv | buffer = initialized to zeros, type = em_tlv_type_client_info, dummy = 0, length = 0 | TLV written in buffer with the header but with no value content | Should be successful |
 * | 02               | Call get_first_tlv to retrieve the first TLV from the buffer          | input: tlvs_buff = reinterpret_cast<em_tlv_t*>(buffer), TLV_HEADER_SIZE | API returns nullptr as no valid TLV exists due to zero length | Should Pass     |
 * | 03               | Verify the returned TLV pointer is nullptr using an assertion           | assert_eq(tlv, nullptr)                                                | Assertion passes verifying that tlv is nullptr       | Should be successful |
 */
TEST(em_msg_t, get_first_tlv_ValidTLVZeroLengthValue) {
    std::cout << "Entering get_first_tlv_ValidTLVZeroLengthValue test" << std::endl;
    unsigned char buffer[TLV_HEADER_SIZE] = {};
    unsigned char dummy = 0;
    write_tlv(buffer, em_tlv_type_client_info, &dummy, 0);
    em_tlv_t* tlvs_buff = reinterpret_cast<em_tlv_t*>(buffer);
    em_tlv_t* tlv = em_msg_t::get_first_tlv(tlvs_buff, TLV_HEADER_SIZE);
    ASSERT_EQ(tlv, nullptr);
    std::cout << "Exiting get_first_tlv_ValidTLVZeroLengthValue test" << std::endl;
}
/**
 * @brief Validates that the get_first_tlv API correctly retrieves a TLV with a non-zero length value
 *
 * This test verifies that when a properly formatted TLV is written into a buffer using write_tlv,
 * the get_first_tlv function returns a valid TLV structure with the correct type, length, and value contents.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 086
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Log entering the test function | N/A | "Entering get_first_tlv_ValidTLVNonZeroLengthValue" is printed to stdout | Should be successful |
 * | 02 | Prepare TLV data by initializing a value array and a buffer, then writing the TLV using write_tlv | value = {0x11, 0x22, 0x33, 0x44}, buffer size = TLV_HEADER_SIZE + 4, type = em_tlv_type_receiver_link_metric | Buffer contains a correctly formatted TLV header and value | Should be successful |
 * | 03 | Invoke the get_first_tlv function on the buffer | buffer pointer cast to em_tlv_t*, buffer size as provided | get_first_tlv returns a non-null TLV pointer | Should Pass |
 * | 04 | Validate the TLV contents: type, length (converted using ntohs), and value bytes | tlv->type should equal em_tlv_type_receiver_link_metric, ntohs(tlv->len) should equal 4, value bytes compared with {0x11, 0x22, 0x33, 0x44} | TLV structure contains the expected type, length, and value data | Should Pass |
 * | 05 | Log exiting the test function | N/A | "Exiting get_first_tlv_ValidTLVNonZeroLengthValue test" is printed to stdout | Should be successful |
 */
TEST(em_msg_t, get_first_tlv_ValidTLVNonZeroLengthValue) {
    std::cout << "Entering get_first_tlv_ValidTLVNonZeroLengthValue test" << std::endl;

    unsigned char value[4] = {0x11, 0x22, 0x33, 0x44};
    unsigned char buffer[TLV_HEADER_SIZE + 4] = {};
    write_tlv(buffer, em_tlv_type_receiver_link_metric, value, sizeof(value));
    em_tlv_t* tlv = em_msg_t::get_first_tlv(reinterpret_cast<em_tlv_t*>(buffer), sizeof(buffer));
    ASSERT_NE(tlv, nullptr);
    EXPECT_EQ(tlv->type, em_tlv_type_receiver_link_metric);
    EXPECT_EQ(ntohs(tlv->len), 4);
    EXPECT_EQ(0, memcmp(reinterpret_cast<unsigned char*>(tlv) + TLV_HEADER_SIZE, value, sizeof(value)));
    std::cout << "Exiting get_first_tlv_ValidTLVNonZeroLengthValue test" << std::endl;
}
/**
 * @brief Test retrieval of the first TLV when the first TLV is an EOM TLV.
 *
 * This test verifies that when a message is constructed with an EOM TLV at the beginning,
 * invoking get_first_tlv returns a nullptr, indicating that there is no valid first TLV entry.
 * 
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 087@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- | -------------- | ----- |
 * | 01 | Print entry log, initialize TLV buffer and dummy value, and write EOM TLV to buffer | buffer = array of TLV_HEADER_SIZE bytes (initialized to 0), dummy = 0, TLV type = em_tlv_type_eom, length = 0 | Entry log printed; buffer contains an EOM TLV | Should be successful |
 * | 02 | Create an em_msg_t object using the buffer | input: buffer, sizeof(buffer) | em_msg_t object is successfully created | Should be successful |
 * | 03 | Invoke get_first_tlv on the message object with the buffer | input: ptr = reinterpret_cast<em_tlv_t*>(buffer), length = sizeof(buffer) | The function returns nullptr since the first TLV is an EOM TLV | Should Pass |
 * | 04 | Assert that the returned TLV pointer is nullptr | ASSERT_EQ(tlv, nullptr) | The assertion passes if tlv is nullptr | Should Pass |
 * | 05 | Print exit log | Log output "Exiting get_first_tlv_eom_first test" | Exit log printed | Should be successful |
 */
TEST(em_msg_t, get_first_tlv_eom_first) {
    std::cout << "Entering get_first_tlv_eom_first test" << std::endl;
    unsigned char buffer[TLV_HEADER_SIZE] = {};
    unsigned char dummy = 0;
    write_tlv(buffer, em_tlv_type_eom, &dummy, 0);
    em_msg_t msg(buffer, sizeof(buffer));
    em_tlv_t* tlv = msg.get_first_tlv(reinterpret_cast<em_tlv_t*>(buffer), sizeof(buffer));
    ASSERT_EQ(tlv, nullptr);
    std::cout << "Exiting get_first_tlv_eom_first test" << std::endl;
}
/**
 * @brief Verify that get_first_tlv correctly retrieves a TLV from the buffer for various TLV types
 *
 * This test iterates over all valid TLV types, creates a TLV entry using write_tlv with a single byte value,
 * and then retrieves the first TLV element using get_first_tlv. The test asserts that the returned TLV is not null,
 * the TLV's type matches the expected type, the length is correctly set to 1 (after network-to-host conversion),
 * and the TLV data matches the inserted value.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 088@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Loop through TLV types from 1 to TLV_TYPE_COUNT-1, create TLV with write_tlv and retrieve using get_first_tlv | input: type = types[i] (for i from 1 to TLV_TYPE_COUNT-1), value = static_cast<unsigned char>(i), buffer = array of size (TLV_HEADER_SIZE+1) initialized to 0; output: tlv pointer from get_first_tlv | Function returns a non-null TLV pointer with tlv->type equal to types[i], tlv->len (after ntohs) equal to 1, and the TLV data equal to value | Should Pass |
 */
TEST(em_msg_t, get_first_tlv_LoopAllEnumTypes) {
    std::cout << "Entering get_first_tlv_LoopAllEnumTypes test" << std::endl;
    for (size_t i = 1; i < TLV_TYPE_COUNT; ++i) {
        unsigned char value = static_cast<unsigned char>(i);
        unsigned char buffer[TLV_HEADER_SIZE + 1] = {};
        write_tlv(buffer, types[i], &value, 1);
        em_tlv_t* tlv = em_msg_t::get_first_tlv(reinterpret_cast<em_tlv_t*>(buffer), sizeof(buffer));
        ASSERT_NE(tlv, nullptr);
        EXPECT_EQ(tlv->type, types[i]);
        EXPECT_EQ(ntohs(tlv->len), 1);
        EXPECT_EQ(*(reinterpret_cast<unsigned char*>(tlv) + TLV_HEADER_SIZE), value);
    }
    std::cout << "Exiting get_first_tlv_LoopAllEnumTypes test" << std::endl;
}
/**
 * @brief Test get_freq_band API with valid frequency band 24
 *
 * This test validates that the get_freq_band method of the em_msg_t class correctly parses a TLV that contains
 * a supported frequency band value (24). The test constructs a TLV using the helper function write_tlv, initializes
 * the em_msg_t object with the TLV buffer, and then calls get_freq_band, asserting that the method returns true and
 * that the frequency band output is correctly set to em_freq_band_24.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 089@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | -------------- | ----- |
 * | 01 | Construct a TLV with supported frequency band 24 and invoke get_freq_band | input: buffer (contains TLV with type=em_tlv_type_supported_freq_band, band=em_freq_band_24, length=1), output: freq_band initialized to em_freq_band_unknown | API returns true and freq_band equals em_freq_band_24; assertions EXPECT_TRUE(result) and EXPECT_EQ(freq_band, em_freq_band_24) pass | Should Pass |
 */
TEST(em_msg_t, get_freq_band_valid_24)
{
    std::cout << "Entering get_freq_band_valid_24 test" << std::endl;
    unsigned char buffer[4];
    unsigned char band = em_freq_band_24;
    write_tlv(buffer, em_tlv_type_supported_freq_band, &band, 1);
    em_msg_t msg(buffer, sizeof(buffer));
    em_freq_band_t freq_band = em_freq_band_unknown;
    bool result = msg.get_freq_band(&freq_band);
    EXPECT_TRUE(result);
    EXPECT_EQ(freq_band, em_freq_band_24);
    std::cout << "Exiting get_freq_band_valid_24 test" << std::endl;
}
/**
 * @brief Verify that get_freq_band correctly retrieves the frequency band when a valid TLV is provided.
 *
 * This test encodes frequency band 5 into a buffer using write_tlv, then creates an em_msg_t object
 * with that buffer. The get_freq_band function is invoked to retrieve the frequency band. The test asserts
 * that the function returns true and that the returned frequency band equals em_freq_band_5.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 090
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result |Notes |
 * | :--------------: | ----------- | --------- | -------------- |-----|
 * |01|Initialize TLV encoded message with frequency band 5 using write_tlv.|buffer = unsigned char[4], band = em_freq_band_5, type = em_tlv_type_supported_freq_band, length = 1|Buffer is correctly populated with frequency band information.|Should be successful|
 * |02|Create an em_msg_t object using the encoded buffer.|buffer = unsigned char[4], size = sizeof(buffer)|Message object is successfully created with the provided buffer.|Should be successful|
 * |03|Invoke get_freq_band to retrieve the frequency band from the message.|msg (em_msg_t object), output parameter: pointer to freq_band (initial value = em_freq_band_unknown)|get_freq_band returns true and freq_band equals em_freq_band_5.|Should Pass|
 * |04|Validate the results using assertions (EXPECT_TRUE and EXPECT_EQ).|result (expected true), freq_band (expected em_freq_band_5)|Assertions pass confirming the correct frequency band was retrieved.|Should Pass|
 */
TEST(em_msg_t, get_freq_band_valid_5)
{
    std::cout << "Entering get_freq_band_valid_5 test" << std::endl;
    unsigned char buffer[4];
    unsigned char band = em_freq_band_5;
    write_tlv(buffer, em_tlv_type_supported_freq_band, &band, 1);
    em_msg_t msg(buffer, sizeof(buffer));
    em_freq_band_t freq_band = em_freq_band_unknown;
    bool result = msg.get_freq_band(&freq_band);
    EXPECT_TRUE(result);
    EXPECT_EQ(freq_band, em_freq_band_5);
    std::cout << "Exiting get_freq_band_valid_5 test" << std::endl;
}
/**
 * @brief Validate that the get_freq_band API correctly extracts the frequency band from a TLV message.
 *
 * This test verifies that when a TLV message is constructed with a supported frequency band (em_freq_band_60), 
 * the get_freq_band function correctly retrieves the frequency band, returning true and setting the output parameter appropriately.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 091@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :-------------: | ------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- | -------------------------------------------------------------- | ----------- |
 * | 01 | Initialize TLV buffer and invoke write_tlv to set the supported frequency band. | buffer = unsigned char[4], band = em_freq_band_60, type = em_tlv_type_supported_freq_band, length = 1 | TLV buffer is successfully updated with the supported frequency band | Should Pass |
 * | 02 | Invoke get_freq_band API on the em_msg_t object and verify the returned frequency band. | msg object with TLV buffer, input: pointer to freq_band, expected output: result = true, freq_band = em_freq_band_60 | get_freq_band returns true and sets freq_band to em_freq_band_60 | Should Pass |
 */
TEST(em_msg_t, get_freq_band_valid_60)
{
    std::cout << "Entering get_freq_band_valid_60 test" << std::endl;
    unsigned char buffer[4];
    unsigned char band = em_freq_band_60;
    write_tlv(buffer, em_tlv_type_supported_freq_band, &band, 1);
    em_msg_t msg(buffer, sizeof(buffer));
    em_freq_band_t freq_band = em_freq_band_unknown;
    bool result = msg.get_freq_band(&freq_band);
    EXPECT_TRUE(result);
    EXPECT_EQ(freq_band, em_freq_band_60);
    std::cout << "Exiting get_freq_band_valid_60 test" << std::endl;
}
/**
 * @brief Validate get_freq_band API with unknown frequency band.
 *
 * This test verifies that the get_freq_band API correctly reads and returns the unknown frequency band value from a TLV buffer.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 092@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Write TLV with unknown frequency band, construct message, call get_freq_band and verify that the frequency band is updated correctly | write_tlv: buffer (unsigned char[4]), tlv_type = em_tlv_type_supported_freq_band, value = em_freq_band_unknown, length = 1; em_msg_t: buffer = buffer, size = 4; get_freq_band: band pointer with initial value = em_freq_band_24 | get_freq_band returns true and band equals em_freq_band_unknown | Should Pass |
 */
TEST(em_msg_t, get_freq_band_valid_unknown)
{
    std::cout << "Entering get_freq_band_valid_unknown test" << std::endl;
    unsigned char buffer[4];
    unsigned char band_val = em_freq_band_unknown;
    write_tlv(buffer, em_tlv_type_supported_freq_band, &band_val, 1);
    em_msg_t msg(buffer, sizeof(buffer));
    em_freq_band_t band = em_freq_band_24; // initialize differently
    bool result = msg.get_freq_band(&band);
    EXPECT_TRUE(result);
    EXPECT_EQ(band, em_freq_band_unknown);
    std::cout << "Exiting get_freq_band_valid_unknown test" << std::endl;
}
/**
 * @brief Verifies that get_freq_band correctly handles a TLV with an incorrect type.
 *
 * This test verifies that the get_freq_band method returns false when the underlying
 * message contains a TLV element with an invalid type. It ensures that the API does not
 * process an unsupported TLV type and correctly handles the error scenario.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 093@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                         | Test Data                                                                                                    | Expected Result                                   | Notes      |
 * | :--------------: | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ | ------------------------------------------------- | ---------- |
 * | 01               | Construct a message with an invalid TLV type along with eom tlv and invoke get_freq_band | buffer = [unsigned char array of size 7 with TLV type 0x99 and eom], dummy_val = 0, band (initially em_freq_band_unknown) | get_freq_band returns false (EXPECT_FALSE(result)) | Should Fail |
 */
TEST(em_msg_t, get_freq_band_wrong_type)
{
    std::cout << "Entering get_freq_band_wrong_type test" << std::endl;
    // TLV( wrong type ) + TLV(EOM)
    unsigned char buffer[TLV_HEADER_SIZE + 1 + TLV_HEADER_SIZE]; // hdr + val + eom
    size_t offset = 0;
    unsigned char dummy_val = 0x00;
    write_tlv(buffer + offset, 0x99, &dummy_val, 1); // wrong type
    offset += TLV_HEADER_SIZE + 1;
    unsigned char dummy = 0;
    write_tlv(buffer + offset, em_tlv_type_eom, &dummy, 0);
    em_msg_t msg(buffer, offset + TLV_HEADER_SIZE);
    em_freq_band_t band = em_freq_band_unknown;
    bool result = msg.get_freq_band(&band);
    EXPECT_FALSE(result);
    std::cout << "Exiting get_freq_band_wrong_type test" << std::endl;
}
/**
 * @brief Validate get_freq_band behavior for messages containing only an EOM TLV
 *
 * This test creates a TLV buffer initialized solely with an EOM (End Of Message)
 * indicator, which inherently does not carry any frequency band information. It then
 * instantiates an em_msg_t object with this buffer and calls the get_freq_band method.
 * The test verifies that get_freq_band returns false as the EOM TLV should not produce
 * a valid frequency band.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 094@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                 | Test Data                                                                                                                    | Expected Result                                                          | Notes       |
 * | :--------------: | --------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ | ----------- |
 * | 01               | Initialize a TLV buffer with an EOM TLV, create a message object, and invoke get_freq_band API. | buffer initialized with EOM TLV (dummy_val = 0, em_tlv_type_eom, length = 0), msg size = sizeof(buffer), band = em_freq_band_unknown | get_freq_band returns false and EXPECT_FALSE(result) assertion passes    | Should Pass |
 */
TEST(em_msg_t, get_freq_band_eom_only)
{
    std::cout << "Entering get_freq_band_eom_only test" << std::endl;
    unsigned char buffer[3];
    unsigned char dummy_val = 0; // EOM has no value
    write_tlv(buffer, em_tlv_type_eom, &dummy_val, 0);
    em_msg_t msg(buffer, sizeof(buffer));
    em_freq_band_t band = em_freq_band_unknown;
    bool result = msg.get_freq_band(&band);
    EXPECT_FALSE(result);
    std::cout << "Exiting get_freq_band_eom_only test" << std::endl;
}
/**
 * @brief Verify that get_next_tlv returns a valid pointer to the next TLV when one exists in the buffer
 *
 * This test verifies that when the buffer contains two TLVs, invoking get_next_tlv on the first TLV returns the pointer to the second TLV. It checks that the returned TLV's type and length match the expected values.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 095@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize the buffer with two TLVs using write_tlv | totalSize = 12, TLV1: type = em_tlv_type_al_mac_address, input value = {0xA1,0xA2,0xA3,0xA4}; TLV2: type = em_tlv_type_device_info, input value = {0xB1,0xB2} | Buffer contains two correctly formatted TLVs | Should be successful |
 * | 02 | Set the pointer to the first TLV in the buffer | current_tlv = reinterpret_cast<em_tlv_t*>(buffer) | current_tlv points to the first TLV in the buffer | Should be successful |
 * | 03 | Call get_next_tlv to retrieve the next TLV from the buffer | current_tlv pointer, starting at buffer, totalSize = 12 | Returns a pointer to the next TLV in the buffer | Should Pass |
 * | 04 | Validate that the returned next TLV pointer is not NULL | next_tlv pointer returned by get_next_tlv | next_tlv != nullptr | Should Pass |
 * | 05 | Verify the type and length of the returned TLV | next_tlv->type, next_tlv->len; expected: em_tlv_type_device_info, 2 | next_tlv->type equals em_tlv_type_device_info and ntohs(next_tlv->len) equals 2 | Should Pass |
 */
TEST(em_msg_t, get_next_tlv_valid_next_tlv_present) {
    std::cout << "Entering get_next_tlv_valid_next_tlv_present test" << std::endl;
    em_msg_t msg;
    const unsigned int totalSize = 12; // two TLVs
    unsigned char buffer[totalSize];
    memset(buffer, 0, totalSize);
    unsigned char val1[4] = {0xA1, 0xA2, 0xA3, 0xA4};
    unsigned char val2[2] = {0xB1, 0xB2};
    write_tlv(buffer, em_tlv_type_al_mac_address, val1, 4);       // first TLV
    write_tlv(buffer + 7, em_tlv_type_device_info, val2, 2);   // second TLV
    em_tlv_t *current_tlv = reinterpret_cast<em_tlv_t*>(buffer);
    em_tlv_t *next_tlv = em_msg_t::get_next_tlv(current_tlv, reinterpret_cast<em_tlv_t*>(buffer), totalSize);
    ASSERT_NE(next_tlv, nullptr);
    EXPECT_EQ(next_tlv->type, em_tlv_type_device_info);
    EXPECT_EQ(ntohs(next_tlv->len), 2);
    std::cout << "Exiting get_next_tlv_valid_next_tlv_present test" << std::endl;
}
/**
 * @brief Unit test for verifying that get_next_tlv returns nullptr when there is no additional TLV in the buffer.
 *
 * This test verifies that the get_next_tlv API correctly returns nullptr when the TLV provided is the only TLV present in the message buffer.
 * The test creates a buffer with one TLV element using write_tlv, then calls get_next_tlv with the current TLV and expects a nullptr since no subsequent TLV exists.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 096
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create a buffer of size 6, write a single TLV using write_tlv, and call get_next_tlv with current_tlv pointing to the start of the buffer | totalSize = 6, val = {0xC1,0xC2,0xC3}, TLV type = em_tlv_type_device_info, current_tlv = buffer address, start pointer = buffer address | get_next_tlv returns nullptr and EXPECT_EQ(next_tlv, nullptr) passes | Should Pass |
 */
TEST(em_msg_t, get_next_tlv_no_next_tlv) {
    std::cout << "Entering get_next_tlv_no_next_tlv test" << std::endl;
    em_msg_t msg;
    const unsigned int totalSize = 6;
    unsigned char buffer[totalSize];
    unsigned char val[3] = {0xC1, 0xC2, 0xC3};
    write_tlv(buffer, em_tlv_type_device_info, val, 3);
    em_tlv_t *current_tlv = reinterpret_cast<em_tlv_t*>(buffer);
    em_tlv_t *next_tlv = em_msg_t::get_next_tlv(current_tlv, reinterpret_cast<em_tlv_t*>(buffer), totalSize);
    EXPECT_EQ(next_tlv, nullptr);
    std::cout << "Exiting get_next_tlv_no_next_tlv test" << std::endl;
}
/**
 * @brief Validate that get_next_tlv correctly identifies out-of-bound TLV scenarios
 *
 * This test verifies that when a TLV is written to a buffer and the provided buffer length is intentionally set smaller than the TLV size, the get_next_tlv function returns a nullptr, ensuring that out-of-bound accesses are properly handled.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 097
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | ----------- | ---------- | -------------- | ----- |
 * | 01 | Write a TLV element into the buffer using write_tlv with TLV type em_tlv_type_device_info and a 10-byte value, then invoke get_next_tlv with a buffer length intentionally set smaller than the TLV size | bufferSize = 13, TLV type = em_tlv_type_device_info, val = {0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9}, buff_len = 12 | The get_next_tlv function should return nullptr and the assertion (ASSERT_EQ(next_tlv, nullptr)) should pass | Should Pass |
 */
TEST(em_msg_t, get_next_tlv_out_of_bounds) {
    std::cout << "Entering get_next_tlv_out_of_bounds test" << std::endl;
    em_msg_t msg;
    const unsigned int bufferSize = 13;
    unsigned char buffer[bufferSize];
    unsigned char val[10] = {0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9};
    write_tlv(buffer, em_tlv_type_device_info, val, 10);
    unsigned int buff_len = 12; // intentionally smaller than TLV size
    em_tlv_t *current_tlv = reinterpret_cast<em_tlv_t*>(buffer);
    em_tlv_t *next_tlv = em_msg_t::get_next_tlv(current_tlv, reinterpret_cast<em_tlv_t*>(buffer), buff_len);
    ASSERT_EQ(next_tlv, nullptr);
    std::cout << "Exiting get_next_tlv_out_of_bounds test" << std::endl;
}
/**
 * @brief Test get_next_tlv handles null current pointer
 *
 * This test verifies that invoking the get_next_tlv API with a null current pointer returns a null value. It confirms that the API correctly handles the case when the current TLV is not provided.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 98@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call get_next_tlv with current set to nullptr and a valid TLV buffer created via write_tlv | current = nullptr, buffer = TLV with type em_tlv_type_device_info and value {0xE1, 0xE2, 0xE3}, totalSize = 6 | API returns nullptr, and ASSERT_EQ passes | Should Pass |
 */

TEST(em_msg_t, get_next_tlv_current_null) {
    std::cout << "Entering get_next_tlv_current_null test" << std::endl;
    em_msg_t msg;
    const unsigned int totalSize = 6;
    unsigned char buffer[totalSize];
    unsigned char val[3] = {0xE1, 0xE2, 0xE3};
    write_tlv(buffer, em_tlv_type_device_info, val, 3);
    em_tlv_t *next_tlv = em_msg_t::get_next_tlv(nullptr, reinterpret_cast<em_tlv_t*>(buffer), totalSize);
    ASSERT_EQ(next_tlv, nullptr);
    std::cout << "Exiting get_next_tlv_current_null test" << std::endl;
}
/**
 * @brief Validate get_next_tlv returns nullptr when provided a null buffer pointer.
 *
 * This test verifies that the get_next_tlv() static function in the em_msg_t class correctly returns a nullptr when the buffer pointer provided for reading the next TLV is null. The test writes a TLV into a local buffer, sets up a current TLV pointer, and then intentionally passes a null buffer pointer to check that the function handles this scenario safely by returning nullptr.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 99
 * **Priority:** High
 * 
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                                         | Test Data                                                                                         | Expected Result                                        | Notes           |
 * | :----:           | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------ | --------------- |
 * | 01               | Write a TLV to localBuffer using write_tlv API                        | input: localBuffer, em_tlv_type_device_info, val = {0xF1,0xF2,0xF3}, length = 3; output: localBuffer updated | localBuffer contains the correct TLV data              | Should be successful |
 * | 02               | Create current_tlv pointer by reinterpreting localBuffer               | input: localBuffer; output: current_tlv pointer                                                   | current_tlv points to the TLV data                     | Should be successful |
 * | 03               | Call get_next_tlv with a null buffer pointer                          | input: current_tlv, buffer pointer = nullptr, size = 6; output: next_tlv pointer                     | next_tlv returns nullptr                               | Should Pass     |
 * | 04               | Assert that next_tlv is nullptr                                       | input: next_tlv value; output: nullptr expected                                                    | ASSERT_EQ confirms that next_tlv is nullptr             | Should Pass     |
 */
TEST(em_msg_t, get_next_tlv_buffer_null) {
    std::cout << "Entering get_next_tlv_buffer_null test" << std::endl;
    em_msg_t msg;
    unsigned char localBuffer[6];
    unsigned char val[3] = {0xF1, 0xF2, 0xF3};
    write_tlv(localBuffer, em_tlv_type_device_info, val, 3);
    em_tlv_t *current_tlv = reinterpret_cast<em_tlv_t*>(localBuffer);
    em_tlv_t *next_tlv = em_msg_t::get_next_tlv(current_tlv, nullptr, 6);
    ASSERT_EQ(next_tlv, nullptr);
    std::cout << "Exiting get_next_tlv_buffer_null test" << std::endl;
}
/**
 * @brief Verify that get_next_tlv returns nullptr when the buffer length is zero.
 *
 * This test verifies the behavior of the get_next_tlv function when it is provided with a valid TLV buffer and a zero buffer length. The test ensures that the API correctly returns a nullptr when no TLV can be parsed due to the zero length.
 *
 * **Test Group ID:** Basic: 01 / Module (L2): 02 / Stress (L2): 03
 * **Test Case ID:** 100
 * **Priority:** (High)
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                  | Test Data                                                                                             | Expected Result                                        | Notes               |
 * | :---------------: | -------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------ | ------------------- |
 * | 01               | Display the start log message for the test                                                   | No input                                                                                              | Start message is displayed                             | Should be successful|
 * | 02               | Setup TLV buffer by writing device info using write_tlv                                      | buffer = [6 bytes], type = em_tlv_type_device_info, val = {0xAA, 0xBB, 0xCC}, len = 3                   | Buffer is populated with a valid TLV structure         | Should be successful|
 * | 03               | Invoke get_next_tlv with the current TLV pointer and a buffer length of 0                      | current_tlv pointer, base TLV pointer (reinterpret_cast from buffer), buffer length = 0                | API returns nullptr                                    | Should Pass         |
 * | 04               | Display the exit log message for the test                                                    | No input                                                                                              | Exit message is displayed                              | Should be successful|
 */
TEST(em_msg_t, get_next_tlv_buff_len_zero) {
    std::cout << "Entering get_next_tlv_buff_len_zero test" << std::endl;
    em_msg_t msg;
    unsigned char buffer[6];
    unsigned char val[3] = {0xAA, 0xBB, 0xCC};
    write_tlv(buffer, em_tlv_type_device_info, val, 3);
    em_tlv_t *current_tlv = reinterpret_cast<em_tlv_t*>(buffer);
    em_tlv_t *next_tlv = em_msg_t::get_next_tlv(current_tlv, reinterpret_cast<em_tlv_t*>(buffer), 0);
    ASSERT_EQ(next_tlv, nullptr);
    std::cout << "Exiting get_next_tlv_buff_len_zero test" << std::endl;
}
/**
 * @brief Test the retrieval of valid client MAC information from a TLV buffer.
 *
 * This test verifies that the API successfully parses a TLV buffer containing valid client information including the MAC address, correctly extracting and returning the MAC address. The test ensures the API works as expected and confirms the integrity of the TLV parsing.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 101
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                  | Test Data                                                                                                     | Expected Result                                                                                            | Notes            |
 * | :--------------: | -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | ---------------- |
 * |      01        | Initialize the TLV buffer and write valid client info including MAC using write_tlv            | buffer size = TLV_HEADER_SIZE + 6, mac_val = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB}                             | Buffer contains valid TLV with correct client information                                                  | Should be successful |
 * |      02        | Create an instance of em_msg_t using the prepared TLV buffer                                   | buffer, buffer length = TLV_HEADER_SIZE + 6                                                                   | em_msg_t object is successfully created                                                                    | Should be successful |
 * |      03        | Call get_client_mac_info to extract the MAC address and compare it with the expected MAC value | output pointer to mac (6 bytes), expected mac_val = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB}                         | Function returns true and the extracted MAC address matches the expected value as per EXPECT_TRUE and EXPECT_EQ | Should Pass       |
 */
TEST(em_msg_t, get_client_mac_info_valid_client_info_tlv)
{
    std::cout << "Entering get_client_mac_info_valid_client_info_tlv test" << std::endl;
    unsigned char buffer[TLV_HEADER_SIZE + 6];
    unsigned char mac_val[6] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB};
    write_tlv(buffer, em_tlv_type_client_info, mac_val, sizeof(mac_val));
    em_msg_t msg(buffer, sizeof(buffer));
    unsigned char mac[6] = {0};
    bool ret = msg.get_client_mac_info(reinterpret_cast<mac_address_t*>(mac));
    EXPECT_TRUE(ret);
    EXPECT_EQ(0, std::memcmp(mac, mac_val, 6));
    std::cout << "Exiting get_client_mac_info_valid_client_info_tlv test" << std::endl;
}
/**
 * @brief Test the behavior when the client MAC info TLV is absent.
 *
 * This test initializes a message buffer with a TLV of a type that is not associated with client MAC information, then calls get_client_mac_info to check that the API correctly returns false, indicating that no client MAC info TLV was found.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 102
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Write TLV with non-client info into buffer and invoke get_client_mac_info | buffer size = TLV_HEADER_SIZE + 6, dummy_val = 0xDE,0xAD,0xBE,0xEF,0x00,0x11, mac = {0} | API returns false indicating client MAC info TLV not found | Should Fail |
 */
TEST(em_msg_t, get_client_mac_info_tlv_not_found)
{
    std::cout << "Entering get_client_mac_info_tlv_not_found test" << std::endl;
    unsigned char buffer[TLV_HEADER_SIZE + 6];
    unsigned char dummy_val[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11};
    write_tlv(buffer, em_tlv_type_ap_metrics, dummy_val, sizeof(dummy_val)); // not client info
    em_msg_t msg(buffer, sizeof(buffer));
    unsigned char mac[6] = {0};
    bool ret = msg.get_client_mac_info(reinterpret_cast<mac_address_t*>(mac));
    EXPECT_FALSE(ret);
    std::cout << "Exiting get_client_mac_info_tlv_not_found test" << std::endl;
}
/**
 * @brief Validate that get_client_mac_info returns false when provided with a null pointer
 *
 * This test validates that when get_client_mac_info is called with a null MAC pointer, it properly handles the null input and returns false as expected. This negative test scenario is important for ensuring robust input validation within the API.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 103@n
 * **Priority:** (High) Test is critical to overall functionality as it ensures proper handling of null pointer input@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                  | Test Data                                                                                                                                                   | Expected Result                                                         | Notes       |
 * | :--------------: | ------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke get_client_mac_info with a null MAC pointer           | buffer = [TLV_HEADER_SIZE + 6 bytes constructed with write_tlv], mac_val = [0xAA,0xBB,0xCC,0xDD,0xEE,0xFF], pointer argument = nullptr                     | API returns false; EXPECT_FALSE(ret) passes                             | Should Pass |
 */
TEST(em_msg_t, get_client_mac_info_null_mac_pointer)
{
    std::cout << "Entering get_client_mac_info_null_mac_pointer test" << std::endl;
    unsigned char buffer[TLV_HEADER_SIZE + 6];
    unsigned char mac_val[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    write_tlv(buffer, em_tlv_type_client_info, mac_val, sizeof(mac_val));
    em_msg_t msg(buffer, sizeof(buffer));
    bool ret = msg.get_client_mac_info(nullptr);
    EXPECT_FALSE(ret);
    std::cout << "Exiting get_client_mac_info_null_mac_pointer test" << std::endl;
}
/**
 * @brief Verify that get_client_mac_info returns false when provided with an empty message buffer.
 *
 * This test validates that the get_client_mac_info method behaves correctly when the message buffer is empty.
 * Specifically, it checks that the method returns false, indicating that client MAC information cannot be extracted
 * from an empty buffer.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 104
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize an empty buffer, create an em_msg_t instance, and invoke get_client_mac_info with a mac pointer | buffer = {0}, bufferLen = 0, mac = {0, 0, 0, 0, 0, 0} | API returns false and EXPECT_FALSE assertion passes | Should Pass |
 */
TEST(em_msg_t, get_client_mac_info_empty_message_buffer)
{
    std::cout << "Entering get_client_mac_info_empty_message_buffer test" << std::endl;
    unsigned char buffer[1] = {}; // dummy buffer, length = 0
    unsigned int bufferLen = 0;
    em_msg_t msg(buffer, bufferLen);
    unsigned char mac[6] = {0};
    bool ret = msg.get_client_mac_info(reinterpret_cast<mac_address_t*>(mac));
    EXPECT_FALSE(ret);
    std::cout << "Exiting get_client_mac_info_empty_message_buffer test" << std::endl;
}
/**
 * @brief Verify that get_profile extracts and returns the correct profile value from a TLV buffer.
 *
 * This test constructs a TLV buffer that includes a WSC TLV, a valid profile TLV with value profile_type_1, and an EOM TLV. It then creates an em_msg_t object with this buffer and calls get_profile to ensure that the profile is correctly extracted and updated from the TLV data.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 105@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Construct the TLV buffer with WSC, Profile (type 1), and EOM TLVs, then create an em_msg_t object and invoke get_profile | buffer, offset (sum of TLV_HEADER_SIZEs and payloads), other_payload = {1,2,3}, profile_payload = {em_profile_type_1}, dummy = 0, msg object with type em_msg_type_topo_disc and initial profile em_profile_type_reserved | get_profile returns true and updates profile to em_profile_type_1 | Should Pass |
 */
TEST(em_msg_t, get_profile_valid_tlv_pofile_1)
{
    std::cout << "Entering get_profile_valid_tlv_pofile_1 test" << std::endl;
    unsigned char buffer[512] = {};
    size_t offset = 0;
    unsigned char other_payload[10] = {1,2,3};
    write_tlv(buffer + offset, em_tlv_type_wsc, other_payload, 3);
    offset += TLV_HEADER_SIZE + 3;
    unsigned char profile_payload[1] = { static_cast<unsigned char>(em_profile_type_1) };
    write_tlv(buffer + offset, em_tlv_type_profile, profile_payload, 1);
    offset += TLV_HEADER_SIZE + 1;
    unsigned char dummy = 0;
    write_tlv(buffer + offset, em_tlv_type_eom, &dummy, 0);
    offset += TLV_HEADER_SIZE;
    em_msg_t msg(em_msg_type_topo_disc, em_profile_type_reserved, buffer, offset);
    em_profile_type_t profile = em_profile_type_reserved;
    bool result = msg.get_profile(&profile);
    EXPECT_TRUE(result);
    EXPECT_EQ(profile, em_profile_type_1);
    std::cout << "Exiting get_profile_valid_tlv_pofile_1 test" << std::endl;
}
/**
 * @brief Validate that the get_profile API correctly retrieves the profile from a properly encoded TLV message buffer
 *
 * This test verifies that the get_profile function extracts the profile type from a TLV buffer that includes WSC, profile, and EOM TLVs. It confirms that the correct profile (profile type 2) is obtained when the TLV segments are written in the expected sequence.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 106@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Write WSC TLV into the buffer | buffer pointer = buffer, offset = 0, type = em_tlv_type_wsc, payload = {1,2,3}, length = 3 | Buffer updated with valid WSC TLV segment | Should be successful |
 * | 02 | Write profile TLV into the buffer | buffer pointer = buffer+offset, type = em_tlv_type_profile, payload = { em_profile_type_2 }, length = 1 | Buffer updated with valid profile TLV segment | Should be successful |
 * | 03 | Write EOM TLV into the buffer | buffer pointer = buffer+offset, type = em_tlv_type_eom, payload = {dummy}, length = 0 | Buffer updated with valid EOM TLV segment | Should be successful |
 * | 04 | Create message object and invoke get_profile | msg = em_msg_t(em_msg_type_topo_disc, em_profile_type_reserved, buffer, offset), input parameter: profile pointer, initial value = em_profile_type_reserved | API returns true and profile equals em_profile_type_2 | Should Pass |
 */
TEST(em_msg_t, get_profile_valid_tlv_pofile_2)
{
    std::cout << "Entering get_profile_valid_tlv_pofile_2 test" << std::endl;
    unsigned char buffer[512] = {};
    size_t offset = 0;
    unsigned char other_payload[10] = {1,2,3};
    write_tlv(buffer + offset, em_tlv_type_wsc, other_payload, 3);
    offset += TLV_HEADER_SIZE + 3;
    unsigned char profile_payload[1] = { static_cast<unsigned char>(em_profile_type_2) };
    write_tlv(buffer + offset, em_tlv_type_profile, profile_payload, 1);
    offset += TLV_HEADER_SIZE + 1;
    unsigned char dummy = 0;
    write_tlv(buffer + offset, em_tlv_type_eom, &dummy, 0);
    offset += TLV_HEADER_SIZE;
    em_msg_t msg(em_msg_type_topo_disc, em_profile_type_reserved, buffer, offset);
    em_profile_type_t profile = em_profile_type_reserved;
    bool result = msg.get_profile(&profile);
    EXPECT_TRUE(result);
    EXPECT_EQ(profile, em_profile_type_2);
    std::cout << "Exiting get_profile_valid_tlv_pofile_2 test" << std::endl;
}
/**
 * @brief Validate that get_profile correctly retrieves a profile from a valid TLV buffer.
 *
 * This test verifies that when a valid TLV payload with profile type 3 is written into the buffer,
 * the get_profile API successfully returns true and updates the profile variable to em_profile_type_3.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 107@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                 | Test Data                                                                                                                           | Expected Result                                                                  | Notes       |
 * | :--------------: | ------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- | ----------- |
 * | 01               | Initialize TLV buffer with profile type 3 and EOM TLV, create em_msg_t object, invoke get_profile API | buffer = 0 (512 bytes), offset computed using TLV_HEADER_SIZE, payload byte = em_profile_type_3, initial profile = em_profile_type_reserved | API returns true and profile is updated to em_profile_type_3, assertions pass     | Should Pass |
 */
TEST(em_msg_t, get_profile_valid_tlv_pofile_3)
{
    std::cout << "Entering get_profile_valid_tlv_pofile_3 test" << std::endl;
    unsigned char buffer[512] = {};
    size_t offset = 0;
    unsigned char payload[1] = { static_cast<unsigned char>(em_profile_type_3) };
    write_tlv(buffer + offset, em_tlv_type_profile, payload, 1);
    offset += TLV_HEADER_SIZE + 1;
    unsigned char dummy = 0;
    write_tlv(buffer + offset, em_tlv_type_eom, &dummy, 0);
    offset += TLV_HEADER_SIZE;
    em_msg_t msg(em_msg_type_topo_disc, em_profile_type_reserved, buffer, offset);
    em_profile_type_t profile = em_profile_type_reserved;
    bool result = msg.get_profile(&profile);
    EXPECT_TRUE(result);
    EXPECT_EQ(profile, em_profile_type_3);
    std::cout << "Exiting get_profile_valid_tlv_pofile_3 test" << std::endl;
}
/**
 * @brief Test case to verify that get_profile returns false when the profile TLV is not present in the message
 *
 * This test verifies that when a message is constructed without a TLV of type "profile" (instead using a TLV of type "wsc"),
 * the get_profile API correctly identifies the absence of the profile TLV and returns false. This ensures that the function
 * does not mistakenly locate or misinterpret other TLVs as a valid profile.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 108@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke write_tlv to insert a TLV with em_tlv_type_wsc (non-profile) into the buffer. | buffer = array of 512 bytes (initialized to zeros), offset = 0, tlv type = em_tlv_type_wsc, payload = {0x00}, length = 1 | TLV written successfully into the buffer. | Should be successful |
 * | 02 | Invoke write_tlv to append a TLV with em_tlv_type_eom into the buffer to mark the end of message. | buffer offset updated, tlv type = em_tlv_type_eom, dummy = 0, length = 0 | TLV appended successfully to the buffer. | Should be successful |
 * | 03 | Construct an em_msg_t object using the message type em_msg_type_topo_disc, a reserved profile type, and the buffer containing the TLVs. | em_msg_type_topo_disc, em_profile_type_reserved, buffer content, offset value after TLVs insertion | Message object created successfully with the provided TLVs. | Should be successful |
 * | 04 | Call get_profile on the constructed message expecting the profile TLV not to be found. | Call get_profile with profile pointer initially set to em_profile_type_reserved | API returns false indicating that the profile TLV is not found; the EXPECT_FALSE assertion passes. | Should Fail |
 */
TEST(em_msg_t, get_profile_tlv_not_found)
{
    std::cout << "Entering get_profile_tlv_not_found test" << std::endl;
    unsigned char buffer[512] = {};
    size_t offset = 0;
    unsigned char payload[1] = {0x00};
    write_tlv(buffer + offset, em_tlv_type_wsc, payload, 1); // TLV type != profile
    offset += TLV_HEADER_SIZE + 1;
    unsigned char dummy = 0;
    write_tlv(buffer + offset, em_tlv_type_eom, &dummy, 0);
    offset += TLV_HEADER_SIZE;
    em_msg_t msg(em_msg_type_topo_disc, em_profile_type_reserved, buffer, offset);
    em_profile_type_t profile = em_profile_type_reserved;
    bool result = msg.get_profile(&profile);
    EXPECT_FALSE(result);
    std::cout << "Exiting get_profile_tlv_not_found test" << std::endl;
}
/**
 * @brief Verify that calling get_profile with a null pointer returns false
 *
 * This test validates the behavior of the get_profile API when provided with a null pointer argument. The test constructs an em_msg_t instance with predetermined TLV data and then attempts to retrieve the profile with a null pointer. The expected outcome is that the API fails the retrieval and returns false.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 109@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- | -------------- | ----- |
 * | 01 | Construct the TLV buffer, create an em_msg_t instance, and invoke get_profile with a null pointer | buffer = unsigned char[512] (initialized), offset updated with TLV_HEADER_SIZE, payload = {em_profile_type_1}, dummy value for em_tlv_type_eom, msg constructed with em_msg_type_topo_disc and em_profile_type_reserved, input pointer = nullptr | get_profile returns false; EXPECT_FALSE(result) assertion passes | Should Pass |
 */
TEST(em_msg_t, get_profile_null_pointer)
{
    std::cout << "Entering get_profile_null_pointer test" << std::endl;
    unsigned char buffer[512] = {};
    size_t offset = 0;
    unsigned char payload[1] = { static_cast<unsigned char>(em_profile_type_1) };
    write_tlv(buffer + offset, em_tlv_type_profile, payload, 1);
    offset += TLV_HEADER_SIZE + 1;
    unsigned char dummy = 0;
    write_tlv(buffer + offset, em_tlv_type_eom, &dummy, 0);
    offset += TLV_HEADER_SIZE;
    em_msg_t msg(em_msg_type_topo_disc, em_profile_type_reserved, buffer, offset);
    bool result = msg.get_profile(nullptr);
    EXPECT_FALSE(result);
    std::cout << "Exiting get_profile_null_pointer test" << std::endl;
}
/**
 * @brief Test get_profile API with an empty buffer.
 *
 * This test validates that the get_profile API of the em_msg_t object returns false when provided with an empty buffer.
 * It initializes an empty buffer, a zero offset, and a reserved profile type value, then verifies that the API correctly identifies
 * the absence of a valid profile by returning false.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 110
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                            | Test Data                                                                                                                      | Expected Result                                                  | Notes       |
 * | :--------------: | ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------- | ----------- |
 * | 01               | Construct em_msg_t with an empty buffer and invoke get_profile API.      | buffer = all zeros (512 bytes), offset = 0, msg type = em_msg_type_topo_disc, profile type = em_profile_type_reserved, profile pointer provided | get_profile returns false and the EXPECT_FALSE assertion passes. | Should Pass |
 */
TEST(em_msg_t, get_profile_empty_buffer)
{
    std::cout << "Entering get_profile_empty_buffer test" << std::endl;
    unsigned char buffer[512] = {};
    size_t offset = 0;
    em_msg_t msg(em_msg_type_topo_disc, em_profile_type_reserved, buffer, offset);
    em_profile_type_t profile = em_profile_type_reserved;
    bool result = msg.get_profile(&profile);
    EXPECT_FALSE(result);
    std::cout << "Exiting get_profile_empty_buffer test" << std::endl;
}
/**
 * @brief Test the retrieval of the reserved profile type from the message
 *
 * This test verifies that the get_profile_type API correctly reads the reserved profile type from a constructed message. The test builds a TLV buffer with a reserved profile type TLV and an EOM TLV, constructs an em_msg_t instance from the TLV buffer, and then retrieves the profile type using the API. It ensures that the API returns true and that the retrieved profile matches the expected reserved profile type.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 111@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Write reserved profile TLV into buffer | buffer pointer (buffer + offset), em_tlv_type_profile, profile_val = em_profile_type_reserved, sizeof(profile_val) | TLV for reserved profile type is written into buffer | Should be successful |
 * | 02 | Write EOM TLV into buffer | buffer pointer (buffer + offset), em_tlv_type_eom, dummy_val = 0, 0 | TLV for end of message is written into buffer | Should be successful |
 * | 03 | Construct em_msg_t with the TLV buffer | em_msg_type_ap_metrics_rsp, profile type = em_profile_type_reserved, buffer, offset | em_msg_t object is constructed with the provided TLV data | Should be successful |
 * | 04 | Retrieve profile type from message using get_profile_type API | Retrieved profile pointer (initial value = em_profile_type_reserved) | API returns true and retrieved profile equals em_profile_type_reserved | Should Pass |
 */
TEST(em_msg_t, get_profile_type_reserved)
{
    std::cout << "Entering get_profile_type_reserved test" << std::endl;
    unsigned char buffer[64] = {0};
    size_t offset = 0;
    em_profile_type_t profile_val = em_profile_type_reserved;
    write_tlv(buffer + offset, em_tlv_type_profile,
              reinterpret_cast<unsigned char*>(&profile_val), sizeof(profile_val));
    offset += TLV_HEADER_SIZE + sizeof(profile_val);
    unsigned char dummy_val = 0;
    write_tlv(buffer + offset, em_tlv_type_eom, &dummy_val, 0);
    offset += TLV_HEADER_SIZE;
    em_msg_t msg(em_msg_type_ap_metrics_rsp, em_profile_type_reserved, buffer, offset);
    em_profile_type_t retrieved_profile = em_profile_type_reserved;
    bool result = msg.get_profile_type(&retrieved_profile);
    EXPECT_TRUE(result);
    EXPECT_EQ(retrieved_profile, em_profile_type_reserved);
    std::cout << "Exiting get_profile_type_reserved test" << std::endl;
}
/**
 * @brief Verifies that get_profile_type correctly retrieves the profile type from a TLV message.
 *
 * This test constructs an em_msg_t object by populating a TLV buffer with a specific profile type
 * (em_profile_type_1) and an end-of-message marker, then calls get_profile_type to extract the profile
 * type from the message. The test confirms that the retrieved profile matches the expected value.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 112@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Write TLV for profile type data into the buffer | buffer (unsigned char[64] initialized to 0), offset = 0, profile_val = em_profile_type_1, TLV header size = TLV_HEADER_SIZE | Buffer updated with profile type TLV segment | Should be successful |
 * | 02 | Write TLV for end-of-message marker | buffer, updated offset, dummy_val = 0, TLV header size = TLV_HEADER_SIZE | Buffer updated with end-of-message TLV segment | Should be successful |
 * | 03 | Create em_msg_t object with the TLV buffer | msg type: em_msg_type_ap_metrics_rsp, profile type: em_profile_type_reserved, buffer, offset (total TLV length) | em_msg_t object successfully created with the TLV message | Should be successful |
 * | 04 | Call get_profile_type and validate the retrieved profile type | retrieved_profile initialized to em_profile_type_reserved, expected output: retrieved_profile should be em_profile_type_1, result expected TRUE | API returns true and retrieved profile matches em_profile_type_1 | Should Pass |
 */
TEST(em_msg_t, get_profile_type_1) 
{
    std::cout << "Entering get_profile_type_1 test" << std::endl;
    unsigned char buffer[64] = {0};
    size_t offset = 0;
    em_profile_type_t profile_val = em_profile_type_1;
    write_tlv(buffer + offset, em_tlv_type_profile,
              reinterpret_cast<unsigned char*>(&profile_val), sizeof(profile_val));
    offset += TLV_HEADER_SIZE + sizeof(profile_val);
    unsigned char dummy_val = 0;
    write_tlv(buffer + offset, em_tlv_type_eom, &dummy_val, 0);
    offset += TLV_HEADER_SIZE;
    em_msg_t msg(em_msg_type_ap_metrics_rsp, em_profile_type_reserved, buffer, offset);
    em_profile_type_t retrieved_profile = em_profile_type_reserved;
    bool result = msg.get_profile_type(&retrieved_profile);
    EXPECT_TRUE(result);
    EXPECT_EQ(retrieved_profile, em_profile_type_1);
    std::cout << "Exiting get_profile_type_1 test" << std::endl;
}
/**
 * @brief Validate the get_profile_type API functionality by testing the correct retrieval of profile type from an em_msg_t object.
 *
 * This test constructs a message buffer with two TLVs: one for a profile type (set to em_profile_type_2) and one for the end-of-message marker. It then creates an em_msg_t object using this buffer and invokes the get_profile_type method to verify that the retrieved profile type matches the expected value. This ensures that the API correctly parses and returns the profile type from the TLV formatted message.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 113@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Write the profile type TLV to the buffer with value em_profile_type_2 | buffer = {0,...}, offset = 0, profile_val = em_profile_type_2 | Buffer updated with TLV header and profile value inserted | Should be successful |
 * | 02 | Write the end-of-message TLV to the buffer | dummy_val = 0, offset incremented by TLV_HEADER_SIZE | Buffer updated with EOM TLV | Should be successful |
 * | 03 | Construct the em_msg_t message with the composed buffer | msg_type = em_msg_type_ap_metrics_rsp, profile = em_profile_type_reserved, buffer, offset | Message object correctly initialized with the TLVs | Should be successful |
 * | 04 | Invoke get_profile_type to retrieve and validate the profile type | retrieved_profile initially set to em_profile_type_reserved, passing its address to API | API returns true and retrieved_profile equals em_profile_type_2 | Should Pass |
 */
TEST(em_msg_t, get_profile_type_2) 
{
    std::cout << "Entering get_profile_type_2 test" << std::endl;
    unsigned char buffer[64] = {0};
    size_t offset = 0;
    em_profile_type_t profile_val = em_profile_type_2;
    write_tlv(buffer + offset, em_tlv_type_profile,
              reinterpret_cast<unsigned char*>(&profile_val), sizeof(profile_val));
    offset += TLV_HEADER_SIZE + sizeof(profile_val);
    unsigned char dummy_val = 0;
    write_tlv(buffer + offset, em_tlv_type_eom, &dummy_val, 0);
    offset += TLV_HEADER_SIZE;
    em_msg_t msg(em_msg_type_ap_metrics_rsp, em_profile_type_reserved, buffer, offset);
    em_profile_type_t retrieved_profile = em_profile_type_reserved;
    bool result = msg.get_profile_type(&retrieved_profile);
    EXPECT_TRUE(result);
    EXPECT_EQ(retrieved_profile, em_profile_type_2);
    std::cout << "Exiting get_profile_type_2 test" << std::endl;
}
/**
 * @brief Verify that get_profile_type correctly retrieves the profile type 3 from the TLV message.
 *
 * This test verifies that the em_msg_t API correctly processes a message buffer containing TLVs,
 * extracts the profile type, and returns the expected value. The test constructs a buffer with the
 * profile TLV and an End Of Message (EOM) TLV, creates a message object, and then retrieves and validates
 * the profile type.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 114@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                     | Test Data                                                                                                               | Expected Result                                                  | Notes            |
 * | :--------------: | ----------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- | ---------------- |
 * | 01               | Call write_tlv to write the profile type TLV to the buffer                                      | buffer = {0}, offset = 0, profile_val = em_profile_type_3, type = em_tlv_type_profile, size = sizeof(profile_val)        | Buffer updated with the profile type TLV data                    | Should be successful |
 * | 02               | Update offset after writing the profile type TLV                                                | offset increased by (TLV_HEADER_SIZE + sizeof(profile_val))                                                             | Offset correctly advanced                                        | Should be successful |
 * | 03               | Call write_tlv to write the EOM TLV to the buffer                                                | buffer + offset, type = em_tlv_type_eom, dummy_val = 0, size = 0                                                          | Buffer updated with the EOM TLV data                               | Should be successful |
 * | 04               | Update offset after writing the EOM TLV                                                          | offset increased by TLV_HEADER_SIZE                                                                                     | Offset correctly advanced                                        | Should be successful |
 * | 05               | Create an instance of em_msg_t with the constructed buffer and initial parameters                | em_msg_type = em_msg_type_ap_metrics_rsp, profile = em_profile_type_reserved, buffer, offset                              | em_msg_t instance created                                        | Should be successful |
 * | 06               | Invoke get_profile_type API to retrieve the profile type from the message                        | retrieved_profile initially set to em_profile_type_reserved; input: pointer to retrieved_profile                          | get_profile_type returns true and retrieved_profile equals em_profile_type_3 | Should Pass         |
 */
TEST(em_msg_t, get_profile_type_3) 
{
    std::cout << "Entering get_profile_type_3 test" << std::endl;
    unsigned char buffer[64] = {0};
    size_t offset = 0;
    em_profile_type_t profile_val = em_profile_type_3;
    write_tlv(buffer + offset, em_tlv_type_profile,
              reinterpret_cast<unsigned char*>(&profile_val), sizeof(profile_val));
    offset += TLV_HEADER_SIZE + sizeof(profile_val);
    unsigned char dummy_val = 0;
    write_tlv(buffer + offset, em_tlv_type_eom, &dummy_val, 0);
    offset += TLV_HEADER_SIZE;
    em_msg_t msg(em_msg_type_ap_metrics_rsp, em_profile_type_reserved, buffer, offset);
    em_profile_type_t retrieved_profile = em_profile_type_reserved;
    bool result = msg.get_profile_type(&retrieved_profile);
    EXPECT_TRUE(result);
    EXPECT_EQ(retrieved_profile, em_profile_type_3);
    std::cout << "Exiting get_profile_type_3 test" << std::endl;
}
/**
 * @brief Test to verify get_profile_type returns false when the TLV is not present
 *
 * This test verifies that the method get_profile_type correctly fails (returns false) when
 * the TLV information is not present in the provided buffer. The test initializes a buffer
 * with dummy TLV data and creates a message object with a reserved profile type. It then
 * attempts to retrieve the profile type, expecting the method to fail and leave the profile type unchanged.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 115@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                              | Test Data                                                                                                                                   | Expected Result                                                                                               | Notes             |
 * | :--------------: | ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- | ----------------- |
 * | 01               | Initialize the buffer, dummy value, and write a TLV with dummy data                        | buffer = {0}, dummy_val = 0, TLV type = em_tlv_type_eom, tlv length = 0                                                                       | Buffer is initialized and TLV is written successfully                                                          | Should be successful |
 * | 02               | Construct the message object with provided parameters                                      | em_msg_type = em_msg_type_ap_metrics_rsp, em_profile_type = em_profile_type_reserved, buffer, length = 3                                   | Message object is created with profile type set to em_profile_type_reserved                                      | Should be successful |
 * | 03               | Invoke get_profile_type and validate the output                                            | initial retrieved_profile = em_profile_type_1, output retrieved_profile, result from get_profile_type invocation                             | get_profile_type returns false and retrieved_profile remains em_profile_type_reserved                            | Should Fail       |
 */
TEST(em_msg_t, get_profile_type_no_tlv) 
{
    std::cout << "Entering get_profile_type_no_tlv test" << std::endl;
    unsigned char buffer[16] = {0};
    unsigned char dummy_val = 0;
    write_tlv(buffer, em_tlv_type_eom, &dummy_val, 0);
    em_msg_t msg(em_msg_type_ap_metrics_rsp, em_profile_type_reserved, buffer, 3);
    em_profile_type_t retrieved_profile = em_profile_type_1;
    bool result = msg.get_profile_type(&retrieved_profile);
    EXPECT_FALSE(result);
    EXPECT_EQ(retrieved_profile, em_profile_type_reserved);
    std::cout << "Exiting get_profile_type_no_tlv test" << std::endl;
}
/**
 * @brief Test get_profile_type API with a null pointer argument
 *
 * This test verifies the behavior of the get_profile_type API when a null pointer is passed. The objective is to ensure that the API gracefully handles invalid (null) pointers and returns the expected failure response.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 116@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                          | Test Data                                      | Expected Result                              | Notes       |
 * | :--------------: | ------------------------------------------------------------------------------------ | ---------------------------------------------- | -------------------------------------------- | ----------- |
 * | 01               | Invoke get_profile_type with a null pointer argument and verify the return value       | msg: instance of em_msg_t, ptr = nullptr         | Return value should be false as per EXPECT_FALSE(result) | Should Fail |
 */
TEST(em_msg_t, get_profile_type_null) 
{
    std::cout << "Entering get_profile_type_null test" << std::endl;
    unsigned char buffer[64] = {0};
    size_t offset = 0;
    em_profile_type_t profile_val = em_profile_type_2;
    write_tlv(buffer + offset, em_tlv_type_profile,
              reinterpret_cast<unsigned char*>(&profile_val), sizeof(profile_val));
    offset += TLV_HEADER_SIZE + sizeof(profile_val);
    unsigned char dummy_val = 0;
    write_tlv(buffer + offset, em_tlv_type_eom, &dummy_val, 0);
    offset += TLV_HEADER_SIZE;
    em_msg_t msg(em_msg_type_ap_metrics_rsp, em_profile_type_reserved, buffer, offset);
    bool result = msg.get_profile_type(nullptr);
    EXPECT_FALSE(result);
    std::cout << "Exiting get_profile_type_null test" << std::endl;
}
/**
 * @brief Test the valid extraction of radio id from the message object.
 *
 * This test verifies that the get_radio_id function correctly extracts the radio id from a TLV encoded buffer. The test constructs a buffer with a radio_id TLV followed by an end-of-message TLV, creates a message instance, and then checks whether get_radio_id returns true and if the extracted MAC address matches the expected value.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 117@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Populate TLV buffer with radio id and end-of-message, instantiate the message object, and call get_radio_id API. | tlvBuffer constructed with: radio_id TLV (expectedMac = 0x00,0x11,0x22,0x33,0x44,0x55), EOM TLV (dummy_val = 0); offset updated accordingly. | API returns true and extracted MAC equals expectedMac. | Should Pass |
 */
TEST(em_msg_t, get_radio_id_valid_extraction) 
{
    std::cout << "Entering get_radio_id_valid_extraction" << std::endl;
    unsigned char tlvBuffer[64];
    unsigned char expectedMac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    size_t offset = 0;
    write_tlv(tlvBuffer + offset, em_tlv_type_radio_id, expectedMac, 6);
    offset += TLV_HEADER_SIZE + 6;
    unsigned char dummy_val = 0;
    write_tlv(tlvBuffer + offset, em_tlv_type_eom, &dummy_val, 0);
    offset += TLV_HEADER_SIZE;
    em_msg_t msg(tlvBuffer, offset);
    unsigned char mac[6] = {0};
    bool retVal = msg.get_radio_id(&mac);
    EXPECT_TRUE(retVal);
    EXPECT_EQ(0, std::memcmp(mac, expectedMac, 6));
    std::cout << "Exiting get_radio_id_valid_extraction" << std::endl;
}
/**
 * @brief Verify that get_radio_id returns false when no radio_id TLV is present in the message
 *
 * This test constructs a TLV buffer containing an AL MAC Address TLV and an End-Of-Message TLV, but omits the radio_id TLV.
 * The test then creates an em_msg_t object using the constructed buffer and invokes the get_radio_id method.
 * It validates that the API returns false, indicating that the radio_id TLV is not present.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 118@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Construct TLV buffer with AL MAC Address TLV and End-Of-Message TLV, then call get_radio_id API on em_msg_t instance | tlvBuffer with em_tlv_type_al_mac_address, dummy_val = [0xAA,0xBB], dummy_eom = 0, mac array initialized to zeros | API returns false indicating absence of radio_id TLV; EXPECT_FALSE(retVal) asserts failure to locate radio_id | Should Fail |
 */
TEST(em_msg_t, get_radio_id_no_radio_id_tlv)
{
    std::cout << "Entering get_radio_id_no_radio_id_tlv" << std::endl;
    unsigned char tlvBuffer[64];
    size_t offset = 0;
    unsigned char dummy_val[2] = {0xAA, 0xBB};
    write_tlv(tlvBuffer + offset, em_tlv_type_al_mac_address, dummy_val, 2);
    offset += TLV_HEADER_SIZE + 2;
    unsigned char dummy_eom = 0;
    write_tlv(tlvBuffer + offset, em_tlv_type_eom, &dummy_eom, 0);
    offset += TLV_HEADER_SIZE;
    em_msg_t msg(tlvBuffer, offset);
    unsigned char mac[6] = {0};
    bool retVal = msg.get_radio_id(&mac);
    EXPECT_FALSE(retVal);
    std::cout << "Exiting get_radio_id_no_radio_id_tlv" << std::endl;
}
/**
 * @brief Test get_radio_id API with a null MAC pointer to verify handling of invalid input.
 *
 * This test verifies that when a null MAC pointer is passed to the get_radio_id method,
 * the API returns false to ensure safe handling of invalid pointer references.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 119
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                               | Test Data                                                                                              | Expected Result                                                      | Notes        |
 * | :--------------: | ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------- | ------------ |
 * | 01               | Invoke get_radio_id with a null MAC pointer after constructing the message. | tlvBuffer: buffer with radio id TLV set (expectedMac = 0x00,0x11,0x22,0x33,0x44,0x55), dummy_eom set; offset computed; input MAC pointer set to nullptr, output expected as false | API returns false, verified by the EXPECT_FALSE assertion in the test | Should Fail  |
 */
TEST(em_msg_t, get_radio_id_null_mac_pointer) 
{
    std::cout << "Entering get_radio_id_null_mac_pointer" << std::endl;
    unsigned char tlvBuffer[64];
    unsigned char expectedMac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    size_t offset = 0;
    write_tlv(tlvBuffer + offset, em_tlv_type_radio_id, expectedMac, 6);
    offset += TLV_HEADER_SIZE + 6;
    unsigned char dummy_eom = 0;
    write_tlv(tlvBuffer + offset, em_tlv_type_eom, &dummy_eom, 0);
    offset += TLV_HEADER_SIZE;
    em_msg_t msg(tlvBuffer, offset);
    bool retVal = msg.get_radio_id(nullptr);
    EXPECT_FALSE(retVal);
    std::cout << "Exiting get_radio_id_null_mac_pointer" << std::endl;
}
/**
 * @brief Validate get_radio_id API behavior with multiple radio_id TLVs
 *
 * This test verifies that when multiple radio_id TLVs are present in the message buffer, the get_radio_id API correctly returns the radio id corresponding to the first radio_id TLV. The test creates a message containing two radio_id TLVs and one end-of-message TLV, and then ensures that the API extracts the radio id from the first TLV.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 120@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize the TLV buffer with two radio_id TLVs and one EOM TLV. | tlvBuffer, mac1 = {0x00,0x11,0x22,0x33,0x44,0x55}, mac2 = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF}, dummy_eom = 0, offset = 0. | Buffer is populated correctly with the first radio_id TLV, the second radio_id TLV, and the EOM TLV at the correct offsets. | Should be successful |
 * | 02 | Invoke get_radio_id API and verify that it extracts the radio id from the first radio_id TLV. | msg constructed from tlvBuffer, input: pointer to mac array initialized to {0}, expected output: retVal = true, mac equals mac1. | API returns true and the extracted radio id matches the first radio id (mac1) in the TLV buffer. | Should Pass |
 */
TEST(em_msg_t, get_radio_id_multiple_radio_id_tlvs) 
{
    std::cout << "Entering get_radio_id_multiple_radio_id_tlvs" << std::endl;
    unsigned char tlvBuffer[64];
    unsigned char mac1[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    unsigned char mac2[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    size_t offset = 0;
    write_tlv(tlvBuffer + offset, em_tlv_type_radio_id, mac1, 6);
    offset += TLV_HEADER_SIZE + 6;
    write_tlv(tlvBuffer + offset, em_tlv_type_radio_id, mac2, 6);
    offset += TLV_HEADER_SIZE + 6;
    unsigned char dummy_eom = 0;
    write_tlv(tlvBuffer + offset, em_tlv_type_eom, &dummy_eom, 0);
    offset += TLV_HEADER_SIZE;
    em_msg_t msg(tlvBuffer, offset);
    unsigned char mac[6] = {0};
    bool retVal = msg.get_radio_id(&mac);
    EXPECT_TRUE(retVal);
    EXPECT_EQ(0, std::memcmp(mac, mac1, 6));
    std::cout << "Exiting get_radio_id_multiple_radio_id_tlvs" << std::endl;
}
/**
 * @brief Validate get_radio_id behavior with an empty TLVs buffer
 *
 * This test verifies that when an em_msg_t object is created with a null TLV buffer and zero buffer length, 
 * the get_radio_id function correctly returns false upon invocation with a mac address pointer. 
 * This negative scenario ensures the API handles invalid or missing input gracefully.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 121@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                                      | Test Data                                                                                         | Expected Result                                            | Notes          |
 * | :--------------: | ---------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- | -------------- |
 * | 01               | Initialize the TLV buffer to nullptr and buffer length to 0, then create an em_msg_t object with these values     | tlvBuffer = nullptr, bufferLen = 0                                                                  | em_msg_t object is created with an empty TLV buffer         | Should be successful |
 * | 02               | Declare a mac array initialized to zeros and invoke get_radio_id with the mac address pointer                     | mac[6] = {0, 0, 0, 0, 0, 0}, output: retVal from get_radio_id call; input: msg object with empty TLV buffer | get_radio_id returns false (negative scenario)             | Should Fail    |
 * | 03               | Print the exit message indicating the end of the test execution                                                  | Console output messages for entering and exiting the test                                         | Exit message is printed to console                          | Should be successful |
 */
TEST(em_msg_t, get_radio_id_empty_tlvs_buffer)
{
    std::cout << "Entering get_radio_id_empty_tlvs_buffer test" << std::endl;
    unsigned char* tlvBuffer = nullptr;
    unsigned int bufferLen = 0;
    em_msg_t msg(tlvBuffer, bufferLen);
    unsigned char mac[6] = {0};
    bool retVal = msg.get_radio_id(reinterpret_cast<mac_address_t*>(mac));
    EXPECT_FALSE(retVal);
    std::cout << "Exiting get_radio_id_empty_tlvs_buffer test" << std::endl;
}
/**
 * @brief Verify valid retrieval of a TLV element from an em_msg_t object
 *
 * This test verifies that a TLV element written into a buffer using the write_tlv API can be successfully retrieved using the get_tlv method of the em_msg_t class. The test ensures that the retrieved TLV contains the expected value and confirms proper TLV identification and extraction.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 122@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- | -------------- | ----- |
 * | 01 | Write TLV data into the buffer using write_tlv function | input: tlvBuffer (pointer), offset = 0, type = em_tlv_type_al_mac_address, value = {10,20,30,40}, size = 4 | TLV data is written into the buffer and offset is updated (offset += TLV_HEADER_SIZE + 4) | Should Pass |
 * | 02 | Create an em_msg_t object using the TLV buffer and updated offset | input: tlvBuffer (with TLV data), offset = TLV_HEADER_SIZE + 4 | em_msg_t object is successfully constructed with the provided TLV data | Should be successful |
 * | 03 | Initialize search buffer and set the TLV type for the search | input: searchBuffer (zero initialized), TLV type field = em_tlv_type_al_mac_address | search_tlv is correctly configured with the desired TLV type in the search buffer | Should be successful |
 * | 04 | Invoke the get_tlv API on the em_msg_t object to retrieve the TLV | input: em_msg_t object, search_tlv (with TLV type = em_tlv_type_al_mac_address) | API returns true indicating successful retrieval of the TLV element | Should Pass |
 * | 05 | Validate the boolean result from get_tlv using EXPECT_TRUE | input: result (boolean from get_tlv) | The result is true as asserted by EXPECT_TRUE | Should be successful |
 * | 06 | Compare the retrieved TLV value with the expected value using memcmp and EXPECT_EQ | input: searchBuffer data after TLV header, expected value = {10,20,30,40} | Memory comparison returns 0 confirming the retrieved value matches the expected value | Should be successful |
 */
TEST(em_msg_t, get_tlv_valid_retrieval) 
{
    std::cout << "Entering get_tlv_valid_retrieval test" << std::endl;
    unsigned char tlvBuffer[32];
    unsigned char value[4] = {10, 20, 30, 40};
    size_t offset = 0;
    write_tlv(tlvBuffer + offset, em_tlv_type_al_mac_address, value, sizeof(value));
    offset += TLV_HEADER_SIZE + sizeof(value);
    em_msg_t msg(tlvBuffer, offset);
    unsigned char searchBuffer[TLV_HEADER_SIZE + sizeof(value)] = {};
    em_tlv_t *search_tlv = reinterpret_cast<em_tlv_t*>(searchBuffer);
    search_tlv->type = em_tlv_type_al_mac_address;
    bool result = msg.get_tlv(search_tlv);
    EXPECT_TRUE(result);
    EXPECT_EQ(0, std::memcmp(searchBuffer + TLV_HEADER_SIZE, value, sizeof(value)));
    std::cout << "Exiting get_tlv_valid_retrieval test" << std::endl;
}
/**
 * @brief Verify that get_tlv returns false when searching for a non-existent TLV in the message
 *
 * This test creates a TLV with type em_tlv_type_al_mac_address in a buffer and then attempts to retrieve a TLV of type em_tlv_type_device_bridging_cap from the message. The test validates that get_tlv returns false since the searched TLV does not exist in the message.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 123@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Write a TLV to buffer using write_tlv with type em_tlv_type_al_mac_address | tlvBuffer pointer, offset = 0, type = em_tlv_type_al_mac_address, value = 10,20,30,40, size = 4 | TLV is correctly written into tlvBuffer with header and value | Should be successful |
 * | 02 | Construct em_msg_t object with the TLV buffer and updated offset | tlvBuffer, offset = TLV_HEADER_SIZE + 4 | em_msg_t object is initialized with available TLV data | Should be successful |
 * | 03 | Prepare a search TLV by setting its type to em_tlv_type_device_bridging_cap | searchBuffer pointer, type = em_tlv_type_device_bridging_cap | searchBuffer correctly represents the search TLV with specified type | Should be successful |
 * | 04 | Invoke get_tlv to search for a non-existent TLV in the message | search_tlv pointer with type = em_tlv_type_device_bridging_cap | API returns false indicating TLV not found (validated with EXPECT_FALSE) | Should Fail |
 */
TEST(em_msg_t, get_tlv_no_matching_tlv) 
{
    std::cout << "Entering get_tlv_no_matching_tlv test"<< std::endl;
    unsigned char tlvBuffer[32];
    unsigned char value[4] = {10, 20, 30, 40};
    size_t offset = 0;
    write_tlv(tlvBuffer + offset, em_tlv_type_al_mac_address, value, sizeof(value));
    offset += TLV_HEADER_SIZE + sizeof(value);
    em_msg_t msg(tlvBuffer, offset);
    unsigned char searchBuffer[TLV_HEADER_SIZE + sizeof(value)] = {};
    em_tlv_t *search_tlv = reinterpret_cast<em_tlv_t*>(searchBuffer);
    search_tlv->type = em_tlv_type_device_bridging_cap;
    bool result = msg.get_tlv(search_tlv);
    EXPECT_FALSE(result);
    std::cout << "Exiting get_tlv_no_matching_tlv test" << std::endl;
}
/**
 * @brief Validate that get_tlv correctly retrieves the TLV with type em_tlv_type_device_info when multiple TLVs are present.
 *
 * This test verifies that when two TLVs (one for MAC address and one for device info) are written to a message buffer, the get_tlv API
 * is able to search for and retrieve the device info TLV correctly. The test ensures that the returned TLV data matches the expected value.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 124@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Write TLV for MAC address | offset = 0, type = em_tlv_type_mac_address, value = [5,6,7], length = 3 | TLV written to tlvBuffer at offset 0 | Should be successful |
 * | 02 | Write TLV for device info | offset updated, type = em_tlv_type_device_info, value = [8,9], length = 2 | TLV appended to tlvBuffer after the first TLV | Should be successful |
 * | 03 | Create message object | input: tlvBuffer, total length = updated offset value | em_msg_t object created containing both TLVs | Should be successful |
 * | 04 | Prepare search TLV header | searchBuffer with search_tlv->type set to em_tlv_type_device_info | searchBuffer initialized with target TLV type | Should be successful |
 * | 05 | Invoke get_tlv API | input: searchBuffer with type = em_tlv_type_device_info | get_tlv returns true indicating target TLV is found | Should Pass |
 * | 06 | Verify TLV data | input: searchBuffer (data starting from TLV_HEADER_SIZE), expected value = [8,9] | memcmp returns 0 confirming data match | Should Pass |
 */
TEST(em_msg_t, get_tlv_multiple_tlvs) 
{
    std::cout << "Entering get_tlv_multiple_tlvs test" << std::endl;
    unsigned char tlvBuffer[64];
    size_t offset = 0;
    unsigned char val1[3] = {5, 6, 7};
    unsigned char val2[2] = {8, 9};
    write_tlv(tlvBuffer + offset, em_tlv_type_mac_address, val1, sizeof(val1));
    offset += TLV_HEADER_SIZE + sizeof(val1);
    write_tlv(tlvBuffer + offset, em_tlv_type_device_info, val2, sizeof(val2));
    offset += TLV_HEADER_SIZE + sizeof(val2);
    em_msg_t msg(tlvBuffer, offset);
    unsigned char searchBuffer[TLV_HEADER_SIZE + sizeof(val2)] = {};
    em_tlv_t *search_tlv = reinterpret_cast<em_tlv_t*>(searchBuffer);
    search_tlv->type = em_tlv_type_device_info;
    bool result = msg.get_tlv(search_tlv);
    EXPECT_TRUE(result);
    EXPECT_EQ(0, std::memcmp(searchBuffer + TLV_HEADER_SIZE, val2, sizeof(val2)));
    std::cout << "Exiting get_tlv_multiple_tlvs test" << std::endl;
}
/**
 * @brief Verify that get_tlv correctly retrieves TLV values for each enumerated type using pointer-based access.
 *
 * This test writes TLV data for each TLV type into a buffer and then verifies that the em_msg_t object's get_tlv method
 * successfully finds and returns the correct TLV for each type. It also validates that the retrieved value matches the inserted value.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 125
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Write TLVs for each enumerated type into the buffer using write_tlv. | buffer, offset, types[i], val = {static_cast<unsigned char>(i)}, sizeof(val) | Buffer filled with valid TLV data for each type | Should be successful |
 * | 02 | Create an em_msg_t object using the populated buffer. | buffer, offset | Message object is correctly initialized with TLV data | Should be successful |
 * | 03 | Retrieve each TLV using get_tlv and validate the returned value. | itlv->type = types[i], itlv->value[0] expected = static_cast<unsigned char>(i) | API returns true and retrieved value matches expected | Should Pass |
 */
TEST(em_msg_t, get_tlv_loop_all_enum_types_by_pointer) 
{
    std::cout << "Entering get_tlv_loop_all_enum_types_by_pointer test" << std::endl;
    unsigned char buffer[1024];
    size_t offset = 0;
    for (size_t i = 1; i < TLV_TYPE_COUNT; ++i) {
        unsigned char val[] = { static_cast<unsigned char>(i) };
        write_tlv(buffer + offset, types[i], val, sizeof(val));
        offset += sizeof(em_tlv_t) + sizeof(val);
    }
    em_msg_t msg(buffer, offset);
    for (size_t i = 1; i < TLV_TYPE_COUNT; ++i) {
        size_t tlv_size = sizeof(em_tlv_t) + 1;
        em_tlv_t* itlv = reinterpret_cast<em_tlv_t*>(new unsigned char[tlv_size]);
        itlv->type = types[i];
        bool found = msg.get_tlv(itlv);
        EXPECT_TRUE(found) << "get_tlv failed for type = 0x";
        EXPECT_EQ(itlv->value[0], static_cast<unsigned char>(i));
        delete[] reinterpret_cast<unsigned char*>(itlv);
    }
    std::cout << "Exiting get_tlv_loop_all_enum_types_by_pointer test" << std::endl;
}
/**
 * @brief Test to verify that get_tlv correctly handles TLV with zero-length value.
 *
 * This test verifies that when a TLV header is written with no data (zero-length value)
 * using write_tlv, the get_tlv function should correctly locate and retrieve the TLV from
 * the message buffer. The test ensures that the API call returns true indicating successful
 * identification of the TLV, even when no value is present.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 126@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Write TLV header with a zero-length value using write_tlv API. | input: tlvBuffer+offset, type = em_tlv_type_device_info; dummy = 0; length = 0; output: TLV header written at tlvBuffer | TLV header should be correctly written without any value. | Should Pass |
 * | 02 | Construct the message object using the TLV buffer. | input: tlvBuffer, offset = TLV_HEADER_SIZE; output: em_msg_t msg instance | Message object should be instantiated with the TLV header data. | Should be successful |
 * | 03 | Prepare the search TLV by setting the type in searchBuffer. | input: searchBuffer (with zero initialization), set type = em_tlv_type_device_info; output: search_tlv pointer with configured type | Search TLV should be correctly prepared for the lookup. | Should be successful |
 * | 04 | Invoke get_tlv on the message with the prepared search TLV. | input: msg, search_tlv pointer; output: boolean result from get_tlv | get_tlv should return true, validating that the TLV was found. | Should Pass |
 */
TEST(em_msg_t, get_tlv_zero_length_value) 
{
    std::cout << "Entering get_tlv_zero_length_value test" << std::endl;
    unsigned char tlvBuffer[16];
    size_t offset = 0;
    unsigned char dummy = 0;
    write_tlv(tlvBuffer + offset, em_tlv_type_device_info, &dummy, 0);
    offset += TLV_HEADER_SIZE;  // only header, no value
    em_msg_t msg(tlvBuffer, offset);
    unsigned char searchBuffer[TLV_HEADER_SIZE] = {};
    em_tlv_t *search_tlv = reinterpret_cast<em_tlv_t*>(searchBuffer);
    search_tlv->type = em_tlv_type_device_info;
    bool result = msg.get_tlv(search_tlv);
    EXPECT_TRUE(result);
    std::cout << "Exiting get_tlv_zero_length_value test" << std::endl;
}
/**
 * @brief Validates that the get_tlv function retrieves a valid TLV when it is located at the beginning of the buffer.
 *
 * This test creates a TLV with a MAC address at the beginning of the buffer and then verifies that the get_tlv API correctly retrieves it.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 127@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:** 
 * | Variation / Step | Description                                                                                   | Test Data                                                                                                                  | Expected Result                                                                                                    | Notes         |
 * | :--------------: | --------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | ------------- |
 * | 01               | Write a TLV with a MAC address into the buffer and update the offset accordingly              | input: tlvBuffer pointer, type = em_tlv_type_mac_address, value = {0xAA, 0xBB, 0xCC, 0xDD}, size = 4, offset updated      | The message buffer is correctly populated with the TLV data and the offset reflects the TLV size                  | Should be successful |
 * | 02               | Instantiate the message object and call the get_tlv API to retrieve the TLV from the message    | input: msg object created from tlvBuffer and offset, searchBuffer with TLV type em_tlv_type_mac_address, output from get_tlv  | get_tlv returns true and the retrieved value matches the original TLV value as validated by memcmp comparison         | Should Pass   |
 */
TEST(em_msg_t, get_tlv_valid_tlv_at_beginning) 
{
    std::cout << "Entering get_tlv_valid_tlv_at_beginning test" << std::endl;
    unsigned char tlvBuffer[64];
    size_t offset = 0;
    unsigned char value[4] = {0xAA, 0xBB, 0xCC, 0xDD};
    write_tlv(tlvBuffer + offset, em_tlv_type_mac_address, value, sizeof(value));
    offset += TLV_HEADER_SIZE + sizeof(value);
    em_msg_t msg(tlvBuffer, offset);
    unsigned char searchBuffer[TLV_HEADER_SIZE + sizeof(value)] = {};
    em_tlv_t *search_tlv = reinterpret_cast<em_tlv_t*>(searchBuffer);
    search_tlv->type = em_tlv_type_mac_address;
    bool result = msg.get_tlv(search_tlv);
    EXPECT_TRUE(result);
    EXPECT_EQ(0, std::memcmp(searchBuffer + TLV_HEADER_SIZE, value, sizeof(value)));
    std::cout << "Exiting get_tlv_valid_tlv_at_beginning test" << std::endl;
}
/**
 * @brief Validate extraction of a valid TLV located in the middle of the TLV message buffer
 *
 * This test verifies that the get_tlv API correctly finds a TLV of type em_tlv_type_link_metric when it is placed in the middle of a message buffer containing multiple TLVs. The test builds a TLV buffer with three TLVs, where the second TLV is the target of the lookup, and validates that the proper TLV is returned.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 128@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                 | Test Data                                                                                                            | Expected Result                                                                                  | Notes            |
 * | :--------------: | ------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ | ---------------- |
 * | 01               | Write the first TLV (device_info) into the buffer                                           | tlvBuffer + offset, em_tlv_type_device_info, val1 = 0x11,0x12, size = 2                                                | TLV written correctly to the buffer                                                            | Should be successful |
 * | 02               | Increment the offset after writing the first TLV                                            | offset updated by TLV_HEADER_SIZE + sizeof(val1)                                                                       | Offset correctly incremented by TLV_HEADER_SIZE + 2                                              | Should be successful |
 * | 03               | Write the second TLV (link_metric) into the buffer (target TLV)                               | tlvBuffer + offset, em_tlv_type_link_metric, val2 = 0x21,0x22,0x23, size = 3                                            | TLV written correctly to the buffer                                                            | Should be successful |
 * | 04               | Increment the offset after writing the second TLV                                           | offset updated by TLV_HEADER_SIZE + sizeof(val2)                                                                       | Offset correctly incremented by TLV_HEADER_SIZE + 3                                              | Should be successful |
 * | 05               | Write the third TLV (device_bridging_cap) into the buffer                                     | tlvBuffer + offset, em_tlv_type_device_bridging_cap, val3 = 0x31,0x32, size = 2                                          | TLV written correctly to the buffer                                                            | Should be successful |
 * | 06               | Create the message object, prepare the search buffer with header for the second TLV, and call get_tlv | msg constructed with tlvBuffer and offset, searchBuffer contains header with type em_tlv_type_link_metric, TLV_HEADER_SIZE and sizeof(val2)  | API returns true and the content in the TLV body matches val2 after TLV header                      | Should Pass      |
 */
TEST(em_msg_t, get_tlv_valid_tlv_in_middle)
{
    std::cout << "Entering get_tlv_valid_tlv_in_middle test" << std::endl;
    unsigned char tlvBuffer[64];
    size_t offset = 0;
    unsigned char val1[2] = {0x11, 0x12};
    unsigned char val2[3] = {0x21, 0x22, 0x23};
    unsigned char val3[2] = {0x31, 0x32};
    write_tlv(tlvBuffer + offset, em_tlv_type_device_info, val1, sizeof(val1));
    offset += TLV_HEADER_SIZE + sizeof(val1);
    write_tlv(tlvBuffer + offset, em_tlv_type_link_metric, val2, sizeof(val2));
    offset += TLV_HEADER_SIZE + sizeof(val2);
    write_tlv(tlvBuffer + offset, em_tlv_type_device_bridging_cap, val3, sizeof(val3));
    offset += TLV_HEADER_SIZE + sizeof(val3);
    em_msg_t msg(tlvBuffer, offset);
    unsigned char searchBuffer[TLV_HEADER_SIZE + sizeof(val2)] = {};
    em_tlv_t *search_tlv = reinterpret_cast<em_tlv_t*>(searchBuffer);
    search_tlv->type = em_tlv_type_link_metric;
    bool result = msg.get_tlv(search_tlv);
    EXPECT_TRUE(result);
    EXPECT_EQ(0, std::memcmp(searchBuffer + TLV_HEADER_SIZE, val2, sizeof(val2)));
    std::cout << "Exiting get_tlv_valid_tlv_in_middle test"<< std::endl;
}
/**
 * @brief Validate that get_tlv returns false when the searched TLV is not present.
 *
 * This test verifies that the get_tlv API function returns false when attempting to retrieve a TLV of a type that does not exist in the constructed message. The test creates a message with TLVs for device bridging capability, wsc, and an end-of-message indicator, and then searches for a TLV with the MAC address type which is not present.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 129@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                         | Test Data                                                                                                                          | Expected Result                                                | Notes      |
 * | :--------------: | --------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- | ---------- |
 * | 01               | Create a message with TLVs (device bridging capability, wsc, and eom) and search for a MAC TLV.      | tlvBuffer: contains TLVs with device bridging capability, wsc, and eom; search_tlv->type = em_tlv_type_mac_address                  | get_tlv returns false; EXPECT_FALSE(result) assertion passes     | Should Fail|
 */
TEST(em_msg_t, get_tlv_not_present) 
{
    std::cout << "Entering get_tlv_not_present test" << std::endl;
    unsigned char tlvBuffer[64];
    size_t offset = 0;
    unsigned char val1[2] = {0x44, 0x45};
    unsigned char val2[2] = {0x55, 0x56};
    write_tlv(tlvBuffer + offset, em_tlv_type_device_bridging_cap, val1, sizeof(val1));
    offset += TLV_HEADER_SIZE + sizeof(val1);
    write_tlv(tlvBuffer + offset, em_tlv_type_wsc, val2, sizeof(val2));
    offset += TLV_HEADER_SIZE + sizeof(val2);
    unsigned char dummy_eom = 0;
    write_tlv(tlvBuffer + offset,em_tlv_type_eom, &dummy_eom, 0);
    offset += TLV_HEADER_SIZE;
    em_msg_t msg(tlvBuffer, offset);
    unsigned char searchBuffer[TLV_HEADER_SIZE] = {};
    em_tlv_t *search_tlv = reinterpret_cast<em_tlv_t*>(searchBuffer);
    search_tlv->type = em_tlv_type_mac_address;
    bool result = msg.get_tlv(search_tlv);
    EXPECT_FALSE(result);
    std::cout << "Exiting get_tlv_not_present test"<< std::endl;
}
/**
 * @brief Verify that get_tlv successfully retrieves an existing single TLV from the message
 *
 * This test verifies that after writing a single TLV into a buffer and constructing an em_msg_t
 * object, the get_tlv API correctly returns a valid pointer to the TLV. Additionally, it checks that
 * the retrieved TLV contains the expected length and value. This functionality is important to ensure
 * proper message parsing for device information.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 130@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                       | Test Data                                                                                                                       | Expected Result                                                                                                          | Notes            |
 * | :--------------: | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- | ---------------- |
 * | 01               | Print the entering test message                                                                   | No input arguments                                                                                                                | "Entering get_tlv_existing_single_tlv test" is printed to console                                                       | Should be successful |
 * | 02               | Write the TLV into the buffer using write_tlv                                                     | input: buffer pointer (buffer+offset), type = em_tlv_type_device_info, val = {1,2,3,4,5}, size = 5, TLV_HEADER_SIZE        | TLV is successfully written in buffer and offset is updated                                                            | Should be successful |
 * | 03               | Construct the em_msg_t object from the buffer                                                     | input: buffer, offset (updated after writing TLV)                                                                                 | em_msg_t object is created correctly with the provided buffer                                                           | Should be successful |
 * | 04               | Retrieve TLV using get_tlv API from the em_msg_t object                                             | input: tlv_type = em_tlv_type_device_info, output: pointer to TLV                                                                 | tlv_ptr is not nullptr (EXPECT_NE assertion passes)                                                                     | Should Pass      |
 * | 05               | Validate the TLV length and TLV value using assertions                                              | input: tlv_ptr->len (converted using ntohs) should equal size of {1,2,3,4,5}, memcmp(tlv_ptr->value, val, sizeof(val))             | Length equals sizeof(val) and memcmp returns 0 (EXPECT_EQ assertions pass)                                                | Should Pass      |
 * | 06               | Print the exiting test message                                                                    | No input arguments                                                                                                                | "Exiting get_tlv_existing_single_tlv test" is printed to console                                                        | Should be successful |
 */
TEST(em_msg_t, get_tlv_existing_single_tlv) 
{
    std::cout << "Entering get_tlv_existing_single_tlv test" << std::endl;
    unsigned char buffer[16];
    unsigned char val[] = {1, 2, 3, 4, 5};
    size_t offset = 0;
    write_tlv(buffer + offset, em_tlv_type_device_info, val, sizeof(val));
    offset += TLV_HEADER_SIZE + sizeof(val);
    em_msg_t msg(buffer, offset);
    em_tlv_t* tlv_ptr = msg.get_tlv(em_tlv_type_device_info);
    EXPECT_NE(tlv_ptr, nullptr);
    EXPECT_EQ(ntohs(tlv_ptr->len), sizeof(val));
    EXPECT_EQ(0, std::memcmp(tlv_ptr->value, val, sizeof(val)));
    std::cout << "Exiting get_tlv_existing_single_tlv test" << std::endl;
}
/**
 * @brief Test that get_tlv returns nullptr when the requested TLV is not present.
 *
 * This test verifies that when an em_msg_t object does not contain a TLV of the specified type 
 * (in this case, em_tlv_type_mac_address), the get_tlv method returns nullptr. This behavior is 
 * essential to ensure that the API correctly handles cases when the requested TLV is absent, preventing 
 * potential invalid memory accesses.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 131@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize a buffer, write a TLV with type em_tlv_type_eom (with no data), create an em_msg_t object using the buffer, and then call get_tlv with type em_tlv_type_mac_address. | buffer: unsigned char[16], offset: 0, write_tlv args: (buffer+offset, em_tlv_type_eom, nullptr, 0), TLV_HEADER_SIZE, get_tlv arg: em_tlv_type_mac_address | get_tlv returns nullptr, as verified by EXPECT_EQ | Should Pass |
 */
TEST(em_msg_t, get_tlv_not_found) 
{
    std::cout << "Entering get_tlv_not_found test" << std::endl;
    unsigned char buffer[16];
    size_t offset = 0;
    write_tlv(buffer + offset, em_tlv_type_eom, nullptr, 0);
    offset += TLV_HEADER_SIZE;
    em_msg_t msg(buffer, offset);
    em_tlv_t* tlv_ptr = msg.get_tlv(em_tlv_type_mac_address);
    EXPECT_EQ(tlv_ptr, nullptr);
    std::cout << "Exiting get_tlv_not_found test" << std::endl;
}
/**
 * @brief Verify that get_tlv returns the first TLV when multiple duplicate TLVs exist.
 *
 * This test function verifies that when multiple TLVs of the same type are written into a buffer, 
 * the em_msg_t::get_tlv method returns the first TLV instance. The test writes two TLVs with identical 
 * types (em_tlv_type_mac_address) and then asserts that the returned TLV pointer is not nullptr and that 
 * its value matches the first written TLV's value.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 132@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize buffer and offset, then write first TLV of type em_tlv_type_mac_address with value {1,2,3} | buffer = allocated 16 bytes, offset = 0, type = em_tlv_type_mac_address, val1 = 1,2,3, TLV_HEADER_SIZE | TLV is written successfully without error | Should be successful |
 * | 02 | Update offset and write second TLV (duplicate) of same type with value {10,11,12,13} | offset = previous offset + sizeof(val1) + TLV_HEADER_SIZE, type = em_tlv_type_mac_address, val2 = 10,11,12,13, TLV_HEADER_SIZE | TLV is written successfully without error | Should be successful |
 * | 03 | Create em_msg_t object with the buffer and invoke get_tlv with type em_tlv_type_mac_address | buffer, offset, em_msg_t object, call get_tlv(em_tlv_type_mac_address) | Returns a non-null pointer, and memory comparison of the TLV's value area with val1 returns 0 | Should Pass |
 */
TEST(em_msg_t, get_tlv_multiple_duplicate_tlv) 
{
    std::cout << "Entering get_tlv_multiple_duplicate_tlv test" << std::endl;
    unsigned char buffer[16];
    size_t offset = 0;
    unsigned char val1[] = {1, 2, 3};
    unsigned char val2[] = {10, 11, 12, 13};
    write_tlv(buffer + offset, em_tlv_type_mac_address, val1, sizeof(val1));
    offset += sizeof(val1) + TLV_HEADER_SIZE;
    write_tlv(buffer + offset, em_tlv_type_mac_address, val2, sizeof(val2));
    offset += sizeof(val2) + TLV_HEADER_SIZE;
    em_msg_t msg(buffer, offset);
    em_tlv_t* tlv_ptr = msg.get_tlv(em_tlv_type_mac_address);
    ASSERT_NE(tlv_ptr, nullptr);
    EXPECT_EQ(0, std::memcmp(reinterpret_cast<unsigned char*>(tlv_ptr) + TLV_HEADER_SIZE, val1, sizeof(val1)));
    std::cout << "Exiting get_tlv_multiple_duplicate_tlv test" << std::endl;
}
/**
 * @brief Test get_tlv_loop_all_enum_types API for correct TLV writing and retrieval
 *
 * This test verifies that for each TLV type in the valid range (excluding reserved/invalid indices),
 * the write_tlv function correctly writes the TLV into a contiguous memory buffer and that the em_msg_t
 * object properly retrieves the corresponding TLV using the get_tlv method. It ensures that the TLV payload
 * matches the expected value for each type.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 133
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                                                     | Test Data                                                                                                                       | Expected Result                                                                                                      | Notes          |
 * | :--------------: | -------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- | -------------- |
 * | 01               | Write TLV entries for each valid enum type using write_tlv function.                                                             | buffer = allocated 1024 bytes, offset = 0, type = types[i] for i = 1 to TLV_TYPE_COUNT-1, val = { static_cast<unsigned char>(i) } | TLV data is correctly written into the buffer, offset updated appropriately                                          | Should be successful |
 * | 02               | Retrieve and validate each TLV entry by invoking get_tlv, and compare the payload against the expected value (i).                  | msg (constructed from buffer and offset), type = types[i] for i = 1 to TLV_TYPE_COUNT-1, expected payload = i (as unsigned char)        | API returns a non-null pointer and the memory comparison for payload returns 0 as expected                              | Should Pass    |
 */
TEST(em_msg_t, get_tlv_loop_all_enum_types) 
{
    std::cout << "Entering get_tlv_loop_all_enum_types test" << std::endl;
    unsigned char buffer[1024];
    size_t offset = 0;
    for (size_t i = 1; i < TLV_TYPE_COUNT; ++i) {
        unsigned char val[] = { static_cast<unsigned char>(i) };
        write_tlv(buffer + offset, types[i], val, sizeof(val));
        offset += sizeof(val) + sizeof(em_tlv_t);
    }
    em_msg_t msg(buffer, offset);
    for (size_t i = 1; i < TLV_TYPE_COUNT; ++i) {
        em_tlv_t* tlv_ptr = msg.get_tlv(types[i]);
        ASSERT_NE(tlv_ptr, nullptr) << "get_tlv failed for type = 0x" 
                                    << std::hex << static_cast<int>(types[i]);
        EXPECT_EQ(0, std::memcmp(reinterpret_cast<unsigned char*>(tlv_ptr) + TLV_HEADER_SIZE, 
                                 &i, sizeof(unsigned char)));
    }
    std::cout << "Exiting get_tlv_loop_all_enum_types test" << std::endl;
}
/**
 * @brief Verify that get_tlv returns nullptr when TLV data is empty.
 *
 * This test case validates that when a TLV header is written with type em_tlv_type_eom and no accompanying data, the get_tlv API correctly returns a nullptr. This ensures that the API handles cases where the TLV structure is incomplete or empty by not falsely identifying any valid data.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 134@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize the buffer and offset for TLV operations | buffer: uninitialized array of 3 bytes, offset = 0 | Buffer is prepared for TLV writing | Should be successful |
 * | 02 | Write a TLV with type em_tlv_type_eom and no additional data | input: buffer+offset, type = em_tlv_type_eom, data = nullptr, data length = 0 | TLV header is written to the buffer, offset updated by TLV_HEADER_SIZE | Should be successful |
 * | 03 | Create an em_msg_t object with the updated buffer and offset | input: buffer, offset = TLV_HEADER_SIZE | em_msg_t object is instantiated with the given buffer and offset | Should be successful |
 * | 04 | Retrieve the TLV using get_tlv API with type em_tlv_type_eom | input: tlv_type = em_tlv_type_eom | API returns nullptr indicating no valid TLV is present | Should Pass |
 */
TEST(em_msg_t, get_tlv_empty_buffer) 
{
    std::cout << "Entering get_tlv_empty_buffer test" << std::endl;
    unsigned char buffer[3];
    size_t offset = 0;
    write_tlv(buffer + offset, em_tlv_type_eom, nullptr, 0);
    offset += TLV_HEADER_SIZE;
    em_msg_t msg(buffer, offset);
    em_tlv_t* tlv_ptr = msg.get_tlv(em_tlv_type_eom);
    ASSERT_EQ(tlv_ptr, nullptr);
    std::cout << "Exiting get_tlv_empty_buffer test" << std::endl;
}
/**
 * @brief Verify that get_tlv returns a valid pointer and the correct TLV content when a matching TLV is present in the message buffer
 *
 * This test checks that the function em_msg_t::get_tlv correctly retrieves a TLV of type em_tlv_type_device_info from a pre-populated message buffer.
 * It first writes a TLV into the buffer with a known value and length, then attempts to retrieve it and verifies that the returned TLV pointer is not null,
 * the length field matches the expected value, and the TLV value is correctly stored.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 135@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                  | Test Data                                                                                                   | Expected Result                                                             | Notes           |
 * | :----:           | -------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- | --------------- |
 * | 01               | Print entry log for the test                                                                 | N/A                                                                                                         | "Entering get_tlv_found_case test" printed                                  | Should be successful |
 * | 02               | Write a TLV into the buffer using write_tlv                                                   | buffer = [16 bytes], type = em_tlv_type_device_info, value = {0xDE, 0xAD, 0xBE, 0xEF}, value_length = 4   | TLV is written into buffer correctly                                        | Should be successful |
 * | 03               | Retrieve the TLV by invoking em_msg_t::get_tlv from the buffer with the specified type         | buffer cast to em_tlv_t*, buffer length = 16, type = em_tlv_type_device_info                                  | Returned pointer is not nullptr                                             | Should Pass     |
 * | 04               | Verify that the TLV length field matches the expected value after ntohs conversion              | Expected length = 4                                                                                         | ntohs(ret->len) equals 4                                                     | Should Pass     |
 * | 05               | Compare the TLV value with the original value using std::memcmp                                | TLV value from ret and expected value = {0xDE, 0xAD, 0xBE, 0xEF}                                              | std::memcmp returns 0 (values match)                                        | Should Pass     |
 * | 06               | Print exit log for the test                                                                  | N/A                                                                                                         | "Exiting get_tlv_found_case test" printed                                   | Should be successful |
 */
TEST(em_msg_t, get_tlv_found_case) 
{
    std::cout << "Entering get_tlv_found_case test" << std::endl;
    unsigned char buffer[16];
    unsigned char value[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    write_tlv(buffer, em_tlv_type_device_info, value, sizeof(value));
    em_tlv_t* ret = em_msg_t::get_tlv(reinterpret_cast<em_tlv_t*>(buffer), sizeof(buffer), em_tlv_type_device_info);
    ASSERT_NE(ret, nullptr);
    EXPECT_EQ(ntohs(ret->len), sizeof(value));
    EXPECT_EQ(0, std::memcmp(ret->value, value, sizeof(value)));
    std::cout << "Exiting get_tlv_found_case test" << std::endl;
}
/**
 * @brief Test to verify that get_tlv returns nullptr when the requested TLV is not found.
 *
 * This test writes a TLV of type em_tlv_type_device_info into a buffer and then attempts to retrieve
 * a TLV of type em_tlv_type_mac_address using em_msg_t::get_tlv. Since no TLV of type em_tlv_type_mac_address
 * is written into the buffer, the expected behavior is that get_tlv returns a nullptr.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 136@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Write a TLV of type em_tlv_type_device_info into the buffer | buffer (unsigned char[16]), value = {0x01, 0x02}, type = em_tlv_type_device_info, size = 2 | TLV is successfully written into the buffer | Should be successful |
 * | 02 | Retrieve TLV of type em_tlv_type_mac_address from the buffer using em_msg_t::get_tlv | buffer (reinterpret_cast<em_tlv_t*>(buffer)), size = 16, type = em_tlv_type_mac_address | API returns nullptr indicating TLV not found | Should Pass |
 * | 03 | Verify that the returned pointer is nullptr using ASSERT_EQ | ret pointer obtained from get_tlv | ASSERT_EQ confirms that ret is nullptr | Should Pass |
 */
TEST(em_msg_t, get_tlv_not_found_case) 
{
    std::cout << "Entering get_tlv_not_found_case test" << std::endl;
    unsigned char buffer[16];
    unsigned char value[2] = {0x01, 0x02};
    write_tlv(buffer, em_tlv_type_device_info, value, sizeof(value));
    em_tlv_t* ret = em_msg_t::get_tlv(reinterpret_cast<em_tlv_t*>(buffer),sizeof(buffer),em_tlv_type_mac_address);
    ASSERT_EQ(ret, nullptr);
    std::cout << "Exiting get_tlv_not_found_case test" << std::endl;
}
/**
 * @brief Verify get_tlv API retrieves the correct TLV when multiple TLVs are present
 *
 * This test verifies the functionality of the get_tlv API by writing two TLVs into a buffer and then retrieving the TLV corresponding to em_tlv_type_mac_address. It confirms that the returned TLV is not null, its length is correct, and its value matches the expected data.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 137
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                                         | Test Data                                                                                                 | Expected Result                                                                               | Notes            |
 * | :--------------: | ------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- | ---------------- |
 * | 01               | Write first TLV for device info into the buffer                                                                     | input: buffer pointer with offset = 0, tlv type = em_tlv_type_device_info, value = {0x11, 0x12}           | TLV written correctly into buffer                                                           | Should be successful |
 * | 02               | Write second TLV for mac address into the buffer                                                                    | input: buffer pointer with updated offset, tlv type = em_tlv_type_mac_address, value = {0x21, 0x22, 0x23}   | TLV written correctly into buffer                                                           | Should be successful |
 * | 03               | Retrieve the mac address TLV using get_tlv API                                                                        | input: buffer pointer cast to em_tlv_t*, length = calculated total length, tlv type = em_tlv_type_mac_address | Returned pointer must not be nullptr, and internal TLV header and value should match expected values | Should Pass      |
 * | 04               | Validate the retrieved TLV’s length and value using assertion checks                                                  | input: retrieved TLV pointer, expected length = 3, expected value = {0x21, 0x22, 0x23}                          | Assertions: ASSERT_NE on TLV pointer, EXPECT_EQ for length and value verification (memcmp comparison)  | Should Pass      |
 */
TEST(em_msg_t, get_tlv_multiple_tlvs_input)
{
    std::cout << "Entering get_tlv_multiple_tlvs_input test" << std::endl;
    unsigned char buffer[32];
    unsigned char val1[2] = {0x11, 0x12};
    unsigned char val2[3] = {0x21, 0x22, 0x23};
    size_t offset = 0;
    write_tlv(buffer + offset, em_tlv_type_device_info, val1, sizeof(val1));
    offset += TLV_HEADER_SIZE + sizeof(val1);
    write_tlv(buffer + offset, em_tlv_type_mac_address, val2, sizeof(val2));
    em_tlv_t* ret = em_msg_t::get_tlv(reinterpret_cast<em_tlv_t*>(buffer), offset + TLV_HEADER_SIZE + sizeof(val2), em_tlv_type_mac_address);
    ASSERT_NE(ret, nullptr);
    EXPECT_EQ(ntohs(ret->len), sizeof(val2));
    EXPECT_EQ(0, std::memcmp(ret->value, val2, sizeof(val2)));
    std::cout << "Exiting get_tlv_multiple_tlvs_input test" << std::endl;
}
/**
 * @brief Test get_tlv function for all TLV enum types using a buffer
 *
 * This test verifies that for each TLV enum type (excluding 0), a TLV entry can be written into a buffer using write_tlv and then successfully retrieved using em_msg_t::get_tlv. The test ensures that each retrieved TLV element is not null and contains the correct value corresponding to its type.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 138
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Populate the buffer with TLV entries by iterating through all enum types (excluding 0) and calling write_tlv | buffer: unsigned char array of size 1024, offset: 0, types[i] for i from 1 to TLV_TYPE_COUNT-1, val: {static_cast<unsigned char>(i)} | Buffer is correctly filled with valid TLV entries for each type | Should Pass |
 * | 02 | Retrieve each TLV entry using get_tlv and validate that the retrieved value matches the expected type value | buffer pointer to TLV elements, total offset after writing, types[i] for i from 1 to TLV_TYPE_COUNT-1, expected output: found->value[0] equals static_cast<unsigned char>(i) | Each TLV element is found (not null) and the value is equal to the type index | Should Pass |
 */
TEST(em_msg_t, get_tlv_loop_all_enum_types_with_buffer) 
{
    std::cout << "Entering get_tlv_loop_all_enum_types_with_buffer test" << std::endl;
    unsigned char buffer[1024];
    size_t offset = 0;
    for (size_t i = 1; i < TLV_TYPE_COUNT; ++i) {
        unsigned char val[] = { static_cast<unsigned char>(i) };
        write_tlv(buffer + offset, types[i], val, sizeof(val));
        offset += sizeof(em_tlv_t) + sizeof(val); // TLV header + value
    }
    for (size_t i = 1; i < TLV_TYPE_COUNT; ++i) {
        em_tlv_t* found = em_msg_t::get_tlv(reinterpret_cast<em_tlv_t*>(buffer), static_cast<unsigned int>(offset), types[i]);
        ASSERT_NE(found, nullptr);
        EXPECT_EQ(found->value[0], static_cast<unsigned char>(i));
    }
    std::cout << "Exiting get_tlv_loop_all_enum_types_with_buffer test" << std::endl;
}
/**
 * @brief Validate that get_tlv successfully retrieves TLV from the beginning of the buffer
 *
 * This test verifies that the get_tlv API correctly identifies and returns a pointer to the TLV
 * element written at the start of the buffer. The test confirms that the returned TLV pointer is non-null,
 * the length value is as expected after converting network to host byte order, and the TLV value matches the input.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 139@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Write TLV into an 8-byte buffer and retrieve it using get_tlv. | buffer = 8-byte array, val = {0xAA,0xBB,0xCC}, type = em_tlv_type_mac_address, len = 3 | Retrieved TLV pointer is non-null; ntohs(ret->len) equals 3; memcmp(ret->value, val, 3) equals 0 | Should Pass |
 */
TEST(em_msg_t, get_tlv_at_buffer_start) 
{
    std::cout << "Entering get_tlv_at_buffer_start test" << std::endl;
    unsigned char buffer[8];
    unsigned char val[3] = {0xAA, 0xBB, 0xCC};
    write_tlv(buffer, em_tlv_type_mac_address, val, sizeof(val));
    em_tlv_t* ret = em_msg_t::get_tlv(reinterpret_cast<em_tlv_t*>(buffer), sizeof(buffer), em_tlv_type_mac_address);
    ASSERT_NE(ret, nullptr);
    EXPECT_EQ(ntohs(ret->len), sizeof(val));
    EXPECT_EQ(0, std::memcmp(ret->value, val, sizeof(val)));
    std::cout << "Exiting get_tlv_at_buffer_start test" << std::endl;
}
/**
 * @brief Verify that the get_tlv function correctly retrieves the MAC address TLV located at the end of the TLV buffer.
 *
 * This test validates that when two TLV entries are written into a buffer—a device info TLV and a MAC address TLV—the get_tlv API correctly locates and returns the MAC address TLV from the buffer. The test further asserts that the returned TLV is not null, its length matches the expected value, and its value data is identical to the MAC address written.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 140@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                         | Test Data                                                                                                                                                    | Expected Result                                                                                                  | Notes         |
 * | :--------------: | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------- | ------------- |
 * | 01               | Initialize a TLV buffer and define TLV values.                                                     | buffer size = 16, val1 = {0x01, 0x02}, val2 = {0x11, 0x12, 0x13, 0x14}                                                                                      | Buffer and value arrays are allocated with the specified initial values.                                        | Should be successful |
 * | 02               | Write the device info TLV into the buffer using write_tlv.                                         | input: buffer pointer, type = em_tlv_type_device_info, value = {0x01, 0x02}, size = 2                                                                          | Device info TLV is written successfully at the beginning of the buffer.                                         | Should be successful |
 * | 03               | Write the MAC address TLV into the buffer at an offset using write_tlv.                             | input: buffer pointer + 5, type = em_tlv_type_mac_address, value = {0x11, 0x12, 0x13, 0x14}, size = 4                                                           | MAC address TLV is written successfully at the specified offset in the buffer.                                    | Should be successful |
 * | 04               | Invoke get_tlv to retrieve the MAC address TLV from the constructed buffer.                        | input: TLV pointer cast from buffer, total length = TLV_HEADER_SIZE + 2 + TLV_HEADER_SIZE + 4, type = em_tlv_type_mac_address                                          | API returns a non-null pointer to the MAC address TLV.                                                            | Should Pass   |
 * | 05               | Assert the retrieved TLV length using ntohs to ensure it equals the size of the MAC address TLV value | input: retrieved TLV->len, expected length = 4                                                                                                                 | The length field of the retrieved TLV, after network-to-host conversion, equals 4.                                | Should Pass   |
 * | 06               | Verify that the TLV value data matches the original MAC address value using memcmp.                 | input: retrieved TLV->value vs. val2 array, expected comparison result = 0                                                                                       | Memory comparison returns 0 indicating the TLV value data is identical to the original MAC address value.         | Should Pass   |
 */
TEST(em_msg_t, get_tlv_at_buffer_end)
{
    std::cout << "Entering get_tlv_at_buffer_end test" << std::endl;
    unsigned char buffer[16];
    unsigned char val1[2] = {0x01, 0x02};
    unsigned char val2[4] = {0x11, 0x12, 0x13, 0x14};
    write_tlv(buffer, em_tlv_type_device_info, val1, sizeof(val1));
    write_tlv(buffer + 5, em_tlv_type_mac_address, val2, sizeof(val2));
    em_tlv_t* ret = em_msg_t::get_tlv(reinterpret_cast<em_tlv_t*>(buffer), TLV_HEADER_SIZE + sizeof(val1) + TLV_HEADER_SIZE + sizeof(val2), em_tlv_type_mac_address);
    ASSERT_NE(ret, nullptr);
    EXPECT_EQ(ntohs(ret->len), sizeof(val2));
    EXPECT_EQ(0, std::memcmp(ret->value, val2, sizeof(val2)));
    std::cout << "Exiting get_tlv_at_buffer_end test" << std::endl;
}
/**
 * @brief Test get_tlv API with zero buffer length input
 *
 * This test prepares a TLV buffer with device info by using write_tlv, then calls get_tlv with a buffer length of zero to verify that the API correctly handles an invalid (zero) buffer length by returning nullptr.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 141
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Prepare a TLV buffer by writing device info using write_tlv function. | buffer = unsigned char[16] (uninitialized), val = {0x01, 0x02}, size = 2, tlv type = em_tlv_type_device_info | TLV buffer is populated with valid TLV data | Should be successful |
 * | 02 | Invoke get_tlv with a buffer length of zero and check the return value. | buffer = pointer to TLV buffer, length = 0, tlv type = em_tlv_type_device_info | Return value is nullptr (API returns error for zero length) and assertion passes | Should Pass |
 */

TEST(em_msg_t, get_tlv_zero_buffer_length_input) 
{
    std::cout << "Entering get_tlv_zero_buffer_length_input test" << std::endl;
    unsigned char buffer[16];
    unsigned char val[2] = {0x01, 0x02};
    write_tlv(buffer, em_tlv_type_device_info, val, sizeof(val));
    em_tlv_t* ret = em_msg_t::get_tlv(reinterpret_cast<em_tlv_t*>(buffer),0,em_tlv_type_device_info);
    ASSERT_EQ(ret, nullptr);
    std::cout << "Exiting get_tlv_zero_buffer_length_input test" << std::endl;
}
/**
 * @brief Test get_tlv function for null input buffer.
 *
 * This test verifies that invoking em_msg_t::get_tlv with a null buffer and zero length returns a nullptr,
 * ensuring the API handles null inputs correctly.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 142@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                            | Test Data                                                         | Expected Result                        | Notes       |
 * | :--------------: | ------------------------------------------------------ | ----------------------------------------------------------------- | -------------------------------------- | ----------- |
 * | 01               | Invoke get_tlv with a null input buffer and zero length | input: buffer = nullptr, length = 0, type = em_tlv_type_device_info; output: ret = nullptr | API returns nullptr; assertion check passes | Should Pass |
 */
TEST(em_msg_t, get_tlv_null_buffer_input) 
{
    std::cout << "Entering get_tlv_null_buffer_input test" << std::endl;
    em_tlv_t* ret = em_msg_t::get_tlv(nullptr, 0, em_tlv_type_device_info);
    ASSERT_EQ(ret, nullptr);
    std::cout << "Exiting get_tlv_null_buffer_input test" << std::endl;
}
/**
 * @brief Validate that get_tlv() returns nullptr when an EOM TLV is encountered before the target TLV.
 *
 * This test sets up a message buffer containing an EOM TLV followed by a client_info TLV, and validates that calling get_tlv with the client_info type returns nullptr. This ensures that the get_tlv() API does not mistakenly retrieve a TLV that appears after an EOM marker, thereby enforcing correct TLV ordering.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 143@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Write an EOM TLV at the start of the buffer using write_tlv | eom_size = TLV_HEADER_SIZE, tlv_type = em_tlv_type_eom, value = nullptr, size = 0 | EOM TLV correctly written to buffer | Should be successful |
 * | 02 | Advance the pointer by the size of the EOM TLV | ptr = buffer + TLV_HEADER_SIZE | Pointer correctly updated to the position after EOM TLV | Should be successful |
 * | 03 | Write a client_info TLV after the EOM TLV using write_tlv | value = {0x77, 0x77, 0x77}, value_len = TLV_HEADER_SIZE, tlv_type = em_tlv_type_client_info | client_info TLV correctly appended after the EOM TLV | Should be successful |
 * | 04 | Invoke get_tlv to retrieve the client_info TLV from the buffer | buffer pointer (cast as em_tlv_t*), total_size, target tlv type = em_tlv_type_client_info | get_tlv returns nullptr, and ASSERT_EQ confirms this result | Should Pass |
 */
TEST(em_msg_t, get_tlv_eom_before_target)
{
    std::cout << "Entering get_tlv_eom_before_target test" << std::endl;
    em_msg_t obj;
    unsigned int eom_size = TLV_HEADER_SIZE;
    unsigned short value_len = TLV_HEADER_SIZE;
    unsigned int tlv_size = TLV_HEADER_SIZE + value_len;
    unsigned int total_size = eom_size + tlv_size;
    unsigned char* buffer = new unsigned char[total_size];
    unsigned char* ptr = buffer;
    write_tlv(ptr, em_tlv_type_eom, nullptr, 0);
    ptr += eom_size;
    unsigned char val[3] = {0x77, 0x77, 0x77};
    write_tlv(ptr, em_tlv_type_client_info, val, value_len);
    em_tlv_t* ret = em_msg_t::get_tlv(reinterpret_cast<em_tlv_t*>(buffer), total_size,em_tlv_type_client_info);
    ASSERT_EQ(ret, nullptr);
    delete[] buffer;
    std::cout << "Exiting get_tlv_eom_before_target test" << std::endl;
}
/**
 * @brief Verify that the higher_layer_data function does not throw exceptions for all valid profiles
 *
 * This test iterates over all supported em_profile_type_t values, constructs an em_msg_t instance using
 * a fixed message type (em_msg_type_higher_layer_data) and a predefined TLV buffer, and then invokes the
 * higher_layer_data() method on each instance. The objective is to ensure that the API correctly handles 
 * data across all profiles without throwing exceptions.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 144
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                        | Test Data                                                                                                 | Expected Result                                            | Notes      |
 * | :--------------: | ------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- | ---------- |
 * | 01               | Loop through each valid profile, create an em_msg_t, and call higher_layer_data() | msgType = em_msg_type_higher_layer_data, profile = each valid profile, tlvBuffer = {0,0,...,0} (10 bytes), bufferLength = 10 | higher_layer_data() call does not throw any exception      | Should Pass |
 */
TEST(em_msg_t, higher_layer_data_profileVariation_loopAllProfiles)
{
    std::cout << "Entering higher_layer_data_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_higher_layer_data;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.higher_layer_data());
    }
    std::cout << "Exiting higher_layer_data_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Verify that the i1905_ack API does not throw exceptions for all profile values.
 *
 * This test iterates over all entries in the profiles array and for each profile,
 * it creates an em_msg_t object with a fixed tlvBuffer and bufferLength. The test then
 * calls the i1905_ack() method to verify that no exceptions are thrown when invoked with
 * valid parameters. This confirms the robustness of the API across various profile types.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 145@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                              | Test Data                                                                                                               | Expected Result                                              | Notes       |
 * | :--------------: | -------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- | ----------- |
 * | 01               | Loop through all profiles and invoke the i1905_ack() API for each profile                               | profile = value from profiles array, msgType = em_msg_type_1905_ack, tlvBuffer = [0,0,0,0,0,0,0,0,0,0], bufferLength = 10 | API call returns normally without throwing any exceptions  | Should Pass |
 */
TEST(em_msg_t, i1905_ack_profileVariation_loopAllProfiles)
{
    std::cout << "Entering i1905_ack_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_1905_ack;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.i1905_ack());
    }
    std::cout << "Exiting i1905_ack_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Validate i1905_decrypt_fail functionality over all profile variations
 *
 * This test iterates over all profiles available in the profiles array and creates an em_msg_t object for each profile with the message type set to em_msg_type_1905_decrypt_fail. It then invokes the i1905_decrypt_fail method ensuring that no exceptions are thrown, thereby verifying that the decryption fail functionality handles all profile variations correctly.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 146@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Log the start of the test execution | None | Console outputs "Entering i1905_decrypt_fail_profileVariation_loopAllProfiles test" | Should be successful |
 * | 02 | Initialize tlvBuffer with 10 zeroed bytes and set bufferLength to 10 | tlvBuffer = {0,0,0,0,0,0,0,0,0,0}, bufferLength = 10 | Variables are correctly initialized | Should be successful |
 * | 03 | Iterate over all profiles in the profiles array | profiles array elements; each profile = value from profiles | Loop iterates without error | Should be successful |
 * | 04 | For each profile, construct em_msg_t object with msgType = em_msg_type_1905_decrypt_fail and invoke i1905_decrypt_fail() method | profile = profiles[i], msgType = em_msg_type_1905_decrypt_fail, tlvBuffer = array of 10 zeros, bufferLength = 10 | EXPECT_NO_THROW verifies method call does not throw an exception | Should Pass |
 * | 05 | Log the end of the test execution | None | Console outputs "Exiting i1905_decrypt_fail_profileVariation_loopAllProfiles test" | Should be successful |
 */
TEST(em_msg_t, i1905_decrypt_fail_profileVariation_loopAllProfiles)
{
    std::cout << "Entering i1905_decrypt_fail_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_1905_decrypt_fail;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.i1905_decrypt_fail());
    }
    std::cout << "Exiting i1905_decrypt_fail_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Validate i1905_encap_eapol API encapsulation for each profile variation.
 *
 * This test ensures that the i1905_encap_eapol method of the em_msg_t object can be invoked without throwing an exception for every profile variation in the profiles array.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 147
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                        | Test Data                                                                                                         | Expected Result                                                | Notes       |
 * | :--------------: | ------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- | ----------- |
 * | 01               | Loop over each profile in the profiles array and invoke i1905_encap_eapol | profiles[i] = each valid profile, msgType = em_msg_type_1905_encap_eapol, tlvBuffer = array of 10 zeros, bufferLength = 10 | API call completes without throwing an exception using EXPECT_NO_THROW | Should Pass |
 */
TEST(em_msg_t, i1905_encap_eapol_profileVariation_loopAllProfiles)
{
    std::cout << "Entering i1905_encap_eapol_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_1905_encap_eapol;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.i1905_encap_eapol());
    }
    std::cout << "Exiting i1905_encap_eapol_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Verify that the i1905_rekey_req API executes without throwing exceptions for all profiles.
 *
 * This test iterates through all defined profiles and creates a message of type i1905_rekey_req for each profile. 
 * It then invokes the i1905_rekey_req function and checks that no exceptions are thrown, ensuring that the API behaves correctly across all profile variations.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 148@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Loop through all defined profiles, create and initialize an i1905_rekey_req message, and invoke i1905_rekey_req | profile = value from profiles array, msgType = em_msg_type_1905_rekey_req, tlvBuffer = 0,0,0,0,0,0,0,0,0,0, bufferLength = 10 | The i1905_rekey_req method should execute without throwing any exceptions. | Should Pass |
 */
TEST(em_msg_t, i1905_rekey_req_profileVariation_loopAllProfiles)
{
    std::cout << "Entering i1905_rekey_req_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_1905_rekey_req;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.i1905_rekey_req());
    }
    std::cout << "Exiting i1905_rekey_req_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Validate link_metric_query does not throw for all profile variations
 *
 * This test verifies that for each profile in the predefined set, the link_metric_query API is invoked and does not throw any exceptions. This ensures that the API correctly handles all variations within the profiles array.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 149
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Loop through each profile and invoke the link_metric_query API | profile = each element from profiles array, msgType = em_msg_type_link_metric_query, tlvBuffer = 0,0,0,0,0,0,0,0,0,0, bufferLength = 10 | The API call returns without throwing an exception; EXPECT_NO_THROW passes | Should Pass |
 */
TEST(em_msg_t, link_metric_query_profileVariation_loopAllProfiles)
{
    std::cout << "Entering link_metric_query_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_link_metric_query;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.link_metric_query());
    }
    std::cout << "Exiting link_metric_query_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Test to verify that the link_metric_resp API behaves correctly for all profiles
 *
 * This test iterates over all available profiles defined in the profiles array, creates an
 * em_msg_t object with the message type set to em_msg_type_link_metric_resp, and calls the
 * link_metric_resp() method. The objective is to confirm that the API does not throw any exceptions
 * for any profile variation.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 150@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- | -------------- | ----- |
 * | 01 | Iterate over each profile from the profiles array, create an em_msg_t object, and invoke link_metric_resp() | profile = each value in profiles, tlvBuffer = {0}, bufferLength = 10, msgType = em_msg_type_link_metric_resp | link_metric_resp() should execute without throwing any exception | Should Pass |
 */
TEST(em_msg_t, link_metric_resp_profileVariation_loopAllProfiles)
{
    std::cout << "Entering link_metric_resp_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_link_metric_resp;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.link_metric_resp());
    }
    std::cout << "Exiting link_metric_resp_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Verify that the op_channel_rprt() API does not throw an exception for each profile.
 *
 * This test iterates over all the profiles contained in the profiles array, creates a message with each profile,
 * and calls the op_channel_rprt() method. The objective is to ensure that no exception is thrown for any valid profile,
 * confirming the stability of the API across multiple profile variations.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 151@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Loop through each profile in the profiles array, create a message, and invoke op_channel_rprt() | tlvBuffer = 0,0,0,0,0,0,0,0,0,0; bufferLength = 10; msgType = em_msg_type_op_channel_rprt; profile = current profile from profiles array | No exception is thrown by msg.op_channel_rprt() | Should Pass |
 */
TEST(em_msg_t, op_channel_rprt_profileVariation_loopAllProfiles)
{
    std::cout << "Entering op_channel_rprt_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_op_channel_rprt;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.op_channel_rprt());
    }
    std::cout << "Exiting op_channel_rprt_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Test to verify that policy_config_req works correctly for all supported profiles
 *
 * This test iterates through each available profile from the profiles array and constructs an em_msg_t object with each profile. It then invokes the policy_config_req() function to ensure that it does not throw any exceptions. This verifies that for every valid profile, the function behaves as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 152@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Loop through all available profiles and call policy_config_req() for each. | input: profile from profiles array, msgType = em_msg_type_map_policy_config_req, tlvBuffer = {0,0,0,0,0,0,0,0,0,0}, bufferLength = 10; output: result of policy_config_req() call | The API call should complete without throwing an exception. | Should Pass |
 */
TEST(em_msg_t, policy_config_req_profileVariation_loopAllProfiles)
{
    std::cout << "Entering policy_config_req_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_map_policy_config_req;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.policy_config_req());
    }
    std::cout << "Exiting policy_config_req_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Validate that proxied_encap_dpp() executes without exceptions for all profiles.
 *
 * This test iterates over all available profiles defined in the profiles array, creates an em_msg_t object with each profile along with predefined tlvBuffer and bufferLength, and ensures that invoking proxied_encap_dpp() does not throw any exceptions. This confirms that the proxied encapsulation DPP functionality is robust across all supported profile types.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 153@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Loop over each profile element and invoke proxied_encap_dpp() on the constructed message | profile = each element in profiles, tlvBuffer = {0,0,0,0,0,0,0,0,0,0}, bufferLength = 10, msgType = em_msg_type_proxied_encap_dpp | The proxied_encap_dpp() API executes without throwing any exceptions (EXPECT_NO_THROW passes) | Should Pass |
 */
TEST(em_msg_t, proxied_encap_dpp_profileVariation_loopAllProfiles)
{
    std::cout << "Entering proxied_encap_dpp_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_proxied_encap_dpp;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.proxied_encap_dpp());
    }
    std::cout << "Exiting proxied_encap_dpp_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Test QoS management notification functionality for all profile variations
 *
 * This test verifies that the qos_mgmt_notif function is executed successfully for each profile in the defined profiles array. The test ensures that no exceptions are thrown when invoking the function with valid input parameters, thereby confirming its robustness across all valid profiles.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 154
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Loop through all available profiles and invoke qos_mgmt_notif for each profile | profile = profiles[i], msgType = em_msg_type_qos_mgmt_notif, tlvBuffer = {0}, bufferLength = 10 | The qos_mgmt_notif function call should not throw any exceptions | Should Pass |
 */
TEST(em_msg_t, qos_mgmt_notif_profileVariation_loopAllProfiles)
{
    std::cout << "Entering qos_mgmt_notif_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_qos_mgmt_notif;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.qos_mgmt_notif());
    }
    std::cout << "Exiting qos_mgmt_notif_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Verify that the reconfig_trigger API does not throw exceptions for all profile variations
 *
 * This test iterates over all available profiles and invokes the reconfig_trigger() API for each profile.
 * It ensures that the API call succeeds without throwing any exceptions, thereby validating proper handling
 * of reconfiguration trigger commands for each profile variation.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 155@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                               | Test Data                                                                                                            | Expected Result                                                   | Notes       |
 * | :--------------: | --------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- | ----------- |
 * | 01               | Loop through all profiles; create em_msg_t object and call reconfig_trigger API                         | msgType = em_msg_type_reconfig_trigger, profile = profiles[i], tlvBuffer = [0,0,0,0,0,0,0,0,0,0], bufferLength = 10 | No exception is thrown when reconfig_trigger() is invoked        | Should Pass |
 */
TEST(em_msg_t, reconfig_trigger_profileVariation_loopAllProfiles)
{
    std::cout << "Entering reconfig_trigger_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_reconfig_trigger;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.reconfig_trigger());
    }
    std::cout << "Exiting reconfig_trigger_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Validates the set_m1 API behavior using a valid TLV buffer input.
 *
 * This test case verifies that the set_m1 API correctly handles and processes a valid TLV buffer input without throwing exceptions. 
 * It ensures that the API behaves as expected when provided with a valid buffer and length, thereby confirming its proper functionality.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 156@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description                                              | Test Data                                             | Expected Result                                    | Notes      |
 * | :--------------: | ---------------------------------------------------------| ------------------------------------------------------| ---------------------------------------------------| ---------- |
 * |      01        | Call set_m1 API with a valid TLV buffer                  | buffer = {0x01, 0x02, 0x03}, length = 3, msg instance   | EXPECT_NO_THROW succeeds without throwing exception| Should Pass|
 */
TEST(em_msg_t, set_m1_valid_TLV_buffer)
{
    std::cout << "Entering set_m1_valid_TLV_buffer test" << std::endl;
    unsigned char buffer[3] = {0x01, 0x02, 0x03};
    em_msg_t msg;
    EXPECT_NO_THROW(msg.set_m1(buffer, 3));
    std::cout << "Exiting set_m1_valid_TLV_buffer test" << std::endl;
}
/**
 * @brief Verify that set_m1 correctly handles an empty TLV payload.
 *
 * This test verifies that the em_msg_t::set_m1 method does not throw an exception when provided with an empty TLV payload.
 * It ensures that the function can safely process a zero-length input without causing any errors.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 157@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke msg.set_m1 with an empty TLV payload | dummyBuffer = {0}, length = 0 | No exception thrown from msg.set_m1 | Should Pass |
 */
TEST(em_msg_t, set_m1_empty_TLV_payload)
{
    std::cout << "Entering set_m1_empty_TLV_payload test" << std::endl;
    unsigned char dummyBuffer[1] = {0};
    em_msg_t msg;
    EXPECT_NO_THROW(msg.set_m1(dummyBuffer, 0));
    std::cout << "Exiting set_m1_empty_TLV_payload test" << std::endl;
}
/**
 * @brief Validate that set_m1 correctly handles a null buffer pointer and zero length.
 *
 * This test verifies that invoking the set_m1 API with a null pointer for the buffer and a zero length does not result in any exceptions. It ensures that the function gracefully handles cases where no data is provided.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 158
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                        | Test Data                                   | Expected Result                      | Notes      |
 * | :--------------: | ------------------------------------------------------------------ | ------------------------------------------- | ------------------------------------ | ---------- |
 * | 01               | Invoke set_m1 with null buffer pointer and zero length parameter   | nullBuffer = nullptr, length = 0            | API does not throw any exceptions    | Should Pass|
 */
TEST(em_msg_t, set_m1_nullptr_zero_length)
{
    std::cout << "Entering set_m1_nullptr_zero_length test" << std::endl;
    unsigned char* nullBuffer = nullptr;
    em_msg_t msg;
    EXPECT_NO_THROW(msg.set_m1(nullBuffer, 0));
    std::cout << "Exiting set_m1_nullptr_zero_length test" << std::endl;
}
/**
 * @brief Validate that set_m1 successfully handles a large length with a valid pointer.
 *
 * This test ensures that the set_m1 function of the em_msg_t class can process a large data length (10 MB) without throwing an exception. It verifies that the API correctly handles and validates the pointer and length, which is critical for system stability when dealing with large inputs.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 159@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize dummy data and create message object with a large data length value. | dummyData = {0xFF}, largeLength = 10485760 (10 MB) | Variables initialized successfully. | Should be successful |
 * | 02 | Invoke the set_m1 API with the valid dummy pointer and large data length. | input: dummyData = {0xFF}, largeLength = 10485760; output: None | API call does not throw any exception (EXPECT_NO_THROW). | Should Pass |
 * | 03 | Output log message signaling the exit of the test. | N/A | Console receives the test exit log message. | Should be successful |
 */
TEST(em_msg_t, set_m1_large_length_valid_pointer)
{
    std::cout << "Entering set_m1_large_length_valid_pointer test" << std::endl;
    unsigned char dummyData[1] = {0xFF};
    em_msg_t msg;
    unsigned int largeLength = 1024 * 1024 * 10; // 10 MB - large but safe
    EXPECT_NO_THROW(msg.set_m1(dummyData, largeLength));
    std::cout << "Exiting set_m1_large_length_valid_pointer test" << std::endl;
}
/**
 * @brief Validate that no exception is thrown by sta_link_metrics_query API for each profile.
 *
 * This test iterates over each available profile in the profiles array, creates a message object using the provided message type,
 * profile, buffer, and length information, and then calls sta_link_metrics_query to verify that it does not throw any exceptions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 160@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                         | Test Data                                                                                   | Expected Result                                        | Notes              |
 * | :--------------: | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ------------------------------------------------------ | -------------------|
 * | 01               | Initialize tlvBuffer and bufferLength                                 | tlvBuffer = [0,0,0,0,0,0,0,0,0,0], bufferLength = 10                                         | Variables are correctly initialized                  | Should be successful |
 * | 02               | Iterate over all available profiles in the profiles array             | profiles array = list of profiles, index i from 0 to (sizeof(profiles)/sizeof(profiles[0]) - 1) | All profiles are enumerated                            | Should be successful |
 * | 03               | Create a message object for each profile and invoke sta_link_metrics_query | msgType = em_msg_type_assoc_sta_link_metrics_query, profile = each profile value, tlvBuffer = [0,...,0], bufferLength = 10 | sta_link_metrics_query does not throw any exception    | Should Pass        |
 * | 04               | Log the entry and exit of the test                                    | Console output: "Entering sta_link_metrics_query_profileVariation_loopAllProfiles test", "Exiting sta_link_metrics_query_profileVariation_loopAllProfiles test" | Correct log messages printed                           | Should be successful |
 */
TEST(em_msg_t, sta_link_metrics_query_profileVariation_loopAllProfiles)
{
    std::cout << "Entering sta_link_metrics_query_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_assoc_sta_link_metrics_query;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.sta_link_metrics_query());
    }
    std::cout << "Exiting sta_link_metrics_query_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Test sta_link_metrics_rsp function across all profile variations ensuring no exceptions are thrown.
 *
 * This test iterates through all profile types defined in the profiles array. For each profile, it constructs an instance of em_msg_t
 * using fixed inputs and then invokes the sta_link_metrics_rsp method, confirming that it does not throw any exceptions. This assures that
 * the function correctly handles different profile types as part of the message processing without errors.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 161@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Loop through each profile in the profiles array, construct em_msg_t and call sta_link_metrics_rsp. | msgType = em_msg_type_assoc_sta_link_metrics_rsp, profile = each value from profiles array, tlvBuffer = {0}, bufferLength = 10 | No exception should be thrown by sta_link_metrics_rsp API invocation | Should Pass |
 */
TEST(em_msg_t, sta_link_metrics_rsp_profileVariation_loopAllProfiles)
{
    std::cout << "Entering sta_link_metrics_rsp_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_assoc_sta_link_metrics_rsp;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.sta_link_metrics_rsp());
    }
    std::cout << "Exiting sta_link_metrics_rsp_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Test that verifies the steering_complete() method executes without throwing exceptions for all valid profiles.
 *
 * This test verifies that for each available profile provided in the profiles array, an em_msg_t object is constructed with the steering_complete message type and the provided buffer. The steering_complete() method is then invoked, and the test confirms that no exception is thrown during this process.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 162@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Print the entry log message and initialize the test buffer and its length | tlvBuffer = {0,0,0,0,0,0,0,0,0,0}, bufferLength = 10 | Entry log message is printed and test inputs are correctly initialized | Should be successful |
 * | 02 | Iterate over all profiles, create em_msg_t object, and invoke steering_complete() | profile = each element from profiles, msgType = em_msg_type_steering_complete, tlvBuffer = {0,0,0,0,0,0,0,0,0,0}, bufferLength = 10 | steering_complete() does not throw any exception for each profile iteration | Should Pass |
 * | 03 | Print the exit log message after completing the test execution | None | Exit log message is printed | Should be successful |
 */
TEST(em_msg_t, steering_complete_profileVariation_loopAllProfiles)
{
    std::cout << "Entering steering_complete_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_steering_complete;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.steering_complete());
    }
    std::cout << "Exiting steering_complete_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Validate svc_prio_req function with all available profiles.
 *
 * This test verifies that the svc_prio_req method of the em_msg_t class executes without any exceptions when invoked for all valid profile values. The test iterates over each profile in the profiles array and calls the svc_prio_req function, ensuring robustness across different profile configurations.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 163@n
 * **Priority:** (High) High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                                         | Test Data                                                                                   | Expected Result                                                                 | Notes              |
 * | :--------------: | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- | ------------------ |
 * | 01               | Print entry log message to indicate start of test                   | No input arguments                                                                            | Console output should display the entry log message                             | Should be successful |
 * | 02               | Iterate over all profiles and invoke svc_prio_req for each profile    | profile = each element in profiles, msgType = em_msg_type_svc_prio_req, tlvBuffer = {0}, bufferLength = 10, output: void | svc_prio_req should execute without throwing any exception; assertion should pass | Should Pass        |
 * | 03               | Print exit log message to indicate end of test                      | No input arguments                                                                            | Console output should display the exit log message                              | Should be successful |
 */
TEST(em_msg_t, svc_prio_req_profileVariation_loopAllProfiles)
{
    std::cout << "Entering svc_prio_req_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_svc_prio_req;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.svc_prio_req());
    }
    std::cout << "Exiting svc_prio_req_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Validate that the topo_disc function processes all available profiles without throwing exceptions.
 *
 * This test iterates over a pre-defined array of profile types, constructs an em_msg_t object with a TLV buffer and a fixed buffer length, and then calls the topo_disc method. The objective is to verify that the API handles all supported profile variations correctly by not throwing any exceptions during execution.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 164@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize TLV buffer and buffer length for the test | tlvBuffer = {0,0,0,0,0,0,0,0,0,0}, bufferLength = 10 | Buffer is correctly initialized | Should be successful |
 * | 02 | Iterate over each profile and construct an em_msg_t object with msgType, profile, tlvBuffer, and bufferLength | For each iteration: profile = profiles[i], msgType = em_msg_type_topo_disc, tlvBuffer = {0,0,0,0,0,0,0,0,0,0}, bufferLength = 10 | Message object is successfully constructed for each profile | Should be successful |
 * | 03 | Invoke the topo_disc() method on the constructed object and assert no exception is thrown | Using the constructed em_msg_t object with valid parameters | No exception is thrown during the topo_disc call | Should Pass |
 */
TEST(em_msg_t, topo_disc_profileVariation_loopAllProfiles)
{
    std::cout << "Entering topo_disc_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_topo_disc;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.topo_disc());
    }
    std::cout << "Exiting topo_disc_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Validate that topo_notif does not throw exceptions for all profile variations
 *
 * This test iterates over each profile in the profiles array and checks that invoking the topo_notif method on the message object constructed with each profile does not throw an exception.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 165@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                 | Test Data                                                                                      | Expected Result                                                       | Notes       |
 * | :--------------: | --------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | ----------- |
 * | 01               | Iterate over profiles array, create a message for each profile and call topo_notif to ensure it does not throw an exception | profile = profiles[i] (each value in profiles), msgType = em_msg_type_topo_notif, tlvBuffer = {0,...,0} (10 zeros), bufferLength = 10 | No exception thrown from msg.topo_notif() as verified by EXPECT_NO_THROW | Should Pass |
 */
TEST(em_msg_t, topo_notif_profileVariation_loopAllProfiles)
{
    std::cout << "Entering topo_notif_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_topo_notif;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.topo_notif());
    }
    std::cout << "Exiting topo_notif_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Validate topo_query execution for all profile variations.
 *
 * This test iterates through each profile in the profiles array. For each profile, it constructs an em_msg_t object with a predefined TLV buffer and buffer length, and then verifies that invoking topo_query does not throw any exceptions. This confirms the robustness of topo_query in handling all available profile types.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 166
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                            | Test Data                                                                  | Expected Result                                             | Notes       |
 * | :--------------: | ---------------------------------------------------------------------- | -------------------------------------------------------------------------- | ----------------------------------------------------------- | ----------- |
 * | 01               | Iterate over each profile, construct em_msg_t object and invoke topo_query | profiles[i] = each profile, msgType = em_msg_type_topo_query, tlvBuffer = an array of 10 zeros, bufferLength = 10 | No exception is thrown when topo_query() is called         | Should Pass |
 */
TEST(em_msg_t, topo_query_profileVariation_loopAllProfiles)
{
    std::cout << "Entering topo_query_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_topo_query;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.topo_query());
    }
    std::cout << "Exiting topo_query_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Validate topo_resp API across all profile variations
 *
 * This test iterates through all available profiles and creates a message instance
 * for each profile using a fixed message type and a given TLV buffer. It then invokes
 * the topo_resp() API to ensure that there are no exceptions thrown, verifying that the
 * API can handle each profile variation correctly.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 167@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result |Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01 | Iterate over each element in the profiles array, create a message with msgType=em_msg_type_topo_resp, associated profile, TLV buffer initialized to zeros, and buffer length of 10, then invoke the topo_resp() method | profile = profiles[i] (varies), msgType = em_msg_type_topo_resp, tlvBuffer = {0,0,0,0,0,0,0,0,0,0}, bufferLength = 10 | The API call returns normally without throwing an exception | Should Pass |
 */
TEST(em_msg_t, topo_resp_profileVariation_loopAllProfiles)
{
    std::cout << "Entering topo_resp_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_topo_resp;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.topo_resp());
    }
    std::cout << "Exiting topo_resp_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Tests the topo_vendor() API call across all vendor profile types.
 *
 * This test evaluates the behavior of the em_msg_t::topo_vendor() method when invoked for every valid profile found in the profiles array.
 * It ensures that no exceptions are thrown, confirming the stability and correct handling of different vendor profiles by the API.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 168@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                              | Test Data                                                                                         | Expected Result                                                 | Notes         |
 * | :--------------: | ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- | ------------- |
 * | 01               | Loop through all available profiles and invoke the topo_vendor() method. | tlvBuffer = {0,0,0,0,0,0,0,0,0,0}, bufferLength = 10, profile = each element from profiles, msgType = em_msg_type_topo_vendor | Method topo_vendor() does not throw an exception when called. | Should Pass   |
 */
TEST(em_msg_t, topo_vendor_profileVariation_loopAllProfiles)
{
    std::cout << "Entering topo_vendor_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_topo_vendor;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.topo_vendor());
    }
    std::cout << "Exiting topo_vendor_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Validate tunneled() method for all supported profile variations.
 *
 * This test iterates through each profile in the profiles array and, for each one, creates a message object with message type em_msg_type_tunneled using a pre-initialized buffer. It then calls the tunneled() API to ensure that no exceptions are thrown, verifying that the function correctly handles all profile variations.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 169
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize test variables and buffer | tlvBuffer = [0,0,0,0,0,0,0,0,0,0], bufferLength = 10 | Buffer initialized correctly | Should be successful |
 * | 02 | Loop through all profiles, create message object and invoke tunneled() API | profile = each value in profiles array, msgType = em_msg_type_tunneled, tlvBuffer = [0,0,0,0,0,0,0,0,0,0], bufferLength = 10 | No exception thrown from msg.tunneled() | Should Pass |
 * | 03 | Log the test exit message | N/A | Exit message printed to console | Should be successful |
 */
TEST(em_msg_t, tunneled_profileVariation_loopAllProfiles)
{
    std::cout << "Entering tunneled_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_tunneled;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.tunneled());
    }
    std::cout << "Exiting tunneled_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Verifies that unassoc_sta_link_metrics_query works correctly for all supported profiles.
 *
 * This test iterates over each available profile, constructs an em_msg_t object with a specified message type, buffer, and buffer length, and then calls the unassoc_sta_link_metrics_query function. It confirms that the function does not throw any exceptions.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 170
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Loop through each profile, create an em_msg_t object with tlvBuffer and bufferLength, and call unassoc_sta_link_metrics_query | profile = profiles[i], msgType = em_msg_type_unassoc_sta_link_metrics_query, tlvBuffer = {0,0,0,0,0,0,0,0,0,0}, bufferLength = 10 | The function call does not throw any exception | Should Pass |
 */
TEST(em_msg_t, unassoc_sta_link_metrics_query_profileVariation_loopAllProfiles)
{
    std::cout << "Entering unassoc_sta_link_metrics_query_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_unassoc_sta_link_metrics_query;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.unassoc_sta_link_metrics_query());
    }
    std::cout << "Exiting unassoc_sta_link_metrics_query_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Validate that the unassoc_sta_link_metrics_rsp function executes without throwing exceptions for all profile variations.
 *
 * This test iterates through all profiles defined in the profiles array, constructs the message object with each profile, and invokes the unassoc_sta_link_metrics_rsp function. It verifies that the API call does not throw an exception, ensuring stability of the implementation when processing different profile types.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 171
 * **Priority:** High
 * 
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                          | Test Data                                                                            | Expected Result                                                                                  | Notes       |
 * | :-------------: | ---------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------| ----------------------------------------------------------------------------------------------- | ----------- |
 * | 01              | Iterate through each profile, create an em_msg_t object with tlvBuffer (10 zeros) and bufferLength 10, and call unassoc_sta_link_metrics_rsp() | profile = value from profiles, tlvBuffer = 0,0,0,0,0,0,0,0,0,0, bufferLength = 10, msgType = em_msg_type_unassoc_sta_link_metrics_rsp | The API should not throw any exception; EXPECT_NO_THROW passes verifying no exceptions are thrown | Should Pass |
 */
TEST(em_msg_t, unassoc_sta_link_metrics_rsp_profileVariation_loopAllProfiles)
{
    std::cout << "Entering unassoc_sta_link_metrics_rsp_profileVariation_loopAllProfiles test" << std::endl;
    unsigned char tlvBuffer[10] = {0};
    unsigned int bufferLength = 10;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        em_profile_type_t profile = profiles[i];
        em_msg_type_t msgType = em_msg_type_unassoc_sta_link_metrics_rsp;
        em_msg_t msg(msgType, profile, tlvBuffer, bufferLength);
        EXPECT_NO_THROW(msg.unassoc_sta_link_metrics_rsp());
    }
    std::cout << "Exiting unassoc_sta_link_metrics_rsp_profileVariation_loopAllProfiles test" << std::endl;
}
/**
 * @brief Validate that the message contains all mandatory TLVs correctly.
 *
 * This test verifies that when all mandatory TLVs (AL MAC address, MAC address, and EOM) are added to the TLV buffer, the message validation function returns true. The test checks the correct TLV construction and the overall integrity of the message.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 172@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize a buffer and set the message length based on header sizes. | buffer size = 256, len = sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t) | Buffer is properly initialized with correct length value. | Should be successful |
 * | 02 | Add the AL MAC address TLV to the buffer. | al_mac = {0x00,0x11,0x22,0x33,0x44,0x55}, pointer offset = buffer + len, tlv type = em_tlv_type_al_mac_address, tlv length = sizeof(al_mac) | AL MAC TLV is correctly appended to the buffer. | Should be successful |
 * | 03 | Add the MAC address TLV to the buffer. | mac = {0x66,0x77,0x88,0x99,0xAA,0xBB}, pointer offset = buffer + len, tlv type = em_tlv_type_mac_address, tlv length = sizeof(mac) | MAC TLV is correctly appended to the buffer. | Should be successful |
 * | 04 | Add the EOM TLV to denote the end of message. | No TLV data (nullptr), pointer offset = buffer + len, tlv type = em_tlv_type_eom, tlv length = 0 | EOM TLV is correctly appended to the buffer. | Should be successful |
 * | 05 | Create an em_msg_t object using the constructed buffer and TLV length. | msg type = em_msg_type_topo_disc, profile type = em_profile_type_1, buffer, len | Message object is successfully created with provided parameters. | Should be successful |
 * | 06 | Validate the message by calling the validate() method. | errors array initialized to {nullptr} | validate() returns true and the assertion passes. | Should Pass |
 * | 07 | Log entry and exit of the test to the console. | Console log messages: "Entering validate_success_with_all_mandatory_tlvs test" and "Exiting validate_success_with_all_mandatory_tlvs test" | Log messages are printed correctly in the console. | Should be successful |
 */
TEST(em_msg_t, validate_success_with_all_mandatory_tlvs)
{
    std::cout << "Entering validate_success_with_all_mandatory_tlvs test" << std::endl;
    unsigned char buffer[256] = {0};
    unsigned int len = sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t);
    unsigned char al_mac[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    unsigned char mac[6]    = {0x66,0x77,0x88,0x99,0xAA,0xBB};
    em_msg_t::add_tlv(buffer + len, &len, em_tlv_type_al_mac_address, al_mac, sizeof(al_mac));
    em_msg_t::add_tlv(buffer + len, &len, em_tlv_type_mac_address, mac, sizeof(mac));
    em_msg_t::add_tlv(buffer + len, &len, em_tlv_type_eom, nullptr, 0);
    em_msg_t msg(em_msg_type_topo_disc, em_profile_type_1, buffer, len);
    char *errors[EM_MAX_TLV_MEMBERS] = {nullptr};
    EXPECT_TRUE(msg.validate(errors));
    std::cout << "Exiting validate_success_with_all_mandatory_tlvs test" << std::endl;
}
/**
 * @brief Validate that missing mandatory TLV causes validation failure
 *
 * This test verifies that the em_msg_t::validate function returns false when a mandatory TLV is missing, and that the appropriate error message ("table 6-9 of IEEE-1905-1") is set. The test constructs a message with specific TLVs, intentionally omitting a mandatory one, and then checks for correct validation error handling.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 173@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create a buffer and TLVs with an AL MAC TLV and an EOM TLV, missing the mandatory TLV | buffer = 256-byte array (zero initialized), len = sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t), al_mac = {0x00,0x11,0x22,0x33,0x44,0x55}, add_tlv calls with em_tlv_type_al_mac_address and em_tlv_type_eom | msg.validate() returns false; errors[0] is not null and equals "table 6-9 of IEEE-1905-1" | Should Pass |
 */
TEST(em_msg_t, validate_fails_missing_mandatory_tlv)
{
    std::cout << "Entering validate_fails_missing_mandatory_tlv test" << std::endl;
    unsigned char buffer[256] = {0};
    unsigned int len = sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t);
    unsigned char al_mac[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    em_msg_t::add_tlv(buffer + len, &len, em_tlv_type_al_mac_address, al_mac, sizeof(al_mac));
    em_msg_t::add_tlv(buffer + len, &len, em_tlv_type_eom, nullptr, 0);
    em_msg_t msg(em_msg_type_topo_disc, em_profile_type_1, buffer, len);
    char *errors[EM_MAX_TLV_MEMBERS] = {nullptr};
    EXPECT_FALSE(msg.validate(errors));
    ASSERT_NE(errors[0], nullptr);
    EXPECT_STREQ(errors[0], "table 6-9 of IEEE-1905-1");
    std::cout << "Exiting validate_fails_missing_mandatory_tlv test" << std::endl;
}
/**
 * @brief Test to validate that the message fails validation when multiple mandatory TLVs are missing
 *
 * This test verifies that when multiple mandatory TLVs are missing in the message, the validate function correctly returns false and sets the appropriate error messages. It ensures that both error messages for missing TLVs from table 6-8 and table 6-9 of IEEE-1905-1 are returned.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 174@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * |01| Print the entering test message | N/A | "Entering validate_fails_multiple_missing_mandatory_tlvs test" printed to stdout | Should be successful |
 * |02| Initialize buffer and compute length | buffer = {0}, len = sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t) | Buffer is initialized and len is correctly computed | Should be successful |
 * |03| Add TLV with missing mandatory information | pointer = buffer + len, len pointer, type = em_tlv_type_eom, data = nullptr, size = 0 | TLV added to the buffer | Should be successful |
 * |04| Instantiate em_msg_t object with given parameters | msg_type = em_msg_type_topo_disc, profile = em_profile_type_1, buffer, len | em_msg_t object is successfully created | Should be successful |
 * |05| Invoke validate on the message object | errors array allocated; msg.validate(errors) | Returns false and errors array gets populated (errors[0] and errors[1] not nullptr) | Should Fail |
 * |06| Assert error messages match expected strings | errors[0] expected "table 6-8 of IEEE-1905-1", errors[1] expected "table 6-9 of IEEE-1905-1" | Error messages match exactly the expected strings | Should Fail |
 * |07| Print the exiting test message | N/A | "Exiting validate_fails_multiple_missing_mandatory_tlvs test" printed to stdout | Should be successful |
 */
TEST(em_msg_t, validate_fails_multiple_missing_mandatory_tlvs)
{
    std::cout << "Entering validate_fails_multiple_missing_mandatory_tlvs test" << std::endl;
    unsigned char buffer[256] = {0};
    unsigned int len = sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t);
    em_msg_t::add_tlv(buffer + len, &len, em_tlv_type_eom, nullptr, 0);
    em_msg_t msg(em_msg_type_topo_disc, em_profile_type_1, buffer, len);
    char *errors[EM_MAX_TLV_MEMBERS] = {nullptr};
    EXPECT_FALSE(msg.validate(errors));
    ASSERT_NE(errors[0], nullptr);
    ASSERT_NE(errors[1], nullptr);
    EXPECT_STREQ(errors[0], "table 6-8 of IEEE-1905-1");
    EXPECT_STREQ(errors[1], "table 6-9 of IEEE-1905-1");
    std::cout << "Exiting validate_fails_multiple_missing_mandatory_tlvs test" << std::endl;
}
/**
 * @brief Validates that the message fails when a mandatory TLV has an invalid length.
 *
 * This test constructs a message with TLVs and deliberately includes a mandatory TLV with an invalid length.
 * The objective is to ensure that msg.validate correctly fails the message validation and returns an expected error message.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 175@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                         | Test Data                                                                                                                                               | Expected Result                                                                                     | Notes       |
 * | :--------------: | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- | ----------- |
 * | 01               | Call add_tlv to add TLVs including a mandatory TLV with invalid length and then validate the message. | buffer = array of 256 bytes initialized to 0, len = sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t), short_mac = [0x01, 0x02, 0x03], errors = array of EM_MAX_TLV_MEMBERS initialized to nullptr | msg.validate returns false and errors[0] is set to "table 6-8 of IEEE-1905-1"                      | Should Fail |
 */
TEST(em_msg_t, validate_fails_invalid_length_mandatory_tlv)
{
    std::cout << "Entering validate_fails_invalid_length_mandatory_tlv test" << std::endl;
    unsigned char buffer[256] = {0};
    unsigned int len = sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t);
    unsigned char short_mac[3] = {0x01,0x02,0x03};
    em_msg_t::add_tlv(buffer + len, &len, em_tlv_type_al_mac_address,short_mac, sizeof(short_mac));
    em_msg_t::add_tlv(buffer + len, &len, em_tlv_type_mac_address, short_mac, sizeof(short_mac));
    em_msg_t::add_tlv(buffer + len, &len, em_tlv_type_eom, nullptr, 0);
    em_msg_t msg(em_msg_type_topo_disc, em_profile_type_1, buffer, len);
    char *errors[EM_MAX_TLV_MEMBERS] = {nullptr};
    EXPECT_FALSE(msg.validate(errors));
    ASSERT_NE(errors[0], nullptr);
    EXPECT_STREQ(errors[0], "table 6-8 of IEEE-1905-1");
    std::cout << "Exiting validate_fails_invalid_length_mandatory_tlv test" << std::endl;
}
/**
 * @brief Verify that the message validation fails when an invalid TLV is present
 *
 * This test verifies that the em_msg_t::validate method correctly identifies and rejects
 * messages that include an improperly set TLV. It adds a valid profile TLV and an invalid EOM TLV,
 * constructs the message, then confirms that validation fails and proper error details are provided.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 176@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                             | Test Data                                                                                                                             | Expected Result                                                                                          | Notes             |
 * | :--------------: | ------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- | ----------------- |
 * | 01               | Initialize the test buffer and calculate the initial length using sizeof(em_raw_hdr_t) and sizeof(em_cmdu_t) | buffer = unsigned char[256]={0}, len = sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)                                                        | Buffer is zeroed and length is correctly computed                                                        | Should be successful |
 * | 02               | Add a profile TLV with valid profile data using add_tlv                                               | function: add_tlv, input: (buffer+len, &len, em_tlv_type_profile, pointer to profile value, sizeof(profile))                           | Profile TLV is appended successfully                                                                      | Should be successful |
 * | 03               | Add an EOM TLV with invalid data (nullptr data and length 0) using add_tlv                              | function: add_tlv, input: (buffer+len, &len, em_tlv_type_eom, nullptr, 0)                                                                | EOM TLV is appended which introduces an error in the TLV structure                                          | Should Fail       |
 * | 04               | Construct the message object with the provided message type, profile, buffer, and computed length         | function: em_msg_t constructor, input: (em_msg_type_topo_query, em_profile_type_1, buffer, len)                                         | Message object is constructed without error                                                               | Should be successful |
 * | 05               | Validate the constructed message and check for the expected error message                               | function: validate, input: (errors array pointer), expected: return value = false, errors[0] equals "17.2.47 of Wi-Fi Easy Mesh 5.0" | validate() returns false; errors[0] is non-null and contains the expected error string                    | Should Pass       |
 * | 06               | Log the exit of the test by printing a message to the console                                           | std::cout output "Exiting validate_fails_bad_tlv_present test"                                                                         | Console output indicates the test has ended                                                               | Should be successful |
 */
TEST(em_msg_t, validate_fails_bad_tlv_present)
{
    std::cout << "Entering validate_fails_bad_tlv_present test" << std::endl;
    unsigned char buffer[256] = {0};
    unsigned int len = sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t);
    em_profile_type_t profile = em_profile_type_1;
    em_msg_t::add_tlv(buffer + len, &len, em_tlv_type_profile, reinterpret_cast<unsigned char*>(&profile), sizeof(profile));
    em_msg_t::add_tlv(buffer + len, &len, em_tlv_type_eom, nullptr, 0);
    em_msg_t msg(em_msg_type_topo_query, em_profile_type_1, buffer, len);
    char *errors[EM_MAX_TLV_MEMBERS] = {nullptr};
    EXPECT_FALSE(msg.validate(errors));
    ASSERT_NE(errors[0], nullptr);
    EXPECT_STREQ(errors[0], "17.2.47 of Wi-Fi Easy Mesh 5.0");
    std::cout << "Exiting validate_fails_bad_tlv_present test" << std::endl;
}
/**
 * @brief Validate that em_msg_t with only optional TLV elements is processed successfully
 *
 * This test case verifies that an em_msg_t object constructed after adding only the optional TLV element (via add_tlv) validates successfully. The test confirms that the message is created and validated properly when the optional TLV is present.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 177@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Print entering message for the test | message = "Entering validate_success_optional_only test" | Console displays the test entry message | Should be successful |
 * | 02 | Initialize buffer array with zeros and calculate the initial length | buffer = {0,...}, len = sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t) | Buffer and length are initialized correctly | Should be successful |
 * | 03 | Invoke add_tlv API to add a TLV element into the buffer | buffer offset = buffer + len, len pointer = &len, type = em_tlv_type_eom, payload = nullptr, payload_len = 0 | TLV element is added and len is updated accordingly | Should Pass |
 * | 04 | Create an em_msg_t object with provided parameters | msg_type = em_msg_type_ap_cap_query, profile_type = em_profile_type_1, buffer, len | em_msg_t object is created successfully | Should Pass |
 * | 05 | Call the validate method on the em_msg_t object | errors array = {nullptr,...} | validate returns true as expected | Should Pass |
 * | 06 | Print exiting message for the test | message = "Exiting validate_success_optional_only test" | Console displays the test exit message | Should be successful |
 */
TEST(em_msg_t, validate_success_optional_only)
{
    std::cout << "Entering validate_success_optional_only test" << std::endl;
    unsigned char buffer[256] = {0};
    unsigned int len = sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t);
    em_msg_t::add_tlv(buffer + len, &len, em_tlv_type_eom, nullptr, 0);
    em_msg_t msg(em_msg_type_ap_cap_query, em_profile_type_1, buffer, len);
    char *errors[EM_MAX_TLV_MEMBERS] = {nullptr};
    EXPECT_TRUE(msg.validate(errors));
    std::cout << "Exiting validate_success_optional_only test" << std::endl;
}
/**
 * @brief Validates that a default constructed em_msg_t object is handled correctly
 *
 * This test verifies that constructing an em_msg_t object using the default constructor does not throw any exceptions.
 * It ensures that the object is created successfully and its destructor is invoked once it goes out of scope.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 178@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                   | Test Data                                    | Expected Result                                        | Notes        |
 * | :--------------: | --------------------------------------------- | -------------------------------------------- | ------------------------------------------------------ | ------------ |
 * | 01               | Invoke the default constructor for em_msg_t.  | em_msg_t object is constructed with no inputs. | The API call should not throw an exception; EXPECT_NO_THROW assertion passed. | Should Pass  |
 */
TEST(em_msg_t, em_msg_t_DestroyDefaultConstructedObject) {
    std::cout << "Entering em_msg_t_DestroyDefaultConstructedObject test" << std::endl;
    EXPECT_NO_THROW({
        std::cout << "Invoking default constructor for em_msg_t." << std::endl;
        em_msg_t obj;
        std::cout << "Default constructed em_msg_t object created successfully." << std::endl;
    });
    std::cout << "Destructor for em_msg_t has been invoked as the object went out of scope." << std::endl;
    std::cout << "Exiting em_msg_t_DestroyDefaultConstructedObject test" << std::endl;
}
/**
 * @brief Validate that the default constructor of em_tlv_member_t does not throw any exception.
 *
 * This test verifies that instantiating an object of em_tlv_member_t using its default constructor
 * completes successfully without throwing any exceptions. The test is aimed at ensuring that the object
 * initialization does not result in any errors, which is critical for subsequent functionalities that depend on a valid instance.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 179@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke the default constructor of em_tlv_member_t within EXPECT_NO_THROW. | Invocation: em_tlv_member_t() | Object is created successfully without throwing an exception; EXPECT_NO_THROW passes. | Should Pass |
 */
TEST(em_tlv_member_t, em_tlv_member_t_default_constructor_uninitialized) {
    std::cout << "Entering em_tlv_member_t_default_constructor_uninitialized test" << std::endl;
    EXPECT_NO_THROW({
        std::cout << "Invoking default constructor: em_tlv_member_t()" << std::endl;
        em_tlv_member_t instance;
        std::cout << "Instance of em_tlv_member_t is created with default constructor." << std::endl;
    });
    std::cout << "Exiting em_tlv_member_t_default_constructor_uninitialized test" << std::endl;
}
/**
 * @brief Test to verify that the em_tlv_member_t constructor does not throw exceptions when provided with valid TLV types.
 *
 * This test iterates over all supported TLV types from the types array. For each type, it creates an em_tlv_member_t object using valid parameters (mandatory flag, a valid specification string, and a valid TLV length) and checks that no exception is thrown. This ensures that the constructor handles all valid TLV types correctly.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 180
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                                                                   | Test Data                                                       | Expected Result                                                       | Notes          |
 * | :--------------: | --------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------------- | -------------- |
 * | 01               | Print an entering message before starting the test.                                                                                         | None                                                             | "Entering em_tlv_member_t_positive_valid_tlv_types test" is printed    | Should be successful |
 * | 02               | Loop over each valid TLV type and instantiate em_tlv_member_t using valid parameters; verify that no exception is thrown.                        | types[i] = valid TLV type, mandatory, spec = "Valid Spec", tlv_length = 10 | No exception thrown; EXPECT_NO_THROW assertion passes                  | Should Pass    |
 * | 03               | Print an exiting message after completing the test.                                                                                         | None                                                             | "Exiting em_tlv_member_t_positive_valid_tlv_types test" is printed      | Should be successful |
 */
TEST(em_tlv_member_t, em_tlv_member_t_positive_valid_tlv_types) {
    std::cout << "Entering em_tlv_member_t_positive_valid_tlv_types test" << std::endl;
    const char* spec = "Valid Spec";
    int tlv_length = 10;
    for (int i = 0; i < TLV_TYPE_COUNT; ++i) {
	    EXPECT_NO_THROW({
            em_tlv_member_t obj(types[i], mandatory, spec, tlv_length);
        });
    }
    std::cout << "Exiting em_tlv_member_t_positive_valid_tlv_types test" << std::endl;
}
/**
 * @brief Validate that em_tlv_member_t constructor correctly handles valid requirement values without throwing exceptions
 *
 * This test verifies that for each valid requirement value provided, the em_tlv_member_t constructor does not throw an exception.
 * The test ensures that the constructor can accept a valid type, valid specification string, valid TLV length, and each of the valid requirement values.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 181@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- | -------------- | ----- |
 * | 01 | Initialize test variables with valid inputs | type = em_tlv_type_device_info, spec = "Valid Spec", tlv_length = 15, reqValues = { mandatory, optional, bad } | Variables are initialized correctly with test data | Should be successful |
 * | 02 | Construct em_tlv_member_t objects for each requirement value and verify no exception is thrown | For each iteration: input: type = em_tlv_type_device_info, requirement = current value from { mandatory, optional, bad }, spec = "Valid Spec", tlv_length = 15 | Constructor call does not throw an exception | Should Pass |
 */
TEST(em_tlv_member_t, em_tlv_member_t_positive_valid_requirement_values) {
    std::cout << "Entering em_tlv_member_t_positive_valid_requirement_values test" << std::endl;
    em_tlv_type_t type = em_tlv_type_device_info;
    const char* spec = "Valid Spec";
    int tlv_length = 15;
    em_tlv_requirement_t reqValues[] = { mandatory, optional, bad };
    const int numReq = sizeof(reqValues) / sizeof(reqValues[0]);
    for (int i = 0; i < numReq; ++i) {
	    EXPECT_NO_THROW({
            em_tlv_member_t obj(type, reqValues[i], spec, tlv_length);
        });
    }
    std::cout << "Exiting em_tlv_member_t_positive_valid_requirement_values test" << std::endl;
}
/**
 * @brief Verify that em_tlv_member_t constructor works with valid inputs.
 *
 * This test verifies that when provided with standard valid parameters, the em_tlv_member_t constructor instantiates an object without throwing an exception.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 182@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                               | Test Data                                                                                                                                                   | Expected Result                                               | Notes      |
 * | :--------------: | ----------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- | ---------- |
 * | 01               | Instantiate em_tlv_member_t with valid input parameters and ensure no exception is thrown. | type = em_tlv_type_device_bridging_cap, requirement = optional, spec = "17.2.7 of Wi-Fi Easy Mesh 5.0", tlv_length = 20 | Object is constructed without any exceptions being thrown. | Should Pass |
 */
TEST(em_tlv_member_t, em_tlv_member_t_standard_valid_inputs) {
    std::cout << "Entering em_tlv_member_t_standard_valid_inputs test" << std::endl;
    EXPECT_NO_THROW({
        em_tlv_type_t type = em_tlv_type_device_bridging_cap;
        em_tlv_requirement_t requirement = optional;
        const char* spec = "17.2.7 of Wi-Fi Easy Mesh 5.0";
        int tlv_length = 20;
        em_tlv_member_t obj(type, requirement, spec, tlv_length);
    });
    std::cout << "Exiting em_tlv_member_t_standard_valid_inputs test" << std::endl;
}
/**
 * @brief Tests that em_tlv_member_t's destructor is invoked successfully.
 *
 * This test creates an instance of em_tlv_member_t using the default constructor and verifies that the destructor is automatically invoked when the object goes out-of-scope. It ensures that no exceptions, memory leaks, or crashes occur during the destruction process.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 183
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- | -------------- | ----- |
 * | 01 | Create an instance using the default constructor and let it go out-of-scope to invoke the destructor | instance creation = default, destructor = automatic invocation | No exceptions thrown; Destructor invoked without errors | Should Pass |
 */
TEST(em_tlv_member_t, em_tlv_member_t_destructor_invoked_valid_instance) {
    std::cout << "Entering em_tlv_member_t_destructor_invoked_valid_instance test" << std::endl;
    EXPECT_NO_THROW({
        std::cout << "Creating em_tlv_member_t instance using default constructor" << std::endl;
        em_tlv_member_t obj;
        std::cout << "Created instance. About to leave scope, which will automatically invoke the destructor ~em_tlv_member_t()" << std::endl;
    });
    std::cout << "Instance went out of scope. Destructor ~em_tlv_member_t() should have been invoked with no errors, memory leaks, or crashes." << std::endl;
    std::cout << "Exiting em_tlv_member_t_destructor_invoked_valid_instance test" << std::endl;
}
