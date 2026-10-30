/**
 * Copyright 2026 Comcast Cable Communications Management, LLC
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
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include <string.h>
#include <vector>
#include <arpa/inet.h>
#include "em.h"
#include "dm_easy_mesh.h"

/*
 * AP Operational BSS TLV payload (tlv->value) layout:
 *   radios_num(1) | { ruid(6) bss_num(1) { bssid(6) ssid_len(1) ssid(n) } * bss_num } * radios_num
 */
class em_configuration_ap_op_bss_test_t : public testing::Test {
protected:
    em_interface_t ruid{};
    dm_easy_mesh_t dm;
    em_t *em = nullptr;

    void SetUp() override
    {
        unsigned char mac[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};

        memcpy(ruid.mac, mac, sizeof(mac));
        strncpy(ruid.name, "wlan0", sizeof(ruid.name) - 1);

        add_network_ssid("TEST");
        add_network_ssid("BSS1");

        // Agent service type: with no manager, get_peer_dm() falls back to this dm,
        // so the peer profile received in a Topology Response is stored and used.
        em = new em_t(&ruid, em_freq_band_24, &dm, nullptr, em_profile_type_3, em_service_type_agent, false);
    }

    void TearDown() override
    {
        delete em;
    }

    void add_network_ssid(const char *ssid)
    {
        em_network_ssid_info_t *info = &dm.m_network_ssid[dm.m_num_net_ssids].m_network_ssid_info;

        memset(info, 0, sizeof(em_network_ssid_info_t));
        strncpy(info->ssid, ssid, sizeof(info->ssid) - 1);
        dm.m_num_net_ssids++;
    }

    /* Fill the data model with existing BSS entries that do not match any BSS used by the tests */
    void add_existing_bss(unsigned int count)
    {
        for (unsigned int i = 0; i < count; i++) {
            em_bss_info_t *info = &dm.m_bss[dm.m_num_bss].m_bss_info;

            memset(info->bssid.mac, 0, sizeof(mac_address_t));
            memset(info->ruid.mac, 0, sizeof(mac_address_t));
            info->bssid.mac[0] = 0x10;
            info->bssid.mac[5] = static_cast<unsigned char>(i);
            dm.m_num_bss++;
        }
    }

    int handle_ap_operational_bss(unsigned char *buff, unsigned int len)
    {
        return static_cast<em_configuration_t *>(em)->handle_ap_operational_bss(buff, len);
    }

    int handle_ap_operational_bss(std::vector<unsigned char> &payload)
    {
        return handle_ap_operational_bss(payload.data(), static_cast<unsigned int>(payload.size()));
    }

    static void add_radio(std::vector<unsigned char> &payload, unsigned char last_octet, unsigned char bss_num)
    {
        unsigned char radio_id[6] = {0x00, 0x11, 0x22, 0x33, 0x44, last_octet};

        payload.insert(payload.end(), radio_id, radio_id + sizeof(radio_id));
        payload.push_back(bss_num);
    }

    static void add_bss(std::vector<unsigned char> &payload, unsigned char last_octet, const char *ssid)
    {
        unsigned char bssid[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, last_octet};
        size_t ssid_len = strlen(ssid);

        payload.insert(payload.end(), bssid, bssid + sizeof(bssid));
        payload.push_back(static_cast<unsigned char>(ssid_len));
        payload.insert(payload.end(), ssid, ssid + ssid_len);
    }

    em_profile_type_t get_peer_profile()
    {
        const mac_address_t src_al_mac = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
        return static_cast<em_configuration_t *>(em)->get_peer_profile(src_al_mac);
    }

    int handle_topology_response(std::vector<unsigned char> &frame)
    {
        return static_cast<em_configuration_t *>(em)->handle_topology_response(frame.data(),
                    static_cast<unsigned int>(frame.size()));
    }

    /* Ethernet header and CMDU header of a Topology Response, without TLVs */
    static std::vector<unsigned char> topology_response_header()
    {
        std::vector<unsigned char> frame(sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t), 0);
        em_raw_hdr_t *hdr = reinterpret_cast<em_raw_hdr_t *>(frame.data());
        em_cmdu_t *cmdu = reinterpret_cast<em_cmdu_t *>(frame.data() + sizeof(em_raw_hdr_t));
        unsigned char src[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
        unsigned char dst[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};

        memcpy(hdr->dst, dst, sizeof(dst));
        memcpy(hdr->src, src, sizeof(src));
        hdr->type = htons(ETH_P_1905);
        cmdu->type = htons(em_msg_type_topo_resp);
        cmdu->id = htons(1);
        cmdu->last_frag_ind = 1;

        return frame;
    }

    /* TLV header with the declared length, followed by the given value bytes */
    static void add_tlv(std::vector<unsigned char> &frame, unsigned char type, unsigned short declared_len,
                        const std::vector<unsigned char> &value)
    {
        frame.push_back(type);
        frame.push_back(static_cast<unsigned char>(declared_len >> 8));
        frame.push_back(static_cast<unsigned char>(declared_len & 0xff));
        frame.insert(frame.end(), value.begin(), value.end());
    }

    static void add_tlv(std::vector<unsigned char> &frame, unsigned char type, const std::vector<unsigned char> &value)
    {
        add_tlv(frame, type, static_cast<unsigned short>(value.size()), value);
    }

    /* Device Information TLV value: AL MAC and one IEEE 802.3 interface */
    static std::vector<unsigned char> device_info_value()
    {
        return {0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
                0x01,
                0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
    }

    /* AP Operational BSS TLV value: one radio with one BSS using a configured SSID */
    static std::vector<unsigned char> op_bss_value()
    {
        std::vector<unsigned char> value = {0x01};

        add_radio(value, 0x55, 1);
        add_bss(value, 0x01, "TEST");

        return value;
    }
};

/**
 * @brief NULL buffer and zero length payload are rejected.
 */
TEST_F(em_configuration_ap_op_bss_test_t, null_or_empty_payload_rejected)
{
    std::vector<unsigned char> payload;

    EXPECT_EQ(handle_ap_operational_bss(NULL, 1), -1);
    EXPECT_EQ(handle_ap_operational_bss(payload), -1);
    EXPECT_EQ(dm.get_num_bss(), 0u);
}

/**
 * @brief Payload with zero radios is valid and does not add any BSS.
 */
TEST_F(em_configuration_ap_op_bss_test_t, valid_zero_radios)
{
    std::vector<unsigned char> payload = {0x00};

    EXPECT_EQ(handle_ap_operational_bss(payload), 0);
    EXPECT_EQ(dm.get_num_bss(), 0u);
}

/**
 * @brief Radio header truncated: radio identifier is only partially present.
 */
TEST_F(em_configuration_ap_op_bss_test_t, truncated_radio_header_rejected)
{
    std::vector<unsigned char> payload = {0x01, 0x00, 0x11, 0x22};

    EXPECT_EQ(handle_ap_operational_bss(payload), -1);
    EXPECT_EQ(dm.get_num_bss(), 0u);
}

/**
 * @brief Number of radios exceeds the radio entries present in the payload.
 */
TEST_F(em_configuration_ap_op_bss_test_t, radios_num_exceeds_payload_rejected)
{
    std::vector<unsigned char> payload = {0x02};

    add_radio(payload, 0x55, 0);

    EXPECT_EQ(handle_ap_operational_bss(payload), -1);
    EXPECT_EQ(dm.get_num_bss(), 0u);
}

/**
 * @brief BSS fixed fields truncated: BSSID is only partially present.
 */
TEST_F(em_configuration_ap_op_bss_test_t, truncated_bss_rejected)
{
    std::vector<unsigned char> payload = {0x01};

    add_radio(payload, 0x55, 1);
    payload.insert(payload.end(), {0xAA, 0xBB, 0xCC});

    EXPECT_EQ(handle_ap_operational_bss(payload), -1);
    EXPECT_EQ(dm.get_num_bss(), 0u);
}

/**
 * @brief Declared SSID length exceeds the remaining payload bytes.
 */
TEST_F(em_configuration_ap_op_bss_test_t, ssid_len_exceeds_payload_rejected)
{
    std::vector<unsigned char> payload = {0x01};

    add_radio(payload, 0x55, 1);
    add_bss(payload, 0x01, "TEST");
    payload.pop_back();
    payload.pop_back();

    EXPECT_EQ(handle_ap_operational_bss(payload), -1);
    EXPECT_EQ(dm.get_num_bss(), 0u);
}

/**
 * @brief Number of BSSs exceeds the BSS entries present: second BSS is missing.
 */
TEST_F(em_configuration_ap_op_bss_test_t, bss_num_exceeds_payload_rejected)
{
    std::vector<unsigned char> payload = {0x01};

    add_radio(payload, 0x55, 2);
    add_bss(payload, 0x01, "T");

    EXPECT_EQ(handle_ap_operational_bss(payload), -1);
    EXPECT_EQ(dm.get_num_bss(), 0u);
}

/**
 * @brief A valid first radio followed by a truncated second radio is rejected
 *        without leaving the first radio's BSS in the data model.
 */
TEST_F(em_configuration_ap_op_bss_test_t, no_partial_update_on_later_truncation)
{
    std::vector<unsigned char> payload = {0x02};

    add_radio(payload, 0x55, 1);
    add_bss(payload, 0x01, "TEST");
    payload.insert(payload.end(), {0x00, 0x66, 0x77});

    EXPECT_EQ(handle_ap_operational_bss(payload), -1);
    EXPECT_EQ(dm.get_num_bss(), 0u);
    EXPECT_EQ(dm.m_db_cfg_param.db_cfg_type, db_cfg_type_none);
}

/**
 * @brief Valid payload with one radio and one BSS is accepted and stored.
 */
TEST_F(em_configuration_ap_op_bss_test_t, valid_one_radio_one_bss)
{
    std::vector<unsigned char> payload = {0x01};

    add_radio(payload, 0x55, 1);
    add_bss(payload, 0x01, "TEST");

    EXPECT_EQ(handle_ap_operational_bss(payload), 0);
    ASSERT_EQ(dm.get_num_bss(), 1u);
    EXPECT_STREQ(dm.m_bss[0].m_bss_info.ssid, "TEST");
    EXPECT_TRUE(dm.m_bss[0].m_bss_info.enabled);
}

/**
 * @brief Valid payload with two radios, each with one BSS, is accepted and stored.
 */
TEST_F(em_configuration_ap_op_bss_test_t, valid_multi_radio)
{
    std::vector<unsigned char> payload = {0x02};

    add_radio(payload, 0x55, 1);
    add_bss(payload, 0x01, "TEST");
    add_radio(payload, 0x66, 1);
    add_bss(payload, 0x02, "BSS1");

    EXPECT_EQ(handle_ap_operational_bss(payload), 0);
    ASSERT_EQ(dm.get_num_bss(), 2u);
    EXPECT_STREQ(dm.m_bss[0].m_bss_info.ssid, "TEST");
    EXPECT_STREQ(dm.m_bss[1].m_bss_info.ssid, "BSS1");
}

/**
 * @brief Valid payload with one radio and two BSSs is accepted and stored.
 */
TEST_F(em_configuration_ap_op_bss_test_t, valid_one_radio_two_bss)
{
    std::vector<unsigned char> payload = {0x01};

    add_radio(payload, 0x55, 2);
    add_bss(payload, 0x01, "TEST");
    add_bss(payload, 0x02, "BSS1");

    EXPECT_EQ(handle_ap_operational_bss(payload), 0);
    EXPECT_EQ(dm.get_num_bss(), 2u);
}

/**
 * @brief Topology Response with only one byte of a TLV header after the CMDU header is rejected.
 */
TEST_F(em_configuration_ap_op_bss_test_t, topology_response_one_byte_tlv_header_rejected)
{
    std::vector<unsigned char> frame = topology_response_header();

    frame.push_back(em_tlv_type_device_info);

    EXPECT_EQ(handle_topology_response(frame), -1);
    EXPECT_EQ(dm.get_num_bss(), 0u);
}

/**
 * @brief Topology Response with only two bytes of a TLV header after the CMDU header is rejected.
 */
TEST_F(em_configuration_ap_op_bss_test_t, topology_response_two_byte_tlv_header_rejected)
{
    std::vector<unsigned char> frame = topology_response_header();

    frame.push_back(em_tlv_type_device_info);
    frame.push_back(0x00);

    EXPECT_EQ(handle_topology_response(frame), -1);
    EXPECT_EQ(dm.get_num_bss(), 0u);
}

/**
 * @brief AP Operational BSS TLV placed before the Profile TLV declares more bytes
 *        than the received frame contains: rejected before any data is used.
 */
TEST_F(em_configuration_ap_op_bss_test_t, topology_response_op_bss_len_exceeds_frame_before_profile_rejected)
{
    std::vector<unsigned char> frame = topology_response_header();

    add_tlv(frame, em_tlv_type_device_info, device_info_value());
    add_tlv(frame, em_tlv_type_operational_bss, 200, op_bss_value());
    add_tlv(frame, em_tlv_type_profile, {em_profile_type_2});
    add_tlv(frame, em_tlv_type_eom, {});

    EXPECT_EQ(handle_topology_response(frame), -1);
    EXPECT_EQ(dm.get_num_bss(), 0u);
}

/**
 * @brief AP Operational BSS TLV placed after the Profile TLV declares more bytes
 *        than the received frame contains: rejected before any data is used.
 */
TEST_F(em_configuration_ap_op_bss_test_t, topology_response_op_bss_len_exceeds_frame_after_profile_rejected)
{
    std::vector<unsigned char> frame = topology_response_header();

    add_tlv(frame, em_tlv_type_device_info, device_info_value());
    add_tlv(frame, em_tlv_type_profile, {em_profile_type_2});
    add_tlv(frame, em_tlv_type_operational_bss, 200, op_bss_value());

    EXPECT_EQ(handle_topology_response(frame), -1);
    EXPECT_EQ(dm.get_num_bss(), 0u);
}

/**
 * @brief Valid Topology Response is accepted. The TLV lengths are encoded in network
 *        byte order, so this also verifies the ntohs() conversion before the length checks.
 */
TEST_F(em_configuration_ap_op_bss_test_t, topology_response_valid)
{
    std::vector<unsigned char> frame = topology_response_header();

    add_tlv(frame, em_tlv_type_device_info, device_info_value());
    add_tlv(frame, em_tlv_type_profile, {em_profile_type_2});
    add_tlv(frame, em_tlv_type_operational_bss, op_bss_value());
    add_tlv(frame, em_tlv_type_eom, {});

    EXPECT_EQ(handle_topology_response(frame), 0);
    EXPECT_EQ(get_peer_profile(), em_profile_type_2);
    ASSERT_EQ(dm.get_num_bss(), 1u);
    EXPECT_STREQ(dm.m_bss[0].m_bss_info.ssid, "TEST");
}

/**
 * @brief Two new BSSs when only one free BSS entry is left: rejected before
 *        any BSS is inserted, so no partial update remains in the data model.
 */
TEST_F(em_configuration_ap_op_bss_test_t, bss_capacity_exceeded_no_partial_update)
{
    std::vector<unsigned char> payload = {0x01};

    add_existing_bss(EM_MAX_BSSS - 1);
    add_radio(payload, 0x55, 2);
    add_bss(payload, 0x01, "TEST");
    add_bss(payload, 0x02, "BSS1");

    EXPECT_EQ(handle_ap_operational_bss(payload), -1);
    EXPECT_EQ(dm.get_num_bss(), static_cast<unsigned int>(EM_MAX_BSSS - 1));
    EXPECT_EQ(dm.m_db_cfg_param.db_cfg_type, db_cfg_type_none);
}

/**
 * @brief The same new BSS reported twice needs only one free BSS entry, so it is accepted.
 */
TEST_F(em_configuration_ap_op_bss_test_t, bss_capacity_repeated_bss_counted_once)
{
    std::vector<unsigned char> payload = {0x01};

    add_existing_bss(EM_MAX_BSSS - 1);
    add_radio(payload, 0x55, 2);
    add_bss(payload, 0x01, "TEST");
    add_bss(payload, 0x01, "TEST");

    EXPECT_EQ(handle_ap_operational_bss(payload), 0);
    EXPECT_EQ(dm.get_num_bss(), static_cast<unsigned int>(EM_MAX_BSSS));
}
