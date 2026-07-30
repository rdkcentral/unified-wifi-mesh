#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <stdio.h>
#include <cstring>
#include <iostream>
#include "em_cmd_backhaul_steer.h"

// Helper: parse a colon separated MAC string into a 6-byte array.
static void parse_mac(const char *str, unsigned char out[6])
{
    unsigned int b[6];
    if (sscanf(str, "%02X:%02X:%02X:%02X:%02X:%02X",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6) {
        memset(out, 0, 6);
        return;
    }
    for (int i = 0; i < 6; i++)
        out[i] = static_cast<unsigned char>(b[i]);
}

/**
 * @brief Tests the creation of an em_cmd_backhaul_steer_t instance with valid standard parameters.
 *
 * Verifies that the constructor properly initializes type, name, orchestration
 * descriptor, and copies all MAC/BSSID/channel parameters without throwing.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 001@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize em_cmd_backhaul_steer_params_t with valid values. | al_mac="AA:BB:CC:DD:EE:FF", sta_mac="00:11:22:33:44:55", target_bssid="66:77:88:99:AA:BB", op_class=81, channel=6 | Structure correctly initialized. | Should be successful |
 * | 02 | Invoke the em_cmd_backhaul_steer_t constructor. | params as above | Instance created without exception; m_type, m_name, m_orch_desc, and params match. | Should Pass |
 */
TEST(em_cmd_backhaul_steer_t, em_cmd_backhaul_steer_t_valid_standard_parameters)
{
    std::cout << "Entering em_cmd_backhaul_steer_t_valid_standard_parameters test" << std::endl;

    em_cmd_backhaul_steer_params_t params{};
    const char *al_mac_str     = "AA:BB:CC:DD:EE:FF";
    const char *sta_mac_str    = "00:11:22:33:44:55";
    const char *bssid_str      = "66:77:88:99:AA:BB";

    unsigned char al_mac_bytes[6], sta_mac_bytes[6], bssid_bytes[6];
    parse_mac(al_mac_str,  al_mac_bytes);
    parse_mac(sta_mac_str, sta_mac_bytes);
    parse_mac(bssid_str,   bssid_bytes);

    memcpy(params.al_mac,       al_mac_bytes,  6);
    memcpy(params.sta_mac,      sta_mac_bytes, 6);
    memcpy(params.target_bssid, bssid_bytes,   6);
    params.op_class = 81;
    params.channel  = 6;

    std::cout << "al_mac: "       << al_mac_str  << std::endl;
    std::cout << "sta_mac: "      << sta_mac_str << std::endl;
    std::cout << "target_bssid: " << bssid_str   << std::endl;
    std::cout << "op_class: "     << params.op_class << std::endl;
    std::cout << "channel: "      << params.channel  << std::endl;

    EXPECT_NO_THROW({
        em_cmd_backhaul_steer_t obj(params);
        std::cout << "Instance created successfully." << std::endl;

        EXPECT_EQ(obj.m_type, em_cmd_type_backhaul_steer);
        EXPECT_STREQ(obj.m_name, "steer_backhaul");
        EXPECT_EQ(obj.m_orch_op_idx, 0);
        EXPECT_EQ(obj.m_num_orch_desc, 1u);
        EXPECT_EQ(obj.m_orch_desc[0].op, dm_orch_type_backhaul_steer);
        EXPECT_EQ(obj.m_orch_desc[0].submit, true);
        EXPECT_EQ(obj.m_svc, em_service_type_ctrl);

        EXPECT_EQ(memcmp(obj.m_param.u.backhaul_steer_params.al_mac,       al_mac_bytes,  6), 0);
        EXPECT_EQ(memcmp(obj.m_param.u.backhaul_steer_params.sta_mac,      sta_mac_bytes, 6), 0);
        EXPECT_EQ(memcmp(obj.m_param.u.backhaul_steer_params.target_bssid, bssid_bytes,   6), 0);
        EXPECT_EQ(obj.m_param.u.backhaul_steer_params.op_class, 81u);
        EXPECT_EQ(obj.m_param.u.backhaul_steer_params.channel,  6u);

        obj.deinit();
    });

    std::cout << "Exiting em_cmd_backhaul_steer_t_valid_standard_parameters test" << std::endl;
}

/**
 * @brief Tests the creation of an em_cmd_backhaul_steer_t instance with all-zero parameters.
 *
 * Verifies that the constructor succeeds with zeroed MAC addresses and channel fields,
 * representing a minimal/default initialization scenario.
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
 * | 01 | Zero-initialize em_cmd_backhaul_steer_params_t. | all fields = 0 | Structure zeroed. | Should be successful |
 * | 02 | Invoke the constructor with zeroed params. | params{} | Instance created without exception; type and name correct. | Should Pass |
 */
TEST(em_cmd_backhaul_steer_t, em_cmd_backhaul_steer_t_valid_zero_parameters)
{
    std::cout << "Entering em_cmd_backhaul_steer_t_valid_zero_parameters test" << std::endl;

    em_cmd_backhaul_steer_params_t params{};
    memset(&params, 0, sizeof(params));

    EXPECT_NO_THROW({
        em_cmd_backhaul_steer_t obj(params);
        std::cout << "Instance created successfully." << std::endl;

        EXPECT_EQ(obj.m_type, em_cmd_type_backhaul_steer);
        EXPECT_STREQ(obj.m_name, "steer_backhaul");
        EXPECT_EQ(obj.m_orch_op_idx, 0);
        EXPECT_EQ(obj.m_num_orch_desc, 1u);
        EXPECT_EQ(obj.m_orch_desc[0].op, dm_orch_type_backhaul_steer);
        EXPECT_EQ(obj.m_orch_desc[0].submit, true);
        EXPECT_EQ(obj.m_svc, em_service_type_ctrl);
        EXPECT_EQ(obj.m_param.u.backhaul_steer_params.op_class, 0u);
        EXPECT_EQ(obj.m_param.u.backhaul_steer_params.channel,  0u);

        obj.deinit();
    });

    std::cout << "Exiting em_cmd_backhaul_steer_t_valid_zero_parameters test" << std::endl;
}

/**
 * @brief Tests the creation of an em_cmd_backhaul_steer_t instance with maximum boundary values.
 *
 * Verifies that the constructor correctly handles maximum uint8 (0xFF) values for all
 * MAC/BSSID bytes, op_class, and channel fields.
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
 * | 01 | Initialize params with broadcast MACs and max uint values. | all MACs="FF:FF:FF:FF:FF:FF", op_class=255, channel=255 | Structure correctly initialized. | Should be successful |
 * | 02 | Invoke the constructor. | params as above | Instance created without exception; params stored correctly. | Should Pass |
 */
TEST(em_cmd_backhaul_steer_t, em_cmd_backhaul_steer_t_valid_max_boundary_values)
{
    std::cout << "Entering em_cmd_backhaul_steer_t_valid_max_boundary_values test" << std::endl;

    em_cmd_backhaul_steer_params_t params{};
    const char *mac_ff = "FF:FF:FF:FF:FF:FF";
    unsigned char ff_bytes[6];
    parse_mac(mac_ff, ff_bytes);

    memcpy(params.al_mac,       ff_bytes, 6);
    memcpy(params.sta_mac,      ff_bytes, 6);
    memcpy(params.target_bssid, ff_bytes, 6);
    params.op_class = 255;
    params.channel  = 255;

    EXPECT_NO_THROW({
        em_cmd_backhaul_steer_t obj(params);
        std::cout << "Instance created successfully." << std::endl;

        EXPECT_EQ(obj.m_type, em_cmd_type_backhaul_steer);
        EXPECT_STREQ(obj.m_name, "steer_backhaul");
        EXPECT_EQ(memcmp(obj.m_param.u.backhaul_steer_params.al_mac,       ff_bytes, 6), 0);
        EXPECT_EQ(memcmp(obj.m_param.u.backhaul_steer_params.sta_mac,      ff_bytes, 6), 0);
        EXPECT_EQ(memcmp(obj.m_param.u.backhaul_steer_params.target_bssid, ff_bytes, 6), 0);
        EXPECT_EQ(obj.m_param.u.backhaul_steer_params.op_class, 255u);
        EXPECT_EQ(obj.m_param.u.backhaul_steer_params.channel,  255u);

        obj.deinit();
    });

    std::cout << "Exiting em_cmd_backhaul_steer_t_valid_max_boundary_values test" << std::endl;
}
