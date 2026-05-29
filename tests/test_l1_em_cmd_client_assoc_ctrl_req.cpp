#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <stdio.h>
#include <cstring>
#include <iostream>

#include "em_cmd_client_assoc_ctrl_req.h"

/* Helper: parse MAC string */
static void parse_mac(const char *str, unsigned char out[6])
{
    unsigned int b[6] = {0};
    int parsed = sscanf(str, "%02X:%02X:%02X:%02X:%02X:%02X",
                        &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]);

    EXPECT_EQ(parsed, 6) << "Invalid MAC string: " << (str ? str : "(null)");

    for (int i = 0; i < 6; i++)
        out[i] = static_cast<unsigned char>(b[i]);
}

/*
 * -------------------------------------------------------------
 * TEST CASE 1: Valid standard parameters
 * -------------------------------------------------------------
 */
TEST(em_cmd_client_assoc_ctrl_req_t, valid_standard_parameters)
{
    std::cout << "Entering valid_standard_parameters test" << std::endl;

    em_cmd_client_assoc_params_t params{};

    const char *bssid_str   = "11:22:33:44:55:66";
    const char *sta_mac_str = "AA:BB:CC:DD:EE:FF";

    unsigned char bssid[6], sta_mac[6];

    parse_mac(bssid_str, bssid);
    parse_mac(sta_mac_str, sta_mac);

    memcpy(params.bssid, bssid, 6);
    params.assoc_control = 0;  // block
    params.validity_period = 30;
    params.sta_count = 1;
    memcpy(params.sta_list[0], sta_mac, 6);

    EXPECT_NO_THROW({
        dm_easy_mesh_t dm;
        em_cmd_client_assoc_ctrl_req_t obj(params, dm);

        EXPECT_EQ(obj.m_type, em_cmd_type_client_assoc_ctrl_req);
        EXPECT_STREQ(obj.m_name, "client_assoc");
        EXPECT_EQ(obj.m_orch_op_idx, 0u);
        EXPECT_EQ(obj.m_num_orch_desc, 1u);
        EXPECT_EQ(obj.m_orch_desc[0].op, dm_orch_type_client_assoc);
        EXPECT_EQ(obj.m_orch_desc[0].submit, true);
        EXPECT_EQ(obj.m_svc, em_service_type_ctrl);

        EXPECT_EQ(memcmp(obj.m_param.u.client_assoc_params.bssid, bssid, 6), 0);
        EXPECT_EQ(obj.m_param.u.client_assoc_params.assoc_control, 0);
        EXPECT_EQ(obj.m_param.u.client_assoc_params.validity_period, 30);
        EXPECT_EQ(obj.m_param.u.client_assoc_params.sta_count, 1);

        EXPECT_EQ(memcmp(obj.m_param.u.client_assoc_params.sta_list[0], sta_mac, 6), 0);

        obj.deinit();
    });

    std::cout << "Exiting valid_standard_parameters test" << std::endl;
}

/*
 * -------------------------------------------------------------
 * TEST CASE 2: Zero parameters
 * -------------------------------------------------------------
 */
TEST(em_cmd_client_assoc_ctrl_req_t, constructs_with_zero_parameters)
{
    std::cout << "Entering constructs_with_zero_parameters test" << std::endl;
    em_cmd_client_assoc_params_t params{};
    memset(&params, 0, sizeof(params));

    EXPECT_NO_THROW({
        dm_easy_mesh_t dm;
        em_cmd_client_assoc_ctrl_req_t obj(params, dm);

        EXPECT_EQ(obj.m_type, em_cmd_type_client_assoc_ctrl_req);
        EXPECT_STREQ(obj.m_name, "client_assoc");

        EXPECT_EQ(obj.m_param.u.client_assoc_params.assoc_control, 0);
        EXPECT_EQ(obj.m_param.u.client_assoc_params.validity_period, 0);
        EXPECT_EQ(obj.m_param.u.client_assoc_params.sta_count, 0);

        obj.deinit();
    });

    std::cout << "Exiting valid_zero_parameters test" << std::endl;
}

/*
 * -------------------------------------------------------------
 * TEST CASE 3: Maximum boundary values
 * -------------------------------------------------------------
 */
TEST(em_cmd_client_assoc_ctrl_req_t, valid_max_boundary_values)
{
    std::cout << "Entering valid_max_boundary_values test" << std::endl;

    em_cmd_client_assoc_params_t params{};

    const char *mac_ff = "FF:FF:FF:FF:FF:FF";
    unsigned char ff[6];

    parse_mac(mac_ff, ff);

    memcpy(params.bssid, ff, 6);
    params.assoc_control = 1;
    params.validity_period = 65535; // max for unsigned short
    params.sta_count = 1;
    memcpy(params.sta_list[0], ff, 6);

    EXPECT_NO_THROW({
        dm_easy_mesh_t dm;
        em_cmd_client_assoc_ctrl_req_t obj(params, dm);

        EXPECT_EQ(obj.m_type, em_cmd_type_client_assoc_ctrl_req);
        EXPECT_STREQ(obj.m_name, "client_assoc");

        EXPECT_EQ(memcmp(obj.m_param.u.client_assoc_params.bssid, ff, 6), 0);
        EXPECT_EQ(obj.m_param.u.client_assoc_params.validity_period, 65535);
        EXPECT_EQ(obj.m_param.u.client_assoc_params.sta_count, 1);

        EXPECT_EQ(memcmp(obj.m_param.u.client_assoc_params.sta_list[0], ff, 6), 0);
        obj.deinit();
    });

    std::cout << "Exiting valid_max_boundary_values test" << std::endl;
}

/*
 * -------------------------------------------------------------
 * TEST CASE 4: Multiple STA entries
 * -------------------------------------------------------------
 */
TEST(em_cmd_client_assoc_ctrl_req_t, multiple_sta_entries)
{
    std::cout << "Entering multiple_sta_entries test" << std::endl;

    em_cmd_client_assoc_params_t params{};

    const char *sta1 = "00:11:22:33:44:55";
    const char *sta2 = "66:77:88:99:AA:BB";

    unsigned char mac1[6], mac2[6];

    parse_mac(sta1, mac1);
    parse_mac(sta2, mac2);

    params.sta_count = 2;
    memcpy(params.sta_list[0], mac1, 6);
    memcpy(params.sta_list[1], mac2, 6);

    EXPECT_NO_THROW({
        dm_easy_mesh_t dm;
        em_cmd_client_assoc_ctrl_req_t obj(params, dm);

        EXPECT_EQ(obj.m_param.u.client_assoc_params.sta_count, 2);

        EXPECT_EQ(memcmp(obj.m_param.u.client_assoc_params.sta_list[0], mac1, 6), 0);
        EXPECT_EQ(memcmp(obj.m_param.u.client_assoc_params.sta_list[1], mac2, 6), 0);
        obj.deinit();
    });

    std::cout << "Exiting multiple_sta_entries test" << std::endl;
}
