/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2026 RDK Management
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
#include <cstring>
#include "dm_easy_mesh_ctrl.h"
#include "dm_easy_mesh.h"
#include "tr_181.h"

/* SetSSID AKMsAllowed parsing: empty string is Open, invalid values are rejected. */

TEST(tr_181_akms_Test, EmptyStringIsEmptyArrayAndOpen) {
    cJSON *arr = tr_181_t::create_akms_array("");
    ASSERT_NE(arr, nullptr);
    EXPECT_EQ(cJSON_GetArraySize(arr), 0);
    EXPECT_STREQ(tr_181_t::akms_array_to_auth_type(arr), "Open");
    cJSON_Delete(arr);
}

TEST(tr_181_akms_Test, SingleAkmValues) {
    struct { const char *akms; const char *auth; } cases[] = {
        { "psk",     "WPA2 Personal"   },
        { "sae",     "WPA3 Personal"   },
        { "psk+sae", "WPA3 Transition" },
    };
    for (auto &c : cases) {
        cJSON *arr = tr_181_t::create_akms_array(c.akms);
        ASSERT_NE(arr, nullptr) << c.akms;
        ASSERT_EQ(cJSON_GetArraySize(arr), 1) << c.akms;
        EXPECT_STREQ(cJSON_GetStringValue(cJSON_GetArrayItem(arr, 0)), c.akms);
        EXPECT_STREQ(tr_181_t::akms_array_to_auth_type(arr), c.auth) << c.akms;
        cJSON_Delete(arr);
    }
}

TEST(tr_181_akms_Test, InvalidValuesAreRejected) {
    EXPECT_EQ(tr_181_t::create_akms_array(NULL), nullptr);
    EXPECT_EQ(tr_181_t::create_akms_array("wep"), nullptr);
    EXPECT_EQ(tr_181_t::create_akms_array("psk,sae"), nullptr);
    EXPECT_EQ(tr_181_t::create_akms_array("   "), nullptr);
    EXPECT_EQ(tr_181_t::akms_array_to_auth_type(NULL), nullptr);
}

/* BSS AKMsAllowed reporting: formatting of stored suites and profile derivation. */

class akms_allowed_Test : public ::testing::Test {
protected:
    dm_easy_mesh_ctrl_t dm_ctrl;
    dm_easy_mesh_t dm;
    em_bss_info_t bi;
    char buf[64];

    void SetUp() override {
        memset(&bi, 0, sizeof(bi));
        memset(buf, 0, sizeof(buf));
    }

    void set_profile(const char *auth_type, em_haul_type_t haul) {
        em_network_ssid_info_t *prof = dm.get_network_ssid(0)->get_network_ssid_info();
        memset(prof, 0, sizeof(*prof));
        snprintf(prof->auth_type, sizeof(prof->auth_type), "%s", auth_type);
        prof->num_hauls = 1;
        prof->haul_type[0] = haul;
        dm.set_num_network_ssid(1);
    }

    void set_radio(const unsigned char mac[6], em_freq_band_t band) {
        em_radio_info_t *ri = dm.get_radio_by_ref(0).get_radio_info();
        memset(ri, 0, sizeof(*ri));
        memcpy(ri->intf.mac, mac, sizeof(mac_address_t));
        ri->band = band;
        dm.set_num_radios(1);
    }
};

TEST_F(akms_allowed_Test, FormatStoredSuites) {
    em_short_string_t akms[3] = { "wpa2-psk", "sae", "" };
    em_short_string_t wpa1[1] = { "wpa-psk" };

    dm_ctrl.fill_akms_allowed(akms, 1, buf, sizeof(buf));
    EXPECT_STREQ(buf, "psk");
    /* akm_t has no WPA1 value; psk is the closest expressible suite. */
    dm_ctrl.fill_akms_allowed(wpa1, 1, buf, sizeof(buf));
    EXPECT_STREQ(buf, "psk");
    dm_ctrl.fill_akms_allowed(&akms[1], 1, buf, sizeof(buf));
    EXPECT_STREQ(buf, "sae");
    dm_ctrl.fill_akms_allowed(akms, 2, buf, sizeof(buf));
    EXPECT_STREQ(buf, "psk+sae");
    dm_ctrl.fill_akms_allowed(akms, 0, buf, sizeof(buf));
    EXPECT_STREQ(buf, "");
}

TEST_F(akms_allowed_Test, FronthaulProfileModes) {
    struct { const char *auth; const char *akms; } cases[] = {
        { "Open",            ""        },
        { "WPA2 Personal",   "psk"     },
        { "WPA3 Personal",   "sae"     },
        { "WPA3 Transition", "psk+sae" },
    };
    bi.id.haul_type = em_haul_type_fronthaul;
    for (auto &c : cases) {
        set_profile(c.auth, em_haul_type_fronthaul);
        dm_ctrl.fill_bss_akms_allowed(&dm, &bi, false, buf, sizeof(buf));
        EXPECT_STREQ(buf, c.akms) << c.auth;
        /* The backhaul side of a fronthaul BSS is always empty. */
        dm_ctrl.fill_bss_akms_allowed(&dm, &bi, true, buf, sizeof(buf));
        EXPECT_STREQ(buf, "") << c.auth;
    }
}

TEST_F(akms_allowed_Test, BackhaulProfileFillsBackhaulSideOnly) {
    set_profile("WPA3 Personal", em_haul_type_backhaul);
    bi.id.haul_type = em_haul_type_backhaul;

    dm_ctrl.fill_bss_akms_allowed(&dm, &bi, true, buf, sizeof(buf));
    EXPECT_STREQ(buf, "sae");
    dm_ctrl.fill_bss_akms_allowed(&dm, &bi, false, buf, sizeof(buf));
    EXPECT_STREQ(buf, "");
}

TEST_F(akms_allowed_Test, SixGhzOverrideForcesSae) {
    const unsigned char mac[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };

    set_profile("WPA2 Personal", em_haul_type_fronthaul);
    set_radio(mac, em_freq_band_6);
    bi.id.haul_type = em_haul_type_fronthaul;
    memcpy(bi.ruid.mac, mac, sizeof(mac_address_t));

    dm_ctrl.fill_bss_akms_allowed(&dm, &bi, false, buf, sizeof(buf));
    EXPECT_STREQ(buf, "sae");
}

TEST_F(akms_allowed_Test, UnknownAuthTypeFallsBackToStoredSuites) {
    set_profile("Not A Mode", em_haul_type_fronthaul);
    bi.id.haul_type = em_haul_type_fronthaul;
    bi.num_fronthaul_akms = 2;
    snprintf(bi.fronthaul_akm[0], sizeof(em_short_string_t), "wpa2-psk");
    snprintf(bi.fronthaul_akm[1], sizeof(em_short_string_t), "sae");

    dm_ctrl.fill_bss_akms_allowed(&dm, &bi, false, buf, sizeof(buf));
    EXPECT_STREQ(buf, "psk+sae");
}
