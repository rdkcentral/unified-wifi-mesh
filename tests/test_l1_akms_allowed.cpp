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
#include "em.h"
#include "em_configuration.h"
#include "em_mgr.h"
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

/* AKM Suite Capabilities TLV: an open BSS stores one empty suite name that must not
   be advertised or counted. */

class akm_suite_cap_Test : public ::testing::Test {
protected:
    dm_easy_mesh_t dm;
    em_interface_t ruid;
    uint8_t buff[MAX_EM_BUFF_SZ];

    void SetUp() override {
        memset(&ruid, 0, sizeof(ruid));
        const unsigned char mac[] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
        memcpy(ruid.mac, mac, sizeof(mac_address_t));
        memset(buff, 0xaa, sizeof(buff));
        dm.set_num_bss(0);
    }

    /* NULL: haul not on this BSS. "": open BSS. */
    void add_bss(const char *fronthaul_akm, const char *backhaul_akm) {
        unsigned int idx = dm.get_num_bss();
        em_bss_info_t *bi = dm.get_bss_info(idx);
        memset(bi, 0, sizeof(*bi));
        if (fronthaul_akm != NULL) {
            snprintf(bi->fronthaul_akm[0], sizeof(em_short_string_t), "%s", fronthaul_akm);
            bi->num_fronthaul_akms = 1;
        }
        if (backhaul_akm != NULL) {
            snprintf(bi->backhaul_akm[0], sizeof(em_short_string_t), "%s", backhaul_akm);
            bi->num_backhaul_akms = 1;
        }
        dm.set_num_bss(idx + 1);
    }

    int build() {
        em_t em(&ruid, em_freq_band_24, &dm, NULL, em_profile_type_3, em_service_type_agent);
        return em.create_akm_suite_cap_tlv(buff);
    }
};

TEST_F(akm_suite_cap_Test, OpenBssIsNotAdvertised) {
    add_bss("", NULL);          /* open fronthaul */
    add_bss("wpa2-psk", NULL);
    add_bss(NULL, "sae");

    const int len = build();

    /* [bh_count][bh suite][fh_count][fh suite] */
    EXPECT_EQ(len, 1 + 4 + 1 + 4);
    EXPECT_EQ(buff[0], 1);                                  /* backhaul count */
    EXPECT_EQ(memcmp(&buff[1], "\x00\x0f\xac\x08", 4), 0);  /* sae */
    EXPECT_EQ(buff[5], 1);                                  /* fronthaul count */
    EXPECT_EQ(memcmp(&buff[6], "\x00\x0f\xac\x02", 4), 0);  /* psk */
}

TEST_F(akm_suite_cap_Test, AllOpenAdvertisesNoSuites) {
    add_bss("", "");
    add_bss("", NULL);

    const int len = build();

    EXPECT_EQ(len, 1 + 1);
    EXPECT_EQ(buff[0], 0);
    EXPECT_EQ(buff[1], 0);
}

TEST_F(akm_suite_cap_Test, SuiteIsAdvertisedOncePerHaul) {
    add_bss("wpa2-psk", NULL);
    add_bss("wpa2-psk", NULL);

    const int len = build();

    EXPECT_EQ(len, 1 + 1 + 4);
    EXPECT_EQ(buff[0], 0);
    EXPECT_EQ(buff[1], 1);
    EXPECT_EQ(memcmp(&buff[2], "\x00\x0f\xac\x02", 4), 0);
}

/* AKM Suite Cap storage: a BSS whose own dm has no profile takes the profile from
   another dm of the same network, never from a different network. */

class StubEmMgr : public em_mgr_t {
public:
    std::vector<dm_easy_mesh_t *> dms;

    dm_easy_mesh_t *get_first_dm() override { return dms.empty() ? nullptr : dms[0]; }
    dm_easy_mesh_t *get_next_dm(dm_easy_mesh_t *dm) override {
        for (size_t i = 0; i + 1 < dms.size(); i++) {
            if (dms[i] == dm) return dms[i + 1];
        }
        return nullptr;
    }

    unsigned short get_next_msg_id() { return 0; }
    void publish_network_topology() override {}
    bool is_data_model_initialized() override { return true; }
    em_t *find_em_for_msg_type(unsigned char*, unsigned int, em_t*) override { return nullptr; }
    int data_model_init(const char*) override { return 0; }
    int orch_init() override { return 0; }
    void input_listener() override {}
    void start_complete() override {}
    void handle_event(em_event_t*) override {}
    void handle_5s_tick() override {}
    void handle_2s_tick() override {}
    void handle_1s_tick() override {}
    void handle_250ms_tick() override {}
    void update_network_topology() override {}
    dm_easy_mesh_t *get_data_model(const char*, const unsigned char*) override { return nullptr; }
    dm_easy_mesh_t *create_data_model(const char*, const em_interface_t*, em_profile_type_t) override { return nullptr; }
    void delete_data_model(const char*, const unsigned char*) override {}
    void delete_all_data_models() override {}
    int update_tables(dm_easy_mesh_t*) override { return 0; }
    int load_net_ssid_table() override { return 0; }
    void debug_probe() override {}
    void io(void*, bool) override {}
    em_service_type_t get_service_type() override { return em_service_type_ctrl; }
};

class akm_suite_store_Test : public ::testing::Test {
protected:
    StubEmMgr mgr;
    dm_easy_mesh_t target, same_net, other_net;

    void SetUp() override {
        set_net_id(target, "net1");
        set_net_id(same_net, "net1");
        set_net_id(other_net, "net2");

        em_bss_info_t *bi = target.get_bss_info(0);
        memset(bi, 0, sizeof(*bi));
        bi->id.haul_type = em_haul_type_fronthaul;
        target.set_num_bss(1);
    }

    static void set_net_id(dm_easy_mesh_t &dm, const char *net_id) {
        snprintf(dm.get_device_info()->id.net_id, sizeof(em_long_string_t), "%s", net_id);
    }

    static void set_profile(dm_easy_mesh_t &dm, const char *auth_type) {
        em_network_ssid_info_t *prof = dm.get_network_ssid(0)->get_network_ssid_info();
        memset(prof, 0, sizeof(*prof));
        snprintf(prof->auth_type, sizeof(prof->auth_type), "%s", auth_type);
        prof->num_hauls = 1;
        prof->haul_type[0] = em_haul_type_fronthaul;
        dm.set_num_network_ssid(1);
    }

    /* TLV advertising no backhaul suite and one fronthaul sae suite. */
    void store() {
        unsigned char tlv[] = { 0, 1, 0x00, 0x0f, 0xac, 0x08 };
        em_configuration_t::store_akm_suite_cap(&target, tlv, sizeof(tlv), &mgr);
    }
};

TEST_F(akm_suite_store_Test, SameNetworkProfileIsUsed) {
    set_profile(other_net, "Open");
    set_profile(same_net, "WPA2 Personal");
    mgr.dms = { &other_net, &same_net };

    store();

    em_bss_info_t *bi = target.get_bss_info(0);
    EXPECT_EQ(bi->num_fronthaul_akms, 1);
    EXPECT_STREQ(bi->fronthaul_akm[0], "wpa2-psk");
    EXPECT_EQ(bi->num_backhaul_akms, 0);
}

TEST_F(akm_suite_store_Test, OtherNetworkProfileIsIgnored) {
    set_profile(other_net, "Open");
    mgr.dms = { &other_net };

    store();

    /* No usable profile: the advertised union stays the fallback. */
    em_bss_info_t *bi = target.get_bss_info(0);
    EXPECT_EQ(bi->num_fronthaul_akms, 1);
    EXPECT_STREQ(bi->fronthaul_akm[0], "sae");
}
