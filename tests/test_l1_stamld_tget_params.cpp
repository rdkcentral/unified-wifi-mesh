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
#include <sanitizer/lsan_interface.h>
#include <gtest/gtest.h>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <string>
#include "em_ctrl.h"

/*
 * dm_easy_mesh_ctrl_t::stamld_tget_params(): the associated STA MLD loop is bounded by
 * EM_MAX_ASSOC_STA_MLD whatever m_num_assoc_sta_mld says, and a NULL dm / ap_mld / property is
 * rejected with bus_error_invalid_input. The handler takes the data model as an argument, so the test
 * builds one directly. The AP MLD address is all zeros, so any zero-filled entry the loop would read
 * past m_assoc_sta_mld[] also matches and shows up as an extra row.
 */

class stamld_tget_params_Test : public ::testing::Test {
protected:
    dm_easy_mesh_t *dm = nullptr;
    em_ap_mld_info_t ami;
    const char *root = "Device.WiFi.DataElements.Network.Device.1.APMLD.1.STAMLD.";

    void SetUp() override {
        __lsan_disable();
        dm = new dm_easy_mesh_t;
        dm->init();
        memset(&ami, 0, sizeof(ami));           /* AP MLD address 00:00:00:00:00:00 */
    }
    void TearDown() override {
        delete dm;
        __lsan_enable();
    }

    /* fills every m_assoc_sta_mld[] slot (all belong to the AP MLD) and sets the stored count */
    void fill(unsigned int stored_count) {
        for (unsigned int i = 0; i < EM_MAX_ASSOC_STA_MLD; i++) {
            em_assoc_sta_mld_info_t *smi = dm->m_assoc_sta_mld[i].get_assoc_sta_mld_info();
            memset(smi, 0, sizeof(*smi));
            smi->mac_addr[0] = 0x02;
            smi->mac_addr[5] = static_cast<unsigned char>(i + 1);
            smi->num_affiliated_sta = 0;
        }
        dm->m_num_assoc_sta_mld = stored_count;
    }

    /* counts the "<n>.MLDMACAddress" properties and frees the list */
    static unsigned int rows_and_free(bus_data_prop_t *prop) {
        unsigned int rows = 0;
        const std::string suffix = ".MLDMACAddress";
        while (prop != nullptr) {
            bus_data_prop_t *next = prop->next_data;
            std::string n = prop->name;
            if (n.size() >= suffix.size() && n.compare(n.size() - suffix.size(), suffix.size(), suffix) == 0) {
                rows++;
            }
            free(prop);
            prop = next;
        }
        return rows;
    }

    unsigned int run(bus_error_t *rc_out = nullptr) {
        bus_data_prop_t *prop = nullptr;
        bus_error_t rc = em_ctrl_t::get_em_ctrl_instance()->get_dm_ctrl()->stamld_tget_params(dm, root, &ami, &prop);
        if (rc_out) *rc_out = rc;
        return rows_and_free(prop);
    }
};

TEST_F(stamld_tget_params_Test, NullDataModelAmldOrPropertyIsRejected) {
    dm_easy_mesh_ctrl_t *c = em_ctrl_t::get_em_ctrl_instance()->get_dm_ctrl();
    bus_data_prop_t *prop = nullptr;
    fill(3);
    EXPECT_EQ(c->stamld_tget_params(nullptr, root, &ami, &prop), bus_error_invalid_input);
    EXPECT_EQ(c->stamld_tget_params(dm, root, nullptr, &prop), bus_error_invalid_input);
    EXPECT_EQ(c->stamld_tget_params(dm, root, &ami, nullptr), bus_error_invalid_input);
    EXPECT_EQ(prop, nullptr);                    /* nothing was appended */
}

TEST_F(stamld_tget_params_Test, NoStaMldProducesNoRows) {
    fill(0);
    bus_error_t rc = bus_error_invalid_input;
    EXPECT_EQ(run(&rc), 0u);
    EXPECT_EQ(rc, bus_error_success);
}

TEST_F(stamld_tget_params_Test, ValidMatchingEntriesAreReported) {
    fill(3);
    bus_error_t rc = bus_error_invalid_input;
    EXPECT_EQ(run(&rc), 3u);
    EXPECT_EQ(rc, bus_error_success);
}

TEST_F(stamld_tget_params_Test, EntriesOfAnotherApMldAreSkipped) {
    fill(3);
    dm->m_assoc_sta_mld[1].get_assoc_sta_mld_info()->ap_mld_mac_addr[5] = 0x09;
    EXPECT_EQ(run(), 2u);
}

TEST_F(stamld_tget_params_Test, CountAtTheArrayCapacityReportsEveryEntry) {
    fill(EM_MAX_ASSOC_STA_MLD);
    EXPECT_EQ(run(), static_cast<unsigned int>(EM_MAX_ASSOC_STA_MLD));
}

TEST_F(stamld_tget_params_Test, CountAboveTheArrayCapacityIsBounded) {
    const unsigned int counts[] = { EM_MAX_ASSOC_STA_MLD + 1, 255, 1000, 100000, UINT_MAX };
    for (unsigned int count : counts) {
        fill(count);
        bus_error_t rc = bus_error_invalid_input;
        EXPECT_EQ(run(&rc), static_cast<unsigned int>(EM_MAX_ASSOC_STA_MLD)) << "count " << count;
        EXPECT_EQ(rc, bus_error_success) << "count " << count;
    }
}
