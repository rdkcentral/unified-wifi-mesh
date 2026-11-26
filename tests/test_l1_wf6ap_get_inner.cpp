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
#include <climits>
#include <cstring>
#include <string>
#include "dm_easy_mesh_ctrl.h"
#include "em.h"

/* wf6ap_get_inner() input validation. The radio token and role count checks are separate static helpers
 * so every malformed / boundary value can be tested without building a data model. */

class wf6ap_get_inner_Test : public ::testing::Test {
protected:
    char name_buf[320];
    raw_data_t raw;

    void SetUp() override {
        memset(name_buf, 0, sizeof(name_buf));
        memset(&raw, 0, sizeof(raw));
    }
    bus_error_t call(const char *ev) {
        snprintf(name_buf, sizeof(name_buf), "%s", ev);
        return dm_easy_mesh_ctrl_t::wf6ap_get_inner(name_buf, &raw, NULL);
    }
};

TEST_F(wf6ap_get_inner_Test, NullEventNameIsRejected) {
    EXPECT_EQ(dm_easy_mesh_ctrl_t::wf6ap_get_inner(NULL, &raw, NULL), bus_error_invalid_input);
}

TEST_F(wf6ap_get_inner_Test, NullRawDataIsRejected) {
    snprintf(name_buf, sizeof(name_buf), "%s", "Device.WiFi.DataElements.Network.Device.1.Radio.1.WiFi6APRole.HE160");
    EXPECT_EQ(dm_easy_mesh_ctrl_t::wf6ap_get_inner(name_buf, NULL, NULL), bus_error_invalid_input);
}

TEST_F(wf6ap_get_inner_Test, NameWithoutDotIsRejected) {
    EXPECT_EQ(call("HE160"), bus_error_invalid_input);
}

TEST_F(wf6ap_get_inner_Test, NameShorterThanNetworkPrefixIsRejected) {
    EXPECT_EQ(call("a.b"), bus_error_invalid_input);
    EXPECT_EQ(call("Device.WiFi.HE160"), bus_error_invalid_input);
    EXPECT_EQ(call("Device.WiFi.DataElements.Network"), bus_error_invalid_input);
}

class wf6ap_radio_instance_Test : public ::testing::Test {
protected:
    bool parse(const char *tok, bool is_num, int *out) {
        return dm_easy_mesh_ctrl_t::parse_radio_instance(tok, is_num, out);
    }
};

TEST_F(wf6ap_radio_instance_Test, ValidRadiosAreAccepted) {
    for (int r = 1; r <= EM_MAX_BANDS; r++) {
        std::string s = std::to_string(r);
        int out = 0;
        ASSERT_TRUE(parse(s.c_str(), true, &out)) << s;
        EXPECT_EQ(out, r);
    }
}

TEST_F(wf6ap_radio_instance_Test, OutOfRangeIsRejected) {
    int out = 77;
    EXPECT_FALSE(parse("0", true, &out));
    EXPECT_FALSE(parse("-1", true, &out));
    std::string above = std::to_string(EM_MAX_BANDS + 1);
    EXPECT_FALSE(parse(above.c_str(), true, &out));
    EXPECT_FALSE(parse("1000000", true, &out));
    EXPECT_EQ(out, 77);
}

TEST_F(wf6ap_radio_instance_Test, OverflowIsRejected) {
    int out = 77;
    EXPECT_FALSE(parse("99999999999999999999999999", true, &out));
    EXPECT_FALSE(parse("4294967297", true, &out));   /* would wrap to 1 if narrowed to 32 bit */
    EXPECT_EQ(out, 77);
}

TEST_F(wf6ap_radio_instance_Test, NonNumericIsRejected) {
    int out = 77;
    EXPECT_FALSE(parse("1", false, &out));           /* alias / bracketed token */
    EXPECT_FALSE(parse("", true, &out));
    EXPECT_FALSE(parse("x", true, &out));
    EXPECT_FALSE(parse("1x", true, &out));           /* trailing text */
    EXPECT_FALSE(parse("1 ", true, &out));
    EXPECT_EQ(out, 77);
}

TEST(wf6ap_role_count_Test, CountIsCappedAtMapApRoleMax) {
    EXPECT_EQ(dm_easy_mesh_ctrl_t::wifi6_role_count(0), 0u);
    EXPECT_EQ(dm_easy_mesh_ctrl_t::wifi6_role_count(1), 1u);
    EXPECT_EQ(dm_easy_mesh_ctrl_t::wifi6_role_count(MAP_AP_ROLE_MAX), static_cast<unsigned int>(MAP_AP_ROLE_MAX));
    EXPECT_EQ(dm_easy_mesh_ctrl_t::wifi6_role_count(MAP_AP_ROLE_MAX + 1), static_cast<unsigned int>(MAP_AP_ROLE_MAX));
    EXPECT_EQ(dm_easy_mesh_ctrl_t::wifi6_role_count(255), static_cast<unsigned int>(MAP_AP_ROLE_MAX));
    EXPECT_EQ(dm_easy_mesh_ctrl_t::wifi6_role_count(UINT_MAX), static_cast<unsigned int>(MAP_AP_ROLE_MAX));
}
