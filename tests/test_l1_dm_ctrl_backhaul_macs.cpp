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
#include <algorithm>
#include <cstring>
#include <string>
#include "dm_easy_mesh_ctrl.h"
#include "em.h"

/* fill_comma_sep() must never write past the destination buffer. */

class fill_comma_sep_Test : public ::testing::Test {
protected:
    dm_easy_mesh_ctrl_t dm_ctrl;
    char store[16 + 8];

    void SetUp() override {
        memset(store, 'X', sizeof(store));
        store[0] = '\0';
    }
    void expect_guard_intact(size_t from) {
        for (size_t i = from; i < sizeof(store); i++) {
            EXPECT_EQ(store[i], 'X') << "byte " << i;
        }
    }
};

TEST_F(fill_comma_sep_Test, EmptyListLeavesBufferEmpty) {
    em_short_string_t list[1] = { "" };
    dm_ctrl.fill_comma_sep(list, 1, store, 16);
    EXPECT_STREQ(store, "");
    expect_guard_intact(16);
}

TEST_F(fill_comma_sep_Test, JoinsEntriesWithCommas) {
    em_short_string_t list[2] = { "a", "b" };
    dm_ctrl.fill_comma_sep(list, 2, store, 16);
    EXPECT_STREQ(store, "a,b");
    expect_guard_intact(16);
}

TEST_F(fill_comma_sep_Test, StopsAtFirstEmptyEntry) {
    em_short_string_t list[3] = { "a", "", "c" };
    dm_ctrl.fill_comma_sep(list, 3, store, 16);
    EXPECT_STREQ(store, "a");
}

TEST_F(fill_comma_sep_Test, ExactFitIsKept) {
    em_short_string_t list[2] = { "aaaaaaa", "bbbbbbb" };   /* 7 + 1 + 7 = 15, plus NUL = 16 */
    dm_ctrl.fill_comma_sep(list, 2, store, 16);
    EXPECT_STREQ(store, "aaaaaaa,bbbbbbb");
    expect_guard_intact(16);
}

TEST_F(fill_comma_sep_Test, EntryThatDoesNotFitIsDropped) {
    em_short_string_t list[3] = { "aaaaaaa", "bbbbbbb", "ccccccc" };
    dm_ctrl.fill_comma_sep(list, 3, store, 15);             /* 16 needed, 15 available */
    EXPECT_STREQ(store, "aaaaaaa");
    expect_guard_intact(15);
}

TEST_F(fill_comma_sep_Test, ZeroAndOneByteBuffers) {
    em_short_string_t list[1] = { "a" };
    dm_ctrl.fill_comma_sep(list, 1, store, 0);
    EXPECT_EQ(store[0], '\0');
    dm_ctrl.fill_comma_sep(list, 1, store, 1);
    EXPECT_STREQ(store, "");
    expect_guard_intact(1);
}

TEST_F(fill_comma_sep_Test, AppendsToExistingContent) {
    snprintf(store, sizeof(store), "x");
    em_short_string_t list[1] = { "a" };
    dm_ctrl.fill_comma_sep(list, 1, store, 16);
    EXPECT_STREQ(store, "x,a");
}

TEST_F(fill_comma_sep_Test, NullBufferIsIgnored) {
    em_short_string_t list[1] = { "a" };
    dm_ctrl.fill_comma_sep(list, 1, NULL, 16);
    SUCCEED();
}

/* BackhaulDownMACAddress of one device: only that device's entries, at most EM_BACKHAUL_DOWNMAC_ADDR. */

class backhaul_down_macs_Test : public ::testing::Test {
protected:
    dm_easy_mesh_ctrl_t dm_ctrl;
    em_device_info_t di;
    char val_str[MAX_EM_BUFF_SZ];

    void SetUp() override {
        memset(&di, 0, sizeof(di));
        for (int i = 0; i < EM_BACKHAUL_DOWNMAC_ADDR; i++) {
            snprintf(di.backhaul_down_mac[i], sizeof(di.backhaul_down_mac[i]), "02:00:00:00:00:%02x", i + 1);
        }
    }
    std::string expected(size_t n) {
        std::string s;
        for (size_t i = 0; i < n; i++) {
            if (i) s += ",";
            s += di.backhaul_down_mac[i];
        }
        return s;
    }
};

TEST_F(backhaul_down_macs_Test, CountIsCappedToTheArraySize) {
    const unsigned char counts[] = { 0, 1, 15, 16, 17, 255 };
    for (unsigned char n : counts) {
        di.num_backhaul_down_mac = n;
        memset(val_str, 'Z', sizeof(val_str));
        dm_ctrl.fill_backhaul_down_macs(&di, val_str, sizeof(val_str));
        EXPECT_EQ(std::string(val_str), expected(std::min<size_t>(n, EM_BACKHAUL_DOWNMAC_ADDR))) << "count " << int(n);
    }
}

TEST_F(backhaul_down_macs_Test, ReusedBufferHoldsOnlyTheCurrentDevice) {
    /* device 1: 15 addresses, device 2: 2 addresses, device 3: none, device 4: 15 again */
    di.num_backhaul_down_mac = 15;
    dm_ctrl.fill_backhaul_down_macs(&di, val_str, sizeof(val_str));
    EXPECT_EQ(std::string(val_str), expected(15));

    di.num_backhaul_down_mac = 2;
    dm_ctrl.fill_backhaul_down_macs(&di, val_str, sizeof(val_str));
    EXPECT_EQ(std::string(val_str), expected(2));

    di.num_backhaul_down_mac = 0;
    dm_ctrl.fill_backhaul_down_macs(&di, val_str, sizeof(val_str));
    EXPECT_STREQ(val_str, "");

    di.num_backhaul_down_mac = 15;
    dm_ctrl.fill_backhaul_down_macs(&di, val_str, sizeof(val_str));
    EXPECT_EQ(std::string(val_str), expected(15));
}

TEST_F(backhaul_down_macs_Test, SmallDestinationNeverOverflows) {
    char small[40 + 8];
    memset(small, 'X', sizeof(small));
    di.num_backhaul_down_mac = 16;
    dm_ctrl.fill_backhaul_down_macs(&di, small, 40);
    EXPECT_EQ(std::string(small), expected(2));              /* 17 + 1 + 17 = 35, a third entry needs 53 */
    for (size_t i = 40; i < sizeof(small); i++) EXPECT_EQ(small[i], 'X');
}

/* device_tget_inner(): an empty or non-partial name is rejected before the last character is read.
   Under AddressSanitizer the empty-name case reports a stack-buffer-underflow without the guard. */

TEST(device_tget_inner_Test, EmptyEventNameIsRejected) {
    char name[] = "";
    raw_data_t raw;
    memset(&raw, 0, sizeof(raw));
    EXPECT_EQ(dm_easy_mesh_ctrl_t::device_tget_inner(name, &raw, NULL), bus_error_invalid_operation);
}

TEST(device_tget_inner_Test, NameWithoutTrailingDotIsRejected) {
    char name[] = "Device.WiFi.DataElements.Network.Device";
    raw_data_t raw;
    memset(&raw, 0, sizeof(raw));
    EXPECT_EQ(dm_easy_mesh_ctrl_t::device_tget_inner(name, &raw, NULL), bus_error_invalid_operation);
}

TEST(device_tget_inner_Test, NullArgumentsAreRejected) {
    raw_data_t raw;
    memset(&raw, 0, sizeof(raw));
    char name[] = "Device.WiFi.DataElements.Network.Device.";
    EXPECT_EQ(dm_easy_mesh_ctrl_t::device_tget_inner(NULL, &raw, NULL), bus_error_invalid_input);
    EXPECT_EQ(dm_easy_mesh_ctrl_t::device_tget_inner(name, NULL, NULL), bus_error_invalid_input);
}
