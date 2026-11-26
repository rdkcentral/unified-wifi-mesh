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
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include "dm_bss.h"

/*
 * dm_bss_t::encode(): the number of AKMs written is bounded by EM_MAX_AKMS (the AKM arrays have that many entries)
 * and the ExtraVendorIEs hex string by the vendor_elements capacity, whatever the stored counts say.
 */

class dm_bss_encode_Test : public ::testing::Test {
protected:
    dm_bss_t bss;
    em_bss_info_t *info = nullptr;
    cJSON *json = nullptr;

    void SetUp() override {
        bss.init();
        info = bss.get_bss_info();
        for (int i = 0; i < EM_MAX_AKMS; i++) {
            snprintf(info->fronthaul_akm[i], sizeof(info->fronthaul_akm[i]), "fh-akm-%d", i);
            snprintf(info->backhaul_akm[i], sizeof(info->backhaul_akm[i]), "bh-akm-%d", i);
        }
        for (size_t i = 0; i < sizeof(info->vendor_elements); i++) {
            info->vendor_elements[i] = static_cast<unsigned char>(i * 7 + 3);
        }
        json = cJSON_CreateObject();
    }
    void TearDown() override { cJSON_Delete(json); }

    static std::string hex_of(const unsigned char *data, size_t len) {
        std::string s;
        char b[3];
        for (size_t i = 0; i < len; i++) {
            snprintf(b, sizeof(b), "%02x", data[i]);
            s += b;
        }
        return s;
    }

    cJSON *array(const char *name) { return cJSON_GetObjectItem(json, name); }
    std::string vendor_ies() {
        cJSON *v = cJSON_GetObjectItem(json, "ExtraVendorIEs");
        return (v != nullptr && cJSON_IsString(v)) ? std::string(v->valuestring) : std::string("<missing>");
    }
};

/* AKM counts: zero, one, exact capacity, above capacity, the largest unsigned char */
TEST_F(dm_bss_encode_Test, AkmCountsAreBoundedByTheArrayCapacity) {
    const unsigned char counts[] = { 0, 1, EM_MAX_AKMS - 1, EM_MAX_AKMS, EM_MAX_AKMS + 1, 46, 255 };
    for (unsigned char count : counts) {
        cJSON_Delete(json);
        json = cJSON_CreateObject();
        info->num_fronthaul_akms = count;
        info->num_backhaul_akms = count;
        bss.encode(json, false);

        int expected = count > EM_MAX_AKMS ? EM_MAX_AKMS : count;
        cJSON *fh = array("FronthaulAKMsAllowed");
        cJSON *bh = array("BackhaulAKMsAllowed");
        ASSERT_NE(fh, nullptr) << "count " << int(count);
        ASSERT_NE(bh, nullptr) << "count " << int(count);
        EXPECT_EQ(cJSON_GetArraySize(fh), expected) << "count " << int(count);
        EXPECT_EQ(cJSON_GetArraySize(bh), expected) << "count " << int(count);
        for (int i = 0; i < expected; i++) {
            EXPECT_STREQ(cJSON_GetArrayItem(fh, i)->valuestring, info->fronthaul_akm[i]);
            EXPECT_STREQ(cJSON_GetArrayItem(bh, i)->valuestring, info->backhaul_akm[i]);
        }
    }
}

/* the two counts are independent */
TEST_F(dm_bss_encode_Test, FronthaulAndBackhaulCountsAreBoundedSeparately) {
    info->num_fronthaul_akms = 200;
    info->num_backhaul_akms = 3;
    bss.encode(json, false);
    EXPECT_EQ(cJSON_GetArraySize(array("FronthaulAKMsAllowed")), EM_MAX_AKMS);
    EXPECT_EQ(cJSON_GetArraySize(array("BackhaulAKMsAllowed")), 3);
}

/* vendor lengths: zero, one, capacity - 1, exact capacity, above capacity, very large, SIZE_MAX */
TEST_F(dm_bss_encode_Test, VendorLengthIsBoundedByTheCapacity) {
    const size_t cap = sizeof(info->vendor_elements);
    const size_t lens[] = { 0, 1, cap - 1, cap, cap + 1, 2 * cap, 10000000, static_cast<size_t>(SIZE_MAX) };
    for (size_t len : lens) {
        cJSON_Delete(json);
        json = cJSON_CreateObject();
        info->vendor_elements_len = len;
        bss.encode(json, false);

        size_t expected_len = len > cap ? cap : len;
        std::string expected = hex_of(info->vendor_elements, expected_len);
        std::string got = vendor_ies();
        EXPECT_EQ(got.size(), 2 * expected_len) << "vendor_elements_len " << len;
        EXPECT_EQ(got, expected) << "vendor_elements_len " << len;
    }
}

/* all three bounds at once */
TEST_F(dm_bss_encode_Test, OversizedCountsAndVendorLengthTogether) {
    info->num_fronthaul_akms = 255;
    info->num_backhaul_akms = 255;
    info->vendor_elements_len = static_cast<size_t>(SIZE_MAX);
    bss.encode(json, false);
    EXPECT_EQ(cJSON_GetArraySize(array("FronthaulAKMsAllowed")), EM_MAX_AKMS);
    EXPECT_EQ(cJSON_GetArraySize(array("BackhaulAKMsAllowed")), EM_MAX_AKMS);
    EXPECT_EQ(vendor_ies().size(), 2 * sizeof(info->vendor_elements));
}

/* the HaulType string is always written, also for a haul type that is not one of the five known values */
TEST_F(dm_bss_encode_Test, UnknownHaulTypeGivesAnEmptyHaulTypeString) {
    info->id.haul_type = em_haul_type_max;
    bss.encode(json, false);
    cJSON *haul = cJSON_GetObjectItem(json, "HaulType");
    ASSERT_NE(haul, nullptr);
    ASSERT_TRUE(cJSON_IsString(haul));
    EXPECT_STREQ(haul->valuestring, "");
}
