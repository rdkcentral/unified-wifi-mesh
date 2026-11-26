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
#include <cstdlib>
#include <cstring>
#include <string>
#include "em_ctrl.h"
#include "dm_easy_mesh_ctrl.h"
#include "em.h"

/* em_ctrl_t::cmd_steerwifibh(): malformed method names and malformed Device instance tokens are rejected
 * with bus_error_invalid_input and a "Failure" status. Paths that reach get_table_instance() with a
 * missing delimiter rely on the get_table_instance() hardening in #871. */

class cmd_steerwifibh_Test : public ::testing::Test {
protected:
    bus_data_prop_t *out = NULL;
    char *method = NULL;   /* exact-size heap copy so a read past the NUL is caught by ASan */

    void SetUp() override {
        /* HARNESS_SETUP */
    }
    void free_out() {
        if (out) {
            free(out->value.raw_data.bytes);
            free(out);
            out = NULL;
        }
    }
    void TearDown() override {
        free(method);
        method = NULL;
        free_out();
    }
    bus_error_t call(const char *name, bool with_out = true) {
        free_out();
        const char *m = NULL;
        if (name) {
            free(method);
            method = static_cast<char *>(malloc(strlen(name) + 1));
            memcpy(method, name, strlen(name) + 1);
            m = method;
        }
        return em_ctrl_t::cmd_steerwifibh(m, NULL, with_out ? &out : NULL, NULL);
    }
    void expect_failure_status() {
        ASSERT_NE(out, nullptr);
        ASSERT_NE(out->value.raw_data.bytes, nullptr);
        EXPECT_STREQ(static_cast<const char *>(out->value.raw_data.bytes), "Failure");
    }
    void expect_rejected(const std::string &device_token) {
        std::string p = "Device.WiFi.DataElements.Network.Device." + device_token + ".SteerWiFiBackhaul()";
        EXPECT_EQ(call(p.c_str()), bus_error_invalid_input) << device_token;
        expect_failure_status();
    }
};

TEST_F(cmd_steerwifibh_Test, NullMethodNameIsRejected) {
    EXPECT_EQ(call(NULL), bus_error_invalid_input);
    expect_failure_status();
}

TEST_F(cmd_steerwifibh_Test, NullMethodNameWithNullOutputIsRejected) {
    EXPECT_EQ(call(NULL, false), bus_error_invalid_input);
    EXPECT_EQ(out, nullptr);
}

TEST_F(cmd_steerwifibh_Test, MethodNameWithoutDotIsRejected) {
    EXPECT_EQ(call("SteerWiFiBackhaul()"), bus_error_invalid_input);
    expect_failure_status();
}

TEST_F(cmd_steerwifibh_Test, WrongMethodIsRejected) {
    EXPECT_EQ(call("Device.WiFi.DataElements.Network.Device.1.Foo()"), bus_error_invalid_method);
    expect_failure_status();
}

TEST_F(cmd_steerwifibh_Test, ShortMethodNameIsRejected) {
    ASSERT_NE(em_ctrl_t::get_em_ctrl_instance(), nullptr);
    EXPECT_EQ(call("X.SteerWiFiBackhaul()"), bus_error_invalid_input);
    expect_failure_status();
}

TEST_F(cmd_steerwifibh_Test, ShortMethodNameWithNullOutputIsRejected) {
    ASSERT_NE(em_ctrl_t::get_em_ctrl_instance(), nullptr);
    EXPECT_EQ(call("X.SteerWiFiBackhaul()", false), bus_error_invalid_input);
}

TEST_F(cmd_steerwifibh_Test, PathWithoutDeviceIsRejected) {
    ASSERT_NE(em_ctrl_t::get_em_ctrl_instance(), nullptr);
    EXPECT_EQ(call("Device.WiFi.DataElements.Network.SteerWiFiBackhaul()"), bus_error_invalid_input);
    expect_failure_status();
}

/* These requests carry no input properties, so a token that passed the instance check would also end in
 * bus_error_invalid_input. They therefore only detect tokens that fail the device lookup ("", "abc", "0", overflow);
 * tokens that atoi() would accept ("1x", "+1") are covered by the is_valid_instance_token() tests below. */
TEST_F(cmd_steerwifibh_Test, EmptyDeviceInstanceIsRejected) { expect_rejected(""); }
TEST_F(cmd_steerwifibh_Test, NegativeDeviceInstanceIsRejected) { expect_rejected("-1"); }
TEST_F(cmd_steerwifibh_Test, NonNumericDeviceInstanceIsRejected) { expect_rejected("abc"); }
TEST_F(cmd_steerwifibh_Test, ZeroDeviceInstanceIsRejected) { expect_rejected("0"); }
TEST_F(cmd_steerwifibh_Test, OverflowingDeviceInstanceIsRejected) {
    expect_rejected("99999999999999999999");
    expect_rejected(std::to_string(static_cast<long long>(INT_MAX) + 1));
}

/* is_valid_instance_token(): numeric tokens must be 1..INT_MAX digits only; alias tokens are not checked here. */
TEST(cmd_steerwifibh_token_Test, ValidTokensAreAccepted) {
    EXPECT_TRUE(dm_easy_mesh_ctrl_t::is_valid_instance_token("1", true));
    EXPECT_TRUE(dm_easy_mesh_ctrl_t::is_valid_instance_token("42", true));
    EXPECT_TRUE(dm_easy_mesh_ctrl_t::is_valid_instance_token("2147483647", true));
    EXPECT_TRUE(dm_easy_mesh_ctrl_t::is_valid_instance_token("02:00:00:00:00:01", false));
}

TEST(cmd_steerwifibh_token_Test, MalformedTokensAreRejected) {
    EXPECT_FALSE(dm_easy_mesh_ctrl_t::is_valid_instance_token(NULL, true));
    EXPECT_FALSE(dm_easy_mesh_ctrl_t::is_valid_instance_token("", true));
    EXPECT_FALSE(dm_easy_mesh_ctrl_t::is_valid_instance_token("0", true));
    EXPECT_FALSE(dm_easy_mesh_ctrl_t::is_valid_instance_token("1x", true));
    EXPECT_FALSE(dm_easy_mesh_ctrl_t::is_valid_instance_token("+1", true));
    EXPECT_FALSE(dm_easy_mesh_ctrl_t::is_valid_instance_token("-1", true));
    EXPECT_FALSE(dm_easy_mesh_ctrl_t::is_valid_instance_token(" 1", true));
    EXPECT_FALSE(dm_easy_mesh_ctrl_t::is_valid_instance_token("2147483648", true));
    EXPECT_FALSE(dm_easy_mesh_ctrl_t::is_valid_instance_token("99999999999999999999", true));
}
