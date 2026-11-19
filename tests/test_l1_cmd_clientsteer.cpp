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
#include <cstdlib>
#include <cstring>
#include <string>
#include "em_ctrl.h"
#include "em.h"

/* em_ctrl_t::cmd_clientsteer(): malformed method names are rejected with bus_error_invalid_input (or
 * bus_error_invalid_method) and a "Failure" status, with or without an output pointer. Cases that
 * reach get_table_instance() with a truncated path (e.g. "...Network.ClientSteer()") rely on the
 * get_table_instance() hardening in #871 and are added once that is merged. */

class cmd_clientsteer_Test : public ::testing::Test {
protected:
    bus_data_prop_t *out = NULL;
    char *method = NULL;   /* exact-size heap copy so a read past the NUL is caught by ASan */

    void SetUp() override {
        /* HARNESS_SETUP */
    }
    void TearDown() override {
        free(method);
        method = NULL;
        if (out) {
            free(out->value.raw_data.bytes);
            free(out);
            out = NULL;
        }
    }
    bus_error_t call(const char *name, bool with_out = true) {
        const char *m = NULL;
        if (name) {
            free(method);
            method = static_cast<char *>(malloc(strlen(name) + 1));
            memcpy(method, name, strlen(name) + 1);
            m = method;
        }
        return em_ctrl_t::cmd_clientsteer(m, NULL, with_out ? &out : NULL, NULL);
    }
    void expect_failure_status() {
        ASSERT_NE(out, nullptr);
        ASSERT_NE(out->value.raw_data.bytes, nullptr);
        EXPECT_STREQ(static_cast<const char *>(out->value.raw_data.bytes), "Failure");
    }
};

TEST_F(cmd_clientsteer_Test, NullMethodNameIsRejected) {
    EXPECT_EQ(call(NULL), bus_error_invalid_input);
    expect_failure_status();
}

TEST_F(cmd_clientsteer_Test, NullMethodNameWithNullOutputIsRejected) {
    EXPECT_EQ(call(NULL, false), bus_error_invalid_input);
    EXPECT_EQ(out, nullptr);
}

TEST_F(cmd_clientsteer_Test, MethodNameWithoutDotIsRejected) {
    EXPECT_EQ(call("ClientSteer()"), bus_error_invalid_input);
    expect_failure_status();
}

TEST_F(cmd_clientsteer_Test, MethodNameWithoutDotAndNullOutputIsRejected) {
    EXPECT_EQ(call("ClientSteer()", false), bus_error_invalid_input);
}

TEST_F(cmd_clientsteer_Test, WrongMethodIsRejected) {
    EXPECT_EQ(call("Device.WiFi.DataElements.Network.Device.1.Radio.1.BSS.1.STA.1.Foo()"), bus_error_invalid_method);
    expect_failure_status();
}

TEST_F(cmd_clientsteer_Test, ShortMethodNameIsRejected) {
    ASSERT_NE(em_ctrl_t::get_em_ctrl_instance(), nullptr);
    EXPECT_EQ(call("X.ClientSteer()"), bus_error_invalid_input);
    expect_failure_status();
}

TEST_F(cmd_clientsteer_Test, ShortMethodNameWithNullOutputIsRejected) {
    ASSERT_NE(em_ctrl_t::get_em_ctrl_instance(), nullptr);
    EXPECT_EQ(call("X.ClientSteer()", false), bus_error_invalid_input);
}

TEST_F(cmd_clientsteer_Test, LongestNameBelowNetworkPrefixIsRejected) {
    ASSERT_NE(em_ctrl_t::get_em_ctrl_instance(), nullptr);
    EXPECT_EQ(call("Device.WiFi.DataEle.ClientSteer()"   /* 33 chars, sizeof(DATAELEMS_NETWORK) is 34 */), bus_error_invalid_input);
    expect_failure_status();
}
