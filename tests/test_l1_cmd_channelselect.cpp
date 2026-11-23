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
#include <cstdlib>
#include <cstring>
#include <string>
#include "em_ctrl.h"

/*
 * em_ctrl_t::cmd_channelselect() method name and path validation. The handler uses the controller singleton
 * (em_ctrl_t::get_em_ctrl_instance()), so its data model is initialised once for the suite with in-memory SQLite
 * (no certificate-backed command listener) and one agent device added with put_device() (em_ctrl_t::create_data_model()
 * creates a controller model, which writes /nvram/EasymeshCfg.json and never assigns an instance id). The device has
 * radios 1..EM_MAX_BANDS. Every rejected request must return its error and set the "Failure" status output.
 *
 * Every method name is placed in an exact-size heap buffer so AddressSanitizer reports any read past its terminating NUL.
 */

class cmd_channelselect_Test : public ::testing::Test {
protected:
    static std::string dev;                       /* device instance (the data model id) */

    static void SetUpTestSuite() {
        __lsan_disable();
        em_ctrl_t *ctrl = em_ctrl_t::get_em_ctrl_instance();
        ASSERT_EQ(ctrl->get_dm_ctrl()->init(":memory:", ctrl, db_client_type_local), 0);
        unsigned char mac[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x0a };
        dm_device_t device;
        memcpy(device.m_device_info.intf.mac, mac, sizeof(mac));
        snprintf(device.m_device_info.id.net_id, sizeof(device.m_device_info.id.net_id), "Network1");
        device.m_device_info.profile = em_profile_type_1;
        /* key: <net_id>@<al mac>@<media> */
        ctrl->get_dm_ctrl()->put_device("Network1@02:00:00:00:00:0a@0", &device);
        dm_easy_mesh_t *dm = ctrl->get_data_model("Network1", mac);
        ASSERT_NE(dm, nullptr);
        ASSERT_GT(dm->get_id(), 0);               /* agent models get an instance id from set_id() */
        dev = std::to_string(dm->get_id());

        dm->set_num_radios(EM_MAX_BANDS);
        for (unsigned int r = 0; r < EM_MAX_BANDS; r++) {
            unsigned char ruid[6] = { 0x02, 0x00, 0x00, 0x00, 0x0a, static_cast<unsigned char>(r + 1) };
            memcpy(dm->get_radio_by_ref(r).get_radio_info()->id.ruid, ruid, sizeof(ruid));
        }
    }
    static void TearDownTestSuite() {
        __lsan_enable();
    }

    static std::string path(const std::string &tail) {
        return "Device.WiFi.DataElements.Network." + tail;
    }

    /* calls the handler with an exact-size heap copy of the name (nullptr = NULL name); a rejected request must set the status output */
    static bus_error_t call(const char *ev, bool expect_status = true) {
        char *name = nullptr;
        if (ev != nullptr) {
            size_t n = strlen(ev) + 1;
            name = static_cast<char *>(malloc(n));
            memcpy(name, ev, n);
        }
        bus_data_prop_t *out = nullptr;
        bus_error_t rc = em_ctrl_t::cmd_channelselect(name, nullptr, &out, nullptr);
        free(name);
        if (expect_status) {
            EXPECT_NE(out, nullptr) << "no status output for " << (ev ? ev : "(null)");
        }
        if (out != nullptr) {
            free(out->value.raw_data.bytes);
            free(out);
        }
        return rc;
    }
    static bus_error_t call(const std::string &ev) { return call(ev.c_str()); }
};

std::string cmd_channelselect_Test::dev;

TEST_F(cmd_channelselect_Test, NullMethodNameIsRejected) {
    EXPECT_EQ(call(static_cast<const char *>(nullptr)), bus_error_invalid_input);
    /* without an output parameter */
    EXPECT_EQ(em_ctrl_t::cmd_channelselect(nullptr, nullptr, nullptr, nullptr), bus_error_invalid_input);
}

TEST_F(cmd_channelselect_Test, MethodNameWithoutDotIsRejected) {
    EXPECT_EQ(call("ChannelSelectionRequest()"), bus_error_invalid_input);
    EXPECT_EQ(call(""), bus_error_invalid_input);
}

TEST_F(cmd_channelselect_Test, UnknownMethodIsRejected) {
    EXPECT_EQ(call(path("Device." + dev + ".Radio.1.Other()")), bus_error_invalid_method);
    EXPECT_EQ(call(path("Device." + dev + ".Radio.1.ChannelSelectionRequest")), bus_error_invalid_method);
}

/* shorter than the Device.WiFi.DataElements.Network. prefix: nothing to parse behind it */
TEST_F(cmd_channelselect_Test, PathShorterThanTheNetworkPrefixIsRejected) {
    EXPECT_EQ(call("X.ChannelSelectionRequest()"), bus_error_invalid_namespace);
    EXPECT_EQ(call(".ChannelSelectionRequest()"), bus_error_invalid_namespace);
    EXPECT_EQ(call("Device.WiFi.ChannelSelectionRequest()"), bus_error_invalid_namespace);
}

TEST_F(cmd_channelselect_Test, PathWithoutADeviceComponentIsRejected) {
    EXPECT_EQ(call(path("ChannelSelectionRequest()")), bus_error_invalid_namespace);
    EXPECT_EQ(call(path("Device.ChannelSelectionRequest()")), bus_error_invalid_namespace);
}

TEST_F(cmd_channelselect_Test, MalformedDeviceAliasIsRejected) {
    EXPECT_EQ(call(path("Device.[abc.Radio.1.ChannelSelectionRequest()")), bus_error_invalid_namespace);
    /* no '.' between the alias and the method name: the text behind the last '.' is no method, rejected before the path is parsed */
    EXPECT_EQ(call(path("Device.[abc]ChannelSelectionRequest()")), bus_error_invalid_method);
    EXPECT_EQ(call(path("Device.[abc]")), bus_error_invalid_method);
}

TEST_F(cmd_channelselect_Test, UnknownDeviceIsRejected) {
    EXPECT_EQ(call(path("Device.999999.Radio.1.ChannelSelectionRequest()")), bus_error_invalid_namespace);
    EXPECT_EQ(call(path("Device.[no-such-device].Radio.1.ChannelSelectionRequest()")), bus_error_invalid_namespace);
}

/* the device exists: the second parse (radio) is reached */
TEST_F(cmd_channelselect_Test, ExistingDeviceWithoutARadioComponentIsRejected) {
    EXPECT_EQ(call(path("Device." + dev + ".ChannelSelectionRequest()")), bus_error_invalid_namespace);
}

TEST_F(cmd_channelselect_Test, ExistingDeviceWithAMalformedRadioAliasIsRejected) {
    EXPECT_EQ(call(path("Device." + dev + ".Radio.[abc.ChannelSelectionRequest()")), bus_error_invalid_namespace);
    EXPECT_EQ(call(path("Device." + dev + ".Radio.[abc]ChannelSelectionRequest()")), bus_error_invalid_method);   /* no '.' behind the alias */
}

TEST_F(cmd_channelselect_Test, ExistingDeviceWithAnUnknownRadioIsRejected) {
    EXPECT_EQ(call(path("Device." + dev + ".Radio.99.ChannelSelectionRequest()")), bus_error_invalid_namespace);
    EXPECT_EQ(call(path("Device." + dev + ".Radio.[no-such-radio].ChannelSelectionRequest()")), bus_error_invalid_namespace);
}
