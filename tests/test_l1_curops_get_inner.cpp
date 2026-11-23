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
 * dm_easy_mesh_ctrl_t::curops_get_inner() path validation. The handler uses the controller singleton
 * (em_ctrl_t::get_em_ctrl_instance()), so its data model is initialised once for the suite with
 * the no-DB client (db_client_type_none: nothing is read from or written to disk, and the on-box recovery script of the local client is never run; no certificate-backed command listener). The device is added as an agent model
 * with put_device() (em_ctrl_t::create_data_model() creates a controller model, which writes
 * /nvram/EasymeshCfg.json and never assigns an instance id). The model holds one device with
 * radios 1..EM_MAX_BANDS and two current operating classes on radio 1.
 *
 * Every path is placed in an exact-size heap buffer so AddressSanitizer reports any read past its
 * terminating NUL.
 */

class curops_get_inner_Test : public ::testing::Test {
protected:
    static dm_easy_mesh_t *dm;
    static std::string dev;                       /* device instance (the data model id) */

    static void SetUpTestSuite() {
        __lsan_disable();
        em_ctrl_t *ctrl = em_ctrl_t::get_em_ctrl_instance();
        /* the no-DB init() bootstraps the controller network from the AL MAC, which is all zero on a fresh controller */
        static const unsigned char al_mac[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0xf0 };
        memcpy(ctrl->get_dm_ctrl()->get_dev_interface()->mac, al_mac, sizeof(al_mac));
        ASSERT_EQ(ctrl->get_dm_ctrl()->init(":memory:", ctrl, db_client_type_none), 0);
        unsigned char mac[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
        dm_device_t device;
        memcpy(device.m_device_info.intf.mac, mac, sizeof(mac));
        snprintf(device.m_device_info.id.net_id, sizeof(device.m_device_info.id.net_id), "Network1");
        device.m_device_info.profile = em_profile_type_1;
        /* key: <net_id>@<al mac>@<media> */
        ctrl->get_dm_ctrl()->put_device("Network1@02:00:00:00:00:01@0", &device);
        dm = ctrl->get_data_model("Network1", mac);
        ASSERT_NE(dm, nullptr);
        ASSERT_GT(dm->get_id(), 0);               /* agent models get an instance id from set_id() */
        dev = std::to_string(dm->get_id());

        dm->set_num_radios(EM_MAX_BANDS);
        for (unsigned int r = 0; r < EM_MAX_BANDS; r++) {
            unsigned char ruid[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, static_cast<unsigned char>(r + 1) };
            memcpy(dm->get_radio_by_ref(r).get_radio_info()->id.ruid, ruid, sizeof(ruid));
        }
        unsigned char ruid1[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
        dm->set_num_op_class(2);
        for (unsigned int i = 0; i < 2; i++) {
            em_op_class_info_t *oci = dm->get_op_class_by_ref(i).get_op_class_info();
            memcpy(oci->id.ruid, ruid1, sizeof(ruid1));
            oci->id.type = em_op_class_type_current;
            oci->op_class = 115u + i;
            oci->channel = 36;
            oci->tx_power = 20;
        }
    }
    static void TearDownTestSuite() {
        __lsan_enable();
    }

    static std::string path(const std::string &radio, const std::string &curop, const char *param = "Class") {
        return "Device.WiFi.DataElements.Network.Device." + dev + ".Radio." + radio +
               ".CurrentOperatingClass." + curop + "." + param;
    }

    /* exact-size heap copy of the event name */
    static bus_error_t call(const std::string &ev) {
        char *name = static_cast<char *>(malloc(ev.size() + 1));
        memcpy(name, ev.c_str(), ev.size() + 1);
        raw_data_t raw;
        memset(&raw, 0, sizeof(raw));
        bus_error_t rc = em_ctrl_t::get_em_ctrl_instance()->get_dm_ctrl()->curops_get_inner(name, &raw, NULL);
        free(name);
        return rc;
    }
};

dm_easy_mesh_t *curops_get_inner_Test::dm = nullptr;
std::string curops_get_inner_Test::dev;

TEST_F(curops_get_inner_Test, NullArgumentsAreRejected) {
    raw_data_t raw;
    memset(&raw, 0, sizeof(raw));
    char name[] = "Device.WiFi.DataElements.Network.Device.1.Radio.1.CurrentOperatingClass.1.Class";
    dm_easy_mesh_ctrl_t *c = em_ctrl_t::get_em_ctrl_instance()->get_dm_ctrl();
    EXPECT_EQ(c->curops_get_inner(NULL, &raw, NULL), bus_error_invalid_input);
    EXPECT_EQ(c->curops_get_inner(name, NULL, NULL), bus_error_invalid_input);
}

TEST_F(curops_get_inner_Test, ShortOrDotlessNamesAreRejected) {
    EXPECT_EQ(call("Class"), bus_error_invalid_input);
    EXPECT_EQ(call("X.Class"), bus_error_invalid_input);
    EXPECT_EQ(call("Device.WiFi.Class"), bus_error_invalid_input);
    EXPECT_EQ(call("Device.WiFi.DataElements.Network.Class"), bus_error_invalid_input);
}

TEST_F(curops_get_inner_Test, PathsThatStopAtEachInstanceLevelAreRejected) {
    EXPECT_EQ(call("Device.WiFi.DataElements.Network.Device.Class"), bus_error_invalid_namespace);   /* "Class" is read as the device instance: no such device */
    EXPECT_EQ(call("Device.WiFi.DataElements.Network.Device." + dev + ".Class"), bus_error_invalid_input);
    EXPECT_EQ(call("Device.WiFi.DataElements.Network.Device." + dev + ".Radio.1.Class"), bus_error_invalid_input);
    EXPECT_EQ(call("Device.WiFi.DataElements.Network.Device." + dev + ".Radio.1.CurrentOperatingClass.Class"),
              bus_error_invalid_input);
}

TEST_F(curops_get_inner_Test, UnknownDeviceIsRejected) {
    EXPECT_EQ(call("Device.WiFi.DataElements.Network.Device.9999.Radio.1.CurrentOperatingClass.1.Class"),
              bus_error_invalid_namespace);
}

TEST_F(curops_get_inner_Test, RadioOutOfRangeIsRejected) {
    EXPECT_EQ(call(path("0", "1")), bus_error_invalid_input);
    EXPECT_EQ(call(path("-1", "1")), bus_error_invalid_input);
    EXPECT_EQ(call(path(std::to_string(EM_MAX_BANDS + 1), "1")), bus_error_invalid_input);
    EXPECT_EQ(call(path("1000000", "1")), bus_error_invalid_input);
}

TEST_F(curops_get_inner_Test, RadioAliasIsRejected) {
    EXPECT_EQ(call(path("[x]", "1")), bus_error_invalid_input);
    EXPECT_EQ(call(path("[02:00:00:00:00:01]", "1")), bus_error_invalid_input);
}

TEST_F(curops_get_inner_Test, RadioWithTrailingTextOrOverflowIsRejected) {
    EXPECT_EQ(call(path("1junk", "1")), bus_error_invalid_input);
    EXPECT_EQ(call(path("1abc", "1")), bus_error_invalid_input);
    EXPECT_EQ(call(path("1 ", "1")), bus_error_invalid_input);
    EXPECT_EQ(call(path("", "1")), bus_error_invalid_input);
    EXPECT_EQ(call(path("99999999999999999999", "1")), bus_error_invalid_input);
    EXPECT_EQ(call(path("4294967297", "1")), bus_error_invalid_input);    /* wraps to 1 if narrowed to 32 bit */
}

TEST_F(curops_get_inner_Test, ValidPathsSucceed) {
    EXPECT_EQ(call(path("1", "1")), bus_error_success);
    EXPECT_EQ(call(path("1", "2")), bus_error_success);
    EXPECT_EQ(call(path("1", "1", "Channel")), bus_error_success);
    EXPECT_EQ(call(path("1", "1", "TxPower")), bus_error_success);
    EXPECT_EQ(call(path(std::to_string(EM_MAX_BANDS), "1")), bus_error_invalid_input);   /* radio exists but has no current class */
}

TEST_F(curops_get_inner_Test, UnknownParameterIsRejected) {
    EXPECT_EQ(call(path("1", "1", "NoSuchParam")), bus_error_invalid_input);
}
