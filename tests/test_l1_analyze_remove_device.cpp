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
#include <stdio.h>
#include <stdlib.h>
#include <cstring>
#include <string>
#include <vector>
#include "em_ctrl.h"

/*
 * dm_easy_mesh_ctrl_t::analyze_remove_device() input validation and capacity checks.
 *
 * The request lists the devices to KEEP (Network.DeviceList); every other device of the data model gets a
 * remove-device command chain (3 commands per device, EM_MAX_CMD = 16 slots in the caller's array). A
 * rejected request returns EM_PARSE_ERR_CONFIG and leaves pcmd[] empty; a request that needs nothing
 * removed returns 0.
 */

class analyze_remove_device_Test : public ::testing::Test {
protected:
    em_ctrl_t ctrl;
    dm_easy_mesh_ctrl_t *dm_ctrl = NULL;
    int next_mac = 0;

    void SetUp() override {
        __lsan_disable();
        ctrl.init("/tmp/test_config.db");
        ctrl.orch_init();
        dm_ctrl = ctrl.get_dm_ctrl();
        /* HARNESS_SETUP */
    }
    void TearDown() override {
        __lsan_enable();
    }

    static std::string mac_str(const unsigned char *m) {
        char s[18];
        snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
        return s;
    }

    /* adds n devices 02:00:00:00:hh:ll to the data model */
    std::vector<std::string> add_devices(int n) {
        std::vector<std::string> macs;
        for (int i = 0; i < n; i++) {
            em_interface_t intf;
            memset(&intf, 0, sizeof(intf));
            snprintf(intf.name, sizeof(intf.name), "eth%d", next_mac);
            unsigned char m[6] = { 0x02, 0x00, 0x00, 0x00, static_cast<unsigned char>((next_mac + 1) >> 8),
                                   static_cast<unsigned char>((next_mac + 1) & 0xff) };
            memcpy(intf.mac, m, sizeof(m));
            next_mac++;
            EXPECT_NE(ctrl.create_data_model("Network1", &intf, em_profile_type_1), nullptr);
            macs.push_back(mac_str(m));
        }
        return macs;
    }

    /* devices already in the model before the test adds any (kept in every request so only the added ones count) */
    std::vector<std::string> existing_devices() {
        std::vector<std::string> macs;
        for (dm_device_t *d = dm_ctrl->get_first_device(); d != NULL; d = dm_ctrl->get_next_device(d)) {
            macs.push_back(mac_str(d->m_device_info.intf.mac));
        }
        return macs;
    }

    static std::string device_list_json(const std::vector<std::string> &ids) {
        std::string s = "{\"wfa-dataelements:RemoveDevice\":{\"Network\":{\"DeviceList\":[";
        for (size_t i = 0; i < ids.size(); i++) {
            s += (i ? "," : "");
            s += "{\"ID\":\"" + ids[i] + "\"}";
        }
        return s + "]}}}";
    }

    /* runs the handler on the given JSON text; deletes the returned commands when ok */
    int run(const std::string &json, em_cmd_t *pcmd[EM_MAX_CMD], bool delete_cmds = true) {
        std::vector<char> raw(sizeof(em_bus_event_t) + json.size() + 1, 0);
        em_bus_event_t *evt = reinterpret_cast<em_bus_event_t *>(raw.data());
        memcpy(evt->u.subdoc.buff, json.c_str(), json.size() + 1);
        memset(pcmd, 0, EM_MAX_CMD * sizeof(em_cmd_t *));
        int num = dm_ctrl->analyze_remove_device(evt, pcmd);
        if (delete_cmds && num > 0) {
            for (int i = 0; i < num && i < EM_MAX_CMD; i++) {
                delete pcmd[i];
                pcmd[i] = NULL;
            }
        }
        return num;
    }
    static void expect_no_commands(em_cmd_t *pcmd[EM_MAX_CMD]) {
        for (int i = 0; i < EM_MAX_CMD; i++) {
            EXPECT_EQ(pcmd[i], nullptr) << "slot " << i;
        }
    }
};

TEST_F(analyze_remove_device_Test, MissingNullOrNonStringIdIsRejected) {
    em_cmd_t *pcmd[EM_MAX_CMD];
    const char *bad[] = {
        "{\"wfa-dataelements:RemoveDevice\":{\"Network\":{\"DeviceList\":[{}]}}}",
        "{\"wfa-dataelements:RemoveDevice\":{\"Network\":{\"DeviceList\":[{\"ID\":null}]}}}",
        "{\"wfa-dataelements:RemoveDevice\":{\"Network\":{\"DeviceList\":[{\"ID\":5}]}}}",
        "{\"wfa-dataelements:RemoveDevice\":{\"Network\":{\"DeviceList\":[{\"ID\":\"02:00:00:00:00:01\"},{\"name\":\"x\"}]}}}",
    };
    add_devices(2);
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        EXPECT_EQ(run(bad[i], pcmd), EM_PARSE_ERR_CONFIG) << bad[i];
        expect_no_commands(pcmd);
    }
}

TEST_F(analyze_remove_device_Test, DeviceListOfExactly32EntriesIsAccepted) {
    em_cmd_t *pcmd[EM_MAX_CMD];
    std::vector<std::string> ids = existing_devices();
    std::vector<std::string> devs = add_devices(1);
    ids.insert(ids.end(), devs.begin(), devs.end());
    for (int i = 0; ids.size() < 32; i++) {
        char s[18];
        snprintf(s, sizeof(s), "aa:bb:cc:dd:ee:%02x", i);   /* not in the model */
        ids.push_back(s);
    }
    ASSERT_EQ(ids.size(), 32u);
    EXPECT_EQ(run(device_list_json(ids), pcmd), 0);          /* every device is kept: nothing to remove, not an error */
    expect_no_commands(pcmd);
}

TEST_F(analyze_remove_device_Test, DeviceListOfMoreThan32EntriesIsRejected) {
    em_cmd_t *pcmd[EM_MAX_CMD];
    for (int n = 33; n <= 40; n += 7) {                       /* 33 and 40 */
        std::vector<std::string> ids;
        for (int i = 0; i < n; i++) {
            char s[18];
            snprintf(s, sizeof(s), "aa:bb:cc:dd:ee:%02x", i);
            ids.push_back(s);
        }
        EXPECT_EQ(run(device_list_json(ids), pcmd), EM_PARSE_ERR_CONFIG) << n << " entries";
        expect_no_commands(pcmd);
    }
}

TEST_F(analyze_remove_device_Test, MoreThan32DevicesToDeleteIsRejected) {
    em_cmd_t *pcmd[EM_MAX_CMD];
    std::vector<std::string> keep = existing_devices();
    add_devices(33);                                          /* 33 devices that are not kept */
    EXPECT_EQ(run(device_list_json(keep), pcmd), EM_PARSE_ERR_CONFIG);
    expect_no_commands(pcmd);
}

TEST_F(analyze_remove_device_Test, RemovalThatFitsInTheCommandArrayIsAccepted) {
    em_cmd_t *pcmd[EM_MAX_CMD];
    std::vector<std::string> keep = existing_devices();
    add_devices(1);
    int per_device = run(device_list_json(keep), pcmd);       /* commands one removed device needs */
    ASSERT_GT(per_device, 0);
    ASSERT_LE(per_device, EM_MAX_CMD);
    int fit = EM_MAX_CMD / per_device;                        /* devices that still fit */
    add_devices(fit - 1);
    EXPECT_EQ(run(device_list_json(keep), pcmd), fit * per_device);
}

TEST_F(analyze_remove_device_Test, OverCapacityRemovalIsRejectedWithoutPartialDeletion) {
    em_cmd_t *pcmd[EM_MAX_CMD];
    std::vector<std::string> keep = existing_devices();
    add_devices(1);
    int per_device = run(device_list_json(keep), pcmd);
    ASSERT_GT(per_device, 0);
    int fit = EM_MAX_CMD / per_device;
    add_devices(fit);                                         /* one device more than the array holds */
    EXPECT_EQ(run(device_list_json(keep), pcmd), EM_PARSE_ERR_CONFIG);
    expect_no_commands(pcmd);                                 /* nothing handed to the caller, nothing left behind */
    add_devices(4);                                           /* well over capacity */
    EXPECT_EQ(run(device_list_json(keep), pcmd), EM_PARSE_ERR_CONFIG);
    expect_no_commands(pcmd);
}

TEST_F(analyze_remove_device_Test, KeepingEveryDeviceRemovesNothing) {
    em_cmd_t *pcmd[EM_MAX_CMD];
    std::vector<std::string> keep = existing_devices();
    std::vector<std::string> devs = add_devices(3);
    keep.insert(keep.end(), devs.begin(), devs.end());
    EXPECT_EQ(run(device_list_json(keep), pcmd), 0);
    expect_no_commands(pcmd);
}

TEST_F(analyze_remove_device_Test, MalformedRequestsAreNoOps) {
    em_cmd_t *pcmd[EM_MAX_CMD];
    EXPECT_EQ(run("not json", pcmd), 0);
    EXPECT_EQ(run("{\"other\":1}", pcmd), 0);
    EXPECT_EQ(run("{\"wfa-dataelements:RemoveDevice\":{}}", pcmd), 0);
    EXPECT_EQ(run("{\"wfa-dataelements:RemoveDevice\":{\"Network\":{}}}", pcmd), 0);
    expect_no_commands(pcmd);
}
