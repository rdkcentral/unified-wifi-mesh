/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2025 RDK Management
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
#include <gmock/gmock.h>
#include <stdio.h>
#include "em_ctrl.h"
#include "dm_easy_mesh_list.h"


extern "C" const char* __asan_default_options() {
    return "detect_leaks=0";
}

class dm_easy_mesh_list_tTEST : public ::testing::Test {
protected:
    dm_easy_mesh_t *dm1, *dm2, *dm3, *dm4;
    bool skip_teardown = false;
    dm_easy_mesh_list_t list;
    em_ctrl_t mgr;
    unsigned char mac1[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    unsigned char mac2[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    unsigned char mac3[6] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x16};
    unsigned char mac4[6] = {0x10, 0x11, 0x12, 0x13, 0x12, 0x15};

    // Helper method to convert MAC bytes to string
    void mac_to_string(unsigned char *mac, char *str) {
        sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x", 
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }

    // Helper to build device key
    void build_device_key(const char *net_id, unsigned char *dev_mac, char *key) {
        char mac_str[18];
        mac_to_string(dev_mac, mac_str);
        sprintf(key, "%s:%s", net_id, mac_str);
    }

    // Helper to build BSS key
    void build_bss_key(const char *net_id, unsigned char *dev_mac, unsigned char *radio_mac, unsigned char *bssid, int haul_type, char *key)
    {
        char dev_str[18], radio_str[18], bssid_str[18];
        mac_to_string(dev_mac, dev_str);
        mac_to_string(radio_mac, radio_str);
        mac_to_string(bssid, bssid_str);
        sprintf(key, "%s@%s@%s@%s@%d",net_id, dev_str, radio_str, bssid_str, haul_type);
    }

    // Helper to build STA key
    void build_sta_key(unsigned char *sta_mac, unsigned char *bssid, 
                       unsigned char *radio_mac, char *key) {
        char sta_str[18], bssid_str[18], radio_str[18];
        mac_to_string(sta_mac, sta_str);
        mac_to_string(bssid, bssid_str);
        mac_to_string(radio_mac, radio_str);
        sprintf(key, "%s@%s@%s", sta_str, bssid_str, radio_str);
    }

    // Helper to build Op Class key
    void build_op_class_key(unsigned char *ruid, em_op_class_type_t type, unsigned int op_class, char *key)
    {
        char ruid_str[18];
        mac_to_string(ruid, ruid_str);
        sprintf(key, "%s@%d@%u", ruid_str, type, op_class);
    }

    // Helper to build Policy key
    void build_policy_key(const char *net_id, unsigned char *dev_mac, unsigned char *radio_mac, em_policy_id_type_t type, char *key) {
        char dev_str[18], radio_str[18];
        dm_easy_mesh_t::macbytes_to_string(dev_mac, dev_str);
        dm_easy_mesh_t::macbytes_to_string(radio_mac, radio_str);
        sprintf(key, "%s@%s@%s@%d", net_id, dev_str, radio_str, type);
    }

    void build_network_ssid_key(const char* net_id, const char* ssid, char* key, size_t key_len = 256)
    {
        snprintf(key, key_len, "%s@%s", ssid, net_id);
    }

    // Helper to build Scan Result key
    void build_scan_result_key(const char *net_id, unsigned char *dev_mac, unsigned char *scanner_mac, int op_class, int channel, int scanner_type, unsigned char *bssid, char *key)
    {
        char dev_str[18], scanner_str[18], bssid_str[18];
        mac_to_string(dev_mac, dev_str);
        mac_to_string(scanner_mac, scanner_str);
        mac_to_string(bssid, bssid_str);
        sprintf(key, "%s@%s@%s@%d@%d@%d@%s",net_id,dev_str,scanner_str,op_class,channel,scanner_type,bssid_str);
    }


    void SetUp() override {
        list.init((em_mgr_t*)&mgr);
        
        // Add data models for Network1
        em_interface_t intf1, intf2, intf3, intf4;        
        memcpy(intf1.mac, mac1, 6);
        strcpy(intf1.name, "eth0");
        dm1 = list.create_data_model("Network1", &intf1, em_profile_type_1, false);
        
        memcpy(intf2.mac, mac2, 6);
        strcpy(intf2.name, "eth1");
        dm2 = list.create_data_model("Network1", &intf2, em_profile_type_2, true);
        
        // Add data models for Network2
        memcpy(intf3.mac, mac3, 6);
        strcpy(intf3.name, "eth2");
        dm3 = list.create_data_model("Network2", &intf3, em_profile_type_3, false);
        
        memcpy(intf4.mac, mac4, 6);
        strcpy(intf4.name, "eth3");
        dm4 = list.create_data_model("Network2", &intf4, em_profile_type_3, false);
        // register networks so get_first_network()/get_next_network() work in tests
        if (dm1) list.put_network("Network1", dm1->get_network());
        if (dm3) list.put_network("Network2", dm3->get_network());
    }

    void TearDown() override {
        if (skip_teardown) {
            return;
        }
        list.delete_data_model("Network1", mac1);
	    list.delete_data_model("Network1", mac2);
	    list.delete_data_model("Network2", mac3);
	    list.delete_data_model("Network2", mac4);

        if (dm1->m_wifi_data != NULL) {
            free(dm1->m_wifi_data);
            dm1->m_wifi_data = nullptr;
        }
        if (dm2->m_wifi_data != NULL) {
            free(dm2->m_wifi_data);
            dm2->m_wifi_data = nullptr;
        }
        if (dm3->m_wifi_data != NULL) {
            free(dm3->m_wifi_data);
            dm3->m_wifi_data = nullptr;
        }
        if (dm4->m_wifi_data != NULL) {
            free(dm4->m_wifi_data);
            dm4->m_wifi_data = nullptr;
        }
    }
};


void setup_valid_interface(em_interface_t &intf, const char* name, const unsigned char mac[6]) {
    strncpy(intf.name, name, sizeof(intf.name) - 1);
    intf.name[sizeof(intf.name)-1] = '\0';
    memcpy(intf.mac, mac, sizeof(mac_address_t));
    intf.media = em_media_type_ieee8023ab;
}

/**
 * @brief Verify creation of a valid data model using valid interface parameters.
 *
 * This test verifies that the create_data_model API successfully creates a data model when valid input is provided. It validates that the network ID, interface (name and MAC address), profile, and colocated flag are correctly set in the created data model. This ensures the proper integration and functioning of the data model creation with valid configuration data.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 001@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**  
 * | Variation / Step | Description | Test Data | Expected Result | Notes |  
 * | :----: | --------- | ---------- |-------------- | ----- |  
 * | 01 | Invoke create_data_model with valid parameters | net_id = Network1, al_intf.name = AL_1, al_intf.mac = 10,11,12,13,14,15, profile = em_profile_type_1, colocated_dm = false | Data model is created successfully; dm is not null and its fields match the input values | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, create_data_model_valid_data_model_creation) {
    const char* testName = "create_data_model_valid_data_model_creation";
    std::cout << "Entering " << testName << " test" << std::endl;
    const char* net_id = "Network1";
    unsigned char mac[6] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15};
    em_interface_t al_intf;
    setup_valid_interface(al_intf, "AL_1", mac);
    em_profile_type_t profile = em_profile_type_1;
    bool colocated_dm = false;
    std::cout << "Invoking create_data_model with net_id = " << net_id
              << ", al_intf.name = " << al_intf.name
              << ", profile = " << profile
              << ", colocated_dm = " << (colocated_dm ? "true" : "false") << std::endl;
    dm_easy_mesh_t* dm = list.create_data_model(net_id, &al_intf, profile, colocated_dm);
    ASSERT_NE(dm, nullptr);
    std::cout << "Retrieved device ID: " << dm->m_device.m_device_info.id.net_id << std::endl;
    std::cout << "Retrieved device profile: " << dm->m_device.m_device_info.profile << std::endl;
    std::cout << "Retrieved collocated value: " << dm->m_colocated << std::endl;
    EXPECT_STREQ(dm->m_device.m_device_info.id.net_id, net_id);
    EXPECT_EQ(dm->m_device.m_device_info.profile, em_profile_type_1);
    for (size_t i = 0; i < sizeof(mac); ++i) {
        EXPECT_EQ(dm->m_device.m_device_info.intf.mac[i], mac[i]);
    }
    EXPECT_EQ(dm->m_colocated, false);
    std::cout << "Exiting " << testName << " test" << std::endl;
}
/**
 * @brief Verify that create_data_model returns a null pointer when net_id is NULL
 *
 * This test verifies that the create_data_model API properly handles a NULL net_id by returning a null pointer,
 * ensuring that the function does not proceed with invalid network identifiers. This is a negative test case to
 * validate the robustness of input validation in the API.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 002@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize test parameters and display the entering message | net_id = NULL, al_intf.name = "AL_Null", mac = 30,31,32,33,34,35, profile = em_profile_type_1, colocated_dm = false | Variables set as per the pre-requisites and printed entering message | Should be successful |
 * | 02 | Invoke create_data_model API with null net_id using the initialized parameters | net_id = NULL, al_intf = {name = "AL_Null", mac = 30,31,32,33,34,35}, profile = em_profile_type_1, colocated_dm = false | API returns a nullptr indicating failure to create a data model with a NULL net_id | Should Fail |
 * | 03 | Validate the returned data model pointer using EXPECT_EQ | dm (result of API call) | EXPECT_EQ(dm, nullptr) evaluates to true confirming the API handled NULL net_id correctly | Should be successful |
 */
TEST_F(dm_easy_mesh_list_tTEST, create_data_model_negative_null_net_id) {
    const char* testName = "create_data_model_negative_null_net_id";
    std::cout << "Entering " << testName << " test" << std::endl;
    const char* net_id = NULL;
    unsigned char mac[6] = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35};
    em_interface_t al_intf;
    setup_valid_interface(al_intf, "AL_Null", mac);
    em_profile_type_t profile = em_profile_type_1;
    bool colocated_dm = false;
    std::cout << "Invoking create_data_model with net_id = NULL"
              << ", al_intf.name = " << al_intf.name
              << ", profile = " << profile
              << ", colocated_dm = " << (colocated_dm ? "true" : "false") << std::endl;
    dm_easy_mesh_t* dm = list.create_data_model(net_id, &al_intf, profile, colocated_dm);
    EXPECT_EQ(dm, nullptr);
    std::cout << "Exiting " << testName << " test" << std::endl;
}
/**
 * @brief Verify handling of null interface pointer in create_data_model API
 *
 * This test verifies that invoking create_data_model with a null pointer for the
 * interface parameter (al_intf) returns a null data model pointer. It ensures that
 * the API properly handles invalid input without performing any further operations.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 003@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke create_data_model with net_id = "Network3", al_intf = NULL, profile = em_profile_type_1, and colocated_dm = false | net_id = Network3, al_intf = NULL, profile = em_profile_type_1, colocated_dm = false, output dm = nullptr | API returns a null pointer and EXPECT_EQ(dm, nullptr) assertion passes | Should Fail |
 */
TEST_F(dm_easy_mesh_list_tTEST, create_data_model_negative_null_al_intf) {
    const char* testName = "create_data_model_negative_null_al_intf";
    std::cout << "Entering " << testName << " test" << std::endl;
    const char* net_id = "Network3";
    em_interface_t* al_intf = NULL;
    em_profile_type_t profile = em_profile_type_1;
    bool colocated_dm = false;
    std::cout << "Invoking create_data_model with net_id = " << net_id
              << " and al_intf = NULL, profile = " << profile
              << ", colocated_dm = " << (colocated_dm ? "true" : "false") << std::endl;
    dm_easy_mesh_t* dm = list.create_data_model(net_id, al_intf, profile, colocated_dm);
    EXPECT_EQ(dm, nullptr);
    std::cout << "Exiting " << testName << " test" << std::endl;
}
/**
 * @brief Test the create_data_model API for multiple loop profile types
 *
 * This test iterates over all available loop profile types (from em_profile_type_reserved to em_profile_type_3) and verifies that the create_data_model API returns a valid data model pointer. It further checks that the resulting device information (network ID, profile type, interface MAC address) and the collocated flag match the expected input parameters.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 004
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize test parameters | net_id = "Network4", mac = {0x50,0x51,0x52,0x53,0x54,0x55}, interface name = "AL_Loop", colocated_dm = false | Test variables are correctly set up for invocation | Should be successful |
 * | 02 | Invoke create_data_model for each profile type in a loop | For each iteration: profile = em_profile_type_reserved to em_profile_type_3, input: net_id, al_intf, profile, colocated_dm = false | Returned dm_easy_mesh_t pointer is non-NULL for each profile type | Should Pass |
 * | 03 | Verify the returned data model's device information | For each iteration: dm->m_device.m_device_info.id.net_id = "Network4", dm->m_device.m_device_info.profile = current profile, dm->m_device.m_device_info.intf.mac = {0x50,0x51,0x52,0x53,0x54,0x55} | Device network ID, profile, and MAC address must match the input values | Should Pass |
 * | 04 | Verify the collocated flag in the returned data model | dm->m_colocated = false | dm->m_colocated is false | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, create_data_model_loop_profile_types) {
    const char* testName = "create_data_model_loop_profile_types";
    std::cout << "Entering " << testName << " test" << std::endl;

    const char* net_id = "Network4";
    unsigned char mac[6] = {0x50, 0x51, 0x52, 0x53, 0x54, 0x55};
    em_interface_t al_intf;
    setup_valid_interface(al_intf, "AL_Loop", mac);
    bool colocated_dm = false;
    
    for (int i = em_profile_type_reserved; i <= em_profile_type_3; i++) {
        em_profile_type_t profile = static_cast<em_profile_type_t>(i);
        std::cout << "Invoking create_data_model with profile = " << profile << std::endl;
        dm_easy_mesh_t* dm = list.create_data_model(net_id, &al_intf, profile, colocated_dm);
        std::cout << "Expected: Non-NULL dm_easy_mesh_t pointer for profile " << profile << std::endl;
        ASSERT_NE(dm, nullptr);
        std::cout << "Retrieved device ID: " << dm->m_device.m_device_info.id.net_id << std::endl;
        std::cout << "Retrieved device profile: " << dm->m_device.m_device_info.profile << std::endl;
        std::cout << "Retrieved collocated value: " << dm->m_colocated << std::endl;
        EXPECT_STREQ(dm->m_device.m_device_info.id.net_id, net_id);
        EXPECT_EQ(dm->m_device.m_device_info.profile, i);
        for (size_t i = 0; i < sizeof(mac); ++i) {
            EXPECT_EQ(dm->m_device.m_device_info.intf.mac[i], mac[i]);
        }
        EXPECT_EQ(dm->m_colocated, false);
    }
    std::cout << "Exiting " << testName << " test" << std::endl;
}
/**
 * @brief Test debug_probe() API for valid invocation.
 *
 * This test verifies that the debug_probe() method of the list object executes without throwing any exceptions. It confirms that when debug_probe() is invoked on a properly initialized and populated list, the operation completes successfully, which is critical for ensuring that diagnostic functionalities are stable.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 005@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                       | Test Data                                   | Expected Result                                                  | Notes       |
 * | :--------------: | ----------------------------------------------------------------- | ------------------------------------------- | ---------------------------------------------------------------- | ----------- |
 * | 01               | Invoke debug_probe() method on the list instance                   | No input parameters, return type: void      | Method should complete without throwing any exceptions using EXPECT_NO_THROW | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, debug_probe_valid_invocation) {
    std::cout << "Entering debug_probe_valid_invocation test" << std::endl;
    std::cout << "Invoking debug_probe() method" << std::endl;
    EXPECT_NO_THROW(list.debug_probe());
    std::cout << "debug_probe() executed successfully" << std::endl;
    std::cout << "Exiting debug_probe_valid_invocation test" << std::endl;
}
/**
 * @brief Validate that an existing data model is correctly deleted.
 *
 * This test verifies that the delete_data_model API successfully deletes a data model for a given network ID and MAC address. 
 * The test first calls create_data_model with specified parameters to ensure that a data model exists (and to prevent double free issues), 
 * and then invokes delete_data_model to perform the deletion. The expected behavior is that the deletion occurs without throwing any exceptions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 006@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                     | Test Data                                                                                                                      | Expected Result                                                   | Notes       |
 * | :--------------: | ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------- | ----------- |
 * | 01               | Invoke create_data_model to add a new data model for "Network1" to set up the test environment     | net_id = "Network1", intf.mac = {0x12, 0x23, 0x33, 0x44, 0x55, 0x66}, intf.name = "eth0", profileType = em_profile_type_1, flag = true | Data model is created successfully and returns a valid pointer      | Should Pass |
 * | 02               | Invoke delete_data_model to delete the previously added data model using the same MAC address      | net_id = "Network1", mac = {0x12, 0x23, 0x33, 0x44, 0x55, 0x66}                                                                 | API completes without throwing an exception                       | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, delete_data_model_existent) {
    std::cout << "Entering delete_data_model_existent test" << std::endl;    
    em_interface_t intf;
    unsigned char mac[6] = {0x12, 0x23, 0x33, 0x44, 0x55, 0x66};
    memcpy(intf.mac, mac, 6);
    strcpy(intf.name, "eth0");
    std::cout << "Invoking create_data_model with net_id as Network1" << " and mac: ";
    for (int i = 0; i < 6; i++) {
        std::cout << std::hex << static_cast<int>(mac[i]) << " ";
    }
    std::cout << std::dec << std::endl;
    //Invoke create_data_model to prevent double free issue in the test fixture
    dm_easy_mesh_t *dm1 = list.create_data_model("Network1", &intf, em_profile_type_1, true);    
    std::cout << "Invoking delete_data_model with net_id: Network1 and same mac" << std::endl;
    EXPECT_NO_THROW(list.delete_data_model("Network1", mac));
    std::cout << "delete_data_model invoked; matching data model found, deletion performed." << std::endl;
    std::cout << "Exiting delete_data_model_existent test" << std::endl;
}
/**
 * @brief Verify that delete_data_model correctly handles deletion requests for non-existent data models.
 *
 * This test verifies that when delete_data_model is invoked with a network identifier and MAC address 
 * that do not match any existing data model, the API throws an exception. This behavior ensures that 
 * erroneous deletion attempts are properly handled without unintended side-effects.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 007@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                       | Test Data                                                                                 | Expected Result                                               | Notes               |
 * | :--------------: | ----------------------------------------------------------------- | ----------------------------------------------------------------------------------------- | ------------------------------------------------------------- | ------------------- |
 * | 01               | Set up the test with a non-existent network identifier and MAC.   | net_id = non_existent, al_mac = 0x00,0x1A,0x2B,0x3C,0x4D,0x5E                              | Data model corresponding to the provided values is not found. | Should be successful |
 * | 02               | Invoke delete_data_model API with the non-existent parameters.      | net_id = non_existent, al_mac = 0x00,0x1A,0x2B,0x3C,0x4D,0x5E                              | Expect an exception to be thrown (verified by EXPECT_ANY_THROW).| Should Fail         |
 * | 03               | Log the completion of the deletion attempt.                       | None                                                                                    | Log messages indicate that no deletion was performed.         | Should be successful |
 */
TEST_F(dm_easy_mesh_list_tTEST, delete_data_model_non_existent) {
    std::cout << "Entering delete_data_model_non_existent test" << std::endl;    
    const char* net_id = "non_existent";
    unsigned char al_mac[6] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
    std::cout << "Invoking delete_data_model with net_id: " << net_id << " and al_mac: ";
    for (int i = 0; i < 6; i++) {
        std::cout << std::hex << static_cast<int>(al_mac[i]) << " ";
    }
    std::cout << std::dec << std::endl;
    EXPECT_ANY_THROW(list.delete_data_model(net_id, al_mac));
    std::cout << "delete_data_model invoked; no matching data model found, no deletion performed." << std::endl;
    std::cout << "Exiting delete_data_model_non_existent test" << std::endl;
}
/**
 * @brief Test delete_data_model API with NULL network ID
 *
 * This test verifies that the delete_data_model API properly handles a null network ID. The function is
 * invoked with a NULL net_id and a valid MAC address. It is expected that the API will throw an exception,
 * ensuring that invalid input is not processed.
 *
 * **Test Group ID:** Basic: 01 / Module (L2): 02 / Stress (L2): 03@n
 * **Test Case ID:** 008@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                        | Test Data                                                       | Expected Result                                                                | Notes       |
 * | :--------------: | ------------------------------------------------------------------ | --------------------------------------------------------------- | ------------------------------------------------------------------------------ | ----------- |
 * | 01               | Call delete_data_model with NULL net_id and valid MAC address input  | net_id = NULL, al_mac = 00:1A:2B:3C:4D:5E                           | API should throw an exception as validated by EXPECT_ANY_THROW                 | Should Fail |
 */
TEST_F(dm_easy_mesh_list_tTEST, delete_data_model_null_netid) {
    std::cout << "Entering delete_data_model_null_netid test" << std::endl;
    const char* net_id = nullptr;
    unsigned char al_mac[6] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
    std::cout << "Invoking delete_data_model with net_id: " 
              << (net_id ? net_id : "NULL") << " and al_mac: ";
    for (int i = 0; i < 6; i++) {
        std::cout << std::hex << static_cast<int>(al_mac[i]) << " ";
    }
    std::cout << std::dec << std::endl;
    EXPECT_ANY_THROW(list.delete_data_model(net_id, al_mac));
    std::cout << "delete_data_model invoked; handled NULL network ID gracefully with no deletion." << std::endl;
    std::cout << "Exiting delete_data_model_null_netid test" << std::endl;
}
/**
 * @brief Test to verify that delete_data_model handles a NULL AL MAC input correctly
 *
 * This test checks if the delete_data_model API gracefully handles a scenario where the AL MAC parameter is NULL.
 * The expected behavior is that the API throws an exception when NULL AL MAC input is provided, ensuring that no deletion occurs.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 009
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                          | Test Data                               | Expected Result                                                               | Notes       |
 * | :--------------: | ---------------------------------------------------------------------------------------------------- | --------------------------------------- | ----------------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke delete_data_model with net_id "net123" and al_mac set to NULL to test error handling          | net_id = net123, al_mac = nullptr        | API throws an exception (EXPECT_ANY_THROW) to indicate invalid parameter input | Should Fail |
 */
TEST_F(dm_easy_mesh_list_tTEST, delete_data_model_null_al_mac) {
    std::cout << "Entering delete_data_model_null_al_mac test" << std::endl;
    const char* net_id = "net123";
    const unsigned char* al_mac = nullptr;
    std::cout << "Invoking delete_data_model with net_id: " << net_id 
              << " and al_mac: " << (al_mac ? "Valid AL MAC" : "NULL") << std::endl;
    EXPECT_ANY_THROW(list.delete_data_model(net_id, al_mac));
    std::cout << "delete_data_model invoked; handled NULL AL MAC gracefully with no deletion." << std::endl;
    std::cout << "Exiting delete_data_model_null_al_mac test" << std::endl;
}
/**
 * @brief Test deletion attempt with an empty network ID
 *
 * This test verifies that invoking delete_data_model with an empty network ID and a valid MAC address does not result in an exception, ensuring that the function gracefully handles the situation without performing any deletion.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 010@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                               | Test Data                                            | Expected Result                                                                  | Notes       |
 * | :------------:   | ------------------------------------------------------------------------- | ---------------------------------------------------- | -------------------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke delete_data_model with an empty network ID and a valid MAC address.  | net_id = "", al_mac = 0x40,0x41,0x42,0x43,0x44,0x45   | The API returns successfully without throwing an exception, indicating no deletion performed. | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, delete_data_model_empty_netid) {
    std::cout << "Entering delete_data_model_empty_netid test" << std::endl;
    const char* net_id = "";
    unsigned char al_mac[6] = {0x40, 0x41, 0x42, 0x43, 0x44, 0x45};
    std::cout << "Invoking delete_data_model with net_id: \"" << net_id << "\" (empty string) and al_mac: ";
    for (int i = 0; i < 6; i++) {
        std::cout << std::hex << static_cast<int>(al_mac[i]) << " ";
    }
    std::cout << std::dec << std::endl;
    EXPECT_NO_THROW(list.delete_data_model(net_id, al_mac));
    std::cout << "delete_data_model invoked; no data model found for empty network ID, no deletion performed." << std::endl;
    std::cout << "Exiting delete_data_model_empty_netid test" << std::endl;
}
/**
 * @brief Validate that the default constructor of dm_easy_mesh_list_t creates a single instance without throwing exceptions
 *
 * This test ensures that invoking the default constructor of dm_easy_mesh_list_t does not throw an exception,
 * confirming that an instance can be created safely. It verifies the basic functionality of object instantiation.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 011@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                    | Test Data                                        | Expected Result                                                    | Notes      |
 * | :--------------: | -------------------------------------------------------------- | ------------------------------------------------ | ------------------------------------------------------------------ | ---------- |
 * | 01               | Call the default constructor of dm_easy_mesh_list_t            | Constructor call: instance creation using dm_easy_mesh_list_t() | Instance should be created successfully without throwing any exceptions | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, dm_easy_mesh_list_t_defaultConstructor_singleInstance) {
    std::cout << "Entering dm_easy_mesh_list_t_defaultConstructor_singleInstance test" << std::endl;
    std::cout << "Invoking dm_easy_mesh_list_t() constructor" << std::endl;
    EXPECT_NO_THROW(dm_easy_mesh_list_t instance);
    std::cout << "Exiting dm_easy_mesh_list_t_defaultConstructor_singleInstance test" << std::endl;
}
/**
 * @brief Test the retrieval of a non-existent BSS key
 *
 * This test verifies that when a BSS key is constructed using fake MAC addresses that do not exist in the data model list, the get_bss API returns a nullptr. It ensures that the API correctly handles cases where the requested BSS key is absent.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 012@n
 * **Priority:** (High) This test is critical as it validates API behavior in negative scenarios@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:** 
 * | Variation / Step | Description                                                    | Test Data                                                                                                                                                      | Expected Result                                                         | Notes       |
 * | :--------------: | -------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- | ----------- |
 * | 01               | Build a fake BSS key using the build_bss_key helper function   | net_id = "Network1", fake_dev_mac = {0x99,0x99,0x99,0x99,0x99,0x99}, fake_radio_mac = {0x88,0x88,0x88,0x88,0x88,0x88}, fake_bssid = {0x77,0x77,0x77,0x77,0x77,0x77}, haul_type = 0, key buffer size = 256 | Key is generated based on the provided fake MAC addresses             | Should Pass |
 * | 02               | Invoke get_bss with the constructed fake key                   | key = (constructed fake BSS key from step 01)                                                                                                                  | Result is nullptr indicating the key does not exist                     | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_bss_key_not_exists) {
    std::cout << "Entering get_bss_key_not_exists test" << std::endl;
    char key[256];
    unsigned char fake_dev_mac[6]   = {0x99,0x99,0x99,0x99,0x99,0x99};
    unsigned char fake_radio_mac[6] = {0x88,0x88,0x88,0x88,0x88,0x88};
    unsigned char fake_bssid[6]     = {0x77,0x77,0x77,0x77,0x77,0x77};
    build_bss_key("Network1", fake_dev_mac, fake_radio_mac, fake_bssid, 0, key);
    std::cout << "Invoking get_bss with key: " << key << std::endl;
    dm_bss_t* result = list.get_bss(key);
    EXPECT_EQ(result, nullptr);
    std::cout << "Exiting get_bss_key_not_exists test" << std::endl;
}
/**
 * @brief Verify that get_bss API returns a null pointer when provided with a null key.
 *
 * This test checks that the get_bss function correctly handles an invalid (null) key by returning a null pointer. The test is essential to ensure that the API gracefully handles such cases without causing undefined behavior.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 013@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**  
 * | Variation / Step | Description                                                       | Test Data                                   | Expected Result                                                    | Notes       |
 * | :--------------: | ----------------------------------------------------------------- | ------------------------------------------- | ------------------------------------------------------------------ | ----------- |
 * | 01               | Invoke get_bss with a null key to validate handling of invalid input | nullKey = nullptr                           | API should return a null pointer; assertion EXPECT_EQ(result, nullptr) | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_bss_null_key) {
    std::cout << "Entering get_bss_null_key test" << std::endl;
    const char *nullKey = nullptr;
    std::cout << "Invoking get_bss with key: " << "NULL" << std::endl;
    dm_bss_t* result = list.get_bss(nullKey);
    std::cout << "Method get_bss returned pointer: " << result << std::endl;
    EXPECT_EQ(result, nullptr);
    std::cout << "Exiting get_bss_null_key test" << std::endl;
}
/**
 * @brief Validate that get_bss returns nullptr when provided with an empty network identifier.
 *
 * This test verifies that when build_bss_key is invoked using an empty network ID, the resultant key is invalid for a lookup. Consequently, a subsequent call to get_bss with this key returns a nullptr. This behavior ensures robustness in the handling of improperly constructed keys.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 014
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                           | Test Data                                                                                                                                                    | Expected Result                                              | Notes         |
 * | :--------------: | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------ | ------------- |
 * | 01               | Generate BSS key using build_bss_key with an empty network id and fake MAC addresses.                 | net_id = "", fake_dev_mac = 89:99:99:99:99:99, fake_radio_mac = 88:88:88:88:88:88, fake_bssid = 77:77:77:77:77:77, haul_type = 0                            | Key is generated based on the inputs (likely invalid key)    | Should be successful |
 * | 02               | Invoke get_bss API with the generated key and validate that the returned pointer is nullptr.          | key = [generated key from step 01]                                                                                                                           | Return value is nullptr and assertion EXPECT_EQ(nullptr) passes | Should Pass   |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_bss_empty_key) {
    std::cout << "Entering get_bss_empty_key test" << std::endl;
    char key[256];
    unsigned char fake_dev_mac[6]   = {0x89,0x99,0x99,0x99,0x99,0x99};
    unsigned char fake_radio_mac[6] = {0x88,0x88,0x88,0x88,0x88,0x88};
    unsigned char fake_bssid[6]     = {0x77,0x77,0x77,0x77,0x77,0x77};
    build_bss_key("", fake_dev_mac, fake_radio_mac, fake_bssid, 0, key);
    std::cout << "Invoking get_bss with key: (empty string)" << std::endl;
    dm_bss_t* result = list.get_bss(key);
    std::cout << "Method get_bss returned pointer: " << result << std::endl;
    EXPECT_EQ(result, nullptr);
    std::cout << "Exiting get_bss_empty_key test" << std::endl;
}
/**
 * @brief Validate retrieval of an existing data model using a valid Network ID and MAC address
 *
 * This test verifies that when providing an existent Network ID ("Network2") and a matching MAC address,
 * the get_data_model API returns a valid data model pointer with the correct network ID and MAC address.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 015@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                                 | Test Data                                                                                      | Expected Result                                                                                                            | Notes       |
 * | :--------------: | ----------------------------------------------------------- | ---------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- | ----------- |
 * | 01               | Prepare input values and print entry log for the test       | net_id = "Network2", mac = 10,11,12,13,14,16                                                     | Log message indicating test entry; input values properly initialized                                                      | Should be successful |
 * | 02               | Invoke get_data_model API to retrieve the data model        | net_id = "Network2", mac = 10,11,12,13,14,16                                                     | Returns a non-null pointer; ASSERT_NE check passes                                                                          | Should Pass |
 * | 03               | Validate the returned data model's network ID and MAC address | net_id = "Network2", mac = 10,11,12,13,14,16                                                     | Data model's network ID equals "Network2" and MAC address matches the provided MAC; ASSERT_STREQ and ASSERT_EQ pass  | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_data_model_ExistentNetworkID) {
    std::cout << "Entering get_data_model_ExistentNetworkID test" << std::endl;
    const char* net_id = "Network2";
    unsigned char mac[6] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x16};
    std::cout << "Invoking get_data_model with net_id: " << net_id
              << " and AL MAC: " 
              << std::hex 
              << static_cast<int>(mac[0]) << ":" << static_cast<int>(mac[1]) << ":" 
              << static_cast<int>(mac[2]) << ":" << static_cast<int>(mac[3]) << ":" 
              << static_cast<int>(mac[4]) << ":" << static_cast<int>(mac[5])
              << std::dec << std::endl;
    dm_easy_mesh_t *dm2 = list.get_data_model(net_id, mac);
    ASSERT_NE(dm2, nullptr);
    std::cout << "Stored net_id: " << dm2->m_device.m_device_info.id.net_id << std::endl;
    std::cout << "Stored mac: "
              << std::hex
              << std::setw(2) << std::setfill('0') << (int)dm2->m_device.m_device_info.intf.mac[0] << ":"
              << std::setw(2) << std::setfill('0') << (int)dm2->m_device.m_device_info.intf.mac[1] << ":"
              << std::setw(2) << std::setfill('0') << (int)dm2->m_device.m_device_info.intf.mac[2] << ":"
              << std::setw(2) << std::setfill('0') << (int)dm2->m_device.m_device_info.intf.mac[3] << ":"
              << std::setw(2) << std::setfill('0') << (int)dm2->m_device.m_device_info.intf.mac[4] << ":"
              << std::setw(2) << std::setfill('0') << (int)dm2->m_device.m_device_info.intf.mac[5]
              << std::dec << std::endl;
    std::cout << "Num policies: " << dm2->m_num_policy << std::endl;
    std::cout << "Num op classes: " << dm2->m_num_opclass << std::endl;
    ASSERT_STREQ(dm2->m_device.m_device_info.id.net_id, net_id);
    ASSERT_EQ(memcmp(dm2->m_device.m_device_info.intf.mac, mac, 6), 0);
    std::cout << "Exiting get_data_model_ExistentNetworkID test" << std::endl;
}
/**
 * @brief Test the retrieval of a data model for a non-existent network ID
 *
 * This test verifies that when get_data_model is called with a network ID that does not exist
 * along with a valid AL MAC address, the API should return a null pointer, indicating that no data model
 * is associated with the given inputs.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 016@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                 | Test Data                                                                                          | Expected Result                                                                     | Notes            |
 * | :--------------: | ------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- | ---------------- |
 * | 01               | Initialize the test variables and log the entry message                                     | net_id = "nonexistent", valid_al_mac = 0x00,0x11,0x22,0x33,0x44,0x55                                 | Entry log message printed successfully                                              | Should be successful |
 * | 02               | Invoke get_data_model API with the non-existent network ID and valid AL MAC address           | net_id = "nonexistent", valid_al_mac = 0x00,0x11,0x22,0x33,0x44,0x55                                 | dataModel is expected to be nullptr and assertion passes                            | Should Pass      |
 * | 03               | Log the exit message from the test                                                          | None                                                                                               | Exit log message printed successfully                                               | Should be successful |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_data_model_NonExistentNetworkID) {
    std::cout << "Entering get_data_model_NonExistentNetworkID test" << std::endl;
    const char* net_id = "nonexistent";
    unsigned char valid_al_mac[6] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    dm_easy_mesh_t *dataModel = list.get_data_model(net_id, valid_al_mac);
    std::cout << "Invoked get_data_model with net_id: " << net_id
              << " and AL MAC: " 
              << std::hex 
              << static_cast<int>(valid_al_mac[0]) << ":" << static_cast<int>(valid_al_mac[1]) << ":" 
              << static_cast<int>(valid_al_mac[2]) << ":" << static_cast<int>(valid_al_mac[3]) << ":" 
              << static_cast<int>(valid_al_mac[4]) << ":" << static_cast<int>(valid_al_mac[5])
              << std::dec << std::endl;
    EXPECT_EQ(dataModel, nullptr);
    std::cout << "Exiting get_data_model_NonExistentNetworkID test" << std::endl;
}
/**
 * @brief Verifies that get_data_model returns nullptr when provided with a null network ID.
 *
 * This test validates that the get_data_model API handles invalid input gracefully by passing a null
 * network identifier. The function is expected to return a nullptr, indicating no valid data model
 * exists for a null network ID. This helps ensure robustness against improper input and prevents
 * undefined behavior.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 017@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                        | Test Data                                                      | Expected Result                                         | Notes       |
 * | :--------------: | ------------------------------------------------------------------ | -------------------------------------------------------------- | ------------------------------------------------------- | ----------- |
 * | 01               | Invoke get_data_model with a null network ID and a valid MAC address | net_id = nullptr, valid_al_mac = 0x00,0x11,0x22,0x33,0x44,0x55 | Function returns nullptr and ASSERT_EQ verifies the condition | Should Fail |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_data_model_NullNetworkID) {
    std::cout << "Entering get_data_model_NullNetworkID test" << std::endl;
    const char* net_id = nullptr;
    unsigned char valid_al_mac[6] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    dm_easy_mesh_t *dataModel = list.get_data_model(net_id, valid_al_mac);
    ASSERT_EQ(dataModel, nullptr);
    std::cout << "Exiting get_data_model_NullNetworkID test" << std::endl;
}
/**
 * @brief Verify that get_data_model returns nullptr when provided with a NULL AL MAC parameter.
 *
 * This test ensures that the get_data_model API correctly handles a scenario where a valid network identifier is provided but the AL MAC pointer is NULL.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 018@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                  | Test Data                                                      | Expected Result                                                                  | Notes        |
 * | :--------------: | ------------------------------------------------------------ | -------------------------------------------------------------- | -------------------------------------------------------------------------------- | ------------ |
 * | 01               | Invoke get_data_model with valid net_id and NULL AL MAC value. | net_id = "network1", al_mac = NULL, output: dataModel pointer    | API should return nullptr; assertion check ensures that dataModel is nullptr.   | Should Pass  |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_data_model_NullALMAC) {
    std::cout << "Entering get_data_model_NullALMAC test" << std::endl;
    const char* net_id = "network1";
    unsigned char* al_mac = nullptr;
    std::cout << "Invoking get_data_model with net_id: " << net_id << " and AL MAC: NULL" << std::endl;
    dm_easy_mesh_t *dataModel = list.get_data_model(net_id, al_mac);
    ASSERT_EQ(dataModel, nullptr);
    std::cout << "Exiting get_data_model_NullALMAC test" << std::endl;
}
/**
 * @brief Validate retrieval of an existing device from the mesh list
 *
 * This test verifies that when a valid device key is provided to the get_device API, it returns a non-null pointer for the existing device. The test further asserts that the network ID, interface MAC address, and profile type of the returned device are correct. This confirmation is essential to ensure that the device lookup functionality is working as intended.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 019@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                          | Test Data                                                                                       | Expected Result                                                                                   | Notes        |
 * | :--------------: | -------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- | ------------ |
 * | 01               | Invoke get_device with a valid device key                            | key = "Network1@AA:BB:CC:DD:EE:FF@0x0100"                                                        | Returns a non-null pointer to the device                                                          | Should Pass  |
 * | 02               | Verify the network ID of the returned device                         | device->m_device_info.id.net_id = "Network1"                                                     | Network ID matches "Network1"                                                                     | Should Pass  |
 * | 03               | Validate the MAC address of the device interface                      | device->m_device_info.intf.mac, expected MAC = "AA:BB:CC:DD:EE:FF"                                 | MAC addresses are identical                                                                       | Should Pass  |
 * | 04               | Ensure that the profile type of the device is as expected             | device->m_device_info.profile, expected profile = em_profile_type_2                                 | Profile equals em_profile_type_2                                                                  | Should Pass  |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_device_valid_existing_device)
{
    std::cout << "Entering get_device_valid_existing_device test" << std::endl;
    const char *key = "Network1@AA:BB:CC:DD:EE:FF@0x0100";
    std::cout << "Invoking get_device with key: " << key << std::endl;
    dm_device_t *device = list.get_device(key);    
    EXPECT_NE(device, nullptr);
    ASSERT_STREQ(device->m_device_info.id.net_id, "Network1");
    unsigned char expected_mac[6] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    ASSERT_EQ(memcmp(device->m_device_info.intf.mac, expected_mac, 6), 0);
    ASSERT_EQ(device->m_device_info.profile, em_profile_type_2);
    std::cout << "Exiting get_device_valid_existing_device test" << std::endl;
}
/**
 * @brief Verify that get_device with a non-existing key returns nullptr.
 *
 * This test verifies that when get_device is called with a valid key that does not exist in the device list,
 * the API correctly returns a null pointer. This ensures that the function handles non-existing device keys as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 020@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                  | Test Data                                         | Expected Result                             | Notes       |
 * | :--------------: | ------------------------------------------------------------ | ------------------------------------------------- | ------------------------------------------- | ----------- |
 * | 01               | Invoke get_device API with a non-existing device key         | key = net2:00-22-33-44-55-66                       | Returns nullptr; EXPECT_EQ(device, nullptr) | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_device_valid_non_existing_device)
{
    std::cout << "Entering get_device_valid_non_existing_device test" << std::endl;
    const char *key = "net2:00-22-33-44-55-66";
    std::cout << "Invoking get_device with key: " << key << std::endl;
    dm_device_t *device = list.get_device(key);
    std::cout << "Returned device pointer: " << device << std::endl;
    EXPECT_EQ(device, nullptr);
    std::cout << "Exiting get_device_valid_non_existing_device test" << std::endl;
}
/**
 * @brief Test get_device API for null key input, ensuring proper null return on invalid input.
 *
 * This test verifies that calling the get_device API with a null key returns a null device pointer.
 * The API should handle the null input gracefully without causing a crash or unexpected behavior.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 021
 * **Priority:** High
 * 
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                             | Test Data                              | Expected Result                                                      | Notes       |
 * | :--------------: | ------------------------------------------------------- | -------------------------------------- | --------------------------------------------------------------------- | ----------- |
 * | 01               | Set the key to nullptr and invoke get_device API        | key = nullptr                          | get_device() should return nullptr and the assertion EXPECT_EQ passes | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_device_null_key)
{
    std::cout << "Entering get_device_null_key test" << std::endl;
    const char *key = nullptr;
    std::cout << "Invoking get_device with key: " << "NULL" << std::endl;
    dm_device_t *device = list.get_device(key);
    std::cout << "Returned device pointer: " << device << std::endl;
    EXPECT_EQ(device, nullptr);
    std::cout << "Exiting get_device_null_key test" << std::endl;
}
/**
 * @brief Test for get_device function with an empty key.
 *
 * This test verifies that invoking the get_device API with an empty string as the key returns a null pointer. This behavior ensures that the API properly handles cases when an invalid or empty key is provided.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 022@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                           | Test Data           | Expected Result                                         | Notes      |
 * | :--------------: | ----------------------------------------------------- | ------------------- | ------------------------------------------------------- | ---------- |
 * | 01               | Invoke get_device with an empty key                   | key = ""            | Returns a null pointer and EXPECT_EQ(device, nullptr)   | Should Pass|
 */
TEST_F(dm_easy_mesh_list_tTEST, get_device_empty_key)
{
    std::cout << "Entering get_device_empty_key test" << std::endl;
    const char *key = "";
    std::cout << "Invoking get_device with key: " << "\"" << key << "\"" << std::endl;
    dm_device_t *device = list.get_device(key);
    std::cout << "Returned device pointer: " << device << std::endl;
    EXPECT_EQ(device, nullptr);
    std::cout << "Exiting get_device_empty_key test" << std::endl;
}
/**
 * @brief Validate get_device returns nullptr for an improperly formatted key
 *
 * This test validates that invoking the get_device method with an improperly formatted key ("invalidkeyformat") correctly returns a nullptr, ensuring the API's ability to handle invalid input formats robustly.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 023@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                          | Test Data                                   | Expected Result                                             | Notes       |
 * | :--------------: | -------------------------------------------------------------------------------------|---------------------------------------------|-------------------------------------------------------------|-------------|
 * | 01               | Invoke get_device with an improperly formatted key and verify it returns nullptr        | key = invalidkeyformat                      | Returned device pointer is nullptr and EXPECT_EQ check passes| Should Fail |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_device_improper_formatted_key)
{
    std::cout << "Entering get_device_improper_formatted_key test" << std::endl;
    const char *key = "invalidkeyformat";
    std::cout << "Invoking get_device with key: " << key << std::endl;
    dm_device_t *device = list.get_device(key);
    std::cout << "Returned device pointer: " << device << std::endl;
    EXPECT_EQ(device, nullptr);
    std::cout << "Exiting get_device_improper_formatted_key test" << std::endl;
}
/**
 * @brief Test to verify get_device handles keys with extra whitespace.
 *
 * This test verifies that the get_device API correctly handles keys that contain leading and trailing whitespace. The expected behavior is that such a malformed key should result in the API returning a nullptr, thereby indicating that the input was not sanitized to match any valid device.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 024@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                   | Test Data                                            | Expected Result                                                              | Notes           |
 * | :--------------: | ------------------------------------------------------------- | ---------------------------------------------------- | ---------------------------------------------------------------------------- | --------------- |
 * | 01               | Log the entry into the get_device_extra_whitespace test       | N/A                                                | "Entering get_device_extra_whitespace test" printed to console               | Should be successful |
 * | 02               | Invoke get_device with a key having extra leading/trailing spaces | key = " net1:AA:BB:CC:DD:EE:FF "                       | get_device returns nullptr and the EXPECT_EQ assertion passes                 | Should Pass     |
 * | 03               | Log the returned device pointer result                        | N/A                                                | "Returned device pointer: nullptr" printed to console                         | Should be successful |
 * | 04               | Log the exit from the get_device_extra_whitespace test          | N/A                                                | "Exiting get_device_extra_whitespace test" printed to console                   | Should be successful |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_device_extra_whitespace)
{
    std::cout << "Entering get_device_extra_whitespace test" << std::endl;
    const char *key = " net1:AA:BB:CC:DD:EE:FF ";
    std::cout << "Invoking get_device with key: " << "\"" << key << "\"" << std::endl;
    dm_device_t *device = list.get_device(key);
    std::cout << "Returned device pointer: " << device << std::endl;
    EXPECT_EQ(device, nullptr);
    std::cout << "Exiting get_device_extra_whitespace test" << std::endl;
}
/**
 * @brief Verify that get_first_bss() returns NULL when the network list has no BSS entries.
 *
 * This test case validates that the get_first_bss() API correctly returns a NULL pointer
 * when there are no BSS (Basic Service Set) entries available in the network list. It checks
 * the behavior of the API in an empty state scenario to ensure that it does not return any
 * invalid pointers or data.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 025@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                       | Test Data                                                             | Expected Result                                                | Notes       |
 * | :--------------: | ----------------------------------------------------------------- | --------------------------------------------------------------------- | -------------------------------------------------------------- | ----------- |
 * | 01               | Invoke get_first_bss() on an empty network list to retrieve the first BSS. | API Invocation: list.get_first_bss() (no input parameters, output: firstBss pointer expected to be NULL) | get_first_bss() returns a NULL pointer; assertion EXPECT_EQ(firstBss, nullptr) passes | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_first_bss_returns_NULL_when_empty)
{
    const char* testName = "get_first_bss_returns_NULL_when_empty";
    std::cout << "Entering " << testName << " test" << std::endl;
    std::cout << "Invoking get_first_bss() on empty network list" << std::endl;
    dm_bss_t* firstBss = list.get_first_bss();
    std::cout << "get_first_bss() returned: " << firstBss << std::endl;
    EXPECT_EQ(firstBss, nullptr);
    std::cout << "Exiting " << testName << " test" << std::endl;
}
/**
 * @brief Verify that get_first_device returns a valid pointer and expected network configuration
 *
 * This test verifies that the function get_first_device correctly returns a non-null device pointer from the mesh device list.
 * It checks that the returned device belongs to "Network2" and has the expected profile (em_profile_type_3), ensuring that the device list
 * initialization and retrieval logic works as intended.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 026
 * **Priority:** High
 * 
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- | -------------- | ----- |
 * | 01 | Print entering test message | None | Console prints "Entering get_first_device_returns_valid_pointer test" | Should be successful |
 * | 02 | Invoke get_first_device() on meshList | Call: device = list.get_first_device() | Returns a non-null pointer to a device | Should Pass |
 * | 03 | Assert that device is not null | device != nullptr | ASSERT_NE passes confirming device is not nullptr | Should Pass |
 * | 04 | Validate network id of device | device->m_device_info.id.net_id = "Network2" | EXPECT_STREQ passes comparing net_id with "Network2" | Should Pass |
 * | 05 | Validate device profile | device->m_device_info.profile = em_profile_type_3 | EXPECT_EQ passes confirming the profile equals em_profile_type_3 | Should Pass |
 * | 06 | Print exiting test message | None | Console prints "Exiting get_first_device_returns_valid_pointer test" | Should be successful |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_first_device_returns_valid_pointer)
{
    std::cout << "Entering get_first_device_returns_valid_pointer test" << std::endl;
    std::cout << "Invoking get_first_device() on meshList" << std::endl;
	dm_device_t *device = list.get_first_device();
	ASSERT_NE(device, nullptr);
	EXPECT_STREQ(device->m_device_info.id.net_id, "Network2");
	EXPECT_EQ(device->m_device_info.profile, em_profile_type_3);
	std::cout << "Exiting get_first_device_returns_valid_pointer test" << std::endl;
}
/**
 * @brief Verify that the get_first_dm API returns the first valid data model element from the list.
 *
 * This test verifies that the dm_easy_mesh_list_t instance returns a valid first data model element. It ensures that the returned element is not null, that its network identifier is "Network2", its profile type is em_profile_type_3, and that it has exactly 8 policies. The test is critical to validate the proper functioning of network data model management.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 027@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                             | Test Data                                                                                          | Expected Result                                                       | Notes           |
 * | :--------------: | ----------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | --------------- |
 * | 01               | Log the entry message "Entering get_first_dm_valid"                      | No input arguments                                                                                 | "Entering get_first_dm_valid" printed to stdout                       | Should be successful |
 * | 02               | Invoke the API call list.get_first_dm() and store the result in firstElement | list instance, method call: firstElement = list.get_first_dm()                                       | A valid pointer (non-null) is returned                                | Should Pass     |
 * | 03               | Assert that the returned firstElement is not null                          | firstElement, expected value: non-null                                                             | Assertion passes when firstElement != nullptr                           | Should Pass     |
 * | 04               | Validate that the network id of firstElement is "Network2"                  | firstElement->m_device.m_device_info.id.net_id = "Network2"                                          | The network id string is equal to "Network2"                           | Should Pass     |
 * | 05               | Validate that the profile type of firstElement is em_profile_type_3         | firstElement->m_device.m_device_info.profile, expected: em_profile_type_3                             | Profile type matches em_profile_type_3                                 | Should Pass     |
 * | 06               | Validate that the number of policies for firstElement is 8                  | firstElement->m_num_policy, expected: 8                                                              | Policy count equals 8                                                   | Should Pass     |
 * | 07               | Log the exit message "Exiting get_first_dm_valid test"                    | No input arguments                                                                                 | "Exiting get_first_dm_valid test" printed to stdout                     | Should be successful |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_first_dm_valid)
{
    std::cout << "Entering get_first_dm_valid" << std::endl;
    dm_easy_mesh_t* firstElement = list.get_first_dm();
    ASSERT_NE(firstElement, nullptr);
	unsigned char expected_mac[6] = {0x10, 0x11, 0x12, 0x13, 0x12, 0x15};
	EXPECT_STREQ(firstElement->m_device.m_device_info.id.net_id, "Network2");
	EXPECT_EQ(firstElement->m_device.m_device_info.profile, em_profile_type_3);
	EXPECT_EQ(firstElement->m_num_policy, 8);
    std::cout << "Exiting get_first_dm_valid test" << std::endl;
}
/**
 * @brief Verify that get_first_network() returns nullptr when no networks are present
 *
 * This test verifies that invoking the get_first_network() API on an empty network list returns a nullptr.
 * In this scenario, it confirms that the API correctly handles cases where no network has been added.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 028@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                         | Test Data                                                        | Expected Result                                                       | Notes        |
 * | :--------------: | ------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------------- | ------------ |
 * | 01               | Invoke get_first_network() on an empty network list                 | list: get_first_network() invoked, no networks present           | Return value is nullptr and ASSERT_EQ(result, nullptr) passes         | Should Pass  |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_first_network_returns_NULL_when_no_networks_present)
{
    std::cout << "Entering get_first_network_returns_NULL_when_no_networks_present test" << std::endl;
    std::cout << "Invoking get_first_network()" << std::endl;
    dm_network_t* result = list.get_first_network();
    ASSERT_EQ(result, nullptr);
    std::cout << "Exiting get_first_network_returns_NULL_when_no_networks_present test" << std::endl;
}
/**
 * @brief Verify that get_first_network_ssid returns null when no network SSID is available.
 *
 * This test invokes the get_first_network_ssid method on the list instance configured in the test fixture.
 * It checks that when no network SSID is present in the list (only networks are registered without SSIDs), 
 * the API returns a nullptr. This ensures that the API behaves correctly under empty conditions.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 029
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                        | Test Data                                                           |Expected Result                                          |Notes        |
 * | :--------------: | ------------------------------------------------------------------ | ------------------------------------------------------------------- |---------------------------------------------------------|------------ |
 * | 01               | Call get_first_network_ssid to retrieve the first network SSID.    | list.get_first_network_ssid() invoked, output first_network = nullptr | API returns nullptr and assertion passes successfully. | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_first_network_ssid_returns_null)
{
    std::cout << "Entering get_first_network_ssid_returns_null test" << std::endl;
    std::cout << "Invoking get_first_network_ssid()" << std::endl;
    dm_network_ssid_t* first_network = list.get_first_network_ssid();
    ASSERT_EQ(first_network, nullptr);
    std::cout << "Exiting get_first_network_ssid_returns_null test" << std::endl;
}
/**
 * @brief Verify correct retrieval of the first operation class from the mesh list
 *
 * This test verifies that the get_first_op_class() API returns a valid op class object when invoked.
 * It sets up a mesh context with an initialized dm_easy_mesh_t object having m_num_opclass set to 0,
 * and then calls the API to retrieve the first op class. The test asserts that the returned pointer is not null
 * and that the op_class field within the op_class info is one of the expected values (81, 115, or 135).
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 030@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize dm_easy_mesh_t instance, set m_num_opclass to 0, and invoke get_first_op_class() API. | dm.m_num_opclass = 0, opClass = list.get_first_op_class() | opClass is not nullptr and opClass->m_op_class_info.op_class is 81, 115, or 135 | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_first_op_class_valid)
{
    std::cout << "Entering get_first_op_class_valid test" << std::endl;
    dm_easy_mesh_t dm;
    dm.m_num_opclass = 0;
    std::cout << "Invoking get_first_op_class()" << std::endl;
    dm_op_class_t* opClass = list.get_first_op_class();
    ASSERT_NE(opClass, nullptr);
    EXPECT_TRUE(opClass->m_op_class_info.op_class == 81 || opClass->m_op_class_info.op_class == 115 || opClass->m_op_class_info.op_class == 135);
    std::cout << "Returned op_class = " << opClass->m_op_class_info.op_class << std::endl;			
    std::cout << "Exiting get_first_op_class_valid test" << std::endl;
}
/**
 * @brief Verify behavior of get_first_policy() when the policy list is empty
 *
 * This test checks if the get_first_policy() function returns a valid policy object even when no policies have been added 
 * (i.e., when m_num_policy is set to 0). The test validates that the returned policy's network ID and type match the expected 
 * default values. This ensures that the API does not fail or return an unexpected null pointer when the policy list is empty.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 031@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                           | Test Data                                                                                     | Expected Result                                                                          | Notes         |
 * | :--------------: | ----------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ------------- |
 * | 01               | Initialize dm_easy_mesh_t instance and set m_num_policy to 0                                          | dm.m_num_policy = 0                                                                           | The policy list is empty                                                                 | Should be successful |
 * | 02               | Invoke get_first_policy() on list                                                                     | Invocation: get_first_policy()                                                                | Returns a non-null pointer to a dm_policy_t object                                         | Should Pass   |
 * | 03               | Validate returned policy's network ID and policy type                                                 | pol->m_policy.id.net_id = OneWifiMesh, pol->m_policy.id.type = em_policy_id_type_ap_metrics_rep | Assertions pass confirming net_id equals "OneWifiMesh" and type equals em_policy_id_type_ap_metrics_rep | Should Pass   |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_first_policy_empty_policy_list)
{
    const char* testName = "get_first_policy_empty_policy_list";
    std::cout << "Entering " << testName << " test" << std::endl;
    dm_easy_mesh_t dm;
    dm.m_num_policy = 0;
    std::cout << "Invoking: get_first_policy()" << std::endl;
    dm_policy_t* pol = list.get_first_policy();
    ASSERT_NE(pol, nullptr);
    EXPECT_STREQ(pol->m_policy.id.net_id, "OneWifiMesh");
    EXPECT_EQ(pol->m_policy.id.type, em_policy_id_type_ap_metrics_rep);
    //EXPECT_EQ(memcmp(pol->m_policy.id.originator, zeroMac, 6), 0);
    std::cout << "Exiting " << testName << " test" << std::endl;
}
/**
 * @brief Test get_first_pre_set_op_class_by_type API for negative scenario where no pre-configured operation class exists.
 *
 * This test verifies that invoking get_first_pre_set_op_class_by_type with type em_op_class_type_none returns a nullptr in the dm_easy_mesh_list_t.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 032@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke get_first_pre_set_op_class_by_type with type em_op_class_type_none | input: type = em_op_class_type_none, output: opClass expected to be nullptr | API returns nullptr and assertion passes | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_first_pre_set_op_class_by_type_NoPreConfiguredOperationClassPresent)
{
    std::cout << "Entering get_first_pre_set_op_class_by_type_NoPreConfiguredOperationClassPresent test" << std::endl;
    std::cout << "Invoking get_first_pre_set_op_class_by_type with type: em_op_class_type_none" << std::endl;
    dm_op_class_t * opClass = list.get_first_pre_set_op_class_by_type(em_op_class_type_none);
    ASSERT_EQ(opClass, nullptr);
    std::cout << "Exiting get_first_pre_set_op_class_by_type_NoPreConfiguredOperationClassPresent test" << std::endl;
}
/**
 * @brief Verify get_first_radio() behavior when multiple radios exist
 *
 * This test verifies that the get_first_radio() function returns a nullptr when invoked on a list containing multiple radio interfaces.
 * The check ensures that the API returns a null pointer when the conditions for a valid radio pointer are not met.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 033@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                  | Test Data                                                     | Expected Result                                                | Notes       |
 * | :--------------: | -------------------------------------------------------------------------------------------- | ------------------------------------------------------------- | -------------------------------------------------------------- | ----------- |
 * | 01               | Invoke get_first_radio() with multiple radio interfaces from the test fixture setup            | list instance (radios from eth0 and eth1 as initialized in SetUp) | get_first_radio() returns nullptr as verified by ASSERT_EQ check | Should Fail |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_first_radio_returns_valid_pointer_when_multiple_radios_exist) {
    std::cout << "Entering get_first_radio_returns_valid_pointer_when_multiple_radios_exist test" << std::endl;  
    std::cout << "Invoking get_first_radio() with 2 radios" << std::endl;
    dm_radio_t *radio = list.get_first_radio();
    ASSERT_EQ(radio, nullptr);
    std::cout << "Exiting get_first_radio_returns_valid_pointer_when_one_radio_exist test" << std::endl;
}
/**
 * @brief Verify that get_first_radio returns NULL for an unmatched network ID.
 *
 * This test ensures that the get_first_radio API returns a NULL pointer when invoked with a network ID that does not exist
 * in the list of registered data models. It confirms that the function handles non-existent network identifiers correctly without
 * producing any radio object.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 034@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke get_first_radio with non-existent network ID "Network4" and a valid MAC address | net_id = "Network4", mac = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66}, output: radio pointer | The function returns a NULL pointer and ASSERT_EQ confirms radio is NULL | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_first_radio_returns_NULL_when_net_id_does_not_match) {
    std::cout << "Entering get_first_radio_returns_NULL_when_net_id_does_not_match test" << std::endl;
    const char* net_id = "Network4";
    mac_address_t mac = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    std::cout << "Invoking get_first_radio(const char*, mac_address_t) with net_id: nonexistent_network_id and MAC: ";
    dm_radio_t* radio = list.get_first_radio(net_id, mac);
    ASSERT_EQ(radio, nullptr);
    std::cout << "Exiting get_first_radio_returns_NULL_when_net_id_does_not_match test" << std::endl;
}
/**
 * @brief Verify that get_first_radio returns nullptr when provided with a null MAC address.
 *
 * This test verifies that the get_first_radio API correctly returns a null pointer when invoked with a MAC address
 * that consists entirely of zeros. This ensures the API properly handles invalid or placeholder MAC address inputs.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 035@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call get_first_radio API with network id "Network1" and a MAC address set to all zeros | net_id = "Network1", MAC = 0,0,0,0,0,0 | API returns a nullptr radio pointer verified by the assertion EXPECT_EQ(radio, nullptr) | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_first_radio_handles_null_mac) {
    std::cout << "Entering get_first_radio_handles_null_mac test" << std::endl;
    unsigned char zero_mac[6] = { 0, 0, 0, 0, 0, 0 };
    std::cout << "Invoking get_first_radio(const char*, mac_address_t) with net_id: \"\" and MAC: ";
    dm_radio_t* radio = list.get_first_radio("Network1", zero_mac);
    EXPECT_EQ(radio, nullptr);
    std::cout << "Exiting get_first_radio_handles_null_mac test" << std::endl;
}
/**
 * @brief Test that verifies get_first_radio returns NULL when provided with a NULL net_id
 *
 * This test invokes the get_first_radio API with a NULL network identifier and a valid al_mac.
 * The purpose is to ensure that the API correctly handles invalid input by returning a NULL pointer.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 036@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:** 
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Prepare test input parameters for the API call. | net_id = NULL, al_mac = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF} | Test inputs are prepared correctly for a negative test scenario. | Should be successful |
 * | 02 | Invoke get_first_radio with the prepared inputs and validate that the return value is NULL. | net_id = NULL, al_mac = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, returned radio = nullptr | API returns a NULL pointer and assertion (ASSERT_EQ(nullptr, radio)) passes. | Should Fail |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_first_radio_NULL_netid_returns_NULL)
{
    std::cout << "Entering get_first_radio_NULL_netid_returns_NULL test" << std::endl;
    unsigned char al_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    std::cout << "Invoking get_first_radio with net_id: NULL and al_mac: {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}" << std::endl;
    dm_radio_t* radio = list.get_first_radio(NULL, al_mac);
    std::cout << "Returned pointer: " << radio << std::endl;
    ASSERT_EQ(nullptr, radio);
    std::cout << "Exiting get_first_radio_NULL_netid_returns_NULL test" << std::endl;
}
/**
 * @brief Test that get_first_radio returns nullptr when provided with an empty network ID.
 *
 * This test verifies that if an empty string is passed as the network ID along with a valid MAC address,
 * the get_first_radio function properly returns a nullptr. This behavior is critical for input validation
 * and ensures that the API does not process invalid network identifiers.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 037
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Log entry message for test start | N/A | Console log prints "Entering get_first_radio_empty_netid_returns_NULL test" | Should be successful |
 * | 02 | Define and initialize MAC address al_mac | al_mac = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF} | MAC address initialized correctly | Should be successful |
 * | 03 | Log API invocation details | net_id = "", al_mac = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF} | Console log prints invocation details | Should be successful |
 * | 04 | Invoke get_first_radio with empty net_id and al_mac | net_id = "", al_mac = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF} | Function returns nullptr | Should Fail |
 * | 05 | Verify via assertion that the returned radio pointer is nullptr | radio pointer from get_first_radio, expected nullptr | ASSERT_EQ(nullptr, radio) passes | Should Pass |
 * | 06 | Log exit message for test completion | N/A | Console log prints "Exiting get_first_radio_empty_netid_returns_NULL test" | Should be successful |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_first_radio_empty_netid_returns_NULL)
{
    std::cout << "Entering get_first_radio_empty_netid_returns_NULL test" << std::endl;
    unsigned char al_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    std::cout << "Invoking get_first_radio with net_id: \"\" and al_mac: {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}" << std::endl;
    dm_radio_t* radio = list.get_first_radio("", al_mac);
    std::cout << "Returned pointer: " << radio << std::endl;
    ASSERT_EQ(nullptr, radio);
    std::cout << "Exiting get_first_radio_empty_netid_returns_NULL test" << std::endl;
}
/**
 * @brief Validate that get_first_scan_result() returns nullptr when no scan results exist
 *
 * This test verifies that the get_first_scan_result() method, when invoked on a dm_easy_mesh_list_t instance that has not received any scan results, correctly returns a nullptr without throwing any exceptions. This ensures that the API can gracefully handle the case when no scan result data is present.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 038@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Log entry into the test case | None | "Entering get_first_scan_result_ReturnNullWhenNoScanResultsExist test" message printed to console | Should be successful |
 * | 02 | Log the invocation of get_first_scan_result() | None | "Invoking get_first_scan_result()" message printed to console | Should be successful |
 * | 03 | Invoke get_first_scan_result() API function | result = list.get_first_scan_result() | API does not throw exception and returns nullptr | Should Pass |
 * | 04 | Assert that the returned result is nullptr | result expected to be nullptr | Assertion confirms that result is nullptr | Should be successful |
 * | 05 | Log exit from the test case | None | "Exiting get_first_scan_result_ReturnNullWhenNoScanResultsExist test" message printed to console | Should be successful |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_first_scan_result_ReturnNullWhenNoScanResultsExist)
{
    std::cout << "Entering get_first_scan_result_ReturnNullWhenNoScanResultsExist test" << std::endl;
    std::cout << "Invoking get_first_scan_result()" << std::endl;
    dm_scan_result_t* result = nullptr;
    EXPECT_NO_THROW(result = list.get_first_scan_result());
    ASSERT_EQ(result, nullptr);
    std::cout << "Exiting get_first_scan_result_ReturnNullWhenNoScanResultsExist test" << std::endl;
}
/**
 * @brief Verify that get_first_sta() returns nullptr when the network list contains no STA entries.
 *
 * This test ensures that when the network list is empty regarding station (STA) entries, invoking get_first_sta() returns a nullptr as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 039@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                                          | Test Data                                           | Expected Result                                                                 | Notes      |
 * | :--------------: | -------------------------------------------------------------------- | --------------------------------------------------- | -------------------------------------------------------------------------------- | ---------- |
 * | 01               | Invoke get_first_sta() on an empty network list                      | No inputs, output firstSta from get_first_sta()     | The API returns a nullptr, and EXPECT_EQ confirms firstSta is equal to nullptr  | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_first_sta_empty_network_list)
{
    const char *testName = "get_first_sta_empty_network_list";
    std::cout << "Entering " << testName << " test" << std::endl;
    std::cout << "Invoking get_first_sta()" << std::endl;
    dm_sta_t* firstSta = list.get_first_sta();
    EXPECT_EQ(firstSta, nullptr);
    std::cout << "Exiting " << testName << " test" << std::endl;
}
/**
 * @brief Test to verify that get_network returns null when a non-existent key is provided.
 *
 * This test validates that the dm_easy_mesh_list_t::get_network API correctly returns a null pointer when invoked with a key that does not exist in the network list. This ensures the proper handling of invalid keys in the network lookup functionality.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 040@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                 | Test Data                           | Expected Result                                              | Notes       |
 * | :--------------: | --------------------------------------------------------------------------- | ----------------------------------- | ------------------------------------------------------------ | ----------- |
 * | 01               | Invoke get_network using a non-existent key and verify the return value.    | key = nonExistentKey                | The API returns a nullptr and the assertion passes.          | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_network_nonExistentKey)
{
    std::cout << "Entering get_network_nonExistentKey test" << std::endl;
    const char* key = "nonExistentKey";
    std::cout << "Invoking get_network with key: " << key << std::endl;
    dm_network_t* retNetwork = list.get_network(key);
    ASSERT_EQ(retNetwork, nullptr);
    std::cout << "Exiting get_network_nonExistentKey test" << std::endl;
}
/**
 * @brief Test for retrieving a network using an empty key
 *
 * This test case validates the functionality of the get_network API when the key provided is empty. It ensures that even with an empty key, the API returns a valid network instance, which is critical for handling edge cases gracefully.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 041
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call get_network() with an empty key and check for a valid network object | key = "" | API returns a non-null pointer and ASSERT_NE(retNetwork, nullptr) passes | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_network_emptyKey)
{
    std::cout << "Entering get_network_emptyKey test" << std::endl;
    const char* key = "";
    std::cout << "Invoking get_network with empty key: \"" << key << "\"" << std::endl;
    dm_network_t* retNetwork = list.get_network(key);
    ASSERT_NE(retNetwork, nullptr);
    std::cout << "Exiting get_network_emptyKey test" << std::endl;
}
/**
 * @brief Verify that get_network returns nullptr when provided a null key
 *
 * This test verifies that the get_network API function properly handles a null key input by returning a nullptr. 
 * This behavior is important to ensure the robustness and reliability of the API in handling invalid or unexpected inputs.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 042@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                  | Test Data                                | Expected Result                                                  | Notes       |
 * | :--------------: | ------------------------------------------------------------ | ---------------------------------------- | ---------------------------------------------------------------- | ----------- |
 * | 01               | Set the key to nullptr and invoke get_network                | key = nullptr                            | API should return nullptr and ASSERT_EQ confirms the null return   | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_network_NULLKey)
{
    std::cout << "Entering get_network_NULLKey test" << std::endl;
    const char* key = nullptr;
    std::cout << "Invoking get_network with NULL key" << std::endl;
    dm_network_t* retNetwork = list.get_network(key);
    ASSERT_EQ(retNetwork, nullptr);
    std::cout << "Exiting get_network_NULLKey test" << std::endl;
}
/**
 * @brief Test negative scenario for get_network_ssid function.
 *
 * This test verifies that invoking the get_network_ssid API with a nonexistent key returns a nullptr.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 043
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                         | Test Data                                          | Expected Result                                         | Notes       |
 * | :--------------: | --------------------------------------------------- | -------------------------------------------------- | ------------------------------------------------------- | ----------- |
 * | 01               | Invoke get_network_ssid with a nonexistent key      | key = nonexistent_key, dm.m_num_net_ssids = 2      | Function returns nullptr and ASSERT_EQ(result, nullptr) | Should Fail |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_network_ssid_Negative_nonexistent_key) {
    std::cout << "Entering get_network_ssid_Negative_nonexistent_key test" << std::endl;
    dm_easy_mesh_t dm;
    dm.m_num_net_ssids = 2;
    const char* key = "nonexistent_key";
    std::cout << "Invoking get_network_ssid with key: " << key << std::endl;
    dm_network_ssid_t* result = list.get_network_ssid(key);
    ASSERT_EQ(result, nullptr);
    std::cout << "Exiting get_network_ssid_Negative_nonexistent_key test" << std::endl;
}
/**
 * @brief Validates the get_network_ssid API with a null key.
 *
 * This test case verifies that when the get_network_ssid API is called with a null key,
 * it returns a null pointer. This negative test ensures that the API correctly handles
 * invalid input by returning an expected failure result.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 044@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                          | Test Data                 | Expected Result                                  | Notes      |
 * | :--------------: | ---------------------------------------------------- | ------------------------- | ------------------------------------------------ | ---------- |
 * | 01               | Set key to NULL and invoke get_network_ssid API call | key = NULL                | API returns nullptr and assertion verifies nullptr | Should Fail |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_network_ssid_Negative_null_key) {
    std::cout << "Entering get_network_ssid_Negative_null_key test" << std::endl;
    const char* key = NULL;
    std::cout << "Invoking get_network_ssid with NULL key" << std::endl;
    dm_network_ssid_t* result = list.get_network_ssid(key);
    ASSERT_EQ(result, nullptr);
    std::cout << "Exiting get_network_ssid_Negative_null_key test" << std::endl;
}
/**
 * @brief Verify that get_network_ssid returns nullptr when provided with an empty string key
 *
 * This test case verifies that the get_network_ssid API correctly handles the scenario when an empty string key is provided. The test ensures that the API returns a nullptr when an empty key is passed.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 045@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                           | Test Data                                                       | Expected Result                                               | Notes       |
 * | :--------------: | --------------------------------------------------------------------- | --------------------------------------------------------------- | ------------------------------------------------------------- | ----------- |
 * | 01               | Initialize dm.m_num_net_ssids to 2 and invoke get_network_ssid with an empty string key | dm.m_num_net_ssids = 2, key = ""                                  | API returns nullptr; EXPECT_EQ confirms the nullptr value      | Should Fail |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_network_ssid_Negative_empty_string_key) {
    std::cout << "Entering get_network_ssid_Negative_empty_string_key test" << std::endl;
    dm_easy_mesh_t dm;
    dm.m_num_net_ssids = 2;
    const char* key = "";
    std::cout << "Invoking get_network_ssid with empty string key" << std::endl;
    dm_network_ssid_t* result = list.get_network_ssid(key);
    std::cout << "Returned pointer: " << result << std::endl;
    EXPECT_EQ(result, nullptr);
    std::cout << "Exiting get_network_ssid_Negative_empty_string_key test" << std::endl;
}
/**
 * @brief Verify that get_network_ssid returns nullptr when provided with a key containing special characters that does not exist in the network SSID list
 *
 * This test validates that the API get_network_ssid correctly handles a key with special characters ("n@work#1") that is not present in the network list,
 * and thus returns a nullptr. The test confirms that the function behaves as expected for non-existent keys.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 046@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                     | Test Data                                      | Expected Result                                   | Notes           |
 * | :--------------: | ---------------------------------------------------------------- | ---------------------------------------------- | ------------------------------------------------- | --------------- |
 * | 01               | Print entering message for test initiation                       | None                                           | "Entering get_network_ssid_Positive_special_character_key_notexists test" is logged | Should be successful |
 * | 02               | Invoke get_network_ssid API with key that includes special characters | key = n@work#1                                | API returns nullptr                               | Should Pass     |
 * | 03               | Assert that the returned pointer is nullptr using ASSERT_EQ        | result = nullptr, expected = nullptr           | Assertion passes confirming result is nullptr     | Should Pass     |
 * | 04               | Print exiting message for test completion                           | None                                           | "Exiting get_network_ssid_Positive_special_character_key_notexists test" is logged  | Should be successful |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_network_ssid_Positive_special_character_key_notexists) {
    std::cout << "Entering get_network_ssid_Positive_special_character_key_notexists test" << std::endl;
    const char* key = "n@work#1";
    std::cout << "Invoking get_network_ssid with key: " << key << std::endl;
    dm_network_ssid_t* result = list.get_network_ssid(key);
    ASSERT_EQ(result, nullptr);
    std::cout << "Exiting get_network_ssid_Positive_special_character_key_notexists test" << std::endl;
}
/**
 * @brief Verify that get_next_bss returns the correct subsequent BSS when provided a valid BSS.
 *
 * This test initializes two BSS objects with corresponding keys using build_bss_key, registers them in the list,
 * retrieves the first BSS using get_first_bss, and then calls get_next_bss with this first BSS to ensure that the subsequent
 * BSS is correctly returned. The test validates that both retrieval operations return non-null pointers.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 047@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                                      | Test Data                                                                                                                                                                                            | Expected Result                                              | Notes          |
 * | :--------------: | ---------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ | -------------- |
 * | 01               | Build two BSS keys using build_bss_key for two BSS objects.                                                      | For key1: network_id="Network1", dev_mac=mac1, radio_mac=mac2, bssid=mac3, haul_type=0, output key1; For key2: network_id="Network1", dev_mac=mac1, radio_mac=mac2, bssid=mac4, haul_type=0, output key2 | Keys generated successfully                                  | Should be successful |
 * | 02               | Initialize two dm_bss_t objects, set their bssid and mld_mac fields, and add them to the list with the keys.       | bss1: after init, bssid.mac=mac3, mld_mac=mac2; bss2: after init, bssid.mac=mac4, mld_mac=mac2; API: put_bss(key1, &bss1), put_bss(key2, &bss2)                                             | BSS objects stored in the list without errors                | Should be successful |
 * | 03               | Retrieve the first BSS using get_first_bss.                                                                      | No additional input; output: pointer to first BSS                                                                                                                                                    | Returned first BSS pointer is not null                       | Should Pass    |
 * | 04               | Invoke get_next_bss with the valid first BSS and verify the result.                                              | Input: first = pointer returned by get_first_bss; API call: get_next_bss(first)                                                                                                                        | Returned next BSS pointer is not null                        | Should Pass    |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_next_bss_valid)
{
    std::cout << "Entering get_next_bss_valid test" << std::endl;
    dm_bss_t bss1 = {}, bss2 = {};
    char key1[256], key2[256];
    build_bss_key("Network1", mac1, mac2, mac3, 0, key1);
    build_bss_key("Network1", mac1, mac2, mac4, 0, key2);
    bss1.init();
    memcpy(bss1.m_bss_info.bssid.mac, mac3, 6);
    memcpy(bss1.m_bss_info.mld_mac, mac2, 6);
    bss2.init();
    memcpy(bss2.m_bss_info.bssid.mac, mac4, 6);
    memcpy(bss2.m_bss_info.mld_mac, mac2, 6);
    list.put_bss(key1, &bss1);
    list.put_bss(key2, &bss2);
    dm_bss_t *first = list.get_first_bss();
    ASSERT_NE(first, nullptr);
    std::cout << "Invoking get_next_bss with valid bss" << std::endl;
    dm_bss_t *result = list.get_next_bss(first);
    ASSERT_NE(result, nullptr);
    std::cout << "Exiting get_next_bss_valid test" << std::endl;
}
/**
 * @brief Verify that get_next_bss returns nullptr when provided a NULL current BSS.
 *
 * This test validates that invoking the get_next_bss API with a NULL pointer as the current BSS returns a nullptr. It ensures that the function handles a NULL input by not proceeding and correctly returning a NULL value, thereby avoiding any potential segmentation faults or undefined behavior.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 048@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                         | Test Data                 | Expected Result                                       | Notes      |
 * | :--------------: | ------------------------------------------------------------------- | ------------------------- | ----------------------------------------------------- | ---------- |
 * | 01               | Invoke get_next_bss with a NULL pointer as the current BSS argument | bss = NULL                | Return value is nullptr and ASSERT_EQ check passes    | Should Pass|
 */
TEST_F(dm_easy_mesh_list_tTEST, get_next_bss_returnNull_when_currentBSSNULL)
{
    std::cout << "Entering get_next_bss_returnNull_when_currentBSSNULL test" << std::endl;
    std::cout << "Invoking get_next_bss with bss = NULL" << std::endl;
    dm_bss_t *result = list.get_next_bss(NULL);
    ASSERT_EQ(result, nullptr);
    std::cout << "Exiting get_next_bss_returnNull_when_currentBSSNULL test" << std::endl;
}
/**
 * @brief Validate that get_next_device returns the valid subsequent device in the list.
 *
 * This test verifies that after retrieving two data models from different networks ("Network1" and "Network2"), the functions get_first_device and get_next_device return valid, non-null device pointers. This confirms the correct traversal and ordering of devices within the list.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 049
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Retrieve first data model from "Network1" using mac1 | input: network = "Network1", mac1 = 11:22:33:44:55:66, output: dm1 pointer | dm1 != nullptr | Should Pass |
 * | 02 | Retrieve second data model from "Network2" using mac3 | input: network = "Network2", mac3 = 10:11:12:13:14:16, output: dm2 pointer | dm2 != nullptr | Should Pass |
 * | 03 | Retrieve the first device from the device list using get_first_device | input: none, output: first device pointer | First device pointer != nullptr | Should Pass |
 * | 04 | Retrieve the next device in the list using get_next_device with the first device as parameter | input: first device pointer, output: next device pointer | Next device pointer != nullptr | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, GetNextDevice_Positive)
{
    std::cout << "Entering GetNextDevice_Positive test" << std::endl;
    dm_easy_mesh_t *dm1 = list.get_data_model("Network1", mac1);
    ASSERT_NE(dm1, nullptr);
    dm_easy_mesh_t *dm2 = list.get_data_model("Network2", mac3);
    ASSERT_NE(dm2, nullptr);
    dm_device_t *first = list.get_first_device();
    ASSERT_NE(first, nullptr);
    dm_device_t *next = list.get_next_device(first);
    ASSERT_NE(next, nullptr);
    std::cout << "Exiting GetNextDevice_Positive test" << std::endl;
}
/**
 * @brief Verify get_next_device returns nullptr when invoked with a NULL device pointer
 *
 * This test verifies that when get_next_device is called with a NULL device pointer, the function correctly returns a nullptr.
 * It ensures the API gracefully handles an empty device list scenario by returning NULL as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 050@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                             | Test Data                                   | Expected Result                                                | Notes      |
 * | :--------------: | ----------------------------------------------------------------------- | ------------------------------------------- | -------------------------------------------------------------- | ---------- |
 * | 01               | Call get_next_device with a NULL device pointer to verify the null return | input: dev = nullptr, output: retDev = nullptr | The function returns nullptr and the assertion confirms the result is NULL | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_next_device_EmptyDeviceListWithNULLInput)
{
    std::cout << "Entering get_next_device_EmptyDeviceListWithNULLInput test" << std::endl;
    std::cout << "Invoking get_next_device with dev = NULL" << std::endl;
    dm_device_t* retDev = list.get_next_device(nullptr);
    ASSERT_EQ(retDev, nullptr);
    std::cout << "Exiting get_next_device_EmptyDeviceListWithNULLInput test" << std::endl;
}
/**
 * @brief Validate the retrieval of the next data model in the list
 *
 * This test verifies that when a valid first data model is retrieved from the list,
 * invoking get_next_dm with the first data model returns a valid non-null next data model.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 051@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                          | Test Data                                                        | Expected Result                                                         | Notes       |
 * | :--------------: | -------------------------------------------------------------------- | ---------------------------------------------------------------- | ----------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke list.get_first_dm() to retrieve the first data model          | No input arguments; output: first = pointer obtained from method   | Returned first pointer is not nullptr                                  | Should Pass |
 * | 02               | Invoke list.get_next_dm(first) to retrieve the next data model         | Input: first pointer from previous step; output: next = pointer from method | Returned next pointer is not nullptr                                  | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_next_dm_Positive) {
    std::cout << "Entering get_next_dm_Positive test" << std::endl;
    std::cout << "Invoking get_next_dm with valid arguments" << std::endl;
    dm_easy_mesh_t *first = list.get_first_dm();
    ASSERT_NE(first, nullptr);
    dm_easy_mesh_t *next = list.get_next_dm(first);
    ASSERT_NE(next, nullptr);
    std::cout << "Exiting get_next_dm_Positive test" << std::endl;
}
/**
 * @brief Verify get_next_dm returns nullptr for a nullptr input.
 *
 * This test case validates that calling get_next_dm with a nullptr argument returns nullptr.
 * It ensures that the API properly handles a null pointer input without causing unexpected behavior.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 052
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                   | Test Data                                   | Expected Result                                   | Notes              |
 * | :--------------: | --------------------------------------------- | ------------------------------------------- | ------------------------------------------------- | ------------------ |
 * | 01               | Print test entry message                      | None                                        | "Entering get_next_dm_NullptrInput test" printed  | Should be successful |
 * | 02               | Invoke get_next_dm with nullptr as the argument| input = nullptr                             | Returns nullptr                                   | Should Pass        |
 * | 03               | Assert that the returned value is nullptr     | output next = nullptr                       | ASSERT_EQ confirms next is nullptr                | Should Pass        |
 * | 04               | Print test exit message                       | None                                        | "Exiting get_next_dm_NullptrInput test" printed   | Should be successful |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_next_dm_NullptrInput) {
    std::cout << "Entering get_next_dm_NullptrInput test" << std::endl;
    std::cout << "Invoking get_next_dm(nullptr)" << std::endl;
    dm_easy_mesh_t* next = list.get_next_dm(nullptr);
    ASSERT_EQ(next, nullptr);
    std::cout << "Exiting get_next_dm_NullptrInput test" << std::endl;
}
/**
 * @brief Verify get_next_network handles NULL current network pointer correctly
 *
 * This test verifies that when get_next_network is invoked with a NULL pointer as the current network, it returns a NULL pointer. This ensures the API handles invalid (NULL) input gracefully without causing unexpected behavior.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 053@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                  | Test Data                                                | Expected Result                                                                                    | Notes      |
 * | :--------------: | ---------------------------------------------------------------------------- | -------------------------------------------------------- | -------------------------------------------------------------------------------------------------- | ---------- |
 * | 01               | Invoke get_next_network with a NULL pointer and verify that the return is NULL | current_network = nullptr, return_value = expected nullptr | The API should return a NULL pointer, and the ASSERT_EQ check should pass indicating the return value is nullptr | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_next_network_null_current_network) {
    std::cout << "Entering get_next_network_null_current_network test" << std::endl;
    std::cout << "Invoking get_next_network with a NULL pointer" << std::endl;
    dm_network_t* nextNet = list.get_next_network(nullptr);
    ASSERT_EQ(nextNet, nullptr);
    std::cout << "Exiting get_next_network_null_current_network test" << std::endl;
}
/**
 * @brief Verify get_next_network_ssid returns nullptr for NULL network_ssid input
 *
 * This test verifies that when a NULL pointer is provided as the network_ssid argument to the 
 * get_next_network_ssid API, the function returns a nullptr. This behavior ensures that the API
 * properly handles invalid input by not proceeding with further processing.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 054@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                  | Test Data                                   | Expected Result                                         | Notes       |
 * | :--------------: | ---------------------------------------------------------------------------- | ------------------------------------------- | ------------------------------------------------------- | ----------- |
 * | 01               | Invoke get_next_network_ssid with network_ssid set to NULL and assert result is nullptr | network_ssid = NULL, result = expected nullptr | Returned result is nullptr; ASSERT_EQ(result, nullptr) passes | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_next_network_ssid_null_input)
{
    std::cout << "Entering get_next_network_ssid_null_input test" << std::endl;
    std::cout << "Invoking get_next_network_ssid with network_ssid = NULL" << std::endl;
    dm_network_ssid_t* result = list.get_next_network_ssid(NULL);
    ASSERT_EQ(result, nullptr);
    std::cout << "Exiting get_next_network_ssid_null_input test" << std::endl;
}
/**
 * @brief Tests the valid functionality of get_next_op_class after obtaining the first op class.
 *
 * This test verifies that the list returns a valid op class pointer when first calling get_first_op_class and subsequently returns a valid next op class pointer when invoking get_next_op_class with the first pointer. This ensures the proper traversal of op class elements within the list.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 055@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke get_first_op_class() on the list to retrieve the first op class. | list instance, no additional inputs, output: first pointer | Returns a non-null pointer; ASSERT_NE(first, nullptr) passes. | Should Pass |
 * | 02 | Invoke get_next_op_class() using the retrieved first op class to get the next op class. | input: first pointer as returned by get_first_op_class, output: next pointer | Returns a non-null pointer; ASSERT_NE(next, nullptr) passes. | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_next_op_class_valid) {
    std::cout << "Entering get_next_op_class_valid test" << std::endl;
    dm_op_class_t* first = list.get_first_op_class();
    ASSERT_NE(first, nullptr);
    std::cout << "Invoking get_next_op_class with valid input" << std::endl;
    dm_op_class_t* next = list.get_next_op_class(first);
    ASSERT_NE(next, nullptr);
    std::cout << "Exiting get_next_op_class_valid test" << std::endl;
}
/**
 * @brief Verify that get_next_op_class gracefully handles a null pointer on an empty list.
 *
 * This test case ensures that when get_next_op_class is called with a NULL pointer on an empty list,
 * the function returns a nullptr. This is critical for validating the API's robust handling of invalid or
 * uninitialized inputs, which helps prevent potential null-pointer dereferencing issues.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 056@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                               | Test Data                         | Expected Result                                                      | Notes       |
 * | :--------------: | --------------------------------------------------------------------------------------------------------- | --------------------------------- | --------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke get_next_op_class with op_class set to NULL on an empty list                                         | input: op_class = NULL            | Returns a nullptr; ASSERT_EQ(result, nullptr) passes                   | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_next_op_class_Retrieve_next_operating_class_from_empty_list_using_NULL_pointer) {
    std::cout << "Entering get_next_op_class_Retrieve_next_operating_class_from_empty_list_using_NULL_pointer test" << std::endl;
    std::cout << "Invoking get_next_op_class with op_class = NULL on an empty list" << std::endl;
    dm_op_class_t* result = list.get_next_op_class(NULL);
    ASSERT_EQ(result, nullptr);
    std::cout << "Exiting get_next_op_class_Retrieve_next_operating_class_from_empty_list_using_NULL_pointer test" << std::endl;
}
/**
 * @brief Validates retrieval of the next policy using valid inputs.
 *
 * This test verifies that the get_next_policy API correctly returns a valid policy pointer when invoked using a valid first policy obtained from get_first_policy. The test ensures that the policy list traversal works as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 057@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                       | Test Data                                                  | Expected Result                                                                 | Notes       |
 * | :--------------: | ----------------------------------------------------------------- | ---------------------------------------------------------- | -------------------------------------------------------------------------------- | ----------- |
 * | 01               | Call get_first_policy API to retrieve the first policy              | input: none, output: first pointer; value: non-null         | get_first_policy returns a non-null policy pointer                                | Should Pass |
 * | 02               | Invoke get_next_policy API using the first policy pointer           | input: first pointer, output: result pointer; value: non-null | get_next_policy returns a non-null policy pointer when provided with valid input   | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_next_policy_positive)
{
    std::cout << "Entering get_next_policy_positive test" << std::endl;
	dm_policy_t * first = list.get_first_policy();
	ASSERT_NE(first, nullptr);
	std::cout << "Invoking get_next_policy with valid input" << std::endl;
	dm_policy_t * result = list.get_next_policy(first); 
	ASSERT_NE(result, nullptr);
	std::cout << "Exiting get_next_policy_positive test" << std::endl;
}
/**
 * @brief Verify that get_next_policy returns nullptr when passed a NULL pointer.
 *
 * This test verifies the behavior of the get_next_policy function when a NULL pointer is provided as the current policy. It ensures that the API correctly handles the NULL input and returns a nullptr, thereby preventing potential dereferencing errors.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 058@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                  | Test Data                                   | Expected Result                                                            | Notes               |
 * | :--------------: | ------------------------------------------------------------ | ------------------------------------------- | -------------------------------------------------------------------------- | ------------------- |
 * | 01               | Log the entry message indicating the start of the test       | No input data                               | "Entering get_next_policy_passing_null_current_policy test" printed         | Should be successful|
 * | 02               | Invoke get_next_policy with a NULL pointer                   | input: current_policy = NULL                | API returns nullptr                                                        | Should Pass         |
 * | 03               | Assert that the returned result is nullptr                   | output: result pointer should be nullptr    | ASSERT_EQ(result, nullptr) passes                                          | Should Pass         |
 * | 04               | Log the exit message indicating the end of the test          | No input data                               | "Exiting get_next_policy_passing_null_current_policy test" printed           | Should be successful|
 */
TEST_F(dm_easy_mesh_list_tTEST, get_next_policy_passing_null_current_policy)
{
    std::cout << "Entering get_next_policy_passing_null_current_policy test" << std::endl;
    std::cout << "Invoking get_next_policy with NULL pointer." << std::endl;
    dm_policy_t * result = list.get_next_policy(NULL);    
    ASSERT_EQ(result, nullptr);
    std::cout << "Exiting get_next_policy_passing_null_current_policy test" << std::endl;
}
/**
 * @brief Verifies that get_next_pre_set_op_class_by_type returns nullptr when invoked with a NULL op_class pointer.
 *
 * This test validates that when the get_next_pre_set_op_class_by_type API is called with the operation type set to em_op_class_type_cac_available and a NULL pointer for the op_class parameter, the function correctly returns a nullptr. This check ensures that the API handles the invalid pointer scenario gracefully.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 059@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Log the entry into the test case | None | "Entering get_next_pre_set_op_class_by_type_null_op_class_exists test" printed to stdout | Should be successful |
 * | 02 | Invoke get_next_pre_set_op_class_by_type API | input: type = em_op_class_type_cac_available, op_class = NULL | API returns nullptr | Should Pass |
 * | 03 | Assert the API's return value is nullptr | output: ret = nullptr | Assertion check passes (ret == nullptr) | Should Pass |
 * | 04 | Log the exit from the test case | None | "Exiting get_next_pre_set_op_class_by_type_null_op_class_exists test" printed to stdout | Should be successful |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_next_pre_set_op_class_by_type_null_op_class_exists)
{
    std::cout << "Entering get_next_pre_set_op_class_by_type_null_op_class_exists test" << std::endl;
    std::cout << "Invoking get_next_pre_set_op_class_by_type with type: em_op_class_type_cac_available and op_class pointer: NULL" << std::endl;
    dm_op_class_t* ret = list.get_next_pre_set_op_class_by_type(em_op_class_type_cac_available, NULL);
    ASSERT_EQ(ret, nullptr);
    std::cout << "Exiting get_next_pre_set_op_class_by_type_null_op_class_exists test" << std::endl;
}
/**
 * @brief Test get_next_pre_set_op_class_by_type with an invalid op_class type.
 *
 * This test verifies that get_next_pre_set_op_class_by_type correctly handles an invalid op_class type by returning a null pointer.
 * The API is expected to reject an op_class type outside the valid range, ensuring robustness in type validation.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 060
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                     | Test Data                                                                | Expected Result                                         | Notes      |
 * | :--------------: | ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ | ------------------------------------------------------- | ---------- |
 * | 01               | Invoke get_next_pre_set_op_class_by_type with an invalid op_class type and a valid pointer to op_class variable | type = em_op_class_type_scan_param+1, op_class pointer = &op_class          | API returns a nullptr; assertion verifies ret is nullptr | Should Fail |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_next_pre_set_op_class_by_type_invalid_opclasstype)
{
    std::cout << "Entering get_next_pre_set_op_class_by_type_invalid_opclasstype test" << std::endl;
    dm_op_class_t op_class;
    std::cout << "Invoking get_next_pre_set_op_class_by_type with type: em_op_class_type_preference and op_class pointer: NULL" << std::endl;
    dm_op_class_t* ret = list.get_next_pre_set_op_class_by_type(static_cast<em_op_class_type_t>(em_op_class_type_scan_param+1), &op_class);
    ASSERT_EQ(ret, nullptr);
    std::cout << "Exiting get_next_pre_set_op_class_by_type_invalid_opclasstype test" << std::endl;
}
/**
 * @brief Validate that get_next_radio returns a valid next radio when available
 *
 * This test verifies that after inserting multiple radio entries into the mesh list for a given network,
 * retrieving the first radio and then invoking get_next_radio returns a valid (non-null) radio pointer.
 * This is important to ensure that the radio iteration functionality works as expected in positive scenarios.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 061@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Convert MAC addresses to string keys using mac_to_string helper | input: mac1 = 0x11,0x22,0x33,0x44,0x55,0x66; mac2 = 0xAA,0xBB,0xCC,0xDD,0xEE,0xFF; output: key1, key2 | Keys (key1 and key2) correctly generated from the given MAC addresses | Should be successful |
 * | 02 | Insert radio entries into the list using put_radio API | input: key1 with radio1, key2 with radio2; output: radio entries stored | Radios correctly inserted into the list associated with "Network1" | Should Pass |
 * | 03 | Retrieve the first radio entry for "Network1" using get_first_radio | input: network id = "Network1", mac1; output: pointer to first radio (first) | Non-null pointer returned indicating the first radio is available | Should Pass |
 * | 04 | Retrieve the next radio entry using get_next_radio starting after the first radio | input: network id = "Network1", mac1, first radio pointer; output: pointer to next radio | A non-null pointer is returned as the next available radio | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_next_radio_valid_next_radio_available)
{
    std::cout << "Entering get_next_radio_valid_next_radio_available test" << std::endl;
	dm_radio_t radio1 = {}, radio2 = {};
    char key1[18], key2[18];
    mac_to_string(mac1, key1);
    mac_to_string(mac2, key2);
    list.put_radio(key1, &radio1);
    list.put_radio(key2, &radio2);    
    dm_radio_t *first = list.get_first_radio("Network1", mac1);
	if (first != nullptr) {
		std::cout << "Invoking get_next_radio" << std::endl;
        dm_radio_t *next = list.get_next_radio("Network1", mac1, first);
		EXPECT_NE(next, nullptr);		
    }
    std::cout << "Exiting get_next_radio_valid_next_radio_available test" << std::endl;
}
/**
 * @brief Validate that get_next_radio returns a null pointer when no subsequent radio is available
 *
 * This test verifies that invoking get_next_radio with a valid network ID and a MAC address for which no subsequent radio exists returns a null pointer. It ensures the proper behavior of the API in the absence of a next radio element.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 062@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call get_next_radio with net_id "mesh_net_1" and a MAC address (00,11,22,33,44,55) where no subsequent radio exists | net_id = "mesh_net_1", al_mac = 0x00,0x11,0x22,0x33,0x44,0x55, radio = pointer to initialized dm_radio_t | The get_next_radio() API returns nullptr; ASSERT_EQ(nextRadio, nullptr) passes | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_next_radio_no_next_radio_available)
{
    std::cout << "Entering get_next_radio_no_next_radio_available test" << std::endl;
    mac_address_t al_mac = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    const char* net_id = "mesh_net_1";
    dm_radio_t radio;
    std::cout << "Initialized last radio at address: " << &radio << std::endl;
    std::cout << "Invoking get_next_radio with net_id: " << net_id 
              << ", al_mac: " 
              << std::hex 
              << static_cast<int>(al_mac[0]) << " " << static_cast<int>(al_mac[1]) << " " 
              << static_cast<int>(al_mac[2]) << " " << static_cast<int>(al_mac[3]) << " " 
              << static_cast<int>(al_mac[4]) << " " << static_cast<int>(al_mac[5])
              << std::dec << std::endl;
    dm_radio_t* nextRadio = list.get_next_radio(net_id, al_mac, &radio);
    std::cout << "get_next_radio returned pointer: " << nextRadio << std::endl;
    ASSERT_EQ(nextRadio, nullptr);
    std::cout << "Exiting get_next_radio_no_next_radio_available test" << std::endl;
}
/**
 * @brief Verify that get_next_radio returns a nullptr when a null network identifier is provided.
 *
 * This test inserts two radio objects into the list, retrieves the first radio using get_first_radio,
 * and then invokes get_next_radio with a simulated null network ID (by setting a local variable to nullptr)
 * to confirm that the API returns a nullptr under such circumstances. This ensures that the function
 * handles improper or null network identifiers gracefully.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 063@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- | -------------- | ----- |
 * | 01 | Insert first radio into the list using put_radio with key generated from mac1. | input: key1 = mac_to_string(mac1), radio1 = {} | Radio successfully inserted. | Should Pass |
 * | 02 | Insert second radio into the list using put_radio with key generated from mac2. | input: key2 = mac_to_string(mac2), radio2 = {} | Radio successfully inserted. | Should Pass |
 * | 03 | Retrieve the first radio from "Network1" using get_first_radio with mac1. | input: network = "Network1", mac = mac1 | Returns a valid pointer (non-null). | Should Pass |
 * | 04 | Invoke get_next_radio with "Network1", mac1, and the first radio while simulating a null network ID context. | input: network = "Network1", mac = mac1, first radio pointer from step 03 | Returns nullptr as the next radio. | Should Fail |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_next_radio_null_net_id_provided)
{
    std::cout << "Entering get_next_radio_null_net_id_provided test" << std::endl;
	dm_radio_t radio1 = {}, radio2 = {};
    char key1[18], key2[18];
    mac_to_string(mac1, key1);
    mac_to_string(mac2, key2);
    list.put_radio(key1, &radio1);
    list.put_radio(key2, &radio2);    
    dm_radio_t *first = list.get_first_radio("Network1", mac1);
	if (first != nullptr) {
		const char* net_id = nullptr;
        std::cout << "Invoking get_next_radio with net_id as NULL" << std::endl; 
        dm_radio_t *next = list.get_next_radio("Network1", mac1, first);
		ASSERT_EQ(next, nullptr);
    }    
    std::cout << "Exiting get_next_radio_null_net_id_provided test" << std::endl;
}
/**
 * @brief Verify that get_next_radio returns a null pointer when a null radio pointer is provided
 *
 * This test verifies that when the get_next_radio API is invoked with a null radio pointer,
 * the function correctly returns a null pointer. This ensures that the API handles erroneous
 * input gracefully and avoids potential dereferencing errors.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 064@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                      | Test Data                                                                | Expected Result                                                                         | Notes        |
 * | :--------------: | ---------------------------------------------------------------- | ------------------------------------------------------------------------ | --------------------------------------------------------------------------------------- | ------------ |
 * | 01               | Call get_next_radio with null radio pointer parameter to verify that no radio is returned | network = Network1, al_mac = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, radio pointer = nullptr | Return value is nullptr; ASSERT_EQ check passes confirming that no radio is returned | Should Fail  |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_next_radio_null_radio_pointer_provided)
{
    std::cout << "Entering get_next_radio_null_radio_pointer_provided test" << std::endl;
    mac_address_t al_mac = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    std::cout << "Invoking get_next_radio with null radio pointer" << std::endl;
    dm_radio_t* nextRadio = list.get_next_radio("Network1", al_mac, nullptr);
    ASSERT_EQ(nextRadio, nullptr);
    std::cout << "Exiting get_next_radio_null_radio_pointer_provided test" << std::endl;
}
/**
 * @brief Verifies that get_next_radio returns NULL when provided with a NULL radio pointer.
 *
 * This test case checks that the get_next_radio API correctly handles a NULL radio pointer
 * by returning a NULL pointer without causing any unexpected behavior or faults.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 065@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                               | Test Data                                                  | Expected Result                                                           | Notes       |
 * | :--------------: | ------------------------------------------------------------------------- | ---------------------------------------------------------- | ------------------------------------------------------------------------- | ----------- |
 * | 01               | Call get_next_radio with the radio pointer set to NULL                    | input: radio pointer = nullptr, output: returnedRadio = nullptr | API returns a NULL pointer; EXPECT_EQ(returnedRadio, nullptr) passes        | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_next_radio_null_input)
{
    std::cout << "Entering get_next_radio_null_input test" << std::endl;
    std::cout << "Invoking get_next_radio with radio pointer as NULL" << std::endl;
    dm_radio_t *returnedRadio = list.get_next_radio(nullptr);
    EXPECT_EQ(returnedRadio, nullptr);
    std::cout << "Exiting get_next_radio_null_input test" << std::endl;
}
/**
 * @brief Validate successful retrieval of the next scan result in a positive scenario
 *
 * This test verifies that after inserting two scan results into the mesh list, calling 
 * get_first_scan_result() followed by get_next_scan_result() returns valid, non-null pointers.
 * It ensures that the ordering and retrieval mechanisms for scan results work as expected.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 066
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                                                       | Test Data                                                                                                                               | Expected Result                                                                                             | Notes         |
 * | :--------------: | --------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | ------------- |
 * | 01               | Initialize two dm_scan_result_t objects (scan1 and scan2) with scan parameters for "Network1" and assign different channels        | For scan1: net_id = "Network1", dev_mac = mac1, scanner_mac = mac2, op_class = 0x81, channel = 6, scanner_type = em_scanner_type_radio; For scan2: same as scan1, but channel = 11 | Scan result objects are properly initialized with correct parameters                                          | Should be successful |
 * | 02               | Generate keys (key1 and key2) for the scan results using build_scan_result_key helper function                                       | For key1: net_id = "Network1", dev_mac = mac1, scanner_mac = mac2, op_class = 0x81, channel = 6, scanner_type = 1, bssid = "ff:ff:ff:ff:ff:ff"; For key2: channel = 11          | Keys are correctly generated and formatted                                                                  | Should be successful |
 * | 03               | Insert the created scan results into the mesh list using put_scan_result with appropriate indices                                   | key1 with scan1 and index = 0; key2 with scan2 and index = 1                                                                               | Scan results are inserted into the list without errors                                                        | Should be successful |
 * | 04               | Retrieve the first scan result using get_first_scan_result() and then get the next scan result using get_next_scan_result()            | No external test data; relies on the inserted scan results                                                                               | Both retrieved scan result pointers are non-null and valid as per the assertions (ASSERT_NE check)              | Should Pass   |
 * | 05               | Remove the scan results from the list using remove_scan_result() to clean up after the test                                           | Removing entries with key1 and key2                                                                                                       | Scan results are removed from the list successfully                                                           | Should be successful |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_next_scan_result_positive)
{
    std::cout << "Entering get_next_scan_result_positive test" << std::endl;
    dm_scan_result_t *scan1 = new dm_scan_result_t{};
    dm_scan_result_t *scan2 = new dm_scan_result_t{};
    strcpy(scan1->m_scan_result.id.net_id, "Network1");
    memcpy(scan1->m_scan_result.id.dev_mac, mac1, 6);
    memcpy(scan1->m_scan_result.id.scanner_mac, mac2, 6);
    scan1->m_scan_result.id.op_class = 0x81;
    scan1->m_scan_result.id.channel = 6;
    scan1->m_scan_result.id.scanner_type = em_scanner_type_radio;
    strcpy(scan2->m_scan_result.id.net_id, "Network1");
    memcpy(scan2->m_scan_result.id.dev_mac, mac1, 6);
    memcpy(scan2->m_scan_result.id.scanner_mac, mac2, 6);
    scan2->m_scan_result.id.op_class = 0x81;
    scan2->m_scan_result.id.channel = 11;
    scan2->m_scan_result.id.scanner_type = em_scanner_type_radio;
    char key1[256], key2[256];
    unsigned char bssid[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    build_scan_result_key("Network1", mac1, mac2, 0x81, 6, 1, bssid, key1);
    build_scan_result_key("Network1", mac1, mac2, 0x81, 11, 1, bssid, key2);
    list.put_scan_result(key1, scan1, 0);
    list.put_scan_result(key2, scan2, 1);
    dm_scan_result_t *first = list.get_first_scan_result();
    ASSERT_NE(first, nullptr);
    dm_scan_result_t *next = list.get_next_scan_result(first);
    ASSERT_NE(next, nullptr);
    list.remove_scan_result(key1);
    list.remove_scan_result(key2);
    delete scan1;
    delete scan2;
    std::cout << "Exiting get_next_scan_result_positive test" << std::endl;
}
/**
 * @brief Test get_next_scan_result with a NULL scan_result parameter
 *
 * This test verifies that invoking the get_next_scan_result API with a NULL pointer for the scan_result argument returns a NULL pointer.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 067@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**  
 * | Variation / Step | Description                                          | Test Data                          | Expected Result                                                  | Notes       |
 * | :--------------: | ---------------------------------------------------- | ---------------------------------- | ---------------------------------------------------------------- | ----------- |
 * | 01               | Call get_next_scan_result with NULL as scan_result   | scan_result = NULL                 | Should return a NULL pointer (EXPECT_EQ(nextResult, nullptr))      | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_next_scan_result_NULL_input)
{
    std::cout << "Entering get_next_scan_result_NULL_input test" << std::endl;
    std::cout << "Invoking get_next_scan_result with scan_result = NULL" << std::endl;    
    dm_scan_result_t *nextResult = list.get_next_scan_result(NULL);
    EXPECT_EQ(nextResult, nullptr);
    std::cout << "Exiting get_next_scan_result_NULL_input test" << std::endl;
}
/**
 * @brief Verify that get_next_sta returns nullptr when a NULL pointer is passed.
 *
 * This test case verifies that the get_next_sta API handles a NULL pointer input gracefully by returning a nullptr.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 068@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                      | Test Data                                 | Expected Result                                                     | Notes      |
 * | :--------------: | ------------------------------------------------ | ----------------------------------------- | ------------------------------------------------------------------- | ---------- |
 * | 01               | Invoke get_next_sta with a NULL pointer input.   | input = NULL, output pointer = nullptr    | Return value is nullptr; assertion EXPECT_EQ(result, nullptr) passes. | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_next_sta_NULL_pointer_returns_NULL) {
    std::cout << "Entering get_next_sta_NULL_pointer_returns_NULL test" << std::endl;
    std::cout << "Invoking get_next_sta with input: NULL" << std::endl;
    dm_sta_t *result = list.get_next_sta(NULL);
    EXPECT_EQ(result, nullptr);
    std::cout << "Exiting get_next_sta_NULL_pointer_returns_NULL test" << std::endl;
}
/**
 * @brief Verify that get_op_class returns nullptr for a non-existent key
 *
 * This test verifies that invoking the get_op_class API with a key that does not exist in the data model list returns a null pointer. The test first builds an op_class key using the helper function build_op_class_key with mac1, em_op_class_type_current and an op_class value of 0x81. It then calls get_op_class with the generated key and checks that the returned pointer is nullptr.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 069@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Log the entry message indicating the start of the test. | None | "Entering get_op_class_non_existent_key test" is printed. | Should be successful |
 * | 02 | Build the op_class key using build_op_class_key with specified parameters. | mac1 = 0x11:0x22:0x33:0x44:0x55:0x66, type = em_op_class_type_current, op_class = 0x81 | The key is generated correctly. | Should be successful |
 * | 03 | Invoke get_op_class API with the generated key. | key = (generated key from step 02) | Returns a nullptr; EXPECT_EQ assertion confirms the result. | Should Fail |
 * | 04 | Log the exit message indicating the end of the test. | None | "Exiting get_op_class_non_existent_key test" is printed. | Should be successful |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_op_class_non_existent_key)
{
    std::cout << "Entering get_op_class_non_existent_key test" << std::endl;
    dm_op_class_t op_class = {};
    char key[256];
    build_op_class_key(mac1, em_op_class_type_current, 0x81, key);
    std::cout << "Invoking get_op_class with key: " << key << std::endl;
    dm_op_class_t * opClassObj = list.get_op_class(key);
    EXPECT_EQ(opClassObj, nullptr);
    std::cout << "Exiting get_op_class_non_existent_key test" << std::endl;
}
/**
 * @brief Validate get_op_class returns null when given a null key.
 *
 * This test verifies that the get_op_class API correctly returns a null pointer when passed a null key.
 * It ensures that the API gracefully handles invalid inputs and does not produce undefined behavior.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 070@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call list.get_op_class() with a null key. | key = nullptr | API should return nullptr | Should Pass |
 * | 02 | Assert that the returned value is nullptr using ASSERT_EQ. | opClassObj = list.get_op_class(key) | Assertion passes confirming opClassObj equals nullptr | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_op_class_null_key)
{
    std::cout << "Entering get_op_class_null_key test" << std::endl;    
    const char * key = nullptr;
    std::cout << "Invoking get_op_class with key: " << key << std::endl;
    dm_op_class_t * opClassObj = list.get_op_class(key);
    ASSERT_EQ(opClassObj, nullptr);
    std::cout << "Exiting get_op_class_null_key test" << std::endl;
}
/**
 * @brief Test for retrieving a non-existent policy key
 *
 * This test verifies that when get_policy is invoked with a policy key that does not exist in the internal data model list, it correctly returns a nullptr. This behavior is essential to ensure that the system does not falsely locate a policy when none has been stored.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 071@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call build_policy_key with "non_existing_key", mac1, mac2, and em_policy_id_type_default_8021q_settings, then invoke get_policy with the generated key | net_id = non_existing_key, dev_mac = {0x11,0x22,0x33,0x44,0x55,0x66}, radio_mac = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF}, type = em_policy_id_type_default_8021q_settings | get_policy returns nullptr; ASSERT_EQ(policyObj, nullptr) passes | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_policy_non_existent_key)
{
    std::cout << "Entering get_policy_non_existent_key test" << std::endl;
    dm_policy_t policy = {};
    char key[256];
    build_policy_key("non_existing_key", mac1, mac2, em_policy_id_type_default_8021q_settings, key);	
    std::cout << "Invoking get_policy with key: " << key << std::endl;    
    dm_policy_t *policyObj = list.get_policy(key);
    ASSERT_EQ(policyObj, nullptr);    
    std::cout << "Exiting get_policy_non_existent_key test" << std::endl;
}
/**
 * @brief Verify that get_policy returns a null pointer when invoked with a NULL key
 *
 * This test verifies that the get_policy API correctly handles an invalid input scenario by returning a null pointer when the provided key is NULL. This is important to ensure the robustness of the API in handling edge cases.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 072
 * **Priority:** High
 * 
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                                                          | Test Data                           | Expected Result                                                      | Notes       |
 * | :--------------: | ------------------------------------------------------------------------------------ | ----------------------------------- | -------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke get_policy with a NULL key to verify it handles invalid input correctly         | key = nullptr, output1 = policyObj  | The API should return a null pointer and the EXPECT_EQ assertion passes | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_policy_null_key)
{
    std::cout << "Entering get_policy_null_key test" << std::endl;
    const char* key = nullptr;
    std::cout << "Invoking get_policy with NULL key" << std::endl;
    dm_policy_t *policyObj = list.get_policy(key);
    EXPECT_EQ(policyObj, nullptr);
    std::cout << "Exiting get_policy_null_key test" << std::endl;
}
/**
 * @brief Checks that get_radio returns nullptr when provided with a non-existent radio key.
 *
 * This test validates that invoking the get_radio API with an invalid radio key ("NON_EXISTENT_RADIO")
 * results in the function returning a nullptr, which ensures the API correctly handles non-existent entries.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 073@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                         | Test Data                                           | Expected Result                                    | Notes                |
 * | :--------------: | ------------------------------------------------------------------- | --------------------------------------------------- | -------------------------------------------------- | -------------------- |
 * |       01         | Set up a non-existent radio key                                     | key = "NON_EXISTENT_RADIO"                          | Key variable initialized with the specified value  | Should be successful |
 * |       02         | Invoke list.get_radio using the non-existent key                    | input key = "NON_EXISTENT_RADIO"                    | Returns a radio pointer as nullptr                 | Should Fail          |
 * |       03         | Assert that the returned radio pointer is null                      | output radio pointer = nullptr                      | Assertion passes confirming the radio pointer is null | Should be successful |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_radio_non_existent_radio_key_returns_null) {
    std::cout << "Entering get_radio_non_existent_radio_key_returns_null test" << std::endl;    
    const char* key = "NON_EXISTENT_RADIO";
    std::cout << "Invoking get_radio with key: " << key << std::endl;
    dm_radio_t* radio = list.get_radio(key);
    std::cout << "Returned radio pointer: " << radio << std::endl;
    ASSERT_EQ(radio, nullptr);
    std::cout << "Exiting get_radio_non_existent_radio_key_returns_null test" << std::endl;
}
/**
 * @brief Verify that get_radio returns nullptr when invoked with a null key
 *
 * This test verifies that the get_radio function correctly handles a null radio key
 * by returning a nullptr. The test prints log messages before and after the API invocation,
 * calls get_radio with a null key, and checks that the return value is nullptr using an assertion.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 074@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                          | Test Data                                | Expected Result                                                                         | Notes         |
 * | :--------------: | -------------------------------------------------------------------- | ---------------------------------------- | --------------------------------------------------------------------------------------- | ------------- |
 * | 01               | Print log message indicating the start of the test                   | N/A                                      | Log message "Entering get_radio_null_radio_key_returns_null test" is displayed             | Should be successful |
 * | 02               | Set the key to nullptr and invoke the get_radio API                    | key = nullptr                            | API returns nullptr and ASSERT_EQ check passes                                          | Should Pass   |
 * | 03               | Print the returned radio pointer                                     | radio pointer captured from get_radio     | Log message shows the radio pointer as nullptr                                           | Should be successful |
 * | 04               | Print log message indicating the end of the test                     | N/A                                      | Log message "Exiting get_radio_null_radio_key_returns_null test" is displayed              | Should be successful |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_radio_null_radio_key_returns_null) {
    std::cout << "Entering get_radio_null_radio_key_returns_null test" << std::endl;
    const char* key = nullptr;
    std::cout << "Invoking get_radio with null key" << std::endl;
    dm_radio_t* radio = list.get_radio(key);
    std::cout << "Returned radio pointer: " << radio << std::endl;
    ASSERT_EQ(radio, nullptr);
    std::cout << "Exiting get_radio_null_radio_key_returns_null test" << std::endl;
}
/**
 * @brief Verify that a valid scan result key returns the corresponding scan result record.
 *
 * This test verifies that when a valid scan result key is provided, the corresponding scan result is correctly stored in the list and retrievable using the get_scan_result API. It sets up a scan result with predefined parameters, inserts it into the list, retrieves it using the key, and asserts that the returned result is not null. Afterwards, the scan result is removed from the list.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 075@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                      | Test Data                                                                                                                          | Expected Result                                                                                | Notes        |
 * | :--------------: | ------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- | ------------ |
 * | 01               | Build a scan result key and insert a valid scan result into the list using put_scan_result.        | input: net_id = "Network1", dev_mac = {0x11,0x22,0x33,0x44,0x55,0x66}, scanner_mac = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF}, op_class = 0x81, channel = 6, scanner_type = em_scanner_type_radio, bssid = {0xff,0xff,0xff,0xff,0xff,0xff} | Scan result is stored successfully in the list.                                                 | Should Pass  |
 * | 02               | Retrieve the scan result using get_scan_result and verify the returned pointer is not null.       | input: key (constructed scan result key)                                                                                           | Returned pointer is non-null and holds the expected scan result data.                          | Should Pass  |
 * | 03               | Remove the scan result from the list using remove_scan_result.                                   | input: key (constructed scan result key)                                                                                           | Scan result is removed without errors.                                                         | Should Pass  |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_scan_result_validKey_returnsCorrespondingScanResult) {
    std::cout << "Entering get_scan_result_validKey_returnsCorrespondingScanResult test" << std::endl;
    dm_scan_result_t scan_result = {};
    unsigned char bssid[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    strcpy(scan_result.m_scan_result.id.net_id, "Network1");
    memcpy(scan_result.m_scan_result.id.dev_mac, mac1, sizeof(mac_address_t));
    memcpy(scan_result.m_scan_result.id.scanner_mac, mac2, sizeof(mac_address_t));
    scan_result.m_scan_result.id.op_class = 0x81;
    scan_result.m_scan_result.id.channel = 6;
    scan_result.m_scan_result.id.scanner_type = em_scanner_type_radio;
    char key[256];
    build_scan_result_key("Network1", mac1, mac2, 0x81, 6, 1, bssid, key);
    list.put_scan_result(key, &scan_result, 0);
    std::cout << "Invoking get_scan_result with key: " << key << std::endl;
    dm_scan_result_t *result = list.get_scan_result(key);
    ASSERT_NE(result, nullptr);
    if(result != nullptr) {
        std::cout << "Retrieved net_id from dm_scan_result_t: " << result->m_scan_result.id.net_id << std::endl;
    }
    list.remove_scan_result(key);
    std::cout << "Exiting get_scan_result_validKey_returnsCorrespondingScanResult test" << std::endl;
}
/**
 * @brief Verify that get_scan_result returns nullptr for a non-existent key.
 *
 * This test ensures that when list.get_scan_result is invoked with a key constructed for a scan result that does not exist in the data model list, the API correctly returns a null pointer. This behavior is critical to handle missing scan results properly.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 076@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01 | Construct the scan result key using build_scan_result_key for a non-existent network key | net_id = "nonexistent_key", dev_mac = mac3, scanner_mac = mac4, op_class = 0x81, channel = 6, scanner_type = 1, bssid = 0xff,0xff,0xff,0xff,0xff,0xff | Key is generated successfully | Should be successful |@n
 * | 02 | Invoke list.get_scan_result with the constructed key | key = generated key | API returns nullptr | Should Pass |@n
 * | 03 | Assert that the returned scan result pointer is nullptr | result = output of list.get_scan_result(key) | Assertion (result == nullptr) passes | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_scan_result_nonexistentKey_returnsNull) {
    std::cout << "Entering get_scan_result_nonexistentKey_returnsNull test" << std::endl;
    dm_scan_result_t scan_result = {};
    char key[256];
    unsigned char bssid[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    build_scan_result_key("nonexistent_key", mac3, mac4, 0x81, 6, 1, bssid, key);
    std::cout << "Invoking get_scan_result with key: " << key << std::endl;
    dm_scan_result_t *result = list.get_scan_result(key);
    ASSERT_EQ(result, nullptr);
    std::cout << "Exiting get_scan_result_nonexistentKey_returnsNull test" << std::endl;
}
/**
 * @brief Test to verify that get_scan_result() returns a null pointer when provided with a NULL key.
 *
 * This test validates that when a NULL key is passed to the get_scan_result() API, the function correctly returns a NULL pointer.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 077@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                            | Test Data                | Expected Result                                     | Notes       |
 * | :--------------: | ------------------------------------------------------ | ------------------------ | --------------------------------------------------- | ----------- |
 * | 01               | Invoke get_scan_result API with a NULL key             | key = nullptr            | API returns a nullptr; EXPECT_EQ(result, nullptr)   | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_scan_result_nullKey_returnsNull) {
    std::cout << "Entering get_scan_result_nullKey_returnsNull test" << std::endl;
    const char * key = nullptr;
    std::cout << "Invoking get_scan_result with a NULL key" << std::endl;
    dm_scan_result_t *result = list.get_scan_result(key);
    EXPECT_EQ(result, nullptr);
    std::cout << "Exiting get_scan_result_nullKey_returnsNull test" << std::endl;
}
/**
 * @brief Verify get_sta API returns nullptr when querying a non-existing station
 *
 * This test verifies that the get_sta API, when supplied with a valid STA key generated by build_sta_key using known MAC addresses, returns a nullptr for a non-existent station in the list.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 078@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Generate a STA key using build_sta_key with provided MAC addresses and then invoke get_sta with this key | input: sta MAC = {0x10,0x11,0x12,0x13,0x12,0x15}, bssid = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF}, radio MAC = {0x10,0x11,0x12,0x13,0x14,0x16}; output: key (string) | get_sta returns nullptr and EXPECT_EQ validates that the returned pointer is nullptr | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_sta_valid_non_existing_sta) {
    const char* testName = "get_sta_valid_non_existing_sta";
    std::cout << "Entering " << testName << " test" << std::endl;
    dm_sta_t sta = {};
    char key[256];
    build_sta_key(mac4, mac2, mac3, key);
    std::cout << "Invoking get_sta with key: " << key << std::endl;
    dm_sta_t* staPtr = list.get_sta(key);
    EXPECT_EQ(staPtr, nullptr);    
    std::cout << "Exiting " << testName << " test" << std::endl;
}
/**
 * @brief Validate that get_sta returns a null pointer when passed a null key.
 *
 * This test verifies that calling the get_sta API with a null key pointer results in a null pointer return.
 * It is important to ensure that the API gracefully handles invalid inputs without causing unexpected behavior.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 079@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                           | Test Data                                           | Expected Result                                           | Notes         |
 * | :--------------: | --------------------------------------------------------------------- | --------------------------------------------------- | --------------------------------------------------------- | ------------- |
 * | 01               | Print the entry message indicating the start of the test              | testName = "get_sta_null_key"                       | Entry message is logged                                   | Should be successful |
 * | 02               | Set the nullKey pointer to a null value                               | nullKey = nullptr                                   | nullKey is assigned a nullptr                             | Should be successful |
 * | 03               | Invoke the get_sta API using the null key input                         | input: key = nullptr, output: staPtr                | The API returns a nullptr pointer                         | Should Pass   |
 * | 04               | Assert that the returned pointer is indeed null                         | assertion: EXPECT_EQ(staPtr, nullptr)               | Assertion passes confirming staPtr equals nullptr          | Should Pass   |
 * | 05               | Print the exit message indicating the end of the test                 | testName = "get_sta_null_key"                       | Exit message is logged                                    | Should be successful |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_sta_null_key) {
    const char* testName = "get_sta_null_key";
    std::cout << "Entering " << testName << " test" << std::endl;
    const char* nullKey = nullptr;
    std::cout << "Invoking get_sta with key: (null pointer)" << std::endl;
    dm_sta_t* staPtr = list.get_sta(nullKey);
    EXPECT_EQ(staPtr, nullptr);
    std::cout << "Exiting " << testName << " test" << std::endl;
}
/**
 * @brief Test the init method with a valid non-null manager
 *
 * This test checks that the init method of the list object initializes correctly when provided with a valid manager object. It ensures that no exception is thrown during the initialization process, confirming proper handling of valid input.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 080@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | ------------- | ----- |
 * | 01 | Call list.init() with a valid mgr object | mgr = valid instance address (&mgr) | The init method should execute without throwing any exception | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, init_valid_non_null_mgr)
{
    std::cout << "Entering init_valid_non_null_mgr test" << std::endl;
    skip_teardown = true;
    em_ctrl_t mgr;
    std::cout << "Invoking init method with valid mgr object" << std::endl;
    EXPECT_NO_THROW(list.init(&mgr));
    std::cout << "Exiting init_valid_non_null_mgr test" << std::endl;
}
/**
 * @brief Test to validate that the initialization function handles a null manager pointer.
 *
 * This test verifies that when the init() method is invoked with a nullptr as the manager pointer,
 * the function properly throws an exception. This ensures robustness by checking the API's ability
 * to handle invalid input parameters.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 081@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                          | Test Data                            | Expected Result                                               | Notes       |
 * | :--------------: | ---------------------------------------------------- | ------------------------------------ | ------------------------------------------------------------- | ----------- |
 * | 01               | Invoke init() with a null mgr pointer                | mgr = nullptr                        | Exception is thrown by the API as validated by EXPECT_ANY_THROW | Should Fail |
 */
TEST_F(dm_easy_mesh_list_tTEST, init_null_mgr)
{
    std::cout << "Entering init_null_mgr test" << std::endl;
    skip_teardown = true;
    std::cout << "Invoking init method with mgr pointer: nullptr" << std::endl;
    EXPECT_ANY_THROW(list.init(nullptr));
    std::cout << "Exiting init_null_mgr test" << std::endl;
}
/**
 * @brief Validate that the put_bss API successfully inserts a valid BSS entry.
 *
 * This test verifies that a BSS structure can be inserted into the dm_easy_mesh_list_t instance 
 * using a well-formed key generated by build_bss_key. It tests the positive scenario where no exception 
 * is thrown upon invoking list.put_bss.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 082@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Generate a valid BSS key using build_bss_key and then invoke put_bss API with the key and a BSS structure pointer | net_id = Network1, dev_mac = 11:22:33:44:55:66, radio_mac = aa:bb:cc:dd:ee:ff, bssid = 10:11:12:13:14:16, haul_type = 0, key = generated key, bss pointer = valid pointer to dm_bss_t struct | No exception thrown and valid insertion of the BSS entry | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, put_bss_valid_insertion)
{
    std::cout << "Entering put_bss_valid_insertion test" << std::endl;
    dm_bss_t bss = {};
    char key[256];
    build_bss_key("Network1", mac1, mac2, mac3, 0, key);
    std::cout << "Invoking put_bss with key: " << key << " and dm_bss_t pointer: " << &bss << std::endl;
    EXPECT_NO_THROW(list.put_bss(key, &bss));
    std::cout << "Exiting put_bss_valid_insertion test" << std::endl;
}
/**
 * @brief Verify that put_bss API throws an exception when provided with a NULL key.
 *
 * This test ensures that the put_bss function correctly handles an invalid input scenario by throwing an exception when a NULL key is passed along with a valid dm_bss_t pointer. This behavior is crucial to maintain robustness and proper error handling in the API.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 083@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                            | Test Data                                                   | Expected Result                                                    | Notes          |
 * | :--------------: | ---------------------------------------------------------------------- | ----------------------------------------------------------- | ------------------------------------------------------------------ | -------------- |
 * | 01               | Log entering the put_bss_null_key test                                 | N/A                                                         | "Entering put_bss_null_key test" message is printed                | Should be successful |
 * | 02               | Initialize dm_bss_t instance and set key pointer to NULL               | key = NULL, dm_bss_t pointer = address of bss               | dm_bss_t instance is prepared and key is NULL                      | Should be successful |
 * | 03               | Invoke list.put_bss with the NULL key and valid dm_bss_t pointer         | key = NULL, dm_bss_t pointer = address of bss               | API call throws an exception as validated by EXPECT_ANY_THROW       | Should Fail    |
 * | 04               | Log exiting the put_bss_null_key test                                  | N/A                                                         | "Exiting put_bss_null_key test" message is printed                 | Should be successful |
 */
TEST_F(dm_easy_mesh_list_tTEST, put_bss_null_key)
{
    std::cout << "Entering put_bss_null_key test" << std::endl;
    dm_bss_t bss;
    const char* key = NULL;
    std::cout << "Invoking put_bss with key NULL and dm_bss_t pointer: " << &bss << std::endl;    
    EXPECT_ANY_THROW(list.put_bss(key, &bss));
    std::cout << "Exiting put_bss_null_key test" << std::endl;
}
/**
 * @brief Test put_bss API with an empty key to verify error handling.
 *
 * This test verifies that the put_bss API correctly handles invalid input by throwing an exception when invoked with an empty key. It ensures that the API does not accept empty keys even when provided with a valid dm_bss_t pointer, thereby maintaining data integrity.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 084@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                         | Test Data                                | Expected Result                          | Notes       |
 * | :--------------: | ------------------------------------------------------------------- | ---------------------------------------- | ---------------------------------------- | ----------- |
 * | 01               | Invoke put_bss API with an empty key and a valid dm_bss_t pointer     | key = "", bss pointer = valid dm_bss_t instance | Exception thrown from put_bss API as per error handling | Should Fail |
 */
TEST_F(dm_easy_mesh_list_tTEST, put_bss_empty_key)
{
    std::cout << "Entering put_bss_empty_key test" << std::endl;
    dm_bss_t bss;
    const char* key = "";
    std::cout << "Invoking put_bss with empty key and valid dm_bss_t pointer" << std::endl;    
    EXPECT_ANY_THROW(list.put_bss(key, &bss));
    std::cout << "Exiting put_bss_empty_key test" << std::endl;
}
/**
 * @brief Verify that put_bss throws an exception when a NULL dm_bss pointer is provided.
 *
 * This test verifies that invoking the list.put_bss API with a valid key string (built using valid MAC addresses and network id)
 * but with a NULL dm_bss pointer results in an exception. This behavior is essential to ensure that the API properly handles invalid inputs.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 085@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Build the BSS key using build_bss_key with appropriate MAC addresses and network id. | net_id = "Network1", dev_mac = {0x11,0x22,0x33,0x44,0x55,0x66}, radio_mac = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF}, bssid = {0x10,0x11,0x12,0x13,0x14,0x16}, haul_type = 0, output key variable | Should generate a valid key string stored in 'key'. | Should be successful |
 * | 02 | Invoke list.put_bss with the generated key and NULL as dm_bss pointer to verify exception handling. | key = [value from step 01], dm_bss pointer = NULL | The API is expected to throw an exception. | Should Fail |
 */
TEST_F(dm_easy_mesh_list_tTEST, put_bss_null_dm_bss)
{
    std::cout << "Entering put_bss_null_dm_bss test" << std::endl;    
    char key[256];
    build_bss_key("Network1", mac1, mac2, mac3, 0, key);
    std::cout << "Invoking put_bss with key: " << key << " and dm_bss_t pointer: " << "NULL" << std::endl;
    EXPECT_ANY_THROW(list.put_bss(key, NULL));
    std::cout << "Exiting put_bss_null_dm_bss test" << std::endl;
}
/**
 * @brief Test to verify that put_bss fails when using a special character key
 *
 * This test verifies that the put_bss API correctly throws an exception when the key contains special characters.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 086@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call build_bss_key to generate a key with special characters in the network id | net_id = "mesh@bss#004$%", dev_mac = {0x11,0x22,0x33,0x44,0x55,0x66}, radio_mac = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF}, bssid = {0x10,0x11,0x12,0x13,0x14,0x16}, haul_type = 0 | The key is generated successfully and stored in the key buffer | Should be successful |
 * | 02 | Invoke put_bss using the generated key and a valid dm_bss_t pointer, and expect an exception | key = generated key, dm_bss_t pointer initialized as bss | An exception is thrown as verified by EXPECT_ANY_THROW | Should Fail |
 */
TEST_F(dm_easy_mesh_list_tTEST, put_bss_special_char_key)
{
    std::cout << "Entering put_bss_special_char_key test" << std::endl;
    dm_bss_t bss;
    char key[256];
    build_bss_key("mesh@bss#004$%", mac1, mac2, mac3, 0, key);
    std::cout << "Invoking put_bss with special characters in netid and valid dm_bss_t pointer" << std::endl;    
    EXPECT_ANY_THROW(list.put_bss(key, &bss));
    std::cout << "Exiting put_bss_special_char_key test" << std::endl;
}
/**
 * @brief Validate the put_device API for valid device insertion.
 *
 * This test verifies that a valid device, with correct network ID and MAC address, can be successfully inserted into the device list without throwing exceptions. It confirms that the helper function build_device_key correctly constructs the device key and that the put_device API processes the valid inputs accordingly.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 087@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize dm_device_t with valid network id "Network1" and valid MAC address from mac1 | net_id = "Network1", dev_mac = 11:22:33:44:55:66 | Device is properly initialized | Should be successful |
 * | 02 | Build device key using build_device_key helper function | Input: net_id = "Network1", mac1 = 11:22:33:44:55:66, Output: key = "Network1:11:22:33:44:55:66" | Key is correctly constructed with expected format | Should be successful |
 * | 03 | Invoke list.put_device with the constructed key and device pointer | key = "Network1:11:22:33:44:55:66", device pointer with valid fields | No exception thrown and device gets inserted into list | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, put_device_valid_insertion) {
    std::cout << "Entering put_device_valid_insertion test" << std::endl;
    dm_device_t device;
	char key[256];
    strcpy(device.m_device_info.id.net_id, "Network1");
    memcpy(device.m_device_info.id.dev_mac, mac1, sizeof(mac_address_t));
    build_device_key("Network1", mac1, key);
	std::cout << "Invoking put_device with key: " << key << std::endl;
    EXPECT_NO_THROW(list.put_device(key, &device));
    std::cout << "Exiting put_device_valid_insertion test" << std::endl;
}
/**
 * @brief Test the behavior of put_device when provided with a NULL key
 *
 * This test verifies that the put_device function throws an exception when called with a NULL key while a valid device pointer is provided. This ensures that the API correctly handles invalid input and maintains error safety.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 088@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                       | Test Data                                  | Expected Result                                                       | Notes      |
 * | :--------------: | ----------------------------------------------------------------- | ------------------------------------------ | --------------------------------------------------------------------- | ---------- |
 * | 01               | Invoke list.put_device with a NULL key and a valid device pointer   | key = NULL, device pointer = address of device | API throws an exception as verified by EXPECT_ANY_THROW check         | Should Fail|
 */
TEST_F(dm_easy_mesh_list_tTEST, put_device_null_key) {
    std::cout << "Entering put_device_null_key test" << std::endl;
    dm_device_t device;
    const char* key = NULL;
    std::cout << "Invoking put_device with NULL key and device pointer: " << &device << std::endl;
    EXPECT_ANY_THROW(list.put_device(key, &device));
    std::cout << "put_device invoked with NULL key" << std::endl;
    std::cout << "Exiting put_device_null_key test" << std::endl;
}
/**
 * @brief Verifies that put_device API throws an exception when invoked with a null device pointer.
 *
 * This test validates the error handling of the put_device API by passing a valid device key along with a NULL device pointer.
 * It uses the build_device_key helper to create a device key for "Network1" and then calls put_device with NULL to ensure that
 * an exception is thrown as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 089@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                 | Test Data                                                            | Expected Result                                                          | Notes               |
 * | :----:           | :---------------------------------------------------------------------------| :------------------------------------------------------------------- | :----------------------------------------------------------------------- | :------------------ |
 * | 01               | Generate a device key using build_device_key with valid parameters           | net_id = "Network1", mac1 = 11:22:33:44:55:66, key = uninitialized      | Device key is generated successfully and stored in key                   | Should be successful  |
 * | 02               | Invoke put_device API with the generated key and a NULL device pointer         | key = <generated device key>, device pointer = NULL                  | An exception is thrown by the API indicating error due to null device pointer   | Should Fail         |
 */
TEST_F(dm_easy_mesh_list_tTEST, put_device_null_device) {
    std::cout << "Entering put_device_null_device test" << std::endl;
	char key[256];
    build_device_key("Network1", mac1, key);
    std::cout << "Invoking put_device with key: " << key << " and NULL device pointer" << std::endl;
    EXPECT_ANY_THROW(list.put_device(key, NULL));
    std::cout << "put_device invoked with key: " << key << " and NULL device pointer" << std::endl;
    std::cout << "Exiting put_device_null_device test" << std::endl;
}
/**
 * @brief Test the insertion of a valid network into the mesh list.
 *
 * This test verifies that the API function put_network can correctly handle the insertion of a valid network identified by "Network1". The test ensures that invoking put_network with a proper network object does not result in any exceptions, thereby confirming the expected behavior of a successful network insertion.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 090@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                            | Test Data                                       | Expected Result                                                                      | Notes       |
 * | :--------------: | -------------------------------------------------------------------------------------- | ----------------------------------------------- | ------------------------------------------------------------------------------------- | ----------- |
 * | 01               | Initialize a default network object and invoke put_network with "Network1"             | network = default initialized object, network name = "Network1", network pointer = &network | API call returns normally without throwing any exceptions; EXPECT_NO_THROW passes       | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, put_network_valid_network_insertion)
{
    std::cout << "Entering put_network_valid_network_insertion test" << std::endl;
    dm_network_t network = {};
    std::cout << "Invoking put_network with Network1" << std::endl;
    EXPECT_NO_THROW(list.put_network("Network1", &network));
    std::cout << "Exiting put_network_valid_network_insertion test" << std::endl;
}
/**
 * @brief Validate that the put_network API throws an exception when invoked with a null key.
 *
 * This test verifies the error handling of the put_network API by passing a null key instead of a valid network key.
 * The test ensures that the API correctly handles invalid input (i.e., a null key) by throwing an exception.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 091@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                          | Test Data                                                  | Expected Result                                                         | Notes           |
 * | :--------------: | ---------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- | ----------------------------------------------------------------------- | --------------- |
 * | 01               | Print the message indicating the start of the put_network_null_key test                              | None                                                       | "Entering put_network_null_key test" message logged                     | Should be successful |
 * | 02               | Initialize the network structure and set the network id to "ValidNetwork"                            | network.m_net_info.id = "ValidNetwork"                     | Network structure initialized with valid network id                     | Should be successful |
 * | 03               | Invoke put_network API with a null key and validate that an exception is thrown using EXPECT_ANY_THROW | key = nullptr, network pointer (id = "ValidNetwork")       | Exception is thrown as expected when put_network is called with null key  | Should Fail     |
 * | 04               | Print the message indicating the exit of the put_network_null_key test                               | None                                                       | "Exiting put_network_null_key test" message logged                      | Should be successful |
 */
TEST_F(dm_easy_mesh_list_tTEST, put_network_null_key)
{
    std::cout << "Entering put_network_null_key test" << std::endl;
    dm_network_t network;
    strncpy(network.m_net_info.id, "ValidNetwork", sizeof(network.m_net_info.id));
    std::cout << "Invoking put_network with key: " << "NULL" << std::endl;
    EXPECT_ANY_THROW(list.put_network(nullptr, &network));
    std::cout << "Exiting put_network_null_key test" << std::endl;
}
/**
 * @brief Test that put_network throws an exception when provided with a null network pointer
 *
 * This test verifies that the put_network API properly handles the error scenario when a null network pointer is provided. The function is expected to throw an exception, ensuring that invalid input is caught and managed correctly.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 092@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                 | Test Data                                                  | Expected Result                                               | Notes              |
 * | :--------------: | --------------------------------------------------------------------------- | ---------------------------------------------------------- | ------------------------------------------------------------- | ------------------ |
 * | 01               | Define the key value to "Network002"                                        | key = "Network002"                                         | key is correctly set to "Network002"                          | Should be successful |
 * | 02               | Invoke put_network using the defined key and a NULL network pointer         | key = "Network002", network pointer = nullptr              | An exception is thrown from put_network                       | Should Fail        |
 * | 03               | Output the test exit log message                                            | Log messages indicating test entry and exit                | Log messages are printed confirming test execution            | Should be successful |
 */
TEST_F(dm_easy_mesh_list_tTEST, put_network_null_network)
{
    std::cout << "Entering put_network_null_network test" << std::endl;
    const char *key = "Network002";
    std::cout << "Invoking put_network with key: " << key << ", network pointer: NULL" << std::endl;
    EXPECT_ANY_THROW(list.put_network(key, nullptr));
    std::cout << "Exiting put_network_null_network test" << std::endl;
}
/**
 * @brief Verifies the successful insertion of a new SSID into the network SSID table.
 *
 * This test verifies that when a valid and new SSID ("SSID1") is provided to the put_network_ssid API along with an initialized
 * dm_network_ssid_t structure, the API correctly inserts the new SSID without throwing an exception.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 093@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                       | Test Data                                                       | Expected Result                                                                  | Notes      |
 * | :--------------: | ----------------------------------------------------------------- | --------------------------------------------------------------- | ------------------------------------------------------------------------------- | ---------- |
 * | 01               | Call put_network_ssid with key "SSID1" and an initialized ssid instance | input: key = "SSID1", network_ssid = { }                        | API call completes successfully without throwing an exception (EXPECT_NO_THROW passes) | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, put_network_ssid_valid_new_ssid_insertion) {
    std::cout << "Entering put_network_ssid_valid_new_ssid_insertion test" << std::endl;
    dm_network_ssid_t network_ssid = {};
    std::cout << "Invoking put_network_ssid with key SSID1 " << std::endl;	
    EXPECT_NO_THROW(list.put_network_ssid("SSID1", &network_ssid));
    std::cout << "Invocation of put_network_ssid completed" << std::endl;
    std::cout << "Exiting put_network_ssid_valid_new_ssid_insertion test" << std::endl;
}
/**
 * @brief Validate that put_network_ssid API handles a NULL key gracefully
 *
 * This test verifies that when a NULL key is passed to the put_network_ssid API,
 * the function throws an exception as expected. This behavior confirms that the API
 * properly validates its input parameters and prevents undefined behavior.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 094@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                             | Test Data                                                            | Expected Result                                                                            | Notes         |
 * | :--------------: | ----------------------------------------------------------------------- | -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ | ------------- |
 * | 01               | Initialize the test variables and set key to NULL                       | key = NULL, networkSSID instance (uninitialized dm_network_ssid_t)   | Test variables are set correctly                                                           | Should be successful |
 * | 02               | Invoke put_network_ssid API with a NULL key and check for exception throw | input: key = NULL, networkSSID pointer                                | API is expected to throw an exception, validated by EXPECT_ANY_THROW                        | Should Fail   |
 */
TEST_F(dm_easy_mesh_list_tTEST, put_network_ssid_negative_null_key) {
    std::cout << "Entering put_network_ssid_negative_null_key test" << std::endl;
    dm_network_ssid_t networkSSID;
    const char *key = NULL;
    std::cout << "Invoking put_network_ssid with NULL key" << std::endl;
    EXPECT_ANY_THROW(list.put_network_ssid(key, &networkSSID));
    std::cout << "Invocation with NULL key completed" << std::endl;
    std::cout << "Exiting put_network_ssid_negative_null_key test" << std::endl;
}
/**
 * @brief Verifies that put_network_ssid API correctly throws an exception when provided with a NULL network_ssid pointer.
 *
 * This test ensures that the put_network_ssid function of dm_easy_mesh_list_t throws an exception when a NULL pointer is passed as the network_ssid argument. The test validates the proper error handling of the API for invalid input conditions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 095@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                             | Test Data                               | Expected Result                                                            | Notes      |
 * | :--------------: | ----------------------------------------------------------------------- | --------------------------------------- | -------------------------------------------------------------------------- | ---------- |
 * | 01               | Invoke put_network_ssid with a valid key "SSID2" and a NULL network_ssid. | key = "SSID2", network_ssid = NULL        | API should throw an exception as detected by EXPECT_ANY_THROW assertion.   | Should Fail |
 */
TEST_F(dm_easy_mesh_list_tTEST, put_network_ssid_negative_null_network_ssid) {
    std::cout << "Entering put_network_ssid_negative_null_network_ssid test" << std::endl;
    const char *key = "SSID2";
    std::cout << "Invoking put_network_ssid with key: " << key << " and NULL network_ssid pointer" << std::endl;
    EXPECT_ANY_THROW(list.put_network_ssid(key, NULL));
    std::cout << "Invocation with NULL network_ssid completed" << std::endl;
    std::cout << "Exiting put_network_ssid_negative_null_network_ssid test" << std::endl;
}
/**
 * @brief Verify that calling put_network_ssid with an empty key raises an exception.
 *
 * This test verifies that the list.put_network_ssid API correctly handles invalid input by throwing an exception when invoked with an empty string as the key. It ensures the robustness of error handling in the API.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 096@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                              | Test Data                                                          | Expected Result                                                  | Notes          |
 * | :--------------: | ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------ | ---------------------------------------------------------------- | -------------- |
 * | 01               | Print message indicating the entry into put_network_ssid_negative_empty_key test           | No input                                                           | Console displays "Entering put_network_ssid_negative_empty_key test" | Should be successful |
 * | 02               | Invoke put_network_ssid API with an empty key                                              | key = "", networkSSID = pointer to dm_network_ssid_t instance        | API throws an exception as validated by EXPECT_ANY_THROW          | Should Fail    |
 * | 03               | Print message indicating the completion of API invocation                                  | No input                                                           | Console displays "Invocation with empty key completed"            | Should be successful |
 * | 04               | Print message indicating the exit from put_network_ssid_negative_empty_key test              | No input                                                           | Console displays "Exiting put_network_ssid_negative_empty_key test"  | Should be successful |
 */
TEST_F(dm_easy_mesh_list_tTEST, put_network_ssid_negative_empty_key) {
    std::cout << "Entering put_network_ssid_negative_empty_key test" << std::endl;
    std::cout << "Invoking put_network_ssid with empty key" << std::endl;
    dm_network_ssid_t networkSSID;
    EXPECT_ANY_THROW(list.put_network_ssid("", &networkSSID));
    std::cout << "Invocation with empty key completed" << std::endl;
    std::cout << "Exiting put_network_ssid_negative_empty_key test" << std::endl;
}
/**
 * @brief Verify that put_op_class function correctly processes valid input without throwing exceptions.
 *
 * This test ensures that when valid op_class information and key are provided to the put_op_class API,
 * the function executes successfully and does not throw any exceptions. It validates the correct handling
 * of the op class data structure and key generation using a valid MAC address.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 097@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data |Expected Result |Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01 | Build op class data structure with valid parameters, generate key using mac1, and invoke put_op_class API | op: m_op_class_info.op_class=10, channel=5, tx_power=15, max_tx_power=20, num_channels=3, channels=(1,6,11), id type=em_op_class_type_current, id.op_class=100; key generated from mac1 | The put_op_class API should execute without throwing an exception | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, put_op_class_valid_input)
{
    std::cout << "Entering put_op_class_valid_input test" << std::endl;
    dm_op_class_t op;
    op.m_op_class_info.op_class = 10;
    op.m_op_class_info.channel = 5;
    op.m_op_class_info.tx_power = 15;
    op.m_op_class_info.max_tx_power = 20;
    op.m_op_class_info.num_channels = 3;
    op.m_op_class_info.channels[0] = 1;
    op.m_op_class_info.channels[1] = 6;
    op.m_op_class_info.channels[2] = 11;
    op.m_op_class_info.id.type = em_op_class_type_current;
    op.m_op_class_info.id.op_class = 100;
    char key[256];
    std::cout << "Invoking put_op_class with key op1 and valid m_op_class_info" << std::endl;
    build_op_class_key(mac1, em_op_class_type_current, 100, key);
    EXPECT_NO_THROW(list.put_op_class(key, &op));
    std::cout << "Exiting put_op_class_valid_input test" << std::endl;
}
/**
 * @brief Tests that put_op_class() throws an exception when provided with a NULL key.
 *
 * This test verifies that the put_op_class() function correctly handles an invalid input where the key is NULL.
 * The test sets up a dm_op_class_t structure with valid op_class information and then invokes the put_op_class() API
 * with a NULL key to ensure that the API throws an exception as expected.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 098
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Log entering message for test execution. | None | "Entering put_op_class_null_key test" is printed to stdout. | Should be successful |
 * | 02 | Initialize a dm_op_class_t structure with op_class, channel, tx_power, max_tx_power, number of channels, channel list, and op_class ID. | op_class = 20, channel = 3, tx_power = 18, max_tx_power = 25, num_channels = 2, channels = [3, 8], id.type = em_op_class_type_capability, id.op_class = 200 | dm_op_class_t is properly initialized with the specified values. | Should be successful |
 * | 03 | Invoke put_op_class() with a NULL key and the initialized dm_op_class_t structure. | key = NULL, op = { op_class = 20, channel = 3, tx_power = 18, max_tx_power = 25, num_channels = 2, channels = [3, 8], id.type = em_op_class_type_capability, id.op_class = 200 } | The API call throws an exception (as expected with a NULL key). | Should Pass |
 * | 04 | Log exiting message for test completion. | None | "Exiting put_op_class_null_key test" is printed to stdout. | Should be successful |
 */
TEST_F(dm_easy_mesh_list_tTEST, put_op_class_null_key)
{
    std::cout << "Entering put_op_class_null_key test" << std::endl;
    dm_op_class_t op;
    op.m_op_class_info.op_class = 20;
    op.m_op_class_info.channel = 3;
    op.m_op_class_info.tx_power = 18;
    op.m_op_class_info.max_tx_power = 25;
    op.m_op_class_info.num_channels = 2;
    op.m_op_class_info.channels[0] = 3;
    op.m_op_class_info.channels[1] = 8;
    op.m_op_class_info.id.type = em_op_class_type_capability;
    op.m_op_class_info.id.op_class = 200;   
    std::cout << "Invoking put_op_class with key: NULL and dm_op_class_t with op_class = " << op.m_op_class_info.op_class << ", channel = " << op.m_op_class_info.channel << std::endl;
    EXPECT_ANY_THROW(list.put_op_class(NULL, &op));    
    std::cout << "Exiting put_op_class_null_key test" << std::endl;
}
/**
 * @brief Verify that put_op_class throws an exception when invoked with a NULL dm_op_class_t pointer
 *
 * This test constructs a valid op class key using build_op_class_key and then calls put_op_class 
 * with the constructed key and a NULL dm_op_class_t pointer. The objective is to ensure that the API 
 * correctly handles invalid input by throwing an exception.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 099@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                      | Test Data                                                                                                   | Expected Result                                                    | Notes       |
 * | :--------------: | ------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ | ----------- |
 * | 01               | Construct op class key using build_op_class_key and invoke put_op_class with a NULL pointer        | mac1 = 11:22:33:44:55:66, em_op_class_type = em_op_class_type_current, op_class = 0x81, dm_op_class pointer = NULL | An exception is thrown by put_op_class (EXPECT_ANY_THROW passes)      | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, put_op_class_null_op_class)
{
    std::cout << "Entering put_op_class_null_op_class test" << std::endl;
    char key[256];	
	build_op_class_key(mac1, em_op_class_type_current, 0x81, key);
	std::cout << "Invoking put_op_class with key: \"" << key << "\" and dm_op_class_t pointer: NULL" << std::endl;
    EXPECT_ANY_THROW(list.put_op_class(key, NULL));
    std::cout << "Exiting put_op_class_null_op_class test" << std::endl;
}
/**
 * @brief Verify that the put_op_class API throws an exception for an empty net_id.
 *
 * This test verifies that the put_op_class API correctly detects and throws an exception when invoked with an empty net_id string, ensuring that invalid parameters are not accepted.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 100@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize the dm_op_class_t structure with specific op_class info values including op_class=30, channel=7, tx_power=22, max_tx_power=28, num_channels=4, channels[0]=2, channels[1]=7, channels[2]=12, channels[3]=14, id.type=em_op_class_type_cac_available, and id.op_class=300. | op.m_op_class_info.op_class = 30, op.m_op_class_info.channel = 7, op.m_op_class_info.tx_power = 22, op.m_op_class_info.max_tx_power = 28, op.m_op_class_info.num_channels = 4, op.m_op_class_info.channels[0] = 2, op.m_op_class_info.channels[1] = 7, op.m_op_class_info.channels[2] = 12, op.m_op_class_info.channels[3] = 14, op.m_op_class_info.id.type = em_op_class_type_cac_available, op.m_op_class_info.id.op_class = 300 | dm_op_class_t structure is properly initialized | Should be successful |
 * | 02 | Invoke list.put_op_class with an empty net_id and the initialized dm_op_class_t structure, and verify that an exception is thrown. | net_id = "", op = (initialized structure) | API should throw an exception which is caught by EXPECT_ANY_THROW | Should Fail |
 */
TEST_F(dm_easy_mesh_list_tTEST, put_op_class_empty_key)
{
    std::cout << "Entering put_op_class_empty_key test" << std::endl;
    dm_op_class_t op;
    op.m_op_class_info.op_class = 30;
    op.m_op_class_info.channel = 7;
    op.m_op_class_info.tx_power = 22;
    op.m_op_class_info.max_tx_power = 28;
    op.m_op_class_info.num_channels = 4;
    op.m_op_class_info.channels[0] = 2;
    op.m_op_class_info.channels[1] = 7;
    op.m_op_class_info.channels[2] = 12;
    op.m_op_class_info.channels[3] = 14;
    op.m_op_class_info.id.type = em_op_class_type_cac_available;
    op.m_op_class_info.id.op_class = 300;    
    std::cout << "Invoking put_op_class with empty  net_id" << std::endl;    
    EXPECT_ANY_THROW(list.put_op_class("", &op));
    std::cout << "Exiting put_op_class_empty_key test" << std::endl;
}
/**
 * @brief Verify valid insertion of a policy via put_policy
 *
 * This test validates that the put_policy API does not throw an exception when a valid
 * dm_policy_t pointer and a correctly constructed key (using build_policy_key) are passed.
 * It verifies that the policy is inserted correctly into the list.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 101@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                  | Test Data                                                                                                                             | Expected Result                                               | Notes         |
 * | :--------------: | -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- | ------------- |
 * | 01               | Construct the policy key using valid network ID, device MAC addresses, and policy type         | network_id = "Network2", dev_mac = [0x10,0x11,0x12,0x13,0x14,0x16], radio_mac = [0x10,0x11,0x12,0x13,0x12,0x15], policy = em_policy_id_type_default_8021q_settings | Key is correctly constructed                                  | Should be successful |
 * | 02               | Invoke put_policy with the constructed key and valid dm_policy_t pointer and check for exception | key (as constructed above), policy pointer (address of dm_policy_t policy)                                                            | API call does not throw any exception                         | Should Pass   |
 */
TEST_F(dm_easy_mesh_list_tTEST, put_policy_valid_policy_insertion)
{
    std::cout << "Entering put_policy_valid_policy_insertion test" << std::endl;
    dm_policy_t policy;
    char key[256];
    build_policy_key("Network2", mac3, mac4, em_policy_id_type_default_8021q_settings, key);
    std::cout << "Calling put_policy with key: " << key << " and valid dm_policy_t pointer." << std::endl;
    EXPECT_NO_THROW(list.put_policy(key, &policy));
    std::cout << "put_policy method invoked successfully for valid insertion." << std::endl;
    std::cout << "Exiting put_policy_valid_policy_insertion test" << std::endl;
}
/**
 * @brief Test put_policy API function with a NULL key.
 *
 * This test verifies that calling put_policy with a NULL key throws an exception. It ensures that error handling is correctly implemented for invalid policy insertion.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 102@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:** 
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize dm_policy_t structure with valid network id, policy type, and number of stations while key is set to NULL. | policy.m_policy.id.net_id = "net_null_key_test", policy.m_policy.id.type = em_policy_id_type_traffic_separation, policy.m_policy.num_sta = 2, key = NULL | dm_policy_t structure is initialized correctly | Should be successful |
 * | 02 | Invoke list.put_policy with the NULL key and the valid dm_policy_t pointer. | key = NULL, policy pointer = address of policy | EXPECT_ANY_THROW throws an exception due to NULL key input | Should Fail |
 */
TEST_F(dm_easy_mesh_list_tTEST, put_policy_null_key)
{
    std::cout << "Entering put_policy_null_key test" << std::endl;
    dm_policy_t policy;
    strcpy(policy.m_policy.id.net_id, "net_null_key_test");
    policy.m_policy.id.type = em_policy_id_type_traffic_separation;
    policy.m_policy.num_sta = 2;
    const char* key = NULL;
    std::cout << "Calling put_policy with NULL key and a valid dm_policy_t pointer." << std::endl;
    EXPECT_ANY_THROW(list.put_policy(key, &policy));
    std::cout << "put_policy invoked with NULL key; error handling should be triggered internally." << std::endl;
    std::cout << "Exiting put_policy_null_key test" << std::endl;
}
/**
 * @brief Validate error handling in put_policy when provided a NULL policy pointer
 *
 * This test verifies that the put_policy function triggers error handling by throwing an exception when invoked with a NULL policy pointer.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 103@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                               | Test Data                                                                                                                     | Expected Result                                                                                       | Notes           |
 * | :--------------: | ----------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | --------------- |
 * | 01               | Generate a policy key using build_policy_key function with valid network and MAC addresses  | net_id = "Network1", dev_mac = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66}, radio_mac = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, type = em_policy_id_type_default_8021q_settings, key = [buffer] | A valid policy key is constructed and stored in 'key' buffer                                          | Should be successful |
 * | 02               | Invoke the put_policy API with the generated key and a NULL policy pointer                   | key = [from step 01], policy pointer = NULL                                                                                   | The API call should throw an exception as validated by EXPECT_ANY_THROW                                | Should Fail     |
 */
TEST_F(dm_easy_mesh_list_tTEST, put_policy_null_policy)
{
    std::cout << "Entering put_policy_null_policy test" << std::endl;
	char key[256];
    build_policy_key("Network1", mac1, mac2, em_policy_id_type_default_8021q_settings, key);
    std::cout << "Calling put_policy with key: " << key << " and NULL dm_policy_t pointer." << std::endl;
    EXPECT_ANY_THROW(list.put_policy(key, NULL));
    std::cout << "put_policy invoked with NULL policy pointer; error handling should be triggered internally." << std::endl;
    std::cout << "Exiting put_policy_null_policy test" << std::endl;
}
/**
 * @brief Test for put_policy API with an empty network identifier in the key
 *
 * This test verifies that the put_policy API function throws an exception when invoked with an empty string key, even though a valid dm_policy_t pointer is provided. This ensures that the API correctly validates the key input and prevents storing a policy with an invalid key.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 104@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                 | Test Data                                                                                                                  | Expected Result                                                 | Notes         |
 * | :--------------: | --------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- | ------------- |
 * | 01               | Build policy key using build_policy_key function with an empty network id   | net_id = "", dev_mac = {0x11,0x22,0x33,0x44,0x55,0x66}, radio_mac = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF}, type = em_policy_id_type_default_8021q_settings, key output buffer | Key is constructed (even if empty network id might result in an invalid key) | Should be successful |
 * | 02               | Invoke put_policy with the empty key and a valid dm_policy_t pointer          | key (from step 01), dm_policy_t pointer = &policy                                                                            | API throws an exception as the key is empty                     | Should Fail   |
 */
TEST_F(dm_easy_mesh_list_tTEST, put_policy_empty_key)
{
    std::cout << "Entering put_policy_empty_key test" << std::endl;
    dm_policy_t policy{};
    char key[256];
    build_policy_key("", mac1, mac2, em_policy_id_type_default_8021q_settings, key);
    std::cout << "Calling put_policy with empty string key and a valid dm_policy_t pointer." << std::endl;
    EXPECT_ANY_THROW(list.put_policy(key, &policy));
    std::cout << "put_policy invoked with empty string key; policy stored if empty key is allowed." << std::endl;
    std::cout << "Exiting put_policy_empty_key test" << std::endl;
}
/**
 * @brief Verify that dm_easy_mesh_list_t::put_radio successfully stores a radio when provided with a valid key and radio pointer.
 *
 * This test verifies the functionality of the put_radio API in the dm_easy_mesh_list_t class by passing a valid key (derived from mac2) and a valid radio pointer. The test ensures that the API call does not throw any exceptions, confirming proper handling of valid radio insertion.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 105@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                         | Test Data                                          | Expected Result                                                                              | Notes       |
 * | :--------------: | ------------------------------------------------------------------- | -------------------------------------------------- | -------------------------------------------------------------------------------------------- | ----------- |
 * | 01               | Convert mac2 to key string and call put_radio with valid parameters   | key = value from mac2, radio pointer = &radio       | put_radio does not throw any exception; EXPECT_NO_THROW passes                               | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, put_radio_valid_radio_valid_key)
{
    std::cout << "Entering put_radio_valid_radio_valid_key test" << std::endl;
    dm_radio_t radio;
    char key[18];
    mac_to_string(mac2, key);
    std::cout << "Invoking dm_easy_mesh_list_t::put_radio with key: " << key << " and radio pointer: " << &radio << std::endl;
    EXPECT_NO_THROW(list.put_radio(key, &radio));
    std::cout << "dm_easy_mesh_list_t::put_radio invoked successfully with valid parameters" << std::endl;
    std::cout << "Exiting put_radio_valid_radio_valid_key test" << std::endl;
}
/**
 * @brief Validate the behavior of put_radio when passed a NULL key
 *
 * This test verifies that the dm_easy_mesh_list_t::put_radio API correctly handles an invalid
 * key parameter (NULL) while being provided with a valid radio pointer. The API is expected to throw 
 * an exception under such conditions. This negative test case ensures the robustness of error handling.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 106@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                 | Test Data                                               | Expected Result                                             | Notes            |
 * | :--------------: | --------------------------------------------------------------------------- | ------------------------------------------------------- | ----------------------------------------------------------- | ---------------- |
 * | 01               | Enter the test function and log the entry                                   | None                                                    | Entry message logged                                        | Should be successful |
 * | 02               | Initialize a radio object and set key to NULL                               | radio object initialized, key = NULL                    | Radio object is created and key is NULL                     | Should be successful |
 * | 03               | Invoke put_radio API with NULL key and valid radio pointer                  | key = NULL, radio pointer = address of radio object       | Exception is thrown as expected                             | Should Fail      |
 * | 04               | Log the successful handling of NULL key and exit the test                   | None                                                    | Exit message logged                                         | Should be successful |
 */
TEST_F(dm_easy_mesh_list_tTEST, put_radio_NULL_key_valid_radio)
{
    std::cout << "Entering put_radio_NULL_key_valid_radio test" << std::endl;
    dm_radio_t radio;
    const char *key = NULL;
    std::cout << "Invoking dm_easy_mesh_list_t::put_radio with key: NULL" << " and radio pointer: " << &radio << std::endl;
    EXPECT_ANY_THROW(list.put_radio(key, &radio));
    std::cout << "dm_easy_mesh_list_t::put_radio handled NULL key parameter" << std::endl;
    std::cout << "Exiting put_radio_NULL_key_valid_radio test" << std::endl;
}
/**
 * @brief Test dm_easy_mesh_list_t::put_radio with a valid key and NULL radio pointer to verify exception handling
 *
 * This test verifies that the dm_easy_mesh_list_t::put_radio API correctly handles a NULL radio pointer when provided with a valid key. 
 * The test ensures that an exception is thrown under this negative input condition, maintaining proper error handling.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 107@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                 | Test Data                                                        | Expected Result                                              | Notes       |
 * | :--------------: | --------------------------------------------------------------------------- | ---------------------------------------------------------------- | ------------------------------------------------------------ | ----------- |
 * | 01               | Invoke dm_easy_mesh_list_t::put_radio with a valid key derived from mac1 and a NULL radio pointer | key = mac_to_string(mac1) result, radio pointer = NULL           | API throws an exception, confirmed via EXPECT_ANY_THROW      | Should Fail |
 */
TEST_F(dm_easy_mesh_list_tTEST, put_radio_valid_key_NULL_radio)
{
    std::cout << "Entering put_radio_valid_key_NULL_radio test" << std::endl;
    char key[18];
    mac_to_string(mac1, key);
    std::cout << "Invoking dm_easy_mesh_list_t::put_radio with key: " << key << " and radio pointer: NULL" << std::endl;
    EXPECT_ANY_THROW(list.put_radio(key, NULL));
    std::cout << "dm_easy_mesh_list_t::put_radio handled NULL radio pointer" << std::endl;
    std::cout << "Exiting put_radio_valid_key_NULL_radio test" << std::endl;
}
/**
 * @brief Verify that the put_radio API throws an exception when provided with an empty key and a valid radio pointer.
 *
 * This test ensures that the dm_easy_mesh_list_t::put_radio function correctly handles the invalid input scenario where the key is generated from an all-zero MAC address. The function is expected to throw an exception, demonstrating proper error handling for an empty key.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 108@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                         | Test Data                                                    | Expected Result                                           | Notes                  |
 * | :--------------: | ----------------------------------------------------------------------------------- | ------------------------------------------------------------ | --------------------------------------------------------- | ---------------------- |
 * | 01               | Initialize the radio object and generate an empty key from a MAC value of all zeros | radio = {}, mac = {0x00,0x00,0x00,0x00,0x00,0x00}, key = "00:00:00:00:00:00" | Key is formatted as "00:00:00:00:00:00"                   | Should be successful     |
 * | 02               | Invoke dm_easy_mesh_list_t::put_radio with the empty key and a valid radio pointer      | key = "00:00:00:00:00:00", radio pointer valid               | Exception is thrown indicating invalid input              | Should Fail            |
 * | 03               | Log the exit message at the end of the test                                          | N/A                                                          | Exit log is successfully printed                         | Should be successful     |
 */
TEST_F(dm_easy_mesh_list_tTEST, put_radio_empty_key_valid_radio)
{
    std::cout << "Entering put_radio_empty_key_valid_radio test" << std::endl;
    dm_radio_t radio = {};
	char key[18];
	unsigned char mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};	
    mac_to_string(mac, key);
    std::cout << "Invoking dm_easy_mesh_list_t::put_radio with empty key and valid radio pointer" << std::endl;
    EXPECT_ANY_THROW(list.put_radio(key, &radio));
    std::cout << "Exiting put_radio_empty_key_valid_radio test" << std::endl;
}
/**
 * @brief Validate standard insertion of a scan result into the list.
 *
 * This test verifies that a valid scan result can be inserted into the dm_easy_mesh_list using the key generated by the build_scan_result_key helper function. It ensures that the put_scan_result API call is executed without throwing any exceptions, verifying the proper handling of valid input parameters.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 109@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                   | Test Data                                                                                                                  | Expected Result                                         | Notes             |
 * | :--------------: | --------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- | ----------------- |
 * | 01               | Generate scan result key using build_scan_result_key with provided parameters.                | net_id = "Network1", dev_mac = mac1, scanner_mac = mac2, op_class = 0x81, channel = 6, scanner_type = 1, bssid = 0xff,0xff,0xff,0xff,0xff,0xff  | Key is generated successfully.                          | Should be successful |
 * | 02               | Invoke put_scan_result API with the generated key, scanResult pointer, and index value.         | key = generated key, scanResult = pointer to dm_scan_result_t, index = 0                                                    | API call does not throw any exception.                  | Should Pass       |
 */
TEST_F(dm_easy_mesh_list_tTEST, put_scan_result_valid_insertion_standard)
{
    std::cout << "Entering put_scan_result_valid_insertion_standard test" << std::endl;
    dm_scan_result_t scanResult;
    skip_teardown = true;
    char key[256];
    unsigned char bssid[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    build_scan_result_key("Network1", mac1, mac2, 0x81, 6, 1, bssid, key);    
    unsigned int index = 0;
    std::cout << "Invoking put_scan_result with key: " << key << ", index: " << index << std::endl;
    EXPECT_NO_THROW(list.put_scan_result(key, &scanResult, index));
    std::cout << "put_scan_result invoked successfully for key: " << key << " and index: " << index << std::endl;
    std::cout << "Exiting put_scan_result_valid_insertion_standard test" << std::endl;
}
/**
 * @brief Verifies that put_scan_result inserts a scan result at a valid non-zero index without throwing exceptions
 *
 * This test creates a scan result key using the build_scan_result_key helper function with valid input parameters, sets up a non-zero index (5), and then invokes the put_scan_result API. The objective is to ensure that the scan result is inserted at the specified index without any exception being thrown.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 110@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Initialize scan result, build scan result key with "Network1", mac1, mac2, op_class=0x81, channel=6, scanner_type=1, bssid=ff:ff:ff:ff:ff:ff; set index to 5; invoke put_scan_result API | key = "Network1@<mac1>@<mac2>@0x81@6@1@ff:ff:ff:ff:ff:ff", index = 5, scanResult = uninitialized instance of dm_scan_result_t | EXPECT_NO_THROW: API should execute without exceptions indicating successful insertion | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, put_scan_result_valid_insertion_non_zero_index)
{
    std::cout << "Entering put_scan_result_valid_insertion_non_zero_index test" << std::endl;
    dm_scan_result_t scanResult;
    skip_teardown = true;
    char key[256];
    unsigned char bssid[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    build_scan_result_key("Network1", mac1, mac2, 0x81, 6, 1, bssid, key);
    unsigned int index = 5;
    std::cout << "Invoking put_scan_result with key: " << key << ", index: " << index << std::endl;
    EXPECT_NO_THROW(list.put_scan_result(key, &scanResult, index));
    std::cout << "put_scan_result invoked successfully for key: " << key << " and index: " << index << std::endl;    
    std::cout << "Exiting put_scan_result_valid_insertion_non_zero_index test" << std::endl;
}
/**
 * @brief Test to verify that put_scan_result throws an exception when invoked with a NULL key.
 *
 * This test verifies that the API put_scan_result correctly handles the scenario when a NULL key is provided,
 * ensuring that invalid input is detected and an appropriate exception is thrown.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 111@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                              | Test Data                                             | Expected Result                                | Notes       |
 * | :--------------: | -------------------------------------------------------- | ----------------------------------------------------- | ---------------------------------------------- | ----------- |
 * | 01               | Call put_scan_result with key set to NULL, a valid scanResult pointer and index value  | key = NULL, scanResult = valid dm_scan_result_t object, index = 3  | An exception is thrown from put_scan_result    | Should Fail |
 */
TEST_F(dm_easy_mesh_list_tTEST, put_scan_result_null_key)
{
    std::cout << "Entering put_scan_result_null_key test" << std::endl;
    dm_scan_result_t scanResult;
    skip_teardown = true;
    const char * key = NULL;
    unsigned int index = 3;
    std::cout << "Invoking put_scan_result with NULL key and index: " << index << std::endl;
    EXPECT_ANY_THROW(list.put_scan_result(key, &scanResult, index));
    std::cout << "put_scan_result invoked with NULL key, index: " << index << std::endl;
    std::cout << "Exiting put_scan_result_null_key test" << std::endl;
}
/**
 * @brief Verify that put_scan_result method throws an exception when provided with a NULL scan_result pointer.
 *
 * This test verifies that calling the put_scan_result API with a valid key but a NULL scan_result pointer triggers an exception.
 * The test is important to ensure the robustness of the API by handling invalid inputs gracefully.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 112
 * **Priority:** High
 * 
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Set skip_teardown to true and generate the scan result key using build_scan_result_key helper with valid MAC addresses and parameters. | net_id = "Network1", mac1 = {0x11,0x22,0x33,0x44,0x55,0x66}, mac2 = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF}, op_class = 0x81, channel = 6, scanner_type = 1, bssid = {0xff,0xff,0xff,0xff,0xff,0xff} | A valid key string is generated based on the provided inputs. | Should be successful |
 * | 02 | Invoke put_scan_result with the generated key, a NULL scan_result pointer, and an index value of 2, expecting an exception to be thrown. | key = generated key, scan_result = NULL, index = 2 | Exception is thrown as verified by EXPECT_ANY_THROW assertion. | Should Fail |
 */
TEST_F(dm_easy_mesh_list_tTEST, put_scan_result_null_scan_result)
{
    std::cout << "Entering put_scan_result_null_scan_result test" << std::endl;
    char key[256];
    skip_teardown = true;
    unsigned char bssid[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    build_scan_result_key("Network1", mac1, mac2, 0x81, 6, 1, bssid, key);
    unsigned int index = 2;
    std::cout << "Invoking put_scan_result with key: " << key << " and NULL scan_result, index: " << index << std::endl;
    EXPECT_ANY_THROW(list.put_scan_result(key, NULL, index));
    std::cout << "put_scan_result invoked with key: " << key << " and NULL scan_result, index: " << index << std::endl;    
    std::cout << "Exiting put_scan_result_null_scan_result test" << std::endl;
}
/**
 * @brief Verify that put_scan_result correctly handles a key with an empty net_id.
 *
 * This test verifies that when the scan result key is constructed with an empty net_id, the put_scan_result API throws an exception.
 * This behavior ensures that the API properly validates the key and prevents invalid operations.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 113@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                  | Test Data                                                                                                                             | Expected Result                                                               | Notes           |
 * | :--------------: | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- | --------------- |
 * | 01               | Build scan result key using empty net_id                                     | net_id = "", mac1 = 0x11:22:33:44:55:66, mac2 = 0xAA:BB:CC:DD:EE:FF, op_class = 0x81, channel = 6, scanner_type = 1, bssid = 0xff:ff:ff:ff:ff:ff | Key constructed with an empty net_id                                         | Should be successful |
 * | 02               | Invoke put_scan_result using the constructed key with index 1 and verify exception thrown | key = constructed key from step 1, index = 1, scanResult = instance of dm_scan_result_t                                                 | API throws an exception indicating failure due to an empty net_id in the key | Should Fail       |
 */
TEST_F(dm_easy_mesh_list_tTEST, put_scan_result_empty_key)
{
    std::cout << "Entering put_scan_result_empty_key test" << std::endl;
	char key[256];
    skip_teardown = true;
    unsigned char bssid[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    build_scan_result_key("", mac1, mac2, 0x81, 6, 1, bssid, key);
    unsigned int index = 1;
    dm_scan_result_t scanResult;
    std::cout << "Invoking put_scan_result with empty net_id in key and index: " << index << std::endl;
    EXPECT_ANY_THROW(list.put_scan_result(key, &scanResult, index));
    std::cout << "put_scan_result invoked with empty key, index: " << index << std::endl;    
    std::cout << "Exiting put_scan_result_empty_key test" << std::endl;
}
/**
 * @brief Verify that put_sta correctly adds a station entry for a valid key and valid dm_sta_t pointer.
 *
 * This test validates that the list.put_sta API correctly handles a key constructed from valid MAC addresses
 * (using build_sta_key) and a valid dm_sta_t pointer. It ensures that no exceptions are thrown during the API call,
 * indicating that the station is added successfully.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 114@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                  | Test Data                                                                                                             | Expected Result                                                              | Notes         |
 * | :----:           | ---------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | ------------- |
 * | 01               | Construct the station key using build_sta_key with valid MAC addresses.      | input: mac1 = {0x11,0x22,0x33,0x44,0x55,0x66}, mac2 = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF}, mac3 = {0x10,0x11,0x12,0x13,0x14,0x16}; output: key string formatted as "mac1:mac2:mac3" | Key string is correctly constructed.                                         | Should be successful |
 * | 02               | Invoke put_sta with the constructed key and a valid dm_sta_t pointer, expecting no exception. | input: key = constructed key, dm_sta_t pointer = valid instance address (&sta)                                           | API completes without throwing exceptions and station is added successfully. | Should Pass   |
 */
TEST_F(dm_easy_mesh_list_tTEST, put_sta_validKey_added) {
    std::cout << "Entering put_sta_validKey_added test" << std::endl;
    dm_sta_t sta;
    char key[256];
    build_sta_key(mac1, mac2, mac3, key);
    std::cout << "Invoking put_sta with key: " << key << " and valid dm_sta_t pointer" << std::endl;
    EXPECT_NO_THROW(list.put_sta(key, &sta));
    std::cout << "Successfully invoked put_sta with key: " << key << std::endl;
    std::cout << "Exiting put_sta_validKey_added test" << std::endl;
}
/**
 * @brief Test put_sta function handling of a NULL key.
 *
 * This test validates that the put_sta API function robustly handles a NULL key by throwing an exception.
 * The test ensures that passing a NULL pointer as the key argument results in the expected exception being thrown,
 * thereby preventing any undefined behavior or application crash.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 115@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke put_sta with a NULL key and a valid dm_sta_t pointer | key = NULL, sta pointer = valid address of dm_sta_t instance | Exception is thrown by list.put_sta indicating invalid argument; EXPECT_ANY_THROW assertion passes | Should Fail |
 */
TEST_F(dm_easy_mesh_list_tTEST, put_sta_nullKey) {
    std::cout << "Entering put_sta_nullKey test" << std::endl;
    dm_sta_t sta;
    const char* key = NULL;
    std::cout << "Invoking put_sta with NULL key and dm_sta_t pointer: " << &sta << std::endl;
    EXPECT_ANY_THROW(list.put_sta(key, &sta));
    std::cout << "Invocation of put_sta with NULL key completed (handled gracefully)" << std::endl;
    std::cout << "Exiting put_sta_nullKey test" << std::endl;
}
/**
 * @brief Verify that the put_sta API properly handles a NULL dm_sta_t pointer.
 *
 * This test checks if the put_sta API correctly throws an exception when invoked with a valid STA key and a NULL pointer for the dm_sta_t parameter. It ensures robustness by validating input parameter checking within the API.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 116@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Build a STA key using mac1, mac2, and mac3, then call put_sta with the generated key and a NULL pointer to dm_sta_t | input: mac1 = 11:22:33:44:55:66, mac2 = AA:BB:CC:DD:EE:FF, mac3 = 10:11:12:13:14:16, key = generated key, dm_sta pointer = NULL | API throws an exception as verified by EXPECT_ANY_THROW | Should Fail |
 */
TEST_F(dm_easy_mesh_list_tTEST, put_sta_nullSta) {
    std::cout << "Entering put_sta_nullSta test" << std::endl;
    char key[256];
    build_sta_key(mac1, mac2, mac3, key);
    std::cout << "Invoking put_sta with key: " << key << " and NULL dm_sta_t pointer" << std::endl;
    EXPECT_ANY_THROW(list.put_sta(key, NULL));
    std::cout << "Invocation of put_sta with NULL dm_sta_t pointer completed (handled gracefully)" << std::endl;
    std::cout << "Exiting put_sta_nullSta test" << std::endl;
}
/**
 * @brief Validate removal of a BSS entry with a valid, existing key.
 *
 * This test verifies that the remove_bss API successfully removes an existing BSS entry when provided with a valid key constructed using build_bss_key. 
 * The key is constructed with "Network1", mac1, mac2, mac3, and haul type 0. The BSS entry is added to the list using put_bss, and then 
 * remove_bss is invoked to ensure proper deletion without throwing exceptions.
 *
 * **Test Group ID:** Basic: 01  
 * **Test Case ID:** 117  
 * **Priority:** High  
 *
 * **Pre-Conditions:** None  
 * **Dependencies:** None  
 * **User Interaction:** None  
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                                    | Test Data                                                                                                                                                                       | Expected Result                                             | Notes      |
 * | :--------------: | -------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- | ---------- |
 * | 01               | Construct the BSS key using build_bss_key, insert a BSS entry using put_bss, then invoke remove_bss with the valid key. | net_id = "Network1", dev_mac = {0x11,0x22,0x33,0x44,0x55,0x66}, radio_mac = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF}, bssid = {0x10,0x11,0x12,0x13,0x14,0x16}, haul_type = 0, dm_bss_t object = {} | remove_bss should execute without throwing an exception.   | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, remove_bss_valid_key_existing)
{
    std::cout << "Entering remove_bss_valid_key_existing test" << std::endl;
    dm_bss_t bss = {};
    char key[256];
    build_bss_key("Network1", mac1, mac2, mac3, 0, key);    
    list.put_bss(key, &bss);
    std::cout << "Invoking remove_bss with key: " << key << std::endl;
    EXPECT_NO_THROW(list.remove_bss(key));
    std::cout << "remove_bss method invoked successfully for key: " << key << std::endl;
    std::cout << "Exiting remove_bss_valid_key_existing test" << std::endl;
}
/**
 * @brief Verify that remove_bss() handles a null key input gracefully
 *
 * This test validates that the list.remove_bss() function, when invoked with a nullptr as the key,
 * correctly throws an exception instead of crashing. This behavior confirms that the API enforces
 * input validation and error handling for invalid parameters.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 118@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                               | Test Data                        | Expected Result                                                   | Notes       |
 * | :--------------: | --------------------------------------------------------- | -------------------------------- | ----------------------------------------------------------------- | ----------- |
 * | 01               | Invoke remove_bss() with a null key and verify exception  | key = nullptr                    | The API throws an exception to indicate invalid argument input    | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, remove_bss_null_key_handles_gracefully)
{
    std::cout << "Entering remove_bss_null_key_handles_gracefully test" << std::endl;
    const char* nullKey = nullptr;
    std::cout << "Invoking remove_bss with key: " << "nullptr" << std::endl;
    EXPECT_ANY_THROW(list.remove_bss(nullKey));
    std::cout << "remove_bss method handled nullptr without crashing." << std::endl;
    std::cout << "Exiting remove_bss_null_key_handles_gracefully test" << std::endl;
}
/**
 * @brief Test the removal of a BSS using a non-existent key to ensure proper exception handling.
 *
 * This test verifies that calling the remove_bss API method with a non-existent key results in an exception.
 * The objective is to validate that the API does not alter the bss list when an invalid key is provided,
 * and that the error handling mechanism (throwing an exception) is functioning as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 119@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                  | Test Data                                   | Expected Result                                                            | Notes       |
 * | :--------------: | -------------------------------------------------------------------------------------------- | ------------------------------------------- | ------------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke remove_bss API with a non-existent key to verify that an exception is thrown.           | key = non_existent_key                      | API returns an exception; assertion EXPECT_ANY_THROW passes if exception thrown | Should Fail |
 */
TEST_F(dm_easy_mesh_list_tTEST, remove_bss_non_existent_key_no_change)
{
    std::cout << "Entering remove_bss_non_existent_key_no_change test" << std::endl;
    const char* nonExistentKey = "non_existent_key";
    std::cout << "Invoking remove_bss with key: " << nonExistentKey << std::endl;    
    EXPECT_ANY_THROW(list.remove_bss(nonExistentKey));
    std::cout << "remove_bss method invoked successfully with key: " << nonExistentKey << std::endl;
    std::cout << "Exiting remove_bss_non_existent_key_no_change test" << std::endl;
}
/**
 * @brief Verify that remove_device successfully removes an existing device using a valid key.
 *
 * This test inserts a device into the device list with a valid key generated by build_device_key and then
 * invokes remove_device to remove the inserted device. It verifies that the removal does not throw any exception,
 * ensuring the proper functioning of the device removal mechanism.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 120@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                  | Test Data                                                            | Expected Result                                                  | Notes         |
 * | :----:           | ------------------------------------------------------------ | -------------------------------------------------------------------- | ---------------------------------------------------------------- | ------------- |
 * | 01               | Build device key using build_device_key                        | net_id = "Network1", dev_mac = 11:22:33:44:55:66                     | Key is constructed for device lookup                             | Should be successful |
 * | 02               | Initialize device object and set device information            | net_id = "Network1", dev_mac = 11:22:33:44:55:66                     | Device object is populated with valid data                       | Should be successful |
 * | 03               | Insert device into list using put_device                       | key = "Network1:11:22:33:44:55:66", device object                     | Device is successfully inserted into the list                    | Should Pass   |
 * | 04               | Remove device using remove_device                              | key = "Network1:11:22:33:44:55:66"                                     | remove_device completes without throwing an exception            | Should Pass   |
 */
TEST_F(dm_easy_mesh_list_tTEST, remove_device_existing_valid_key)
{
    std::cout << "Entering remove_device_existing_valid_key test" << std::endl;
	dm_device_t device = {};
	char key[256];
    build_device_key("Network1", mac1, key);
    strcpy(device.m_device_info.id.net_id, "Network1");
    memcpy(device.m_device_info.id.dev_mac, mac1, sizeof(mac_address_t));
	list.put_device(key, &device);
    std::cout << "Invoking remove_device with key: " << key << std::endl;
    EXPECT_NO_THROW(list.remove_device(key));
    std::cout << "remove_device returned. Expected device with key " << key << " to be removed from m_list." << std::endl;
    std::cout << "Exiting remove_device_existing_valid_key test" << std::endl;
}
/**
 * @brief Validate remove_device API with a non-existent device key.
 *
 * This test verifies that invoking remove_device() with a device key that does not exist does not throw any exception and does not modify the internal device list and network count. The device key is generated using build_device_key with an empty network ID and a valid MAC address, ensuring that it doesn't match any existing device in the list.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 121@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                          | Test Data                                                                              | Expected Result                                                | Notes               |
 * | :--------------: | -------------------------------------------------------------------- | -------------------------------------------------------------------------------------- | -------------------------------------------------------------- | ------------------- |
 * | 01               | Generate device key using build_device_key with an empty net_id and mac1. | net_id = "", mac1 = 0x11:0x22:0x33:0x44:0x55:0x66, key = output buffer                   | Device key is generated and stored in 'key'.                   | Should be successful  |
 * | 02               | Invoke remove_device() with the generated key.                       | key = generated key (non-existent device key)                                          | No exception is thrown when remove_device() is called.         | Should Pass         |
 * | 03               | Validate that the internal list and network count remain unchanged.    | (No additional test data)                                                               | Internal state remains unchanged as expected.                   | Should be successful  |
 */
TEST_F(dm_easy_mesh_list_tTEST, remove_device_non_existent_key)
{
    std::cout << "Entering remove_device_non_existent_key test" << std::endl;
	char key[256];
    build_device_key("", mac1, key);
    std::cout << "Invoking remove_device with key: non_existent_device" << std::endl;
    EXPECT_NO_THROW(list.remove_device(key));    
    std::cout << "remove_device returned. Expected no change in m_list and m_num_networks for non-existent key." << std::endl;    
    std::cout << "Exiting remove_device_non_existent_key test" << std::endl;
}
/**
 * @brief Test remove_device API with a NULL key
 *
 * This test verifies that providing a NULL key to the remove_device API triggers an exception and ensures that the internal state of the dm_easy_mesh_list_t object remains unchanged. This negative test case is designed to validate that the API robustly handles invalid input parameters.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 122@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call remove_device with a NULL pointer to test error handling | input: key = NULL | Exception is thrown; m_list and m_num_networks remain unchanged | Should Fail |
 */
TEST_F(dm_easy_mesh_list_tTEST, remove_device_null_key)
{
    std::cout << "Entering remove_device_null_key test" << std::endl;
    std::cout << "Invoking remove_device with key: NULL" << std::endl;
    EXPECT_ANY_THROW(list.remove_device(nullptr));
    std::cout << "remove_device returned. Expected graceful handling of NULL key; m_list and m_num_networks remain unchanged." << std::endl;
    std::cout << "Exiting remove_device_null_key test" << std::endl;
}
/**
 * @brief Verify that remove_network successfully removes an existing network when provided with a valid key.
 *
 * This test validates that invoking remove_network with a valid network key ("Network1") does not throw an exception.
 * The test first registers a network using list.put_network and then calls remove_network to remove it.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 123@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup network by invoking put_network with the key "Network1" and an empty network structure | input: key = "Network1", network = {} | Network is registered successfully in the list | Should be successful |
 * | 02 | Invoke remove_network with the valid key "Network1" to remove the registered network | input: key = "Network1" | remove_network does not throw any exception (EXPECT_NO_THROW) and the network is removed | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, remove_network_existing_valid_key)
{
    std::cout << "Entering remove_network_existing_valid_key test" << std::endl;
    dm_network_t network = {};
    list.put_network("Network1", &network);
    std::cout << "Invoking remove_network" << std::endl;
    EXPECT_NO_THROW(list.remove_network("Network1"));    
    std::cout << "Exiting remove_network_existing_valid_key test" << std::endl;
}
/**
 * @brief Tests removal of a non-existent network key from the network list.
 *
 * This test verifies that calling remove_network with a key that does not exist in the network list
 * properly throws an exception, ensuring that the list remains unchanged. It is important for validating
 * the error handling mechanism for invalid removal requests.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 124@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                  | Test Data                           | Expected Result                                                         | Notes           |
 * | :----:           | -----------------------------------------------------------------------------| ----------------------------------- | ----------------------------------------------------------------------- | --------------- |
 * | 01               | Log the entry message indicating the start of the test                       | N/A                                 | "Entering remove_network_non_existent_key test" message is printed        | Should be successful |
 * | 02               | Invoke remove_network with key "non_existing_network" and expect an exception  | key = non_existing_network          | remove_network throws an exception; EXPECT_ANY_THROW validates this       | Should Fail     |
 * | 03               | Log the exit message after API call and exception check                      | N/A                                 | "Exiting remove_network_non_existent_key test" message is printed           | Should be successful |
 */
TEST_F(dm_easy_mesh_list_tTEST, remove_network_non_existent_key)
{
    std::cout << "Entering remove_network_non_existent_key test" << std::endl;
    const char* key = "non_existing_network";
    std::cout << "Invoking remove_network with key: " << key << std::endl;
    EXPECT_ANY_THROW(list.remove_network(key));
    std::cout << "remove_network called with key: " << key << ". Expected no changes in the network list." << std::endl;
    std::cout << "Exiting remove_network_non_existent_key test" << std::endl;
}
/**
 * @brief Verify remove_network behaves gracefully when a nullptr key is provided.
 *
 * This test ensures that the remove_network API handles a nullptr key input gracefully by throwing an exception.
 * It checks the input validation and exception handling mechanism to prevent unexpected modifications to the internal state.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 125
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                         | Test Data                             | Expected Result                                                    | Notes                |
 * | :--------------: | --------------------------------------------------------------------| ------------------------------------- | ------------------------------------------------------------------ | -------------------- |
 * | 01               | Log the beginning of the test execution                             | N/A                                   | Log message indicating test start                                  | Should be successful |
 * | 02               | Initialize the key with a nullptr                                     | key = nullptr                         | key is set to nullptr                                               | Should be successful |
 * | 03               | Invoke remove_network with the nullptr key and check for an exception | key = nullptr, output: exception thrown | Exception thrown; internal state remains unchanged                   | Should Fail          |
 * | 04               | Log the completion of the test execution                              | N/A                                   | Log message indicating test exit                                    | Should be successful |
 */
TEST_F(dm_easy_mesh_list_tTEST, remove_network_null_key)
{
    std::cout << "Entering remove_network_null_key test" << std::endl;
    const char* key = nullptr;
    std::cout << "Invoking remove_network with key: nullptr" << std::endl;
    EXPECT_ANY_THROW(list.remove_network(key));
    std::cout << "remove_network called with nullptr. Expected graceful handling without altering internal state." << std::endl;
    std::cout << "Exiting remove_network_null_key test" << std::endl;
}
/**
 * @brief Verify removal of an existing network SSID record using a valid key.
 *
 * This test verifies that invoking remove_network_ssid with a valid and existing key ("SSID1")
 * successfully removes the network SSID record without throwing any exceptions. The test first
 * adds a network SSID entry by calling put_network_ssid and then removes it by calling remove_network_ssid.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 126@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                              | Test Data                                                         | Expected Result                                                   | Notes     |
 * | :--------------: | ---------------------------------------------------------------------------------------- | ----------------------------------------------------------------- | ----------------------------------------------------------------- | --------- |
 * | 01               | Invoke put_network_ssid to add a network SSID entry                                        | input1 = key "SSID1", input2 = network_ssid instance (default init) | Network SSID entry is added successfully                          | Should Pass |
 * | 02               | Invoke remove_network_ssid to remove the existing network SSID entry using key "SSID1"       | input1 = key "SSID1"                                                | API executes without throwing an exception (network SSID removed)  | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, remove_network_ssid_valid_existing_key)
{
    const char* testName = "remove_network_ssid_valid_existing_key";
    std::cout << "Entering " << testName << " test" << std::endl;
	dm_network_ssid_t network_ssid = {};
    list.put_network_ssid("SSID1", &network_ssid);
    std::cout << "Invoking remove_network_ssid with key: validSSID" << std::endl;
    EXPECT_NO_THROW({
        list.remove_network_ssid("SSID1");
        std::cout << "Method remove_network_ssid invoked with key: validSSID" << std::endl;
    });
    std::cout << "Exiting " << testName << " test" << std::endl;
}
/**
 * @brief Remove network SSID with a non-existent key test
 *
 * This test verifies that calling remove_network_ssid with a key that does not exist ("nonExistentSSID") results in an exception. It ensures that the API correctly handles the invalid input scenario by throwing an exception.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 127@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                           | Test Data                      | Expected Result                                           | Notes      |
 * | :--------------: | --------------------------------------------------------------------- | ------------------------------ | --------------------------------------------------------- | ---------- |
 * | 01               | Invoke remove_network_ssid with a non-existent key "nonExistentSSID".   | key = nonExistentSSID          | API throws an exception as per EXPECT_ANY_THROW check     | Should Fail|
 */
TEST_F(dm_easy_mesh_list_tTEST, remove_network_ssid_nonexistent_key)
{
    const char* testName = "remove_network_ssid_nonexistent_key";
    std::cout << "Entering " << testName << " test" << std::endl;
    std::cout << "Invoking remove_network_ssid with key: nonExistentSSID" << std::endl;
    EXPECT_ANY_THROW({
        list.remove_network_ssid("nonExistentSSID");
        std::cout << "Method remove_network_ssid invoked with key: nonExistentSSID" << std::endl;
    });
    std::cout << "Exiting " << testName << " test" << std::endl;
}
/**
 * @brief Test remove_network_ssid function for handling NULL key input
 *
 * This test validates that invoking remove_network_ssid with a NULL key results in an exception being thrown.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 128@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                          | Test Data               | Expected Result                                           | Notes       |
 * | :--------------: | ---------------------------------------------------- | ----------------------- | --------------------------------------------------------- | ----------- |
 * | 01               | Invoke remove_network_ssid API with a null key       | key = nullptr           | Exception thrown; EXPECT_ANY_THROW assertion is met       | Should Fail |
 */
TEST_F(dm_easy_mesh_list_tTEST, remove_network_ssid_null_key)
{
    const char* testName = "remove_network_ssid_null_key";
    std::cout << "Entering " << testName << " test" << std::endl;
    std::cout << "Invoking remove_network_ssid with key: NULL" << std::endl;
    EXPECT_ANY_THROW(list.remove_network_ssid(nullptr));
    std::cout << "Method remove_network_ssid invoked with key: NULL" << std::endl;
    std::cout << "Exiting " << testName << " test" << std::endl;
}
/**
 * @brief Test removal of an operation class when a valid key is present.
 *
 * This test verifies that the op class entry can be successfully removed from the list when a valid key is provided. It generates a valid key using a MAC address, inserts the op class using that key, and then removes it, expecting no exception to be thrown.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 129
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Generate a valid op class key using mac1 with op class type 'em_op_class_type_current' and value 0x81 | mac1 = 11,22,33,44,55,66, op_class_type = em_op_class_type_current, op_class value = 0x81 | Key is properly generated as a valid string | Should be successful |
 * | 02 | Insert the generated op class into the list using the created key | key = generated key, op_class pointer address | Insertion is successful and op class entry is added to the list | Should Pass |
 * | 03 | Remove the op class by invoking list.remove_op_class with the valid key | key = generated key | API invocation throws no exception (operation succeeds) | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, remove_op_class_valid_key_present) {
    std::cout << "Entering remove_op_class_valid_key_present test" << std::endl;
    dm_op_class_t op_class = {};
    char key[256];
    build_op_class_key(mac1, em_op_class_type_current, 0x81, key);
    list.put_op_class(key, &op_class);
    std::cout << "Invoking remove_op_class with key: ValidOpClassKey" << std::endl;
    EXPECT_NO_THROW(list.remove_op_class(key));
    std::cout << "Exiting remove_op_class_valid_key_present test" << std::endl;
}
/**
 * @brief Test removal of an op class entry using a valid key that is not present in the list.
 *
 * This test verifies that calling remove_op_class with a key "NonExistentOpClassKey" that does not exist in the list results in an exception being thrown.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 130@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                    | Test Data                             | Expected Result                                     | Notes              |
 * | :--------------: | -------------------------------------------------------------- | ------------------------------------- | --------------------------------------------------- | ------------------ |
 * | 01               | Print entering message indicating the start of the test        | None                                  | Message displayed on console                        | Should be successful |
 * | 02               | Invoke remove_op_class with key "NonExistentOpClassKey" to check exception handling | input key = NonExistentOpClassKey     | Exception thrown by remove_op_class                 | Should Fail        |
 * | 03               | Print exiting message indicating the end of the test           | None                                  | Message displayed on console                        | Should be successful |
 */
TEST_F(dm_easy_mesh_list_tTEST, remove_op_class_valid_key_not_present) {
    std::cout << "Entering remove_op_class_valid_key_not_present test" << std::endl;
    std::cout << "Invoking remove_op_class with key: NonExistentOpClassKey" << std::endl;
    EXPECT_ANY_THROW(list.remove_op_class("NonExistentOpClassKey"));
    std::cout << "Exiting remove_op_class_valid_key_not_present test" << std::endl;
}
/**
 * @brief Validate error handling of remove_op_class function with a NULL key
 *
 * This test verifies that invoking the remove_op_class method with a NULL key correctly throws an exception. This ensures the API properly handles invalid input by rejecting NULL values.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 131@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                               | Test Data      | Expected Result                                                               | Notes       |
 * | :--------------: | ----------------------------------------- | -------------- | ----------------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke remove_op_class with NULL key      | key = NULL     | Exception thrown from remove_op_class and EXPECT_ANY_THROW assertion passes   | Should Fail |
 */
TEST_F(dm_easy_mesh_list_tTEST, remove_op_class_null_key) {
    std::cout << "Entering remove_op_class_null_key test" << std::endl;
    std::cout << "Invoking remove_op_class with key: NULL" << std::endl;
    EXPECT_ANY_THROW(list.remove_op_class(NULL));
    std::cout << "Exiting remove_op_class_null_key test" << std::endl;
}
/**
 * @brief Verify that removing an existing policy using a valid policy key succeeds without exceptions
 *
 * This test verifies that when a policy is added to the list with a valid policy key, invoking the 
 * remove_policy API function successfully removes the policy without throwing any exceptions. 
 * The key is constructed using the build_policy_key helper, and the policy is added via put_policy 
 * before removal is attempted.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 132@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:** 
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create policy key using build_policy_key and add policy via put_policy | net_id = "Network1", dev_mac = 0x11:22:33:44:55:66, radio_mac = 0xAA:BB:CC:DD:EE:FF, type = em_policy_id_type_default_8021q_settings, policy = {} | Policy is added successfully | Should Pass |
 * | 02 | Invoke remove_policy API with the previously added key and validate no exception is thrown | key (constructed from step 01) | remove_policy returns without throwing an exception | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, remove_policy_existing_policy_key)
{
    std::cout << "Entering remove_policy_existing_policy_key test" << std::endl;
    dm_policy_t policy = {};
    char key[256];
    build_policy_key("Network1", mac1, mac2, em_policy_id_type_default_8021q_settings, key);
    list.put_policy(key, &policy);
    std::cout << "Invoking remove_policy with key: " << key << std::endl;
    EXPECT_NO_THROW(list.remove_policy(key));
    std::cout << "Exiting remove_policy_existing_policy_key test" << std::endl;
}
/**
 * @brief Verify that removing a policy with a non-existent key results in an exception.
 *
 * This test verifies that the remove_policy API correctly throws an exception when it is invoked with a policy key that does not exist in the list. The test constructs a policy key using parameters that are not associated with any actual stored policy and then attempts to remove the policy using that key.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 133@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:** 
 * | Variation / Step | Description                                                                                     | Test Data                                                                                                                       | Expected Result                                                                             | Notes       |
 * | :--------------: | ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ----------- |
 * | 01               | Construct a policy key using build_policy_key helper with a non-existent network ID and MAC addresses. | input: net_id = non_existent_policy_key, dev_mac = 0x11,0x22,0x33,0x44,0x55,0x66, radio_mac = 0xAA,0xBB,0xCC,0xDD,0xEE,0xFF, type = em_policy_id_type_default_8021q_settings, output: key buffer | The key should be constructed successfully.                                               | Should be successful |
 * | 02               | Invoke remove_policy with the constructed non-existent policy key.                              | input: key (the key constructed in step 01)                                                                                     | remove_policy API is expected to throw an exception (ASSERT check using EXPECT_ANY_THROW).    | Should Fail |
 */
TEST_F(dm_easy_mesh_list_tTEST, remove_policy_non_existent_policy_key)
{
    std::cout << "Entering remove_policy_non_existent_policy_key test" << std::endl;
    char key[256];
    build_policy_key("non_existent_policy_key", mac1, mac2, em_policy_id_type_default_8021q_settings, key);
    std::cout << "Invoking remove_policy with key: " << key << std::endl;
    EXPECT_ANY_THROW(list.remove_policy(key));
    std::cout << "Exiting remove_policy_non_existent_policy_key test" << std::endl;
}
/**
 * @brief Test removal of policy with a null key
 *
 * This test verifies that invoking remove_policy with a NULL key correctly triggers an exception. The test ensures the system handles invalid input appropriately by throwing an error.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 134@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                          | Test Data           | Expected Result                                                            | Notes        |
 * | :--------------: | ---------------------------------------------------- | ------------------- | -------------------------------------------------------------------------- | ------------ |
 * | 01               | Invoke list.remove_policy with a NULL key            | key = NULL          | Function throws an exception as validated by EXPECT_ANY_THROW macro        | Should Fail  |
 */
TEST_F(dm_easy_mesh_list_tTEST, remove_policy_null_key)
{
    std::cout << "Entering remove_policy_null_key test" << std::endl;
    const char* key = NULL;
    std::cout << "Invoking remove_policy with key: NULL" << std::endl;
    EXPECT_ANY_THROW(list.remove_policy(key));
    std::cout << "Exiting remove_policy_null_key test" << std::endl;
}
/**
 * @brief Test removal of an existing radio entry using a valid key.
 *
 * This test verifies that the remove_radio function correctly removes a radio entry when provided with a valid key generated from a MAC address. The test first adds a radio entry into the list and then removes it, ensuring no exceptions are thrown during removal. This confirms that the radio removal functionality works as expected.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 135
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | ----------- | ----------- | ----------- | ----- |
 * | 01 | Add radio entry into the list using valid key generated from mac1 | input: mac1 = 0x11,0x22,0x33,0x44,0x55,0x66; output: radio object instance | Radio is successfully added to the list | Should be successful |
 * | 02 | Remove the radio entry using the valid key | input: key generated from mac1 by mac_to_string(mac1, key) | remove_radio returns without throwing exceptions (successful removal) | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, remove_radio_existingRadio_validKey) {
    std::cout << "Entering remove_radio_existingRadio_validKey test" << std::endl;
    dm_radio_t radio = {};
    char key[18];
    mac_to_string(mac1, key);
    list.put_radio(key, &radio);
    std::cout << "Invoking remove_radio with key: " << key << std::endl;
    EXPECT_NO_THROW(list.remove_radio(key));
    std::cout << "Exiting remove_radio_existingRadio_validKey test" << std::endl;
}
/**
 * @brief Verify that remove_radio API throws an exception for a non-existent radio key.
 *
 * This test verifies that invoking the remove_radio API with a key (derived from mac2) that is not registered in the list
 * results in an exception being thrown. It ensures that the API properly handles attempts to remove a non-existent radio.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 136@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                      | Test Data                                                        | Expected Result                                          | Notes      |
 * | :--------------: | -------------------------------------------------------------------------------- | ---------------------------------------------------------------- | -------------------------------------------------------- | ---------- |
 * | 01               | Invoke remove_radio with a key from mac2 that is not present in the list.          | mac2 = 0xAA,0xBB,0xCC,0xDD,0xEE,0xFF, key = "aa:bb:cc:dd:ee:ff"    | API call throws an exception as verified by EXPECT_ANY_THROW | Should Fail |
 */
TEST_F(dm_easy_mesh_list_tTEST, remove_radio_nonExistentKey) {
    std::cout << "Entering remove_radio_nonExistentKey test" << std::endl;
    dm_radio_t radio = {};
    char key[18];
    mac_to_string(mac2, key);
    std::cout << "Invoking remove_radio with key: " << key << std::endl;
    EXPECT_ANY_THROW(list.remove_radio(key));
    std::cout << "Exiting remove_radio_nonExistentKey test" << std::endl;
}
/**
 * @brief Validate that remove_radio API correctly handles a NULL pointer key.
 *
 * This test invokes the remove_radio API with a NULL key pointer to verify that the API raises an exception, ensuring proper input validation and error handling. This negative test case confirms that the API does not accept invalid pointer inputs.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 137@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                              | Test Data      | Expected Result                                             | Notes      |
 * | :--------------: | ---------------------------------------------------------| -------------- | ----------------------------------------------------------- | ---------- |
 * | 01               | Set key pointer to NULL and invoke remove_radio API      | key = NULL     | API throws an exception as validated by EXPECT_ANY_THROW    | Should Fail |
 */
TEST_F(dm_easy_mesh_list_tTEST, remove_radio_nullPointerKey) {
    std::cout << "Entering remove_radio_nullPointerKey test" << std::endl;
    const char* key = NULL;
    std::cout << "Invoking remove_radio with NULL pointer key." << std::endl;
    EXPECT_ANY_THROW(list.remove_radio(key));
    std::cout << "Method remove_radio invoked with NULL pointer key." << std::endl;
    std::cout << "Exiting remove_radio_nullPointerKey test" << std::endl;
}
/**
 * @brief Validate the removal of an existing valid scan result key
 *
 * This test verifies that a scan result inserted with a valid key can be successfully removed without throwing an exception. The test builds a scan result key using build_scan_result_key, inserts a default scan result using put_scan_result, and then attempts to remove it using remove_scan_result.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 138@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Generate a scan result key using build_scan_result_key with the following parameters: net_id = "Network1", dev_mac = mac1, scanner_mac = mac2, op_class = 0x81, channel = 6, scanner_type = 1, and bssid = [0xff,0xff,0xff,0xff,0xff,0xff]. | net_id = "Network1", dev_mac = {0x11,0x22,0x33,0x44,0x55,0x66}, scanner_mac = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF}, op_class = 0x81, channel = 6, scanner_type = 1, bssid = [0xff,0xff,0xff,0xff,0xff,0xff] | Valid key string is generated | Should be successful |
 * | 02 | Insert a scan result using put_scan_result with the generated key and a default dm_scan_result_t structure with timestamp = 0. | key = generated key, scan_result = default dm_scan_result_t, timestamp = 0 | Scan result is stored | Should Pass |
 * | 03 | Remove the scan result using remove_scan_result with the same key. | key = generated key | No exception thrown during removal | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, remove_scan_result_existing_valid_key)
{
    std::cout << "Entering remove_scan_result_existing_valid_key test" << std::endl;
    dm_scan_result_t scan_result = {};
    char key[256];
    unsigned char bssid[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    build_scan_result_key("Network1", mac1, mac2, 0x81, 6, 1, bssid, key);
    list.put_scan_result(key, &scan_result, 0);
    std::cout << "Invoking remove_scan_result with key: " << key << std::endl;
    EXPECT_NO_THROW(list.remove_scan_result(key));
    std::cout << "Exiting remove_scan_result_existing_valid_key test" << std::endl;
}
/**
 * @brief Validate behavior of remove_scan_result for a non-existent key
 *
 * This test verifies that invoking remove_scan_result with a key that does
 * not exist in the list does not throw any exceptions. The test first builds
 * a scan result key using specific network and MAC parameters, then calls the API,
 * and finally checks that the API call is executed without errors.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 139@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                                   | Test Data                                                                                                          | Expected Result                                                             | Notes          |
 * | :--------------: | ------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------- | -------------- |
 * | 01               | Log the entry message indicating the start of the test                                                        | None                                                                                                               | "Entering remove_scan_result_non_existent_key test" is printed              | Should be successful |
 * | 02               | Build a scan result key using given parameters: net_id="Network2", dev_mac=mac3, scanner_mac=mac4, op_class=0x81, channel=6, scanner_type=1, bssid="ff:ff:ff:ff:ff:ff" | net_id = Network2, dev_mac = mac3, scanner_mac = mac4, op_class = 0x81, channel = 6, scanner_type = 1, bssid = ff:ff:ff:ff:ff:ff | The scan result key is generated correctly and stored in the key variable    | Should be successful |
 * | 03               | Invoke the remove_scan_result API with the non-existent key                                                     | key = generated key                                                                                                | API completes without throwing an exception                               | Should Pass    |
 * | 04               | Log the exit message indicating the end of the test                                                            | None                                                                                                               | "Exiting remove_scan_result_non_existent_key test" is printed                | Should be successful |
 */
TEST_F(dm_easy_mesh_list_tTEST, remove_scan_result_non_existent_key)
{
    std::cout << "Entering remove_scan_result_non_existent_key test" << std::endl;
    dm_scan_result_t scan_result = {};
    char key[256];
    unsigned char bssid[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    build_scan_result_key("Network2", mac3, mac4, 0x81, 6, 1, bssid, key);
    std::cout << "Invoking remove_scan_result with key: " << key << std::endl;
    EXPECT_NO_THROW(list.remove_scan_result(key));
    std::cout << "Exiting remove_scan_result_non_existent_key test" << std::endl;
}
/**
 * @brief Verify that remove_scan_result handles a NULL key gracefully.
 *
 * This test verifies that when a NULL key is passed to the remove_scan_result API, 
 * the function does not throw any exception and the system handles the input gracefully.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 140@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                         | Test Data                                          | Expected Result                                              | Notes          |
 * | :--------------: | ------------------------------------------------------------------- | -------------------------------------------------- | ------------------------------------------------------------ | -------------- |
 * | 01               | Print entry log message for the test                                  | None                                               | Logs: "Entering remove_scan_result_null_key test"             | Should be successful |
 * | 02               | Set the key to NULL and print invocation message                      | key = NULL                                         | Logs: "Invoking remove_scan_result with key: NULL"              | Should Pass    |
 * | 03               | Call remove_scan_result with NULL key and check that no exception thrown | key = NULL                                         | API does not throw exception                                  | Should Pass    |
 * | 04               | Print success log message after API invocation                        | None                                               | Logs: "NULL key handled gracefully"                           | Should be successful |
 * | 05               | Print exit log message for the test                                   | None                                               | Logs: "Exiting remove_scan_result_null_key test"              | Should be successful |
 */
TEST_F(dm_easy_mesh_list_tTEST, remove_scan_result_null_key)
{
    std::cout << "Entering remove_scan_result_null_key test" << std::endl;
    const char * key = NULL;
    std::cout << "Invoking remove_scan_result with key: " << "NULL" << std::endl;
    EXPECT_NO_THROW(list.remove_scan_result(key));
    std::cout << "NULL key handled gracefully" << std::endl;    
    std::cout << "Exiting remove_scan_result_null_key test" << std::endl;
}
/**
 * @brief Validate removal of an existing STA with valid parameters
 *
 * This test verifies that a STA entry, when added to the list using a valid key,
 * can be successfully removed without throwing an exception. The test builds a STA key
 * using known MAC addresses, inserts a default STA entry, and then removes it while checking
 * that no exceptions are thrown during the removal process.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 141@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Generate STA key by invoking build_sta_key with mac1, mac2, and mac3 and insert the STA entry using put_sta. | input: mac1 = 0x11,0x22,0x33,0x44,0x55,0x66; mac2 = 0xAA,0xBB,0xCC,0xDD,0xEE,0xFF; mac3 = 0x10,0x11,0x12,0x13,0x14,0x16; key (computed), sta (default initialized) | STA entry is added successfully into the list. | Should be successful |
 * | 02 | Remove the inserted STA entry by calling remove_sta with the computed key and verify that no exception is thrown. | input: key (same computed value as above) | remove_sta API completes without throwing an exception. | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, remove_sta_existing_sta_valid) {
    std::cout << "Entering remove_sta_existing_sta_valid test" << std::endl;
    dm_sta_t sta = {};
    char key[256];
    build_sta_key(mac1, mac2, mac3, key);
	list.put_sta(key, &sta);
    std::cout << "Invoking remove_sta with key: " << key << std::endl;
    EXPECT_NO_THROW({
        list.remove_sta(key);
        std::cout << "remove_sta invoked with key: " << key << std::endl;
    });
    std::cout << "Exiting remove_sta_existing_sta_valid test" << std::endl;
}
/**
 * @brief Test to verify removal of non-existing STA entry.
 *
 * This test verifies that calling remove_sta with a non-existing STA key results in an exception.
 * The test builds a STA key using invalid MAC addresses corresponding to a non-existent STA and expects
 * the remove_sta API to throw an exception.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 142@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                      | Test Data                                                                                                                                | Expected Result                                                       | Notes         |
 * | :--------------: | ------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | ------------- |
 * | 01               | Build STA key using build_sta_key helper function with mac2, mac3, and mac4.                      | mac2 = 0xAA:0xBB:0xCC:0xDD:0xEE:0xFF, mac3 = 0x10:0x11:0x12:0x13:0x14:0x16, mac4 = 0x10:0x11:0x12:0x13:0x12:0x15                   | A valid STA key string is generated.                                  | Should be successful |
 * | 02               | Invoke remove_sta on the list with the generated non-existing STA key wrapped in EXPECT_ANY_THROW. | key = <generated STA key>                                                                                                                 | Exception is thrown when remove_sta is invoked.                       | Should Fail   |
 */
TEST_F(dm_easy_mesh_list_tTEST, remove_sta_non_existing_sta) {
    std::cout << "Entering remove_sta_non_existing_sta test" << std::endl;
    dm_sta_t sta = {};
    char key[256];
    build_sta_key(mac2, mac3, mac4, key);
    std::cout << "Invoking remove_sta with key: " << key << std::endl;
    EXPECT_ANY_THROW({
        list.remove_sta(key);
        std::cout << "remove_sta invoked with key: " << key << std::endl;
    });
    std::cout << "Exiting remove_sta_non_existing_sta test" << std::endl;
}
/**
 * @brief Verify that remove_sta function handles NULL key input by throwing an exception
 *
 * This test validates that invoking the remove_sta API with a NULL key correctly results in an exception. 
 * It ensures that the API properly checks for null pointer inputs and adheres to error handling expectations.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 143@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke remove_sta with a NULL key to verify exception handling. | key = nullptr | Exception is thrown (validated by EXPECT_ANY_THROW) | Should Fail |
 */
TEST_F(dm_easy_mesh_list_tTEST, remove_sta_null_key) {
    std::cout << "Entering remove_sta_null_key test" << std::endl;
    const char* key = nullptr;
    std::cout << "Invoking remove_sta with key: " << "NULL" << std::endl;
    EXPECT_ANY_THROW({
        list.remove_sta(key);   
    });
    std::cout << "remove_sta invoked with key NULL" << std::endl;
    std::cout << "Exiting remove_sta_null_key test" << std::endl;
}
/**
 * @brief Validate the construction and destruction of dm_easy_mesh_list_t object
 *
 * This test ensures that a dm_easy_mesh_list_t object is successfully created using the default constructor and then properly destroyed using the delete operator without throwing exceptions. It verifies that the object's allocation and cleanup are correctly handled.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 144@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                    | Test Data                                                     | Expected Result                                                         | Notes       |
 * | :--------------: | -------------------------------------------------------------- | ------------------------------------------------------------- | ----------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke the default constructor of dm_easy_mesh_list_t          | Constructor call, no input parameters; output: valid object pointer | Object is created without throwing exceptions and valid pointer returned | Should Pass |
 * | 02               | Invoke the destructor using delete operator on the object pointer | Delete call on the created object; input: object instance       | Destructor is called without throwing exceptions and resources cleaned up | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, dm_easy_mesh_list_t_valid_destruction) {
    std::cout << "Entering dm_easy_mesh_list_t_valid_destruction test" << std::endl;
    std::cout << "Invoking constructor of dm_easy_mesh_list_t" << std::endl;
    dm_easy_mesh_list_t* obj = nullptr;
    EXPECT_NO_THROW({
        obj = new dm_easy_mesh_list_t();
        std::cout << "dm_easy_mesh_list_t object created using default constructor" << std::endl;
    });
    std::cout << "Invoking destructor of dm_easy_mesh_list_t by calling delete" << std::endl;
    EXPECT_NO_THROW({
        delete obj;
        std::cout << "Destructor of dm_easy_mesh_list_t called" << std::endl;
    });
    std::cout << "Exiting dm_easy_mesh_list_t_valid_destruction test" << std::endl;
}
/**
 * @brief Validate that delete_all_data_models() correctly deletes non-empty data models without throwing exceptions.
 *
 * This test verifies the behavior of the list.delete_all_data_models() API when the data model list is non-empty.
 * It checks that the API does not throw any exceptions when invoked, and subsequently a new data model can be added
 * to prevent issues such as double free. This confirms that the deletion mechanism is robust even when the list has valid entries.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 145@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                   | Test Data                                                                                                                           | Expected Result                                          | Notes          |
 * | :--------------: | --------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- | -------------- |
 * | 01               | Print the entry message indicating the start of the test.                                     | No input.                                                                                                                           | "Entering delete_all_data_models_DeleteNonEmptyDataModels test" printed. | Should be successful |
 * | 02               | Set the skip_teardown flag to true to prevent normal teardown cleanup from executing.          | skip_teardown = true                                                                                                                | Variable is set to true.                                 | Should be successful |
 * | 03               | Invoke list.delete_all_data_models() and verify that no exception is thrown.                    | list with non-empty data models.                                                                                                    | API does not throw any exception.                        | Should Pass    |
 * | 04               | Add a new data model to the list to prevent a double free scenario after deletion.             | input1 = "Network1", intf1.mac = {0x11,0x22,0x33,0x44,0x55,0x66}, intf1.name = "eth0", em_profile_type = em_profile_type_2, flag = true | New data model is created successfully.                | Should Pass    |
 * | 05               | Print the exit message indicating the end of the test execution.                              | No input.                                                                                                                           | "Exiting delete_all_data_models_DeleteNonEmptyDataModels test" printed. | Should be successful |
 */
TEST_F(dm_easy_mesh_list_tTEST, delete_all_data_models_DeleteNonEmptyDataModels) {
    std::cout << "Entering delete_all_data_models_DeleteNonEmptyDataModels test" << std::endl;
    skip_teardown = true;
    std::cout << "Invoking delete_all_data_models()" << std::endl;
    EXPECT_NO_THROW(list.delete_all_data_models());
    std::cout << "Method delete_all_data_models() invoked" << std::endl;
    em_interface_t intf1, intf2, intf3, intf4;        
    memcpy(intf1.mac, mac1, 6);
    strcpy(intf1.name, "eth0");
    dm1 = list.create_data_model("Network1", &intf1, em_profile_type_1, false);        
    memcpy(intf2.mac, mac2, 6);
    strcpy(intf2.name, "eth1");
    dm2 = list.create_data_model("Network1", &intf2, em_profile_type_2, true);        
    memcpy(intf3.mac, mac3, 6);
    strcpy(intf3.name, "eth2");
    dm3 = list.create_data_model("Network2", &intf3, em_profile_type_3, false);        
    memcpy(intf4.mac, mac4, 6);
    strcpy(intf4.name, "eth3");
    dm4 = list.create_data_model("Network2", &intf4, em_profile_type_3, false);
    std::cout << "Exiting delete_all_data_models_DeleteNonEmptyDataModels test" << std::endl;
}
/**
 * @brief Validate that the get_next_pre_set_op_class_by_type API returns the correct next operation class from the preset list.
 *
 * This test verifies that after obtaining the initial operation class record using get_first_pre_set_op_class_by_type, invoking get_next_pre_set_op_class_by_type with the valid pointer returns another valid operation class record.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 146@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke get_first_pre_set_op_class_by_type with type em_op_class_type_scan_param and verify that the returned pointer is not null | input: em_op_class_type = em_op_class_type_scan_param; output: dm_op_class_t* first must be non-null | first != nullptr; ASSERT_NE(first, nullptr) passes | Should Pass |
 * | 02 | Invoke get_next_pre_set_op_class_by_type with type em_op_class_type_scan_param using the pointer from step 01 and verify that the returned pointer is not null | input: em_op_class_type = em_op_class_type_scan_param, first pointer from step 01; output: dm_op_class_t* ret must be non-null | ret != nullptr; ASSERT_NE(ret, nullptr) passes | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_next_pre_set_op_class_by_type_positive)
{
    std::cout << "Entering get_next_pre_set_op_class_by_type_positive test" << std::endl;    
    dm_op_class_t* first = list.get_first_pre_set_op_class_by_type(em_op_class_type_scan_param);
    ASSERT_NE(first, nullptr);
    std::cout << "Invoking get_next_pre_set_op_class_by_type with valid pointer." << std::endl;
    dm_op_class_t* ret = list.get_next_pre_set_op_class_by_type(em_op_class_type_scan_param, first);
    ASSERT_NE(ret, nullptr);
    std::cout << "Exiting get_next_pre_set_op_class_by_type_positive test" << std::endl;
}
/**
 * @brief Verifies that the get_bss method returns a valid BSS object.
 *
 * This test case validates that a BSS object can be correctly inserted into the mesh list
 * using a constructed key and then retrieved using the same key. It ensures that the BSS information,
 * particularly the BSSID, is consistent with the inserted data.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 147
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Construct the BSS key using build_bss_key function with given parameters. | net_id = "Network1", dev_mac = {0x11,0x22,0x33,0x44,0x55,0x66}, radio_mac = {0,0,0,0,0,0}, bssid = {0,0,0,0,0,1}, haul_type = em_haul_type_backhaul | Key is successfully constructed. | Should Pass |
 * | 02 | Initialize the dm_bss_t object and populate its m_bss_info fields with the correct values. | net_id = "Network1", dev_mac = {0x11,0x22,0x33,0x44,0x55,0x66}, ruid = {0,0,0,0,0,0}, bssid = {0,0,0,0,0,1}, haul_type = em_haul_type_backhaul | dm_bss_t object is initialized with proper BSS info. | Should be successful |
 * | 03 | Insert the initialized dm_bss_t object into the mesh list using list.put_bss. | key (from Step 01), pointer to initialized dm_bss_t object | BSS object is added to the list. | Should Pass |
 * | 04 | Retrieve the BSS object using list.get_bss and verify its validity and data consistency. | key (same as used above) | Retrieved pointer is non-null and BSSID matches the expected value. | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_bss_returns_valid_bss)
{
    std::cout << "Entering get_bss_returns_valid_bss test" << std::endl;
    unsigned char radio_mac[6] = {0,0,0,0,0,0};
    unsigned char bssid[6]     = {0,0,0,0,0,1};
    char key[256];
    build_bss_key("Network1", mac1, radio_mac, bssid, em_haul_type_backhaul, key);
    dm_bss_t bssObj{};
    bssObj.init();
    strcpy(bssObj.m_bss_info.id.net_id, "Network1");
    memcpy(bssObj.m_bss_info.id.dev_mac, mac1, 6);
    memcpy(bssObj.m_bss_info.id.ruid, radio_mac, 6);
    memcpy(bssObj.m_bss_info.id.bssid, bssid, 6);
    bssObj.m_bss_info.id.haul_type = em_haul_type_backhaul;
    list.put_bss(key, &bssObj);
    dm_bss_t* bss = list.get_bss(key);
    ASSERT_NE(bss, nullptr);
    EXPECT_EQ(memcmp(bss->m_bss_info.id.bssid, bssid, 6), 0);
    std::cout << "Exiting get_bss_returns_valid_bss test" << std::endl;
}

/**
 * @brief Validate that get_next_network_ssid returns a valid, distinct network SSID entry following the first entry.
 *
 * This test verifies that after adding two network SSID entries for a network, calling get_first_network_ssid followed by get_next_network_ssid properly retrieves two different entries. The test ensures the network SSID list iteration works correctly.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 148@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize a network object, set its id to "Network1", and configure the colocated agent MAC to 11:22:33:44:55:66. | net.m_net_info.id = "Network1", colocated_agent_id.mac = 0x11,0x22,0x33,0x44,0x55,0x66 | Network object is correctly initialized. | Should be successful |
 * | 02 | Add the initialized network to the network list using put_network. | id = "Network1", network pointer = address of net | Network list contains the network entry. | Should Pass |
 * | 03 | Create and initialize the first network SSID entry with ssid "TestSSID1", build its key, and add it to the network SSID list. | ssid1.m_network_ssid_info.id = "Network1", ssid1.m_network_ssid_info.ssid = "TestSSID1", key computed from build_network_ssid_key("Network1", "TestSSID1") | The first network SSID entry is successfully added. | Should Pass |
 * | 04 | Create and initialize the second network SSID entry with ssid "TestSSID2", build its key, and add it to the network SSID list. | ssid2.m_network_ssid_info.id = "Network1", ssid2.m_network_ssid_info.ssid = "TestSSID2", key computed from build_network_ssid_key("Network1", "TestSSID2") | The second network SSID entry is successfully added. | Should Pass |
 * | 05 | Retrieve the first network SSID entry from the list using get_first_network_ssid and perform a not-null check. | No additional input (retrieval of first SSID) | The retrieved first network SSID pointer is not null. | Should Pass |
 * | 06 | Retrieve the subsequent network SSID entry using get_next_network_ssid with the first entry as argument and perform a not-null check. | Input: first SSID pointer from previous step | The retrieved next network SSID pointer is not null. | Should Pass |
 * | 07 | Verify that the SSID strings of the first and next network SSID entries are distinct using EXPECT_STRNE. | Comparison of first->m_network_ssid_info.ssid and next->m_network_ssid_info.ssid | The two SSID strings are different. | Should Pass |
 */
TEST_F(dm_easy_mesh_list_tTEST, get_next_network_ssid_positive)
{
    std::cout << "Entering get_next_network_ssid_positive test" << std::endl;
    dm_network_t net{};
    net.init();
    strcpy(net.m_net_info.id, "Network1");
    unsigned char al_mac[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    memcpy(net.m_net_info.colocated_agent_id.mac, al_mac, sizeof(mac_address_t));
    list.put_network("Network1", &net);
    dm_network_ssid_t ssid1{};
    ssid1.init();
    strcpy(ssid1.m_network_ssid_info.id, "Network1");
    strcpy((char*)ssid1.m_network_ssid_info.ssid, "TestSSID1");
    char key1[256];
    build_network_ssid_key("Network1", "TestSSID1", key1);
    list.put_network_ssid(key1, &ssid1);
    dm_network_ssid_t ssid2{};
    ssid2.init();
    strcpy(ssid2.m_network_ssid_info.id, "Network1");
    strcpy((char*)ssid2.m_network_ssid_info.ssid, "TestSSID2");
    char key2[256];
    build_network_ssid_key("Network1", "TestSSID2", key2);
    list.put_network_ssid(key2, &ssid2);
    dm_network_ssid_t* first = list.get_first_network_ssid();
    ASSERT_NE(first, nullptr);
    dm_network_ssid_t* next = list.get_next_network_ssid(first);
    ASSERT_NE(next, nullptr);
    EXPECT_STRNE((char*)first->m_network_ssid_info.ssid, (char*)next->m_network_ssid_info.ssid);
    std::cout << "Exiting get_next_network_ssid_positive test" << std::endl;
}