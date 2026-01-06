/**
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
#include "ec_enrollee.h"

static ec_ops_t make_dummy_ops()
{
    ec_ops_t ops;
    ops.send_act_frame = [](uint8_t*, uint8_t*, size_t, unsigned int, unsigned int){ return false; };
    ops.get_backhaul_sta_info = [](uint8_t*) -> cJSON* { return nullptr; };
    ops.trigger_sta_scan = [](){ return false; };
    ops.bsta_connect = [](const std::string&, const std::string&, bssid_t){ return false; };
    ops.send_dir_encap_dpp = [](uint8_t*, size_t, uint8_t*){ return false; };
    ops.send_1905_eapol_encap = [](uint8_t*, size_t, uint8_t*){ return false; };
    ops.send_autoconf_search = [](em_dpp_chirp_value_t*, size_t){ return false; };
    ops.send_bss_config_req = [](uint8_t[ETH_ALEN]){ return false; };
    return ops;
}

/**
 * @brief Test that start_onboarding returns false when boot data is null.
 *
 * This test verifies that the ECEnrollee_t::start_onboarding API correctly handles the scenario where null boot data is provided.
 * The function is expected to return false, ensuring that the system does not proceed with onboarding in the absence of boot data.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 001
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke start_onboarding with null boot data on an EC enrollee object initialized with dummy operations and a valid MAC address. | force=false, boot_data=nullptr, secure=false, output=false | Function returns false and EXPECT_FALSE(res) assertion passes. | Should Pass |
 */
TEST(ECEnrollee_t, StartOnboarding_NullBootData)
{
    std::cout << "Entering StartOnboarding_NullBootData test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    bool res = enrollee.start_onboarding(false, nullptr, false);
    EXPECT_FALSE(res);
    std::cout << "Exiting StartOnboarding_NullBootData test" << std::endl;
}
/**
 * @brief Verify that the onboarding process fails when an unsupported bootstrapping version is provided.
 *
 * This test checks that when the boot_data structure is configured with an unsupported version value (version = 1), 
 * the start_onboarding method correctly returns false. This helps ensure that the enrollee does not initiate onboarding 
 * with invalid bootstrapping parameters.
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
 * | Variation / Step | Description                                                                              | Test Data                                                                                                                     | Expected Result                                    | Notes       |
 * | :--------------: | ---------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------- | ----------- |
 * | 01               | Create an ec_enrollee object with a valid MAC address and dummy operations; initialize boot_data with version = 1 and a specific MAC address value; then invoke start_onboarding with flags set to false. | mac_addr = "02:11:22:33:44:55", boot_data.version = 1, boot_data.mac_addr[0] = 0x02, flag1 = false, flag2 = false, output: res expected to be false | Return value false from start_onboarding and EXPECT_FALSE assertion passes | Should Pass |
 */
TEST(ECEnrollee_t, StartOnboarding_UnsupportedBootstrappingVersion)
{
    std::cout << "Entering StartOnboarding_UnsupportedBootstrappingVersion test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    ec_data_t boot_data{};
    memset(&boot_data, 0, sizeof(ec_data_t));
    boot_data.version = 1; // unsupported
    boot_data.mac_addr[0] = 0x02;
    bool res = enrollee.start_onboarding(false, &boot_data, false);
    EXPECT_FALSE(res);
    std::cout << "Exiting StartOnboarding_UnsupportedBootstrappingVersion test" << std::endl;
}
/**
 * @brief Test the start_onboarding API with a boot_data structure having an all-zero MAC address.
 *
 * This test verifies that invoking the start_onboarding method with a boot_data structure where the MAC address is left as all zeros
 * returns false. The enquiry confirms that the API does not process the onboarding operation when provided with an invalid boot_data structure.
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
 * | :----: | --------- | ---------- | -------------- | ----- |
 * | 01 | Invoke make_dummy_ops() to generate a dummy ec_ops_t structure. | No inputs | Dummy operations structure created. | Should be successful |
 * | 02 | Create an ec_enrollee_t instance using a valid MAC address and the dummy operations. | input: MAC = "02:11:22:33:44:55", ops = dummy_ops | Instance is created successfully. | Should be successful |
 * | 03 | Initialize an ec_data_t structure to zeros and set the version to 2. | input: boot_data = zeros, boot_data.version = 2 | Data structure is correctly initialized with zeros and version set. | Should be successful |
 * | 04 | Call start_onboarding with flags set to false and the boot_data containing an all-zero MAC address. | input: flag1 = false, input: boot_data pointer, input: flag2 = false | API returns false, confirmed by EXPECT_FALSE(res). | Should Fail |
 */
TEST(ECEnrollee_t, StartOnboarding_ZeroMacAddress)
{
    std::cout << "Entering StartOnboarding_ZeroMacAddress test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    ec_data_t boot_data{};
    memset(&boot_data, 0, sizeof(ec_data_t));
    boot_data.version = 2;
    // MAC left as all zeros
    bool res = enrollee.start_onboarding(false, &boot_data, false);
    EXPECT_FALSE(res);
    std::cout << "Exiting StartOnboarding_ZeroMacAddress test" << std::endl;
}
/**
 * @brief Test StartOnboarding with a null responder boot key to verify proper handling of invalid input
 *
 * This test verifies that the start_onboarding API call returns false when the responder_boot_key provided in the boot_data structure is nullptr. It ensures that the API correctly identifies the invalid boot key and fails the onboarding process.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 004@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize ec_enrollee and boot_data, then call start_onboarding with responder_boot_key set to nullptr | flag = false, boot_data.version = 2, boot_data.mac_addr[0] = 0x02, boot_data.responder_boot_key = nullptr | API returns false; ASSERT_FALSE verifies the false return value | Should Fail |
 */
TEST(ECEnrollee_t, StartOnboarding_NullResponderBootKey)
{
    std::cout << "Entering StartOnboarding_NullResponderBootKey test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    ec_data_t boot_data{};
    memset(&boot_data, 0, sizeof(ec_data_t));
    boot_data.version = 2;
    boot_data.mac_addr[0] = 0x02;
    boot_data.responder_boot_key = nullptr;
    bool res = enrollee.start_onboarding(false, &boot_data, false);
    EXPECT_FALSE(res);
    std::cout << "Exiting StartOnboarding_NullResponderBootKey test" << std::endl;
}
/**
 * @brief Verify that handle_auth_request returns false when provided with a null frame pointer.
 *
 * This test validates that the API correctly handles invalid input by passing a null frame pointer.
 * The function should safely return false without causing any unexpected behavior.
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
 * | Variation / Step | Description                                                               | Test Data                                                        | Expected Result                                                                 | Notes       |
 * | :--------------: | ------------------------------------------------------------------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke handle_auth_request with a null frame pointer to test error handling | frame = nullptr, length = 0, mac = 00:00:00:00:00:00, channel = 2412 | API returns false as verified by EXPECT_FALSE, confirming correct handling of null input | Should Fail |
 */
TEST(ECEnrollee_t, HandleAuthRequest_NullFrame)
{
    std::cout << "Entering HandleAuthRequest_NullFrame test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t mac[ETH_ALEN] = {0};
    bool res = enrollee.handle_auth_request(nullptr, 0, mac, 2412);
    EXPECT_FALSE(res);
    std::cout << "Exiting HandleAuthRequest_NullFrame test" << std::endl;
}
/**
 * @brief Verify that the authentication request handling fails when responder key hash is missing
 *
 * This test verifies that the handle_auth_request function correctly identifies an authentication request frame
 * that lacks the responder key hash attribute and returns false, ensuring that the system properly rejects incomplete
 * authentication requests.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 006@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                    | Test Data                                                                                                                       | Expected Result                                            | Notes      |
 * | :--------------: | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- | ---------- |
 * | 01               | Invoke handle_auth_request with a frame missing the responder key hash attribute | frame->category = 0x04, frame->action = 0x01, no responder key hash attribute, MAC = {02:11:22:33:44:55}, frame_size = sizeof(ec_frame_t)+16, channel = 2412 | API returns false; EXPECT_FALSE assertion passes           | Should Fail |
 */
TEST(ECEnrollee_t, HandleAuthRequest_MissingResponderKeyHash)
{
    std::cout << "Entering HandleAuthRequest_MissingResponderKeyHash test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t raw_buf[sizeof(ec_frame_t) + 16];
    memset(raw_buf, 0, sizeof(raw_buf));
    ec_frame_t* frame = reinterpret_cast<ec_frame_t*>(raw_buf);
    frame->category = 0x04;
    frame->action   = 0x01;
    // No attributes → responder key hash missing
    uint8_t mac[ETH_ALEN] = {0x02,0x11,0x22,0x33,0x44,0x55};
    bool res = enrollee.handle_auth_request(frame, sizeof(raw_buf), mac, 2412);
    EXPECT_FALSE(res);
    std::cout << "Exiting HandleAuthRequest_MissingResponderKeyHash test" << std::endl;
}
/**
 * @brief Test to validate that handle_auth_confirm properly handles a null frame pointer.
 *
 * This test verifies that when a null frame pointer is passed to the handle_auth_confirm API along with a zero length and a MAC address of all zeros, the function correctly returns false. This ensures that the enrollee's authentication confirmation process safely handles invalid input.
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
 * | Variation / Step | Description                                                         | Test Data                                           | Expected Result                                                                  | Notes         |
 * | :--------------: | ------------------------------------------------------------------- | --------------------------------------------------- | -------------------------------------------------------------------------------- | ------------- |
 * | 01               | Invoke handle_auth_confirm API with a null frame pointer, zero length, and a MAC address of zeros | frame = nullptr, length = 0, mac = 0,0,0,0,0,0 | Return value should be false; assertion EXPECT_FALSE verifies the condition | Should Pass   |
 */
TEST(ECEnrollee_t, HandleAuthConfirm_NullFrame)
{
    std::cout << "Entering HandleAuthConfirm_NullFrame test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t mac[ETH_ALEN] = {0};
    bool res = enrollee.handle_auth_confirm(nullptr, 0, mac);
    EXPECT_FALSE(res);
    std::cout << "Exiting HandleAuthConfirm_NullFrame test" << std::endl;
}
/**
 * @brief Verify that the Authorization Confirmation handler fails when the DPP status attribute is missing
 *
 * This test validates the behavior of the EC enrollee's handle_auth_confirm API when invoked with an EC frame that lacks the mandatory DPP status attribute.
 * The objective is to ensure that the API correctly identifies the absence of required attributes and safely returns a failure status.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 008@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                   | Test Data                                                                                                  | Expected Result                                                    | Notes       |
 * | :--------------: | --------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ | ----------- |
 * | 01               | Invoke handle_auth_confirm with an EC frame missing the DPP status attribute                    | frame->category = 0x04, frame->action = 0x02, raw buffer size = sizeof(ec_frame_t)+16, MAC = 02:11:22:33:44:55, no DPP status attribute present | The API returns false and the EXPECT_FALSE assertion passes         | Should Fail |
 */
TEST(ECEnrollee_t, HandleAuthConfirm_MissingStatusAttribute)
{
    std::cout << "Entering HandleAuthConfirm_MissingStatusAttribute test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t raw_buf[sizeof(ec_frame_t) + 16];
    memset(raw_buf, 0, sizeof(raw_buf));
    ec_frame_t* frame = reinterpret_cast<ec_frame_t*>(raw_buf);
    frame->category = 0x04;
    frame->action   = 0x02;
    // No attributes → missing DPP status
    uint8_t mac[ETH_ALEN] = {0x02,0x11,0x22,0x33,0x44,0x55};
    bool res = enrollee.handle_auth_confirm(frame, sizeof(raw_buf), mac);
    EXPECT_FALSE(res);
    std::cout << "Exiting HandleAuthConfirm_MissingStatusAttribute test" << std::endl;
}
/**
 * @brief Test the HandleAuthConfirm function with missing wrapped data
 *
 * This test verifies that the HandleAuthConfirm API returns a failure indication
 * when the authentication confirmation frame is missing the expected wrapped data.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 009@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                          | Test Data                                                                                                                                                                                         | Expected Result                                     | Notes       |
 * | :--------------: | ---------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- | ----------- |
 * | 01               | Invoke handle_auth_confirm API with a frame missing wrapped data to validate error handling behavior   | frame->category = 0x04, frame->action = 0x02, attr->attr_id = SWAP_LITTLE_ENDIAN(ec_attrib_id_dpp_status), attr->length = SWAP_LITTLE_ENDIAN(1), attr->data[0] = DPP_STATUS_OK, src_mac = 02:11:22:33:44:55, frame_len = EC_FRAME_BASE_SIZE + sizeof(ec_net_attribute_t) + 1 | API should return false based on the missing wrapped data scenario | Should Fail |
 */
TEST(ECEnrollee_t, HandleAuthConfirm_MissingWrappedData)
{
    std::cout << "Entering HandleAuthConfirm_MissingWrappedData test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t buffer[EC_FRAME_BASE_SIZE + sizeof(ec_net_attribute_t) + 1] = {};
    ec_frame_t* frame = reinterpret_cast<ec_frame_t*>(buffer);
    frame->category = 0x04;
    frame->action   = 0x02;
    auto* attr = reinterpret_cast<ec_net_attribute_t*>(frame->attributes);
    attr->attr_id = SWAP_LITTLE_ENDIAN(ec_attrib_id_dpp_status);
    attr->length  = SWAP_LITTLE_ENDIAN(1);
    attr->data[0] = DPP_STATUS_OK;
    uint8_t src_mac[ETH_ALEN] = {0x02,0x11,0x22,0x33,0x44,0x55};
    size_t frame_len = EC_FRAME_BASE_SIZE + sizeof(ec_net_attribute_t) + 1;
    bool ret = enrollee.handle_auth_confirm(frame, frame_len, src_mac);
    EXPECT_FALSE(ret);
    std::cout << "Exiting HandleAuthConfirm_MissingWrappedData test" << std::endl;
}
/**
 * @brief Verify that handle_config_response returns false when a null query response is provided.
 *
 * This test verifies that the handle_config_response method in the ECEnrollee_t class can properly handle a null pointer for the query response. The function is expected to return false in order to indicate an error in processing the null input.
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
 * | Variation / Step | Description                                                                              | Test Data                                                              | Expected Result                                          | Notes             |
 * | :--------------: | ---------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- | -------------------------------------------------------- | ----------------- |
 * | 01               | Initialize dummy operational parameters and create an ECEnrollee_t object with a MAC address. | input: ops = make_dummy_ops(), input: "02:11:22:33:44:55"              | Enrollee object is successfully created                | Should be successful |
 * | 02               | Prepare the source address array using predefined test data.                              | input: sa = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55}                          | Source address array is properly initialized             | Should be successful |
 * | 03               | Invoke handle_config_response with a null query response and check for false return.         | input: query response = nullptr, input: length = 10, input: sa as above  | Return value is false; assertion EXPECT_FALSE(result) is triggered | Should Pass       |
 */
TEST(ECEnrollee_t, HandleConfigResponse_NullQueryResp)
{
    std::cout << "Entering HandleConfigResponse_NullQueryResp test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t sa[ETH_ALEN] = {0x02,0x11,0x22,0x33,0x44,0x55};
    bool result = enrollee.handle_config_response(nullptr, 10, sa);
    EXPECT_FALSE(result);
    std::cout << "Exiting HandleConfigResponse_NullQueryResp test" << std::endl;
}
/**
 * @brief Verify that handle_config_response returns false when provided with a zero-length buffer
 *
 * This test checks the behavior of the ECEnrollee_t::handle_config_response function when the configuration response buffer length is zero.
 * The test initializes an enrollee object with dummy operations and a valid MAC address then calls the API with a zero-length configuration response.
 * The expected behavior is that the function should return false, indicating that the response is invalid or not processed.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 011@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                         | Test Data                                                                                         | Expected Result                                             | Notes      |
 * | :--------------: | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- | ---------- |
 * | 01               | Call handle_config_response with a zero-length configuration buffer   | buf = {0}, length = 0, sa = {0x02,0x11,0x22,0x33,0x44,0x55}                                        | API returns false, and EXPECT_FALSE(result) assertion passes | Should Pass |
 */
TEST(ECEnrollee_t, HandleConfigResponse_ZeroLength)
{
    std::cout << "Entering HandleConfigResponse_ZeroLength test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t buf[1] = {0};
    uint8_t sa[ETH_ALEN] = {0x02,0x11,0x22,0x33,0x44,0x55};
    bool result = enrollee.handle_config_response(buf, 0, sa);
    EXPECT_FALSE(result);
    std::cout << "Exiting HandleConfigResponse_ZeroLength test" << std::endl;
}
/**
 * @brief Test the handle_config_response API when DPP status is missing.
 *
 * This test verifies that the handle_config_response function of the ECEnrollee_t class
 * correctly handles the scenario when the DPP status is missing in the configuration response.
 * The function is expected to return false in this case.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 012@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                              | Test Data                                                                                  | Expected Result                                            | Notes          |
 * | :--------------: | ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ | ---------------------------------------------------------- | -------------- |
 * | 01               | Initialize dummy operations and create enrollee object using a given MAC address         | input: MAC = "02:11:22:33:44:55", ops = dummy operations                                     | Enrollee object successfully created                       | Should be successful |
 * | 02               | Prepare a buffer with missing DPP status                                                 | input: buf = {0, 0, 0, 0}                                                                    | Buffer initialized with missing status indicator           | Should be successful |
 * | 03               | Set up the source address array with the provided hardware address                         | input: sa = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55}                                             | Source address correctly configured                         | Should be successful |
 * | 04               | Invoke handle_config_response API with the prepared buffer and source address               | input: buf, buf size = 4; input: sa = {0x02,0x11,0x22,0x33,0x44,0x55}; output: result = false   | API returns false indicating configuration failure due to missing DPP status | Should Fail    |
 */
TEST(ECEnrollee_t, HandleConfigResponse_MissingStatus)
{
    std::cout << "Entering HandleConfigResponse_MissingStatus test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t buf[4] = {0};  // no DPP status
    uint8_t sa[ETH_ALEN] = {0x02,0x11,0x22,0x33,0x44,0x55};
    bool result = enrollee.handle_config_response(buf, sizeof(buf), sa);
    EXPECT_FALSE(result);
    std::cout << "Exiting HandleConfigResponse_MissingStatus test" << std::endl;
}
/**
 * @brief Validate that handle_config_response correctly handles unhandled DPP status codes.
 *
 * This test verifies that when the configuration response contains one of the unhandled DPP status codes
 * (DPP_STATUS_CONFIGURE_PENDING, DPP_STATUS_NEW_KEY_NEEDED, DPP_STATUS_CSR_BAD), the API handle_config_response
 * returns false. The test is essential to ensure that unexpected or unsupported status codes do not falsely pass
 * as valid configurations.
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
 * | Variation / Step | Description                                                                                         | Test Data                                                                                                                        | Expected Result                                                            | Notes      |
 * | :--------------: | --------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- | ---------- |
 * | 01               | Invoke handle_config_response with attr->data[0] set to DPP_STATUS_CONFIGURE_PENDING.              | input: attr->attr_id = ec_attrib_id_dpp_status, length = 1, data[0] = DPP_STATUS_CONFIGURE_PENDING, buf size = sizeof(buf), sa = "02:11:22:33:44:55" | API returns false; EXPECT_FALSE(result)                                    | Should Fail |
 * | 02               | Invoke handle_config_response with attr->data[0] set to DPP_STATUS_NEW_KEY_NEEDED.                   | input: attr->attr_id = ec_attrib_id_dpp_status, length = 1, data[0] = DPP_STATUS_NEW_KEY_NEEDED, buf size = sizeof(buf), sa = "02:11:22:33:44:55"  | API returns false; EXPECT_FALSE(result)                                    | Should Fail |
 * | 03               | Invoke handle_config_response with attr->data[0] set to DPP_STATUS_CSR_BAD.                          | input: attr->attr_id = ec_attrib_id_dpp_status, length = 1, data[0] = DPP_STATUS_CSR_BAD, buf size = sizeof(buf), sa = "02:11:22:33:44:55"         | API returns false; EXPECT_FALSE(result)                                    | Should Fail |
 */
TEST(ECEnrollee_t, HandleConfigResponse_UnhandledStatus) 
{
    std::cout << "Entering HandleConfigResponse_UnhandledStatus test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t sa[ETH_ALEN] = {0x02,0x11,0x22,0x33,0x44,0x55};
    for (auto status : {DPP_STATUS_CONFIGURE_PENDING, DPP_STATUS_NEW_KEY_NEEDED, DPP_STATUS_CSR_BAD}) {
        uint8_t buf[sizeof(ec_net_attribute_t) + 1];
        ec_net_attribute_t* attr = reinterpret_cast<ec_net_attribute_t*>(buf);
        attr->attr_id = ec_attrib_id_dpp_status;
        attr->length  = 1;
        attr->data[0] = static_cast<uint8_t>(status);
        bool result = enrollee.handle_config_response(buf, sizeof(buf), sa);
        EXPECT_FALSE(result);
    }
    std::cout << "Exiting HandleConfigResponse_UnhandledStatus test" << std::endl;
}
/**
 * @brief Validate that the enrollee correctly handles a configuration response with missing wrapped data
 *
 * This test verifies that when the configuration response is missing the expected wrapped data structure, the
 * handle_config_response API returns false, indicating an error in processing the incomplete response.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 014@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                   | Test Data                                                                                                                                                                       | Expected Result                                                                                                      | Notes       |
 * | :--------------: | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ----------- |
 * | 01               | Initialize a dummy operator, construct an enrollee, set up a network attribute with minimal data, and call handle_config_response with a buffer missing wrapped data. | input: ops = make_dummy_ops(), enrollee MAC = "02:11:22:33:44:55", buffer containing ec_net_attribute_t with attr_id = ec_attrib_id_dpp_status, length = 1, data[0] = DPP_STATUS_OK, buffer size = sizeof(ec_net_attribute_t) + 1, sa = {0x02,0x11,0x22,0x33,0x44,0x55} | API returns false; assertion EXPECT_FALSE(result) passes, indicating the API correctly detects missing wrapped data. | Should Fail |
 */
TEST(ECEnrollee_t, HandleConfigResponse_MissingWrappedData) 
{
    std::cout << "Entering HandleConfigResponse_MissingWrappedData test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t sa[ETH_ALEN] = {0x02,0x11,0x22,0x33,0x44,0x55};
    uint8_t buf[sizeof(ec_net_attribute_t) + 1];
    ec_net_attribute_t* attr = reinterpret_cast<ec_net_attribute_t*>(buf);
    attr->attr_id = ec_attrib_id_dpp_status;
    attr->length  = 1;
    attr->data[0] = DPP_STATUS_OK;
    bool result = enrollee.handle_config_response(buf, sizeof(buf), sa);
    EXPECT_FALSE(result);
    std::cout << "Exiting HandleConfigResponse_MissingWrappedData test" << std::endl;
}
/**
 * @brief Verify that handle_gas_comeback_response correctly handles a NULL frame
 *
 * This test ensures that when a NULL frame is provided to the handle_gas_comeback_response API, the function returns false, indicating correct error handling.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 015@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                      | Test Data                                                         | Expected Result                                      | Notes      |
 * | :--------------: | ---------------------------------------------------------------- | ----------------------------------------------------------------- | ----------------------------------------------------- | ---------- |
 * | 01               | Invoke handle_gas_comeback_response with a NULL frame pointer      | frame = nullptr, frame_length = 0, mac = {0,0,0,0,0,0}              | Returns false; EXPECT_FALSE(res) assertion passes     | Should Pass |
 */
TEST(ECEnrollee_t, HandleGasComebackResponse_NullFrame) 
{
    std::cout << "Entering HandleGasComebackResponse_NullFrame test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t mac[ETH_ALEN] = {0};
    bool res = enrollee.handle_gas_comeback_response(nullptr, 0, mac);
    EXPECT_FALSE(res);
    std::cout << "Exiting HandleGasComebackResponse_NullFrame test" << std::endl;
}
/**
 * @brief This test verifies that the handle_gas_comeback_response function correctly handles a zero-length frame.
 *
 * This test creates an ec_enrollee object with a valid MAC address and dummy operations, then invokes the
 * handle_gas_comeback_response function with a frame buffer of the appropriate size but with a frame length set to zero.
 * The expected behavior is that the function returns false, indicating that it has properly handled the invalid (zero-length) input.
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
 * | Variation / Step | Description                                                                                               | Test Data                                                                                                   | Expected Result                                                       | Notes         |
 * | :--------------: | --------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | ------------- |
 * | 01               | Create a dummy operations object and an ec_enrollee with a valid MAC, then invoke the API with zero frame length | ec_ops_t ops = make_dummy_ops(), ec_enrollee MAC = "02:11:22:33:44:55", frame length = 0, dummy_mac = 0,0,0,0,0,0 | API returns false and EXPECT_FALSE(result) assertion passes             | Should Pass   |
 */
TEST(ECEnrollee_t, HandleGasComebackResponse_ZeroFrameLength) 
{
    std::cout << "Entering HandleGasComebackResponse_ZeroFrameLength test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t ec_enrollee("02:11:22:33:44:55", ops);
    uint8_t frame_buf[sizeof(ec_gas_comeback_response_frame_t)] = {0};
    ec_gas_comeback_response_frame_t* frame = (ec_gas_comeback_response_frame_t*)frame_buf;
    uint8_t dummy_mac[6] = {0};
    bool result = ec_enrollee.handle_gas_comeback_response(frame, 0, dummy_mac);
    EXPECT_FALSE(result);
    std::cout << "Exiting HandleGasComebackResponse_ZeroFrameLength test" << std::endl;
}
/**
 * @brief Validate that the enrollee correctly rejects a GAS comeback response when the fragment ID mismatches
 *
 * This test verifies that when a GAS comeback response frame is received with a fragment ID that does not match
 * the expected value, the enrollee rejects the response by returning false. It ensures that the API correctly detects
 * the mismatch between the expected and received fragment IDs.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 017@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01 | Create a dummy operations instance, initialize the enrollee object, prepare a GAS comeback response frame with a mismatched fragment ID, and invoke handle_gas_comeback_response API | ops = make_dummy_ops(), enrollee = ec_enrollee_t("02:11:22:33:44:55", ops), frame: dialog_token = 1, fragment_id = 1, more_fragments = 0, comeback_resp_len = 1, comeback_resp[0] = 0xAA, mac = {0x02,0x11,0x22,0x33,0x44,0x55} | The API should return false as the fragment ID does not match the expected value | Should Fail |
 */
TEST(ECEnrollee_t, HandleGasComebackResponse_FragmentIdMismatch)
{
    std::cout << "Entering HandleGasComebackResponse_FragmentIdMismatch test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t raw[sizeof(ec_gas_comeback_response_frame_t) + 4];
    memset(raw, 0, sizeof(raw));
    ec_gas_comeback_response_frame_t* frame = reinterpret_cast<ec_gas_comeback_response_frame_t*>(raw);
    frame->base.dialog_token = 1;
    frame->fragment_id = 1; // mismatch: expected 0
    frame->more_fragments = 0;
    frame->comeback_resp_len = 1;
    frame->comeback_resp[0] = 0xAA;
    uint8_t mac[ETH_ALEN] = {0x02,0x11,0x22,0x33,0x44,0x55};
    bool res = enrollee.handle_gas_comeback_response(frame, sizeof(raw), mac);
    EXPECT_FALSE(res);
    std::cout << "Exiting HandleGasComebackResponse_FragmentIdMismatch test" << std::endl;
}
/**
 * @brief Verify that handle_gas_initial_response properly handles a null frame pointer.
 *
 * This test verifies that the handle_gas_initial_response method returns false when provided with a null frame pointer,
 * ensuring that the enrollee correctly identifies and handles invalid input.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create dummy operations and enrollee instance | input: MAC = "02:11:22:33:44:55", ops = make_dummy_ops() | Enrollee instance is created successfully | Should be successful |
 * | 02 | Setup MAC address variable with zeros | input: mac = {0,0,0,0,0,0} | MAC array is initialized to zeros | Should be successful |
 * | 03 | Invoke handle_gas_initial_response with null frame pointer | input: frame = nullptr, length = 0, mac = {0,0,0,0,0,0} | Function returns false | Should Pass |
 */
TEST(ECEnrollee_t, HandleGasInitialResponse_NullFrame) 
{
    std::cout << "Entering HandleGasInitialResponse_NullFrame test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t mac[ETH_ALEN] = {0};
    EXPECT_FALSE(enrollee.handle_gas_initial_response(nullptr, 0, mac));
    std::cout << "Exiting HandleGasInitialResponse_NullFrame test" << std::endl;
}
/**
 * @brief Tests the gas initial response handler with an invalid configuration.
 *
 * This test case validates that the API handle_gas_initial_response correctly handles an invalid configuration.
 * It creates a dummy operational structure and an EC enrollee instance, then sets up an invalid gas initial response frame.
 * The frame is deliberately configured with zero gas_comeback_delay and a preset response length, combined with a MAC address,
 * to simulate an error condition. The expected result is that the function returns false, indicating invalid input processing.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize dummy operations and create an EC enrollee instance, then prepare an invalid gas initial response frame with gas_comeback_delay set to 0 and resp_len to 4, and finally invoke handle_gas_initial_response with these parameters. | ops = make_dummy_ops(), enrollee with MAC "02:11:22:33:44:55", frame->gas_comeback_delay = 0, frame->resp_len = 4, raw payload = all zeros, mac = {0x02,0x11,0x22,0x33,0x44,0x55} | API returns false indicating that the invalid configuration is correctly rejected. | Should Fail |
 */
TEST(ECEnrollee_t, HandleGasInitialResponse_InvalidConfig) 
{
    std::cout << "Entering HandleGasInitialResponse_InvalidConfig test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    constexpr size_t RESP_LEN = 4;
    uint8_t raw[sizeof(ec_gas_initial_response_frame_t) + RESP_LEN] = {};
    auto* frame = reinterpret_cast<ec_gas_initial_response_frame_t*>(raw);
    frame->gas_comeback_delay = 0;
    frame->resp_len = RESP_LEN;
    memset(raw + sizeof(ec_gas_initial_response_frame_t), 0, RESP_LEN);
    uint8_t mac[ETH_ALEN] = {0x02,0x11,0x22,0x33,0x44,0x55};
    EXPECT_FALSE(enrollee.handle_gas_initial_response(frame, sizeof(raw), mac));
    std::cout << "Exiting HandleGasInitialResponse_InvalidConfig test" << std::endl;
}
/**
 * @brief Tests the handle_recfg_auth_request function with a null frame input.
 *
 * This test verifies that the handle_recfg_auth_request function correctly handles a null frame pointer by returning false. It ensures that the API behaves as expected when provided with invalid input data.
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
 * | Variation / Step | Description                                                                  | Test Data                                                       | Expected Result                                      | Notes             |
 * | :---------------: | ---------------------------------------------------------------------------- | --------------------------------------------------------------- | ---------------------------------------------------- | ----------------- |
 * | 01                | Initialize dummy operations and create an ECEnrollee instance with valid MAC   | ops = value from make_dummy_ops(), enrollee MAC = "02:11:22:33:44:55" | ECEnrollee_t instance created successfully           | Should be successful |
 * | 02                | Call handle_recfg_auth_request with a null frame pointer                       | frame = nullptr, frame_len = 0, mac = 00:00:00:00:00:00            | API returns false as the null frame is handled correctly | Should Pass       |
 */
TEST(ECEnrollee_t, HandleRecfgAuthRequest_NullFrame)
{
    std::cout << "Entering HandleRecfgAuthRequest_NullFrame test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t mac[ETH_ALEN] = {0};
    EXPECT_FALSE(enrollee.handle_recfg_auth_request(nullptr, 0, mac));
    std::cout << "Exiting HandleRecfgAuthRequest_NullFrame test" << std::endl;
}
/**
 * @brief Verify that handle_recfg_auth_request returns false when protocol attribute is missing
 *
 * This test verifies that when the EC enrollee's handle_recfg_auth_request method is invoked with a raw frame that contains only a transaction ID attribute and lacks the protocol attribute, the API returns false. This ensures that the absence of critical protocol parameters is correctly handled.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 021@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                       | Test Data                                                                                                                                | Expected Result                                | Notes            |
 * | :--------------: | ------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------- | ---------------- |
 * | 01               | Initialize dummy operations and create an EC enrollee object with a given MAC address             | ops = make_dummy_ops(), enrollee MAC = "02:11:22:33:44:55"                                                                                | Object initialization is successful             | Should be successful |
 * | 02               | Prepare a raw frame buffer with only the transaction ID attribute (protocol attribute is missing) | raw buffer size = sizeof(ec_frame_t)+4+1, trans_id_attr->attr_id = SWAP_LITTLE_ENDIAN(ec_attrib_id_trans_id), length = SWAP_LITTLE_ENDIAN(1), data[0] = 1  | Raw frame is correctly populated                 | Should be successful |
 * | 03               | Invoke handle_recfg_auth_request using the prepared frame and MAC address                           | frame pointer = raw, size = sizeof(raw), mac = {0x02,0x11,0x22,0x33,0x44,0x55}                                                              | API returns false as the protocol attribute is missing | Should Pass       |
 */
TEST(ECEnrollee_t, HandleRecfgAuthRequest_NoProtocolAttribute) 
{
    std::cout << "Entering HandleRecfgAuthRequest_NoProtocolAttribute test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t raw[sizeof(ec_frame_t) + 4 + 1] = {};
    ec_frame_t* frame = reinterpret_cast<ec_frame_t*>(raw);
    // Transaction ID attribute
    ec_net_attribute_t* trans_id_attr = reinterpret_cast<ec_net_attribute_t*>(raw + sizeof(ec_frame_t));
    trans_id_attr->attr_id = SWAP_LITTLE_ENDIAN(ec_attrib_id_trans_id);
    trans_id_attr->length = SWAP_LITTLE_ENDIAN(1);
    trans_id_attr->data[0] = 1;
    uint8_t mac[ETH_ALEN] = {0x02,0x11,0x22,0x33,0x44,0x55};
    EXPECT_FALSE(enrollee.handle_recfg_auth_request(frame, sizeof(raw), mac));
    std::cout << "Exiting HandleRecfgAuthRequest_NoProtocolAttribute test" << std::endl;
}
/**
 * @brief Validate that the recfg auth request is rejected when the protocol version is too low
 *
 * This test verifies that when the protocol version provided in the configuration request is below the minimum required value, the enrollee correctly rejects the reconfiguration authentication request. It ensures that improper protocol versions are not accepted, preserving protocol integrity.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Initialize test data including dummy operations, enrollee instance, and network frame with attributes (transaction ID, configuration nonce, protocol version set to 1, dpp connector) | ops = dummy, enrollee MAC = 02:11:22:33:44:55, transaction ID = 1, config nonce = 0xAB, protocol version = 1, dpp connector = 0xAA | Payload constructed with the expected attribute values | Should be successful |
 * | 02 | Invoke handle_recfg_auth_request API and verify that the request is rejected due to low protocol version | frame pointer = raw, frame size = sizeof(raw), mac = 02:11:22:33:44:55 | Expected return value: false, assertion: EXPECT_FALSE returned false | Should Fail |
 */
TEST(ECEnrollee_t, HandleRecfgAuthRequest_ProtocolVersionTooLow)
{
    std::cout << "Entering HandleRecfgAuthRequest_ProtocolVersionTooLow test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t raw[sizeof(ec_frame_t) + 5 + 5 + 5 + 5] = {}; // 4 attributes
    ec_frame_t* frame = reinterpret_cast<ec_frame_t*>(raw);
    uint8_t* ptr = raw + sizeof(ec_frame_t);
    // Transaction ID attribute
    ec_net_attribute_t* trans_id_attr = reinterpret_cast<ec_net_attribute_t*>(ptr);
    trans_id_attr->attr_id = SWAP_LITTLE_ENDIAN(ec_attrib_id_trans_id);
    trans_id_attr->length = SWAP_LITTLE_ENDIAN(1);
    trans_id_attr->data[0] = 1;
    ptr += sizeof(ec_net_attribute_t) + 1;
    // Configuration Nonce attribute
    ec_net_attribute_t* nonce_attr = reinterpret_cast<ec_net_attribute_t*>(ptr);
    nonce_attr->attr_id = SWAP_LITTLE_ENDIAN(ec_attrib_id_config_nonce);
    nonce_attr->length = SWAP_LITTLE_ENDIAN(1);
    nonce_attr->data[0] = 0xAB; // dummy nonce byte
    ptr += sizeof(ec_net_attribute_t) + 1;
    // Protocol version attribute (too low)
    ec_net_attribute_t* proto_attr = reinterpret_cast<ec_net_attribute_t*>(ptr);
    proto_attr->attr_id = SWAP_LITTLE_ENDIAN(ec_attrib_id_proto_version);
    proto_attr->length = SWAP_LITTLE_ENDIAN(1);
    proto_attr->data[0] = 1; // version < 2
    ptr += sizeof(ec_net_attribute_t) + 1;
    // DPP Connector attribute (dummy data)
    ec_net_attribute_t* dpp_attr = reinterpret_cast<ec_net_attribute_t*>(ptr);
    dpp_attr->attr_id = SWAP_LITTLE_ENDIAN(ec_attrib_id_dpp_connector);
    dpp_attr->length = SWAP_LITTLE_ENDIAN(1);
    dpp_attr->data[0] = 0xAA; // dummy connector byte
    uint8_t mac[ETH_ALEN] = {0x02,0x11,0x22,0x33,0x44,0x55};
    EXPECT_FALSE(enrollee.handle_recfg_auth_request(frame, sizeof(raw), mac));
    std::cout << "Exiting HandleRecfgAuthRequest_ProtocolVersionTooLow test" << std::endl;
}
/**
 * @brief Verify that handle_recfg_auth_request correctly handles a frame missing the transaction ID.
 *
 * This test verifies that the handle_recfg_auth_request API properly returns false when the received
 * frame does not include the mandatory transaction ID attribute. The test sets up the frame with only
 * the protocol version attribute and then asserts the expected failure behavior.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 023@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize dummy operations and create enrollee object with specified MAC address | MAC = "02:11:22:33:44:55", ops = make_dummy_ops() | Enrollee object is successfully created | Should be successful |
 * | 02 | Prepare the frame containing only the protocol version attribute and omit the transaction ID | raw frame with proto_attr->attr_id = ec_attrib_id_proto_version, proto_attr->length = 1, proto_attr->data[0] = 2 | Frame is configured without the transaction ID | Should be successful |
 * | 03 | Invoke handle_recfg_auth_request API with the prepared frame and MAC address | frame pointer, size = sizeof(raw), mac = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55} | API returns false indicating missing transaction ID | Should Pass |
 */
TEST(ECEnrollee_t, HandleRecfgAuthRequest_MissingTransactionID)
{
    std::cout << "Entering HandleRecfgAuthRequest_MissingTransactionID test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t raw[EC_FRAME_BASE_SIZE + sizeof(ec_net_attribute_t) + 1] = {};
    auto* frame = reinterpret_cast<ec_frame_t*>(raw);
    // Only proto version attribute, no transaction ID
    ec_net_attribute_t* proto_attr = reinterpret_cast<ec_net_attribute_t*>(frame->attributes);
    proto_attr->attr_id = SWAP_LITTLE_ENDIAN(static_cast<uint16_t>(ec_attrib_id_proto_version));
    proto_attr->length = SWAP_LITTLE_ENDIAN(1);
    proto_attr->data[0] = 2;
    uint8_t mac[ETH_ALEN] = {0x02,0x11,0x22,0x33,0x44,0x55};
    EXPECT_FALSE(enrollee.handle_recfg_auth_request(frame, sizeof(raw), mac));
    std::cout << "Exiting HandleRecfgAuthRequest_MissingTransactionID test" << std::endl;
}
/**
 * @brief Test handling of reconfiguration authorization request when C-connector is missing
 *
 * This test verifies that the EC enrollee correctly handles the reconfiguration authorization 
 * request by returning false when the mandatory C-connector attribute is missing from the frame.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |  
 * | :----: | --------- | ---------- | -------------- | ----- |  
 * | 01 | Create a dummy operations object and initialise an EC enrollee instance with MAC "02:11:22:33:44:55" | input: ops = make_dummy_ops(), enrollee MAC = "02:11:22:33:44:55" | EC enrollee object is created successfully | Should be successful |  
 * | 02 | Prepare the frame by setting the transaction ID and protocol version attributes | input: tid_attr: attr_id = SWAP_LITTLE_ENDIAN(ec_attrib_id_trans_id), length = 1, data = 0x42; proto_attr: attr_id = SWAP_LITTLE_ENDIAN(ec_attrib_id_proto_version), length = 1, data = 2 | Frame attributes are correctly assigned | Should be successful |  
 * | 03 | Invoke handle_recfg_auth_request API with a frame missing the C-connector attribute | input: frame pointer (raw), frame size = sizeof(raw), mac = {0x02,0x11,0x22,0x33,0x44,0x55} | API returns false; EXPECT_FALSE assertion passes | Should Fail |
 */
TEST(ECEnrollee_t, HandleRecfgAuthRequest_MissingCConnector)
{
    std::cout << "Entering HandleRecfgAuthRequest_MissingCConnector test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t raw[EC_FRAME_BASE_SIZE + 2*sizeof(ec_net_attribute_t) + 2] = {};
    auto* frame = reinterpret_cast<ec_frame_t*>(raw);
    // Transaction ID
    ec_net_attribute_t* tid_attr = reinterpret_cast<ec_net_attribute_t*>(frame->attributes);
    tid_attr->attr_id = SWAP_LITTLE_ENDIAN(static_cast<uint16_t>(ec_attrib_id_trans_id));
    tid_attr->length = SWAP_LITTLE_ENDIAN(1);
    tid_attr->data[0] = 0x42;
    // Protocol version
    ec_net_attribute_t* proto_attr = reinterpret_cast<ec_net_attribute_t*>(
        reinterpret_cast<uint8_t*>(tid_attr) + sizeof(ec_net_attribute_t) + 1);
    proto_attr->attr_id = SWAP_LITTLE_ENDIAN(static_cast<uint16_t>(ec_attrib_id_proto_version));
    proto_attr->length = SWAP_LITTLE_ENDIAN(1);
    proto_attr->data[0] = 2;
    // Missing c-connector
    uint8_t mac[ETH_ALEN] = {0x02,0x11,0x22,0x33,0x44,0x55};
    EXPECT_FALSE(enrollee.handle_recfg_auth_request(frame, sizeof(raw), mac));
    std::cout << "Exiting HandleRecfgAuthRequest_MissingCConnector test" << std::endl;
}
/**
 * @brief Verify that handle_recfg_auth_confirm properly handles a null frame pointer.
 *
 * This test verifies that the method handle_recfg_auth_confirm returns false when provided with a null frame pointer. The test ensures that the system correctly identifies and handles an invalid (null) frame input without processing any further data.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 025
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                         | Test Data                                              | Expected Result                                        | Notes      |
 * | :--------------: | ------------------------------------------------------------------- | ------------------------------------------------------ | ------------------------------------------------------ | ---------- |
 * | 01               | Invoke handle_recfg_auth_confirm with a null frame pointer and valid MAC address | frame = nullptr, length = 0, mac = {0,0,0,0,0,0}       | Returns: false; Assertion: EXPECT_FALSE passes         | Should Pass|
 */
TEST(ECEnrollee_t, HandleRecfgAuthConfirm_NullFrame)
{
    std::cout << "Entering HandleRecfgAuthConfirm_NullFrame test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t mac[ETH_ALEN] = {0};
    EXPECT_FALSE(enrollee.handle_recfg_auth_confirm(nullptr, 0, mac));
    std::cout << "Exiting HandleRecfgAuthConfirm_NullFrame test" << std::endl;
}
/**
 * @brief Verify that handle_recfg_auth_confirm returns false when DPP status attribute is missing.
 *
 * This test creates an enrollee instance with dummy operations and a valid MAC address, then prepares a frame with no attributes provided.
 * It verifies that the handle_recfg_auth_confirm API returns false due to the missing DPP status in the frame.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 026@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01 | Initialize dummy operations, create an enrollee instance with a valid MAC, prepare an empty frame (i.e., missing DPP status), and invoke handle_recfg_auth_confirm. | input: frame pointer = pointer to ec_frame_t with empty attributes, frame length = sizeof(raw), MAC = {0} | API returns false (i.e., EXPECT_FALSE returns true) | Should Pass |
 */
TEST(ECEnrollee_t, HandleRecfgAuthConfirm_MissingDppStatus)
{
    std::cout << "Entering HandleRecfgAuthConfirm_MissingDppStatus test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t raw[sizeof(ec_frame_t)] = {}; // No attributes
    ec_frame_t* frame = reinterpret_cast<ec_frame_t*>(raw);
    uint8_t mac[ETH_ALEN] = {0};
    EXPECT_FALSE(enrollee.handle_recfg_auth_confirm(frame, sizeof(raw), mac));
    std::cout << "Exiting HandleRecfgAuthConfirm_MissingDppStatus test" << std::endl;
}
/**
 * @brief Test handle_recfg_auth_confirm API for missing wrapped data scenario.
 *
 * This test verifies that handle_recfg_auth_confirm returns false when the provided frame lacks wrapped data, ensuring the function handles missing data gracefully.@n
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke handle_recfg_auth_confirm with a frame missing wrapped data | frame = pointer to ec_frame_t (constructed with a valid status attribute but missing wrapped data), frame_size = sizeof(raw), mac = {0} | API returns false; EXPECT_FALSE assertion passes | Should Fail |
 */
TEST(ECEnrollee_t, HandleRecfgAuthConfirm_MissingWrappedData)
{
    std::cout << "Entering HandleRecfgAuthConfirm_MissingWrappedData test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t raw[sizeof(ec_frame_t) + 5] = {};
    ec_frame_t* frame = reinterpret_cast<ec_frame_t*>(raw);
    ec_net_attribute_t* status_attr = reinterpret_cast<ec_net_attribute_t*>(raw + sizeof(ec_frame_t));
    status_attr->attr_id = SWAP_LITTLE_ENDIAN(ec_attrib_id_dpp_status);
    status_attr->length = SWAP_LITTLE_ENDIAN(1);
    status_attr->data[0] = DPP_STATUS_OK;
    uint8_t mac[ETH_ALEN] = {0};
    EXPECT_FALSE(enrollee.handle_recfg_auth_confirm(frame, sizeof(raw), mac));
    std::cout << "Exiting HandleRecfgAuthConfirm_MissingWrappedData test" << std::endl;
}
/**
 * @brief Validates that process_direct_encap_dpp_msg correctly handles a null frame input.
 *
 * This test verifies that when process_direct_encap_dpp_msg is invoked with a null frame pointer, the API returns false. It ensures proper error handling when an invalid (null) frame is provided.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 028
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                        | Test Data                                                     | Expected Result                                                         | Notes      |
 * | :--------------: | ------------------------------------------------------------------ | ------------------------------------------------------------- | ----------------------------------------------------------------------- | ---------- |
 * | 01               | Invoke process_direct_encap_dpp_msg with a null frame pointer and verify return value | frame = nullptr, length = 10, mac = "02:11:22:33:44:55"       | The API returns false as asserted by EXPECT_FALSE                      | Should Pass |
 */
TEST(ECEnrollee_t, ProcessDirectEncapDppMsg_NullFrame)
{
    std::cout << "Entering ProcessDirectEncapDppMsg_NullFrame test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t mac[ETH_ALEN] = {0x02,0x11,0x22,0x33,0x44,0x55};
    EXPECT_FALSE(enrollee.process_direct_encap_dpp_msg(nullptr, 10, mac));
    std::cout << "Exiting ProcessDirectEncapDppMsg_NullFrame test" << std::endl;
}
/**
 * @brief Validate that process_direct_encap_dpp_msg returns false for a zero-length frame
 *
 * This test ensures that the API process_direct_encap_dpp_msg handles an empty (zero-length) frame correctly by returning false. It verifies proper error handling when an invalid frame length is provided.
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
 * | Variation / Step | Description                                                        | Test Data                                                                                   | Expected Result                                                   | Notes       |
 * | :--------------: | ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- | ----------- |
 * | 01               | Invoke process_direct_encap_dpp_msg with a zero-length frame         | dummy_frame = [0,0,0,0,0,0,0,0,0,0], length = 0, mac = [0x02,0x11,0x22,0x33,0x44,0x55]    | The function should return false and the assertion EXPECT_FALSE passes | Should Fail |
 */
TEST(ECEnrollee_t, ProcessDirectEncapDppMsg_ZeroLengthFrame)
{
    std::cout << "Entering ProcessDirectEncapDppMsg_ZeroLengthFrame test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t dummy_frame[10] = {};
    uint8_t mac[ETH_ALEN] = {0x02,0x11,0x22,0x33,0x44,0x55};
    EXPECT_FALSE(enrollee.process_direct_encap_dpp_msg(dummy_frame, 0, mac));
    std::cout << "Exiting ProcessDirectEncapDppMsg_ZeroLengthFrame test" << std::endl;
}
/**
 * @brief Verify that process_direct_encap_dpp_msg returns false for a GAS frame scenario
 *
 * This test verifies that the process_direct_encap_dpp_msg function correctly identifies a GAS frame and returns false. The test creates a dummy enrollee with a specific MAC address, prepares a frame with the GAS action, and then calls the API. The expected behavior is that the API returns false indicating a failure to process a GAS frame as intended.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 030@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create dummy operations and enrollee instance with a specific MAC address | input: ops = make_dummy_ops(), enrollee MAC = "02:11:22:33:44:55" | Enrollee object is successfully created | Should be successful |
 * | 02 | Prepare frame with GAS initial request action | input: frame action = dpp_gas_initial_req, frame size = sizeof(ec_frame_t) | Frame is prepared with the GAS action set | Should be successful |
 * | 03 | Call process_direct_encap_dpp_msg with the prepared frame and MAC address | input: frame pointer to frame, frame size = sizeof(frame), mac = {0x02,0x11,0x22,0x33,0x44,0x55} | API returns false indicating GAS frame failure | Should Fail |
 */
TEST(ECEnrollee_t, ProcessDirectEncapDPPMsg_GasFrameFailure)
{
    std::cout << "Entering ProcessDirectEncapDPPMsg_GasFrameFailure test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t frame[sizeof(ec_frame_t)] = {};
    ec_frame_t* ec_frame = reinterpret_cast<ec_frame_t*>(frame);
    ec_frame->action = dpp_gas_initial_req; // GAS action
    uint8_t mac[ETH_ALEN] = {0x02,0x11,0x22,0x33,0x44,0x55};
    EXPECT_FALSE(enrollee.process_direct_encap_dpp_msg(frame, sizeof(frame), mac));
    std::cout << "Exiting ProcessDirectEncapDPPMsg_GasFrameFailure test" << std::endl;
}
/**
 * @brief Test that process_direct_encap_dpp_msg returns false for an unhandled frame type
 *
 * This test creates an ec_enrollee object using dummy operations and sets up a frame with an invalid frame type.
 * It then calls process_direct_encap_dpp_msg with a specific MAC address and verifies that the function returns false,
 * indicating that the invalid/unsupported frame type is correctly unhandled.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 031
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize ec_enrollee with dummy operations, set up a frame with an invalid frame type (99), and invoke process_direct_encap_dpp_msg with a given MAC address | input: frame_type = 99, enrollee MAC = "02:11:22:33:44:55", dummy ops from make_dummy_ops; output: expected return value from process_direct_encap_dpp_msg is false | The process_direct_encap_dpp_msg function returns false and the EXPECT_FALSE assertion passes | Should Pass |
 */
TEST(ECEnrollee_t, ProcessDirectEncapDPPMsg_UnhandledFrameType)
{
    std::cout << "Entering ProcessDirectEncapDPPMsg_UnhandledFrameType test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t frame[sizeof(ec_frame_t)] = {};
    ec_frame_t* ec_frame = reinterpret_cast<ec_frame_t*>(frame);
    ec_frame->frame_type = 99; // invalid frame type
    uint8_t mac[ETH_ALEN] = {0x02,0x11,0x22,0x33,0x44,0x55};
    EXPECT_FALSE(enrollee.process_direct_encap_dpp_msg(frame, sizeof(frame), mac));
    std::cout << "Exiting ProcessDirectEncapDPPMsg_UnhandledFrameType test" << std::endl;
}
/**
 * @brief Verify that processing a direct encapsulated DPP message fails when the frame type corresponds to Peer Discovery Response.
 *
 * This unit test ensures that the ec_enrollee_t's process_direct_encap_dpp_msg method correctly returns false when a frame with
 * a Peer Discovery Response type is processed. This negative test case confirms that the enrollee handles unexpected message types appropriately.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 032
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                              | Test Data                                                                                                | Expected Result                                                  | Notes               |
 * | :----:           | ---------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- | ------------------- |
 * | 01               | Create dummy operations using make_dummy_ops.                                            | None                                                                                                     | Dummy operations object is created                               | Should be successful|
 * | 02               | Instantiate ec_enrollee_t with MAC "02:11:22:33:44:55" and dummy operations.              | input: MAC = "02:11:22:33:44:55", ops = dummy_ops, output: enrollee instance                               | Enrollee object is properly instantiated                         | Should be successful|
 * | 03               | Allocate a frame buffer of size ec_frame_t and cast it to ec_frame_t pointer.              | input: frame size = sizeof(ec_frame_t), output: frame pointer                                            | Frame buffer is allocated and cast correctly                     | Should be successful|
 * | 04               | Set the frame_type field of the frame to ec_frame_type_peer_disc_rsp.                      | input: frame->frame_type = ec_frame_type_peer_disc_rsp                                                   | Frame type is set as Peer Discovery Response                     | Should be successful|
 * | 05               | Define a MAC address array with the value {0x02,0x11,0x22,0x33,0x44,0x55}.                  | input: mac = 0x02,0x11,0x22,0x33,0x44,0x55                                                                 | MAC array is defined correctly                                   | Should be successful|
 * | 06               | Invoke process_direct_encap_dpp_msg and verify that it returns false.                      | input: frame pointer, frame size, mac pointer, output: expected return = false                             | API returns false and assertion EXPECT_FALSE passes              | Should Fail         |
 */
TEST(ECEnrollee_t, ProcessDirectEncapDPPMsg_PeerDiscRespFailure)
{
    std::cout << "Entering ProcessDirectEncapDPPMsg_PeerDiscRespFailure test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t frame[sizeof(ec_frame_t)] = {};
    ec_frame_t* ec_frame = reinterpret_cast<ec_frame_t*>(frame);
    ec_frame->frame_type = static_cast<uint8_t>(ec_frame_type_peer_disc_rsp);
    uint8_t mac[ETH_ALEN] = {0x02,0x11,0x22,0x33,0x44,0x55};
    EXPECT_FALSE(enrollee.process_direct_encap_dpp_msg(frame, sizeof(frame), mac));
    std::cout << "Exiting ProcessDirectEncapDPPMsg_PeerDiscRespFailure test" << std::endl;
}
/**
 * @brief Verify that processing a direct encapsulated DPP message with an authentication request frame fails.
 *
 * This test instantiates an enrollee with dummy operations and prepares a DPP message frame with an authentication request frame type.
 * The objective is to ensure that the process_direct_encap_dpp_msg API correctly identifies the incorrect frame type and returns false,
 * indicating a failure in processing the authentication request.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 033@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Instantiate dummy operations and create enrollee object | input: MAC = "02:11:22:33:44:55", ops = dummy ops; output: enrollee object created | Enrollee should be successfully created | Should be successful |
 * | 02 | Prepare DPP message frame with authentication request type | input: frame buffer allocated of size sizeof(ec_frame_t), frame_type = ec_frame_type_auth_req | Frame is initialized with auth_req type | Should be successful |
 * | 03 | Invoke process_direct_encap_dpp_msg API with the prepared frame and MAC address | input: frame pointer, frame length = sizeof(frame), mac = "02:11:22:33:44:55" | API returns false indicating processing failure | Should Fail |
 */
TEST(ECEnrollee_t, ProcessDirectEncapDPPMsg_AuthReqFailure)
{
    std::cout << "Entering ProcessDirectEncapDPPMsg_AuthReqFailure test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t frame[sizeof(ec_frame_t)] = {};
    ec_frame_t* ec_frame = reinterpret_cast<ec_frame_t*>(frame);
    ec_frame->frame_type = static_cast<uint8_t>(ec_frame_type_auth_req);
    uint8_t mac[ETH_ALEN] = {0x02,0x11,0x22,0x33,0x44,0x55};
    EXPECT_FALSE(enrollee.process_direct_encap_dpp_msg(frame, sizeof(frame), mac));
    std::cout << "Exiting ProcessDirectEncapDPPMsg_AuthReqFailure test" << std::endl;
}
/**
 * @brief Test processing of direct encapsulated DPP message - Auth Confirmation Failure
 *
 * Verifies that process_direct_encap_dpp_msg returns false when provided with a message frame indicating an authentication confirmation, thus simulating an authentication confirmation failure scenario.
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
 * | Variation / Step | Description                                                                                  | Test Data                                                                                                | Expected Result                                                                                                            | Notes      |
 * | :--------------: | -------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- | ---------- |
 * |       01         | Invoke process_direct_encap_dpp_msg with a frame having type auth_cnf to simulate auth failure  | frame: frame_type = auth_cnf, frame_len = sizeof(frame), mac = 02:11:22:33:44:55                         | API returns false indicating that processing of a direct encapsulated DPP message with auth confirmation fails            | Should Fail |
 */
TEST(ECEnrollee_t, ProcessDirectEncapDPPMsg_AuthCnfFailure)
{
    std::cout << "Entering ProcessDirectEncapDPPMsg_AuthCnfFailure test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t frame[sizeof(ec_frame_t)] = {};
    ec_frame_t* ec_frame = reinterpret_cast<ec_frame_t*>(frame);
    ec_frame->frame_type = static_cast<uint8_t>(ec_frame_type_auth_cnf);
    uint8_t mac[ETH_ALEN] = {0x02,0x11,0x22,0x33,0x44,0x55};
    EXPECT_FALSE(enrollee.process_direct_encap_dpp_msg(frame, sizeof(frame), mac));
    std::cout << "Exiting ProcessDirectEncapDPPMsg_AuthCnfFailure test" << std::endl;
}
/**
 * @brief Tests the process_direct_encap_dpp_gas_msg function with a NULL frame pointer to validate error handling.
 *
 * This test verifies that the process_direct_encap_dpp_gas_msg API correctly handles a scenario where the frame pointer is NULL.
 * It ensures that the function returns false when provided with invalid frame input, thereby maintaining robustness.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 035@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                        | Test Data                                                              | Expected Result                                     | Notes         |
 * | :--------------: | ------------------------------------------------------------------ | ---------------------------------------------------------------------- | --------------------------------------------------- | ------------- |
 * | 01               | Prepare dummy operations and construct the enrollee instance using a valid MAC address. | ops = make_dummy_ops(), MAC = "02:11:22:33:44:55"                      | Enrollee instance is constructed successfully.    | Should be successful |
 * | 02               | Invoke process_direct_encap_dpp_gas_msg with a NULL frame pointer to validate error handling. | frame_ptr = nullptr, frame_len = 10, mac = {0, 0, 0, 0, 0, 0}            | The API returns false indicating proper error handling. | Should Fail   |
 */
TEST(ECEnrollee_t, ProcessDirectEncapDppGasMsg_NullFrame)
{
    std::cout << "Entering ProcessDirectEncapDppGasMsg_NullFrame test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t mac[ETH_ALEN] = {0};
    EXPECT_FALSE(enrollee.process_direct_encap_dpp_gas_msg(nullptr, 10, mac));
    std::cout << "Exiting ProcessDirectEncapDppGasMsg_NullFrame test" << std::endl;
}
/**
 * @brief Test the process_direct_encap_dpp_gas_msg API with a zero-length frame
 *
 * This test validates that when a zero-length frame is passed to the process_direct_encap_dpp_gas_msg function, 
 * the API correctly handles the edge case by returning false. It ensures that no processing is attempted on invalid input.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 036@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                         | Test Data                                                    | Expected Result                                                     | Notes         |
 * | :--------------: | ------------------------------------------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------------- | ------------- |
 * | 01               | Create dummy operations, instantiate enrollee, and invoke the API   | ops = make_dummy_ops(), enrollee with MAC "02:11:22:33:44:55", frame = [0,0,...,0] (10 bytes), frame length = 0, mac = [0,0,...,0] (ETH_ALEN) | API returns false and the assertion EXPECT_FALSE passes             | Should Pass   |
 */
TEST(ECEnrollee_t, ProcessDirectEncapDppGasMsg_ZeroLength)
{
    std::cout << "Entering ProcessDirectEncapDppGasMsg_ZeroLength test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t frame[10] = {};
    uint8_t mac[ETH_ALEN] = {0};
    EXPECT_FALSE(enrollee.process_direct_encap_dpp_gas_msg(frame, 0, mac));
    std::cout << "Exiting ProcessDirectEncapDppGasMsg_ZeroLength test" << std::endl;
}
/**
 * @brief Test the failure path of processing a direct encapsulated DPP GAS message in an enrollee object.
 *
 * This test verifies that the enrollee's process_direct_encap_dpp_gas_msg API correctly returns a failure indication when processing a GAS frame that represents an initial response, which is not expected to succeed.
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
 * | Variation / Step | Description                                                                                                  | Test Data                                                                                                                         | Expected Result                                                     | Notes          |
 * | :--------------: | ------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | -------------- |
 * | 01               | Log the entry message for the test.                                                                          | None                                                                                                                              | "Entering ProcessDirectEncapDppGasMsg_InitialResponseFailure test" printed. | Should be successful |
 * | 02               | Initialize ec_ops structure and create an enrollee object with MAC "02:11:22:33:44:55".                         | ops = make_dummy_ops(), enrollee = ec_enrollee_t("02:11:22:33:44:55", ops)                                                         | Enrollee object is successfully created.                           | Should be successful |
 * | 03               | Prepare a GAS message frame and set its action to dpp_gas_initial_resp.                                        | frame = {0}, gas->action = dpp_gas_initial_resp                                                                                   | GAS frame is properly configured with dpp_gas_initial_resp action.   | Should be successful |
 * | 04               | Prepare a MAC address array with the value {0x02, 0x11, 0x22, 0x33, 0x44, 0x55}.                                | mac = {0x02,0x11,0x22,0x33,0x44,0x55}                                                                                               | MAC array is correctly initialized.                                  | Should be successful |
 * | 05               | Invoke process_direct_encap_dpp_gas_msg API with the prepared frame and MAC, and verify it returns false.        | input: frame, input size: sizeof(frame), input: mac; output: return value expected = false                                          | API returns false and the assertion EXPECT_FALSE passes.             | Should Fail    |
 * | 06               | Log the exit message for the test.                                                                           | None                                                                                                                              | "Exiting ProcessDirectEncapDppGasMsg_InitialResponseFailure test" printed. | Should be successful |
 */
TEST(ECEnrollee_t, ProcessDirectEncapDppGasMsg_InitialResponseFailure)
{
    std::cout << "Entering ProcessDirectEncapDppGasMsg_InitialResponseFailure test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t frame[sizeof(ec_gas_initial_response_frame_t)] = {};
    auto* gas = reinterpret_cast<ec_gas_frame_base_t*>(frame);
    gas->action = dpp_gas_initial_resp;
    uint8_t mac[ETH_ALEN] = {0x02,0x11,0x22,0x33,0x44,0x55};
    EXPECT_FALSE(enrollee.process_direct_encap_dpp_gas_msg(frame, sizeof(frame), mac));
    std::cout << "Exiting ProcessDirectEncapDppGasMsg_InitialResponseFailure test" << std::endl;
}
/**
 * @brief Validate that the process_direct_encap_dpp_gas_msg API correctly handles a DPP GAS comeback response scenario by returning false.
 *
 * This test verifies that when a DPP GAS comeback response frame is passed to the process_direct_encap_dpp_gas_msg API, the function detects the scenario as a failure condition and returns false. This behavior is critical to ensure that the function properly handles specific GAS message types that are not supported or indicate an error.
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
 * | Variation / Step | Description                                                                                           | Test Data                                                                                                                        | Expected Result                                                              | Notes         |
 * | :--------------: | ----------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | ------------- |
 * | 01               | Create dummy operations, initialize an enrollee instance with a specific MAC, and prepare a frame with the DPP GAS comeback response action before invoking the API. | ops = make_dummy_ops(), enrollee MAC = "02:11:22:33:44:55", frame action = dpp_gas_comeback_resp, frame size = sizeof(frame), mac = {0x02,0x11,0x22,0x33,0x44,0x55} | The process_direct_encap_dpp_gas_msg API returns false indicating the failure scenario is correctly handled. | Should Pass   |
 */
TEST(ECEnrollee_t, ProcessDirectEncapDppGasMsg_ComebackResponseFailure)
{
    std::cout << "Entering ProcessDirectEncapDppGasMsg_ComebackResponseFailure test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t frame[sizeof(ec_gas_comeback_response_frame_t)] = {};
    auto* gas = reinterpret_cast<ec_gas_frame_base_t*>(frame);
    gas->action = dpp_gas_comeback_resp;
    uint8_t mac[ETH_ALEN] = {0x02,0x11,0x22,0x33,0x44,0x55};
    EXPECT_FALSE(enrollee.process_direct_encap_dpp_gas_msg(frame, sizeof(frame), mac));
    std::cout << "Exiting ProcessDirectEncapDppGasMsg_ComebackResponseFailure test" << std::endl;
}
/**
 * @brief Verify that an unhandled DPP GAS initial request returns false.
 *
 * This test verifies that when a GAS frame with the action set to dpp_gas_initial_req is processed,
 * the ec_enrollee_t::process_direct_encap_dpp_gas_msg function returns false, indicating that the initial request
 * is not handled. The test uses dummy operations and a sample MAC address to instantiate the enrollee.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Instantiate dummy operations and create ec_enrollee instance with a valid MAC address. | input: mac = "02:11:22:33:44:55", ops = make_dummy_ops() | Enrollee instance is created successfully. | Should be successful |
 * | 02 | Prepare a GAS frame setting its action to dpp_gas_initial_req. | input: gas->action = dpp_gas_initial_req, frame size = sizeof(ec_gas_frame_base_t) | GAS frame is set correctly with the initial request action. | Should be successful |
 * | 03 | Invoke process_direct_encap_dpp_gas_msg with the prepared frame and an uninitialized MAC array. | input: frame pointer = frame, frame size = sizeof(frame), mac = {0} | Function returns false, indicating the initial request is not handled. | Should Pass |
 */
TEST(ECEnrollee_t, ProcessDirectEncapDppGasMsg_InitialRequestUnhandled)
{
    std::cout << "Entering ProcessDirectEncapDppGasMsg_InitialRequestUnhandled test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t frame[sizeof(ec_gas_frame_base_t)] = {};
    auto* gas = reinterpret_cast<ec_gas_frame_base_t*>(frame);
    gas->action = dpp_gas_initial_req;
    uint8_t mac[ETH_ALEN] = {0};
    EXPECT_FALSE(enrollee.process_direct_encap_dpp_gas_msg(frame, sizeof(frame), mac));
    std::cout << "Exiting ProcessDirectEncapDppGasMsg_InitialRequestUnhandled test" << std::endl;
}
/**
 * @brief Verify that ProcessDirectEncapDppGasMsg properly handles unhandled comeback requests.
 *
 * This test checks that when an enrollee receives a GAS message with the action set to dpp_gas_comeback_req,
 * the process_direct_encap_dpp_gas_msg API returns false, indicating that unhandled comeback requests are not processed.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 040@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                                      | Test Data                                                                                                                                                                    | Expected Result                                           | Notes       |
 * | :--------------: | ---------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- | ----------- |
 * | 01               | Initialize dummy operations, create an enrollee with MAC "02:11:22:33:44:55", prepare a gas frame, set its action to dpp_gas_comeback_req, and call process_direct_encap_dpp_gas_msg with the prepared frame, frame size, and an all-zero MAC address. | enrollee: MAC = "02:11:22:33:44:55", ops from make_dummy_ops(), frame: array of size sizeof(ec_gas_frame_base_t) with gas->action = dpp_gas_comeback_req, mac: 00:00:00:00:00:00 | API returns false; Assertion EXPECT_FALSE evaluates to true | Should Pass |
 */
TEST(ECEnrollee_t, ProcessDirectEncapDppGasMsg_ComebackRequestUnhandled)
{
    std::cout << "Entering ProcessDirectEncapDppGasMsg_ComebackRequestUnhandled test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t frame[sizeof(ec_gas_frame_base_t)] = {};
    auto* gas = reinterpret_cast<ec_gas_frame_base_t*>(frame);
    gas->action = dpp_gas_comeback_req;
    uint8_t mac[ETH_ALEN] = {0};
    EXPECT_FALSE(enrollee.process_direct_encap_dpp_gas_msg(frame, sizeof(frame), mac));
    std::cout << "Exiting ProcessDirectEncapDppGasMsg_ComebackRequestUnhandled test" << std::endl;
}
/**
 * @brief Verify that process_direct_encap_dpp_gas_msg returns false for an unknown action code.
 *
 * This test verifies that when process_direct_encap_dpp_gas_msg is invoked with a gas frame containing an invalid
 * action value (0xFF), the method correctly identifies the unknown action and returns false, ensuring proper error handling.
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
 * | Variation / Step | Description                                                                                                          | Test Data                                                                                                                    | Expected Result                                       | Notes      |
 * | :--------------: | -------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- | ---------- |
 * | 01               | Instantiate dummy operations and enrollee with MAC "02:11:22:33:44:55". Prepare a gas frame with an invalid action | ops = dummy, enrollee MAC = "02:11:22:33:44:55", frame = {action=0xFF,...}, frame size = sizeof(ec_gas_frame_base_t), mac = {0} | API returns false; EXPECT_FALSE assertion passes.     | Should Fail |
 */
TEST(ECEnrollee_t, ProcessDirectEncapDppGasMsg_UnknownAction)
{
    std::cout << "Entering ProcessDirectEncapDppGasMsg_UnknownAction test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t frame[sizeof(ec_gas_frame_base_t)] = {};
    auto* gas = reinterpret_cast<ec_gas_frame_base_t*>(frame);
    gas->action = 0xFF; // invalid
    uint8_t mac[ETH_ALEN] = {0};
    EXPECT_FALSE(enrollee.process_direct_encap_dpp_gas_msg(frame, sizeof(frame), mac));
    std::cout << "Exiting ProcessDirectEncapDppGasMsg_UnknownAction test" << std::endl;
}
/**
 * @brief Test the HandleAssocStatus function for a connected station scenario
 *
 * Verify that when the station is in a connected state with valid BSSID and SSID information, the enrollee's handle_assoc_status() returns true. This test confirms that when not awaiting a BSSID and already connected, the function performs as expected.
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
 * | Variation / Step | Description                                                                                                           | Test Data                                                                                                                                                                  | Expected Result                                                                    | Notes       |
 * | :----:           | --------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- | ----------- |
 * | 01               | Initialize dummy operations, create an enrollee with a specific MAC, set the station status to connected, and assign valid BSSID and SSID; call handle_assoc_status() | input: MAC = "02:11:22:33:44:55", ops = dummy ops, sta.stats.connect_status = wifi_connection_status_connected, sta.bss_info.bssid = AA:BB:CC:DD:EE:FF, sta.bss_info.ssid = "TestSSID"; output: expects true | The function returns true and the assertion passes                                 | Should Pass |
 */
TEST(ECEnrollee_t, HandleAssocStatus_NotAwaitingBssid_Connected)
{
    std::cout << "Entering HandleAssocStatus_NotAwaitingBssid_Connected test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    rdk_sta_data_t sta = {};
    sta.stats.connect_status = wifi_connection_status_connected;
    memcpy(sta.bss_info.bssid, "\xAA\xBB\xCC\xDD\xEE\xFF", ETH_ALEN);
    strcpy(sta.bss_info.ssid, "TestSSID");
    EXPECT_TRUE(enrollee.handle_assoc_status(sta));
    std::cout << "Exiting HandleAssocStatus_NotAwaitingBssid_Connected test" << std::endl;
}
/**
 * @brief Verify that handle_assoc_status returns true when the station is disconnected
 *
 * This test verifies that the ECEnrollee_t object's handle_assoc_status method correctly returns true when the station's connection status is wifi_connection_status_disconnected, even if the BSSID is provided. The test ensures that the enrollee correctly handles the scenario when it is not awaiting the BSSID.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 043@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                                      | Test Data                                                                                                                                               | Expected Result                                                         | Notes      |
 * | :--------------: | --------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- | ---------- |
 * | 01               | Create dummy operations, initialize ECEnrollee_t with a given MAC address, set station data with a disconnected status, and invoke handle_assoc_status. | ops = result of make_dummy_ops(), mac = "02:11:22:33:44:55", sta.stats.connect_status = wifi_connection_status_disconnected, sta.bss_info.bssid = "\x01\x02\x03\x04\x05\x06", sta.bss_info.ssid = "SSID" | handle_assoc_status returns true and EXPECT_TRUE assertion passes             | Should Pass |
 */
TEST(ECEnrollee_t, HandleAssocStatus_NotAwaitingBssid_Disconnected)
{
    std::cout << "Entering HandleAssocStatus_NotAwaitingBssid_Disconnected test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    rdk_sta_data_t sta = {};
    sta.stats.connect_status = wifi_connection_status_disconnected;
    memcpy(sta.bss_info.bssid, "\x01\x02\x03\x04\x05\x06", ETH_ALEN);
    strcpy(sta.bss_info.ssid, "SSID");
    EXPECT_TRUE(enrollee.handle_assoc_status(sta));
    std::cout << "Exiting HandleAssocStatus_NotAwaitingBssid_Disconnected test" << std::endl;
}
/**
 * @brief Test the behavior of handle_assoc_status when not awaiting BSSID and AP is not found.
 *
 * This test verifies that when the connection status is set to wifi_connection_status_ap_not_found, the enrollee's handle_assoc_status method correctly processes the station data and returns true. The test confirms that the API works as expected even when the BSSID is not being awaited.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize dummy operations and create an enrollee instance with MAC "02:11:22:33:44:55". | input: ops = make_dummy_ops(), MAC = 02:11:22:33:44:55, output: enrollee object created | Enrollee object is successfully created. | Should be successful |
 * | 02 | Set station data with connection status "wifi_connection_status_ap_not_found", BSSID, and SSID. | input: sta.stats.connect_status = wifi_connection_status_ap_not_found, sta.bss_info.bssid = "\x10\x20\x30\x40\x50\x60", sta.bss_info.ssid = "SSID" | Station data is correctly populated. | Should be successful |
 * | 03 | Invoke handle_assoc_status API with the prepared station data. | input: enrollee.handle_assoc_status(sta) | Returns true; Assertion EXPECT_TRUE passes. | Should Pass |
 */
TEST(ECEnrollee_t, HandleAssocStatus_NotAwaitingBssid_ApNotFound)
{
    std::cout << "Entering HandleAssocStatus_NotAwaitingBssid_ApNotFound test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    rdk_sta_data_t sta = {};
    sta.stats.connect_status = wifi_connection_status_ap_not_found;
    memcpy(sta.bss_info.bssid, "\x10\x20\x30\x40\x50\x60", ETH_ALEN);
    strcpy(sta.bss_info.ssid, "SSID");
    EXPECT_TRUE(enrollee.handle_assoc_status(sta));
    std::cout << "Exiting HandleAssocStatus_NotAwaitingBssid_ApNotFound test" << std::endl;
}
/**
 * @brief Verify that handle_autoconf_response_chirp returns false when a null chirp pointer is passed.
 *
 * This test case verifies that when the API function handle_autoconf_response_chirp is invoked with a null chirp pointer,
 * the function correctly handles the error and returns false. This behavior ensures that the API safely handles invalid input.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 045@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                                                  | Test Data                                                                                   | Expected Result                                                      | Notes          |
 * | :--------------: | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- | -------------- |
 * | 01               | Create a dummy operations object and initialize the enrollee instance        | MAC = "02:11:22:33:44:55", ops = make_dummy_ops()                                             | Enrollee object is successfully created                              | Should be successful |
 * | 02               | Invoke handle_autoconf_response_chirp with a null chirp pointer and verify output | input1 (chirp pointer) = nullptr, input2 (length) = 10, input3 (src_mac) = {0}                  | API returns false and EXPECT_FALSE assertion passes                  | Should Pass    |
 */
TEST(ECEnrollee_t, HandleAutoconfChirp_NullChirp)
{
    std::cout << "Entering HandleAutoconfChirp_NullChirp test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t src_mac[ETH_ALEN] = {0};
    bool res = enrollee.handle_autoconf_response_chirp(nullptr, 10, src_mac);
    EXPECT_FALSE(res);
    std::cout << "Exiting HandleAutoconfChirp_NullChirp test" << std::endl;
}
/**
 * @brief Verify that the enrollee returns false when the autoconf chirp has zero length
 *
 * This test verifies that when the handle_autoconf_response_chirp API is invoked with a chirp length of zero, the function correctly returns false. This ensures that the function does not erroneously process an autoconf chirp with invalid (zero) length.
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
 * | Variation / Step | Description                                                                 | Test Data                                                              | Expected Result                                                    | Notes           |
 * | :--------------: | --------------------------------------------------------------------------- | ---------------------------------------------------------------------- | ------------------------------------------------------------------ | --------------- |
 * | 01               | Create dummy operations object using make_dummy_ops                         | ops = make_dummy_ops()                                                 | Dummy operations object is created successfully                    | Should be successful |
 * | 02               | Instantiate enrollee object with given MAC and the dummy operations         | input1 = MAC "02:11:22:33:44:55", input2 = ops                            | Enrollee object is created successfully                           | Should be successful |
 * | 03               | Initialize an empty chirp structure                                         | chirp = {}                                                             | Chirp structure is initialized                                     | Should be successful |
 * | 04               | Prepare a source MAC array with all zeros                                   | src_mac = 0,0,0,0,0,0 (ETH_ALEN elements)                              | src_mac array is initialized correctly                             | Should be successful |
 * | 05               | Invoke handle_autoconf_response_chirp with zero length and validate return    | input1 = &chirp, input2 = 0, input3 = src_mac                             | API returns false as the chirp length is zero                        | Should Fail     |
 * | 06               | Log exit message indicating end of test execution                           | No input arguments                                                     | Exit logging message is printed                                      | Should be successful |
 */
TEST(ECEnrollee_t, HandleAutoconfChirp_ZeroLengthChirp)
{
    std::cout << "Entering HandleAutoconfChirp_ZeroLengthChirp test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    em_dpp_chirp_value_t chirp {};
    uint8_t src_mac[ETH_ALEN] = {0};
    bool res = enrollee.handle_autoconf_response_chirp(&chirp, 0, src_mac);
    EXPECT_FALSE(res);
    std::cout << "Exiting HandleAutoconfChirp_ZeroLengthChirp test" << std::endl;
}
/**
 * @brief Verify that handle_autoconf_response_chirp correctly handles an invalid chirp hash.
 *
 * This test verifies that when the handle_autoconf_response_chirp API is invoked with a chirp structure
 * having an invalid hash, it returns false. This ensures that the EC enrollee correctly identifies and
 * rejects chirps with invalid hash values during autoconfiguration.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 047@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create EC enrollee instance using a dummy operations structure with MAC address "02:11:22:33:44:55" | input: MAC = "02:11:22:33:44:55", ops = dummy operations | Instance should be created successfully | Should be successful |
 * | 02 | Prepare chirp structure with an invalid hash | input: chirp.hash_valid = false, chirp size = sizeof(chirp) | Chirp structure prepared with an invalid hash | Should be successful |
 * | 03 | Invoke handle_autoconf_response_chirp API with the invalid chirp and a zeroed source MAC address | input: chirp pointer, size = sizeof(chirp), src_mac array = {0} | API should return false, and EXPECT_FALSE(res) assertion should pass | Should Pass |
 * | 04 | Output test entry and exit logs via std::cout | input: log messages "Entering HandleAutoconfChirp_InvalidHash test" and "Exiting HandleAutoconfChirp_InvalidHash test" | Log messages should be printed accordingly | Should be successful |
 */
TEST(ECEnrollee_t, HandleAutoconfChirp_InvalidHash)
{
    std::cout << "Entering HandleAutoconfChirp_InvalidHash test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    em_dpp_chirp_value_t chirp {};
    chirp.hash_valid = false;
    uint8_t src_mac[ETH_ALEN] = {0};
    bool res = enrollee.handle_autoconf_response_chirp(&chirp, sizeof(chirp), src_mac);
    EXPECT_FALSE(res);
    std::cout << "Exiting HandleAutoconfChirp_InvalidHash test" << std::endl;
}
/**
 * @brief Validate that ec_enrollee_t::get_al_mac_addr returns the correct MAC address
 *
 * This test verifies that when an ec_enrollee_t object is constructed with a specific MAC address, the get_al_mac_addr method returns the same address. It ensures the basic functionality of MAC retrieval is working as expected.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 048
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                     | Test Data                                                                                                   | Expected Result                                                  | Notes             |
 * | :--------------: | ------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- | ----------------- |
 * | 01               | Print the entering test log message                                             | No input, log output = "Entering GetAlMacAddr_ReturnsCorrectMac test"                                        | Log message is printed                                           | Should be successful |
 * | 02               | Create a dummy operator using make_dummy_ops()                                  | No input, output = ops object                                                                               | Dummy operator is created                                        | Should be successful |
 * | 03               | Instantiate ec_enrollee_t object with a specific MAC address and dummy operator   | input: mac = "02:11:22:33:44:55", ops = dummy operator                                                       | Object is constructed with the provided MAC address              | Should be successful |
 * | 04               | Invoke the get_al_mac_addr() method on the ec_enrollee_t object                   | input: enrollee object with mac = "02:11:22:33:44:55"                                                        | Method is called and returns a MAC address                        | Should be successful |
 * | 05               | Compare the returned MAC address with the expected MAC address using EXPECT_EQ    | input: result from get_al_mac_addr() = "02:11:22:33:44:55", expected output = "02:11:22:33:44:55"            | EXPECT_EQ assertion passes confirming the MAC addresses match       | Should Pass       |
 * | 06               | Print the exiting test log message                                              | No input, log output = "Exiting GetAlMacAddr_ReturnsCorrectMac test"                                        | Log message is printed                                           | Should be successful |
 */
TEST(ECEnrollee_t, GetAlMacAddr_ReturnsCorrectMac)
{
    std::cout << "Entering GetAlMacAddr_ReturnsCorrectMac test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    std::string mac = "02:11:22:33:44:55";
    ec_enrollee_t enrollee(mac, ops);
    std::string result = enrollee.get_al_mac_addr();
    EXPECT_EQ(result, mac);
    std::cout << "Exiting GetAlMacAddr_ReturnsCorrectMac test" << std::endl;
}
/**
 * @brief Verify that multiple instances of ec_enrollee_t return the correct MAC address.
 *
 * This test creates two instances of ec_enrollee_t with distinct MAC addresses and verifies
 * that the get_al_mac_addr() method returns the correct MAC address for each instance.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 049@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize dummy operations object and create the first ec_enrollee_t instance using MAC "00:11:22:33:44:55". | input: MAC = "00:11:22:33:44:55", ops = make_dummy_ops() | ec_enrollee_t instance (enrollee1) is created with MAC "00:11:22:33:44:55" | Should be successful |
 * | 02 | Create the second ec_enrollee_t instance using MAC "66:77:88:99:AA:BB". | input: MAC = "66:77:88:99:AA:BB", ops = make_dummy_ops() | ec_enrollee_t instance (enrollee2) is created with MAC "66:77:88:99:AA:BB" | Should be successful |
 * | 03 | Invoke get_al_mac_addr() on enrollee1 to retrieve the MAC address. | output: enrollee1.get_al_mac_addr() expected = "00:11:22:33:44:55" | Returns "00:11:22:33:44:55" and passes EXPECT_EQ assertion | Should Pass |
 * | 04 | Invoke get_al_mac_addr() on enrollee2 to retrieve the MAC address. | output: enrollee2.get_al_mac_addr() expected = "66:77:88:99:AA:BB" | Returns "66:77:88:99:AA:BB" and passes EXPECT_EQ assertion | Should Pass |
 */

TEST(ECEnrollee_t, GetAlMacAddr_MultipleInstancesReturnCorrectMac)
{
    std::cout << "Entering GetAlMacAddr_MultipleInstancesReturnCorrectMac test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee1("00:11:22:33:44:55", ops);
    ec_enrollee_t enrollee2("66:77:88:99:AA:BB", ops);
    EXPECT_EQ(enrollee1.get_al_mac_addr(), "00:11:22:33:44:55");
    EXPECT_EQ(enrollee2.get_al_mac_addr(), "66:77:88:99:AA:BB");
    std::cout << "Exiting GetAlMacAddr_MultipleInstancesReturnCorrectMac test" << std::endl;
}
/**
 * @brief Validate that the default secure context is retrieved successfully.
 *
 * This test verifies that when an EC enrollee object is constructed with a valid MAC address and dummy operations, the get_sec_ctx() method returns a non-null pointer indicating that a valid, default secure security context is provided.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 050@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                        | Test Data                                                | Expected Result                                                        | Notes             |
 * | :--------------: | ------------------------------------------------------------------ | -------------------------------------------------------- | ---------------------------------------------------------------------- | ----------------- |
 * | 01               | Create dummy operations using make_dummy_ops() function            | None                                                     | Dummy operations object created successfully                           | Should be successful |
 * | 02               | Construct an enrollee object with MAC "02:11:22:33:44:55" and dummy ops | MAC = "02:11:22:33:44:55", ops = dummy ops                | Enrollee object is successfully created                                | Should be successful |
 * | 03               | Invoke get_sec_ctx() on the enrollee object                          | Enrollee object, method get_sec_ctx()                     | Return value is non-null, thus a valid security context is obtained      | Should Pass       |
 */
TEST(ECEnrollee_t, GetSecCtx_Default)
{
    std::cout << "Entering GetSecCtx_Default test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    ec_persistent_sec_ctx_t* sec_ctx = enrollee.get_sec_ctx();
    ASSERT_NE(sec_ctx, nullptr);
    std::cout << "Exiting GetSecCtx_Default test" << std::endl;
}
/**
 * @brief Test the retrieval of the connection context from an ECEnrollee_t instance.
 *
 * This test verifies that the get_conn_ctx method returns a valid non-null connection context pointer when the ECEnrollee_t object is instantiated using a valid MAC address and dummy operations.
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
 * | Variation / Step | Description                                                                                                   | Test Data                                                                                         | Expected Result                                                                       | Notes       |
 * | :-------------: | ------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- | ----------- |
 * | 01              | Create dummy operations and instantiate ECEnrollee_t with a given MAC address, then call get_conn_ctx.         | MAC = "02:11:22:33:44:55", ops = make_dummy_ops(), output1 = conn_ctx pointer from get_conn_ctx() | get_conn_ctx returns a non-null pointer and ASSERT_NE(conn_ctx, nullptr) passes         | Should Pass |
 */
TEST(ECEnrollee_t, GetConnCtx_Default)
{
    std::cout << "Entering GetConnCtx_Default test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    ec_connection_context_t* conn_ctx = enrollee.get_conn_ctx();
    ASSERT_NE(conn_ctx, nullptr);
    std::cout << "Exiting GetConnCtx_Default test" << std::endl;
}
/**
 * @brief Test the default onboarding state of an enrollee
 *
 * This test verifies that when an enrollee is created using a dummy operations structure and a valid MAC address,
 * its onboarding state is false. It ensures that the default state is correctly set to not onboarding, which is critical
 * for proper lifecycle management.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 052@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                              | Test Data                                                            | Expected Result                                                | Notes       |
 * | :--------------: | ---------------------------------------------------------------------------------------- | -------------------------------------------------------------------- | -------------------------------------------------------------- | ----------- |
 * | 01               | Create a dummy operations structure, construct an enrollee with a valid MAC address, invoke is_onboarding, and verify it returns false | input: MAC = "02:11:22:33:44:55", ops = make_dummy_ops(), output: false | The is_onboarding API should return false, and the assertion check should pass | Should Pass |
 */
TEST(ECEnrollee_t, IsOnboarding_Default)
{
    std::cout << "Entering IsOnboarding_Default test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    EXPECT_FALSE(enrollee.is_onboarding());
    std::cout << "Exiting IsOnboarding_Default test" << std::endl;
}
/**
 * @brief Tests the default behavior of the teardown_connection API function.
 *
 * This test verifies that the teardown_connection method of an ec_enrollee_t object can be invoked without throwing any exceptions. 
 * The enrollee is instantiated with a specific MAC address and dummy operations to simulate a typical setup. The test ensures that the 
 * connection teardown process completes successfully in the default scenario.
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
 * | Variation / Step | Description                                                              | Test Data                                          | Expected Result               | Notes           |
 * | :--------------: | ------------------------------------------------------------------------ | -------------------------------------------------- | ----------------------------- | --------------- |
 * | 01               | Create dummy ops using make_dummy_ops function                           | (none)                                             | Dummy ops structure created   | Should be successful |
 * | 02               | Instantiate ec_enrollee_t with MAC "02:11:22:33:44:55" and dummy ops        | MAC="02:11:22:33:44:55", ops=dummy_ops               | Object instantiated successfully | Should be successful |
 * | 03               | Call teardown_connection() and verify no exception is thrown               | Method call: teardown_connection()                  | No exception thrown           | Should Pass     |
 */
TEST(ECEnrollee_t, TeardownConnection_Default)
{
    std::cout << "Entering TeardownConnection_Default test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    EXPECT_NO_THROW(enrollee.teardown_connection());
    std::cout << "Exiting TeardownConnection_Default test" << std::endl;
}
/**
 * @brief Verify that signal_enrollee_is_upgrading executes without throwing an exception
 *
 * This test validates that a valid ec_enrollee instance, constructed with dummy operations, can successfully invoke
 * signal_enrollee_is_upgrading without any exception being thrown. It ensures that the functionality for signalling the
 * enrollee's upgrading state works as expected under normal conditions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 054@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                     | Test Data                                                        | Expected Result                       | Notes         |
 * | :--------------: | ----------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- | ------------------------------------- | ------------- |
 * | 01               | Create an ec_enrollee with a valid MAC address and dummy operations, and invoke the signal method | address = "02:11:22:33:44:55", ops = dummy_ops                     | NO exception thrown, EXPECT_NO_THROW  | Should Pass   |
 */
TEST(ECEnrollee_t, SignalEnrolleeIsUpgrading_Default)
{
    std::cout << "Entering SignalEnrolleeIsUpgrading_Default test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    EXPECT_NO_THROW(enrollee.signal_enrollee_is_upgrading());
    std::cout << "Exiting SignalEnrolleeIsUpgrading_Default test" << std::endl;
}
/**
 * @brief Verify that process_1905_eapol_encap_msg properly handles a null frame pointer
 *
 * This test checks whether the function process_1905_eapol_encap_msg returns false when provided with a null pointer for the frame.
 * The test ensures that the API performs proper input validation and handles invalid input gracefully.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 055@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Log entry message for the test | None | "Entering Process1905Eapol_FrameNull test" is printed to the console | Should be successful |
 * | 02 | Initialize dummy operations and create an enrollee object | id = "02:11:22:33:44:55", ops = make_dummy_ops() | ec_enrollee_t object is successfully created | Should be successful |
 * | 03 | Invoke process_1905_eapol_encap_msg with a null frame pointer | frame = nullptr, length = 100, src_mac = {0x02,0x11,0x22,0x33,0x44,0x55} | API returns false, and EXPECT_FALSE check passes | Should Fail |
 * | 04 | Log exit message for the test | None | "Exiting Process1905Eapol_FrameNull test" is printed to the console | Should be successful |
 */
TEST(ECEnrollee_t, Process1905Eapol_FrameNull)
{
    std::cout << "Entering Process1905Eapol_FrameNull test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t src_mac[6] = {0x02,0x11,0x22,0x33,0x44,0x55};
    bool result = enrollee.process_1905_eapol_encap_msg(nullptr, 100, src_mac);
    EXPECT_FALSE(result);
    std::cout << "Exiting Process1905Eapol_FrameNull test" << std::endl;
}
/**
 * @brief Verify that process_1905_eapol_encap_msg returns false when the length is zero
 *
 * This test case verifies that the process_1905_eapol_encap_msg function correctly handles the scenario where a frame with zero length is provided. The test ensures that the enrollee does not process an empty frame even when supplied with a valid source MAC address.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 056@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                            | Test Data                                                                                     | Expected Result                                               | Notes       |
 * | :--------------: | -------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------- | ----------- |
 * | 01               | Invoke process_1905_eapol_encap_msg with a zero-length frame while providing a valid MAC | frame = {0,0,0,0,0,0,0,0,0,0}, length = 0, src_mac = {0x02,0x11,0x22,0x33,0x44,0x55}          | Return value false; EXPECT_FALSE assertion should pass        | Should Pass |
 */
TEST(ECEnrollee_t, Process1905Eapol_LengthZero)
{
    std::cout << "Entering Process1905Eapol_LengthZero test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t frame[10] = {};
    uint8_t src_mac[6] = {0x02,0x11,0x22,0x33,0x44,0x55};
    bool result = enrollee.process_1905_eapol_encap_msg(frame, 0, src_mac);
    EXPECT_FALSE(result);
    std::cout << "Exiting Process1905Eapol_LengthZero test" << std::endl;
}
/**
 * @brief Verify that process_1905_eapol_encap_msg returns false when srcMac is null
 *
 * This test verifies that the process_1905_eapol_encap_msg API correctly handles a null srcMac parameter.
 * It creates a dummy enrollee object and invokes the API with a frame containing zeroed bytes and a null srcMac pointer.
 * The test ensures that the API returns false, indicating proper error handling for invalid input.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 057@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01 | Create dummy ec_ops and enrollee instance; call process_1905_eapol_encap_msg with a 10-byte zero frame and a null srcMac parameter | frame = 0,0,0,0,0,0,0,0,0,0, frameSize = 10, srcMac = nullptr, enrollee MAC = "02:11:22:33:44:55" | API returns false, verified by EXPECT_FALSE(result) | Should Fail |
 */
TEST(ECEnrollee_t, Process1905Eapol_SrcMacNull)
{
    std::cout << "Entering Process1905Eapol_SrcMacNull test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    uint8_t frame[10] = {};
    bool result = enrollee.process_1905_eapol_encap_msg(frame, sizeof(frame), nullptr);
    EXPECT_FALSE(result);
    std::cout << "Exiting Process1905Eapol_SrcMacNull test" << std::endl;
}
/**
 * @brief Verify that start_secure_1905_layer returns false when invoked with a null MAC address pointer.
 *
 * This test verifies that when the API start_secure_1905_layer is called with a null pointer for the MAC address,
 * the function correctly handles the error by returning false. This behavior is critical for ensuring that invalid inputs are safely rejected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 058@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create a dummy operations object and initialize the enrollee with a valid MAC address | ops = make_dummy_ops(), MAC = "02:11:22:33:44:55" | Enrollee object is created successfully | Should be successful |
 * | 02 | Invoke start_secure_1905_layer with a null MAC address pointer | input: pointer = nullptr | API returns false indicating the secure 1905 layer did not start | Should Pass |
 */
TEST(ECEnrollee_t, StartSecure1905Layer_Nullmac)
{
    std::cout << "Entering StartSecure1905Layer_Nullmac test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_enrollee_t enrollee("02:11:22:33:44:55", ops);
    bool res = enrollee.start_secure_1905_layer(nullptr);
    EXPECT_FALSE(res);
    std::cout << "Exiting StartSecure1905Layer_Nullmac test" << std::endl;
}
/**
 * @brief Validate that ec_enrollee_t constructor works with minimal valid inputs
 *
 * This test ensures that the ec_enrollee_t constructor correctly handles minimal input validation by accepting a valid MAC address, a valid dummy operations structure, and an empty optional parameter without throwing any exceptions.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 059
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                      | Test Data                                                        | Expected Result                                                  | Notes      |
 * | :--------------: | ---------------------------------------------------------------- | ---------------------------------------------------------------- | ---------------------------------------------------------------- | ---------- |
 * | 01               | Invoke ec_enrollee_t constructor using minimal valid inputs      | mac = "AA:BB:CC:DD:EE:FF", ops = result from make_dummy_ops(), optional parameter = std::nullopt | Constructor should complete without throwing any exception       | Should Pass|
 */
TEST(ECEnrollee_t, Constructor_Minimal_Validation)
{
    std::cout << "Entering Constructor_Minimal_Validation test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    std::string mac = "AA:BB:CC:DD:EE:FF";
    EXPECT_NO_THROW(ec_enrollee_t enrollee(mac, ops, std::nullopt));
    std::cout << "Exiting Constructor_Minimal_Validation test" << std::endl;
}
