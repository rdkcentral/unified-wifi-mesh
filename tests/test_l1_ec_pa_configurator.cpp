
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
#include <ec_util.h>
#include "ec_pa_configurator.h"

static ec_persistent_sec_ctx_t make_dummy_sec_ctx()
{
    ec_persistent_sec_ctx_t sec_ctx{};
    sec_ctx.C_signing_key   = nullptr;
    sec_ctx.pp_key          = nullptr;
    sec_ctx.net_access_key  = nullptr;
    sec_ctx.connector       = nullptr;
    return sec_ctx;
}

static ec_ops_t make_dummy_ops()
{
    ec_ops_t ops{};
    ops.toggle_cce = [](bool /*enable*/) { return true; };
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
 * @brief Test for constructing ec_pa_configurator_t with valid parameters and colocated flag set to true
 *
 * This test validates that the ec_pa_configurator_t object can be successfully instantiated using valid inputs,
 * including a proper MAC address string, a control MAC address vector, dummy operation and security context objects,
 * and a valid callback function. The test ensures that the constructor does not throw any exceptions when the 
 * colocated flag is true.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 001@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * |01|Initialize test parameters including al_mac_addr, ctrl_al_mac_addr, ops, sec_ctx, and the handshake_completed_handler callback. | al_mac_addr = "00:11:22:33:44:55", ctrl_al_mac_addr = {0x11,0x22,0x33,0x44,0x55,0x66}, ops = make_dummy_ops(), sec_ctx = make_dummy_sec_ctx(), callback = lambda(uint8_t[ETH_ALEN], bool) | All inputs are correctly initialized. | Should be successful |
 * |02|Invoke the ec_pa_configurator_t constructor with the initialized parameters and set colocated to true. | Input: al_mac_addr = "00:11:22:33:44:55", ctrl_al_mac_addr = {0x11,0x22,0x33,0x44,0x55,0x66}, ops, sec_ctx, colocated = true, callback | Constructor does not throw any exception. | Should Pass |
 */
TEST(ec_pa_configurator_t, construct_valid_colocated_true)
{
    std::cout << "Entering construct_valid_colocated_true test" << std::endl;
    std::string al_mac_addr = "00:11:22:33:44:55";
    std::vector<uint8_t> ctrl_al_mac_addr = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETH_ALEN], bool) {};
    EXPECT_NO_THROW({
        ec_pa_configurator_t obj(al_mac_addr, ctrl_al_mac_addr, ops, sec_ctx, true, cb);
    });
    std::cout << "Exiting construct_valid_colocated_true test" << std::endl;
}
/**
 * @brief Validate the instantiation of ec_pa_configurator_t with valid parameters and colocated flag set to false.
 *
 * This test constructs an instance of ec_pa_configurator_t using valid configuration parameters including a well-formed MAC address string, its corresponding byte vector, dummy operations, a dummy security context, and a lambda callback. It verifies that the object is created without throwing any exception.
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
 * | 01 | Set valid inputs and call the ec_pa_configurator_t constructor with colocated flag set to false | al_mac_addr = "AA:BB:CC:DD:EE:FF", ctrl_al_mac_addr = 0xAA,0xBB,0xCC,0xDD,0xEE,0xFF, ops = dummy operations, sec_ctx = dummy security context, colocated = false, cb = lambda handler | Object is constructed without throwing an exception | Should Pass |
 */
TEST(ec_pa_configurator_t, construct_valid_colocated_false)
{
    std::cout << "Entering construct_valid_colocated_false test" << std::endl;
    std::string al_mac_addr = "AA:BB:CC:DD:EE:FF";
    std::vector<uint8_t> ctrl_al_mac_addr = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETH_ALEN], bool) {};
    EXPECT_NO_THROW({
        ec_pa_configurator_t obj(al_mac_addr, ctrl_al_mac_addr, ops, sec_ctx, false, cb);
    });
    std::cout << "Exiting construct_valid_colocated_false test" << std::endl;
}
/**
 * @brief Test construct_empty_almac API to validate exception on empty al_mac_addr input
 *
 * This test validates that constructing ec_pa_configurator_t with an empty al_mac_addr while providing valid ctrl_al_mac_addr,
 * operations, security context, and a handshake callback correctly throws an exception. It ensures that the API handles invalid input 
 * for al_mac_addr as expected.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 003
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                | Test Data                                                                                                            | Expected Result                                                | Notes       |
 * | :--------------: | ------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- | ----------- |
 * | 01               | Invoke ec_pa_configurator_t constructor with an empty al_mac_addr and valid other arguments. | al_mac_addr = "", ctrl_al_mac_addr = {0x11,0x22,0x33,0x44,0x55,0x66}, ops = dummy ops, sec_ctx = dummy sec_ctx, flag = true, cb = lambda | API should throw an exception as verified by EXPECT_ANY_THROW. | Should Pass |
 */
TEST(ec_pa_configurator_t, construct_empty_almac)
{
    std::cout << "Entering construct_empty_almac test" << std::endl;
    std::string al_mac_addr = "";
    std::vector<uint8_t> ctrl_al_mac_addr = {0x11,0x22,0x33,0x44,0x55,0x66};
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETH_ALEN], bool) {};
    EXPECT_ANY_THROW({
        ec_pa_configurator_t obj(al_mac_addr, ctrl_al_mac_addr, ops, sec_ctx, true, cb);
    });
    std::cout << "Exiting construct_empty_almac test" << std::endl;
}
/**
 * @brief Verify that handle_presence_announcement returns false when a null frame pointer is provided
 *
 * This test ensures that the handle_presence_announcement API correctly handles the scenario where the frame pointer is null.
 * It sets up the necessary dummy operations, security context, and callback, creates an ec_pa_configurator instance,
 * and then invokes handle_presence_announcement with a null frame. It verifies that the API returns false as expected.
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
 * | Variation / Step | Description                                                                                                                        | Test Data                                                                                                                                                                                   | Expected Result                                                                               | Notes         |
 * | :--------------: | ---------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- | ------------- |
 * | 01               | Initialize dummy operations, security context, and handshake callback, and create an ec_pa_configurator instance with valid parameters. | ops = make_dummy_ops(), sec_ctx = make_dummy_sec_ctx(), mac_addr = "66:77:88:99:AA:BB", ip = "0x0A,0x0B,0x0C,0x0D,0x0E,0x0F", callback = lambda function                              | Configurator instance is successfully created.                                               | Should be successful |
 * | 02               | Invoke handle_presence_announcement with a null frame pointer along with a length of 12 and a zero-initialized source MAC address.       | frame = nullptr, len = 12, src_mac = "0,0,0,0,0,0"                                                                                                                                         | Returns false; EXPECT_FALSE assertion passes confirming the API correctly handles null input. | Should Pass   |
 */
TEST(ec_pa_configurator_t, handle_presence_announcement_null_frame)
{
    std::cout << "Entering handle_presence_announcement_null_frame test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETHER_ADDR_LEN], bool) {};
    ec_pa_configurator_t configurator("66:77:88:99:AA:BB", {0x0A,0x0B,0x0C,0x0D,0x0E,0x0F}, ops, sec_ctx, true, cb);
    uint8_t src_mac[ETHER_ADDR_LEN] = {0};
    EXPECT_FALSE(configurator.handle_presence_announcement(nullptr, 12, src_mac));
    std::cout << "Exiting handle_presence_announcement_null_frame test" << std::endl;
}
/**
 * @brief Verify that handle_presence_announcement returns false when the source MAC address is null
 *
 * This test validates that the handle_presence_announcement function correctly handles a null source MAC address by returning false. By invoking the API with a null pointer for the source MAC, it ensures that the function performs the necessary error checking.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create dummy operations and security context, instantiate configurator, prepare a zeroed frame buffer, set source MAC pointer to null, and invoke handle_presence_announcement | ops = make_dummy_ops(), sec_ctx = make_dummy_sec_ctx(), configurator parameters = "66:77:88:99:AA:BB", {0x0A,0x0B,0x0C,0x0D,0x0E,0x0F}, true, callback; frameSize = EC_FRAME_BASE_SIZE; buffer = 0-initialized array; sa = nullptr | API should return false; Assertion: EXPECT_FALSE(ret) | Should Pass |
 */
TEST(ec_pa_configurator_t, handle_presence_announcement_null_mac) {
    std::cout << "Entering handle_presence_announcement_null_mac test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETHER_ADDR_LEN], bool) {};
    ec_pa_configurator_t configurator("66:77:88:99:AA:BB", {0x0A,0x0B,0x0C,0x0D,0x0E,0x0F}, ops, sec_ctx, true, cb);
    constexpr size_t frameSize = EC_FRAME_BASE_SIZE;
    uint8_t buffer[frameSize] = {0};
    ec_frame_t* frame = reinterpret_cast<ec_frame_t*>(buffer);
    uint8_t* sa = nullptr;
    bool ret = configurator.handle_presence_announcement(frame, frameSize, sa);
    EXPECT_FALSE(ret);
    std::cout << "Exiting handle_presence_announcement_null_mac test" << std::endl;
}
/**
 * @brief Test handle_presence_announcement function to validate behavior when hash attribute is missing
 *
 * This test verifies that when the frame provided to the handle_presence_announcement API is missing the hash attribute,
 * the function returns false, indicating that the required hash attribute was not present in the frame.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 006@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                           | Test Data                                                                                                                                                                              | Expected Result                                              | Notes       |
 * | :--------------: | ----------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ | ----------- |
 * | 01               | Invoke handle_presence_announcement with a frame missing the hash attribute data                      | frame.category=3, frame.action=4, frame.oui=0x01-0x02-0x03, frame.oui_type=2, frame.crypto_suite=2, frame.frame_type=2, attr_data_len=4, src_mac=0xAA-0xBB-0xCC-0xDD-0xEE-0xFF, frameSize=EC_FRAME_BASE_SIZE+sizeof(ec_net_attribute_t)+4 | API returns false and EXPECT_FALSE(ret) assertion passes       | Should Fail |
 */
TEST(ec_pa_configurator_t, handle_presence_announcement_missing_hash)
{
    std::cout << "Entering handle_presence_announcement_missing_hash test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETHER_ADDR_LEN], bool) {};
    ec_pa_configurator_t configurator("66:77:88:99:AA:BB", {0x0A,0x0B,0x0C,0x0D,0x0E,0x0F}, ops, sec_ctx, true, cb);
    constexpr size_t attr_data_len = 4;
    constexpr size_t frameSize = EC_FRAME_BASE_SIZE + sizeof(ec_net_attribute_t) + attr_data_len;
    uint8_t* buffer = new uint8_t[frameSize]{0};
    ec_frame_t* frame = reinterpret_cast<ec_frame_t*>(buffer);
    frame->category = 3;
    frame->action   = 4;
    frame->oui[0] = 0x01; frame->oui[1] = 0x02; frame->oui[2] = 0x03;
    frame->oui_type = 2;
    frame->crypto_suite = 2;
    frame->frame_type   = 2;
    uint8_t src_mac[ETHER_ADDR_LEN] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    bool ret = configurator.handle_presence_announcement(frame, frameSize, src_mac);
    EXPECT_FALSE(ret);
    // Cleanup
    delete[] buffer;
    std::cout << "Exiting handle_presence_announcement_missing_hash test" << std::endl;
}
/**
 * @brief Test to ensure that handle_recfg_announcement returns false when no attribute data is provided in the announcement frame
 *
 * This test sets up an ec_pa_configurator_t instance with dummy operations, a dummy security context, and a handshake callback. It then creates a dummy EC frame with required header fields but without any valid attribute entries. The handle_recfg_announcement method is invoked with this frame, and the test verifies that the method returns false, which is the expected outcome when no attributes are present.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 007@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Log the entry into the test | None | "Entering handle_recfg_announcement_no_attributes test" printed to stdout | Should be successful |
 * | 02 | Initialize dummy operations, security context, and handshake callback | ops = make_dummy_ops(), sec_ctx = make_dummy_sec_ctx(), cb = lambda(uint8_t[ETHER_ADDR_LEN], bool) {} | Dummy objects and callback are successfully initialized | Should be successful |
 * | 03 | Construct ec_pa_configurator_t instance with specified MAC addresses and dummy dependencies | MAC = "66:77:88:99:AA:BB", hardware address = {0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}, enable flag = true | Configurator object is created without errors | Should be successful |
 * | 04 | Prepare an EC frame with proper header fields and no attribute data | frameSize = EC_FRAME_BASE_SIZE, frame->category = 3, frame->action = 5, frame->oui = {0x01, 0x02, 0x03}, frame->oui_type = 2, frame->crypto_suite = 2, frame->frame_type = 3, sa = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, src_al_mac = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66} | EC frame is correctly set with no additional attribute data | Should be successful |
 * | 05 | Invoke handle_recfg_announcement method with the prepared frame and source addresses | Input arguments: frame, frameSize, sa, src_al_mac; Expected output: ret = false | Method returns false and the assertion (EXPECT_FALSE(ret)) passes | Should Pass |
 * | 06 | Log the exit from the test | None | "Exiting handle_recfg_announcement_no_attributes test" printed to stdout | Should be successful |
 */
TEST(ec_pa_configurator_t, handle_recfg_announcement_no_attributes)
{
    std::cout << "Entering handle_recfg_announcement_no_attributes test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETHER_ADDR_LEN], bool) {};
    ec_pa_configurator_t configurator("66:77:88:99:AA:BB", {0x0A,0x0B,0x0C,0x0D,0x0E,0x0F}, ops, sec_ctx, true, cb);
    constexpr size_t frameSize = EC_FRAME_BASE_SIZE;
    uint8_t buffer[frameSize] = {0};
    ec_frame_t* frame = reinterpret_cast<ec_frame_t*>(buffer);
    frame->category = 3;
    frame->action   = 5;
    frame->oui[0] = 0x01; frame->oui[1] = 0x02; frame->oui[2] = 0x03;
    frame->oui_type    = 2;
    frame->crypto_suite = 2;
    frame->frame_type  = 3;
    uint8_t sa[ETH_ALEN]         = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    uint8_t src_al_mac[ETH_ALEN] = {0x11,0x22,0x33,0x44,0x55,0x66};
    bool ret = configurator.handle_recfg_announcement(frame, frameSize, sa, src_al_mac);
    EXPECT_FALSE(ret);
    std::cout << "Exiting handle_recfg_announcement_no_attributes test" << std::endl;
}
/**
 * @brief Verify that handle_recfg_announcement returns false when the frame pointer is null.
 *
 * Tests that the handle_recfg_announcement method gracefully handles a null frame input by returning false.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 008
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                              | Test Data                                                                                                       | Expected Result                                           | Notes       |
 * | :--------------: | ------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- | ----------- |
 * | 01               | Invoke handle_recfg_announcement with a null frame pointer and frameSize 0 | frame = nullptr, frameSize = 0, sa = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF}, src_al_mac = {0x11,0x22,0x33,0x44,0x55,0x66} | API returns false and EXPECT_FALSE(ret) assertion passes   | Should Fail |
 */
TEST(ec_pa_configurator_t, handle_recfg_announcement_null_frame)
{
    std::cout << "Entering handle_recfg_announcement_null_frame test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETHER_ADDR_LEN], bool) {};
    ec_pa_configurator_t configurator("66:77:88:99:AA:BB", {0x0A,0x0B,0x0C,0x0D,0x0E,0x0F}, ops, sec_ctx, true, cb);
    uint8_t sa[ETH_ALEN]         = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    uint8_t src_al_mac[ETH_ALEN] = {0x11,0x22,0x33,0x44,0x55,0x66};
    ec_frame_t* frame = nullptr;
    size_t frameSize = 0;
    bool ret = configurator.handle_recfg_announcement(frame, frameSize, sa, src_al_mac);
    EXPECT_FALSE(ret);
    std::cout << "Exiting handle_recfg_announcement_null_frame test" << std::endl;
}
/**
 * @brief Verify that handle_recfg_announcement returns false when a null source MAC address is provided.
 *
 * This test validates that when the handle_recfg_announcement API is invoked with a null source MAC address (sa),
 * it correctly identifies the invalid input and returns false. This ensures robustness against erroneous configuration
 * scenarios in the system.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 009@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke handle_recfg_announcement with a valid frame and null source MAC address | frame.category = 3, frame.action = 5, frame.oui = {0x01,0x02,0x03}, frame.oui_type = 2, frame.crypto_suite = 2, frame.frame_type = 3; frameSize = EC_FRAME_BASE_SIZE; sa = nullptr, src_al_mac = {0x11,0x22,0x33,0x44,0x55,0x66} | API returns false and EXPECT_FALSE(ret) assertion passes | Should Fail |
 */
TEST(ec_pa_configurator_t, handle_recfg_announcement_null_mac) {
    std::cout << "Entering handle_recfg_announcement_null_mac test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETHER_ADDR_LEN], bool) {};
    ec_pa_configurator_t configurator("66:77:88:99:AA:BB", {0x0A,0x0B,0x0C,0x0D,0x0E,0x0F}, ops, sec_ctx, true, cb);
    constexpr size_t frameSize = EC_FRAME_BASE_SIZE;
    uint8_t buffer[frameSize] = {0};
    ec_frame_t* frame = reinterpret_cast<ec_frame_t*>(buffer);
    frame->category = 3;
    frame->action   = 5;
    frame->oui[0] = 0x01; frame->oui[1] = 0x02; frame->oui[2] = 0x03;
    frame->oui_type = 2;
    frame->crypto_suite = 2;
    frame->frame_type = 3;
    uint8_t* sa = nullptr;
    uint8_t src_al_mac[ETH_ALEN] = {0x11,0x22,0x33,0x44,0x55,0x66};
    bool ret = configurator.handle_recfg_announcement(frame, frameSize, sa, src_al_mac);
    EXPECT_FALSE(ret);
    std::cout << "Exiting handle_recfg_announcement_null_mac test" << std::endl;
}
/**
 * @brief Verify that handle_auth_response returns false when src_mac is null.
 *
 * This test verifies that the handle_auth_response method correctly handles a scenario 
 * where the source MAC address pointer (src_mac) is a null pointer. The objective is to 
 * ensure that the API does not process a null src_mac and returns false as expected.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke handle_auth_response with src_mac set to nullptr to simulate a null MAC condition | frame = buff, len = 3, src_mac = nullptr, src_al_mac = [0x11,0x22,0x33,0x44,0x55,0x66] | Should return false and cause EXPECT_FALSE(ret) to pass | Should Fail |
 */
TEST(ec_pa_configurator_t, handle_auth_response_null_mac) {
    std::cout << "Entering handle_auth_response_null_mac test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETHER_ADDR_LEN], bool) {};
    ec_pa_configurator_t configurator("66:77:88:99:AA:BB", {0x0A,0x0B,0x0C,0x0D,0x0E,0x0F}, ops, sec_ctx, true, cb);
    uint8_t buff[] = {0x10,0x20,0x30};
    unsigned int len = sizeof(buff);
    uint8_t* src_mac = nullptr;
    uint8_t src_al_mac[ETH_ALEN] = {0x11,0x22,0x33,0x44,0x55,0x66};
    bool ret = configurator.handle_auth_response(reinterpret_cast<ec_frame_t*>(buff), len, src_mac, src_al_mac);
    EXPECT_FALSE(ret);
    std::cout << "Exiting handle_auth_response_null_mac test" << std::endl;
}
/**
 * @brief Validate that handle_auth_response returns false for a null frame with zero length.
 *
 * This test verifies that the function handle_auth_response correctly handles invalid input by returning false when provided with a null data frame and a frame length of zero. The test sets up a configurator with dummy parameters, including MAC addresses, dummy operation and security context objects, and a callback function. It then invokes the API with a null frame pointer and zero length, ensuring that the API detects the invalid input and returns false.
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
 * | Variation / Step | Description                                                                  | Test Data                                                                                                                                                         | Expected Result                                           | Notes             |
 * | :--------------: | ---------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- | ----------------- |
 * | 01               | Create dummy operation and security context using helper functions           | ec_ops_t = make_dummy_ops(), ec_persistent_sec_ctx_t = make_dummy_sec_ctx()                                                                                          | Dummy context objects created successfully                | Should be successful |
 * | 02               | Define a handshake callback and initialize the configurator with dummy MACs    | configurator initialized with mac "66:77:88:99:AA:BB", secondary mac {0x0A,0x0B,0x0C,0x0D,0x0E,0x0F}, operations, security context, true flag, callback         | Configurator object initialized without issues            | Should be successful |
 * | 03               | Setup source MAC addresses for the API invocation                            | src_mac = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF}, src_al_mac = {0x11,0x22,0x33,0x44,0x55,0x66}                                                                           | Source MAC addresses defined                              | Should be successful |
 * | 04               | Invoke handle_auth_response with a null frame pointer and zero frame length    | frame = nullptr, len = 0, src_mac as defined, src_al_mac as defined                                                                                                 | API returns false; EXPECT_FALSE(ret) assertion passes     | Should Pass       |
 */
TEST(ec_pa_configurator_t, handle_auth_response_null_frame_zero_len)
{
    std::cout << "Entering handle_auth_response_null_frame_zero_len test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETHER_ADDR_LEN], bool) {};
    ec_pa_configurator_t configurator("66:77:88:99:AA:BB", {0x0A,0x0B,0x0C,0x0D,0x0E,0x0F},ops,sec_ctx, true, cb);
    uint8_t src_mac[ETHER_ADDR_LEN] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    uint8_t src_al_mac[ETH_ALEN]   = {0x11,0x22,0x33,0x44,0x55,0x66};
    bool ret = configurator.handle_auth_response(nullptr, 0, src_mac, src_al_mac);
    EXPECT_FALSE(ret);
    std::cout << "Exiting handle_auth_response_null_frame_zero_len test" << std::endl;
}
/**
 * @brief Verify that handle_cfg_request returns false when provided with a null buffer
 *
 * This test verifies that the ec_pa_configurator_t::handle_cfg_request method correctly handles the scenario where the buffer pointer is null.
 * It ensures that the API does not process an invalid (null) configuration buffer and returns a false indicator as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 012@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize ec_pa_configurator_t with dummy operations, security context, and a valid callback | MAC = "AA:BB:CC:DD:EE:FF", IP = {0xDE,0xAD,0xBE,0xEF,0x0E,0x0F}, ops = make_dummy_ops(), sec_ctx = make_dummy_sec_ctx(), callback = lambda function | Configurator object is created successfully | Should be successful |
 * | 02 | Invoke handle_cfg_request with a null buffer along with a specific length and source address | buff = nullptr, len = 20, sa = {0x01,0x23,0x45,0x67,0x89,0xAB} | Returns false; assertion EXPECT_FALSE(result) passes | Should Pass |
 */
TEST(ec_pa_configurator_t, handle_cfg_request_null_buffer) 
{
    std::cout << "Entering handle_cfg_request_null_buffer test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETHER_ADDR_LEN], bool) {};
    ec_pa_configurator_t configurator("AA:BB:CC:DD:EE:FF", {0xDE,0xAD,0xBE,0xEF,0x0E,0x0F}, ops, sec_ctx, true, cb);
    uint8_t* buff = nullptr;
    unsigned int len = 20;
    uint8_t sa[6] = {0x01,0x23,0x45,0x67,0x89,0xAB};
    bool result = configurator.handle_cfg_request(buff, len, sa);
    EXPECT_FALSE(result);
    std::cout << "Exiting handle_cfg_request_null_buffer test" << std::endl;
}
/**
 * @brief Verify that handle_cfg_request fails when provided a null MAC address.
 *
 * This test evaluates the behavior of the handle_cfg_request API when a null MAC address (sa) is provided. 
 * It ensures that the configuration request handling correctly identifies the invalid MAC input and returns false.
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
 * | Variation / Step | Description                                                               | Test Data                                                                                                                  | Expected Result                                                       | Notes      |
 * | :--------------: | ------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | ---------- |
 * | 01               | Invoke handle_cfg_request with a valid buffer and null MAC address input    | buff = {0x10,0x20,0x30,0x40}, len = 4, sa = nullptr, config parameters: "AA:BB:CC:DD:EE:FF", {0xDE,0xAD,0xBE,0xEF}, ops, sec_ctx, true, cb | Return value false and EXPECT_FALSE(result) assertion passes          | Should Pass |
 */
TEST(ec_pa_configurator_t, handle_cfg_request_nullmac) {
    std::cout << "Entering handle_cfg_request_nullmac test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETHER_ADDR_LEN], bool) {};
    ec_pa_configurator_t configurator("AA:BB:CC:DD:EE:FF", {0xDE,0xAD,0xBE,0xEF}, ops, sec_ctx, true, cb);
    uint8_t buff[] = {0x10,0x20,0x30,0x40};
    unsigned int len = sizeof(buff);
    uint8_t* sa = nullptr;
    bool result = configurator.handle_cfg_request(buff, len, sa);
    EXPECT_FALSE(result);
    std::cout << "Exiting handle_cfg_request_nullmac test" << std::endl;
}
/**
 * @brief Test the behavior of handle_cfg_result when a null frame is provided
 *
 * This test verifies that the handle_cfg_result API properly handles a null frame input. It sets up a dummy configurator and invokes the API with a null frame, and checks whether the API returns false as expected.
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
 * | Variation / Step | Description                                                        | Test Data                                                                                             | Expected Result                                    | Notes       |
 * | :--------------: | ------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------- | -------------------------------------------------- | ----------- |
 * | 01               | Invoke handle_cfg_result API with a null frame parameter             | frame = nullptr, len = EC_FRAME_BASE_SIZE, sa = 0xAA,0xBB,0xCC,0xDD,0xEE,0xFF                         | API returns false and assertion EXPECT_FALSE passes | Should Fail |
 */
TEST(ec_pa_configurator_t, handle_cfg_result_null_frame)
{
    std::cout << "Entering handle_cfg_result_null_frame test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETHER_ADDR_LEN], bool) {};
    ec_pa_configurator_t configurator(
        "66:77:88:99:AA:BB",{0x0A,0x0B,0x0C,0x0D,0x0E,0x0F},ops, sec_ctx, true, cb);
    ec_frame_t* frame = nullptr;
    size_t len = EC_FRAME_BASE_SIZE;
    uint8_t sa[ETH_ALEN] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    bool ret = configurator.handle_cfg_result(frame, len, sa);
    EXPECT_FALSE(ret);
    std::cout << "Exiting handle_cfg_result_null_frame test" << std::endl;
}
/**
 * @brief Verify that handle_cfg_result returns false when the source address is null
 *
 * This test verifies that the API handle_cfg_result of the ec_pa_configurator_t class returns false when invoked with a null source address. This condition is tested to ensure that the function correctly handles cases where the MAC address is not provided.
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
 * | Variation / Step | Description                                                        | Test Data                                                                                                                        | Expected Result                                          | Notes       |
 * | :--------------: | ------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- | ----------- |
 * | 01               | Call handle_cfg_result with valid frame pointer, valid length, and a null source address | frame = pointer to ec_frame_t derived from a valid buffer of EC_FRAME_BASE_SIZE bytes, len = EC_FRAME_BASE_SIZE, sa = nullptr | Returns false as verified by EXPECT_FALSE(ret)          | Should Fail |
 */
TEST(ec_pa_configurator_t, handle_cfg_result_null_mac)
{
    std::cout << "Entering handle_cfg_result_null_mac test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETHER_ADDR_LEN], bool) {};
    ec_pa_configurator_t configurator(
         "66:77:88:99:AA:BB",{0x0A,0x0B,0x0C,0x0D,0x0E,0x0F},ops, sec_ctx, true, cb);
    uint8_t buffer[EC_FRAME_BASE_SIZE] = {0};
    ec_frame_t* frame = reinterpret_cast<ec_frame_t*>(buffer);
    size_t len = EC_FRAME_BASE_SIZE;
    uint8_t* sa = nullptr;
    bool ret = configurator.handle_cfg_result(frame, len, sa);
    EXPECT_FALSE(ret);
    std::cout << "Exiting handle_cfg_result_null_mac test" << std::endl;
}
/**
 * @brief Test the behavior of handle_connection_status_result when a NULL frame is provided.
 *
 * This test verifies that when a null frame is passed to the handle_connection_status_result API, the function returns false.
 * The objective is to ensure that the API can gracefully handle an invalid input (null frame) and the assertion EXPECT_FALSE(ret) passes.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 016@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                 | Test Data                                                                                                                            | Expected Result                                                        | Notes             |
 * | :--------------: | --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------- | ----------------- |
 * | 01               | Log the entry message for the test                                          | None                                                                                                                                | "Entering handle_connection_status_result null frame test" message logged | Should be successful |
 * | 02               | Initialize dummy operations, secure context, and handshake callback         | ops = make_dummy_ops(), sec_ctx = make_dummy_sec_ctx(), cb = lambda function                                                           | Dummy objects and callback are correctly initialized                   | Should be successful |
 * | 03               | Create ec_pa_configurator_t instance with provided MAC addresses and contexts | mac1 = "66:77:88:99:AA:BB", mac2 = {0x0A,0x0B,0x0C,0x0D,0x0E,0x0F}, ops, sec_ctx, enabled = true                                               | Configurator instance is created successfully                           | Should be successful |
 * | 04               | Prepare input parameters for the API call                                   | frame = nullptr, len = EC_FRAME_BASE_SIZE, sa = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF}                                                         | Inputs are correctly set for the negative test scenario                   | Should be successful |
 * | 05               | Invoke handle_connection_status_result and validate the result              | API call: ret = configurator.handle_connection_status_result(frame, len, sa)                                                         | API returns false and EXPECT_FALSE(ret) assertion passes                  | Should Fail       |
 * | 06               | Log the exit message for the test                                           | None                                                                                                                                | "Exiting handle_connection_status_result null frame test" message logged   | Should be successful |
 */
TEST(ec_pa_configurator_t, handle_connection_status_result_null_frame)
{
    std::cout << "Entering handle_connection_status_result_null_frame test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETHER_ADDR_LEN], bool) {};
    ec_pa_configurator_t configurator(
        "66:77:88:99:AA:BB",{0x0A,0x0B,0x0C,0x0D,0x0E,0x0F},ops, sec_ctx, true, cb);
    ec_frame_t* frame = nullptr;
    size_t len = EC_FRAME_BASE_SIZE;
    uint8_t sa[ETH_ALEN] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    bool ret = configurator.handle_connection_status_result(frame, len, sa);
    EXPECT_FALSE(ret);
    std::cout << "Exiting handle_connection_status_result_null_frame test" << std::endl;
}
/**
 * @brief Verify that handle_connection_status_result returns false when given a null MAC address pointer.
 *
 * This test verifies that when a null pointer is provided for the source address (sa) to the handle_connection_status_result API,
 * the function correctly handles the error condition and returns false. The test sets up a dummy configuration, operations, security context,
 * and a handshake callback before invoking the API with a null source address. The assertion checks that the function returns false,
 * which is the expected behavior when the MAC address pointer is null.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | ----------- | --------- | -------------- | ----- |
 * | 01 | Initialize dummy operations and security context, create configurator with valid BSSID and MAC, then call handle_connection_status_result with a valid frame pointer, size equal to EC_FRAME_BASE_SIZE, and a null source address pointer (sa) | frame: pointer to ec_frame_t (buffer of size EC_FRAME_BASE_SIZE) = valid, len = EC_FRAME_BASE_SIZE, sa = nullptr | API returns false, verified by EXPECT_FALSE(ret) | Should Fail |
 */
TEST(ec_pa_configurator_t, handle_connection_status_result_null_mac)
{
    std::cout << "Entering handle_connection_status_result_null_mac test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETHER_ADDR_LEN], bool) {};
    ec_pa_configurator_t configurator(
        "66:77:88:99:AA:BB",{0x0A,0x0B,0x0C,0x0D,0x0E,0x0F},ops, sec_ctx, true, cb);
    uint8_t buffer[EC_FRAME_BASE_SIZE] = {0};
    ec_frame_t* frame = reinterpret_cast<ec_frame_t*>(buffer);
    size_t len = EC_FRAME_BASE_SIZE;
    uint8_t* sa = nullptr;
    bool ret = configurator.handle_connection_status_result(frame, len, sa);
    EXPECT_FALSE(ret);
    std::cout << "Exiting handle_connection_status_result_null_mac test" << std::endl;
}
/**
 * @brief Validate that process_proxy_encap_dpp_msg returns false when provided a null encap TLV pointer
 *
 * This test verifies that the process_proxy_encap_dpp_msg API correctly handles a scenario where the encap TLV pointer is null. The function is expected to return false, ensuring that the error handling for a null TLV input is properly implemented.
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
 * | 01 | Call process_proxy_encap_dpp_msg with a null encap TLV pointer to verify error handling | encap_tlv = nullptr, encap_tlv_len = sizeof(em_encap_dpp_t), peer_info = nullptr, peer_info_len = 0, src_al_mac = {0x00,0x11,0x22,0x33,0x44,0x55} | Returns false; EXPECT_FALSE assertion passes | Should Fail |
 */
TEST(ec_pa_configurator_t, process_proxy_encap_dpp_msg_null_encap_tlv)
{
    std::cout << "Entering process_proxy_encap_dpp_msg_null_encap_tlv test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETHER_ADDR_LEN], bool) {};
    ec_pa_configurator_t configurator(
        "66:77:88:99:AA:BB",{0x0A,0x0B,0x0C,0x0D,0x0E,0x0F},ops, sec_ctx, true, cb);
    uint8_t src_al_mac[ETH_ALEN] = {0x00,0x11,0x22,0x33,0x44,0x55};
    bool ret = configurator.process_proxy_encap_dpp_msg(nullptr,sizeof(em_encap_dpp_t),nullptr,0,src_al_mac);
    EXPECT_FALSE(ret);
    std::cout << "Exiting process_proxy_encap_dpp_msg_null_encap_tlv test" << std::endl;
}
/**
 * @brief Validate that process_proxy_encap_dpp_msg returns false when invoked with a zero encapsulation length.
 *
 * This test verifies that when the process_proxy_encap_dpp_msg API is called with a zero value for the encapsulation length, 
 * it correctly handles the scenario by returning false. This ensures that the function does not process invalid or insufficient data.
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
 * | 01 | Invoke process_proxy_encap_dpp_msg with zero encapsulation length and verify its response | encap = {} , encap_len = 0, second_param = nullptr, third_param = 0, src_al_mac = {0} | Returns false; Assertion: EXPECT_FALSE(ret) | Should Pass |
 */
TEST(ec_pa_configurator_t, process_proxy_encap_dpp_msg_zero_encap_len)
{
    std::cout << "Entering process_proxy_encap_dpp_msg_zero_encap_len test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETHER_ADDR_LEN], bool) {};
    ec_pa_configurator_t configurator(
        "66:77:88:99:AA:BB",{0x0A,0x0B,0x0C,0x0D,0x0E,0x0F},ops, sec_ctx, true, cb);
    em_encap_dpp_t encap = {};
    uint8_t src_al_mac[ETH_ALEN] = {0};
    bool ret = configurator.process_proxy_encap_dpp_msg(&encap,0,nullptr,0,src_al_mac);
    EXPECT_FALSE(ret);
    std::cout << "Exiting process_proxy_encap_dpp_msg_zero_encap_len test" << std::endl;
}
/**
 * @brief Verify that process_proxy_encap_dpp_msg returns false when there is no GAS session available.
 *
 * This test verifies the behavior of the process_proxy_encap_dpp_msg API when invoked without an active GAS session.
 * It creates a dummy TLV structure representing a DPP frame with an enrollee MAC address, sets the frame type,
 * and invokes the method with a nullptr for the GAS session. The API is expected to return false under these conditions.
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
 * | Variation / Step | Description                                                                                                                | Test Data                                                                                                                                                                                                              | Expected Result                                        | Notes       |
 * | :--------------: | -------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ | ----------- |
 * | 01               | Invoke process_proxy_encap_dpp_msg with a properly constructed TLV for a DPP message and no GAS session configured.         | tlv: valid TLV with dpp_frame_indicator = 0, enrollee_mac_addr_present = 1, dest_mac = 00:11:22:33:44:55, frame_type = ec_frame_type_easymesh, payload_len = WIFI_MTU_SIZE+10, alloc_size = computed size; gas_session = nullptr, gas_session_len = 0, dummy_mac = 00:00:00:00:00:00 | API returns false; EXPECT_FALSE(ret) assertion passes     | Should Pass |
 */
TEST(ec_pa_configurator_t, process_proxy_encap_dpp_msg_no_gas_session)
{
    std::cout << "Entering process_proxy_encap_dpp_msg_no_gas_session test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETHER_ADDR_LEN], bool) {};
    ec_pa_configurator_t configurator(
		    "66:77:88:99:AA:BB",{0x0A,0x0B,0x0C,0x0D,0x0E,0x0F},ops, sec_ctx, true, cb);
    uint8_t dummy_mac[ETH_ALEN] = {0};
    uint16_t payload_len = WIFI_MTU_SIZE + 10;
    size_t alloc_size = sizeof(em_encap_dpp_t) + sizeof(mac_addr_t) + 1 + 2 + payload_len;
    em_encap_dpp_t* tlv = reinterpret_cast<em_encap_dpp_t*>(calloc(1, alloc_size));
    ASSERT_NE(tlv, nullptr);
    tlv->dpp_frame_indicator = 0;
    tlv->enrollee_mac_addr_present = 1;
    uint8_t dest_mac[ETH_ALEN] = {0x00,0x11,0x22,0x33,0x44,0x55};
    memcpy(tlv->data, dest_mac, sizeof(mac_addr_t));
    tlv->data[6] = static_cast<uint8_t>(ec_frame_type_t::ec_frame_type_easymesh);
    uint16_t net_payload_len = htons(payload_len);
    memcpy(&tlv->data[7], &net_payload_len, sizeof(net_payload_len));
    memset(&tlv->data[9], 0xAA, payload_len);
    bool ret = configurator.process_proxy_encap_dpp_msg(tlv,static_cast<uint16_t>(alloc_size),nullptr,0,dummy_mac);
    EXPECT_FALSE(ret);
    free(tlv);
    std::cout << "Exiting process_proxy_encap_dpp_msg_no_gas_session test" << std::endl;
}
/**
 * @brief Verify that the process_proxy_encap_dpp_msg function returns false when the enrollee MAC is not provided.
 *
 * This test validates the error handling of the process_proxy_encap_dpp_msg API by simulating the scenario where the TLV structure lacks an enrollee MAC address. The API is expected to detect this missing field and return false, ensuring that the configuration process does not proceed with invalid inputs.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 021@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize dummy operations, secure context, and create a configurator instance with specified MAC addresses. | ops = make_dummy_ops(), sec_ctx = make_dummy_sec_ctx(), configurator constructed with MAC "66:77:88:99:AA:BB" and key {0x0A,0x0B,0x0C,0x0D,0x0E,0x0F} | Configurator instance created successfully | Should be successful |
 * | 02 | Construct a TLV structure with dpp_frame_indicator set to 1, enrollee_mac_addr_present set to 0, and fill the frame data. Then, invoke process_proxy_encap_dpp_msg with this TLV and dummy MAC data. | tlv->dpp_frame_indicator = 1, tlv->enrollee_mac_addr_present = 0, tlv->data[0] = ec_frame_type_easymesh, payload_len = 20, alloc_size = sizeof(em_encap_dpp_t) + 1 + 2 + payload_len, dummy_mac = {0} | API returns false indicating that the enrollee MAC is missing | Should Pass |
 */
TEST(ec_pa_configurator_t, process_proxy_encap_dpp_msg_no_enrollee_mac)
{
    std::cout << "Entering process_proxy_encap_dpp_msg_no_enrollee_mac test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETHER_ADDR_LEN], bool) {};
    ec_pa_configurator_t configurator("66:77:88:99:AA:BB", {0x0A,0x0B,0x0C,0x0D,0x0E,0x0F}, ops, sec_ctx, true, cb);
    uint8_t dummy_mac[ETH_ALEN] = {0};
    uint16_t payload_len = 20;
    size_t alloc_size = sizeof(em_encap_dpp_t) + 1 + 2 + payload_len;
    em_encap_dpp_t* tlv = reinterpret_cast<em_encap_dpp_t*>(calloc(1, alloc_size));
    ASSERT_NE(tlv, nullptr);
    tlv->dpp_frame_indicator = 1;
    tlv->enrollee_mac_addr_present = 0;
    tlv->data[0] = static_cast<uint8_t>(ec_frame_type_t::ec_frame_type_easymesh);
    uint16_t net_payload_len = htons(payload_len);
    memcpy(&tlv->data[1], &net_payload_len, sizeof(net_payload_len));
    memset(&tlv->data[3], 0xBB, payload_len);
    bool ret = configurator.process_proxy_encap_dpp_msg(tlv, static_cast<uint16_t>(alloc_size), nullptr, 0, dummy_mac);
    EXPECT_FALSE(ret);
    free(tlv);
    std::cout << "Exiting process_proxy_encap_dpp_msg_no_enrollee_mac test" << std::endl;
}
/**
 * @brief Verify that process_proxy_encap_dpp_msg properly handles parsing failure scenario
 *
 * This test verifies that the process_proxy_encap_dpp_msg API returns failure when encountering a parsing error due to an invalid message buffer. The test sets up a dummy configuration and context, invokes the API with a crafted buffer, and asserts that the function returns false.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 022@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Construct dummy operations, security context, and create a configurator instance with specified MAC addresses and flags | ops = make_dummy_ops(), sec_ctx = make_dummy_sec_ctx(), primary MAC = "66:77:88:99:AA:BB", secondary MAC = "0x0A,0x0B,0x0C,0x0D,0x0E,0x0F", secure flag = true | Configurator instance created successfully | Should be successful |
 * | 02 | Prepare an 8-byte buffer and reinterpret it as an em_encap_dpp_t structure; initialize a source AL MAC | Buffer = {0,0,0,0,0,0,0,0}, src_al_mac = "AA,BB,CC,DD,EE,FF" | Data prepared as expected | Should be successful |
 * | 03 | Invoke process_proxy_encap_dpp_msg with the invalid message to simulate a parsing failure | Input: encap pointer, buffer length = 8, secondary buffer = nullptr, secondary length = 0, src_al_mac = "AA,BB,CC,DD,EE,FF" | API returns false indicating parse failure | Should Pass |
 * | 04 | Validate the API return value using EXPECT_FALSE assertion | EXPECT_FALSE(ret) on return value from API | Test asserts that the return value is false | Should Pass |
 */
TEST(ec_pa_configurator_t, process_proxy_encap_dpp_msg_parse_failure)
{
    std::cout << "Entering process_proxy_encap_dpp_msg_parse_failure test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETHER_ADDR_LEN], bool) {};
    ec_pa_configurator_t configurator("66:77:88:99:AA:BB",{0x0A,0x0B,0x0C,0x0D,0x0E,0x0F},ops, sec_ctx, true, cb);
    uint8_t buffer[8] = {0};
    em_encap_dpp_t* encap = reinterpret_cast<em_encap_dpp_t*>(buffer);
    uint8_t src_al_mac[ETH_ALEN] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    bool ret = configurator.process_proxy_encap_dpp_msg(encap,sizeof(buffer),nullptr,0,src_al_mac);
    EXPECT_FALSE(ret);
    std::cout << "Exiting process_proxy_encap_dpp_msg_parse_failure test" << std::endl;
}
/**
 * @brief Test for process_direct_encap_dpp_msg handling of a null frame input
 *
 * This test verifies that the process_direct_encap_dpp_msg API returns false when 
 * provided with a null pointer for the frame data. This checks the robustness of the 
 * input validation within the API for handling erroneous inputs.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 023
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                  | Test Data                                                         | Expected Result                                                                    | Notes         |
 * | :--------------: | ---------------------------------------------------------------------------- | ----------------------------------------------------------------- | ---------------------------------------------------------------------------------- | ------------- |
 * | 01               | Invoke process_direct_encap_dpp_msg with a null frame to test input validation | frame = nullptr, frame_length = 10, src_mac = {0, 0, 0, 0, 0, 0}  | API returns false and EXPECT_FALSE assertion passes indicating proper error check | Should Fail   |
 */
TEST(ec_pa_configurator_t, process_direct_encap_dpp_msg_null_frame)
{
    std::cout << "Entering process_direct_encap_dpp_msg_null_frame test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETHER_ADDR_LEN], bool) {};
    ec_pa_configurator_t configurator("66:77:88:99:AA:BB",{0x0A,0x0B,0x0C,0x0D,0x0E,0x0F},ops, sec_ctx, true, cb);
    uint8_t src_mac[ETH_ALEN] = {0};
    bool ret = configurator.process_direct_encap_dpp_msg(nullptr, 10, src_mac);
    EXPECT_FALSE(ret);
    std::cout << "Exiting process_direct_encap_dpp_msg_null_frame test" << std::endl;
}
/**
 * @brief Verify that process_direct_encap_dpp_msg returns false when invoked with a zero frame length.
 *
 * This test case evaluates the behavior of process_direct_encap_dpp_msg in ec_pa_configurator_t by providing a zero-length frame.
 * The objective is to ensure the function correctly handles an edge case where the frame length is invalid, thereby returning false.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 024
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                 | Test Data                                                                                                                          | Expected Result                                                                             | Notes             |
 * | :--------------: | --------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ----------------- |
 * | 01               | Setup the test by creating dummy operations, security context, and callback | No direct input; internal calls: make_dummy_ops(), make_dummy_sec_ctx(), callback lambda for handshake_completed_handler | Dummy objects created successfully                                                          | Should be successful |
 * | 02               | Instantiate ec_pa_configurator_t with valid MAC, BSSID, ops, sec_ctx, flag, and callback | MAC: "66:77:88:99:AA:BB", BSSID: {0x0A,0x0B,0x0C,0x0D,0x0E,0x0F}, ops from dummy, sec_ctx from dummy, flag: true, callback lambda | Configurator instance initialized successfully                                              | Should be successful |
 * | 03               | Prepare an empty ec_frame_t object and zeroed source MAC for the test         | frame: default initialized ec_frame_t, src_mac: {0,0,0,0,0,0}                                                                         | Frame and source MAC setup correctly                                                         | Should be successful |
 * | 04               | Invoke process_direct_encap_dpp_msg with a zero frame length                  | input: frame pointer (reinterpret_cast<uint8_t*>(&frame)), frame length = 0, src_mac = {0,0,0,0,0,0}                                 | API returns false and assertion EXPECT_FALSE(ret) passes                                      | Should Fail       |
 */
TEST(ec_pa_configurator_t, process_direct_encap_dpp_msg_zero_frame_length)
{
    std::cout << "Entering process_direct_encap_dpp_msg_zero_frame_length test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETHER_ADDR_LEN], bool) {};
    ec_pa_configurator_t configurator("66:77:88:99:AA:BB",{0x0A,0x0B,0x0C,0x0D,0x0E,0x0F},ops, sec_ctx, true, cb);
    ec_frame_t frame = {};
    uint8_t src_mac[ETH_ALEN] = {0};
    bool ret = configurator.process_direct_encap_dpp_msg(reinterpret_cast<uint8_t*>(&frame), 0, src_mac);
    EXPECT_FALSE(ret);
    std::cout << "Exiting process_direct_encap_dpp_msg_zero_frame_length test" << std::endl;
}
/**
 * @brief Test that verifies process_direct_encap_dpp_msg returns false for unsupported frame types
 *
 * This test invokes the API process_direct_encap_dpp_msg with a frame that has a type of ec_frame_type_cfg_result,
 * which is not supported by the configurator. The objective is to ensure that the method correctly identifies this as an
 * unsupported frame type and returns false accordingly.
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
 * | Variation / Step | Description                                                                                                         | Test Data                                                                                                                            | Expected Result                          | Notes      |
 * | :--------------: | ------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------- | ---------- |
 * | 01               | Call process_direct_encap_dpp_msg with a frame of type ec_frame_type_cfg_result to verify it returns false            | frame.frame_type = ec_frame_type_cfg_result, frame pointer = reinterpret_cast<uint8_t*>(&frame), size = sizeof(frame), src_mac = {0,0,0,0,0,0} | API returns false and ASSERT_FALSE evaluates to true | Should Fail |
 */
TEST(ec_pa_configurator_t, process_direct_encap_dpp_msg_unsupported_frametype)
{
    std::cout << "Entering process_direct_encap_dpp_msg_unsupported_frametype test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETHER_ADDR_LEN], bool) {};
    ec_pa_configurator_t configurator("66:77:88:99:AA:BB",{0x0A,0x0B,0x0C,0x0D,0x0E,0x0F},ops, sec_ctx, true, cb);
    ec_frame_t frame = {};
    frame.frame_type = ec_frame_type_cfg_result;
    uint8_t src_mac[ETH_ALEN] = {0};
    bool ret = configurator.process_direct_encap_dpp_msg(reinterpret_cast<uint8_t*>(&frame),sizeof(frame),src_mac);
    EXPECT_FALSE(ret);
    std::cout << "Exiting process_direct_encap_dpp_msg_unsupported_frametype test" << std::endl;
}
/**
 * @brief Validates spurious GAS comeback request handling in ec_pa_configurator_t.
 *
 * This test verifies that the ec_pa_configurator_t instance properly processes a spurious GAS comeback request.
 * It confirms that the API call returns true when the GAS comeback request is handled, ensuring the correct operation of the configurator.
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
 * | Variation / Step | Description                                                                                          | Test Data                                                                                                                     | Expected Result                                                                 | Notes              |
 * | :--------------: | ---------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- | ------------------ |
 * | 01               | Create dummy ec_ops_t and ec_persistent_sec_ctx_t objects; define a dummy handshake callback          | ops = make_dummy_ops(), sec_ctx = make_dummy_sec_ctx(), callback = lambda with dummy values                                     | Dummy objects and callback are created successfully                            | Should be successful |
 * | 02               | Instantiate ec_pa_configurator_t with specified MAC, IP, operations, security context, and callback   | mac = "66:77:88:99:AA:BB", ip = {0x0A,0x0B,0x0C,0x0D,0x0E,0x0F}, ops, sec_ctx, enable flag = true, callback                  | Instance is constructed without errors                                         | Should be successful |
 * | 03               | Prepare dummy buffer, its length, and source MAC address for the GAS comeback request invocation      | dummy_buff = {0,0,0,0,0,0,0,0}, dummy_len = 8, sa = {0x00,0x11,0x22,0x33,0x44,0x55}                                        | Test data variables are set up correctly                                       | Should be successful |
 * | 04               | Invoke the handle_gas_comeback_request API and validate its return value using an assertion          | Call handle_gas_comeback_request(dummy_buff, dummy_len, sa)                                                                   | API returns true and EXPECT_TRUE(ret) assertion passes                         | Should Pass        |
 */
TEST(ec_pa_configurator_t, handle_gas_comeback_request_spurious_request)
{
    std::cout << "Entering handle_gas_comeback_request_spurious_request test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETHER_ADDR_LEN], bool) {};
    ec_pa_configurator_t configurator("66:77:88:99:AA:BB",{0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},ops,sec_ctx,true,cb);
    uint8_t sa[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t dummy_buff[8] = {0};
    unsigned int dummy_len = sizeof(dummy_buff);
    bool ret = configurator.handle_gas_comeback_request(dummy_buff,dummy_len,sa);
    EXPECT_TRUE(ret);
    std::cout << "Exiting handle_gas_comeback_request_spurious_request test" << std::endl;
}
/**
 * @brief Validate that handle_gas_comeback_request returns false when provided with a null MAC address.
 *
 * This test verifies that the handle_gas_comeback_request API correctly handles a scenario where the MAC address parameter is passed as a null pointer. It ensures that the function fails gracefully by returning false, indicating that no valid action could be taken due to the null MAC input.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 027@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize dummy operational parameters and security context. | ops = make_dummy_ops(), sec_ctx = make_dummy_sec_ctx() | Dummy contexts are initialized successfully. | Should be successful |
 * | 02 | Create the ec_pa_configurator_t object with valid MAC address, IP address, operational parameters, security context, a boolean flag, and a callback function. | MAC = "66:77:88:99:AA:BB", IP = {0x0A,0x0B,0x0C,0x0D,0x0E,0x0F}, ops, sec_ctx, bool = true, cb = lambda | Object is constructed successfully. | Should be successful |
 * | 03 | Invoke handle_gas_comeback_request using a dummy buffer, its length and a null MAC address parameter. | dummy_buff = {0,0,0,0,0,0,0,0}, dummy_len = size of dummy_buff, mac = nullptr | The API returns false because the MAC address parameter is null. | Should Pass |
 */
TEST(ec_pa_configurator_t, handle_gas_comeback_request_null_mac)
{
    std::cout << "Entering handle_gas_comeback_request_null_mac test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETHER_ADDR_LEN], bool) {};
    ec_pa_configurator_t configurator("66:77:88:99:AA:BB", {0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}, ops, sec_ctx, true, cb);
    uint8_t dummy_buff[8] = {0};
    unsigned int dummy_len = sizeof(dummy_buff);
    bool ret = configurator.handle_gas_comeback_request(dummy_buff, dummy_len, nullptr);
    EXPECT_FALSE(ret);
    std::cout << "Exiting handle_gas_comeback_request_null_mac test" << std::endl;
}
/**
 * @brief Validate successful enabling of CCE using toggle operation.
 *
 * This test verifies that calling m_toggle_cce with the 'true' flag on an ec_pa_configurator_t instance correctly enables the CCE functionality. It ensures that the configurator behaves as expected by returning true.
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
 * | Variation / Step | Description                                                                                                                                         | Test Data                                                                                                                 | Expected Result                                              | Notes             |
 * | :--------------: | --------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ | ----------------- |
 * | 01               | Create dummy operations and a dummy security context required to initialize the configurator.                                                      | No input parameters; used functions: make_dummy_ops(), make_dummy_sec_ctx()                                             | Dummy operations and security context are created successfully | Should be successful |
 * | 02               | Initialize the ec_pa_configurator_t object with specified MAC addresses, a callback, and enable flag for CCE.                                       | input1 = "66:77:88:99:AA:BB", input2 = {0x0A,0x0B,0x0C,0x0D,0x0E,0x0F}, input3 = ops, input4 = sec_ctx, input5 = true, input6 = cb | The configurator is instantiated correctly                    | Should be successful |
 * | 03               | Invoke the m_toggle_cce method with the flag set to true and verify that the method returns true.                                                 | input = enable flag = true; output = ret from m_toggle_cce(true)                                                           | Returns true and matches the assertion EXPECT_TRUE(ret)      | Should Pass       |
 */
TEST(ec_pa_configurator_t, toggle_cce_enable)
{
    std::cout << "Entering toggle_cce_enable test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETHER_ADDR_LEN], bool) {};
    ec_pa_configurator_t configurator("66:77:88:99:AA:BB", {0x0A,0x0B,0x0C,0x0D,0x0E,0x0F},ops, sec_ctx, true, cb);
    bool ret = configurator.m_toggle_cce(true);
    EXPECT_TRUE(ret);
    std::cout << "Exiting toggle_cce_enable test" << std::endl;
}
/**
 * @brief Verify that the toggle_cce function correctly disables CCE when requested.
 *
 * This test checks whether the m_toggle_cce method in the ec_pa_configurator_t class correctly processes a disable CCE command, returning true as expected. The test uses dummy operations and context to simulate the environment.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 029@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                                         | Test Data                                                                                                                                                | Expected Result                                                           | Notes       |
 * | :----:           | ------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------| ------------------------------------------------------------------------- | ----------- |
 * | 01               | Create dummy operations and security context, instantiate configurator, and call m_toggle_cce with false as argument. | ip_addr = "66:77:88:99:AA:BB", mac = {0x0A,0x0B,0x0C,0x0D,0x0E,0x0F}, ops = make_dummy_ops(), sec_ctx = make_dummy_sec_ctx(), initial_flag = true, toggle_flag = false | Return value of m_toggle_cce is true, validating that the disable operation is successful | Should Pass |
 */
TEST(ec_pa_configurator_t, toggle_cce_disable)
{
    std::cout << "Entering toggle_cce_disable test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETHER_ADDR_LEN], bool){};
    ec_pa_configurator_t configurator("66:77:88:99:AA:BB", {0x0A,0x0B,0x0C,0x0D,0x0E,0x0F}, ops, sec_ctx, true, cb);
    bool ret = configurator.m_toggle_cce(false);
    EXPECT_TRUE(ret);
    std::cout << "Exiting toggle_cce_disable test" << std::endl;
}
/**
 * @brief Test for process_1905_eapol_encap_msg API with null frame pointer.
 *
 * This test verifies that the process_1905_eapol_encap_msg function gracefully handles a null frame pointer input
 * and returns false as expected.
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
 * | Variation / Step | Description                                                  | Test Data                                             | Expected Result                                                         | Notes       |
 * | :--------------: | ------------------------------------------------------------ | ----------------------------------------------------- | ----------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke process_1905_eapol_encap_msg with null frame pointer    | frame = nullptr, frame_length = 100, src_mac = 00:00:00:00:00:00:00 | API returns false and EXPECT_FALSE assertion passes                      | Should Fail |
 */
TEST(ec_pa_configurator_t, process_1905_eapol_encap_msg_null_frame)
{
    std::cout << "Entering process_1905_eapol_encap_msg_null_frame test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETHER_ADDR_LEN], bool){};
    ec_pa_configurator_t configurator(
        "66:77:88:99:AA:BB",{0x0A,0x0B,0x0C,0x0D,0x0E,0x0F},ops,sec_ctx,true,cb);
    uint8_t src_mac[ETH_ALEN] = {0};
    bool ret = configurator.process_1905_eapol_encap_msg(nullptr, 100, src_mac);
    EXPECT_FALSE(ret);
    std::cout << "Exiting process_1905_eapol_encap_msg_null_frame test" << std::endl;
}
/**
 * @brief Verify that process_1905_eapol_encap_msg returns false when invoked with a zero-length frame.
 *
 * This test verifies that when the process_1905_eapol_encap_msg API is provided with a frame length of zero, it handles the condition appropriately by returning false. The test uses dummy operations and a dummy security context to simulate the required environment.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 031@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                      | Test Data                                                                                                         | Expected Result                                           | Notes              |
 * | :--------------: | ----------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- | ------------------ |
 * | 01               | Setup dummy operations, security context, and callback required for the configurator instance.   | ops = make_dummy_ops(), sec_ctx = make_dummy_sec_ctx(), cb = lambda(uint8_t[ETHER_ADDR_LEN], bool)                  | Dummy components initialized successfully               | Should be successful |
 * | 02               | Instantiate ec_pa_configurator and invoke process_1905_eapol_encap_msg with a zero-length frame.   | configurator parameters: "66:77:88:99:AA:BB", {0x0A,0x0B,0x0C,0x0D,0x0E,0x0F}, ops, sec_ctx, true, cb; frame = {0}, length = 0, src_mac = {0} | Returns false indicating failure in processing zero-length frame | Should Fail        |
 * | 03               | Print exiting test message.                                                                      | N/A                                                                                                               | Console output displays test exit message               | Should be successful |
 */
TEST(ec_pa_configurator_t, process_1905_eapol_encap_msg_zero_len)
{
    std::cout << "Entering process_1905_eapol_encap_msg_zero_len test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETHER_ADDR_LEN], bool){};
    ec_pa_configurator_t configurator(
        "66:77:88:99:AA:BB",{0x0A,0x0B,0x0C,0x0D,0x0E,0x0F},ops,sec_ctx,true,cb);
    uint8_t frame[64] = {0};
    uint8_t src_mac[ETH_ALEN] = {0};
    bool ret = configurator.process_1905_eapol_encap_msg(frame, 0, src_mac);
    EXPECT_FALSE(ret);
    std::cout << "Exiting process_1905_eapol_encap_msg_zero_len test" << std::endl;
}
/**
 * @brief Test that process_1905_eapol_encap_msg returns false when called with a null MAC address.
 *
 * This test verifies that the process_1905_eapol_encap_msg API correctly handles a scenario where it is provided a valid frame and frame length but a null pointer for the MAC address. The function should detect the null MAC and return false, ensuring robust error handling.
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
 * | 01 | Invoke process_1905_eapol_encap_msg with a valid frame, proper frame length, and a null MAC pointer | frame = [0,0,...,0] (64 zeros), size = 64, mac = nullptr | API returns false and EXPECT_FALSE assertion passes | Should Fail |
 */
TEST(ec_pa_configurator_t, process_1905_eapol_encap_msg_null_mac)
{
    std::cout << "Entering process_1905_eapol_encap_msg_null_mac test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETHER_ADDR_LEN], bool){};
    ec_pa_configurator_t configurator(
        "66:77:88:99:AA:BB",{0x0A,0x0B,0x0C,0x0D,0x0E,0x0F},ops,sec_ctx,true,cb);
    uint8_t frame[64] = {0};
    bool ret = configurator.process_1905_eapol_encap_msg(frame, sizeof(frame), nullptr);
    EXPECT_FALSE(ret);
    std::cout << "Exiting process_1905_eapol_encap_msg_null_mac test" << std::endl;
}
/**
 * @brief Verify that process_1905_eapol_encap_msg returns false when no valid key context is provided
 *
 * This test case sets up a configurator instance with dummy operational functions and a dummy security context, but without a proper key context. It then invokes process_1905_eapol_encap_msg with a dummy frame and a specified source MAC address. The expected outcome is that the method returns false, demonstrating the failure to process the message due to the absence of a valid key context.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke process_1905_eapol_encap_msg with a dummy frame and source MAC while configurator is initialized without a valid key context | frame = [0, 0, ..., 0] (64 bytes), frame_size = 64, src_mac = {0x10,0x11,0x12,0x13,0x14,0x15}, MAC = "66:77:88:99:AA:BB", key = {0x0A,0x0B,0x0C,0x0D,0x0E,0x0F} | Returns false; EXPECT_FALSE(ret) assertion passes | Should Fail |
 */
TEST(ec_pa_configurator_t, process_1905_eapol_encap_msg_no_key_context)
{
    std::cout << "Entering process_1905_eapol_encap_msg_no_key_context test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETHER_ADDR_LEN], bool){};
    ec_pa_configurator_t configurator(
        "66:77:88:99:AA:BB",{0x0A,0x0B,0x0C,0x0D,0x0E,0x0F},ops,sec_ctx,true,cb);
    uint8_t frame[64] = {0};
    uint8_t src_mac[ETH_ALEN] = {0x10,0x11,0x12,0x13,0x14,0x15};
    bool ret = configurator.process_1905_eapol_encap_msg(frame, sizeof(frame), src_mac);
    EXPECT_FALSE(ret);
    std::cout << "Exiting process_1905_eapol_encap_msg_no_key_context test" << std::endl;
}
/**
 * @brief Validate that invoking teardown_connection with a non-present MAC address does not throw an exception.
 *
 * Validate that the API correctly handles a scenario where the provided MAC address is not present in the active connection list,
 * ensuring that the method call is safely executed without throwing an exception. This helps in verifying the robustness of the teardown functionality.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 034
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                                            | Test Data                                                                                                                     | Expected Result                                                                                      | Notes      |
 * | :--------------: | ---------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- | ---------- |
 * | 01               | Instantiate dummy ops, security context, configurator instance, and invoke teardown_connection with a non-existent MAC address "11:22:33:44:55:66". | input: MAC address = "11:22:33:44:55:66", ops = dummy, sec_ctx = dummy, callback = lambda, connection_flag = true, other params as given | The teardown_connection method should be executed without throwing any exception and handle the missing MAC appropriately. | Should Pass |
 */
TEST(ec_pa_configurator_t, teardown_connection_not_present_mac)
{
    std::cout << "Entering teardown_connection_not_present_mac test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETHER_ADDR_LEN], bool){};
    ec_pa_configurator_t configurator(
        "66:77:88:99:AA:BB",{0x0A,0x0B,0x0C,0x0D,0x0E,0x0F},ops,sec_ctx,true,cb);
    EXPECT_NO_THROW({
        configurator.teardown_connection("11:22:33:44:55:66");
    });
    std::cout << "Exiting teardown_connection_not_present_mac test" << std::endl;
}
/**
 * @brief Tests that the teardown_connection API handles an empty MAC address input gracefully
 *
 * This test validates that when an empty string is passed to the teardown_connection function,
 * the function does not throw any exception. The function is part of a secure connection teardown mechanism.
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
 * | 01 | Invoke teardown_connection API with an empty MAC address | input: MAC address = "", additional inputs: MAC = "66:77:88:99:AA:BB", sec_ctx = dummy, ops = dummy, flag = true, cb = lambda function | API does not throw an exception | Should Pass |
 */
TEST(ec_pa_configurator_t, teardown_connection_empty_mac)
{
    std::cout << "Entering teardown_connection_empty_mac test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETHER_ADDR_LEN], bool){};
    ec_pa_configurator_t configurator(
        "66:77:88:99:AA:BB",{0x0A,0x0B,0x0C,0x0D,0x0E,0x0F},ops,sec_ctx,true,cb);
    EXPECT_NO_THROW({
        configurator.teardown_connection("");
    });
    std::cout << "Exiting teardown_connection_empty_mac test" << std::endl;
}
/**
 * @brief Tests that the secure 1905 layer fails to start with a null MAC address
 *
 * This test verifies that invoking the start_secure_1905_layer API with a null MAC address correctly returns false. This ensures that the API properly validates its input and prevents invalid initialization.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create dummy operational context, persistent security context, and a handshake completion callback. | ops = make_dummy_ops(), sec_ctx = make_dummy_sec_ctx(), cb = lambda(uint8_t[ETHER_ADDR_LEN], bool) | Dependencies are created successfully. | Should be successful |
 * | 02 | Instantiate ec_pa_configurator_t with valid MAC address and dummy parameters. | configurator = ec_pa_configurator_t("66:77:88:99:AA:BB", {0x0A,0x0B,0x0C,0x0D,0x0E,0x0F}, ops, sec_ctx, true, cb) | Configurator instance is created correctly with valid parameters. | Should be successful |
 * | 03 | Invoke start_secure_1905_layer with a null MAC address. | Input: mac = nullptr, Expected Return: false | API returns false due to invalid (null) MAC address validation. | Should Pass |
 */
TEST(ec_pa_configurator_t, start_secure_1905_layer_null_mac)
{
    std::cout << "Entering start_secure_1905_layer_null_mac test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETHER_ADDR_LEN], bool){};
    ec_pa_configurator_t configurator(
        "66:77:88:99:AA:BB",{0x0A,0x0B,0x0C,0x0D,0x0E,0x0F},ops,sec_ctx,true,cb);
    bool ret = configurator.start_secure_1905_layer(nullptr);
    EXPECT_FALSE(ret);
    std::cout << "Exiting start_secure_1905_layer_null_mac test" << std::endl;
}
/**
 * @brief Test the default security context retrieval
 *
 * This test verifies that the ec_pa_configurator instance correctly returns a non-null pointer to the persistent security context when the get_sec_ctx() method is called. It uses dummy operations, a dummy security context, and a valid handshake callback to simulate a proper environment.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 037@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Instantiate dummy operations, dummy security context, and valid callback; create an ec_pa_configurator object; invoke get_sec_ctx() method | MAC = "66:77:88:99:AA:BB", IP = {0x0A,0x0B,0x0C,0x0D,0x0E,0x0F}, ops = make_dummy_ops(), sec_ctx = make_dummy_sec_ctx(), secure flag = true, callback = valid lambda | Returns non-null pointer to persistent security context; EXPECT_NE assertion passes | Should Pass |
 */
TEST(ec_pa_configurator_t, get_sec_ctx_default)
{
    std::cout << "Entering get_sec_ctx_default test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETHER_ADDR_LEN], bool){};
    ec_pa_configurator_t configurator(
        "66:77:88:99:AA:BB",{0x0A,0x0B,0x0C,0x0D,0x0E,0x0F},ops,sec_ctx,true,cb);
    ec_persistent_sec_ctx_t* ctx = configurator.get_sec_ctx();
    EXPECT_NE(ctx, nullptr);
    std::cout << "Exiting get_sec_ctx_default test" << std::endl;
}
/**
 * @brief Validate get_al_conn_ctx returns nullptr for an unknown MAC address.
 *
 * This test verifies that when the get_al_conn_ctx API is invoked with a MAC address that is not configured or known, 
 * it correctly returns a nullptr. This ensures that the configurator handles unknown MAC addresses appropriately.
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
 * | 01 | Create ec_pa_configurator_t object with dummy operations and persistent security context, then invoke get_al_conn_ctx with an unknown MAC address | configurator MAC = "66:77:88:99:AA:BB", secondary MAC = {0x0A,0x0B,0x0C,0x0D,0x0E,0x0F}, dummy ops, dummy sec_ctx, flag = true, callback = lambda, input MAC = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF} | The API returns a nullptr and EXPECT_EQ confirms the return value is nullptr | Should Pass |
 */
TEST(ec_pa_configurator_t, get_al_conn_ctx_unknown_mac)
{
    std::cout << "Entering get_al_conn_ctx_unknown_mac test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETHER_ADDR_LEN], bool){};
    ec_pa_configurator_t configurator(
        "66:77:88:99:AA:BB",{0x0A,0x0B,0x0C,0x0D,0x0E,0x0F},ops,sec_ctx,true,cb);
    uint8_t mac[ETH_ALEN] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    ec_connection_context_t* ctx = configurator.get_al_conn_ctx(mac);
    EXPECT_EQ(ctx, nullptr);
    std::cout << "Exiting get_al_conn_ctx_unknown_mac test" << std::endl;
}
/**
 * @brief Verify get_al_conn_ctx returns nullptr when provided with a null MAC address
 *
 * This test validates that the get_al_conn_ctx method correctly handles a scenario where the MAC address is passed as a null pointer. The function is expected to check for invalid input and return a nullptr, ensuring that no invalid connection context is created.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 039
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                     | Test Data                                                                                                                   | Expected Result                                     | Notes        |
 * | :---------------:| ---------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- | ------------ |
 * | 01               | Call get_al_conn_ctx with a null MAC address                      | mac = nullptr, configuration details provided by dummy ops and dummy sec_ctx, callback, and boolean parameter = true         | API returns nullptr for the connection context; EXPECT_EQ(ctx, nullptr) passes | Should Pass  |
 */
TEST(ec_pa_configurator_t, get_al_conn_ctx_null_mac)
{
    std::cout << "Entering get_al_conn_ctx_null_mac test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler cb = [](uint8_t[ETHER_ADDR_LEN], bool){};
    ec_pa_configurator_t configurator(
        "66:77:88:99:AA:BB",{0x0A,0x0B,0x0C,0x0D,0x0E,0x0F},ops,sec_ctx,true,cb);
    uint8_t* mac = nullptr;
    ec_connection_context_t* ctx = configurator.get_al_conn_ctx(mac);
    EXPECT_EQ(ctx, nullptr);
    std::cout << "Exiting get_al_conn_ctx_null_mac test" << std::endl;
}
