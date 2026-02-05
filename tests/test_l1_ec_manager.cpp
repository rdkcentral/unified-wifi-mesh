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
#include <gmock/gmock.h>
#include <stdio.h>
#include <ec_util.h>
#include "ec_manager.h"
#include <gtest/gtest.h>
#include <arpa/inet.h>

static ec_persistent_sec_ctx_t make_dummy_sec_ctx()
{
    ec_persistent_sec_ctx_t sec_ctx{};  // zero-init everything
    // Encryption is safely disabled when keys are null
    sec_ctx.C_signing_key   = nullptr;
    sec_ctx.pp_key          = nullptr;
    sec_ctx.net_access_key  = nullptr;
    sec_ctx.connector       = nullptr;
    return sec_ctx;
}

static ec_ops_t make_dummy_ops()
{
    ec_ops_t ops{};   // zero-init everything
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
 * @brief Verify that ec_manager_t constructor throws runtime_error when sec_ctx is not provided
 *
 * This test validates that when the ec_manager_t constructor is invoked with a null optional security context
 * (sec_ctx) while acting as the controller, the constructor throws a std::runtime_error. This behavior ensures
 * that the API correctly handles the scenario where the required security context is missing.
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
 * | Variation / Step | Description                                                                                      | Test Data                                                                                                                      | Expected Result                                         | Notes       |
 * | :--------------: | ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------- | ----------- |
 * | 01               | Invoke ec_manager_t constructor with al_mac_addr, is_controller, dummy ops, null sec_ctx, and handler | al_mac_addr = "11:22:33:44:55:66", is_controller = true, ops = dummy ops, sec_ctx = nullopt, handler = lambda function | std::runtime_error is thrown by the constructor         | Should Pass |
 */
TEST(ec_manager_t, ec_manager_t_controller_without_sec_ctx_throws)
{
    std::cout << "Entering ec_manager_t_controller_without_sec_ctx_throws test" << std::endl;
    std::string al_mac_addr = "11:22:33:44:55:66";
    bool is_controller = true;
    ec_ops_t ops = make_dummy_ops();
    std::optional<ec_persistent_sec_ctx_t> sec_ctx = std::nullopt;
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    std::cout << "Invoking ec_manager_t constructor with values:" << std::endl;
    std::cout << "al_mac_addr=" << al_mac_addr << ", is_controller=" << is_controller << ", sec_ctx=nullopt" << std::endl;
    EXPECT_THROW({
        ec_manager_t mgr(al_mac_addr, ops, is_controller, sec_ctx, handler);
    }, std::runtime_error);

    std::cout << "Exiting ec_manager_t_controller_without_sec_ctx_throws test" << std::endl;
}
/**
 * @brief Test creation of ec_manager_t object for an enrollee without security context
 *
 * This test verifies that the ec_manager_t constructor can successfully create an object for an enrollee when the optional security context is not provided (i.e., std::nullopt). It ensures that no exception is thrown during object creation and validates the proper handling of missing security context.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 002@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup test input parameters for ec_manager_t object creation | al_mac_addr = "22:33:44:55:66:77", is_controller = false, ops = dummyOps, sec_ctx = std::nullopt, handler = lambda function | Parameters are correctly initialized | Should be successful |
 * | 02 | Invoke ec_manager_t constructor within EXPECT_NO_THROW to verify object creation without security context | al_mac_addr = "22:33:44:55:66:77", is_controller = false, ops = dummyOps, sec_ctx = std::nullopt, handler = lambda function | ec_manager_t object is created successfully and no exception is thrown | Should Pass |
 */
TEST(ec_manager_t, ec_manager_t_enrollee_without_sec_ctx)
{
    std::cout << "Entering ec_manager_t_enrollee_without_sec_ctx test" << std::endl;
    std::string al_mac_addr = "22:33:44:55:66:77";
    bool is_controller = false;
    ec_ops_t ops = make_dummy_ops();
    std::optional<ec_persistent_sec_ctx_t> sec_ctx = std::nullopt;
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    std::cout << "Invoking ec_manager_t constructor with values:" << std::endl;
    std::cout << "al_mac_addr=" << al_mac_addr << ", is_controller=" << is_controller << ", sec_ctx=nullopt" << std::endl;
    EXPECT_NO_THROW({
        ec_manager_t mgr(al_mac_addr, ops, is_controller, sec_ctx, handler);
        std::cout << "ec_manager_t object successfully created for enrollee without security context" << std::endl;
    });
    std::cout << "Exiting ec_manager_t_enrollee_without_sec_ctx test" << std::endl;
}
/**
 * @brief Validate the creation of an ec_manager_t object for an enrollee with a valid security context
 *
 * This test verifies that the ec_manager_t constructor correctly initializes an enrollee instance when provided with a valid
 * security context along with other necessary parameters. The test ensures that no exceptions are thrown during the object creation.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 003@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke ec_manager_t constructor with a valid enrollee configuration and a provided security context | al_mac_addr = "33:44:55:66:77:88", is_controller = false, ops = dummy operations, sec_ctx = dummy security context, handler = lambda function | Constructor completes without throwing any exceptions and the object is successfully created | Should Pass |
 */
TEST(ec_manager_t, ec_manager_t_enrollee_with_sec_ctx)
{
    std::cout << "Entering ec_manager_t_enrollee_with_sec_ctx test" << std::endl;
    std::string al_mac_addr = "33:44:55:66:77:88";
    bool is_controller = false;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    std::cout << "Invoking ec_manager_t constructor with values:" << std::endl;
    std::cout << "al_mac_addr=" << al_mac_addr << ", is_controller=" << is_controller << ", sec_ctx=provided" << std::endl;
    EXPECT_NO_THROW({
        ec_manager_t mgr(al_mac_addr, ops, is_controller, sec_ctx, handler);
        std::cout << "ec_manager_t object successfully created for enrollee with security context" << std::endl;
    });
    std::cout << "Exiting ec_manager_t_enrollee_with_sec_ctx test" << std::endl;
}
/**
 * @brief Verify that ec_manager_t constructor properly handles an empty MAC address.
 *
 * This test checks that invoking the ec_manager_t constructor with an empty MAC address 
 * correctly results in an exception. The test ensures that the API enforces input validation 
 * for the MAC address parameter to prevent invalid configuration.
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
 * | Variation / Step | Description                                              | Test Data                                                                                                              | Expected Result                                               | Notes       |
 * | :--------------: | -------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- | ----------- |
 * | 01               | Invoke ec_manager_t constructor with an empty MAC address | al_mac_addr = "", is_controller = false, ops = dummy object from make_dummy_ops(),                                          sec_ctx = dummy object from make_dummy_sec_ctx(), handler = lambda function  | Constructor throws an exception due to invalid (empty) MAC address | Should Pass |
 */
TEST(ec_manager_t, ec_manager_t_empty_mac_address)
{
    std::cout << "Entering ec_manager_t_empty_mac_address test" << std::endl;
    std::string al_mac_addr = "";
    bool is_controller = false;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    std::cout << "Invoking ec_manager_t constructor with values:" << std::endl;
    std::cout << "al_mac_addr=<empty>, is_controller=" << is_controller << std::endl;
    EXPECT_ANY_THROW({
        ec_manager_t mgr(al_mac_addr, ops, is_controller, sec_ctx, handler);
        std::cout << "ec_manager_t object creation with empty MAC address failed" << std::endl;
    });
    std::cout << "Exiting ec_manager_t_empty_mac_address test" << std::endl;
}
/**
 * @brief Verify that ec_manager_t constructor throws an exception for a long MAC address string
 *
 * This test verifies that providing an overly long MAC address string to the ec_manager_t constructor results in an exception.
 * It ensures that the constructor correctly validates the MAC address format and fails when input exceeds the expected length.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 005@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                     | Test Data                                                                                                                       | Expected Result                                                                                             | Notes       |
 * | :--------------: | --------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke ec_manager_t constructor with a long MAC address string    | al_mac_addr = AA:BB:CC:DD:EE:FF:11:22:33:44:55:66, is_controller = false, ops = dummy operation, sec_ctx = dummy sec context, handler = lambda function | API should throw an exception as verified by EXPECT_ANY_THROW assertion                                      | Should Pass |
 */
TEST(ec_manager_t, ec_manager_t_long_mac_address_string)
{
    std::cout << "Entering ec_manager_t_long_mac_address_string test" << std::endl;
    std::string al_mac_addr = "AA:BB:CC:DD:EE:FF:11:22:33:44:55:66";
    bool is_controller = false;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    std::cout << "Invoking ec_manager_t constructor with values:" << std::endl;
    std::cout << "al_mac_addr=" << al_mac_addr << ", is_controller=" << is_controller << std::endl;
    EXPECT_ANY_THROW({
        ec_manager_t mgr(al_mac_addr, ops, is_controller, sec_ctx, handler);
        std::cout << "ec_manager_t object creation with long MAC address string failed" << std::endl;
    });
    std::cout << "Exiting ec_manager_t_long_mac_address_string test" << std::endl;
}
/**
 * @brief Verify that the ec_manager_t destructor properly deletes an instance without throwing exceptions when provided with a valid security context.
 *
 * This test creates an instance of ec_manager_t using valid parameters including a MAC address, dummy operations, a dummy security context, and a handshake handler. It then deletes the instance and ensures that no exceptions are thrown during the destruction process. This confirms that the destructor can handle the provided valid security context correctly.
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
 * | Variation / Step | Description                                                                                              | Test Data                                                                                                                                                                                              | Expected Result                                                                    | Notes       |
 * | :--------------: | -------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke the ec_manager_t constructor with valid parameters to create an instance                          | al_mac_addr = "AA:BB:CC:DD:EE:01", ops = make_dummy_ops(), is_controller = false, sec_ctx = make_dummy_sec_ctx(), handler = lambda(uint8_t[ETH_ALEN], bool) {}                    | Object is successfully created without any exceptions                             | Should Pass |
 * | 02               | Invoke the destructor using delete on the created instance to ensure proper cleanup without exception    | delete mgr                                                                                                                                                                                             | No exceptions are thrown; object is destroyed successfully and memory is deallocated | Should Pass |
 */
TEST(ec_manager_t, ec_manager_t_destructor_controller_valid_sec_ctx)
{
    std::cout << "Entering ec_manager_t_destructor_controller_valid_sec_ctx test" << std::endl;
    std::string al_mac_addr = "AA:BB:CC:DD:EE:01";
    ec_ops_t ops = make_dummy_ops();
    bool is_controller = false;
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    std::cout << "Invoking ec_manager_t constructor with values:" << std::endl;
    std::cout << "al_mac_addr=" << al_mac_addr << ", is_controller=" << is_controller << std::endl;
    ec_manager_t* mgr = new ec_manager_t(al_mac_addr, ops, is_controller, sec_ctx, handler);
    std::cout << "Invoking ec_manager_t destructor using delete" << std::endl;
    EXPECT_NO_THROW({
        delete mgr;
    });
    std::cout << "Exiting ec_manager_t_destructor_controller_valid_sec_ctx test" << std::endl;
}
/**
 * @brief Verifies that the handle_recv_ec_action_frame API correctly handles a nullptr frame.
 *
 * This test verifies that when handle_recv_ec_action_frame is invoked with an invalid (nullptr) frame pointer,
 * the API returns false indicating an error or non-successful handling. It ensures the robustness of the API
 * against null input for the frame parameter.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 007
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | ------------- | ----- |
 * | 01 | Initialize ec_manager_t with dummy operations and a valid MAC, construct necessary parameters, and invoke handle_recv_ec_action_frame with a nullptr frame. | frame = nullptr, len = sizeof(ec_frame_t), src_mac = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, recv_freq = 2412, ops = make_dummy_ops(), handler = lambda function | Return value should be false, validated by the EXPECT_FALSE assertion. | Should Pass |
 */
TEST(ec_manager_t, handle_recv_ec_action_frame_invalid_frame)
{
    std::cout << "Entering handle_recv_ec_action_frame_invalid_frame test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    ec_manager_t mgr("00:11:22:33:44:55", ops, false, std::nullopt, handler);
    ec_frame_t* frame = nullptr;
    size_t len = sizeof(ec_frame_t);
    uint8_t src_mac[ETHER_ADDR_LEN] = {0x00,0x11,0x22,0x33,0x44,0x55};
    unsigned int recv_freq = 2412;
    std::cout << "Invoking handle_recv_ec_action_frame with frame=nullptr"
              << ", recv_freq=" << recv_freq << std::endl;
    bool ret = mgr.handle_recv_ec_action_frame(frame, len, src_mac, recv_freq);
    std::cout << "Returned value: " << ret << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting handle_recv_ec_action_frame_invalid_frame test" << std::endl;
}
/**
 * @brief Test to verify the handling of EC action frames with an invalid MAC address.
 *
 * This test creates an instance of ec_manager_t with dummy operations and a valid manager MAC ("00:11:22:33:44:55"), and prepares an EC frame. It then calls handle_recv_ec_action_frame with a nullptr for the source MAC to simulate an invalid MAC input, ensuring that the function properly returns false.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Instantiate ec_manager_t with dummy operations, valid manager MAC, and handshake flag set to false. | input: MAC = "00:11:22:33:44:55", ops = dummy ops, handshake flag = false | ec_manager_t instance created successfully | Should be successful |
 * | 02 | Prepare an ec_frame_t with specific values for category, action, OUI, oui_type, crypto_suite, and frame_type. | input: frame.category = 0x04, frame.action = 0x09, frame.oui = {0x50, 0x6f, 0x9a}, frame.oui_type = DPP_OUI_TYPE, frame.crypto_suite = 0x01, frame.frame_type = ec_frame_type_auth_req, len = sizeof(ec_frame_t) | Frame is set up correctly for invalid MAC test | Should be successful |
 * | 03 | Invoke handle_recv_ec_action_frame with src_mac as nullptr and recv_freq = 2412. | input: src_mac = nullptr, recv_freq = 2412, output: ret (expected false) | API returns false indicating failure due to invalid MAC | Should Fail |
 */
TEST(ec_manager_t, handle_recv_ec_action_frame_invalid_MAC)
{
    std::cout << "Entering handle_recv_ec_action_frame_invalid_MAC test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    ec_manager_t mgr("00:11:22:33:44:55", ops, false, std::nullopt, handler);
    ec_frame_t frame{};
    frame.category = 0x04;
    frame.action = 0x09;
    frame.oui[0] = 0x50;
    frame.oui[1] = 0x6f;
    frame.oui[2] = 0x9a;
    frame.oui_type = DPP_OUI_TYPE;
    frame.crypto_suite = 0x01;
    frame.frame_type = ec_frame_type_auth_req;
    size_t len = sizeof(ec_frame_t);
    uint8_t* src_mac = nullptr;
    unsigned int recv_freq = 2412;
    std::cout << "Invoking handle_recv_ec_action_frame with src_mac=nullptr"
              << ", recv_freq=" << recv_freq << std::endl;
    bool ret = mgr.handle_recv_ec_action_frame(&frame, len, src_mac, recv_freq);
    std::cout << "Returned value: " << ret << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting handle_recv_ec_action_frame_invalid_MAC test" << std::endl;
}
/**
 * @brief Verify that handle_recv_ec_action_frame returns false for an unknown frame type
 *
 * This test validates that the ec_manager_t::handle_recv_ec_action_frame API correctly identifies and handles a frame with an unknown frame type (0xFF). The function should return false when such a frame is received, ensuring the robustness of the frame handling logic.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke handle_recv_ec_action_frame with a frame containing an unknown frame type (0xFF) | frame.category = 0x04, frame.action = 0x09, frame.oui = {0x50, 0x6f, 0x9a}, frame.oui_type = DPP_OUI_TYPE, frame.crypto_suite = 0x01, frame.frame_type = 0xFF, len = sizeof(ec_frame_t), src_mac = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, recv_freq = 2412 | API returns false and EXPECT_FALSE(ret) assertion passes | Should Pass |
 */
TEST(ec_manager_t, handle_recv_ec_action_frame_unknown_frame_type)
{
    std::cout << "Entering handle_recv_ec_action_frame_unknown_frame_type test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    ec_manager_t mgr("00:11:22:33:44:55", ops, false, std::nullopt, handler);
    ec_frame_t frame{};
    frame.category = 0x04;
    frame.action = 0x09;
    frame.oui[0] = 0x50;
    frame.oui[1] = 0x6f;
    frame.oui[2] = 0x9a;
    frame.oui_type = DPP_OUI_TYPE;
    frame.crypto_suite = 0x01;
    frame.frame_type = static_cast<ec_frame_type_t>(0xFF);
    size_t len = sizeof(ec_frame_t);
    uint8_t src_mac[ETHER_ADDR_LEN] = {0x00,0x11,0x22,0x33,0x44,0x55};
    unsigned int recv_freq = 2412;
    std::cout << "Invoking handle_recv_ec_action_frame with unknown frame_type=0xFF" << std::endl;
    bool ret = mgr.handle_recv_ec_action_frame(&frame, len, src_mac, recv_freq);
    std::cout << "Returned value: " << ret << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting handle_recv_ec_action_frame_unknown_frame_type test" << std::endl;
}
/**
 * @brief Verify that handle_recv_gas_pub_action_frame returns false when a null frame is provided
 *
 * This test creates an ec_manager_t instance with dummy operations and a dummy handshake_completed_handler.
 * It then calls handle_recv_gas_pub_action_frame with a null pointer for the frame, a length of 0, and a zeroed source MAC address.
 * The objective is to ensure that the function correctly detects the null frame and returns false, indicating an error in handling a null input.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 010
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke handle_recv_gas_pub_action_frame with a null frame pointer | frame = nullptr, len = 0, src_mac = {0,0,0,0,0,0} | Function returns false; assertion EXPECT_FALSE(ret) passes | Should Fail |
 */
TEST(ec_manager_t, handle_recv_gas_pub_action_frame_null_frame)
{
    std::cout << "Entering handle_recv_gas_pub_action_frame_null_frame test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    ec_manager_t mgr("00:11:22:33:44:55", ops, false, std::nullopt, handler);
    ec_gas_frame_base_t* frame = nullptr;
    size_t len = 0;
    uint8_t src_mac[ETH_ALEN] = {0};
    std::cout << "Invoking handle_recv_gas_pub_action_frame with frame=nullptr, len=" << len << std::endl;
    bool ret = mgr.handle_recv_gas_pub_action_frame(frame, len, src_mac);
    std::cout << "Returned value: " << ret << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting handle_recv_gas_pub_action_frame_null_frame test" << std::endl;
}
/**
 * @brief Verify that the ec_manager_t correctly handles a GAS public action frame with an unknown action.
 *
 * This test creates an ec_manager_t using dummy operations and a handshake handler, then constructs a GAS 
 * public action frame with an unsupported action (0xFF). The objective is to validate that the manager's 
 * handler (handle_recv_gas_pub_action_frame) returns false when it encounters an unknown action, ensuring 
 * that unexpected actions do not trigger erroneous behavior.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize dummy operations and handshake handler. | ops = make_dummy_ops(), handler = lambda | Dummy operations and handler initialized successfully | Should be successful |
 * | 02 | Instantiate ec_manager_t with provided MAC address, dummy operations, and handshake handler. | mac = "00:11:22:33:44:55", ops, config_flag = false, optional = std::nullopt | ec_manager_t instance created successfully | Should be successful |
 * | 03 | Setup ec_gas_frame_base_t frame with an unknown action and prepare the source MAC. | frame.action = 0xFF, len = sizeof(frame), src_mac = {0x00,0x11,0x22,0x33,0x44,0x55} | Frame structure and source MAC setup correctly | Should be successful |
 * | 04 | Invoke handle_recv_gas_pub_action_frame API with the constructed frame and source MAC. | frame pointer, len, src_mac | API returns false indicating the unknown action is not processed | Should Pass |
 * | 05 | Validate that the EXPECT_FALSE assertion catches the false return value. | ret = false | Assertion passes confirming the API behavior | Should Pass |
 */
TEST(ec_manager_t, handle_recv_gas_pub_action_frame_unknown_action)
{
    std::cout << "Entering handle_recv_gas_pub_action_frame_unknown_action test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    ec_manager_t mgr("00:11:22:33:44:55", ops, false, std::nullopt, handler);
    ec_gas_frame_base_t frame{};
    frame.action = 0xFF;
    size_t len = sizeof(frame);
    uint8_t src_mac[ETH_ALEN] = {0x00,0x11,0x22,0x33,0x44,0x55};
    std::cout << "Invoking handle_recv_gas_pub_action_frame with action=" << static_cast<int>(frame.action) << std::endl;
    bool ret = mgr.handle_recv_gas_pub_action_frame(&frame, len, src_mac);
    std::cout << "Returned value: " << ret << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting handle_recv_gas_pub_action_frame_unknown_action test" << std::endl;
}
/**
 * @brief Test to verify that the API correctly handles a null source MAC address.
 *
 * This test verifies that the handle_recv_gas_pub_action_frame function correctly handles
 * a scenario where a null pointer is passed for the source MAC address. The function is expected
 * to validate the input parameters and return false when the MAC address is null, ensuring robust error handling.
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
 * | Variation / Step | Description                                                                                           | Test Data                                                                                                                      | Expected Result                                                    | Notes         |
 * | :--------------: | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------ | ------------- |
 * | 01               | Create dummy operations, handshake handler, and instantiate ec_manager_t with valid parameters.      | input: MAC = "00:11:22:33:44:55", ops = dummy ops, secure flag = false, optional parameter = std::nullopt, handler = lambda    | Instance of ec_manager_t is successfully created                   | Should be successful |
 * | 02               | Initialize the GAS comeback response frame with action set to dpp_gas_comeback_resp and other fields.   | input: frame.base.action = dpp_gas_comeback_resp, fragment_id = 0, more_fragments = 0, comeback_resp_len = 0, len = sizeof(frame) | GAS comeback response frame is correctly initialized              | Should be successful |
 * | 03               | Invoke handle_recv_gas_pub_action_frame with a null source MAC and verify the returned value.         | input: frame pointer, len = sizeof(frame), src_mac = nullptr                                                                     | API returns false and EXPECT_FALSE(ret) assertion passes           | Should Fail   |
 */
TEST(ec_manager_t, handle_recv_gas_pub_action_frame_null_MAC)
{
    std::cout << "Entering handle_recv_gas_pub_action_frame_null_MAC test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    ec_manager_t mgr("00:11:22:33:44:55", ops, false, std::nullopt, handler);
    ec_gas_comeback_response_frame_t frame{};
    frame.base.action = dpp_gas_comeback_resp;
    frame.fragment_id = 0;
    frame.more_fragments = 0;
    frame.comeback_resp_len = 0;
    size_t len = sizeof(frame);
    uint8_t* src_mac = nullptr;
    std::cout << "Invoking handle_recv_gas_pub_action_frame with action=dpp_gas_comeback_resp, len=" << len << std::endl;
    bool ret = mgr.handle_recv_gas_pub_action_frame(reinterpret_cast<ec_gas_frame_base_t*>(&frame), len, src_mac);
    std::cout << "Returned value: " << ret << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting handle_recv_gas_pub_action_frame_null_MAC test" << std::endl;
}
/**
 * @brief Verify that cfg_onboard_enrollee fails when provided with nullptr enrollee data.
 *
 * This test verifies that invoking the cfg_onboard_enrollee function with a nullptr enrollee data pointer
 * results in a failure, ensuring proper error handling in the API when invalid or absent configuration data
 * is provided.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 013@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                        | Test Data                                              | Expected Result                                       | Notes       |
 * | :--------------: | ------------------------------------------------------------------ | ------------------------------------------------------ | ----------------------------------------------------- | ----------- |
 * | 01               | Call cfg_onboard_enrollee with a null pointer for enrollee data.   | data = nullptr, mgr initialized with dummy parameters  | API returns false indicating failure in processing null data. | Should Pass |
 */
TEST(ec_manager_t, cfg_onboard_enrollee_null_data_enrollee)
{
    std::cout << "Entering cfg_onboard_enrollee_null_data_enrollee test" << std::endl;
    ec_ops_t ops = make_dummy_ops();    
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    ec_manager_t mgr("00:11:22:33:44:55", ops, false, std::nullopt, handler);
    ec_data_t* data = nullptr;
    std::cout << "Invoking cfg_onboard_enrollee with data=nullptr" << std::endl;
    bool ret = mgr.cfg_onboard_enrollee(data);
    std::cout << "Returned value: " << ret << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting cfg_onboard_enrollee_null_data_enrollee test" << std::endl;
}
/**
 * @brief Validate that cfg_onboard_enrollee returns false when invoked in non-controller mode.
 *
 * This test verifies that the cfg_onboard_enrollee API correctly processes the request when the ec_manager_t instance
 * is configured with is_controller set to false. The expected behavior in this non-controller scenario is to return false.
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
 * | Variation / Step | Description                                                                 | Test Data                                                                                                                          | Expected Result                                     | Notes         |
 * | :--------------: | --------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- | ------------- |
 * | 01               | Instantiate ec_manager_t with is_controller set to false.                   | mac_address = "66:55:44:33:22:11", ops = default, is_controller = false, optional_param = std::nullopt, callback = nullptr      | ec_manager_t instance is created successfully.      | Should be successful |
 * | 02               | Invoke cfg_onboard_enrollee with a default ec_data_t pointer and validate the output. | data pointer = address of default ec_data_t instance                                                                                | API returns false as validated by EXPECT_FALSE.     | Should Pass   |
 */
TEST(ec_manager_t, cfg_onboard_enrollee_non_controller)
{
    std::cout << "Entering cfg_onboard_enrollee_non_controller test" << std::endl;
    ec_ops_t ops{};
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    ec_manager_t mgr("66:55:44:33:22:11", ops, false, std::nullopt, handler);
    ec_data_t data{};
    std::cout << "Invoking cfg_onboard_enrollee with is_controller=false" << std::endl;
    bool ret = mgr.cfg_onboard_enrollee(&data);
    std::cout << "Returned value: " << ret << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting cfg_onboard_enrollee_non_controller test" << std::endl;
}
/**
 * @brief Test enrollee_start_onboarding for unsupported bootstrapping version in enrollee mode
 *
 * This test verifies that the enrollee_start_onboarding API correctly rejects boot data with an unsupported bootstrapping version.
 * It creates an ec_manager_t instance with dummy operations and a dummy handshake handler, initializes boot data with version 1 (unsupported),
 * and then calls enrollee_start_onboarding. The function is expected to return false, indicating proper handling of the unsupported version.
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
 * | Variation / Step | Description                                                        | Test Data                                                                                 | Expected Result                                          | Notes              |
 * | :--------------: | ------------------------------------------------------------------ | ----------------------------------------------------------------------------------------- | -------------------------------------------------------- | ------------------ |
 * | 01               | Construct ec_manager_t instance with dummy operations and handler    | N/A                                                                                       | Instance should be created successfully                | Should be successful |
 * | 02               | Initialize ec_data_t structure with unsupported bootstrapping version| boot_data.version = 1, boot_data.mac_addr[0] = 0x02                                         | Data structure prepared properly                       | Should be successful |
 * | 03               | Call enrollee_start_onboarding with do_reconfig=false and ethernet=false| do_reconfig = false, ethernet = false, boot_data structure as above                         | Return value is false indicating rejection of boot data  | Should Pass         |
 * | 04               | Validate returned value using EXPECT_FALSE                           | ret = result of enrollee_start_onboarding(..) expected to be false                           | EXPECT_FALSE(ret) assertion passes                     | Should be successful |
 */
TEST(ec_manager_t, enrollee_start_onboarding_enrollee_mode_UnsupportedBootstrappingVersion)
{
    std::cout << "Entering enrollee_start_onboarding_enrollee_mode_UnsupportedBootstrappingVersion test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    ec_manager_t mgr("66:55:44:33:22:11", ops, false, std::nullopt, handler);
    ec_data_t boot_data{};
    memset(&boot_data, 0, sizeof(ec_data_t));
    boot_data.version = 1; // unsupported
    boot_data.mac_addr[0] = 0x02;
    bool do_reconfig = false;
    bool ethernet = false;
    std::cout << "Invoking enrollee_start_onboarding with do_reconfig="
              << do_reconfig << ", ethernet=" << ethernet << std::endl;
    bool ret = mgr.enrollee_start_onboarding(do_reconfig, &boot_data, ethernet);
    std::cout << "Returned value: " << ret << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting enrollee_start_onboarding_enrollee_mode_UnsupportedBootstrappingVersion test" << std::endl;
}
/**
 * @brief Verify that enrollment onboarding fails when boot data contains a zero MAC address.
 *
 * This test verifies that the enrollee_start_onboarding API returns false when invoked with boot data that has been zeroed out except for the version field.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize EC operations, handshake handler, and create an instance of ec_manager_t with a valid MAC ("66:55:44:33:22:11") and dummy operations | input: MAC = "66:55:44:33:22:11", ops = dummy operations, secure flag = false, optional config = std::nullopt, handler = lambda function | Instance created successfully | Should be successful |
 * | 02 | Prepare boot_data by zeroing memory and setting version to 2 (simulating zero MAC address scenario) | input: boot_data = { all fields zero, version = 2 } | boot_data properly initialized with zero values and version set | Should be successful |
 * | 03 | Set configuration flags do_reconfig and ethernet to false | input: do_reconfig = false, ethernet = false | Flags set to false | Should be successful |
 * | 04 | Invoke enrollee_start_onboarding API with prepared parameters | input: do_reconfig = false, boot_data pointer, ethernet = false; output: ret from API | API returns false; assertion EXPECT_FALSE(ret) passes | Should Fail |
 */
TEST(ec_manager_t, enrollee_start_onboarding_ZeroMacAddress)
{
    std::cout << "Entering enrollee_start_onboarding_ZeroMacAddress test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    ec_manager_t mgr("66:55:44:33:22:11", ops, false, std::nullopt, handler);
    ec_data_t boot_data{};
    memset(&boot_data, 0, sizeof(ec_data_t));
    boot_data.version = 2;
    bool do_reconfig = false;
    bool ethernet = false;
    std::cout << "Invoking enrollee_start_onboarding with do_reconfig="
              << do_reconfig << ", ethernet=" << ethernet << std::endl;
    bool ret = mgr.enrollee_start_onboarding(do_reconfig, &boot_data, ethernet);
    std::cout << "Returned value: " << ret << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting enrollee_start_onboarding_ZeroMacAddress test" << std::endl;
}
/**
 * @brief Test enrollee_start_onboarding API with null boot_data parameter
 *
 * This test verifies that the enrollee_start_onboarding function returns false when provided with a null boot_data pointer. It checks that the API correctly handles invalid boot_data input, ensuring robust error handling.
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
 * | Variation / Step | Description                                                              | Test Data                                               | Expected Result                                                         | Notes       |
 * | :--------------: | ------------------------------------------------------------------------ | ------------------------------------------------------- | ----------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke enrollee_start_onboarding with boot_data set to nullptr, do_reconfig = false, and ethernet = false | do_reconfig = false, boot_data = nullptr, ethernet = false | API returns false and the EXPECT_FALSE assertion is satisfied           | Should Pass |
 */
TEST(ec_manager_t, enrollee_start_onboarding_null_boot_data)
{
    std::cout << "Entering enrollee_start_onboarding_null_boot_data test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    ec_manager_t mgr("aa:bb:cc:dd:ee:ff", ops, false, std::nullopt, handler);
    bool do_reconfig = false;
    bool ethernet = false;
    std::cout << "Invoking enrollee_start_onboarding with boot_data=nullptr, do_reconfig="
              << do_reconfig << ", ethernet=" << ethernet << std::endl;
    bool ret = mgr.enrollee_start_onboarding(do_reconfig, nullptr, ethernet);
    std::cout << "Returned value: " << ret << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting enrollee_start_onboarding_null_boot_data test" << std::endl;
}
/**
 * @brief Verify that enrollee_start_onboarding returns false when responder_boot_key is null.
 *
 * This test evaluates the behaviour of the enrollee_start_onboarding API when the ec_data_t structure
 * has a null responder_boot_key. It ensures that the API properly handles the null key scenario by returning false.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 018
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Log the entry message to mark the start of the test | None | Message "Entering enrollee_start_onboarding_null_responder_key test" printed to console | Should be successful |
 * | 02 | Create dummy operations by calling make_dummy_ops() | None | ec_ops_t object successfully created | Should be successful |
 * | 03 | Define a lambda function for handshake_completed_handler | None | Lambda function assigned to handler | Should be successful |
 * | 04 | Construct ec_manager_t object with a given MAC address, dummy operations, secure flag false, no responder key, and the lambda handler | input: key = "01:23:45:67:89:ab", ops = dummy ops, secure = false, responder key = std::nullopt, handler = lambda | ec_manager_t object successfully created | Should be successful |
 * | 05 | Initialize ec_data_t structure with version 2, null responder_boot_key, and set MAC address | input: version = 2, responder_boot_key = nullptr, mac_addr = "\x01\x02\x03\x04\x05\x06" | ec_data_t structure correctly initialized | Should be successful |
 * | 06 | Set the boolean flags do_reconfig and ethernet to false | input: do_reconfig = false, ethernet = false | Flags correctly set to false | Should be successful |
 * | 07 | Call enrollee_start_onboarding with the prepared flags and ec_data_t structure | input: do_reconfig = false, data pointer, ethernet = false | API returns false indicating the null responder_boot_key is handled as expected | Should Pass |
 * | 08 | Log the returned value and test exit message | input: ret = false | Correct output printed and test exits properly, with EXPECT_FALSE(ret) validating the false return value | Should Pass |
 */
TEST(ec_manager_t, enrollee_start_onboarding_null_responder_key)
{
    std::cout << "Entering enrollee_start_onboarding_null_responder_key test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    ec_manager_t mgr("01:23:45:67:89:ab", ops, false, std::nullopt, handler);
    ec_data_t data{};
    data.version = 2;
    data.responder_boot_key = nullptr;
    memcpy(data.mac_addr, "\x01\x02\x03\x04\x05\x06", ETHER_ADDR_LEN);
    bool do_reconfig = false;
    bool ethernet = false;
    std::cout << "Invoking enrollee_start_onboarding with responder_boot_key=null" << std::endl;
    bool ret = mgr.enrollee_start_onboarding(do_reconfig, &data, ethernet);
    std::cout << "Returned value: " << ret << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting enrollee_start_onboarding_null_responder_key test" << std::endl;
}
/**
 * @brief Verify that the pa_cfg_toggle_cce function returns false when enrollment mode is disabled.
 *
 * This test initializes an ec_manager_t instance with dummy operations and a valid handshake handler.
 * It then invokes the pa_cfg_toggle_cce function with enable set to false. The test verifies that the
 * API returns false as expected, confirming correct behavior in an enrolllee scenario.
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
 * | 01 | Initialize ec_manager_t instance with dummy operations and a valid handshake handler, then invoke pa_cfg_toggle_cce with enable set to false. | ec_manager_t - MAC="de:ad:be:ef:00:01", ops=dummy, flag=false, optional config=null, handler=dummy; pa_cfg_toggle_cce input - enable=false | API returns false; assertion EXPECT_FALSE(ret) passes | Should Pass |
 */
TEST(ec_manager_t, pa_cfg_toggle_cce_enrollee)
{
    std::cout << "Entering pa_cfg_toggle_cce_enrollee test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    ec_manager_t mgr("de:ad:be:ef:00:01", ops, false, std::nullopt, handler);
    bool enable = false;
    std::cout << "Invoking pa_cfg_toggle_cce with enable=" << enable << std::endl;
    bool ret = mgr.pa_cfg_toggle_cce(enable);
    std::cout << "Returned value: " << ret << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting pa_cfg_toggle_cce_enrollee test" << std::endl;
}
/**
 * @brief Test start_secure_1905_layer API for enrollee scenario with null MAC input
 *
 * This test verifies that the start_secure_1905_layer API correctly handles the case when a null MAC is provided.
 * The function is expected to return false to indicate failure in starting the secure 1905 layer due to invalid input.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 020
 * **Priority:** High
 * 
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                                                               | Test Data                                                                                                                        | Expected Result                                                                           | Notes        |
 * | :--------------: | ----------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- | ------------ |
 * | 01               | Invoke start_secure_1905_layer with nullptr to simulate a null MAC input for the enrollee   | dest_mac = "66:77:88:99:aa:bb", ops = dummy_ops, secure_ctx = dummy_sec_ctx, configurator_flag = false, handler = lambda, argument = nullptr | Return value false from start_secure_1905_layer and EXPECT_FALSE assertion passes           | Should Fail  |
 */
TEST(ec_manager_t, start_secure_1905_layer_enrollee_Nullmac)
{
    std::cout << "Entering start_secure_1905_layer_enrollee_Nullmac test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    ec_persistent_sec_ctx_t sec_ctx = make_dummy_sec_ctx();
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    ec_manager_t mgr("66:77:88:99:aa:bb", ops, false, std::nullopt, handler);
    std::cout << "Invoking start_secure_1905_layer with configurator present, dest_al_mac=" << "66:77:88:99:aa:bb" << std::endl;
    bool ret = mgr.start_secure_1905_layer(nullptr);
    std::cout << "Returned value: " << ret << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting start_secure_1905_layer_enrollee_Nullmac test" << std::endl;
}
/**
 * @brief Validate that rekey_1905_layer_gtk() fails for an enrollee-based ec_manager_t.
 *
 * This test verifies that when an ec_manager_t instance is created with enrollee 
 * characteristics, the API rekey_1905_layer_gtk() correctly returns false, indicating 
 * that rekeying is not supported on an enrollee-based configuration.
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
 * | Variation / Step | Description                                                         | Test Data                                                                                           | Expected Result                                                     | Notes            |
 * | :--------------: | ------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ---------------- |
 * | 01               | Initialize ec_manager_t with enrollee parameters.                   | MAC = "00:11:22:33:44:55", ops = dummy_ops, enrollee flag = false, handshake handler = lambda       | ec_manager_t object is instantiated successfully.                   | Should be successful |
 * | 02               | Invoke rekey_1905_layer_gtk() method on the enrollee-based manager.   | API Call: rekey_1905_layer_gtk()                                                                    | Return value is false indicating operation not supported.           | Should Fail      |
 * | 03               | Validate the returned value using an assertion.                     | ret = false (as returned from rekey_1905_layer_gtk())                                               | EXPECT_FALSE(ret) assertion passes.                                 | Should be successful |
 */
TEST(ec_manager_t, rekey_1905_layer_gtk_enrollee_not_supported) {
    std::cout << "Entering rekey_1905_layer_gtk_enrollee_not_supported test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    ec_manager_t manager("00:11:22:33:44:55", ops, false, std::nullopt, handler);
    std::cout << "Invoking rekey_1905_layer_gtk() on enrollee-based ec_manager_t" << std::endl;
    bool ret = manager.rekey_1905_layer_gtk();
    std::cout << "Returned value from rekey_1905_layer_gtk(): " << ret << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting rekey_1905_layer_gtk_enrollee_not_supported test" << std::endl;
}
/**
 * @brief Verify that get_sec_ctx API returns a valid security context in an enrollee scenario
 *
 * This test verifies that when an ec_manager object is instantiated with dummy operations,
 * a dummy handshake handler, a valid MAC address, and default security settings, the get_sec_ctx()
 * method returns a non-null pointer to a security context. This confirms that the API is able to
 * initialize and provide a valid security context for further operations.
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
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize dummy operations and handshake handler | N/A | Dummy objects created successfully | Should be successful |
 * | 02 | Create ec_manager object with MAC = "00:11:22:33:44:55", ops = dummy operations, secure flag = false, optional parameter = std::nullopt, handshake handler = lambda | input: MAC address = "00:11:22:33:44:55", ops = dummy operation, secure=false, optional param = std::nullopt, handshake handler = lambda; output: ec_manager instance | ec_manager instance created successfully | Should be successful |
 * | 03 | Invoke get_sec_ctx() API on ec_manager instance | input: no additional parameters; output: ec_persistent_sec_ctx_t* pointer | Return value is non-null | Should Pass |
 * | 04 | Print the returned security context fields (C_signing_key, pp_key, net_access_key, connector) | output: ctx->C_signing_key, ctx->pp_key, ctx->net_access_key, ctx->connector | Correct context information printed | Should be successful |
 */
TEST(ec_manager_t, get_sec_ctx_enrollee_returns_valid_ctx) {
    std::cout << "Entering get_sec_ctx_enrollee_returns_valid_ctx test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    ec_manager_t manager("00:11:22:33:44:55", ops, false, std::nullopt, handler);
    std::cout << "Invoking get_sec_ctx()" << std::endl;
    ec_persistent_sec_ctx_t* ctx = manager.get_sec_ctx();
    ASSERT_NE(ctx, nullptr);
    std::cout << "C_signing_key: " << ctx->C_signing_key << std::endl;
    std::cout << "pp_key: " << ctx->pp_key << std::endl;
    std::cout << "net_access_key: " << ctx->net_access_key << std::endl;
    std::cout << "connector: " << (ctx->connector ? ctx->connector : "NULL") << std::endl;
    std::cout << "Exiting get_sec_ctx_enrollee_returns_valid_ctx test" << std::endl;
}
/**
 * @brief Verify that get_al_conn_ctx returns a valid connection context for the enrollee
 *
 * This test validates that the ec_manager_t::get_al_conn_ctx() API successfully returns a non-null connection context
 * pointer when provided with a valid peer MAC address. The test creates dummy operations and a handshake handler,
 * instantiates an ec_manager_t object, and verifies through an assertion that the returned pointer is not null.
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
 * | Variation / Step | Description                                                                 | Test Data                                                                                             | Expected Result                                                          | Notes           |
 * | :--------------: | --------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ | --------------- |
 * | 01               | Initialize dummy ec_ops, handshake_completed_handler, and create ec_manager_t | MAC address = "00:11:22:33:44:55", ops = dummy ops, handshake handler = lambda function                | ec_manager_t instance is created successfully                           | Should be successful |
 * | 02               | Initialize the peer MAC address for the enrollee                            | peer_mac = {0x00,0xAA,0xBB,0xCC,0xDD,0xEE}                                                              | peer_mac is correctly initialized                                       | Should be successful |
 * | 03               | Invoke get_al_conn_ctx() on the ec_manager_t instance with the defined peer_mac | Function call: get_al_conn_ctx(peer_mac) with peer_mac = {0x00,0xAA,0xBB,0xCC,0xDD,0xEE}                   | Returns a non-null pointer to ec_connection_context_t                   | Should Pass     |
 * | 04               | Verify the returned connection context's parameters                         | Context fields: peer_al_mac, is_easyconnect_dpp_complete, is_eth; Expected peer_al_mac pattern printed | Connection context's fields reflect the expected initialized values and check passes correctly | Should be successful |
 */
TEST(ec_manager_t, get_al_conn_ctx_enrollee_returns_context) {
    std::cout << "Entering get_al_conn_ctx_enrollee_returns_context test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    ec_manager_t manager("00:11:22:33:44:55", ops, false, std::nullopt, handler);
    uint8_t peer_mac[ETH_ALEN] = {0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    std::cout << "Invoking get_al_conn_ctx() with peer_al_mac = " << std::endl;
    ec_connection_context_t* ctx = manager.get_al_conn_ctx(peer_mac);
    std::cout << "Returned ec_connection_context_t pointer with peer_al_mac 00:11:22:33:44:55" << ctx << std::endl;
    ASSERT_NE(ctx, nullptr);
    std::cout << "Retrieved peer_al_mac from context: "
              << std::hex
              << static_cast<int>(ctx->peer_al_mac[0]) << ":"
              << static_cast<int>(ctx->peer_al_mac[1]) << ":"
              << static_cast<int>(ctx->peer_al_mac[2]) << ":"
              << static_cast<int>(ctx->peer_al_mac[3]) << ":"
              << static_cast<int>(ctx->peer_al_mac[4]) << ":"
              << static_cast<int>(ctx->peer_al_mac[5]) << std::dec << std::endl;
    std::cout << "is_easyconnect_dpp_complete: " << ctx->is_easyconnect_dpp_complete << std::endl;
    std::cout << "is_eth: " << ctx->is_eth << std::endl;
    std::cout << "Exiting get_al_conn_ctx_enrollee_returns_context test" << std::endl;
}
/**
 * @brief Verify that upgrading to an onboarded proxy agent with a null control MAC fails.
 *
 * This test verifies that the upgrade_to_onboarded_proxy_agent API correctly handles a null pointer
 * for the control MAC address. The expectation is that the API will return false when a null pointer is passed,
 * ensuring that the internal validation is properly enforced.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 024@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                   | Test Data                                                                                                    | Expected Result                                                              | Notes          |
 * | :--------------: | ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------- | -------------- |
 * |       01         | Create ec_manager_t instance with dummy operations and valid MAC address      | MAC = "00:11:22:33:44:55", ops = make_dummy_ops(), flag = false, optional = std::nullopt, handler = lambda | ec_manager_t object is successfully created                                  | Should be successful |
 * |       02         | Set control MAC pointer to nullptr                                            | ctrl_mac = nullptr                                                                                           | ctrl_mac is set to nullptr                                                    | Should be successful |
 * |       03         | Invoke upgrade_to_onboarded_proxy_agent API with ctrl_mac set to nullptr        | ctrl_mac = nullptr, output value expected = false, assertion = EXPECT_FALSE(ret)                             | API returns false indicating failure in upgrading due to null control MAC      | Should Fail    |
 */
TEST(ec_manager_t, upgrade_to_onboarded_proxy_agent_null_mac_fails)
{
    std::cout << "Entering upgrade_to_onboarded_proxy_agent_null_mac_fails test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    ec_manager_t mgr("00:11:22:33:44:55", ops, false, std::nullopt, handler);
    uint8_t* ctrl_mac = nullptr;
    std::cout << "Invoking upgrade_to_onboarded_proxy_agent with ctrl_mac=nullptr" << std::endl;
    bool ret = mgr.upgrade_to_onboarded_proxy_agent(ctrl_mac);
    std::cout << "Returned value: " << ret << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting upgrade_to_onboarded_proxy_agent_null_mac_fails test" << std::endl;
}
/**
 * @brief Test that upgrade_to_onboarded_proxy_agent fails when provided with a zero MAC address
 *
 * This test verifies that invoking the upgrade_to_onboarded_proxy_agent API with a zeroed control MAC address 
 * correctly results in a failure. The manager is initialized with a valid onboarded MAC address and dummy operations, 
 * while the control MAC is deliberately set to all zeros. The test confirms that the API does not accept a zero MAC.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Instantiate ec_manager_t with valid onboarded MAC and dummy operations | input: onboarded_mac = "00:11:22:33:44:55", ops = make_dummy_ops() | Manager instance created successfully | Should be successful |
 * | 02 | Initialize a zero MAC address array for control MAC | input: ctrl_mac = "00:00:00:00:00:00" | Zero MAC address array is correctly initialized | Should be successful |
 * | 03 | Invoke upgrade_to_onboarded_proxy_agent with zero MAC address | input: ctrl_mac = "00:00:00:00:00:00" | API returns false and EXPECT_FALSE assertion passes | Should Pass |
 */
TEST(ec_manager_t, upgrade_to_onboarded_proxy_agent_zero_mac_fails)
{
    std::cout << "Entering upgrade_to_onboarded_proxy_agent_zero_mac_fails test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    ec_manager_t mgr("00:11:22:33:44:55", ops, false, std::nullopt, handler);
    uint8_t ctrl_mac[ETH_ALEN] = {0,0,0,0,0,0};
    std::cout << "Invoking upgrade_to_onboarded_proxy_agent with ctrl_mac=00:00:00:00:00:00" << std::endl;
    bool ret = mgr.upgrade_to_onboarded_proxy_agent(ctrl_mac);
    std::cout << "Returned value: " << ret << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting upgrade_to_onboarded_proxy_agent_zero_mac_fails test" << std::endl;
}
/**
 * @brief Test upgrading to onboarded proxy agent without keys
 *
 * This test verifies that the ec_manager_t object successfully upgrades to an onboarded proxy agent when no keys are provided. It sets up dummy operations and a handler, initializes the manager without keys, and then invokes the upgrade_to_onboarded_proxy_agent API with a prepared ctrl_mac value to validate the expected true return value.
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
 * |Variation / Step|Description|Test Data|Expected Result|Notes|
 * |:--------------:|-----------|---------|-------------|-----|
 * |01|Setup dummy operations, handshake handler, and ec_manager_t object.|ops = make_dummy_ops(), device_id = "00:11:22:33:44:55", keys = false, optional keys = std::nullopt, handler = lambda function|ec_manager_t object is correctly initialized for the test|Should be successful|
 * |02|Prepare the ctrl_mac array with the MAC address aa:bb:cc:dd:ee:ff.|ctrl_mac = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}|ctrl_mac array is properly set with the specified MAC address|Should be successful|
 * |03|Invoke upgrade_to_onboarded_proxy_agent using the prepared ctrl_mac.|input: ctrl_mac, output: ret value|API invocation returns a true value indicating success|Should Pass|
 * |04|Validate the returned value using EXPECT_TRUE.|Expected: ret == true|The EXPECT_TRUE check passes confirming successful execution|Should Pass|
 */
TEST(ec_manager_t, upgrade_to_onboarded_proxy_agent_success_without_keys)
{
    std::cout << "Entering upgrade_to_onboarded_proxy_agent_success_without_keys test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    ec_manager_t mgr("00:11:22:33:44:55", ops, false, std::nullopt, handler);
    uint8_t ctrl_mac[ETH_ALEN] = {0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    std::cout << "Invoking upgrade_to_onboarded_proxy_agent with ctrl_mac=aa:bb:cc:dd:ee:ff" << std::endl;
    bool ret = mgr.upgrade_to_onboarded_proxy_agent(ctrl_mac);
    std::cout << "Returned value: " << ret << std::endl;
    EXPECT_TRUE(ret);
    std::cout << "Exiting upgrade_to_onboarded_proxy_agent_success_without_keys test" << std::endl;
}
/**
 * @brief Check that upgrading to onboarded proxy agent fails if already upgraded
 *
 * This test validates that when the upgrade_to_onboarded_proxy_agent API is invoked, the first call succeeds while the second call fails because the proxy agent is already upgraded. It ensures that the system prevents multiple upgrades by returning the appropriate boolean status for each call.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 027
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke first upgrade_to_onboarded_proxy_agent with ctrl_mac1 | ctrl_mac1 = {0xaa,0xbb,0xcc,0xdd,0xee,0x01}, output1 = ret1 | Return value true indicating the API call succeeded | Should Pass |
 * | 02 | Invoke second upgrade_to_onboarded_proxy_agent with ctrl_mac2 | ctrl_mac2 = {0xaa,0xbb,0xcc,0xdd,0xee,0x02}, output2 = ret2 | Return value false indicating the API call failed (already upgraded) | Should Pass |
 */
TEST(ec_manager_t, upgrade_to_onboarded_proxy_agent_already_upgraded_fails)
{
    std::cout << "Entering upgrade_to_onboarded_proxy_agent_already_upgraded_fails test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    ec_manager_t mgr("00:11:22:33:44:55", ops, false, std::nullopt, handler);
    uint8_t ctrl_mac1[ETH_ALEN] = {0xaa,0xbb,0xcc,0xdd,0xee,0x01};
    uint8_t ctrl_mac2[ETH_ALEN] = {0xaa,0xbb,0xcc,0xdd,0xee,0x02};
    std::cout << "Invoking first upgrade_to_onboarded_proxy_agent with ctrl_mac=aa:bb:cc:dd:ee:01" << std::endl;
    bool ret1 = mgr.upgrade_to_onboarded_proxy_agent(ctrl_mac1);
    std::cout << "Returned value: " << ret1 << std::endl;
    std::cout << "Invoking second upgrade_to_onboarded_proxy_agent with ctrl_mac=aa:bb:cc:dd:ee:02" << std::endl;
    bool ret2 = mgr.upgrade_to_onboarded_proxy_agent(ctrl_mac2);
    std::cout << "Returned value: " << ret2 << std::endl;
    EXPECT_TRUE(ret1);
    EXPECT_FALSE(ret2);
    std::cout << "Exiting upgrade_to_onboarded_proxy_agent_already_upgraded_fails test" << std::endl;
}
/**
 * @brief Verify process_chirp_notification returns failure when no configurator is available
 *
 * This test validates that the process_chirp_notification API fails as expected when the configurator is not provided. 
 * It confirms that the API correctly handles the nullptr for chirp_tlv and returns false.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 028@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:** 
 * | Variation / Step | Description                                                                 | Test Data                                                                                                         | Expected Result                                                                                  | Notes             |
 * | :--------------: | --------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ | ----------------- |
 * | 01               | Initialize ec_manager with dummy operations and no configurator             | input: MAC = "00:11:22:33:44:55", ops = make_dummy_ops(), configurator = false, handler = dummy handler         | ec_manager object is successfully created                                                        | Should be successful |
 * | 02               | Invoke process_chirp_notification with chirp_tlv as nullptr and tlv_len as 0  | input: chirp_tlv = nullptr, tlv_len = 0, src_mac = "00:11:22:33:44:55", output: ret expected = false               | API returns false and the failure is correctly asserted                                          | Should Pass       |
 */
TEST(ec_manager_t, process_chirp_notification_no_configurator_fails)
{
    std::cout << "Entering process_chirp_notification_no_configurator_fails test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    ec_manager_t mgr("00:11:22:33:44:55", ops, false, std::nullopt, handler);
    em_dpp_chirp_value_t* chirp_tlv = nullptr;
    uint16_t tlv_len = 0;
    uint8_t src_mac[ETH_ALEN] = {0x00,0x11,0x22,0x33,0x44,0x55};
    std::cout << "Invoking process_chirp_notification with chirp_tlv=nullptr, tlv_len="
              << tlv_len << std::endl;
    bool ret = mgr.process_chirp_notification(chirp_tlv, tlv_len, src_mac);
    std::cout << "Returned value: " << ret << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting process_chirp_notification_no_configurator_fails test" << std::endl;
}
/**
 * @brief Test process_proxy_encap_dpp_msg failure when configurator is not provided
 *
 * This test verifies that the process_proxy_encap_dpp_msg API fails as expected when the configurator is not provided.
 * The test instantiates an ec_manager_t with dummy operations and without a configurator, then calls process_proxy_encap_dpp_msg
 * with nullptr values for both encap and chirp TLVs. The expected behavior is that the function returns false.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 029@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                                              | Test Data                                                                                                       | Expected Result                                                                      | Notes         |
 * | :--------------: | ------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ | ------------- |
 * | 01               | Instantiate ec_manager_t with dummy operations, no configurator, and a handshake completion handler                     | MAC = "00:11:22:33:44:55", ops = make_dummy_ops(), configurator flag = false, handler = lambda function        | ec_manager_t object created successfully                                             | Should be successful |
 * | 02               | Invoke process_proxy_encap_dpp_msg with encap_tlv = nullptr, encap_len = 0, chirp_tlv = nullptr, chirp_len = 0, src_mac set  | encap_tlv = nullptr, encap_len = 0, chirp_tlv = nullptr, chirp_len = 0, src_mac = "00:11:22:33:44:55"             | API returns false and EXPECT_FALSE(ret) assertion passes                             | Should Pass   |
 */
TEST(ec_manager_t, process_proxy_encap_dpp_msg_no_configurator_fails)
{
    std::cout << "Entering process_proxy_encap_dpp_msg_no_configurator_fails test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    ec_manager_t mgr("00:11:22:33:44:55", ops, false, std::nullopt, handler);
    em_encap_dpp_t* encap_tlv = nullptr;
    uint16_t encap_len = 0;
    em_dpp_chirp_value_t* chirp_tlv = nullptr;
    uint16_t chirp_len = 0;
    uint8_t src_mac[ETH_ALEN] = {0x00,0x11,0x22,0x33,0x44,0x55};
    std::cout << "Invoking process_proxy_encap_dpp_msg with encap_tlv=nullptr, chirp_tlv=nullptr" << std::endl;
    bool ret = mgr.process_proxy_encap_dpp_msg(encap_tlv, encap_len, chirp_tlv, chirp_len, src_mac);
    std::cout << "Returned value: " << ret << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting process_proxy_encap_dpp_msg_no_configurator_fails test" << std::endl;
}
/**
 * @brief Test the response of process_direct_encap_dpp_msg when provided with a null dpp_frame pointer
 *
 * This test verifies that process_direct_encap_dpp_msg correctly handles a scenario where the dpp_frame parameter is null.
 * The API is expected to return false when a null pointer is provided for the dpp_frame.
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
 * | Variation / Step | Description                                                                                   | Test Data                                                              | Expected Result                                      | Notes        |
 * | :--------------: | --------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- | ---------------------------------------------------- | ------------ |
 * | 01               | Create an ec_manager_t instance and invoke process_direct_encap_dpp_msg with a null dpp_frame   | dpp_frame = nullptr, dpp_len = sizeof(ec_frame_t), src_mac = 00:01:02:03:04:05 | Return value is false and EXPECT_FALSE assertion passes | Should Fail  |
 */
TEST(ec_manager_t, process_direct_encap_dpp_msg_enrollee_null_frame)
{
    std::cout << "Entering process_direct_encap_dpp_msg_enrollee_null_frame test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    ec_manager_t mgr("00:11:22:33:44:55", ops, false, std::nullopt, handler);
    uint8_t* dpp_frame = nullptr;
    uint16_t dpp_len = sizeof(ec_frame_t);
    uint8_t src_mac[ETH_ALEN] = {0x00,0x01,0x02,0x03,0x04,0x05};
    std::cout << "Invoking process_direct_encap_dpp_msg with null dpp_frame" << std::endl;
    bool ret = mgr.process_direct_encap_dpp_msg(dpp_frame, dpp_len, src_mac);
    std::cout << "Returned value: " << ret << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting process_direct_encap_dpp_msg_enrollee_null_frame test" << std::endl;
}
/**
 * @brief Test process_direct_encap_dpp_msg to validate handling of a zero-length DPP message.
 *
 * This test verifies that when the process_direct_encap_dpp_msg API is invoked with a DPP message
 * frame having a zero length, the API correctly returns false. It ensures that the API refuses to
 * process an invalid or empty DPP message.
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
 * | Variation / Step | Description                                                               | Test Data                                                                                                  | Expected Result                                            | Notes       |
 * | :--------------: | ------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- | ----------- |
 * | 01               | Invoke process_direct_encap_dpp_msg with a zero-length DPP message frame    | frame = {0,...}, dpp_len = 0, src_mac = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, other parameters as default  | API returns false and assertion EXPECT_FALSE(ret) passes   | Should Fail |
 */
TEST(ec_manager_t, process_direct_encap_dpp_msg_enrollee_zero_length)
{
    std::cout << "Entering process_direct_encap_dpp_msg_enrollee_zero_length test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    ec_manager_t mgr("00:11:22:33:44:55", ops, false, std::nullopt, handler);
    uint8_t frame[sizeof(ec_frame_t)] = {0};
    uint16_t dpp_len = 0;
    uint8_t src_mac[ETH_ALEN] = {0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    std::cout << "Invoking process_direct_encap_dpp_msg with zero length" << std::endl;
    bool ret = mgr.process_direct_encap_dpp_msg(frame, dpp_len, src_mac);
    std::cout << "Returned value: " << ret << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting process_direct_encap_dpp_msg_enrollee_zero_length test" << std::endl;
}
/**
 * @brief Validate that process_direct_encap_dpp_msg returns false for an invalid frame type
 *
 * This test verifies that the process_direct_encap_dpp_msg API correctly identifies an unsupported frame type.
 * An ec_frame_t is set up with an invalid frame_type (0xff) and a valid action value. The test ensures that
 * the method returns false when encountering this invalid frame type.
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
 * | 01 | Initialize ec_manager_t instance with dummy operations and a handshake callback | MAC = "00:11:22:33:44:55", ops = make_dummy_ops(), flag = false, handler = lambda | ec_manager_t instance is created successfully | Should be successful |
 * | 02 | Setup ec_frame_t with an unsupported frame_type and valid action value | frame_type = 0xff, action = 0x01, dpp_len = sizeof(ec_frame_t) | ec_frame_t is configured with invalid frame_type | Should be successful |
 * | 03 | Invoke process_direct_encap_dpp_msg with the configured frame and verify the returned value | frame buffer containing ec_frame_t, dpp_len, src_mac = {0x10,0x20,0x30,0x40,0x50,0x60} | API returns false and EXPECT_FALSE assertion passes | Should Fail |
 */
TEST(ec_manager_t, process_direct_encap_dpp_msg_enrollee_invalid_frame_type)
{
    std::cout << "Entering process_direct_encap_dpp_msg_enrollee_invalid_frame_type test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    ec_manager_t mgr("00:11:22:33:44:55", ops, false, std::nullopt, handler);
    uint8_t frame[sizeof(ec_frame_t)] = {0};
    ec_frame_t* ec_frame = reinterpret_cast<ec_frame_t*>(frame);
    ec_frame->frame_type = 0xff;
    ec_frame->action = 0x01;
    uint16_t dpp_len = sizeof(ec_frame_t);
    uint8_t src_mac[ETH_ALEN] = {0x10,0x20,0x30,0x40,0x50,0x60};
    std::cout << "Invoking process_direct_encap_dpp_msg with unsupported frame_type="
              << static_cast<int>(ec_frame->frame_type) << std::endl;
    bool ret = mgr.process_direct_encap_dpp_msg(frame, dpp_len, src_mac);
    std::cout << "Returned value: " << ret << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting process_direct_encap_dpp_msg_enrollee_invalid_frame_type test" << std::endl;
}
/**
 * @brief Verify that process_direct_encap_dpp_msg returns false when src_mac is nullptr
 *
 * This test ensures that the process_direct_encap_dpp_msg method correctly handles a null source MAC pointer. It sets up an ec_manager_t instance with dummy operations, prepares a valid frame structure with necessary fields, and then invokes the API with src_mac set to nullptr. The expected behavior is that the API returns false.
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
 * | 01 | Initialize ec_manager_t object with dummy parameters | mac = "00:11:22:33:44:55", ops = dummy operations, encryption flag = false, optional = std::nullopt, handler = lambda | Object constructed successfully | Should be successful |
 * | 02 | Set frame fields including frame_type and action | frame_type = ec_frame_type_auth_req, action = 0x09 | Frame initialized with correct values | Should be successful |
 * | 03 | Set dpp_len equal to sizeof(ec_frame_t) and src_mac to nullptr | dpp_len = sizeof(ec_frame_t), src_mac = nullptr | Parameters set for API call | Should be successful |
 * | 04 | Invoke process_direct_encap_dpp_msg method with src_mac set to nullptr | frame pointer, dpp_len, src_mac = nullptr | Return value should be false | Should Pass |
 * | 05 | Validate the output using EXPECT_FALSE | ret = output of process_direct_encap_dpp_msg | Assertion passes if ret is false | Should Pass |
 */
TEST(ec_manager_t, process_direct_encap_dpp_msg_enrollee_null_src_mac)
{
    std::cout << "Entering process_direct_encap_dpp_msg_enrollee_null_src_mac test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    ec_manager_t mgr("00:11:22:33:44:55", ops, false, std::nullopt, handler);
    uint8_t frame[sizeof(ec_frame_t)] = {0};
    ec_frame_t* ec_frame = reinterpret_cast<ec_frame_t*>(frame);
    ec_frame->frame_type = ec_frame_type_auth_req;
    ec_frame->action = 0x09;
    uint16_t dpp_len = sizeof(ec_frame_t);
    uint8_t* src_mac = nullptr;
    std::cout << "Invoking process_direct_encap_dpp_msg with src_mac=nullptr" << std::endl;
    bool ret = mgr.process_direct_encap_dpp_msg(frame, dpp_len, src_mac);
    std::cout << "Returned value: " << ret << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting process_direct_encap_dpp_msg_enrollee_null_src_mac test" << std::endl;
}
/**
 * @brief Verify handle_autoconf_chirp returns false for enrollee instance with null chirp value
 *
 * This test verifies that when an enrollee instance of ec_manager_t is used and the chirp pointer is null, the method handle_autoconf_chirp correctly returns false. This behavior is expected as the chirp value is mandatory for a successful operation.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 034@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                           | Test Data                                                                                          | Expected Result                                   | Notes         |
 * | :--------------: | ----------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- | ------------------------------------------------- | ------------- |
 * | 01               | Setup ec_manager_t instance with dummy operations and a handshake_completed_handler for enrollee mode| mac = "00:11:22:33:44:55", ops = make_dummy_ops(), enrollee flag = false, handler = lambda   | Instance created successfully                       | Should be successful |
 * | 02               | Invoke handle_autoconf_chirp API with null chirp pointer                                              | chirp = nullptr, len = 0, src_mac = {0,0,0,0,0,0}, msg_id = 1                                    | Return value should be false; EXPECT_FALSE check passes | Should Pass   |
 */
TEST(ec_manager_t, handle_autoconf_chirp_enrollee_path)
{
    std::cout << "Entering handle_autoconf_chirp_enrollee_path test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    ec_manager_t mgr("00:11:22:33:44:55", ops, false, std::nullopt, handler);
    em_dpp_chirp_value_t* chirp = nullptr;
    size_t len = 0;
    uint8_t src_mac[ETH_ALEN] = {0};
    unsigned short msg_id = 1;
    std::cout << "Invoking handle_autoconf_chirp with enrollee instance" << std::endl;
    bool ret = mgr.handle_autoconf_chirp(chirp, len, src_mac, msg_id);
    std::cout << "Returned value: " << ret << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting handle_autoconf_chirp_enrollee_path test" << std::endl;
}
/**
 * @brief Validate handle_autoconf_resp_chirp() API for null chirp pointer input
 *
 * This test verifies that the handle_autoconf_resp_chirp function returns false when provided with a nullptr for the chirp parameter. This ensures the API correctly handles a null input scenario.
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
 * | Variation / Step | Description                                                    | Test Data                                                                                                   | Expected Result                                         | Notes             |
 * | :--------------: | -------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- | ----------------- |
 * | 01               | Initialize ec_manager_t with dummy operations and handler.     | ops = make_dummy_ops(), handler = lambda(uint8_t[ETH_ALEN], bool), MAC = "00:11:22:33:44:55", flag = false | Object is created successfully.                        | Should be successful |
 * | 02               | Invoke handle_autoconf_resp_chirp with chirp set to nullptr.     | chirp = nullptr, len = sizeof(em_dpp_chirp_value_t), src_mac = "00:01:02:03:04:05"                          | API returns false.                                      | Should Fail       |
 * | 03               | Validate the return value using EXPECT_FALSE assertion.        | ret = result from API call                                                                                  | Assertion passes if ret is false.                       | Should be successful |
 */
TEST(ec_manager_t, handle_autoconf_resp_chirp_enrollee_null_chirp)
{
    std::cout << "Entering handle_autoconf_resp_chirp_enrollee_null_chirp test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    ec_manager_t mgr("00:11:22:33:44:55", ops, false, std::nullopt, handler);
    em_dpp_chirp_value_t* chirp = nullptr;
    size_t len = sizeof(em_dpp_chirp_value_t);
    uint8_t src_mac[ETH_ALEN] = {0x00,0x01,0x02,0x03,0x04,0x05};
    std::cout << "Invoking handle_autoconf_resp_chirp with chirp=nullptr, len=" << len << std::endl;
    bool ret = mgr.handle_autoconf_resp_chirp(chirp, len, src_mac);
    std::cout << "Returned value: " << ret << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting handle_autoconf_resp_chirp_enrollee_null_chirp test" << std::endl;
}
/**
 * @brief Verify that handle_autoconf_resp_chirp returns false when the chirp length is zero.
 *
 * This test ensures that when a zero-length chirp is provided to the handle_autoconf_resp_chirp function, the function correctly returns false. This confirms that the API properly handles invalid (empty) chirp data.
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
 * | Variation / Step | Description | Test Data | Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke handle_autoconf_resp_chirp with a zero-length chirp to simulate an enrollee scenario | chirp = default em_dpp_chirp_value_t, len = 0, src_mac = 0xaa,0xbb,0xcc,0xdd,0xee,0xff | API returns false; EXPECT_FALSE(ret) passes | Should Pass |
 */
TEST(ec_manager_t, handle_autoconf_resp_chirp_enrollee_zero_length)
{
    std::cout << "Entering handle_autoconf_resp_chirp_enrollee_zero_length test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    ec_manager_t mgr("00:11:22:33:44:55", ops, false, std::nullopt, handler);
    em_dpp_chirp_value_t chirp{};
    size_t len = 0;
    uint8_t src_mac[ETH_ALEN] = {0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    std::cout << "Invoking handle_autoconf_resp_chirp with len=0" << std::endl;
    bool ret = mgr.handle_autoconf_resp_chirp(&chirp, len, src_mac);
    std::cout << "Returned value: " << ret << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting handle_autoconf_resp_chirp_enrollee_zero_length test" << std::endl;
}
/**
 * @brief Verify that handle_autoconf_resp_chirp returns false when processing a chirp with an invalid hash.
 *
 * This test verifies that when the chirp message received by the EC manager has an invalid hash,
 * the API correctly identifies the error and returns false. This ensures that invalid chirp inputs
 * are properly handled.
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
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize EC manager with dummy operations and a handshake handler | MAC = "00:11:22:33:44:55", ops = make_dummy_ops(), handler = lambda(uint8_t[ETH_ALEN], bool) {} | EC manager instance is created successfully | Should be successful |
 * | 02 | Prepare the chirp message with an invalid hash and set required parameters | chirp.hash_valid = false, len = sizeof(em_dpp_chirp_value_t), src_mac = {0x10,0x20,0x30,0x40,0x50,0x60} | Chirp structure is configured with invalid hash | Should be successful |
 * | 03 | Invoke handle_autoconf_resp_chirp with the prepared chirp message and parameters | Input: chirp (hash_valid = false), len = sizeof(em_dpp_chirp_value_t), src_mac = {0x10,0x20,0x30,0x40,0x50,0x60} | API returns false, and EXPECT_FALSE(ret) passes | Should Pass |
 */
TEST(ec_manager_t, handle_autoconf_resp_chirp_enrollee_invalid_hash)
{
    std::cout << "Entering handle_autoconf_resp_chirp_enrollee_invalid_hash test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    ec_manager_t mgr("00:11:22:33:44:55", ops, false, std::nullopt, handler);
    em_dpp_chirp_value_t chirp{};
    chirp.hash_valid = false;
    size_t len = sizeof(em_dpp_chirp_value_t);
    uint8_t src_mac[ETH_ALEN] = {0x10,0x20,0x30,0x40,0x50,0x60};
    std::cout << "Invoking handle_autoconf_resp_chirp with hash_valid=false" << std::endl;
    bool ret = mgr.handle_autoconf_resp_chirp(&chirp, len, src_mac);
    std::cout << "Returned value: " << ret << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting handle_autoconf_resp_chirp_enrollee_invalid_hash test" << std::endl;
}
/**
 * @brief Validate handling of autoconfiguration response with a valid chirp for enrollee
 *
 * This test verifies that the handle_autoconf_resp_chirp API correctly processes a valid chirp message when the device is in enrollee mode. The objective is to ensure that under valid chirp conditions, the function returns false as expected, indicating proper handling of the autoconfiguration response.
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
 * | Variation / Step | Description | Test Data | Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize EC manager with dummy operations and handshake handler, prepare a valid chirp value and source MAC address. | ec_manager_t parameters: mac = "00:11:22:33:44:55", ops = dummy ops, mode flag = false; chirp.hash_valid = true; len = sizeof(em_dpp_chirp_value_t); src_mac = {0xde,0xad,0xbe,0xef,0x00,0x01} | EC manager instance is correctly created and chirp data is valid. | Should be successful |
 * | 02 | Invoke handle_autoconf_resp_chirp API with the prepared chirp and verify that the API returns false. | Input: pointer to chirp, len = sizeof(em_dpp_chirp_value_t), src_mac = {0xde,0xad,0xbe,0xef,0x00,0x01}; Output: ret (expected false) | The API returns false and the assertion EXPECT_FALSE(ret) passes. | Should Pass |
 */
TEST(ec_manager_t, handle_autoconf_resp_chirp_enrollee_valid_chirp)
{
    std::cout << "Entering handle_autoconf_resp_chirp_enrollee_valid_chirp test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    handshake_completed_handler handler = [](uint8_t[ETH_ALEN], bool) {};
    ec_manager_t mgr("00:11:22:33:44:55", ops, false, std::nullopt, handler);
    em_dpp_chirp_value_t chirp{};
    chirp.hash_valid = true;
    size_t len = sizeof(em_dpp_chirp_value_t);
    uint8_t src_mac[ETH_ALEN] = {0xde,0xad,0xbe,0xef,0x00,0x01};
    std::cout << "Invoking handle_autoconf_resp_chirp with valid chirp" << std::endl;
    bool ret = mgr.handle_autoconf_resp_chirp(&chirp, len, src_mac);
    std::cout << "Returned value: " << ret << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting handle_autoconf_resp_chirp_enrollee_valid_chirp test" << std::endl;
}
/**
 * @brief Tests process_1905_eapol_encap_msg with null frame for enrollee scenario
 *
 * This test verifies that the process_1905_eapol_encap_msg API returns false when invoked with a null frame pointer and zero length. It ensures that the function handles null input frames correctly for an enrollee role.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 039@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create ec_manager_t object as enrollee with dummy operations and secure context. | ops = dummy_ops(), sec_ctx = dummy_sec_ctx(), mac = "00:11:22:33:44:56", enrollee flag = false | Object is successfully created. | Should be successful |
 * | 02 | Invoke process_1905_eapol_encap_msg with null frame and zero length. | frame = nullptr, len = 0, src_mac = {0x00,0x11,0x22,0x33,0x44,0x55} | API returns false and EXPECT_FALSE(ret) passes. | Should Pass |
 */
TEST(ec_manager_t, process_1905_eapol_encap_msg_EnrolleeNullFrame)
{
    std::cout << "Entering process_1905_eapol_encap_msg_EnrolleeNullFrame test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    std::optional<ec_persistent_sec_ctx_t> sec_ctx = make_dummy_sec_ctx();
    std::cout << "Creating ec_manager_t object as enrollee" << std::endl;
    ec_manager_t mgr("00:11:22:33:44:56", ops, false, sec_ctx, nullptr);
    uint8_t *frame = nullptr;
    uint16_t len = 0;
    uint8_t src_mac[ETH_ALEN] = {0x00,0x11,0x22,0x33,0x44,0x55};
    std::cout << "Invoking process_1905_eapol_encap_msg with null frame and zero length" << std::endl;
    bool ret = mgr.process_1905_eapol_encap_msg(frame, len, src_mac);
    std::cout << "Returned value: " << ret << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting process_1905_eapol_encap_msg_EnrolleeNullFrame test" << std::endl;
}
/**
 * @brief Test the behavior of process_1905_eapol_encap_msg when provided with a zero-length frame.
 *
 * This test verifies that the process_1905_eapol_encap_msg function of ec_manager_t returns false when invoked with a zero-length frame.
 * It ensures that the function correctly handles invalid input conditions (i.e., an enrollee sending an EAPOL message with no content) by performing input validation and returning an error indication.
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
 * | Variation / Step | Description                                                                                          | Test Data                                                                                          | Expected Result                                                              | Notes       |
 * | :--------------: | ---------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke process_1905_eapol_encap_msg with a zero-length frame after initializing required context      | frame = [0,0,0,0,0,0,0,0,0,0], len = 0, src_mac = 0xaa,0xbb,0xcc,0xdd,0xee,0xff, ops = dummy, sec_ctx = dummy, id = "00:11:22:33:44:57" | Function returns false; EXPECT_FALSE(ret) assertion passes                   | Should Fail |
 */
TEST(ec_manager_t, process_1905_eapol_encap_msg_EnrolleeZeroLengthFrame)
{
    std::cout << "Entering process_1905_eapol_encap_msg_EnrolleeZeroLengthFrame test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    std::optional<ec_persistent_sec_ctx_t> sec_ctx = make_dummy_sec_ctx();
    ec_manager_t mgr("00:11:22:33:44:57", ops, false, sec_ctx, nullptr);
    uint8_t frame[10] = {0};
    uint16_t len = 0;
    uint8_t src_mac[ETH_ALEN] = {0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    std::cout << "Invoking process_1905_eapol_encap_msg with zero length frame" << std::endl;
    bool ret = mgr.process_1905_eapol_encap_msg(frame, len, src_mac);
    std::cout << "Returned value: " << ret << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting process_1905_eapol_encap_msg_EnrolleeZeroLengthFrame test" << std::endl;
}
/**
 * @brief Validate the process_1905_eapol_encap_msg API behavior with valid inputs in absence of the encryption layer.
 *
 * This test verifies that when the process_1905_eapol_encap_msg API is invoked with valid frame and source MAC inputs (and without an encryption layer enabled), it returns false as expected. The test ensures that the manager correctly handles the message encapsulation process for an enrollee with valid inputs but without encryption.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 041@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                        | Test Data                                                                                                                       | Expected Result                                                                       | Notes           |
 * | :--------------: | -------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- | --------------- |
 * | 01               | Create dummy operations using make_dummy_ops()                                                     | None                                                                                                                            | Dummy operations object created                                                       | Should be successful |
 * | 02               | Create dummy security context using make_dummy_sec_ctx()                                           | None                                                                                                                            | Dummy security context created                                                         | Should be successful |
 * | 03               | Instantiate ec_manager_t with given parameters                                                     | mac = "00:11:22:33:44:58", ops = result from make_dummy_ops(), flag = false, sec_ctx = result from make_dummy_sec_ctx(), nullptr as last argument | ec_manager_t object constructed                                                       | Should be successful |
 * | 04               | Initialize frame buffer and source MAC address                                                     | frame = {0x01,0x02,0x03, rest = 0x00}, len = size of frame, src_mac = {0x10,0x20,0x30,0x40,0x50,0x60}                        | Frame buffer and source MAC are correctly initialized                                   | Should be successful |
 * | 05               | Invoke process_1905_eapol_encap_msg API with valid frame and src_mac                                 | frame pointer, len, src_mac                                                                                                       | API returns false indicating expected behavior                                        | Should Fail     |
 * | 06               | Verify that the returned value from the API is false via the EXPECT_FALSE assertion                  | ret variable holding the return value from process_1905_eapol_encap_msg                                                         | The EXPECT_FALSE assertion should pass confirming the API returned false               | Should be successful |
 */
TEST(ec_manager_t, process_1905_eapol_encap_msg_EnrolleeValidInputsWithoutEncryptLayer)
{
    std::cout << "Entering process_1905_eapol_encap_msg_EnrolleeValidInputsWithoutEncryptLayer test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    std::optional<ec_persistent_sec_ctx_t> sec_ctx = make_dummy_sec_ctx();
    ec_manager_t mgr("00:11:22:33:44:58", ops, false, sec_ctx, nullptr);
    uint8_t frame[64] = {0x01,0x02,0x03};
    uint16_t len = sizeof(frame);
    uint8_t src_mac[ETH_ALEN] = {0x10,0x20,0x30,0x40,0x50,0x60};
    std::cout << "Invoking process_1905_eapol_encap_msg with valid frame and src_mac" << std::endl;
    bool ret = mgr.process_1905_eapol_encap_msg(frame, len, src_mac);
    std::cout << "Returned value: " << ret << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting process_1905_eapol_encap_msg_EnrolleeValidInputsWithoutEncryptLayer test" << std::endl;
}
/**
 * @brief Verify that the enrollee's default onboarding state is false
 *
 * This test creates an ec_manager_t object with dummy operational parameters and a dummy secure context,
 * then invokes is_enrollee_onboarding() to ensure that the default state correctly returns false.
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
 * | Variation / Step | Description                                                                                         | Test Data                                                                                                                             | Expected Result                                                      | Notes       |
 * | :--------------: | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- | ----------- |
 * | 01               | Create ec_manager_t object with dummy operations and secure context, then invoke is_enrollee_onboarding() to check default state | input1 = MAC "00:11:22:33:44:BB", input2 = dummy ops, input3 = enrollee flag false, input4 = dummy sec_ctx, input5 = nullptr, output1 = false | is_enrollee_onboarding() returns false based on default object's configuration | Should Pass |
 */
TEST(ec_manager_t, is_enrollee_onboarding_EnrolleeDefaultStateReturnsFalse)
{
    std::cout << "Entering is_enrollee_onboarding_EnrolleeDefaultStateReturnsFalse test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    std::optional<ec_persistent_sec_ctx_t> sec_ctx = make_dummy_sec_ctx();
    std::cout << "Creating ec_manager_t object as enrollee" << std::endl;
    ec_manager_t mgr("00:11:22:33:44:BB", ops, false, sec_ctx, nullptr);
    std::cout << "Invoking is_enrollee_onboarding()" << std::endl;
    bool ret = mgr.is_enrollee_onboarding();
    std::cout << "Returned value: " << ret << std::endl;
    std::cout << "Exiting is_enrollee_onboarding_EnrolleeDefaultStateReturnsFalse test" << std::endl;
}
/**
 * @brief Verify that handle_assoc_status returns true when provided with default-initialized sta_data for an enrollee
 *
 * This test creates a dummy ec_ops_t object and a dummy security context, then instantiates an ec_manager_t
 * object configured as an enrollee. It uses a default-initialized rdk_sta_data_t structure as input to the
 * handle_assoc_status API and verifies that the function returns true, ensuring that the API behaves as expected
 * under these conditions.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke make_dummy_ops to create dummy operations. | None | ec_ops_t instance created (dummy operations) | Should be successful |
 * | 02 | Invoke make_dummy_sec_ctx to create a dummy security context. | None | ec_persistent_sec_ctx_t is valid | Should be successful |
 * | 03 | Instantiate ec_manager_t as an enrollee. | mac = "00:11:22:33:44:11", ops = dummy ops, isEnrollee = false, sec_ctx = dummy sec_ctx, ptr = nullptr | ec_manager_t object is successfully created | Should be successful |
 * | 04 | Default initialize the rdk_sta_data_t structure. | sta_data = default-initialized | rdk_sta_data_t is default and unchanged | Should be successful |
 * | 05 | Invoke handle_assoc_status with the default sta_data. | sta_data = default-initialized | API returns true | Should Pass |
 * | 06 | Assert that the returned value is true using EXPECT_TRUE. | ret = true | The assertion verifies that ret equals true | Should Pass |
 */
TEST(ec_manager_t, handle_assoc_status_EnrolleeDefaultStaDataReturnsTrue)
{
    std::cout << "Entering handle_assoc_status_EnrolleeDefaultStaDataReturnsTrue test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    std::optional<ec_persistent_sec_ctx_t> sec_ctx = make_dummy_sec_ctx();
    std::cout << "Creating ec_manager_t object as enrollee" << std::endl;
    ec_manager_t mgr("00:11:22:33:44:11", ops, false, sec_ctx, nullptr);
    rdk_sta_data_t sta_data{};
    std::cout << "Invoking handle_assoc_status with default-initialized sta_data" << std::endl;
    bool ret = mgr.handle_assoc_status(sta_data);
    std::cout << "Returned value: " << ret << std::endl;
    EXPECT_TRUE(ret);
    std::cout << "Exiting handle_assoc_status_EnrolleeDefaultStaDataReturnsTrue test" << std::endl;
}
/**
 * @brief Verify that passing an empty wifi_bss_info_t list to handle_bss_info_event returns true.
 *
 * This test verifies that when the handle_bss_info_event method is invoked on an ec_manager_t instance,
 * instantiated as an enrollee, with an empty wifi BSS information list, the method returns true.
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
 * | 01 | Instantiate ec_manager_t as enrollee using dummy operations and security context. | ops = make_dummy_ops(), sec_ctx = make_dummy_sec_ctx(), mac = "00:11:22:33:44:13", enrollee flag = false, pointer = nullptr | ec_manager_t object is created successfully. | Should be successful |
 * | 02 | Initialize an empty wifi BSS information list. | bss_info_list = {} | bss_info_list is empty. | Should be successful |
 * | 03 | Invoke handle_bss_info_event with the empty list and check returned value. | input: bss_info_list = {} ; output: ret = API return value | API returns true as verified by EXPECT_TRUE(ret). | Should Pass |
 */
TEST(ec_manager_t, handle_bss_info_event_EnrolleeEmptyListReturnsTrue)
{
    std::cout << "Entering handle_bss_info_event_EnrolleeEmptyListReturnsTrue test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    std::optional<ec_persistent_sec_ctx_t> sec_ctx = make_dummy_sec_ctx();
    std::cout << "Creating ec_manager_t object as enrollee" << std::endl;
    ec_manager_t mgr("00:11:22:33:44:13", ops, false, sec_ctx, nullptr);
    std::vector<wifi_bss_info_t> bss_info_list;
    std::cout << "Invoking handle_bss_info_event with empty bss_info_list, size: "
              << bss_info_list.size() << std::endl;
    bool ret = mgr.handle_bss_info_event(bss_info_list);
    std::cout << "Returned value: " << ret << std::endl;
    EXPECT_TRUE(ret);
    std::cout << "Exiting handle_bss_info_event_EnrolleeEmptyListReturnsTrue test" << std::endl;
}
/**
 * @brief Verify that handle_bss_info_event returns true for a single default BSS info entry in enrollee mode
 *
 * This test validates that the ec_manager_t::handle_bss_info_event API correctly processes a BSS info list, which contains a single default entry, when instantiated in enrollee mode. It ensures that the function returns a true value as expected in a positive scenario.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create ec_manager_t object using dummy operations and security context, set up a single default wifi_bss_info_t in a vector, and invoke handle_bss_info_event. | MAC = "00:11:22:33:44:14", ops = make_dummy_ops(), sec_ctx = make_dummy_sec_ctx(), bss_info_list = [wifi_bss_info_t{}] | Function returns true and EXPECT_TRUE(ret) assertion passes | Should Pass |
 */
TEST(ec_manager_t, handle_bss_info_event_EnrolleeSingleDefaultEntryReturnsTrue)
{
    std::cout << "Entering handle_bss_info_event_EnrolleeSingleDefaultEntryReturnsTrue test" << std::endl;
    ec_ops_t ops = make_dummy_ops();
    std::optional<ec_persistent_sec_ctx_t> sec_ctx = make_dummy_sec_ctx();
    std::cout << "Creating ec_manager_t object as enrollee" << std::endl;
    ec_manager_t mgr("00:11:22:33:44:14", ops, false, sec_ctx, nullptr);
    wifi_bss_info_t bss_info{};
    std::vector<wifi_bss_info_t> bss_info_list{bss_info};
    std::cout << "Invoking handle_bss_info_event with bss_info_list size: "
              << bss_info_list.size() << std::endl;
    bool ret = mgr.handle_bss_info_event(bss_info_list);
    std::cout << "Returned value: " << ret << std::endl;
    EXPECT_TRUE(ret);
    std::cout << "Exiting handle_bss_info_event_EnrolleeSingleDefaultEntryReturnsTrue test" << std::endl;
}
