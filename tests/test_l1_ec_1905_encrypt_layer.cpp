#include <gtest/gtest.h>
#include <stdexcept>
#include <cstring>

#include "ec_1905_encrypt_layer.h"
#include "util.h"

using namespace std;

static bool g_send_dir_called = false;
static bool g_send_eapol_called = false;
static uint8_t g_last_sent_len = 0;

static send_dir_encap_dpp_func make_send_dir_stub() {
    return [](uint8_t* frame, size_t len, uint8_t* dst)->bool {
        std::cout << "Invoking send_dir_encap_dpp_msg len=%zu" << len << std::endl;
        g_send_dir_called = true;
        g_last_sent_len = static_cast<uint8_t>(len);
        return true;
    };
}

static send_1905_eapol_encap_func make_send_eapol_stub() {
    return [](uint8_t* frame, size_t len, uint8_t* dst)->bool {
        std::cout << "Invoking send_1905_eapol_encap_msg len=%zu" << len << std::endl;
        g_send_eapol_called = true;
        g_last_sent_len = static_cast<uint8_t>(len);
        return true;
    };
}

static handshake_completed_handler make_handshake_stub() {
    return [](uint8_t mac[ETH_ALEN], bool is_group){
        std::cout << "Handshake completed callback invoked for is_group=%d" << is_group << std::endl;
    };
}

// Helper MACs
static uint8_t valid_mac[ETH_ALEN] = {0x00,0x11,0x22,0x33,0x44,0x55};
static uint8_t other_mac[ETH_ALEN] = {0x66,0x77,0x88,0x99,0xAA,0xBB};

/**
 * @brief Verify if the ec_1905_encrypt_layer_t constructor properly constructs an object with a valid MAC.
 *
 * This test verifies that when a valid MAC string ("00:11:22:33:44:55") is provided along with stub functions
 * for send_dir, send_eapol, and handshake, the ec_1905_encrypt_layer_t object is constructed successfully without throwing
 * any exceptions. It ensures that the constructor handles valid input correctly.
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
 * | Variation / Step | Description                                                                 | Test Data                                                              | Expected Result                                                         | Notes           |
 * | :--------------: | --------------------------------------------------------------------------- | ---------------------------------------------------------------------- | ------------------------------------------------------------------------ | --------------- |
 * | 01               | Create stub functions for send_dir, send_eapol, and handshake                 | None                                                                   | Stubs created successfully                                               | Should be successful |
 * | 02               | Log the entry message "Entering Constructor_ValidMac_Constructs"            | Log: "Entering Constructor_ValidMac_Constructs"                      | Entry message logged                                                     | Should be successful |
 * | 03               | Invoke the constructor with a valid MAC string and the corresponding stubs    | input = "00:11:22:33:44:55", send_dir = stub, send_eapol = stub, handshake = stub | Object constructed without throwing an exception                       | Should Pass     |
 * | 04               | Log the exit message "Exiting Constructor_ValidMac_Constructs"              | Log: "Exiting Constructor_ValidMac_Constructs"                       | Exit message logged                                                      | Should be successful |
 */
TEST(EC1905EncryptLayer, Constructor_ValidMac_Constructs) {
    std::cout << "Entering Constructor_ValidMac_Constructs" << std::endl;
    auto send_dir = make_send_dir_stub();
    auto send_eapol = make_send_eapol_stub();
    auto handshake = make_handshake_stub();
    std::cout << "Invoking constructor with valid MAC string" << std::endl;
    EXPECT_NO_THROW({ ec_1905_encrypt_layer_t obj(std::string("00:11:22:33:44:55"), send_dir, send_eapol, handshake); });
    std::cout << "Exiting Constructor_ValidMac_Constructs" << std::endl;
}
/**
 * @brief Validate constructor input validation for ec_1905_encrypt_layer_t with an invalid MAC string.
 *
 * This test verifies that the constructor of ec_1905_encrypt_layer_t throws a std::invalid_argument exception when provided with an invalid MAC string. It ensures that the input validation mechanism within the constructor correctly identifies and handles malformed MAC addresses.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 002
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                                                                         | Test Data                                                                                              | Expected Result                                                                                                      | Notes       |
 * | :----:           | :-------------------------------------------------------------------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------- | :---------- |
 * | 01               | Create necessary stub objects and invoke the constructor of ec_1905_encrypt_layer_t with an invalid MAC string "badmac".                             | input: MAC string = "badmac", send_dir = stub, send_eapol = stub, handshake = stub                       | The constructor should throw a std::invalid_argument exception. Assertion: ADD_FAILURE if no exception thrown.         | Should Pass |
 */
TEST(EC1905EncryptLayer, Constructor_InvalidMac_Throws) {
    std::cout << "Entering Constructor_InvalidMac_Throws" << std::endl;
    auto send_dir = make_send_dir_stub();
    auto send_eapol = make_send_eapol_stub();
    auto handshake = make_handshake_stub();
    std::cout << "Invoking constructor with invalid MAC string (should throw)" << std::endl;
    try {
        ec_1905_encrypt_layer_t obj(std::string("badmac"), send_dir, send_eapol, handshake);
        // If we get here the constructor didn't throw
        ADD_FAILURE() << "Constructor did not throw for invalid MAC";
    } catch (const std::invalid_argument &e) {
        std::cout << "Caught expected exception: %s" << e.what() << std::endl; 
    } catch (...) {
        ADD_FAILURE() << "Constructor threw unexpected exception type";
    }
    std::cout << "Exiting Constructor_InvalidMac_Throws" << std::endl;
}
/**
 * @brief Verify that set_sec_params returns false when the c_sign_key parameter is null.
 *
 * This test validates the behavior of the ec_1905_encrypt_layer_t API when invoked with a null c_sign_key parameter.
 * The objective is to ensure that the API correctly identifies an invalid null key scenario and returns false.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create stub functions and instantiate ec_1905_encrypt_layer_t with a valid MAC address and stub functions. | mac_addr = "00:11:22:33:44:55", send_dir = stub, send_eapol = stub, handshake = stub | The stubs are created and the object is initialized successfully. | Should be successful |
 * | 02 | Invoke set_sec_params with nullptr for c_sign_key and a non-null dummy for net_access_key. | c_sign_key = nullptr, net_access_key = dummy value (0x1), additional parameters: empty string, EVP_sha256(), empty initializer list | The API returns false because the c_sign_key parameter is null. | Should Fail |
 * | 03 | Validate that the returned result is false using EXPECT_FALSE. | ret = result from set_sec_params call | The assertion verifies that the return value is false. | Should be successful |
 */
TEST(EC1905EncryptLayer, SetSecParams_NullCSignKey_ReturnsFalse) {
    std::cout << "Entering SetSecParams_NullCSignKey_ReturnsFalse" << std::endl;
    auto send_dir = make_send_dir_stub();
    auto send_eapol = make_send_eapol_stub();
    auto handshake = make_handshake_stub();
    ec_1905_encrypt_layer_t obj(std::string("00:11:22:33:44:55"), send_dir, send_eapol, handshake);
    std::cout << "Invoking set_sec_params with NULL c_sign_key (only c_sign_key is null)" << std::endl;
    // Provide a non-null dummy for net_access_key to ensure the first NULL check is for c_sign_key
    SSL_KEY* dummy_net_access = reinterpret_cast<SSL_KEY*>(0x1);
    bool ret = obj.set_sec_params(nullptr, dummy_net_access, std::string(""), EVP_sha256(), {});
    std::cout << "Exiting SetSecParams_NullCSignKey_ReturnsFalse: returned %s" << (ret ? "true" : "false") << std::endl;
    EXPECT_FALSE(ret);
}
/**
 * @brief Validate that set_sec_params returns false when net_access_key is NULL
 *
 * This test verifies that when the net_access_key parameter is passed as NULL to the set_sec_params API, the API correctly returns false. The test instantiates an ec_1905_encrypt_layer_t object with stub functions and invokes set_sec_params with a valid dummy c_sign and a NULL net_access_key parameter.
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
 * | Variation / Step | Description                                                                 | Test Data                                                                                               | Expected Result                                                  | Notes          |
 * | :--------------: | --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- | -------------- |
 * | 01               | Initialize EC1905EncryptLayer instance with stub functions and a valid MAC | MAC = "00:11:22:33:44:55", send_dir stub, send_eapol stub, handshake stub                                | Object is correctly instantiated                                  | Should be successful |
 * | 02               | Invoke set_sec_params with a valid dummy c_sign and NULL net_access_key         | input1 (c_sign) = reinterpret_cast<SSL_KEY*>(0x1), input2 (net_access_key) = nullptr, input3 (dummy string) = "dummy", input4 (hash algorithm) = EVP_sha256(), input5 (empty vector) | API returns false                                                 | Should Pass    |
 * | 03               | Validate the returned value from set_sec_params                              | output (ret) = bool value returned by set_sec_params                                                    | EXPECT_FALSE(ret) assertion passes                                 | Should be successful |
 */
TEST(EC1905EncryptLayer, SetSecParams_NullNetAccessKey_ReturnsFalse) {
    std::cout << "Entering SetSecParams_NullNetAccessKey_ReturnsFalse" << std::endl;
    auto send_dir = make_send_dir_stub();
    auto send_eapol = make_send_eapol_stub();
    auto handshake = make_handshake_stub();
    ec_1905_encrypt_layer_t obj(std::string("00:11:22:33:44:55"), send_dir, send_eapol, handshake);
    std::cout << "Invoking set_sec_params with NULL net_access_key (only net_access_key is null)" << std::endl;
    SSL_KEY* dummy_c_sign = reinterpret_cast<SSL_KEY*>(0x1);
    bool ret = obj.set_sec_params(dummy_c_sign, nullptr, std::string("dummy"), EVP_sha256(), {});
    std::cout << "Exiting SetSecParams_NullNetAccessKey_ReturnsFalse: returned %s" << (ret ? "true" : "false") << std::endl;
    EXPECT_FALSE(ret);
}
/**
 * @brief Tests handle_eapol_frame with a NULL frame to ensure that it returns false.
 *
 * This test validates that when a NULL frame pointer is provided to the handle_eapol_frame API, the method correctly handles the invalid input by returning false. This helps confirm robust error handling in the encryption layer.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize EC1905EncryptLayer object with a valid MAC address and stub functions. | MAC = "00:11:22:33:44:55", send_dir = make_send_dir_stub(), send_eapol = make_send_eapol_stub(), handshake = make_handshake_stub() | Object is created successfully without errors. | Should be successful |
 * | 02 | Invoke handle_eapol_frame with a NULL frame pointer. | frame = nullptr, length = 0, mac = valid_mac | Returns false and EXPECT_FALSE assertion passes. | Should Pass |
 */
TEST(EC1905EncryptLayer, HandleEapolFrame_NullFrame_ReturnsFalse) {
    std::cout << "Entering HandleEapolFrame_NullFrame_ReturnsFalse" << std::endl;
    auto send_dir = make_send_dir_stub();
    auto send_eapol = make_send_eapol_stub();
    auto handshake = make_handshake_stub();
    ec_1905_encrypt_layer_t obj(std::string("00:11:22:33:44:55"), send_dir, send_eapol, handshake);
    std::cout << "Invoking handle_eapol_frame with NULL frame" << std::endl;
    bool ret = obj.handle_eapol_frame(nullptr, 0, valid_mac);
    std::cout << "Exiting handle_eapol_frame(NULL): returned %s" << (ret ? "true" : "false") << std::endl;
    EXPECT_FALSE(ret);
}
/**
 * @brief Verify that handle_eapol_frame returns false when the frame length is zero.
 *
 * This test verifies that the ec_1905_encrypt_layer_t::handle_eapol_frame function correctly returns false when provided with a valid, non-null frame pointer but with a length of zero. This behavior is essential to ensure that the API properly handles cases of invalid frame length, preventing further processing of an empty payload.
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
 * | Variation / Step | Description                                                                                         | Test Data                                                       | Expected Result                                          | Notes     |
 * | :--------------: | --------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- | -------------------------------------------------------- | --------- |
 * |       01       | Initialize EC1905EncryptLayer with stub functions and invoke handle_eapol_frame with len==0           | tmp = {0}, len = 0, valid_mac = valid_mac, MAC = "00:11:22:33:44:55" | API returns false and EXPECT_FALSE assertion passes      | Should Pass |
 */
TEST(EC1905EncryptLayer, HandleEapolFrame_LenZero_ReturnsFalse) {
    std::cout << "Entering HandleEapolFrame_LenZero_ReturnsFalse" << std::endl;
    auto send_dir = make_send_dir_stub();
    auto send_eapol = make_send_eapol_stub();
    auto handshake = make_handshake_stub();
    ec_1905_encrypt_layer_t obj(std::string("00:11:22:33:44:55"), send_dir, send_eapol, handshake);
    std::cout << "Invoking handle_eapol_frame with non-null frame but len==0" << std::endl;
    uint8_t tmp[4] = {0};
    bool ret = obj.handle_eapol_frame(tmp, 0, valid_mac);
    std::cout << "Exiting handle_eapol_frame(len==0): returned %s" << (ret ? "true" : "false") << std::endl;
    EXPECT_FALSE(ret);
}
/**
 * @brief Verify that starting the secure 1905 layer with a NULL destination address returns false.
 *
 * This test case validates that the ec_1905_encrypt_layer_t API correctly returns a false value when invoked with a NULL destination MAC address. It simulates an invalid input scenario to ensure that the API can handle erroneous conditions properly.@n
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
 * | Variation / Step | Description                                                                     | Test Data                                                        | Expected Result                                                  | Notes            |
 * | :--------------: | ------------------------------------------------------------------------------- | ---------------------------------------------------------------- | ---------------------------------------------------------------- | ---------------- |
 * | 01               | Display entry message and create send_dir, send_eapol, and handshake stubs.     | Invocation of make_send_dir_stub, make_send_eapol_stub, make_handshake_stub | Stubs are created successfully.                                  | Should be successful |
 * | 02               | Construct ec_1905_encrypt_layer_t object with a valid MAC and the created stubs.  | input1 = "00:11:22:33:44:55", stub pointers as output parameters   | Object is constructed correctly.                                 | Should be successful |
 * | 03               | Invoke start_secure_1905_layer with a NULL destination address.                 | dest = nullptr                                                  | API returns false and EXPECT_FALSE assertion passes.             | Should Pass      |
 * | 04               | Display exit message with the returned result.                                | ret = false (from API call)                                        | Console output indicates the result is false.                      | Should be successful |
 */
TEST(EC1905EncryptLayer, StartSecure1905Layer_NullDest_ReturnsFalse) {
    std::cout << "Entering StartSecure1905Layer_NullDest_ReturnsFalse" << std::endl;
    auto send_dir = make_send_dir_stub();
    auto send_eapol = make_send_eapol_stub();
    auto handshake = make_handshake_stub();
    ec_1905_encrypt_layer_t obj(std::string("00:11:22:33:44:55"), send_dir, send_eapol, handshake);
    std::cout << "Invoking start_secure_1905_layer with NULL dest_al_mac" << std::endl;
    uint8_t* dest = nullptr;
    bool ret = obj.start_secure_1905_layer(dest);
    std::cout << "Exiting StartSecure1905Layer_NullDest_ReturnsFalse: returned %s" << (ret ? "true" : "false") << std::endl;
    EXPECT_FALSE(ret);
}
/**
 * @brief Verify that start_secure_1905_layer returns false when provided with an invalid MAC address length.
 *
 * This test checks the behavior of the start_secure_1905_layer API when an input MAC address of invalid (short) length is supplied.
 * It ensures that the API correctly identifies the invalid MAC address and returns a false value.
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
 * | Variation / Step | Description                                                                                   | Test Data                                                                            | Expected Result                                                       | Notes            |
 * | :--------------: | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ | --------------------------------------------------------------------- | ---------------- |
 * | 01               | Set up stubs for send_dir, send_eapol, and handshake, and instantiate ec_1905_encrypt_layer_t. | MAC = "00:11:22:33:44:55", send_dir = stub, send_eapol = stub, handshake = stub       | Object is created successfully.                                      | Should be successful |
 * | 02               | Invoke start_secure_1905_layer with a MAC address of invalid (short) length and assert false.   | short_mac = {1,2,3}                                                                  | API returns false; EXPECT_FALSE assertion passes.                    | Should Fail       |
 */
TEST(EC1905EncryptLayer, StartSecure1905Layer_InvalidMacLength_ReturnsFalse)
{
    std::cout << "Entering StartSecure1905Layer_InvalidMacLength_ReturnsFalse"  << std::endl;
    auto send_dir   = make_send_dir_stub();
    auto send_eapol = make_send_eapol_stub();
    auto handshake  = make_handshake_stub();
    ec_1905_encrypt_layer_t obj("00:11:22:33:44:55", send_dir, send_eapol, handshake);
    uint8_t short_mac[3] = {1,2,3};
    std::cout << "Exiting StartSecure1905Layer_InvalidMacLength_ReturnsFalse" << std::endl;
    EXPECT_FALSE(obj.start_secure_1905_layer(short_mac));
}
/**
 * @brief Test rekey_1905_layer_ptk() returns false when security parameters are incomplete
 *
 * This test validates that invoking rekey_1905_layer_ptk() without providing necessary security parameters (e.g., CSignKey) correctly results in a failure by returning false. The test ensures that the API checks for complete security parameter configuration and does not process an incomplete request.
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
 * | Variation / Step | Description                                                                 | Test Data                                                                                  | Expected Result                                                   | Notes       |
 * | :--------------: | --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ | ----------------------------------------------------------------- | ----------- |
 * | 01               | Instantiate ec_1905_encrypt_layer_t without the complete security parameters and call rekey_1905_layer_ptk() | macAddress = "00:11:22:33:44:55", send_dir = stub, send_eapol = stub, handshake = stub, security params missing | The API returns false and the EXPECT_FALSE assertion passes      | Should Pass |
 */
TEST(EC1905EncryptLayer, RekeyPTK_All_NoCSignKey_ReturnsFalse) {
    std::cout << "Entering RekeyPTK_All_NoCSignKey_ReturnsFalse" << std::endl;
    auto send_dir = make_send_dir_stub();
    auto send_eapol = make_send_eapol_stub();
    auto handshake = make_handshake_stub();
    ec_1905_encrypt_layer_t obj(std::string("00:11:22:33:44:55"), send_dir, send_eapol, handshake);
    std::cout << "Invoking rekey_1905_layer_ptk() without security params (should return false)" << std::endl;
    bool ret = obj.rekey_1905_layer_ptk();
    std::cout << "Exiting rekey_1905_layer_ptk(): returned %s" << (ret ? "true" : "false") << std::endl;
    EXPECT_FALSE(ret);
}
/**
 * @brief Verify that rekey_1905_layer_ptk returns false when invoked without security parameters.
 *
 * This test verifies that the rekey_1905_layer_ptk function in ec_1905_encrypt_layer_t returns false
 * when called with a valid MAC address but without the necessary security parameters. It ensures that the
 * function handles a negative scenario correctly where the certificate/signing key is not provided.
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
 * | Variation / Step | Description                                                                      | Test Data                                                                    | Expected Result                                                         | Notes               |
 * | :--------------: | -------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | ---------------------------------------------------------------------- | ------------------- |
 * | 01               | Initialize stubs and create ec_1905_encrypt_layer_t object with MAC "00:11:22:33:44:55" | input: MAC = "00:11:22:33:44:55", send_dir = stub, send_eapol = stub, handshake = stub | Object is successfully created                                           | Should be successful |
 * | 02               | Invoke rekey_1905_layer_ptk using valid_mac without the required security parameters | input: valid_mac = valid_mac                                                  | API returns false                                                      | Should Fail         |
 * | 03               | Validate that the returned value is false using ASSERT_FALSE                      | output: ret = false                                                           | Return value false verified by EXPECT_FALSE                               | Should be successful |
 */
TEST(EC1905EncryptLayer, RekeyPTK_Single_NoCSignKey_ReturnsFalse) {
    std::cout << "Entering RekeyPTK_Single_NoCSignKey_ReturnsFalse" << std::endl;
    auto send_dir = make_send_dir_stub();
    auto send_eapol = make_send_eapol_stub();
    auto handshake = make_handshake_stub();
    ec_1905_encrypt_layer_t obj(std::string("00:11:22:33:44:55"), send_dir, send_eapol, handshake);
    std::cout << "Invoking rekey_1905_layer_ptk(dest) without security params (should return false)" << std::endl;
    bool ret = obj.rekey_1905_layer_ptk(valid_mac);
    std::cout << "Exiting rekey_1905_layer_ptk(dest): returned %s" << (ret ? "true" : "false") << std::endl;
    EXPECT_FALSE(ret);
}
/**
 * @brief Test that rekey_1905_layer_gtk returns false when no security parameters are provided.
 *
 * This test validates that the rekey_1905_layer_gtk function correctly handles the scenario where no security parameters (CSign key or GMK)
 * are provided, ensuring that the function returns false. This behavior is essential to prevent insecure operations.
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
 * | Variation / Step | Description                                                                   | Test Data                                                                                          | Expected Result                            | Notes              |
 * | :--------------: | ----------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- | ------------------------------------------ | ------------------ |
 * | 01               | Set up stub functions for send_dir, send_eapol, and handshake.                | send_dir = make_send_dir_stub(), send_eapol = make_send_eapol_stub(), handshake = make_handshake_stub() | Stub functions created successfully.       | Should be successful |
 * | 02               | Instantiate EC1905EncryptLayer object with MAC address and stubs.             | mac = "00:11:22:33:44:55", send_dir = stub, send_eapol = stub, handshake = stub                     | Encryption layer object created successfully. | Should be successful |
 * | 03               | Invoke rekey_1905_layer_gtk without security parameters or GMK.             | No additional security parameters provided                                                         | Function returns false.                    | Should Fail         |
 * | 04               | Verify that the function returns false using EXPECT_FALSE.                  | return value from rekey_1905_layer_gtk = false                                                       | Return value equals false.                 | Should be successful |
 */
TEST(EC1905EncryptLayer, RekeyGTK_NoCSignKeyOrGMK_ReturnsFalse) {
    std::cout << "Entering RekeyGTK_NoCSignKeyOrGMK_ReturnsFalse" << std::endl;
    auto send_dir = make_send_dir_stub();
    auto send_eapol = make_send_eapol_stub();
    auto handshake = make_handshake_stub();
    ec_1905_encrypt_layer_t obj(std::string("00:11:22:33:44:55"), send_dir, send_eapol, handshake);
    std::cout << "Invoking rekey_1905_layer_gtk without security params/GMK" << std::endl;
    bool ret = obj.rekey_1905_layer_gtk();
    std::cout << "Exiting rekey_1905_layer_gtk: returned %s" << (ret ? "true" : "false") << std::endl;
    EXPECT_FALSE(ret);
}
/**
 * @brief Verify that handle_eapol_frame returns false when provided with a NULL source MAC.
 *
 * Tests the behavior of the ec_1905_encrypt_layer_t object when handle_eapol_frame is called with a valid frame but a NULL source MAC pointer. The test ensures that the method returns false and that the send_dir and send_eapol stub functions are not called.
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
 * | 01 | Create stub objects and instantiate ec_1905_encrypt_layer_t with a preset MAC address and stub functions | input: MAC = "00:11:22:33:44:55", send_dir stub, send_eapol stub, handshake stub | Object is instantiated successfully | Should be successful |
 * | 02 | Initialize a frame buffer and invoke handle_eapol_frame with a valid frame and a NULL source MAC pointer | input: frame = {0,...} (32 bytes), size = 32, source MAC = NULL, output: return value false | Returns false; send_dir and send_eapol functions are not called | Should Pass |
 */
TEST(EC1905EncryptLayer, HandleEapolFrame_NullSourceMac_ReturnsFalse)
{
    std::cout << "Entering HandleEapolFrame_NullSourceMac_ReturnsFalse" << std::endl;
    auto send_dir   = make_send_dir_stub();
    auto send_eapol = make_send_eapol_stub();
    auto handshake  = make_handshake_stub();
    ec_1905_encrypt_layer_t obj("00:11:22:33:44:55", send_dir, send_eapol, handshake);
    uint8_t frame[32] = {0};
    std::cout << "Calling handle_eapol_frame with NULL source MAC" << std::endl;
    bool ret = obj.handle_eapol_frame(frame, sizeof(frame), nullptr);
    EXPECT_FALSE(ret);
    EXPECT_FALSE(g_send_dir_called);
    EXPECT_FALSE(g_send_eapol_called);
    std::cout << "Exiting HandleEapolFrame_NullSourceMac_ReturnsFalse" << std::endl;
}
/**
 * @brief Test to ensure that handle_eapol_frame processes frames without crashing when security parameters are provided.
 *
 * This test verifies that the EC1905EncryptLayer::handle_eapol_frame function can handle an EAPOL frame input along with security parameters without throwing any exceptions. It creates stub objects for dependencies, initializes the EC1905EncryptLayer instance, prepares a sample EAPOL frame, and invokes the API to check that no crash occurs.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize all stub dependencies and create an instance of EC1905EncryptLayer. | mac = "00:11:22:33:44:55", send_dir = make_send_dir_stub(), send_eapol = make_send_eapol_stub(), handshake = make_handshake_stub() | EC1905EncryptLayer instance is created successfully. | Should be successful |
 * | 02 | Prepare the EAPOL frame data for testing. | frame = {1,2,3,4,0,0,0,...} (32 bytes total) | Frame data is correctly initialized. | Should be successful |
 * | 03 | Invoke handle_eapol_frame with the prepared frame and other_mac, ensuring it does not throw an exception. | frame pointer = frame, frame size = 32, other_mac = <provided externally> | The function call completes without throwing exceptions. | Should Pass |
 */
TEST(EC1905EncryptLayer, HandleEapolFrame_WithSecParams_NoCrash)
{
    std::cout << "Entering HandleEapolFrame_WithSecParams_NoCrash"  << std::endl;
    auto send_dir   = make_send_dir_stub();
    auto send_eapol = make_send_eapol_stub();
    auto handshake  = make_handshake_stub();
    ec_1905_encrypt_layer_t obj("00:11:22:33:44:55", send_dir, send_eapol, handshake);
    uint8_t frame[32] = {1,2,3,4};
    EXPECT_NO_THROW({
        obj.handle_eapol_frame(frame, sizeof(frame), other_mac);
    });
    std::cout << "Exiting HandleEapolFrame_WithSecParams_NoCrash"  << std::endl;
}
/**
 * @brief Test that the API returns false when a broadcast MAC address is provided.
 *
 * This test validates the functionality of the handle_eapol_frame method of the ec_1905_encrypt_layer_t class.
 * It ensures that when a broadcast MAC address is used as the destination, the method correctly returns false,
 * indicating that frames destined for broadcast should not be processed.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 014@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                              | Test Data                                                                                                                           | Expected Result                                                               | Notes       |
 * | :--------------: | ---------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- | ----------- |
 * | 01               | Construct the ec_1905_encrypt_layer_t object using stub functions and provided MAC address | object MAC = "00:11:22:33:44:55", send_dir stub, send_eapol stub, handshake stub                                                     | Object is constructed successfully                                          | Should be successful |
 * | 02               | Invoke handle_eapol_frame with a frame buffer and a broadcast MAC address                  | frame = {1, ...}, size = 32, destination MAC = 0xff,0xff,0xff,0xff,0xff,0xff; (all values are set in the test setup)                 | Returns false and the EXPECT_FALSE check passes                             | Should Pass  |
 */
TEST(EC1905EncryptLayer, HandleEapolFrame_BroadcastMac_ReturnsFalse)
{
    std::cout << "Entering HandleEapolFrame_BroadcastMac_ReturnsFalse"  << std::endl;
    auto send_dir   = make_send_dir_stub();
    auto send_eapol = make_send_eapol_stub();
    auto handshake  = make_handshake_stub();
    ec_1905_encrypt_layer_t obj("00:11:22:33:44:55", send_dir, send_eapol, handshake);
    uint8_t frame[32] = {1};
    uint8_t broadcast[ETH_ALEN] = {0xff,0xff,0xff,0xff,0xff,0xff};
    EXPECT_FALSE(obj.handle_eapol_frame(frame, sizeof(frame), broadcast));
    std::cout << "Exiting HandleEapolFrame_BroadcastMac_ReturnsFalse"  << std::endl;
}
/**
 * @brief Validate that handle_eapol_frame returns false when invoked before setting security parameters.
 *
 * This test verifies that the handle_eapol_frame API returns false when it is called before security parameters are set for the encryption layer. It also confirms that the related functions send_dir and send_eapol are not invoked.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 015
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                   | Test Data                                                                                         | Expected Result                                                                                      | Notes            |
 * | :--------------: | ------------------------------------------------------------------------------| --------------------------------------------------------------------------------------------------| ---------------------------------------------------------------------------------------------------- | ---------------- |
 * | 01               | Create stub instances for send_dir, send_eapol, and handshake objects.         | No input arguments.                                                                                 | Stub objects are successfully created.                                                               | Should be successful |
 * | 02               | Instantiate ec_1905_encrypt_layer_t with the specified MAC address and stubs.  | input: MAC = "00:11:22:33:44:55", send_dir, send_eapol, handshake                                    | Object instance is created successfully.                                                             | Should be successful |
 * | 03               | Prepare an EAPOL frame of 64 bytes initialized to 0.                          | input: frame = 64 bytes all set to 0.                                                               | Frame data is properly prepared.                                                                     | Should be successful |
 * | 04               | Invoke handle_eapol_frame before setting security parameters.                | input: frame pointer, frame size = 64, other_mac = <value>                                          | API returns false as confirmed by EXPECT_FALSE(ret).                                                 | Should Fail      |
 * | 05               | Verify that send_dir and send_eapol functions were not called.                | input: global flags g_send_dir_called = false, g_send_eapol_called = false                           | Global flags remain false as confirmed by EXPECT_FALSE(g_send_dir_called) and EXPECT_FALSE(g_send_eapol_called). | Should be successful |
 */
TEST(EC1905EncryptLayer, HandleEapolFrame_BeforeSetSecParams_ReturnsFalse)
{
    std::cout << "Entering HandleEapolFrame_BeforeSetSecParams_ReturnsFalse" << std::endl;
    auto send_dir   = make_send_dir_stub();
    auto send_eapol = make_send_eapol_stub();
    auto handshake  = make_handshake_stub();
    ec_1905_encrypt_layer_t obj("00:11:22:33:44:55", send_dir, send_eapol, handshake);
    uint8_t frame[64] = {0};
    std::cout << "Invoking handle_eapol_frame before setting security params" << std::endl;
    bool ret = obj.handle_eapol_frame(frame, sizeof(frame), other_mac);
    EXPECT_FALSE(ret);
    EXPECT_FALSE(g_send_dir_called);
    EXPECT_FALSE(g_send_eapol_called);
    std::cout << "Exiting HandleEapolFrame_BeforeSetSecParams_ReturnsFalse" << std::endl;
}
/**
 * @brief Verify that starting the secure 1905 layer without security keys returns false.
 *
 * This test validates that when the EC1905EncryptLayer API is invoked without providing the necessary security keys, 
 * the secure 1905 layer does not start and the method returns false. Additionally, it confirms that the send_dir callback is not triggered.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 016
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                        | Test Data                                                                                          | Expected Result                                                       | Notes            |
 * | :--------------: | ------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | ---------------- |
 * | 01               | Initialize stubs and create an EC1905EncryptLayer object with MAC address | send_dir = make_send_dir_stub(), send_eapol = make_send_eapol_stub(), handshake = make_handshake_stub(), MAC = "00:11:22:33:44:55" | EC1905EncryptLayer object is instantiated successfully                | Should be successful |
 * | 02               | Invoke start_secure_1905_layer without security keys               | input: other_mac = value not provided (test-specific value), no security keys provided             | The API returns false                                                 | Should Pass      |
 * | 03               | Validate that the send_dir callback was not triggered              | output: g_send_dir_called flag is expected to be false                                             | g_send_dir_called remains false                                       | Should Pass      |
 */
TEST(EC1905EncryptLayer, StartSecure1905Layer_WithoutKeys_ReturnsFalse)
{
    std::cout << "Entering StartSecure1905Layer_WithoutKeys_ReturnsFalse" << std::endl;
    auto send_dir   = make_send_dir_stub();
    auto send_eapol = make_send_eapol_stub();
    auto handshake  = make_handshake_stub();
    ec_1905_encrypt_layer_t obj("00:11:22:33:44:55", send_dir, send_eapol, handshake);
    std::cout << "Calling start_secure_1905_layer without security keys" << std::endl;
    bool ret = obj.start_secure_1905_layer(other_mac);
    EXPECT_FALSE(ret);
    EXPECT_FALSE(g_send_dir_called);
    std::cout << "Exiting StartSecure1905Layer_WithoutKeys_ReturnsFalse" << std::endl;
}
/**
 * @brief Verify that rekey_1905_layer_ptk returns false when provided with a NULL MAC address
 *
 * This test case validates that the function rekey_1905_layer_ptk correctly handles a NULL MAC address input by returning false.
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
 * | Variation / Step | Description                                                              | Test Data                                                                                                                          | Expected Result                                   | Notes         |
 * | :--------------: | ------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- | ------------- |
 * | 01               | Initialize the EC1905EncryptLayer object with valid MAC and stub handlers | input: MAC = "00:11:22:33:44:55", send_dir = make_send_dir_stub(), send_eapol = make_send_eapol_stub(), handshake = make_handshake_stub() | Object is initialized without error               | Should be successful |
 * | 02               | Invoke rekey_1905_layer_ptk with a NULL MAC pointer                        | input: mac = nullptr, output: ret (expected to be false)                                                                           | API returns false and assertion EXPECT_FALSE passes | Should Fail   |
 */
TEST(EC1905EncryptLayer, RekeyPTK_NullMac_ReturnsFalse)
{
    std::cout << "Entering RekeyPTK_NullMac_ReturnsFalse" << std::endl;
    auto send_dir   = make_send_dir_stub();
    auto send_eapol = make_send_eapol_stub();
    auto handshake  = make_handshake_stub();
    ec_1905_encrypt_layer_t obj("00:11:22:33:44:55", send_dir, send_eapol, handshake);
    std::cout << "Calling rekey_1905_layer_ptk with NULL MAC" << std::endl;
    bool ret = obj.rekey_1905_layer_ptk(nullptr);
    EXPECT_FALSE(ret);
    std::cout << "Exiting RekeyPTK_NullMac_ReturnsFalse" << std::endl;
}
/**
 * @brief Verify that rekey_1905_layer_gtk fails when GMK is not provided
 *
 * This test case checks the behavior of the rekey_1905_layer_gtk API when the GMK is missing.
 * It instantiates the EC1905EncryptLayer object with valid stub functions and a preset MAC address,
 * but without initializing the GMK. The API is expected to return false, indicating the rekeying operation fails.
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
 * | Variation / Step | Description                                                                                  | Test Data                                                                                                                       | Expected Result                                                                             | Notes          |
 * | :--------------: | -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | -------------- |
 * | 01               | Instantiate EC1905EncryptLayer object with required stub functions and without GMK             | mac address = "00:11:22:33:44:55", send_dir = stub pointer, send_eapol = stub pointer, handshake = stub pointer                | Object is created successfully                                                              | Should be successful |
 * | 02               | Call rekey_1905_layer_gtk() method to trigger GTK rekey operation without GMK                   | input: none, output: return value = false                                                                                       | API returns false indicating failure due to missing GMK, and EXPECT_FALSE assertion passes  | Should Fail    |
 */
TEST(EC1905EncryptLayer, RekeyGTK_WithoutGMK_ReturnsFalse)
{
    std::cout << "Entering RekeyGTK_WithoutGMK_ReturnsFalse" << std::endl;
    auto send_dir   = make_send_dir_stub();
    auto send_eapol = make_send_eapol_stub();
    auto handshake  = make_handshake_stub();
    ec_1905_encrypt_layer_t obj("00:11:22:33:44:55", send_dir, send_eapol, handshake);
    std::cout << "Calling rekey_1905_layer_gtk without GMK" << std::endl;
    bool ret = obj.rekey_1905_layer_gtk();
    EXPECT_FALSE(ret);
    std::cout << "Exiting RekeyGTK_WithoutGMK_ReturnsFalse" << std::endl;
}
/**
 * @brief Test to ensure that multiple instances of ec_1905_encrypt_layer_t can be constructed without throwing exceptions
 *
 * This test verifies that when constructing multiple instances of ec_1905_encrypt_layer_t with different MAC addresses and using stubs for send_dir, send_eapol, and handshake, no exceptions are thrown. It is important to confirm that the constructor supports multiple valid input combinations reliably.
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
 * | Variation / Step | Description                                                                                       | Test Data                                                                                                                                                               | Expected Result                                                              | Notes      |
 * | :--------------: | ------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | ---------- |
 * | 01               | Invoke the constructor for two instances of ec_1905_encrypt_layer_t with valid stubs              | input1 = "00:11:22:33:44:55", send_dir, send_eapol, handshake; input1 = "66:77:88:99:AA:BB", send_dir, send_eapol, handshake                                             | No exception thrown during instantiation; constructor assertion passes       | Should Pass |
 */
TEST(EC1905EncryptLayer, Constructor_MultipleInstances_Constructs)
{
    std::cout << "Entering Constructor_MultipleInstances_Constructs" << std::endl;
    auto send_dir   = make_send_dir_stub();
    auto send_eapol = make_send_eapol_stub();
    auto handshake  = make_handshake_stub();
    EXPECT_NO_THROW({
        ec_1905_encrypt_layer_t obj1("00:11:22:33:44:55", send_dir, send_eapol, handshake);
        ec_1905_encrypt_layer_t obj2("66:77:88:99:AA:BB", send_dir, send_eapol, handshake);
    });
    std::cout << "Exiting Constructor_MultipleInstances_Constructs" << std::endl;
}
/**
 * @brief Verify that the ec_1905_encrypt_layer_t constructor accepts valid MAC address formats.
 *
 * This test ensures that the ec_1905_encrypt_layer_t constructor successfully creates objects when provided with both lower-case ("aa:bb:cc:dd:ee:ff") and upper-case ("AA:BB:CC:DD:EE:FF") MAC address formats. The test confirms that no exceptions are thrown during the construction process, ensuring reliability for valid MAC inputs.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 020@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke ec_1905_encrypt_layer_t constructor with valid lower-case and upper-case MAC addresses, using valid stubs for send_dir, send_eapol, and handshake | For first object: input MAC = "aa:bb:cc:dd:ee:ff", send_dir = valid stub, send_eapol = valid stub, handshake = valid stub; For second object: input MAC = "AA:BB:CC:DD:EE:FF", send_dir = valid stub, send_eapol = valid stub, handshake = valid stub | No exceptions thrown and successful object construction | Should Pass |
 */
TEST(EC1905EncryptLayer, Constructor_ValidMacFormats_Constructs)
{
    std::cout << "Entering Constructor_ValidMacFormats_Constructs" << std::endl;
    auto send_dir   = make_send_dir_stub();
    auto send_eapol = make_send_eapol_stub();
    auto handshake  = make_handshake_stub();
    EXPECT_NO_THROW({
        ec_1905_encrypt_layer_t obj1("aa:bb:cc:dd:ee:ff", send_dir, send_eapol, handshake);
        ec_1905_encrypt_layer_t obj2("AA:BB:CC:DD:EE:FF", send_dir, send_eapol, handshake);
    });
    std::cout << "Exiting Constructor_ValidMacFormats_Constructs" << std::endl;
}
/**
 * @brief Verifies that multiple invocations of handle_eapol_frame do not crash the system.
 *
 * This test verifies that repeated calls to EC1905EncryptLayer::handle_eapol_frame using a dummy frame do not cause a crash. It further confirms that the API consistently returns false, ensuring its stability under repeated usage.
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
 * | Variation / Step | Description                                                                   | Test Data                                                                                                                    | Expected Result                                                                    | Notes            |
 * | :--------------: | ----------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- | ---------------- |
 * | 01               | Initialize EC1905EncryptLayer object with stub functions and a valid MAC address | send_dir = make_send_dir_stub(), send_eapol = make_send_eapol_stub(), handshake = make_handshake_stub(), mac = "00:11:22:33:44:55" | Object is successfully created without errors                                     | Should be successful |
 * | 02               | Repeatedly invoke handle_eapol_frame with a dummy frame to test stability     | frame = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], frame_size = 16, other_mac = value from global variable                         | Each call returns false, indicating safe and stable handling without crashing      | Should Pass      |
 */
TEST(EC1905EncryptLayer, HandleEapolFrame_RepeatedCalls_NoCrash)
{
    std::cout << "Entering HandleEapolFrame_RepeatedCalls_NoCrash" << std::endl;
    auto send_dir   = make_send_dir_stub();
    auto send_eapol = make_send_eapol_stub();
    auto handshake  = make_handshake_stub();
    ec_1905_encrypt_layer_t obj("00:11:22:33:44:55", send_dir, send_eapol, handshake);
    uint8_t frame[16] = {0};
    for (int i = 0; i < 5; i++) {
        bool ret = obj.handle_eapol_frame(frame, sizeof(frame), other_mac);
        EXPECT_FALSE(ret);
    }
    std::cout << "Exiting HandleEapolFrame_RepeatedCalls_NoCrash" << std::endl;
}
/**
 * @brief Verify that ec_1905_encrypt_layer_t destructor does not crash during object cleanup.
 *
 * This test confirms that when an ec_1905_encrypt_layer_t object goes out of scope, its destructor is called safely without causing a crash. The test is important because proper resource cleanup in the destructor ensures system stability.
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
 * | 01 | Invoke helper functions to create stub objects for send_dir, send_eapol, and handshake. | No input values; output: send_dir stub, send_eapol stub, handshake stub returned from make_send_dir_stub(), make_send_eapol_stub(), and make_handshake_stub() respectively. | Valid stub objects are returned. | Should be successful |
 * | 02 | Create an ec_1905_encrypt_layer_t object within a scoped block using the created stubs and a fixed MAC address. | input: MAC = "00:11:22:33:44:55", send_dir = valid stub, send_eapol = valid stub, handshake = valid stub. | Object is constructed successfully. | Should Pass |
 * | 03 | Allow the object to go out of scope, triggering the destructor. | Implicit destruction upon exiting the scope. | The destructor is invoked without causing any crash. | Should Pass |
 * | 04 | Execute SUCCEED() to confirm the test completion status. | No specific input; call to SUCCEED(). | Test is marked as passed. | Should be successful |
 */
TEST(EC1905EncryptLayer, Destructor_NoCrash)
{
    std::cout << "Entering Destructor_NoCrash" << std::endl;
    auto send_dir   = make_send_dir_stub();
    auto send_eapol = make_send_eapol_stub();
    auto handshake  = make_handshake_stub();
    {
        ec_1905_encrypt_layer_t obj("00:11:22:33:44:55", send_dir, send_eapol, handshake);
        std::cout << "Object in scope" << std::endl;
    }
    std::cout << "Exiting Object destroyed safely" << std::endl;
    SUCCEED();
}
/**
 * @brief Verify that the handle_eapol_frame function does not crash and returns the appropriate error result.
 *
 * This test verifies that invoking the handle_eapol_frame API on an ec_1905_encrypt_layer_t instance does not cause a crash and returns false, indicating proper error handling when provided with an eapol frame. The test also checks that the stubbed dependencies and logging execute as expected.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- | -------------- | ----- |
 * | 01 | Create stub objects and an ec_1905_encrypt_layer_t instance | send_dir = make_send_dir_stub(), send_eapol = make_send_eapol_stub(), handshake = make_handshake_stub(), MAC Address = "00:11:22:33:44:55" | Instance is created successfully | Should be successful |
 * | 02 | Initialize eapol frame buffer and call handle_eapol_frame API | frame = 32 bytes (all zeros), length = 32, other_mac = value of other_mac variable | API returns false; no crash occurs | Should Pass |
 * | 03 | Log entry and exit messages to std::cout | "Entering HandleEapolFrame_NoCrash", "Invoking handle_eapol_frame", "Exiting HandleEapolFrame_NoCrash" | Log messages are printed as expected | Should be successful |
 */
TEST(EC1905EncryptLayer, HandleEapolFrame_NoCrash)
{
    std::cout << "Entering HandleEapolFrame_NoCrash" << std::endl;
    auto send_dir   = make_send_dir_stub();
    auto send_eapol = make_send_eapol_stub();
    auto handshake  = make_handshake_stub();
    ec_1905_encrypt_layer_t obj(
        "00:11:22:33:44:55",
        send_dir,
        send_eapol,
        handshake
    );
    uint8_t frame[32] = {0};
    std::cout << "Invoking handle_eapol_frame" << std::endl;
    EXPECT_FALSE(obj.handle_eapol_frame(frame, sizeof(frame), other_mac));
    std::cout << "Exiting HandleEapolFrame_NoCrash" << std::endl;
}
/**
 * @brief Verify that start_secure_1905_layer function does not crash and returns false.
 *
 * This test creates stub functions for sending directory, sending EAPOL, and handshake operations.
 * It instantiates an ec_1905_encrypt_layer_t object with a predefined MAC address and calls start_secure_1905_layer
 * using an undefined "other_mac" parameter to ensure that the API does not crash and returns false as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 024@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create stub functions, instantiate ec_1905_encrypt_layer_t with MAC "00:11:22:33:44:55", and call start_secure_1905_layer with other_mac | macAddress = "00:11:22:33:44:55", send_dir = stub, send_eapol = stub, handshake = stub, other_mac = undefined | API returns false and no crash occurs; EXPECT_FALSE assertion passes | Should Pass |
 */
TEST(EC1905EncryptLayer, StartSecure1905Layer_NoCrash)
{
    std::cout << "Entering StartSecure1905Layer_NoCrash" << std::endl;
    auto send_dir   = make_send_dir_stub();
    auto send_eapol = make_send_eapol_stub();
    auto handshake  = make_handshake_stub();
    ec_1905_encrypt_layer_t obj(
        "00:11:22:33:44:55",
        send_dir,
        send_eapol,
        handshake
    );
    std::cout << "Invoking start_secure_1905_layer" << std::endl;
    EXPECT_FALSE(obj.start_secure_1905_layer(other_mac));
    std::cout << "Exiting StartSecure1905Layer_NoCrash" << std::endl;
}
/**
 * @brief Test to ensure that rekey_1905_layer_ptk does not crash and returns false
 *
 * This test validates that when the ec_1905_encrypt_layer_t object is instantiated with
 * the appropriate MAC address and stub dependencies, invoking the rekey_1905_layer_ptk API with
 * a specified other_mac does not result in a crash and correctly returns false.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 025@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                           | Test Data                                                                                          | Expected Result                                                  | Notes            |
 * | :--------------: | ----------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- | ---------------- |
 * | 01               | Create stub objects (send_dir, send_eapol, handshake) and instantiate ec_1905_encrypt_layer_t object   | MAC address = "00:11:22:33:44:55", send_dir = stub, send_eapol = stub, handshake = stub           | Object is instantiated successfully                              | Should be successful |
 * | 02               | Invoke rekey_1905_layer_ptk with other_mac and validate that the API returns false                      | other_mac = other_mac                                                                              | Returned value is false as verified by EXPECT_FALSE               | Should Pass      |
 */
TEST(EC1905EncryptLayer, Rekey1905LayerPtk_NoCrash)
{
    std::cout << "Entering Rekey1905LayerPtk_NoCrash" << std::endl;
    auto send_dir   = make_send_dir_stub();
    auto send_eapol = make_send_eapol_stub();
    auto handshake  = make_handshake_stub();
    ec_1905_encrypt_layer_t obj(
        "00:11:22:33:44:55",
        send_dir,
        send_eapol,
        handshake
    );
    std::cout << "Invoking rekey_1905_layer_ptk" << std::endl;
    EXPECT_FALSE(obj.rekey_1905_layer_ptk(other_mac));
    std::cout << "Exiting Rekey1905LayerPtk_NoCrash" << std::endl;
}
/**
 * @brief Verify that inserting an object into the container does not crash
 *
 * This test ensures that an ec_1905_encrypt_layer_t object can be successfully created 
 * and stored within a container without causing any crash scenarios. It verifies that the 
 * necessary stubs and the emplace_back operation work correctly as expected.
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
 * | 01 | Create stubs for send_dir, send_eapol, and handshake to be used for object instantiation | send_dir = make_send_dir_stub(), send_eapol = make_send_eapol_stub(), handshake = make_handshake_stub() | Stubs should be created successfully | Should be successful |@n
 * | 02 | Declare an empty vector container for ec_1905_encrypt_layer_t objects | No input parameters; vector<ec_1905_encrypt_layer_t> vec | Container declared as an empty vector | Should be successful |@n
 * | 03 | Insert an ec_1905_encrypt_layer_t object into the vector using emplace_back | Input: MAC = "00:11:22:33:44:55", send_dir, send_eapol, handshake; No explicit output parameter | No exception is thrown as verified by EXPECT_NO_THROW | Should Pass |
 */
TEST(EC1905EncryptLayer, ObjectStoredInContainer_NoCrash)
{
    std::cout << "Entering ObjectStoredInContainer_NoCrash" << std::endl;
    auto send_dir   = make_send_dir_stub();
    auto send_eapol = make_send_eapol_stub();
    auto handshake  = make_handshake_stub();
    std::vector<ec_1905_encrypt_layer_t> vec;
    EXPECT_NO_THROW({
        vec.emplace_back("00:11:22:33:44:55", send_dir, send_eapol, handshake);
    });
    std::cout << "Exiting ObjectStoredInContainer_NoCrash" << std::endl;
}
/**
 * @brief Verify that the ec_1905_encrypt_layer_t constructor successfully creates objects with different valid MAC addresses.
 *
 * This test checks if the constructor of ec_1905_encrypt_layer_t correctly initializes objects when provided with different valid MAC addresses along with valid stubs for send_dir, send_eapol, and handshake. The focus is to ensure that no exception is thrown during the construction process, ensuring correct handling of the input parameters.
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
 * | Variation / Step | Description                                                                                 | Test Data                                                                                               | Expected Result                                  | Notes       |
 * | :--------------: | ------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- | ------------------------------------------------ | ----------- |
 * | 01               | Call API constructor with first valid MAC address along with stubs for send_dir, send_eapol, and handshake. | MAC = "12:34:56:78:9a:bc", send_dir, send_eapol, handshake                                               | Constructor should not throw an exception.       | Should Pass |
 * | 02               | Call API constructor with second valid MAC address along with stubs for send_dir, send_eapol, and handshake. | MAC = "fe:dc:ba:98:76:54", send_dir, send_eapol, handshake                                               | Constructor should not throw an exception.       | Should Pass |
 */
TEST(EC1905EncryptLayer, Constructor_DifferentValidMacs_Constructs)
{
    std::cout << "TEST START: Constructor_DifferentValidMacs_Constructs" << std::endl;
    auto send_dir   = make_send_dir_stub();
    auto send_eapol = make_send_eapol_stub();
    auto handshake  = make_handshake_stub();
    EXPECT_NO_THROW({
        ec_1905_encrypt_layer_t obj1("12:34:56:78:9a:bc", send_dir, send_eapol, handshake);
        ec_1905_encrypt_layer_t obj2("fe:dc:ba:98:76:54", send_dir, send_eapol, handshake);
    });
    std::cout << "TEST END: Constructor_DifferentValidMacs_Constructs" << std::endl;
}
/**
 * @brief Verify that handle_eapol_frame returns false when the source MAC is the same as the device's local MAC.
 *
 * This test sets up stub functions for sending directions, EAPOL messages, and handshake procedures. It then creates an instance of ec_1905_encrypt_layer_t with a predefined MAC ("00:11:22:33:44:55") and prepares a frame of 32 zeros. The test calls handle_eapol_frame with a valid MAC that is identical to the device's MAC and verifies that the function returns false and no network frames are sent.
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
 * | Variation / Step | Description                                                                                           | Test Data                                                                                           | Expected Result                                                                    | Notes       |
 * | :--------------: | ----------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke handle_eapol_frame with self MAC to verify it returns false and no frame is sent                | input: frame = {0,0,...,0} (32 zeros), frame_length = 32, object's MAC = 00:11:22:33:44:55, valid_mac = valid_mac | Function returns false; g_send_dir_called = false; g_send_eapol_called = false       | Should Pass |
 */
TEST(EC1905EncryptLayer, HandleEapolFrame_SelfMac_ReturnsFalse)
{
    std::cout << "Entering HandleEapolFrame_SelfMac_ReturnsFalse" << std::endl;
    auto send_dir   = make_send_dir_stub();
    auto send_eapol = make_send_eapol_stub();
    auto handshake  = make_handshake_stub();
    ec_1905_encrypt_layer_t obj("00:11:22:33:44:55", send_dir, send_eapol, handshake);
    uint8_t frame[32] = {0};
    std::cout << "Calling handle_eapol_frame with self AL MAC" << std::endl;
    bool ret = obj.handle_eapol_frame(frame, sizeof(frame), valid_mac);
    EXPECT_FALSE(ret);
    EXPECT_FALSE(g_send_dir_called);
    EXPECT_FALSE(g_send_eapol_called);
    std::cout << "Exiting HandleEapolFrame_SelfMac_ReturnsFalse" << std::endl;
}
/**
 * @brief Verify that start_secure_1905_layer returns false when self MAC is used
 *
 * This test verifies that invoking start_secure_1905_layer with a MAC address identical to the object's
 * own MAC address does not start the secure layer and returns false. This prevents the scenario where
 * a device inadvertently attempts to secure communication with itself.
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
 * | Variation / Step | Description                                                                           | Test Data                                                                                                                                       | Expected Result                                                              | Notes         |
 * | :--------------: | ------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | ------------- |
 * | 01               | Setup test stubs and create EC1905EncryptLayer object with self MAC address            | send_dir = make_send_dir_stub(), send_eapol = make_send_eapol_stub(), handshake = make_handshake_stub(), instance_mac = "00:11:22:33:44:55" | Object is created successfully without errors                              | Should be successful |
 * | 02               | Call start_secure_1905_layer with a MAC address equal to the object's MAC                | input1 = valid_mac                                                                                                                              | Function returns false                                                       | Should Pass   |
 * | 03               | Validate that send_dir callback was not invoked after the function call                  | g_send_dir_called = false                                                                                                                        | send_dir remains uninvoked (false)                                           | Should Pass   |
 */
TEST(EC1905EncryptLayer, StartSecure1905Layer_SelfMac_ReturnsFalse)
{
    std::cout << "Entering StartSecure1905Layer_SelfMac_ReturnsFalse" << std::endl;
    auto send_dir   = make_send_dir_stub();
    auto send_eapol = make_send_eapol_stub();
    auto handshake  = make_handshake_stub();
    ec_1905_encrypt_layer_t obj("00:11:22:33:44:55", send_dir, send_eapol, handshake);
    std::cout << "Calling start_secure_1905_layer with self MAC" << std::endl;
    bool ret = obj.start_secure_1905_layer(valid_mac);
    EXPECT_FALSE(ret);
    EXPECT_FALSE(g_send_dir_called);
    std::cout << "Exiting StartSecure1905Layer_SelfMac_ReturnsFalse" << std::endl;
}
/**
 * @brief Test that rekey_1905_layer_ptk returns false when invoked with the self MAC address.
 *
 * This test verifies that when the API rekey_1905_layer_ptk is called using the same MAC address as the object's MAC, it properly returns false, indicating that a rekey is not permitted with a self MAC. This behavior is critical to ensure that the encryption layer correctly prevents self rekeying attempts.
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
 * | Variation / Step | Description                                                                                       | Test Data                                                                                | Expected Result                                                       | Notes         |
 * | :--------------: | ------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | ------------- |
 * | 01               | Initialize encryption layer object with MAC "00:11:22:33:44:55" and stub functions              | input1 = mac "00:11:22:33:44:55", input2 = send_dir (stub), input3 = send_eapol (stub), input4 = handshake (stub) | Object instantiated successfully                                      | Should be successful |
 * | 02               | Invoke rekey_1905_layer_ptk function with self MAC address (valid_mac)                               | input1 = valid_mac, output1 = ret                                                           | Returns false and assertion EXPECT_FALSE(ret) passes                  | Should Pass   |
 */
TEST(EC1905EncryptLayer, RekeyPTK_SelfMac_ReturnsFalse)
{
    std::cout << "Entering RekeyPTK_SelfMac_ReturnsFalse" << std::endl;
    auto send_dir   = make_send_dir_stub();
    auto send_eapol = make_send_eapol_stub();
    auto handshake  = make_handshake_stub();
    ec_1905_encrypt_layer_t obj("00:11:22:33:44:55", send_dir, send_eapol, handshake);
    std::cout << "Calling rekey_1905_layer_ptk with self MAC" << std::endl;
    bool ret = obj.rekey_1905_layer_ptk(valid_mac);
    EXPECT_FALSE(ret);
    std::cout << "Exiting RekeyPTK_SelfMac_ReturnsFalse" << std::endl;
}
/**
 * @brief Validate that the secure 1905 layer starts without throwing an exception when provided a valid MAC.
 *
 * This test verifies that creating an instance of ec_1905_encrypt_layer_t with a valid MAC address and valid
 * stubbed dependencies, and then calling start_secure_1905_layer with a valid MAC value (other_mac), does not
 * throw any exceptions. The correct initialization and handling of dependencies are crucial for secure communication.
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
 * | :----: | --------- | ---------- | -------------- | ----- |
 * | 01 | Print entry log message | None | "Entering StartSecure1905Layer_ValidMac_NoThrow" is printed | Should be successful |
 * | 02 | Create stubs, instantiate ec_1905_encrypt_layer_t with valid MAC, and call start_secure_1905_layer with valid parameter | input1 = MAC = "00:11:22:33:44:55", input2 = send_dir stub, input3 = send_eapol stub, input4 = handshake stub, input5 = other_mac | No exception thrown; EXPECT_NO_THROW passes | Should Pass |
 * | 03 | Print exit log message | None | "Exiting StartSecure1905Layer_ValidMac_NoThrow" is printed | Should be successful |
 */
TEST(EC1905EncryptLayer, StartSecure1905Layer_ValidMac_NoThrow)
{
    std::cout << "Entering StartSecure1905Layer_ValidMac_NoThrow" << std::endl;
    auto send_dir   = make_send_dir_stub();
    auto send_eapol = make_send_eapol_stub();
    auto handshake  = make_handshake_stub();
    EXPECT_NO_THROW({
        ec_1905_encrypt_layer_t obj("00:11:22:33:44:55", send_dir, send_eapol, handshake);
        obj.start_secure_1905_layer(other_mac);
    });
    std::cout << "Exiting StartSecure1905Layer_ValidMac_NoThrow" << std::endl;
}
/**
 * @brief Verify that multiple invocations of rekey_1905_layer_gtk do not crash the encryption layer.
 *
 * This test creates an instance of ec_1905_encrypt_layer_t with stub dependencies and repeatedly calls
 * the rekey_1905_layer_gtk API method. It checks that each call consistently returns false, ensuring 
 * that no crash occurs even when the function is invoked multiple times.
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
 * | Variation / Step | Description                                                          | Test Data                                                                                           | Expected Result                                                 | Notes         |
 * | :--------------: | -------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- | ------------- |
 * | 01               | Initialize stub objects and create encryption layer instance         | MAC = "00:11:22:33:44:55", send_dir = make_send_dir_stub(), send_eapol = make_send_eapol_stub(), handshake = make_handshake_stub() | Instance is created successfully                                 | Should be successful |
 * | 02               | Invoke rekey_1905_layer_gtk() repeatedly (three iterations)           | Iteration index = 0, 1, 2; each call: input: none, output: expected return = false                  | Each call returns false as verified by EXPECT_FALSE              | Should Pass   |
 */
TEST(EC1905EncryptLayer, RekeyGTK_RepeatedCalls_NoCrash)
{
    std::cout << "Entering RekeyGTK_RepeatedCalls_NoCrash" << std::endl;
    auto send_dir   = make_send_dir_stub();
    auto send_eapol = make_send_eapol_stub();
    auto handshake  = make_handshake_stub();
    ec_1905_encrypt_layer_t obj("00:11:22:33:44:55", send_dir, send_eapol, handshake);
    for (int i = 0; i < 3; i++) {
        EXPECT_FALSE(obj.rekey_1905_layer_gtk());
    }
    std::cout << "Exiting RekeyGTK_RepeatedCalls_NoCrash" << std::endl;
}
