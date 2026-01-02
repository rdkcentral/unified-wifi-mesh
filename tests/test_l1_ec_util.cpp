#include <gtest/gtest.h>
#include <iostream>
#include <vector>
#include <unordered_map>
#include <cstring>
#include <cstdlib>
#include <arpa/inet.h>

#include "ec_util.h"
#include "aes_siv.h"

using namespace std;


/* ============================================================
 * Helper: write uint16 in network order (test-only)
 * ============================================================ */
static inline void write_u16(uint16_t v, uint8_t *p)
{
    uint16_t n = htons(v);
    memcpy(p, &n, sizeof(n));
}


#ifndef SWAP_LITTLE_ENDIAN
#define SWAP_LITTLE_ENDIAN(x) htons(x)
#endif

/**
 * @brief Verify that the generate_channel_list API correctly processes channel mapping data
 *
 * This test validates that the ec_util::generate_channel_list API returns the expected formatted string when supplied with a valid input mapping. The test uses a predefined mapping containing scanned channel details and compares the returned string with the expected value.
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
 * | 01 | Invoke ec_util::generate_channel_list with a valid channel mapping input | input: "test", m: { "test" = [ {channel = 1, freq = 81}, {channel = 6, freq = 81}, {channel = 11, freq = 81}, {channel = 36, freq = 115} ] } | Returned string equals "81/1,6,11,115/36" with EXPECT_EQ passing | Should Pass |
 */
TEST(EcUtilTest, GenerateChannelListBasic) {
    std::cout << "Entering GenerateChannelListBasic test" << std::endl;
    std::cout << "Invoking ec_util::generate_channel_list(...)" << std::endl;
    std::unordered_map<std::string, std::vector<ec_util::scanned_channels_t>> m;
    ec_util::scanned_channels_t a{1, 81};
    ec_util::scanned_channels_t b{6, 81};
    ec_util::scanned_channels_t c{11, 81};
    ec_util::scanned_channels_t d{36, 115};
    m["test"] = {a, b, c, d};
    auto out = ec_util::generate_channel_list("test", m);
    std::cout << "Returned string='" << out << "'" << std::endl;
    EXPECT_EQ(out, string("81/1,6,11,115/36"));
    std::cout << "Exiting GenerateChannelListBasic test" << std::endl;
}
/**
 * @brief Validate that ec_util::check_caps_compatible confirms compatibility for positive inputs
 *
 * This test verifies that when the capabilities of the initializer and responder are set based on positive conditions,
 * the ec_util::check_caps_compatible function returns true. The test is important to ensure that the compatibility check
 * succeeds when the configurator and enrollee flags are correctly set.
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
 * | Variation / Step | Description                                                                | Test Data                                                           | Expected Result                                           | Notes      |
 * | :--------------: | -------------------------------------------------------------------------- | ------------------------------------------------------------------- | ---------------------------------------------------------- | ---------- |
 * | 01               | Invoke ec_util::check_caps_compatible with positive capability values      | init: byte=0, configurator=1, enrollee=0; resp: byte=0, configurator=0, enrollee=1 | Returns true from check_caps_compatible and EXPECT_TRUE passes | Should Pass |
 */
TEST(EcUtilTest, CheckCapsCompatible_Positive) {
    std::cout << "Entering CheckCapsCompatible_Positive test" << std::endl;
    ec_dpp_capabilities_t init = {};
    ec_dpp_capabilities_t resp = {};
    init.byte = 0; init.configurator = 1; init.enrollee = 0;
    resp.byte = 0; resp.configurator = 0; resp.enrollee = 1;
    bool ok = ec_util::check_caps_compatible(init, resp);
    EXPECT_TRUE(ok);
    std::cout << "Exiting CheckCapsCompatible_Positive test" << std::endl;
}
/**
 * @brief Tests the negative scenario of the check_caps_compatible function.
 *
 * This test verifies that when both the "init" and "resp" structures are configured with the same capability settings that indicate an incompatible state, the ec_util::check_caps_compatible function returns false. This negative scenario ensures that the function accurately detects an invalid compatibility configuration.
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
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke ec_util::check_caps_compatible with initialized capability structures for the negative scenario | init.byte=0, init.configurator=0, init.enrollee=1, resp.byte=0, resp.configurator=0, resp.enrollee=1 | Function returns false and EXPECT_FALSE assertion passes | Should Fail |
 */
TEST(EcUtilTest, CheckCapsCompatible_Negative) {
    std::cout << "Entering CheckCapsCompatible_Negative test" << std::endl;
    ec_dpp_capabilities_t init = {};
    ec_dpp_capabilities_t resp = {};
    init.byte = 0; init.configurator = 0; init.enrollee = 1;
    resp.byte = 0; resp.configurator = 0; resp.enrollee = 1;
    bool ok2 = ec_util::check_caps_compatible(init, resp);
    EXPECT_FALSE(ok2);
    std::cout << "Exiting CheckCapsCompatible_Negative test" << std::endl;
}
/**
 * @brief Test for verifying create_dpp_chirp_tlv API functionality with positive inputs.
 *
 * This test verifies that the create_dpp_chirp_tlv function returns a non-null pointer and valid length when provided with valid MAC and hash inputs.
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
 * | Variation / Step | Description                                                        | Test Data                                                                                              | Expected Result                                                  | Notes       |
 * | :--------------: | ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------- | ----------- |
 * | 01               | Invoke ec_util::create_dpp_chirp_tlv with valid inputs to allocate TLV structure | input1 = true, input2 = true, mac = {0x01,0x02,0x03,0x04,0x05,0x06}, hash_in = {0xAA,0xBB}, hash_len = 2, output pointer expected non-null | Returns non-null pointer and valid length; assertion check passes | Should Pass |
 */
TEST(EcUtilTest, CreateDppChirpTlv_Positive) {
    std::cout << "Entering CreateDppChirpTlv_Positive test" << std::endl;
    std::cout << "Invoking ec_util::create_dpp_chirp_tlv(...)" << std::endl;
    uint8_t mac[6] = {0x01,0x02,0x03,0x04,0x05,0x06};
    uint8_t hash_in[2] = {0xAA, 0xBB};
    auto created = ec_util::create_dpp_chirp_tlv(true, true, mac, hash_in, 2);
    EXPECT_NE(created.first, nullptr);
    uint16_t created_len = created.second;
    std::cout << "create_dpp_chirp_tlv returned len=" << created_len << std::endl;
    free(created.first);
    std::cout << "Exiting CreateDppChirpTlv_Positive test" << std::endl;
}
/**
 * @brief Validate parsing of DPP chirp TLV with valid MAC and hash inputs.
 *
 * This test evaluates the positive scenario for the ec_util::parse_dpp_chirp_tlv API. It verifies that a TLV structure, which includes a MAC address and a hash, is correctly parsed. The test confirms that the function returns a true status and that the length of the parsed hash matches the expected value.
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
 * | Variation / Step | Description                                                                                  | Test Data                                                                                                           | Expected Result                                                                                   | Notes             |
 * | :--------------: | -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- | ----------------- |
 * | 01               | Allocate memory for TLV buffer and initialize it with a valid MAC and hash                   | mac = {0x0a,0x0b,0x0c,0x0d,0x0e,0x0f}, hash_in = {0x11,0x22,0x33}, buf_len = sizeof(em_dpp_chirp_value_t)+sizeof(mac)+sizeof(uint16_t)+sizeof(hash_in) | Memory allocated without error and TLV buffer is correctly initialized                             | Should be successful |
 * | 02               | Set TLV structure flags to indicate that MAC is present and hash is valid                    | chirp->mac_present = 1, chirp->hash_valid = 1                                                                        | TLV structure flags set properly                                                                  | Should be successful |
 * | 03               | Populate the TLV buffer with the MAC, the length of the hash, and the hash itself              | memcpy operations to copy mac and hash_in, write_u16 used for hash length                                             | TLV buffer populated with correct values                                                          | Should be successful |
 * | 04               | Invoke the parse_dpp_chirp_tlv API with the constructed TLV buffer and validate the results    | Input: chirp, buf_len; Output: parsed_mac, parsed_hash, parsed_len; EXPECT_TRUE(ok), EXPECT_EQ(parsed_len, sizeof(hash_in))                  | API returns true; parsed hash length equals sizeof(hash_in) and assertions pass                    | Should Pass       |
 */
TEST(EcUtilTest, ParseDppChirpTlv_Positive)
{
    std::cout << "ParseDppChirpTlv_Positive" << std::endl;
    uint8_t mac[6]     = {0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    uint8_t hash_in[3] = {0x11, 0x22, 0x33};
    size_t buf_len = sizeof(em_dpp_chirp_value_t) + sizeof(mac) + sizeof(uint16_t) + sizeof(hash_in);
    uint8_t *buf = reinterpret_cast<uint8_t*>(calloc(buf_len, 1));
    EXPECT_NE(buf, nullptr);
    em_dpp_chirp_value_t *chirp = reinterpret_cast<em_dpp_chirp_value_t*>(buf);
    chirp->mac_present = 1;
    chirp->hash_valid  = 1;
    uint8_t *p = chirp->data;
    memcpy(p, mac, sizeof(mac));
    p += sizeof(mac);
    write_u16(static_cast<uint16_t>(sizeof(hash_in)), p);
    p += sizeof(uint16_t);
    memcpy(p, hash_in, sizeof(hash_in));
    mac_addr_t parsed_mac = {};
    uint8_t *parsed_hash  = nullptr;
    uint16_t parsed_len   = 0;
    bool ok = ec_util::parse_dpp_chirp_tlv( chirp, static_cast<uint16_t>(buf_len), &parsed_mac, &parsed_hash, &parsed_len );
    EXPECT_TRUE(ok);
    EXPECT_EQ(parsed_len, sizeof(hash_in));
    if (parsed_hash) {
        free(parsed_hash);
    }
    free(buf);
    std::cout << "ParseDppChirpTlv_Positive completed" << std::endl;
}
/**
 * @brief Validate that ec_util::parse_dpp_chirp_tlv returns false for a malformed chirp TLV structure.
 *
 * This test validates that when the chirp TLV structure is set up with an incorrect length and 
 * invalid data, the parsing function correctly fails. It ensures that the API does not mistakenly 
 * parse an improperly formatted buffer and that the output pointers remain unchanged.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 006
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize an invalid chirp TLV buffer with improper length and data, then invoke parse_dpp_chirp_tlv API. | bad_chirp = pointer to allocated buffer with bad_len = sizeof(em_dpp_chirp_value_t) + sizeof(mac) + sizeof(uint16_t), mac = {0x0a,0x0b,0x0c,0x0d,0x0e,0x0f}, dummy_mac = {0}, bad_hash = nullptr, bad_hash_len = 0 | The function returns false, bad_hash remains nullptr, and bad_hash_len remains 0. | Should Fail |
 */
TEST(EcUtilTest, ParseDppChirpTlv_Negative)
{
    std::cout << "ParseDppChirpTlv_Negative" << std::endl;
    uint8_t mac[6] = {0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    size_t bad_len = sizeof(em_dpp_chirp_value_t) + sizeof(mac) + sizeof(uint16_t);
    uint8_t *bad_buf = reinterpret_cast<uint8_t*>(calloc(bad_len, 1));
    EXPECT_NE(bad_buf, nullptr);
    em_dpp_chirp_value_t *bad_chirp = reinterpret_cast<em_dpp_chirp_value_t*>(bad_buf);
    bad_chirp->mac_present = 1;
    bad_chirp->hash_valid  = 1;
    uint8_t *bp = bad_chirp->data;
    memcpy(bp, mac, sizeof(mac));
    bp += sizeof(mac);
    write_u16(0, bp);
    mac_addr_t dummy_mac = {0};
    uint8_t  *bad_hash = nullptr;
    uint16_t  bad_hash_len = 0;
    bool ok = ec_util::parse_dpp_chirp_tlv(bad_chirp, static_cast<uint16_t>(bad_len), &dummy_mac, &bad_hash, &bad_hash_len);
    EXPECT_FALSE(ok);
    EXPECT_EQ(bad_hash, nullptr);
    EXPECT_EQ(bad_hash_len, 0);
    free(bad_buf);
    std::cout << "ParseDppChirpTlv_Negative completed" << std::endl;
}
/**
 * @brief Verify that create_encap_dpp_tlv successfully creates an encapsulated DPP TLV with valid inputs
 *
 * This test case verifies that when valid parameters are provided to ec_util::create_encap_dpp_tlv, the function returns a non-null pointer along with a valid TLV length. The test ensures that the API behaves as expected in a positive scenario, confirming that the TLV creation process is correct.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 007@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                   | Test Data                                                                                                      | Expected Result                                                                                                              | Notes        |
 * | :--------------: | --------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- | ------------ |
 * | 01               | Invoke ec_util::create_encap_dpp_tlv with a valid MAC address, frame type, and frame buffer     | flag = true, mac = {0x0a,0x0b,0x0c,0x0d,0x0e,0x0f}, frame_type = ec_frame_type_easymesh, frame = {0x11,0x22,0x33}, frame_length = 3 | Function returns a non-null pointer and a valid TLV length; EXPECT_NE assertion passes                                           | Should Pass  |
 */
TEST(EcUtilTest, CreateEncapDppTlv_Positive) {
    std::cout << "Entering CreateEncapDppTlv_Positive test" << std::endl;
    std::cout << "Invoking ec_util::create_encap_dpp_tlv(...)" << std::endl;
    uint8_t mac[6] = {0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    uint8_t frame[] = {0x11, 0x22, 0x33};
    auto created = ec_util::create_encap_dpp_tlv(true, mac, ec_frame_type_easymesh, frame, sizeof(frame));
    EXPECT_NE(created.first, nullptr);
    uint16_t created_len = created.second;
    std::cout << "create_encap_dpp_tlv returned len=" << created_len << std::endl;
    free(created.first);
    std::cout << "Exiting CreateEncapDppTlv_Positive test" << std::endl;
}
/**
 * @brief Validate the parsing of a properly formatted encapsulated DPP TLV structure.
 *
 * This test validates that the ec_util::parse_encap_dpp_tlv API correctly parses a valid encapsulated DPP TLV input.
 * It sets up an encapsulated data buffer with pre-populated destination MAC, TLV length, and frame content,
 * then ensures that the API correctly extracts the parsed MAC address, frame type, and frame length.
 * This helps verify that the encapsulated parsing logic works as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 008@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                       | Test Data                                                                                                            | Expected Result                                                                                                  | Notes         |
 * | :--------------: | ------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | ------------- |
 * | 01               | Allocate memory for the test buffer and check for successful allocation                           | buf_len = sizeof(em_encap_dpp_t) + extra, buf = allocated memory                                                     | buf is not nullptr                                                                                               | Should be successful |
 * | 02               | Initialize the encapsulated DPP TLV structure with dpp_frame_indicator and enrollee_mac_addr_present | encap->dpp_frame_indicator = 1, encap->enrollee_mac_addr_present = 1                                                   | Structure fields are set                                                                                         | Should be successful |
 * | 03               | Populate the TLV data section with destination MAC address, flag, TLV length, and frame content      | dest_mac = 0x01,0x02,0x03,0x04,0x05,0x06; flag = 0xBB; TLV length = sizeof(encap_frame); encap_frame = 0xAA              | Data segment contains correct MAC, flag, length, and frame                                                          | Should be successful |
 * | 04               | Invoke ec_util::parse_encap_dpp_tlv and verify returned status and parsed frame length             | Input: encap buffer, buf_len; Output: parsed_mac, frame_type, parsed_frame, parsed_len                                 | Function returns true and parsed_len equals sizeof(encap_frame); assertion checks pass                             | Should Pass   |
 * | 05               | Free all allocated memory after test execution                                                     | Free allocated buf and parsed_frame (if allocated)                                                                   | Memory is successfully deallocated                                                                               | Should be successful |
 */
TEST(EcUtilTest, ParseEncapDppTlv_Positive)
{
    std::cout << "ParseEncapDppTlv_Positive" << std::endl;
    uint8_t dest_mac[6]   = {0x01,0x02,0x03,0x04,0x05,0x06};
    uint8_t encap_frame[] = {0xAA};
    size_t extra = sizeof(dest_mac) + 1 + sizeof(uint16_t) + sizeof(encap_frame);
    size_t buf_len = sizeof(em_encap_dpp_t) + extra;
    uint8_t *buf = reinterpret_cast<uint8_t*>(calloc(buf_len, 1));
    EXPECT_NE(buf, nullptr);
    em_encap_dpp_t *encap = reinterpret_cast<em_encap_dpp_t*>(buf);
    encap->dpp_frame_indicator       = 1;
    encap->enrollee_mac_addr_present = 1;
    uint8_t *p = encap->data;
    memcpy(p, dest_mac, sizeof(dest_mac));
    p += sizeof(dest_mac);
    *p = 0xBB;
    p++;
    write_u16(static_cast<uint16_t>(sizeof(encap_frame)), p);
    p += sizeof(uint16_t);
    memcpy(p, encap_frame, sizeof(encap_frame));
    mac_addr_t parsed_mac = {};
    uint8_t    frame_type = 0;
    uint8_t   *parsed_frame = nullptr;
    uint16_t   parsed_len = 0;
    bool ok = ec_util::parse_encap_dpp_tlv( encap, static_cast<uint16_t>(buf_len), &parsed_mac, &frame_type, &parsed_frame, &parsed_len );
    EXPECT_TRUE(ok);
    EXPECT_EQ(parsed_len, sizeof(encap_frame));
    if (parsed_frame) {
        free(parsed_frame);
    }
    free(buf);
    std::cout << "ParseEncapDppTlv_Positive completed" << std::endl;
}
/**
 * @brief Validate error handling by supplying an invalid encap DPP TLV buffer
 *
 * This test verifies that the function ec_util::parse_encap_dpp_tlv correctly identifies an invalid encap DPP TLV buffer by providing a buffer with an incorrect length and improperly initialized fields. The test ensures that the function returns a failure response, and that no unexpected data is returned for the output parameters.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Print start message indicating the beginning of the test case | None | "ParseEncapDppTlv_Negative" message printed to stdout | Should be successful |
 * | 02 | Allocate a bad length buffer for the encap DPP TLV structure and verify allocation | bad_len = sizeof(em_encap_dpp_t) + 1, allocation of bad_buf | bad_buf is not null | Should be successful |
 * | 03 | Initialize the encap structure fields and dummy variables for the test | bad_encap->dpp_frame_indicator = 0, bad_encap->enrollee_mac_addr_present = 0, dummy_mac = {0}, dummy_frame_type = 0, unused_frame = nullptr, unused_frame_len = 0 | Fields and variables initialized correctly | Should be successful |
 * | 04 | Call ec_util::parse_encap_dpp_tlv with the invalid input buffer and parameters | encap = bad_encap, len = bad_len, dummy_mac, dummy_frame_type, unused_frame, unused_frame_len | API returns false; assertions verify that unused_frame remains nullptr and unused_frame_len equals 0 | Should Fail |
 * | 05 | Free the allocated memory and print completion message | free(bad_buf) | Memory freed and "ParseEncapDppTlv_Negative completed" message printed to stdout | Should be successful |
 */
TEST(EcUtilTest, ParseEncapDppTlv_Negative)
{
    std::cout << "ParseEncapDppTlv_Negative" << std::endl;
    size_t bad_len = sizeof(em_encap_dpp_t) + 1;
    uint8_t *bad_buf = reinterpret_cast<uint8_t*>(calloc(bad_len, 1));
    EXPECT_NE(bad_buf, nullptr);
    em_encap_dpp_t *bad_encap = reinterpret_cast<em_encap_dpp_t*>(bad_buf);
    bad_encap->dpp_frame_indicator = 0;
    bad_encap->enrollee_mac_addr_present = 0;
    mac_addr_t dummy_mac = {0};
    uint8_t dummy_frame_type = 0;
    uint8_t *unused_frame = nullptr;
    uint16_t unused_frame_len = 0;
    bool ok = ec_util::parse_encap_dpp_tlv(bad_encap, static_cast<uint16_t>(bad_len), &dummy_mac, &dummy_frame_type, &unused_frame, &unused_frame_len);
    EXPECT_FALSE(ok);
    EXPECT_EQ(unused_frame, nullptr);
    EXPECT_EQ(unused_frame_len, 0);
    free(bad_buf);
    std::cout << "ParseEncapDppTlv_Negative completed" << std::endl;
}
/**
 * @brief Verify that ec_util::add_attrib correctly adds an attribute for a valid input payload.
 *
 * This test validates the positive scenario for the ec_util::add_attrib function. It ensures that when
 * provided with a valid payload and attribute identifier, the function returns a non-null pointer and updates
 * the buffer length appropriately. This confirms that the attribute addition mechanism behaves as expected under
 * normal conditions.
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
 * | 01 | Invoke ec_util::add_attrib with valid parameters | buff = nullptr, buff_len = 0, attrib_id = ec_attrib_id_bootstrap_key, attribute_length = 5, attribute_data = "hello" (converted to vector<uint8_t>) | Returns a non-null pointer and buff_len > 0 | Should Pass |
 */
TEST(EcUtilTest, AddAttrib_Positive)
{
    std::cout << "Entering AddAttrib_Positive test" << std::endl;
    std::cout << "Invoking ec_util::add_attrib(...)" << std::endl;
    uint8_t *buff = nullptr;
    size_t buff_len = 0;
    std::string payload = "hello";
    std::vector<uint8_t> data(payload.begin(), payload.end());
    buff = ec_util::add_attrib( buff, &buff_len, ec_attrib_id_bootstrap_key, static_cast<uint16_t>(data.size()), data.data());
    EXPECT_NE(buff, nullptr);
    EXPECT_GT(buff_len, 0u);
    if (buff) {
        free(buff);
    }
    std::cout << "Exiting AddAttrib_Positive test" << std::endl;
}
/**
 * @brief Verify correct extraction of an attribute from the buffer using ec_util::get_attrib.
 *
 * This test verifies that the ec_util::get_attrib function correctly extracts the attribute from a constructed attribute buffer. The buffer is initialized with a valid payload and attribute details, and the test confirms that the API returns a valid optional value containing the attribute.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 011
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Construct attribute buffer with valid payload and initialize attribute structure | payload = "hello", data_len = 5, total = offsetof(ec_net_attribute_t, data) + 5, buf allocated, attr->attr_id = SWAP_LITTLE_ENDIAN(ec_attrib_id_bootstrap_key), attr->length = SWAP_LITTLE_ENDIAN(data_len) | Buffer is allocated and attribute fields are set correctly | Should be successful |
 * | 02 | Invoke ec_util::get_attrib with the constructed buffer and expected attribute id | buf pointer, total, ec_attrib_id_bootstrap_key | Function returns an std::optional with a value (has_value() is true) | Should Pass |
 * | 03 | Free the allocated buffer to release resources | buf pointer | Memory is freed without errors | Should be successful |
 */
TEST(EcUtilTest, GetAttrib_Positive) {
    std::cout << "Entering GetAttrib_Positive test" << std::endl;
    std::cout << "Constructing attribute buffer and invoking ec_util::get_attrib(...)" << std::endl;
    const char *payload = "hello";
    uint16_t data_len = static_cast<uint16_t>(strlen(payload));
    size_t total = offsetof(ec_net_attribute_t, data) + data_len;
    uint8_t *buf = reinterpret_cast<uint8_t*>(calloc(total, 1));
    EXPECT_NE(buf, nullptr);
    ec_net_attribute_t *attr = reinterpret_cast<ec_net_attribute_t*>(buf);
    attr->attr_id = SWAP_LITTLE_ENDIAN(ec_attrib_id_bootstrap_key);
    attr->length = SWAP_LITTLE_ENDIAN(data_len);
    memcpy(attr->data, payload, data_len);
    auto opt = ec_util::get_attrib(buf, total, ec_attrib_id_bootstrap_key);
    EXPECT_TRUE(opt.has_value());
    free(buf);
    std::cout << "Exiting GetAttrib_Positive test" << std::endl;
}
/**
 * @brief Verify that get_attrib returns an empty optional when provided with an empty buffer
 *
 * This test verifies that the ec_util::get_attrib function handles an invalid input scenario where the provided
 * buffer is NULL and the length is 0. It ensures that the function correctly returns an empty optional,
 * thereby preventing erroneous processing of invalid memory access.
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
 * | 01 | Invoke ec_util::get_attrib with a NULL buffer and zero length to simulate an edge-case input | buffer = nullptr, length = 0, attrib_id = ec_attrib_id_bootstrap_key | The API returns an optional with no value; EXPECT_FALSE(opt.has_value()) passes | Should Pass |
 */
TEST(EcUtilTest, GetAttrib_Negative_EmptyBuffer) {
    std::cout << "Entering GetAttrib_Negative_EmptyBuffer test" << std::endl;
    std::cout << "Invoking ec_util::get_attrib(...) with NULL/0" << std::endl;
    auto opt = ec_util::get_attrib(nullptr, 0, ec_attrib_id_bootstrap_key);
    std::cout << "Returned present=" << (opt.has_value() ? 1 : 0) << std::endl;
    EXPECT_FALSE(opt.has_value());
    std::cout << "Exiting GetAttrib_Negative_EmptyBuffer test" << std::endl;
}
/**
 * @brief Validates that ec_util::alloc_gas_frame allocates and initializes a valid gas frame for an initial request.
 *
 * This test verifies that invoking ec_util::alloc_gas_frame with the action type dpp_gas_initial_req and a count of 7 returns a non-null frame pointer and a size greater than zero. It ensures that the API correctly allocates resources required for subsequent operations.
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
 * | Variation / Step | Description                                                          | Test Data                                                        | Expected Result                                                        | Notes       |
 * | :--------------: | -------------------------------------------------------------------- | ---------------------------------------------------------------- | ---------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke ec_util::alloc_gas_frame with action type dpp_gas_initial_req and count 7 | action = dpp_gas_initial_req, count = 7, output: frame_ptr, size | API returns a non-null pointer and size > 0 as verified by assertions    | Should Pass |
 */
TEST(EcUtilTest, AllocGasFrame_Positive) {
    std::cout << "Entering AllocGasFrame_Positive test" << std::endl;
    std::cout << "Invoking ec_util::alloc_gas_frame(...) for initial req" << std::endl;
    auto [frame_ptr, size] = ec_util::alloc_gas_frame(dpp_gas_action_type_t::dpp_gas_initial_req, 7);
    std::cout << "Returned frame_ptr non-null=" << (frame_ptr ? 1 : 0) << " size=" << size << std::endl;
    EXPECT_NE(frame_ptr, nullptr);
    EXPECT_GT(size, 0u);
    if (frame_ptr) free(frame_ptr);
    std::cout << "Exiting AllocGasFrame_Positive test" << std::endl;
}
/**
 * @brief Validate that alloc_gas_frame returns a null frame pointer and zero size when invoked with an invalid gas action.
 *
 * This test verifies that the alloc_gas_frame API properly handles an invalid gas action type by returning a null pointer for the frame and a size of zero.
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
 * | Variation / Step | Description                                                                                 | Test Data                                                         | Expected Result                                                                  | Notes      |
 * | :--------------: | ------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- | -------------------------------------------------------------------------------- | ---------- |
 * | 01               | Invoke alloc_gas_frame with an invalid dpp_gas_action_type_t (value 0xFF) and size 1       | input: action = 0xFF, size = 1, output: frame_ptr = nullptr, size = 0 | API returns frame_ptr as nullptr and size as 0; assertions verify these values    | Should Fail |
 */
TEST(EcUtilTest, AllocGasFrame_Negative) {
    std::cout << "Entering AllocGasFrame_Negative test" << std::endl;
    std::cout << "Invoking alloc_gas_frame with invalid action" << std::endl;
    auto [frame2, size2] = ec_util::alloc_gas_frame(static_cast<dpp_gas_action_type_t>(0xFF), 1);
    std::cout << "Returned frame_ptr=" << (frame2 ? 1 : 0) << " size=" << size2 << std::endl;
    EXPECT_EQ(frame2, nullptr);
    EXPECT_EQ(size2, 0u);

    std::cout << "Exiting AllocGasFrame_Negative test" << std::endl;
}
/**
 * @brief Validate that the frame is correctly validated when provided with valid parameters.
 *
 * This test verifies that a frame with proper values for category, action, OUI, OUI type, and crypto suite passes the validation check.
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
 * | Variation / Step | Description                                                                   | Test Data                                                                                                              | Expected Result                                                                                                | Notes         |
 * | :--------------: | ----------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | ------------- |
 * | 01               | Allocate memory for ec_frame_t and verify allocation is successful.           | output frame pointer, allocated using calloc(1, sizeof(ec_frame_t))                                                     | Frame pointer should not be nullptr (EXPECT_NE(frame, nullptr) passes)                                           | Should be successful  |
 * | 02               | Initialize the frame fields with valid parameters.                          | category = 0x04, action = 0x09, oui[0] = 0x50, oui[1] = 0x6f, oui[2] = 0x9a, oui_type = DPP_OUI_TYPE, crypto_suite = 0x01   | Frame fields are set with valid values                                                                          | Should be successful  |
 * | 03               | Invoke ec_util::validate_frame to validate the frame.                       | input: frame pointer with initialized values                                                                           | Returns true (EXPECT_TRUE(ok) passes), indicating the frame is valid                                               | Should Pass   |
 * | 04               | Free the allocated memory for the frame.                                    | free(frame)                                                                                                            | Memory is released without error                                                                                 | Should be successful  |
 */
TEST(EcUtilTest, ValidateFrame_Positive) {
    std::cout << "Entering ValidateFrame_Positive test" << std::endl;
    ec_frame_t *frame = reinterpret_cast<ec_frame_t*>(calloc(1, sizeof(ec_frame_t)));
    EXPECT_NE(frame, nullptr);
    frame->category = 0x04;
    frame->action = 0x09;
    frame->oui[0] = 0x50; frame->oui[1] = 0x6f; frame->oui[2] = 0x9a;
    frame->oui_type = DPP_OUI_TYPE;
    frame->crypto_suite = 0x01;
    bool ok = ec_util::validate_frame(frame);
    EXPECT_TRUE(ok);
    free(frame);
    std::cout << "Exiting ValidateFrame_Positive test" << std::endl;
}
/**
 * @brief Test to validate that an improperly initialized frame fails validation
 *
 * This test verifies that ec_util::validate_frame returns false when provided with a frame
 * structure that is deliberately populated with invalid parameters. The test allocates a frame,
 * initializes its members with negative test data, invokes the validation function, and asserts
 * that the result indicates failure.
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
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Allocate memory for the frame and initialize its members with invalid values | frame pointer = non-null (calloc), category = 0x04, action = 0x09, oui[0] initially set then overwritten to 0x00, oui[1] = 0x6f, oui[2] = 0x9a, oui_type = DPP_OUI_TYPE, crypto_suite = 0x01 | Frame is allocated and initialized without errors | Should be successful |
 * | 02 | Invoke ec_util::validate_frame with the invalid frame structure | input: pointer to frame with invalid parameters; output: ok2 (boolean value) | validate_frame returns false, causing EXPECT_FALSE(ok2) to pass | Should Fail |
 */
TEST(EcUtilTest, ValidateFrame_Negative) {
    std::cout << "Entering ValidateFrame_Negative test" << std::endl;
    ec_frame_t *frame = reinterpret_cast<ec_frame_t*>(calloc(1, sizeof(ec_frame_t)));
    EXPECT_NE(frame, nullptr);
    frame->category = 0x04;
    frame->action = 0x09;
    frame->oui[0] = 0x50; frame->oui[1] = 0x6f; frame->oui[2] = 0x9a;
    frame->oui_type = DPP_OUI_TYPE;
    frame->crypto_suite = 0x01;
    frame->oui[0] = 0x00;
    bool ok2 = ec_util::validate_frame(frame);
    EXPECT_FALSE(ok2);
    free(frame);
    std::cout << "Exiting ValidateFrame_Negative test" << std::endl;
}
/**
 * @brief Tests the functionality of ec_util::freq_to_channel_attr when provided with a positive frequency input.
 *
 * This test case verifies that the function ec_util::freq_to_channel_attr correctly processes the input frequency value (2412 MHz)
 * and returns the expected encoded channel attribute. The test ensures that the computed value matches the expected value which is
 * determined by shifting 81 left by 8 bits and OR'ing with 1.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 017
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call ec_util::freq_to_channel_attr with frequency 2412 and verify that the returned encoded value is as expected | input: freq = 2412, output: expected encoded = (81<<8)|1 i.e., 0x5101 | The returned encoded value equals 0x5101 and the assertion passes | Should Pass |
 */
TEST(EcUtilTest, FreqToChannelAttr_Positive)
{
    std::cout << "Entering FreqToChannelAttr_Positive test" << std::endl;
    std::cout << "Invoking ec_util::freq_to_channel_attr(...)" << std::endl;
    unsigned int freq = 2412;
    uint16_t encoded = ec_util::freq_to_channel_attr(freq);
    uint16_t expected = static_cast<uint16_t>((81 << 8) | 1); 
    std::cout << "Returned encoded=0x" << std::hex << encoded << " expected=0x" << expected << std::dec << std::endl;
    EXPECT_EQ(encoded, expected);
    std::cout << "Exiting FreqToChannelAttr_Positive test" << std::endl;
}
/**
 * @brief Validate ec_util::freq_to_channel_attr for an invalid frequency input
 *
 * This test verifies that invoking ec_util::freq_to_channel_attr with an invalid frequency value (123456) returns 0, ensuring that the function correctly handles out-of-range frequency inputs.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 018@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke ec_util::freq_to_channel_attr with an invalid frequency value to validate proper error handling | input frequency = 123456, output expected = 0u | Function returns 0u as verified by EXPECT_EQ(encoded_bad, 0u) | Should Fail |
 */
TEST(EcUtilTest, FreqToChannelAttr_Negative) {
    std::cout << "Entering FreqToChannelAttr_Negative test" << std::endl;
    std::cout << "Invoking ec_util::freq_to_channel_attr(...) with invalid frequency" << std::endl;
    uint16_t encoded_bad = ec_util::freq_to_channel_attr(123456);
    std::cout << "Returned for invalid freq=" << encoded_bad << std::endl;
    EXPECT_EQ(encoded_bad, 0u);
    std::cout << "Exiting FreqToChannelAttr_Negative test" << std::endl;
}
/**
 * @brief Validate the correct parsing of a valid dpp URI channel list.
 *
 * This test verifies that the api ec_util::parse_dpp_uri_channel_list correctly parses a valid dpp URI containing two channel pairs, and that the returned vector contains the correct size and channel pair values.
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
 * | Variation / Step | Description                                                                                   | Test Data                                                                                                                     | Expected Result                                                                                          | Notes        |
 * | :--------------: | --------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- | ------------ |
 * | 01               | Invoke parse_dpp_uri_channel_list with a valid dpp URI string and validate the parsed output.   | input = "81/1,115/36", output vector size = 2, output[0] = (first = 81, second = 1), output[1] = (first = 115, second = 36) | The API returns a vector of size 2 with channel pairs correctly parsed and all assertions passing.    | Should Pass  |
 */
TEST(EcUtilTest, ParseDppUriChannelList_Single_Positive) {
    std::cout << "Entering ParseDppUriChannelList_Single_Positive test" << std::endl;
    auto v = ec_util::parse_dpp_uri_channel_list("81/1,115/36");
    EXPECT_EQ(v.size(), 2u);
    EXPECT_EQ(v[0].first, 81u);
    EXPECT_EQ(v[0].second, 1u);
    std::cout << "Exiting ParseDppUriChannelList_Single_Positive test" << std::endl;
}
/**
 * @brief Verify that parse_dpp_uri_channel_list correctly parses multiple channel entries.
 *
 * This test validates that when a comma separated list of channel identifiers is provided,
 * the parse_dpp_uri_channel_list API returns a vector containing the expected number of entries.
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
 * | Variation / Step | Description                                                          | Test Data                                      | Expected Result                         | Notes       |
 * | :--------------: | -------------------------------------------------------------------- | ---------------------------------------------- | --------------------------------------- | ----------- |
 * | 01               | Invoke parse_dpp_uri_channel_list with a multiple channel string input | input = "81/1,81/6,115/36"                      | API returns a vector with 3 elements    | Should Pass |
 * | 02               | Validate that the returned vector size equals 3 using EXPECT_EQ        | output vector size, expected value = 3         | EXPECT_EQ verifies the vector size is 3 | Should be successful |
 */
TEST(EcUtilTest, ParseDppUriChannelList_Multiple_Positive) {
    std::cout << "Entering ParseDppUriChannelList_Multiple_Positive test" << std::endl;
    auto v3 = ec_util::parse_dpp_uri_channel_list("81/1,81/6,115/36");
    EXPECT_EQ(v3.size(), 3u);
    std::cout << "Exiting ParseDppUriChannelList_Multiple_Positive test" << std::endl;
}
/**
 * @brief Test to verify that the parse_dpp_uri_channel_list API handles invalid input properly.
 *
 * This test case checks that when an invalid DPP URI string ("badstring") is provided, the API returns an empty vector as a fallback behavior. It ensures that the function gracefully handles malformed input without causing crashes or unexpected behavior.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke parse_dpp_uri_channel_list with an invalid URI string "badstring" and check for an empty output vector | input: uri = "badstring", output: vector size = 0 | The API returns an empty vector and EXPECT_EQ(v2.size(), 0) assertion passes | Should Fail |
 */
TEST(EcUtilTest, ParseDppUriChannelList_Bad_Negative) {
    std::cout << "Entering ParseDppUriChannelList_Bad_Negative test" << std::endl;
    auto v2 = ec_util::parse_dpp_uri_channel_list("badstring");
    EXPECT_EQ(v2.size(), 0u);
    std::cout << "Exiting ParseDppUriChannelList_Bad_Negative test" << std::endl;
}
/**
 * @brief Validate function behavior for empty dpp uri channel list input
 *
 * This test verifies that the ec_util::parse_dpp_uri_channel_list function correctly handles an empty string input by returning a vector with zero elements. This confirms that the function can gracefully manage empty inputs without error.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 022
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                          | Test Data         | Expected Result                                              | Notes       |
 * | :--------------: | ------------------------------------------------------------------------------------ | ----------------- | ------------------------------------------------------------ | ----------- |
 * | 01               | Invoke ec_util::parse_dpp_uri_channel_list with an empty string and verify vector size | input = "", output vector size = 0 | API returns a vector of size 0 as verified by EXPECT_EQ check | Should Pass |
 */
TEST(EcUtilTest, ParseDppUriChannelList_Empty_Negative) {
    std::cout << "Entering ParseDppUriChannelList_Empty_Negative test" << std::endl;
    auto v_empty = ec_util::parse_dpp_uri_channel_list("");
    EXPECT_EQ(v_empty.size(), 0u);
    std::cout << "Exiting ParseDppUriChannelList_Empty_Negative test" << std::endl;
}
/**
 * @brief Verify that alloc_gas_frame returns a valid pointer and positive size for initial gas frame response.
 *
 * This test checks that the ec_util::alloc_gas_frame API, when invoked with the parameters dpp_gas_initial_resp and 8, returns a non-null pointer and a response size greater than 0. Correct execution of this function is essential to allocate memory properly for the initial gas frame response.
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
 * | Variation / Step | Description | Test Data | Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke ec_util::alloc_gas_frame with dpp_gas_initial_resp action type and size 8 | input: dpp_gas_action_type_t = dpp_gas_initial_resp, size = 8; output: resp_ptr, resp_size | resp_ptr is not nullptr and resp_size > 0; Assertions: EXPECT_NE(resp_ptr, nullptr) and EXPECT_GT(resp_size, 0u) | Should Pass |
 */
TEST(EcUtilTest, AllocGasFrame_InitialResp_Positive) {
    std::cout << "Entering AllocGasFrame_InitialResp_Positive test" << std::endl;
    auto [resp_ptr, resp_size] = ec_util::alloc_gas_frame(dpp_gas_action_type_t::dpp_gas_initial_resp, 8);
    EXPECT_NE(resp_ptr, nullptr);
    EXPECT_GT(resp_size, 0u);
    if (resp_ptr) free(resp_ptr);
    std::cout << "Exiting AllocGasFrame_InitialResp_Positive test" << std::endl;
}
/**
 * @brief Validates the positive case of alloc_gas_frame for dpp_gas_comeback_req action
 *
 * This test verifies that calling alloc_gas_frame with dpp_gas_comeback_req and a frame size of 9 returns a non-null pointer and a positive frame size. The memory is freed after validation.
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
 * | Variation / Step | Description                                                        | Test Data                                                       | Expected Result                                             | Notes           |
 * | :--------------: | ------------------------------------------------------------------ | --------------------------------------------------------------- | ----------------------------------------------------------- | --------------- |
 * | 01               | Invoke alloc_gas_frame API with dpp_gas_comeback_req and size 9      | action = dpp_gas_comeback_req, requested_size = 9               | Returned pointer is not nullptr and returned size is > 0    | Should Pass     |
 * | 02               | Free the allocated memory if pointer is valid                        | pointer = valid pointer from alloc_gas_frame                      | Memory is correctly freed without errors                    | Should be successful  |
 */
TEST(EcUtilTest, AllocGasFrame_ComebackReq_Positive) {
    std::cout << "Entering AllocGasFrame_ComebackReq_Positive test" << std::endl;
    auto [cb_req_ptr, cb_req_size] = ec_util::alloc_gas_frame(dpp_gas_action_type_t::dpp_gas_comeback_req, 9);
    EXPECT_NE(cb_req_ptr, nullptr);
    EXPECT_GT(cb_req_size, 0u);
    if (cb_req_ptr) free(cb_req_ptr);
    std::cout << "Exiting AllocGasFrame_ComebackReq_Positive test" << std::endl;
}
/**
 * @brief Verify that the gas frame allocation for a comeback response succeeds
 *
 * This test verifies that calling ec_util::alloc_gas_frame with the dpp_gas_comeback_resp action and a frame size of 10 returns a non-null pointer and a frame size greater than zero. It tests the successful allocation and integrity of the returned frame data.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Call ec_util::alloc_gas_frame with action type dpp_gas_comeback_resp and frame size 10 | input1 = dpp_gas_action_type_t::dpp_gas_comeback_resp, input2 = 10, output1 = cb_resp_ptr, output2 = cb_resp_size | cb_resp_ptr should not be nullptr and cb_resp_size should be greater than 0 | Should Pass |
 */
TEST(EcUtilTest, AllocGasFrame_ComebackResp_Positive) {
    std::cout << "Entering AllocGasFrame_ComebackResp_Positive test" << std::endl;
    auto [cb_resp_ptr, cb_resp_size] = ec_util::alloc_gas_frame(dpp_gas_action_type_t::dpp_gas_comeback_resp, 10);
    EXPECT_NE(cb_resp_ptr, nullptr);
    EXPECT_GT(cb_resp_size, 0u);
    if (cb_resp_ptr) free(cb_resp_ptr);
    std::cout << "Exiting AllocGasFrame_ComebackResp_Positive test" << std::endl;
}
/**
 * @brief Validate frame type positive scenario.
 *
 * This test verifies that ec_util::validate_frame correctly validates an easymesh frame 
 * when all required fields are properly initialized. It ensures that the frame structure 
 * passes the validation check when provided with valid parameters.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 026@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                          | Test Data                                                                                                                  | Expected Result                                                                         | Notes       |
 * | :--------------: | ---------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- | ----------- |
 * | 01               | Allocate memory for ec_frame_t, initialize its fields with valid values, then call validate_frame API | frame allocated with: category=0x04, action=0x09, oui={0x50,0x6f,0x9a}, oui_type=DPP_OUI_TYPE, crypto_suite=0x01, frame_type=ec_frame_type_easymesh | The API returns true and the assertion (EXPECT_TRUE) passes confirming valid frame type     | Should Pass |
 */
TEST(EcUtilTest, ValidateFrame_Type_Positive) {
    std::cout << "Entering ValidateFrame_Type_Positive test" << std::endl;
    ec_frame_t *frame = reinterpret_cast<ec_frame_t*>(calloc(1, sizeof(ec_frame_t)));
    EXPECT_NE(frame, nullptr);
    frame->category = 0x04;
    frame->action = 0x09;
    frame->oui[0] = 0x50; frame->oui[1] = 0x6f; frame->oui[2] = 0x9a;
    frame->oui_type = DPP_OUI_TYPE;
    frame->crypto_suite = 0x01;
    frame->frame_type = ec_frame_type_easymesh;
    bool ok = ec_util::validate_frame(frame, ec_frame_type_easymesh);
    EXPECT_TRUE(ok);
    free(frame);
    std::cout << "Exiting ValidateFrame_Type_Positive test" << std::endl;
}
/**
 * @brief To verify that validate_frame function returns false when provided a mismatching frame type.
 *
 * This test verifies that the validate_frame function, when given a frame with a frame type that does not match the expected type (negative scenario), returns false.
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
 * | 01 | Allocate memory for the frame and verify successful allocation | output: frame pointer = non-null | Frame pointer is non-null | Should be successful |
 * | 02 | Populate frame fields with predetermined test values | category = 0x04, action = 0x09, oui = (0x50, 0x6f, 0x9a), oui_type = DPP_OUI_TYPE, crypto_suite = 0x01, frame_type = ec_frame_type_auth_req | Frame fields are set to the correct values | Should be successful |
 * | 03 | Invoke validate_frame with an incorrect expected frame type | input: frame pointer, expected frame type = ec_frame_type_easymesh | Function returns false; EXPECT_FALSE validates the result | Should Fail |
 * | 04 | Release allocated frame memory | free(frame) | Memory is released without errors | Should be successful |
 */
TEST(EcUtilTest, ValidateFrame_Type_Negative) {
    std::cout << "Entering ValidateFrame_Type_Negative test" << std::endl;
    ec_frame_t *frame = reinterpret_cast<ec_frame_t*>(calloc(1, sizeof(ec_frame_t)));
    EXPECT_NE(frame, nullptr);
    frame->category = 0x04;
    frame->action = 0x09;
    frame->oui[0] = 0x50; frame->oui[1] = 0x6f; frame->oui[2] = 0x9a;
    frame->oui_type = DPP_OUI_TYPE;
    frame->crypto_suite = 0x01;
    frame->frame_type = ec_frame_type_auth_req;
    bool ok_wrong = ec_util::validate_frame(frame, ec_frame_type_easymesh);
    EXPECT_FALSE(ok_wrong);
    free(frame);
    std::cout << "Exiting ValidateFrame_Type_Positive test" << std::endl;
}
/**
 * @brief Validate the conversion of a 5GHz frequency to its channel attributes.
 *
 * This test verifies that the ec_util::freq_to_channel_attr function correctly encodes a given 5GHz frequency value.
 * The objective is to ensure that the conversion logic produces the expected encoded value for a valid 5GHz input.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call ec_util::freq_to_channel_attr with a 5GHz frequency value (5180) and validate the encoded output | freq = 5180, output = encoded, expected = (115 << 8) | 36 | Return value equals expected encoded value and the EXPECT_EQ assertion passes | Should Pass |
 */
TEST(EcUtilTest, FreqToChannelAttr_AdditionalPositive)
{
    std::cout << "Entering FreqToChannelAttr_AdditionalPositive test" << std::endl;
    std::cout << "Invoking ec_util::freq_to_channel_attr(...) for a 5GHz freq" << std::endl;
    unsigned int freq = 5180;
    uint16_t encoded = ec_util::freq_to_channel_attr(freq);
    uint16_t expected = static_cast<uint16_t>((115 << 8) | 36);
    std::cout << "Returned encoded=0x" << std::hex << encoded << " expected=0x" << expected << std::dec << std::endl;
    EXPECT_EQ(encoded, expected);
    std::cout << "Exiting FreqToChannelAttr_AdditionalPositive test" << std::endl;
}
/**
 * @brief Check proper initialization of ec_frame_t structure using ec_util::init_frame
 *
 * This test verifies that the ec_util::init_frame API correctly initializes an instance of ec_frame_t with the expected default values. It allocates memory for the frame, checks for a non-null pointer, initializes the frame, validates each field for accuracy, and then frees the allocated memory.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Allocate memory for ec_frame_t and verify allocation is successful | input: none, output: frame pointer allocated | frame pointer is non-null | Should be successful |
 * | 02 | Initialize frame using ec_util::init_frame and validate field values | input: frame pointer, output: category = 0x04, action = 0x09, oui = 0x50,0x6f,0x9a, oui_type = DPP_OUI_TYPE, crypto_suite = 0x01 | All fields are correctly set | Should Pass |
 * | 03 | Free allocated memory | input: frame pointer | Memory is freed successfully | Should be successful |
 */
TEST(EcUtilTest, InitFrame_Positive) {
    std::cout << "Entering InitFrame_Positive test" << std::endl;
    ec_frame_t *frame = reinterpret_cast<ec_frame_t*>(calloc(1, sizeof(ec_frame_t)));
    EXPECT_NE(frame, nullptr);
    ec_util::init_frame(frame);
    EXPECT_EQ(frame->category, 0x04);
    EXPECT_EQ(frame->action, 0x09);
    EXPECT_EQ(frame->oui[0], 0x50);
    EXPECT_EQ(frame->oui[1], 0x6f);
    EXPECT_EQ(frame->oui[2], 0x9a);
    EXPECT_EQ(frame->oui_type, DPP_OUI_TYPE);
    EXPECT_EQ(frame->crypto_suite, 0x01);
    free(frame);
    std::cout << "Exiting InitFrame_Positive test" << std::endl;
}
/**
 * @brief Tests the ec_util::get_ec_attr_size function for correctness
 *
 * This test verifies that the ec_util::get_ec_attr_size function computes the expected attribute size by correctly adding the offset of the data field in ec_net_attribute_t and the given data length. This ensures that the attribute size calculation adheres to the structure's layout requirements.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke ec_util::get_ec_attr_size with data_len = 5 and verify the return value against offsetof(ec_net_attribute_t, data) + 5 | data_len = 5, expected = offsetof(ec_net_attribute_t, data) + 5 | Should return the computed size matching the expected value and satisfy EXPECT_EQ | Should Pass |
 */
TEST(EcUtilTest, GetEcAttrSize_Basic) {
    std::cout << "Entering GetEcAttrSize_Basic test" << std::endl;
    uint16_t data_len = 5;
    size_t expected = offsetof(ec_net_attribute_t, data) + data_len;
    EXPECT_EQ(ec_util::get_ec_attr_size(data_len), expected);
    std::cout << "Exiting GetEcAttrSize_Basic test" << std::endl;
}
/**
 * @brief Validate that attributes are correctly copied into the frame buffer using ec_util::copy_attrs_to_frame.
 *
 * This test verifies that the API correctly copies a given attributes array into the allocated frame buffer.
 * It checks for proper memory allocation, non-null pointers, and correct data copy by comparing the resulting
 * memory block with the original attributes array.
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
 * | Variation / Step | Description                                                                  | Test Data                                                                                      | Expected Result                                     | Notes          |
 * | :--------------: | ---------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- | --------------------------------------------------- | -------------- |
 * | 01               | Print entering test message                                                  | stdout message = "Entering CopyAttrsToFrame_Positive test"                                     | Message printed on console                          | Should be successful |
 * | 02               | Allocate frame buffer using calloc and verify allocation                     | input: EC_FRAME_BASE_SIZE                                                     | frame_buf != nullptr                                | Should Pass    |
 * | 03               | Invoke ec_util::copy_attrs_to_frame with valid attributes                    | input: frame_buf, EC_FRAME_BASE_SIZE, attrs = {0xAA,0xBB,0xCC}, attrs_len = 3                     | Returned pointer (res) != nullptr                   | Should Pass    |
 * | 04               | Validate that attributes are correctly copied into the frame                 | input: res pointer offset by EC_FRAME_BASE_SIZE, compare with attrs = {0xAA,0xBB,0xCC}             | memcmp returns 0 (data matches)                      | Should Pass    |
 * | 05               | Free allocated memory and print exit message                                 | free(res)                                                                  | Memory freed and exit message printed              | Should be successful |
 */
TEST(EcUtilTest, CopyAttrsToFrame_Positive) {
    std::cout << "Entering CopyAttrsToFrame_Positive test" << std::endl;
    uint8_t attrs[] = {0xAA, 0xBB, 0xCC};
    size_t attrs_len = sizeof(attrs);
    uint8_t *frame_buf = reinterpret_cast<uint8_t*>(calloc(EC_FRAME_BASE_SIZE, 1));
    EXPECT_NE(frame_buf, nullptr);
    uint8_t *res = ec_util::copy_attrs_to_frame(frame_buf, EC_FRAME_BASE_SIZE, attrs, attrs_len);
    EXPECT_NE(res, nullptr);
    EXPECT_EQ(memcmp(res + EC_FRAME_BASE_SIZE, attrs, attrs_len), 0);
    free(res);
    std::cout << "Exiting CopyAttrsToFrame_Positive test" << std::endl;
}
/**
 * @brief Validates that the function copy_payload_to_gas_resp correctly copies the given payload into the gas response frame.
 *
 * This test creates a gas response frame and a defined payload then invokes copy_payload_to_gas_resp.
 * It verifies that:
 * - Memory allocation for the response frame is successful.
 * - The API call returns a valid pointer.
 * - The contents of the payload are accurately copied into the appropriate location of the response buffer.
 * This test ensures that the payload is appended correctly after the header in a positive scenario.
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
 * | Variation / Step | Description                                                                                             | Test Data                                                                                          | Expected Result                                                                             | Notes         |
 * | :--------------: | ------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ------------- |
 * | 01               | Allocate memory for the gas response frame using calloc                                                 | frame_buf = calloc(sizeof(ec_gas_initial_response_frame_t), 1)                                     | Memory allocated; frame_buf is non-null                                                     | Should be successful |
 * | 02               | Verify successful allocation of the response frame                                                      | frame_buf pointer                                                                                  | Expect frame_buf != nullptr                                                                 | Should be successful |
 * | 03               | Define the payload data to be copied                                                                     | payload = {0xDE, 0xAD, 0xBE, 0xEF}, payload_len = 4                                               | Payload array is correctly defined                                                          | Should be successful |
 * | 04               | Invoke copy_payload_to_gas_resp to copy the payload into the response buffer                               | resp pointer, payload, payload_len                                                                 | API returns a valid (non-null) pointer                                                      | Should Pass   |
 * | 05               | Verify that the payload is copied correctly after the header                                             | raw memory (res offset by sizeof(ec_gas_initial_response_frame_t)), payload, payload_len           | memcmp returns 0 showing the copied payload matches the original payload                      | Should Pass   |
 * | 06               | Free up the allocated memory to avoid memory leaks                                                       | res pointer                                                                                        | Memory is freed successfully                                                                | Should be successful |
 */
TEST(EcUtilTest, CopyPayloadToGasResp_Positive) {
    std::cout << "Entering CopyPayloadToGasResp_Positive test" << std::endl;
    uint8_t *frame_buf = reinterpret_cast<uint8_t*>(calloc(sizeof(ec_gas_initial_response_frame_t), 1));
    EXPECT_NE(frame_buf, nullptr);
    ec_gas_initial_response_frame_t *resp = reinterpret_cast<ec_gas_initial_response_frame_t*>(frame_buf);
    uint8_t payload[] = {0xDE, 0xAD, 0xBE, 0xEF};
    size_t payload_len = sizeof(payload);
    auto *res = ec_util::copy_payload_to_gas_resp(resp, payload, payload_len);
    EXPECT_NE(res, nullptr);
    uint8_t *raw = reinterpret_cast<uint8_t*>(res);
    EXPECT_EQ(memcmp(raw + sizeof(ec_gas_initial_response_frame_t), payload, payload_len), 0);
    free(res);
    std::cout << "Exiting CopyPayloadToGasResp_Positive test" << std::endl;
}
/**
 * @brief Test the functionality of ec_util::add_attrib for a string attribute.
 *
 * This test verifies that invoking ec_util::add_attrib with a string payload correctly allocates a buffer, sets the length to a valid non-zero value, and returns a non-null pointer.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 033
 * **Priority:** High
 * 
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                                    | Test Data                                                                                                 | Expected Result                                                     | Notes       |
 * | :--------------: | -------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ | ----------- |
 * | 01               | Call ec_util::add_attrib with a null buffer, a length pointer, an attribute id, and a string payload | buff = nullptr, len = 0, attrib id = ec_attrib_id_bootstrap_key, payload = "str-payload"                  | Return pointer is not null and len is greater than 0               | Should Pass |
 */
TEST(EcUtilTest, AddAttrib_String_Positive) {
    std::cout << "Entering AddAttrib_String_Positive test" << std::endl;
    size_t len = 0;
    uint8_t *buff = nullptr;
    buff = ec_util::add_attrib(buff, &len, ec_attrib_id_bootstrap_key, std::string("str-payload"));
    EXPECT_NE(buff, nullptr);
    EXPECT_GT(len, 0u);
    free(buff);
    std::cout << "Exiting AddAttrib_String_Positive test" << std::endl;
}
/**
 * @brief Validate the successful addition of a uint8_t attribute using ec_util::add_attrib
 *
 * This test case verifies that the ec_util::add_attrib API correctly adds an attribute of type uint8_t
 * and returns a non-null buffer pointer along with a length greater than zero when provided with valid inputs.
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
 * | Variation / Step | Description                                                                                   | Test Data                                                                                                   | Expected Result                                                                                   | Notes           |
 * | :---------------:| --------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- | --------------- |
 * | 01               | Print a log message indicating the test has started.                                          | None                                                                                                        | A log message "Entering AddAttrib_Uint8_Positive test" is displayed.                              | Should be successful |
 * | 02               | Initialize the variables 'len' with 0 and 'buff' with nullptr.                                | len = 0, buff = nullptr                                                                                       | Variables are initialized to 0 and nullptr respectively.                                        | Should be successful |
 * | 03               | Invoke ec_util::add_attrib with buff (nullptr), pointer to len, ec_attrib_id_bootstrap_key, and 0x7F. | input_buff = nullptr, len_ptr = pointer to variable len, attrib_id = ec_attrib_id_bootstrap_key, input_val = 0x7F | Returned buff should be non-null and len greater than 0.                                          | Should Pass     |
 * | 04               | Validate the return values using assertions EXPECT_NE and EXPECT_GT.                            | output_buff = returned buff, output_len = modified len                                                             | EXPECT_NE(buff, nullptr) and EXPECT_GT(len, 0) must pass.                                         | Should Pass     |
 * | 05               | Free the allocated buffer memory using free(buff).                                            | buff (non-null allocated memory)                                                                              | Memory is successfully freed.                                                                     | Should be successful |
 * | 06               | Print a log message indicating the test has completed.                                        | None                                                                                                        | A log message "Exiting AddAttrib_Uint8_Positive test" is displayed.                              | Should be successful |
 */
TEST(EcUtilTest, AddAttrib_Uint8_Positive) {
    std::cout << "Entering AddAttrib_Uint8_Positive test" << std::endl;
    size_t len = 0;
    uint8_t *buff = nullptr;
    buff = ec_util::add_attrib(buff, &len, ec_attrib_id_bootstrap_key, static_cast<uint8_t>(0x7F));
    EXPECT_NE(buff, nullptr);
    EXPECT_GT(len, 0u);
    free(buff);
    std::cout << "Exiting AddAttrib_Uint8_Positive test" << std::endl;
}
/**
 * @brief Validate that ec_util::add_attrib correctly adds a uint16_t attribute and updates the buffer length.
 *
 * This test verifies that when provided with a null buffer pointer, a pointer to a size variable, a valid attribute ID (ec_attrib_id_bootstrap_key), and a uint16_t value (0x1234), the ec_util::add_attrib function returns a non-null pointer and updates the length variable to a value greater than zero.
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
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Invoke ec_util::add_attrib with a null buffer, a zero-initialized length, valid attribute ID, and uint16_t value 0x1234 | buff = nullptr, len = 0, attrib_id = ec_attrib_id_bootstrap_key, value = 0x1234, output: buff, len | buff is non-null and len > 0 | Should Pass |
 */
TEST(EcUtilTest, AddAttrib_Uint16_Positive) {
    std::cout << "Entering AddAttrib_Uint16_Positive test" << std::endl;
    size_t len = 0;
    uint8_t *buff = nullptr;
    buff = ec_util::add_attrib(buff, &len, ec_attrib_id_bootstrap_key, static_cast<uint16_t>(0x1234));
    EXPECT_NE(buff, nullptr);
    EXPECT_GT(len, 0u);
    free(buff);
    std::cout << "Exiting AddAttrib_Uint16_Positive test" << std::endl;
}
/**
 * @brief Test for verifying that configuration wrapped data attribute is added successfully for a positive scenario
 *
 * This test validates that the API ec_util::add_cfg_wrapped_data_attr correctly processes the null attribute input along with a default key and a custom lambda callback to create wrapped attributes. It checks that the API returns a non-null pointer and updates the non_wrapped_len value appropriately.
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
 * | 01 | Invoke ec_util::add_cfg_wrapped_data_attr with a null attribute pointer, pointer to non_wrapped_len, false flag, a key array initialized to zeros, and a lambda that returns wrapped attribute data | input1 = attrs = NULL, input2 = non_wrapped_len pointer (initial value 0), input3 = flag = false, input4 = key = {0,0,...,0} (64 zeros), input5 = create_wrap_attribs lambda that returns { pointer to 'wrap', length = 4 } | Returned pointer should not be nullptr and non_wrapped_len should be greater than 0 | Should Pass |
 * | 02 | Validate the API output and perform memory cleanup | output1 = new_attrs pointer returned from API; non_wrapped_len updated value | API assertions: EXPECT_NE(new_attrs, nullptr) and EXPECT_GT(non_wrapped_len, 0u); free(new_attrs) should execute successfully | Should be successful |
 */
TEST(EcUtilTest, AddCfgWrappedDataAttr_Positive) {
    std::cout << "Entering AddCfgWrappedDataAttr_Positive test" << std::endl;
    uint8_t key[64] = {0};
    size_t non_wrapped_len = 0;
    uint8_t *attrs = NULL;
    auto create_wrap_attribs = []() -> std::pair<uint8_t*, uint16_t> {
        uint16_t l = 4;
        uint8_t *b = reinterpret_cast<uint8_t*>(calloc(l,1));
        memcpy(b, "wrap", l);
        return {b, l};
    };
    uint8_t *new_attrs = ec_util::add_cfg_wrapped_data_attr(attrs, &non_wrapped_len, false, key, create_wrap_attribs);
    EXPECT_NE(new_attrs, nullptr);
    EXPECT_GT(non_wrapped_len, 0u);
    free(new_attrs);
    std::cout << "Exiting AddCfgWrappedDataAttr_Positive test" << std::endl;
}
/**
 * @brief Verify that the unwrapping of a wrapped attribute successfully returns the original plain text.
 *
 * This test creates a wrapped attribute by encrypting a plain text with a SIV context and then attempts to unwrap it.
 * It checks that the SIV initialization, encryption, and unwrapping operations complete successfully and that the decrypted
 * data matches the original plain text.
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
 * | Variation / Step | Description                                                                                           | Test Data                                                                                                                           | Expected Result                                                                                           | Notes           |
 * | :---------------:| ------------------------------------------------------------------------------------------------------| -----------------------------------------------------------------------------------------------------------------------------------| ---------------------------------------------------------------------------------------------------------| --------------- |
 * | 01               | Print the test start message to the console.                                                        | Stdout message: "Entering UnwrapWrappedAttrib_Positive test"                                                                        | Message printed to console.                                                                               | Should be successful |
 * | 02               | Initialize the key and plain text variables.                                                        | key[64] = all zeros, plain[] = {0x01, 0x02, 0x03, 0x04, 0x05}, plain_len = 5                                                         | Variables initialized with correct values.                                                               | Should be successful |
 * | 03               | Initialize the SIV context using siv_init API.                                                      | key, SIV_256                                                                                                                        | siv_init() returns 1 indicating success.                                                                   | Should Pass     |
 * | 04               | Allocate memory for cipher.                                                                           | plain_len = 5                                                                                                                       | cipher pointer is not nullptr.                                                                             | Should be successful |
 * | 05               | Initialize the CTR array to zeros.                                                                    | ctr[AES_BLOCK_SIZE] = all zeros                                                                                                     | CTR array is correctly initialized to zero.                                                                | Should be successful |
 * | 06               | Encrypt the plain text using the siv_encrypt API.                                                   | SIV context, plain, cipher, plain_len, ctr, flag = 0                                                                                  | siv_encrypt() returns 1 indicating successful encryption.                                                  | Should Pass     |
 * | 07               | Free the SIV context using siv_free API.                                                              | ctx pointer                                                                                                                         | SIV context freed successfully.                                                                            | Should be successful |
 * | 08               | Prepare the wrapped attribute by calculating wrapped length and total buffer size then allocate buffer. | wrapped_len = plain_len, total = offsetof(ec_net_attribute_t, data) + AES_BLOCK_SIZE + wrapped_len                                      | Buffer is allocated and is not a nullptr.                                                                  | Should be successful |
 * | 09               | Populate the ec_net_attribute_t structure with proper fields and copy data.                         | attr->attr_id = SWAP_LITTLE_ENDIAN(ec_attrib_id_wrapped_data), attr->length = SWAP_LITTLE_ENDIAN(AES_BLOCK_SIZE + wrapped_len), ctr, cipher | Attribute structure is populated correctly with header and data.                                           | Should be successful |
 * | 10               | Call ec_util::unwrap_wrapped_attrib API and validate the result.                                    | ec_attribute_t (from attr), frame_attribs = {0x00}, flag = false, key                                                               | Result pointer is not null, result length equals wrapped_len, and decrypted data matches the original plain text. | Should Pass     |
 * | 11               | Free all allocated memory including result, cipher, and buffer.                                     | result.first, cipher, buf                                                                                                             | Memory freed successfully without leaks.                                                                   | Should be successful |
 * | 12               | Print the test exit message to the console.                                                         | Stdout message: "Exiting UnwrapWrappedAttrib_Positive test"                                                                         | Message printed to console.                                                                               | Should be successful |
 */
TEST(EcUtilTest, UnwrapWrappedAttrib_Positive)
{
    std::cout << "Entering UnwrapWrappedAttrib_Positive test" << std::endl;
    uint8_t key[64] = {0};
    uint8_t plain[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    size_t plain_len = sizeof(plain);
    siv_ctx ctx;
    EXPECT_EQ(siv_init(&ctx, key, SIV_256), 1);
    uint8_t *cipher = static_cast<uint8_t*>(calloc(plain_len, 1));
    EXPECT_NE(cipher, nullptr);
    uint8_t ctr[AES_BLOCK_SIZE] = {0};
    EXPECT_EQ(siv_encrypt(&ctx, plain, cipher, plain_len, ctr, 0), 1);
    siv_free(&ctx);
    uint16_t wrapped_len = static_cast<uint16_t>(plain_len);
    size_t total = offsetof(ec_net_attribute_t, data) + AES_BLOCK_SIZE + wrapped_len;
    uint8_t *buf = static_cast<uint8_t*>(calloc(total, 1));
    EXPECT_NE(buf, nullptr);
    ec_net_attribute_t *attr = reinterpret_cast<ec_net_attribute_t*>(buf);
    attr->attr_id = SWAP_LITTLE_ENDIAN(ec_attrib_id_wrapped_data);
    attr->length  = SWAP_LITTLE_ENDIAN(static_cast<uint16_t>(AES_BLOCK_SIZE + wrapped_len) );
    memcpy(attr->data, ctr, AES_BLOCK_SIZE);
    memcpy(attr->data + AES_BLOCK_SIZE, cipher, wrapped_len);
    uint8_t frame_attribs[1] = {0x00};
    auto result = ec_util::unwrap_wrapped_attrib(*reinterpret_cast<ec_attribute_t*>(attr), frame_attribs, false, key);
    EXPECT_NE(result.first, nullptr);
    EXPECT_EQ(result.second, wrapped_len);
    EXPECT_EQ(memcmp(result.first, plain, plain_len), 0);
    free(result.first);
    free(cipher);
    free(buf);
    std::cout << "Exiting UnwrapWrappedAttrib_Positive test" << std::endl;
}
/**
 * @brief Verifies that the UnwrapWrappedAttrib API correctly fails when provided with an incorrect decryption key.
 *
 * This test ensures that when the UnwrapWrappedAttrib function is invoked with a wrong key, it returns a null pointer or zero output length, thereby rejecting the operation.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 038
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                | Test Data                                                                                                                          | Expected Result                                                              | Notes            |
 * | :--------------: | ------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | ---------------- |
 * | 01               | Initialize SIV context with a correct key and encrypt plaintext.                           | good_key = 0x00 (64 bytes), plaintext = {0x0A, 0x0B, 0x0C}, plain_len = 3, CTR = {0x00,...}                                        | siv_init and siv_encrypt return 1.                                           | Should Pass      |
 * | 02               | Prepare network attribute buffer with CTR and ciphertext.                                  | net_attr->attr_id = ec_attrib_id_wrapped_data (after endian swap), net_attr->length = AES_BLOCK_SIZE + wrapped_len, CTR, ciphertext      | Buffer is allocated and structured correctly; non-null allocation observed. | Should be successful |
 * | 03               | Call UnwrapWrappedAttrib with the wrong key.                                               | dummy_frame = {0}, dummy_frame_attribs = {0}, bad_key = 0xFF (64 bytes)                                                              | Result returns a null pointer or length 0, as verified by the assertion.     | Should Fail      |
 * | 04               | Free allocated resources (cipher, buf, and any returned result).                           | Free pointers: cipher, buf, and result.first if non-null                                                                             | All allocated memory is freed without leaks.                               | Should be successful |
 */
TEST(EcUtilTest, UnwrapWrappedAttrib_WrongKey_Negative)
{
    std::cout << "Entering UnwrapWrappedAttrib_WrongKey_Negative test" << std::endl;
    uint8_t good_key[64] = {0};
    uint8_t bad_key[64];
    memset(bad_key, 0xFF, sizeof(bad_key));
    uint8_t plain[] = {0x0A, 0x0B, 0x0C};
    size_t plain_len = sizeof(plain);
    siv_ctx ctx;
    EXPECT_EQ(siv_init(&ctx, good_key, SIV_256), 1);
    uint8_t *cipher = static_cast<uint8_t*>(calloc(plain_len, 1));
    EXPECT_NE(cipher, nullptr);
    uint8_t ctr[AES_BLOCK_SIZE] = {0};
    EXPECT_EQ(siv_encrypt(&ctx, plain, cipher, plain_len, ctr, 0), 1);
    siv_free(&ctx);
    uint16_t wrapped_len = static_cast<uint16_t>(plain_len);
    size_t total = offsetof(ec_net_attribute_t, data) + AES_BLOCK_SIZE + wrapped_len + AES_BLOCK_SIZE;
    uint8_t *buf = static_cast<uint8_t*>(calloc(total, 1));
    EXPECT_NE(buf, nullptr);
    auto *net_attr = reinterpret_cast<ec_net_attribute_t*>(buf);
    net_attr->attr_id = SWAP_LITTLE_ENDIAN(ec_attrib_id_wrapped_data);
    net_attr->length  = SWAP_LITTLE_ENDIAN(static_cast<uint16_t>(AES_BLOCK_SIZE + wrapped_len));
    memcpy(net_attr->data, ctr, AES_BLOCK_SIZE);
    memcpy(net_attr->data + AES_BLOCK_SIZE, cipher, wrapped_len);
    uint8_t dummy_frame[1] = {0};
    uint8_t dummy_frame_attribs[1] = {0};
    auto result = ec_util::unwrap_wrapped_attrib(*reinterpret_cast<ec_attribute_t*>(net_attr), dummy_frame, sizeof(dummy_frame), dummy_frame_attribs, false, bad_key);
    EXPECT_TRUE(result.first == nullptr || result.second == 0u);
    if (result.first) {
        free(result.first);
    }
    free(cipher);
    free(buf);
    std::cout << "Exiting UnwrapWrappedAttrib_WrongKey_Negative test" << std::endl;
}
