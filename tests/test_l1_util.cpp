// Unit tests for util functions
#include <gtest/gtest.h>
#include <iostream>
#include <vector>
#include <arpa/inet.h>
#include <cstring>
#include <cstdio>
#include <fstream>
#include <string>
#include <unistd.h>
#include "util.h"

using namespace util;

/* Per-process paths so parallel test binaries never collide on the same file. */
static std::string tmp_path(const char *tag)
{
    return "/tmp/test_l1_util_" + std::string(tag) + "_" + std::to_string(getpid());
}

static void write_raw_file(const std::string &path, const std::string &content)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << content;
}

static std::string read_raw_file(const std::string &path)
{
    std::ifstream in(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

/**
 * @brief Verify that the split_nodelim_hex_str function correctly splits a hexadecimal string into a vector of bytes.
 *
 * This test validates that when provided with a valid hexadecimal string "000FAC02" and a desired byte count of 4,
 * the function split_nodelim_hex_str returns a vector with exactly 4 elements, ensuring that the conversion from hex
 * to bytes is functioning as expected.
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
 * | Variation / Step | Description                                                         | Test Data                                             | Expected Result                                              | Notes       |
 * | :--------------: | ------------------------------------------------------------------- | ----------------------------------------------------- | ------------------------------------------------------------ | ----------- |
 * | 01               | Call split_nodelim_hex_str with a valid hex string and specified count| input: hex = "000FAC02", count = 4                      | Return vector with 4 bytes (vector.size() == 4) and assertion passes | Should Pass |
 */
TEST(UtilTest, split_nodelim_hex_str_positive) {
    std::cout << "Entering split_nodelim_hex_str_positive test" << std::endl;
    std::cout << "Invoking split_nodelim_hex_str(...)" << std::endl;
    std::string hex = "000FAC02";
    auto bytes = split_nodelim_hex_str(hex, 4);
    EXPECT_EQ(bytes.size(), 4u);
    std::cout << "Returned bytes:";
    for (auto b : bytes) {
        std::cout << " " << std::hex << std::uppercase << static_cast<int>(b);
    }
    std::cout << std::dec << std::endl;
    std::cout << "Exiting split_nodelim_hex_str_positive test" << std::endl;
}
/**
 * @brief Validate that split_nodelim_hex_str returns an empty vector when provided a hex string with an incorrect byte length
 *
 * This test verifies that the split_nodelim_hex_str API correctly handles an input hex string whose length does not match the expected number of bytes. The function is expected to return an empty vector when a wrong length string is passed.
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
 * | 01| Log entry indicating the start of the test | None | "Entering split_nodelim_hex_str_negative_wrong_length test" printed to console | Should be successful |
 * | 02| Log message indicating invocation of API with wrong length input | None | "Invoking split_nodelim_hex_str(...) with wrong length" printed to console | Should be successful |
 * | 03| Invoke split_nodelim_hex_str with an incorrect hex string length | input: hex = "000FAC", expected length = 4 | Function returns an empty vector | Should Pass |
 * | 04| Assert that the returned vector is empty | input: vector from API | EXPECT_TRUE verifies that the vector is empty | Should Pass |
 * | 05| Log the returned vector size | output: bytes.size = 0 | "Returned empty vector size=0" printed to console | Should be successful |
 * | 06| Log exit message indicating the end of the test | None | "Exiting split_nodelim_hex_str_negative_wrong_length test" printed to console | Should be successful |
 */
TEST(UtilTest, split_nodelim_hex_str_negative_wrong_length) {
    std::cout << "Entering split_nodelim_hex_str_negative_wrong_length test" << std::endl;
    std::cout << "Invoking split_nodelim_hex_str(...) with wrong length" << std::endl;
    std::string hex = "000FAC"; // 3 bytes, expected 4
    auto bytes = split_nodelim_hex_str(hex, 4);
    EXPECT_TRUE(bytes.empty());
    std::cout << "Returned empty vector size=" << bytes.size() << std::endl;
    std::cout << "Exiting split_nodelim_hex_str_negative_wrong_length test" << std::endl;
}
/**
 * @brief Test the conversion of a colon-delimited MAC address string to a byte vector.
 *
 * This test verifies that the macstr_to_vector function correctly processes a valid MAC address string formatted with colon delimiters, splits it into individual bytes, and returns a vector containing exactly six elements. This ensures that the API functions properly under normal conditions.
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
 * | 01 | Provide a valid MAC address string and delimiter, then invoke macstr_to_vector function. | mac = "01:23:45:67:89:ab", delimiter = ":" | Returns a vector with 6 bytes; ASSERTION EXPECT_EQ(v.size(), 6u) passes | Should Pass |
 */
TEST(UtilTest, macstr_to_vector_positive_colon_delim) {
    std::cout << "Entering macstr_to_vector_positive_colon_delim test" << std::endl;
    std::cout << "Invoking macstr_to_vector(...)" << std::endl;
    std::string mac = "01:23:45:67:89:ab";
    auto v = macstr_to_vector(mac, ":");
    EXPECT_EQ(v.size(), 6u);
    std::cout << "Returned MAC bytes:";
    for (auto b : v) {
        std::cout << " " << std::hex << static_cast<int>(b);
    }
    std::cout << std::dec << std::endl;
    std::cout << "Exiting macstr_to_vector_positive_colon_delim test" << std::endl;
}
/**
 * @brief Tests that macstr_to_vector returns an empty vector when provided with a MAC string that has insufficient parts.
 *
 * This test verifies that macstr_to_vector correctly handles a MAC address string with only 5 parts,
 * ensuring that the function identifies the bad input format and returns an empty vector as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 004@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke macstr_to_vector with a MAC string having only 5 parts | input: mac = "01:23:45:67:89", delimiter = ":" | Returns an empty vector and EXPECT_TRUE(v.empty()) passes | Should Fail |
 */
TEST(UtilTest, macstr_to_vector_negative_bad_parts) {
    std::cout << "Entering macstr_to_vector_negative_bad_parts test" << std::endl;
    std::cout << "Invoking macstr_to_vector(...) with bad input" << std::endl;
    std::string mac = "01:23:45:67:89"; // only 5 parts
    auto v = macstr_to_vector(mac, ":");
    EXPECT_TRUE(v.empty());
    std::cout << "Returned empty vector size=" << v.size() << std::endl;
    std::cout << "Exiting macstr_to_vector_negative_bad_parts test" << std::endl;
}
/**
 * @brief Test the remove_whitespace API with a valid input string containing whitespace characters.
 *
 * This test verifies that the remove_whitespace function correctly removes spaces, tabs, and newline characters from the input string.
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
 * | Variation / Step | Description                                                                 | Test Data                                          | Expected Result                                                         | Notes             |
 * | :--------------: | --------------------------------------------------------------------------- | -------------------------------------------------- | ----------------------------------------------------------------------- | ----------------- |
 * | 01               | Initialize the test by preparing an input string with whitespace characters. | s = " a b\t c\n"                                   | The input string is initialized correctly.                             | Should be successful |
 * | 02               | Invoke the remove_whitespace API using the prepared input string.            | input: s = " a b\t c\n"                             | API returns a string with all whitespace removed (i.e., "abc").          | Should Pass       |
 * | 03               | Verify that the output from remove_whitespace matches the expected string.   | output = function return value, expected = "abc"   | The output string equals "abc" as asserted by EXPECT_EQ.                 | Should Pass       |
 * | 04               | Log the output result and exit the test.                                    | output string printed to standard output           | The printed output displays the correctly processed string ("abc").      | Should be successful |
 */
TEST(UtilTest, remove_whitespace_positive) {
    std::cout << "Entering remove_whitespace_positive test" << std::endl;
    std::cout << "Invoking remove_whitespace(...)" << std::endl;
    std::string s = " a b\t c\n";
    auto out = remove_whitespace(s);
    EXPECT_EQ(out, "abc");
    std::cout << "Returned string='" << out << "'" << std::endl;
    std::cout << "Exiting remove_whitespace_positive test" << std::endl;
}
/**
 * @brief Verify remove_whitespace function correctly handles input string with only whitespace characters.
 *
 * This test passes a string consisting solely of whitespace characters to the remove_whitespace function and verifies that it returns an empty string. It ensures that the function correctly removes all whitespace when no other characters are present.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize input string containing only whitespace characters | input string = " \t\n\r" | String variable is correctly initialized | Should be successful |
 * | 02 | Invoke remove_whitespace function with the given input string | input string = " \t\n\r" | Function returns an empty string | Should Pass |
 * | 03 | Verify the returned string is empty using EXPECT_TRUE | output = result of remove_whitespace (expected: empty string) | EXPECT_TRUE assertion passes confirming empty output | Should Pass |
 */
TEST(UtilTest, remove_whitespace_negative_all_spaces) {
    std::cout << "Entering remove_whitespace_negative_all_spaces test" << std::endl;
    std::cout << "Invoking remove_whitespace(...) with only whitespace" << std::endl;
    std::string s = " \t\n\r";
    auto out = remove_whitespace(s);
    EXPECT_TRUE(out.empty());
    std::cout << "Returned empty string length=" << out.size() << std::endl;
    std::cout << "Exiting remove_whitespace_negative_all_spaces test" << std::endl;
}
/**
 * @brief Verify that em_chan_to_freq calculates the correct frequency for valid input.
 *
 * This test verifies that the em_chan_to_freq API correctly computes the frequency using the provided operating class,
 * channel, and options. Specifically, it checks that for operating class 81 and channel 1, the resulting frequency equals 2407 + (1 * 5) = 2412.
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
 * | Variation / Step | Description                                                                                     | Test Data                                              | Expected Result                                    | Notes      |
 * | :--------------: | ----------------------------------------------------------------------------------------------- | ------------------------------------------------------ | -------------------------------------------------- | ---------- |
 * | 01               | Invoke em_chan_to_freq with valid input (operating class 81, channel 1, empty string options).  | op_class = 81, channel = 1, options = "", expected frequency = 2412 | Return value equals 2412 and assertion passes. | Should Pass |
 */
TEST(UtilTest, em_chan_to_freq_positive) {
    std::cout << "Entering em_chan_to_freq_positive test" << std::endl;
    std::cout << "Invoking em_chan_to_freq(...)" << std::endl;
    // op_class 81 channel 1 -> expected 2407 + 1*5 = 2412
    int freq = em_chan_to_freq(81, 1, "");
    EXPECT_EQ(freq, 2407 + 1 * 5);
    std::cout << "Returned frequency=" << freq << std::endl;
    std::cout << "Exiting em_chan_to_freq_positive test" << std::endl;
}
/**
 * @brief Validates that the em_chan_to_freq API returns an error when provided with an unknown op_class.
 *
 * This test invokes em_chan_to_freq using an unknown channel value (0xFF) to verify that the function appropriately returns -1,
 * indicating that it does not support the unknown op_class. The test ensures that error handling for invalid input conditions is in place.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke em_chan_to_freq with an unknown op_class to validate error handling | chan = 0xFF, op_class = 1, extra_param = "" | Return value is -1 and assertion EXPECT_EQ(freq, -1) passes | Should Fail |
 */
TEST(UtilTest, em_chan_to_freq_negative_unknown) {
    std::cout << "Entering em_chan_to_freq_negative_unknown test" << std::endl;
    std::cout << "Invoking em_chan_to_freq(...) with unknown op_class" << std::endl;
    int freq = em_chan_to_freq(0xFF, 1, "");
    EXPECT_EQ(freq, -1);
    std::cout << "Returned frequency=" << freq << std::endl;
    std::cout << "Exiting em_chan_to_freq_negative_unknown test" << std::endl;
}
/**
 * @brief Verify that em_freq_to_chan returns correct channel and operating class for a given frequency in a global context.
 *
 * This test invokes the em_freq_to_chan API with a frequency of 2412 MHz and an empty region string, expecting the function to return a pair where the first element (operating class) is 81 and the second element (channel) is 1. This helps ensure that the API behaves correctly when global parameters are used.
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
 * | Variation / Step | Description                                                          | Test Data                                          | Expected Result                                          | Notes      |
 * | :--------------: | -------------------------------------------------------------------- | -------------------------------------------------- | -------------------------------------------------------- | ---------- |
 * | 01               | Call em_freq_to_chan with frequency 2412 and empty region string.    | frequency = 2412, region = "", expected_op_class = 81, expected_channel = 1 | API returns a pair with op_class 81 and channel 1; assertions pass | Should Pass |
 */
TEST(UtilTest, em_freq_to_chan_positive_global) {
    std::cout << "Entering em_freq_to_chan_positive_global test" << std::endl;
    std::cout << "Invoking em_freq_to_chan(...)" << std::endl;
    auto p = em_freq_to_chan(2412, "");
    EXPECT_EQ(p.first, 81);
    EXPECT_EQ(p.second, 1);
    std::cout << "Returned op_class=" << static_cast<int>(p.first)  << " channel=" << static_cast<int>(p.second) << std::endl;
    std::cout << "Exiting em_freq_to_chan_positive_global test" << std::endl;
}
/**
 * @brief Test to verify that em_freq_to_chan returns a not found result for an out-of-range frequency.
 *
 * This test invokes the em_freq_to_chan function with a frequency value that is out-of-range (123456) and an empty string.
 * It verifies that the function correctly returns 0 for both op_class and channel when the frequency is not found.
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
 * | Variation / Step | Description                                                                                           | Test Data                                                              | Expected Result                                                           | Notes       |
 * | :--------------: | ----------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- | ------------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke em_freq_to_chan with out-of-range frequency (123456) and empty string                          | input frequency = 123456, input string = "", expected op_class = 0, expected channel = 0 | Return pair with op_class 0 and channel 0, assertions pass by matching expected values | Should Fail |
 */
TEST(UtilTest, em_freq_to_chan_negative_not_found) {
    std::cout << "Entering em_freq_to_chan_negative_not_found test" << std::endl;
    std::cout << "Invoking em_freq_to_chan(...) with out-of-range frequency" << std::endl;
    auto p = em_freq_to_chan(123456, "");
    EXPECT_EQ(p.first, 0);
    EXPECT_EQ(p.second, 0);
    std::cout << "Returned op_class=" << static_cast<int>(p.first) << " channel=" << static_cast<int>(p.second) << std::endl;
    std::cout << "Exiting em_freq_to_chan_negative_not_found test" << std::endl;
}
/**
 * @brief Validate that the akm_to_oui API returns the expected OUI for a given input.
 *
 * This test verifies that when the akm_to_oui function is invoked with the input string "psk", 
 * it correctly converts it into the corresponding OUI "000FAC02". The test ensures that the API's 
 * conversion logic is accurate and that the expected result is returned.
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
 * | Variation / Step | Description                                         | Test Data                               | Expected Result                               | Notes       |
 * | :--------------: | --------------------------------------------------- | --------------------------------------- | --------------------------------------------- | ----------- |
 * | 01               | Invoke akm_to_oui with input "psk"                  | input = "psk", output = "000FAC02"       | API returns "000FAC02" matching the expected value | Should Pass |
 */
TEST(UtilTest, akm_to_oui_positive) {
    std::cout << "Entering akm_to_oui_positive test" << std::endl;
    std::cout << "Invoking akm_to_oui(...)" << std::endl;
    auto s = akm_to_oui("psk");
    EXPECT_EQ(s, "000FAC02");
    std::cout << "Returned string='" << s << "'" << std::endl;
    std::cout << "Exiting akm_to_oui_positive test" << std::endl;
}
/**
 * @brief Verify that akm_to_oui returns an empty string when provided with an unknown akm value
 *
 * This test is designed to validate the behavior of the akm_to_oui API when an unrecognized akm string is passed. It verifies that the function correctly handles the error scenario by returning an empty string.
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
 * | Variation / Step | Description                                                | Test Data                                         | Expected Result                                          | Notes      |
 * | :--------------: | ---------------------------------------------------------- | ------------------------------------------------- | -------------------------------------------------------- | ---------- |
 * | 01               | Invoke akm_to_oui with an unknown akm value                | input = "does-not-exist", output = empty string   | Return value is an empty string and EXPECT_TRUE(s.empty()) passes | Should Pass |
 */
TEST(UtilTest, akm_to_oui_negative_unknown) {
    std::cout << "Entering akm_to_oui_negative_unknown test" << std::endl;
    std::cout << "Invoking akm_to_oui(...) with unknown akm" << std::endl;
    auto s = akm_to_oui("does-not-exist");
    EXPECT_TRUE(s.empty());
    std::cout << "Returned empty string length=" << s.size() << std::endl;
    std::cout << "Exiting akm_to_oui_negative_unknown test" << std::endl;
}
/**
 * @brief Test the functionality of oui_to_akm in a positive scenario.
 *
 * This test verifies that when a valid Organizationally Unique Identifier (OUI) "000FAC02" is provided, the function oui_to_akm returns the expected Authentication and Key Management (AKM) string "wpa2-psk". This ensures correct mapping from OUI to AKM.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 013
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                         | Test Data                                                  | Expected Result                                             | Notes      |
 * | :--------------: | --------------------------------------------------- | ---------------------------------------------------------- | ----------------------------------------------------------- | ---------- |
 * | 01               | Invoke oui_to_akm with input '000FAC02'             | input: oui = "000FAC02", output: expected = "wpa2-psk"      | Function returns "wpa2-psk" and EXPECT_EQ validates the result | Should Pass |
 */
TEST(UtilTest, oui_to_akm_positive) {
    std::cout << "Entering oui_to_akm_positive test" << std::endl;
    std::cout << "Invoking oui_to_akm(...)" << std::endl;
    auto s = oui_to_akm("000FAC02");
    EXPECT_EQ(s, "wpa2-psk");
    std::cout << "Returned string='" << s << "'" << std::endl;
    std::cout << "Exiting oui_to_akm_positive test" << std::endl;
}
/**
 * @brief Test API oui_to_akm with an unknown OUI to ensure it returns an empty string.
 *
 * This test verifies that when an unknown OUI ("DEADBEEF") is provided to the oui_to_akm API, 
 * the API correctly returns an empty string, indicating that there is no associated AKM value. 
 * This negative scenario helps ensure the robustness of the OUI to AKM translation functionality.
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
 * | Variation / Step | Description                                                                                           | Test Data                                          | Expected Result                                                                                         | Notes            |
 * | :--------------: | ----------------------------------------------------------------------------------------------------- | -------------------------------------------------- | ------------------------------------------------------------------------------------------------------- | ---------------- |
 * | 01               | Invoke the oui_to_akm API with the unknown OUI value to test the negative scenario.                   | input: oui = DEADBEEF                              | The API should return an empty string to indicate no valid AKM mapping exists.                           | Should Fail      |
 * | 02               | Validate the API response is empty using the assertion check EXPECT_TRUE(s.empty()).                  | output: s = empty string                           | The assertion verifies that the returned string is empty, confirming the expected negative scenario.   | Should be successful |
 */
TEST(UtilTest, oui_to_akm_negative_unknown) {
    std::cout << "Entering oui_to_akm_negative_unknown test" << std::endl;
    std::cout << "Invoking oui_to_akm(...) with unknown oui" << std::endl;
    auto s = oui_to_akm("DEADBEEF");
    EXPECT_TRUE(s.empty());
    std::cout << "Returned empty string length=" << s.size() << std::endl;
    std::cout << "Exiting oui_to_akm_negative_unknown test" << std::endl;
}
/**
 * @brief Validate that akm_to_bytes converts the "psk" string to a valid byte vector.
 *
 * This test verifies that the akm_to_bytes API correctly converts the given "psk" string into a byte vector. The test confirms that the resulting vector contains 4 elements, ensuring proper byte conversion.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 015@n
 * **Priority:** (High) This test is critical to ensure the correct functionality of the byte conversion API@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call akm_to_bytes with the input "psk" and verify the returned vector's size | input = "psk", expected output size = 4 | The returned vector should have a size of 4; assertion passes | Should Pass |
 */
TEST(UtilTest, akm_to_bytes_positive) {
    std::cout << "Entering akm_to_bytes_positive test" << std::endl;
    std::cout << "Invoking akm_to_bytes(...)" << std::endl;
    auto v = akm_to_bytes("psk");
    EXPECT_EQ(v.size(), 4u);
    std::cout << "Returned bytes:";
    for (auto b : v) {
        std::cout << " " << std::hex << static_cast<int>(b);
    }
    std::cout << std::dec << std::endl;
    std::cout << "Exiting akm_to_bytes_positive test" << std::endl;
}
/**
 * @brief Validate akm_to_bytes handles an unknown akm input
 *
 * This test verifies that when akm_to_bytes is invoked with an invalid or unknown akm string ("nope"), 
 * it returns an empty vector. This behavior is crucial to ensure the API gracefully handles unexpected input.
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
 * | Variation / Step | Description                                                   | Test Data                                  | Expected Result                                                      | Notes      |
 * | :--------------: | ------------------------------------------------------------- | ------------------------------------------ | -------------------------------------------------------------------- | ---------- |
 * | 01               | Invoke akm_to_bytes with an unknown akm string "nope"         | input = "nope", output = empty vector      | Returns an empty vector and the EXPECT_TRUE assertion passes         | Should Fail |
 */
TEST(UtilTest, akm_to_bytes_negative_unknown) {
    std::cout << "Entering akm_to_bytes_negative_unknown test" << std::endl;
    std::cout << "Invoking akm_to_bytes(...) with unknown akm" << std::endl;
    auto v = akm_to_bytes("nope");
    EXPECT_TRUE(v.empty());
    std::cout << "Returned empty vector size=" << v.size() << std::endl;
    std::cout << "Exiting akm_to_bytes_negative_unknown test" << std::endl;
}
/**
 * @brief Verify that deref_net_uint16_to_host correctly converts network byte order to host byte order
 *
 * This test verifies that the function deref_net_uint16_to_host correctly converts a 16-bit unsigned integer from network byte order back to its host representation. The test initializes a host value, converts it to network byte order using htons, copies the network order bytes into a buffer, and then invokes deref_net_uint16_to_host to convert the value back to host order. The expected outcome is that the returned value matches the original host value.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize host value, convert it to network byte order, and copy the value into a buffer | host = 0x1234, net = htons(host) | Buffer contains the correct network byte order representation of host | Should be successful |
 * | 02 | Invoke deref_net_uint16_to_host with the buffer and check the conversion to host order | buf contains network order value, output variable for host conversion | Return value equals the original host value (0x1234) and assertion passes | Should Pass |
 */
TEST(UtilTest, deref_net_uint16_to_host_positive) {
    std::cout << "Entering deref_net_uint16_to_host_positive test" << std::endl;
    std::cout << "Invoking deref_net_uint16_to_host(...)" << std::endl;
    uint16_t host = 0x1234;
    uint16_t net = htons(host);
    uint8_t buf[2];
    memcpy(buf, &net, sizeof(net));
    uint16_t out = deref_net_uint16_to_host(buf);
    EXPECT_EQ(out, host);
    std::cout << "Returned value=0x" << std::hex << out << std::dec << std::endl;
    std::cout << "Exiting deref_net_uint16_to_host_positive test" << std::endl;
}
/**
 * @brief Verify that deref_net_uint16_to_host handles a NULL pointer correctly.
 *
 * This test checks that when deref_net_uint16_to_host is invoked with a NULL pointer,
 * it returns 0. This ensures the API properly handles an invalid pointer input.
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
 * | Variation / Step | Description                                               | Test Data                               | Expected Result                                                  | Notes          |
 * | :--------------: | --------------------------------------------------------- | --------------------------------------- | ---------------------------------------------------------------- | -------------- |
 * | 01               | Log entering the test; this sets up the test environment. | None                                    | Log message indicating test entry is printed                     | Should be successful |
 * | 02               | Invoke deref_net_uint16_to_host with a NULL pointer.      | input = nullptr, output = undefined     | Function returns 0 and EXPECT_EQ(out, 0u) assertion passes         | Should Pass    |
 * | 03               | Log the returned output value for verification.         | out = returned value from function      | Log message displays the output value correctly                    | Should be successful |
 * | 04               | Log exiting the test to mark the end of the test execution. | None                                    | Log message indicating test exit is printed                        | Should be successful |
 */
TEST(UtilTest, deref_net_uint16_to_host_negative_nullptr) {
    std::cout << "Entering deref_net_uint16_to_host_negative_nullptr test" << std::endl;
    std::cout << "Invoking deref_net_uint16_to_host(...) with NULL" << std::endl;
    uint16_t out = deref_net_uint16_to_host(nullptr);
    EXPECT_EQ(out, 0u);
    std::cout << "Returned value=" << out << std::endl;
    std::cout << "Exiting deref_net_uint16_to_host_negative_nullptr test" << std::endl;
}
/**
 * @brief Tests conversion of host uint16_t to network byte order
 *
 * This test verifies that the function set_net_uint16_from_host correctly converts a host-order uint16_t value (0xBEEF) into its network byte order representation and stores it in the provided buffer. The test checks both the return status of the function and the accuracy of the conversion.
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
 * | Variation / Step | Description                                                                                   | Test Data                               | Expected Result                                                       | Notes        |
 * | :--------------: | --------------------------------------------------------------------------------------------- | --------------------------------------- | --------------------------------------------------------------------- | ------------ |
 * | 01               | Invoke set_net_uint16_from_host with a host value of 0xBEEF and an empty buffer                 | host = 0xBEEF, buf[2] = {0, 0}            | Function returns true indicating the conversion was successful         | Should Pass  |
 * | 02               | Validate that the network byte order value stored in the buffer converts back to the original  | buf holds network order value, using ntohs to convert back                                                                 | After conversion, the value equals 0xBEEF confirming accurate conversion | Should Pass  |
 */
TEST(UtilTest, set_net_uint16_from_host_positive) {
    std::cout << "Entering set_net_uint16_from_host_positive test" << std::endl;
    std::cout << "Invoking set_net_uint16_from_host(...)" << std::endl;
    uint16_t host = 0xBEEF;
    uint8_t buf[2] = {};
    bool ok = set_net_uint16_from_host(host, buf);
    EXPECT_TRUE(ok);
    uint16_t net; memcpy(&net, buf, sizeof(net));
    uint16_t back = ntohs(net);
    EXPECT_EQ(back, host);
    std::cout << "Returned bool=" << ok << " stored_host=0x" << std::hex << back << std::dec << std::endl;
    std::cout << "Exiting set_net_uint16_from_host_positive test" << std::endl;
}
/**
 * @brief Validate that set_net_uint16_from_host returns false when invoked with a nullptr for the output pointer.
 *
 * This test checks the robustness of the set_net_uint16_from_host API by passing a valid host value along with a null pointer. The expected behavior is that the function gracefully handles the invalid pointer input by returning false. This ensures that the API correctly validates its input parameters.
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
 * | Variation / Step | Description                                                                         | Test Data                          | Expected Result                                            | Notes             |
 * | :--------------: | ----------------------------------------------------------------------------------- | ---------------------------------- | ---------------------------------------------------------- | ----------------- |
 * | 01               | Print the entry log indicating the start of the test.                               | None                               | Entry message printed successfully.                      | Should be successful |
 * | 02               | Invoke set_net_uint16_from_host with a valid host value and a nullptr pointer.        | input = 0x1, pointer argument = nullptr | API returns false; assertion EXPECT_FALSE(ok) passes.    | Should Fail       |
 * | 03               | Print the result and exit log indicating the end of the test execution.              | ok = false                         | Exit messages printed successfully with correct boolean. | Should be successful |
 */
TEST(UtilTest, set_net_uint16_from_host_negative_nullptr) {
    std::cout << "Entering set_net_uint16_from_host_negative_nullptr test" << std::endl;
    std::cout << "Invoking set_net_uint16_from_host(...) with NULL" << std::endl;
    bool ok = set_net_uint16_from_host(0x1, nullptr);
    EXPECT_FALSE(ok);
    std::cout << "Returned bool=" << ok << std::endl;
    std::cout << "Exiting set_net_uint16_from_host_negative_nullptr test" << std::endl;
}
/**
 * @brief Verify that get_random_bytes fills the requested number of bytes and reports success.
 *
 * This test confirms that get_random_bytes returns 0 for a valid buffer and length, that it writes
 * exactly len bytes and not one byte more, and that two consecutive calls do not return the same
 * 32-byte sequence. The buffer is pre-filled with a sentinel and a guard byte is placed past the
 * requested length so that both under-filling and over-running are detected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 021@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** URANDOM_FILE is readable@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Pre-fill a 33 byte buffer with 0xAA and invoke get_random_bytes for the first 32 bytes | buf[33] = 0xAA, len = 32 | Function returns 0 | Should Pass |
 * | 02 | Inspect the guard byte located past the requested length | buf[32] | Guard byte still holds 0xAA, proving no overrun | Should Pass |
 * | 03 | Invoke get_random_bytes a second time into a separate buffer and compare | len = 32 | The two 32 byte sequences differ | Should Pass |
 */
TEST(UtilTest, get_random_bytes_positive) {
    std::cout << "Entering get_random_bytes_positive test" << std::endl;
    std::cout << "Invoking get_random_bytes(...)" << std::endl;
    unsigned char first[33];
    unsigned char second[33];
    memset(first, 0xAA, sizeof(first));
    memset(second, 0xAA, sizeof(second));

    EXPECT_EQ(get_random_bytes(first, 32), 0);
    EXPECT_EQ(get_random_bytes(second, 32), 0);

    /* The byte past the requested length must be untouched. */
    EXPECT_EQ(first[32], 0xAA);
    EXPECT_EQ(second[32], 0xAA);

    /* Two independent 32 byte draws colliding has probability 2^-256. */
    EXPECT_NE(memcmp(first, second, 32), 0);

    std::cout << "Returned two distinct 32 byte buffers, guard byte intact" << std::endl;
    std::cout << "Exiting get_random_bytes_positive test" << std::endl;
}
/**
 * @brief Verify that get_random_bytes fills a single byte request.
 *
 * This test exercises the smallest valid length so that the boundary between the rejected length of
 * zero and an accepted request is covered, and confirms the write stays inside the requested byte.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 022@n
 * **Priority:** Medium@n
 *
 * **Pre-Conditions:** URANDOM_FILE is readable@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke get_random_bytes with a length of one on a sentinel filled buffer | buf[2] = 0xAA, len = 1 | Function returns 0 | Should Pass |
 * | 02 | Inspect the second byte of the buffer | buf[1] | Still holds 0xAA, proving only one byte was written | Should Pass |
 */
TEST(UtilTest, get_random_bytes_positive_single_byte) {
    std::cout << "Entering get_random_bytes_positive_single_byte test" << std::endl;
    std::cout << "Invoking get_random_bytes(...) with len=1" << std::endl;
    unsigned char buf[2];
    memset(buf, 0xAA, sizeof(buf));
    EXPECT_EQ(get_random_bytes(buf, 1), 0);
    EXPECT_EQ(buf[1], 0xAA);
    std::cout << "Returned single byte, guard byte intact" << std::endl;
    std::cout << "Exiting get_random_bytes_positive_single_byte test" << std::endl;
}
/**
 * @brief Validate that get_random_bytes rejects a NULL buffer.
 *
 * This test verifies that the API validates its output pointer instead of dereferencing it, which
 * would otherwise crash the caller.
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
 * | 01 | Invoke get_random_bytes with a NULL buffer and a non zero length | buf = nullptr, len = 16 | Function returns -1 without dereferencing the pointer | Should Pass |
 */
TEST(UtilTest, get_random_bytes_negative_nullptr) {
    std::cout << "Entering get_random_bytes_negative_nullptr test" << std::endl;
    std::cout << "Invoking get_random_bytes(...) with NULL" << std::endl;
    int rc = get_random_bytes(nullptr, 16);
    EXPECT_EQ(rc, -1);
    std::cout << "Returned rc=" << rc << std::endl;
    std::cout << "Exiting get_random_bytes_negative_nullptr test" << std::endl;
}
/**
 * @brief Validate that get_random_bytes rejects a zero length request.
 *
 * A zero length request carries no meaning for the caller and must be reported as an error rather
 * than silently succeeding, so that a caller cannot mistake an unfilled buffer for random data.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke get_random_bytes with a valid buffer and a length of zero | buf[4] = 0xAA, len = 0 | Function returns -1 | Should Pass |
 * | 02 | Inspect the buffer contents | buf[0] | Still holds 0xAA, proving nothing was written | Should Pass |
 */
TEST(UtilTest, get_random_bytes_negative_zero_len) {
    std::cout << "Entering get_random_bytes_negative_zero_len test" << std::endl;
    std::cout << "Invoking get_random_bytes(...) with len=0" << std::endl;
    unsigned char buf[4];
    memset(buf, 0xAA, sizeof(buf));
    int rc = get_random_bytes(buf, 0);
    EXPECT_EQ(rc, -1);
    EXPECT_EQ(buf[0], 0xAA);
    std::cout << "Returned rc=" << rc << std::endl;
    std::cout << "Exiting get_random_bytes_negative_zero_len test" << std::endl;
}
/**
 * @brief Verify that get_file_content reads the first line of a file and strips the trailing newline.
 *
 * The APIs that consume this function read single line sysfs style files, so the trailing newline
 * that such files carry must not reach the caller. This test writes a file with a trailing newline
 * and confirms the returned string excludes it.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 025@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** /tmp is writable@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create a file whose single line ends with a newline | content = "1234567890\n" | File created | Should be successful |
 * | 02 | Invoke get_file_content on that file | path = temp file, max_len = 64 | Function returns 0 | Should Pass |
 * | 03 | Compare the returned string against the content without the newline | out_val | Equals "1234567890" | Should Pass |
 */
TEST(UtilTest, get_file_content_positive_strips_newline) {
    std::cout << "Entering get_file_content_positive_strips_newline test" << std::endl;
    const std::string path = tmp_path("get_nl");
    write_raw_file(path, "1234567890\n");

    char out[64];
    memset(out, 0xAA, sizeof(out));
    std::cout << "Invoking get_file_content(...)" << std::endl;
    int rc = get_file_content(path.c_str(), out, sizeof(out));
    EXPECT_EQ(rc, 0);
    EXPECT_STREQ(out, "1234567890");

    remove(path.c_str());
    std::cout << "Returned rc=" << rc << " out='" << out << "'" << std::endl;
    std::cout << "Exiting get_file_content_positive_strips_newline test" << std::endl;
}
/**
 * @brief Verify that get_file_content returns the content unchanged when the file has no trailing newline.
 *
 * The newline stripping must be conditional. This test confirms that a file whose last line is not
 * newline terminated is not shortened by one character.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 026@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** /tmp is writable@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create a file with no trailing newline | content = "abcdef" | File created | Should be successful |
 * | 02 | Invoke get_file_content on that file | path = temp file, max_len = 64 | Function returns 0 | Should Pass |
 * | 03 | Compare the returned string against the full content | out_val | Equals "abcdef", no character dropped | Should Pass |
 */
TEST(UtilTest, get_file_content_positive_no_newline) {
    std::cout << "Entering get_file_content_positive_no_newline test" << std::endl;
    const std::string path = tmp_path("get_nonl");
    write_raw_file(path, "abcdef");

    char out[64];
    std::cout << "Invoking get_file_content(...)" << std::endl;
    int rc = get_file_content(path.c_str(), out, sizeof(out));
    EXPECT_EQ(rc, 0);
    EXPECT_STREQ(out, "abcdef");

    remove(path.c_str());
    std::cout << "Returned rc=" << rc << " out='" << out << "'" << std::endl;
    std::cout << "Exiting get_file_content_positive_no_newline test" << std::endl;
}
/**
 * @brief Verify that get_file_content reads only the first line of a multi line file.
 *
 * The function is documented to read a single line. This test confirms that content after the first
 * newline is not returned and that the first line arrives without its newline.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 027@n
 * **Priority:** Medium@n
 *
 * **Pre-Conditions:** /tmp is writable@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create a file holding three lines | content = "first\nsecond\nthird\n" | File created | Should be successful |
 * | 02 | Invoke get_file_content on that file | path = temp file, max_len = 64 | Function returns 0 | Should Pass |
 * | 03 | Compare the returned string against the first line | out_val | Equals "first" | Should Pass |
 */
TEST(UtilTest, get_file_content_positive_first_line_only) {
    std::cout << "Entering get_file_content_positive_first_line_only test" << std::endl;
    const std::string path = tmp_path("get_multiline");
    write_raw_file(path, "first\nsecond\nthird\n");

    char out[64];
    std::cout << "Invoking get_file_content(...)" << std::endl;
    int rc = get_file_content(path.c_str(), out, sizeof(out));
    EXPECT_EQ(rc, 0);
    EXPECT_STREQ(out, "first");

    remove(path.c_str());
    std::cout << "Returned rc=" << rc << " out='" << out << "'" << std::endl;
    std::cout << "Exiting get_file_content_positive_first_line_only test" << std::endl;
}
/**
 * @brief Verify that get_file_content truncates to max_len and stays NUL terminated.
 *
 * A short output buffer must never be overrun and must always come back NUL terminated. This test
 * passes a buffer smaller than the file content and checks that at most max_len - 1 characters are
 * returned, that the result is terminated, and that a guard byte past max_len is untouched.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 028@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** /tmp is writable@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create a file with content longer than the buffer that will be offered | content = "0123456789abcdef\n" | File created | Should be successful |
 * | 02 | Invoke get_file_content with max_len smaller than the content | max_len = 5, buffer holds a guard byte at index 5 | Function returns 0 | Should Pass |
 * | 03 | Compare the returned string against the first max_len - 1 characters | out_val | Equals "0123" and is NUL terminated | Should Pass |
 * | 04 | Inspect the guard byte past max_len | out[5] | Still holds 0xAA, proving no overrun | Should Pass |
 */
TEST(UtilTest, get_file_content_positive_truncates_to_max_len) {
    std::cout << "Entering get_file_content_positive_truncates_to_max_len test" << std::endl;
    const std::string path = tmp_path("get_trunc");
    write_raw_file(path, "0123456789abcdef\n");

    char out[8];
    memset(out, 0xAA, sizeof(out));
    std::cout << "Invoking get_file_content(...) with max_len=5" << std::endl;
    int rc = get_file_content(path.c_str(), out, 5);
    EXPECT_EQ(rc, 0);
    EXPECT_STREQ(out, "0123");
    EXPECT_EQ(strlen(out), 4u);
    /* Nothing may be written at or past max_len. */
    EXPECT_EQ(out[5], static_cast<char>(0xAA));

    remove(path.c_str());
    std::cout << "Returned rc=" << rc << " out='" << out << "'" << std::endl;
    std::cout << "Exiting get_file_content_positive_truncates_to_max_len test" << std::endl;
}
/**
 * @brief Validate that get_file_content reports a missing file and clears the output buffer.
 *
 * A caller that ignores the return code must not be handed stale bytes from a previous use of the
 * buffer. This test confirms both the error return and that the output buffer is emptied first.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 029@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** The path used must not exist@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Pre-fill the output buffer with stale content | out = "stale" | Buffer holds stale content | Should be successful |
 * | 02 | Invoke get_file_content on a path that does not exist | path = non existent temp path, max_len = 64 | Function returns -1 | Should Pass |
 * | 03 | Inspect the output buffer | out_val | Holds an empty string, the stale content is gone | Should Pass |
 */
TEST(UtilTest, get_file_content_negative_missing_file) {
    std::cout << "Entering get_file_content_negative_missing_file test" << std::endl;
    const std::string path = tmp_path("get_missing");
    remove(path.c_str());

    char out[64];
    snprintf(out, sizeof(out), "stale");
    std::cout << "Invoking get_file_content(...) on a missing path" << std::endl;
    int rc = get_file_content(path.c_str(), out, sizeof(out));
    EXPECT_EQ(rc, -1);
    EXPECT_STREQ(out, "");
    std::cout << "Returned rc=" << rc << " out='" << out << "'" << std::endl;
    std::cout << "Exiting get_file_content_negative_missing_file test" << std::endl;
}
/**
 * @brief Validate that get_file_content reports an empty file as an error.
 *
 * An empty file yields no line to read, so the function must report failure rather than returning an
 * empty string that a caller could mistake for a valid value.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 030@n
 * **Priority:** Medium@n
 *
 * **Pre-Conditions:** /tmp is writable@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create a zero byte file | content = "" | File created and empty | Should be successful |
 * | 02 | Invoke get_file_content on that file | path = temp file, max_len = 64 | Function returns -1 | Should Pass |
 * | 03 | Inspect the output buffer | out_val | Holds an empty string | Should Pass |
 */
TEST(UtilTest, get_file_content_negative_empty_file) {
    std::cout << "Entering get_file_content_negative_empty_file test" << std::endl;
    const std::string path = tmp_path("get_empty");
    write_raw_file(path, "");

    char out[64];
    snprintf(out, sizeof(out), "stale");
    std::cout << "Invoking get_file_content(...) on an empty file" << std::endl;
    int rc = get_file_content(path.c_str(), out, sizeof(out));
    EXPECT_EQ(rc, -1);
    EXPECT_STREQ(out, "");

    remove(path.c_str());
    std::cout << "Returned rc=" << rc << std::endl;
    std::cout << "Exiting get_file_content_negative_empty_file test" << std::endl;
}
/**
 * @brief Validate that get_file_content reports a read failure on an openable but unreadable path.
 *
 * Opening a directory for reading succeeds while reading from it fails, which exercises the read
 * failure branch that a missing file cannot reach.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 031@n
 * **Priority:** Medium@n
 *
 * **Pre-Conditions:** /tmp exists and is a directory@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke get_file_content on a directory path | path = "/tmp", max_len = 64 | Function returns -1 because the read fails after a successful open | Should Pass |
 * | 02 | Inspect the output buffer | out_val | Holds an empty string | Should Pass |
 */
TEST(UtilTest, get_file_content_negative_read_failure) {
    std::cout << "Entering get_file_content_negative_read_failure test" << std::endl;
    char out[64];
    snprintf(out, sizeof(out), "stale");
    std::cout << "Invoking get_file_content(...) on a directory" << std::endl;
    int rc = get_file_content("/tmp", out, sizeof(out));
    EXPECT_EQ(rc, -1);
    EXPECT_STREQ(out, "");
    std::cout << "Returned rc=" << rc << std::endl;
    std::cout << "Exiting get_file_content_negative_read_failure test" << std::endl;
}
/**
 * @brief Validate that get_file_content rejects invalid arguments.
 *
 * This test covers the three argument combinations the function must refuse: a NULL path, a NULL
 * output buffer, and a zero length output buffer. A zero length buffer has no room even for the
 * terminator, so writing to it would be an overrun.
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
 * | 01 | Invoke get_file_content with a NULL path | path = nullptr, out = valid, max_len = 64 | Function returns -1 | Should Pass |
 * | 02 | Invoke get_file_content with a NULL output buffer | path = valid, out = nullptr, max_len = 64 | Function returns -1 | Should Pass |
 * | 03 | Invoke get_file_content with a zero length output buffer | path = valid, out = valid, max_len = 0 | Function returns -1 and the buffer is left untouched | Should Pass |
 */
TEST(UtilTest, get_file_content_negative_invalid_args) {
    std::cout << "Entering get_file_content_negative_invalid_args test" << std::endl;
    const std::string path = tmp_path("get_args");
    write_raw_file(path, "value\n");

    char out[64];
    memset(out, 0xAA, sizeof(out));

    std::cout << "Invoking get_file_content(...) with NULL path" << std::endl;
    EXPECT_EQ(get_file_content(nullptr, out, sizeof(out)), -1);

    std::cout << "Invoking get_file_content(...) with NULL out_val" << std::endl;
    EXPECT_EQ(get_file_content(path.c_str(), nullptr, sizeof(out)), -1);

    std::cout << "Invoking get_file_content(...) with max_len=0" << std::endl;
    EXPECT_EQ(get_file_content(path.c_str(), out, 0), -1);
    /* A zero length buffer has no room for a terminator, so nothing may be written. */
    EXPECT_EQ(out[0], static_cast<char>(0xAA));

    remove(path.c_str());
    std::cout << "Exiting get_file_content_negative_invalid_args test" << std::endl;
}
/**
 * @brief Verify that set_file_content writes exactly the supplied string.
 *
 * This test confirms the value reaches the file byte for byte, with no newline appended, since a
 * caller reading the file back with get_file_content would otherwise see a different string.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 033@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** /tmp is writable@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke set_file_content with a plain value on a new path | path = temp file, val = "0123456789" | Function returns 0 | Should Pass |
 * | 02 | Read the raw file back and compare byte for byte | file content | Equals "0123456789" with no trailing newline | Should Pass |
 */
TEST(UtilTest, set_file_content_positive) {
    std::cout << "Entering set_file_content_positive test" << std::endl;
    const std::string path = tmp_path("set_basic");
    remove(path.c_str());

    std::cout << "Invoking set_file_content(...)" << std::endl;
    int rc = set_file_content(path.c_str(), "0123456789");
    EXPECT_EQ(rc, 0);
    EXPECT_EQ(read_raw_file(path), "0123456789");

    remove(path.c_str());
    std::cout << "Returned rc=" << rc << std::endl;
    std::cout << "Exiting set_file_content_positive test" << std::endl;
}
/**
 * @brief Verify that set_file_content truncates an existing longer file.
 *
 * Writing a shorter value over a longer one must not leave the tail of the previous value behind,
 * which would make the file read back as a concatenation of both.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 034@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** /tmp is writable@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create a file holding a long value | content = "AAAAAAAAAAAAAAAAAAAAAAAA" | File created | Should be successful |
 * | 02 | Invoke set_file_content with a shorter value on the same path | val = "B" | Function returns 0 | Should Pass |
 * | 03 | Read the raw file back and compare | file content | Equals "B" only, the previous value is fully gone | Should Pass |
 */
TEST(UtilTest, set_file_content_positive_truncates_existing) {
    std::cout << "Entering set_file_content_positive_truncates_existing test" << std::endl;
    const std::string path = tmp_path("set_trunc");
    write_raw_file(path, "AAAAAAAAAAAAAAAAAAAAAAAA");

    std::cout << "Invoking set_file_content(...) with a shorter value" << std::endl;
    int rc = set_file_content(path.c_str(), "B");
    EXPECT_EQ(rc, 0);
    EXPECT_EQ(read_raw_file(path), "B");

    remove(path.c_str());
    std::cout << "Returned rc=" << rc << std::endl;
    std::cout << "Exiting set_file_content_positive_truncates_existing test" << std::endl;
}
/**
 * @brief Verify that a value written by set_file_content is returned unchanged by get_file_content.
 *
 * The two functions are used as a pair on the same file, so this test checks the round trip rather
 * than each side in isolation, including the empty value which writes a zero byte file.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 035@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** /tmp is writable@n
 * **Dependencies:** get_file_content and set_file_content@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Write a value and read it back | val = "4294967295" | Both calls return 0 and the value matches | Should Pass |
 * | 02 | Write a value containing spaces and punctuation and read it back | val = "a b-c_d.e" | Both calls return 0 and the value matches | Should Pass |
 * | 03 | Write an empty value and read it back | val = "" | The write returns 0 and the read returns -1 because the file holds no line | Should Pass |
 */
TEST(UtilTest, set_get_file_content_positive_round_trip) {
    std::cout << "Entering set_get_file_content_positive_round_trip test" << std::endl;
    const std::string path = tmp_path("round_trip");
    char out[64];

    std::cout << "Invoking set_file_content(...) then get_file_content(...)" << std::endl;
    EXPECT_EQ(set_file_content(path.c_str(), "4294967295"), 0);
    EXPECT_EQ(get_file_content(path.c_str(), out, sizeof(out)), 0);
    EXPECT_STREQ(out, "4294967295");

    EXPECT_EQ(set_file_content(path.c_str(), "a b-c_d.e"), 0);
    EXPECT_EQ(get_file_content(path.c_str(), out, sizeof(out)), 0);
    EXPECT_STREQ(out, "a b-c_d.e");

    /* An empty value produces a zero byte file, which has no line to read back. */
    EXPECT_EQ(set_file_content(path.c_str(), ""), 0);
    EXPECT_EQ(read_raw_file(path), "");
    EXPECT_EQ(get_file_content(path.c_str(), out, sizeof(out)), -1);

    remove(path.c_str());
    std::cout << "Exiting set_get_file_content_positive_round_trip test" << std::endl;
}
/**
 * @brief Validate that set_file_content reports an unopenable path.
 *
 * A path inside a directory that does not exist cannot be opened for writing, and the failure must
 * be reported to the caller rather than being silently swallowed.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 036@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** The parent directory used must not exist@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke set_file_content on a path whose parent directory does not exist | path = "/tmp/<missing dir>/file", val = "x" | Function returns -1 | Should Pass |
 */
TEST(UtilTest, set_file_content_negative_unopenable_path) {
    std::cout << "Entering set_file_content_negative_unopenable_path test" << std::endl;
    const std::string path = tmp_path("no_such_dir") + "/file";
    std::cout << "Invoking set_file_content(...) on an unopenable path" << std::endl;
    int rc = set_file_content(path.c_str(), "x");
    EXPECT_EQ(rc, -1);
    std::cout << "Returned rc=" << rc << std::endl;
    std::cout << "Exiting set_file_content_negative_unopenable_path test" << std::endl;
}
/**
 * @brief Validate that set_file_content rejects a NULL path and a NULL value.
 *
 * Both arguments are passed straight to stdio, so they must be validated before use to avoid
 * undefined behaviour inside fopen and fputs.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 037@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** /tmp is writable@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke set_file_content with a NULL path | path = nullptr, val = "x" | Function returns -1 | Should Pass |
 * | 02 | Invoke set_file_content with a NULL value | path = valid temp path, val = nullptr | Function returns -1 | Should Pass |
 * | 03 | Check whether the NULL value call created a file | temp path | No file was created | Should Pass |
 */
TEST(UtilTest, set_file_content_negative_invalid_args) {
    std::cout << "Entering set_file_content_negative_invalid_args test" << std::endl;
    const std::string path = tmp_path("set_args");
    remove(path.c_str());

    std::cout << "Invoking set_file_content(...) with NULL path" << std::endl;
    EXPECT_EQ(set_file_content(nullptr, "x"), -1);

    std::cout << "Invoking set_file_content(...) with NULL val" << std::endl;
    EXPECT_EQ(set_file_content(path.c_str(), nullptr), -1);

    /* Rejecting the value must happen before the file is created. */
    EXPECT_NE(access(path.c_str(), F_OK), 0);

    std::cout << "Exiting set_file_content_negative_invalid_args test" << std::endl;
}
