#include <gtest/gtest.h>
#include <string>

#include "util.h" 
#include <netinet/in.h>

TEST(EmUtilTest, TestStringSplit) {
    std::string test = "Valid.Data.String";
    std::vector<std::string> result = util::split_by_delim(test, '.');
    EXPECT_EQ(result.size(), 3);
    EXPECT_EQ(result[0], "Valid");
    EXPECT_EQ(result[1], "Data");
    EXPECT_EQ(result[2], "String");
}

TEST(EmUtilTest, TestSplitNodelimHexStr) {
    // Test valid hex string with correct length
    std::string valid_hex = "0123456789ab";
    std::vector<uint8_t> result = util::split_nodelim_hex_str(valid_hex, 6);
    EXPECT_EQ(result.size(), 6);
    EXPECT_EQ(result[0], 0x01);
    EXPECT_EQ(result[1], 0x23);
    EXPECT_EQ(result[2], 0x45);
    EXPECT_EQ(result[3], 0x67);
    EXPECT_EQ(result[4], 0x89);
    EXPECT_EQ(result[5], 0xab);

    // Test with uppercase hex characters
    std::string uppercase_hex = "ABCDEF012345";
    result = util::split_nodelim_hex_str(uppercase_hex, 6);
    EXPECT_EQ(result.size(), 6);
    EXPECT_EQ(result[0], 0xAB);
    EXPECT_EQ(result[1], 0xCD);
    EXPECT_EQ(result[2], 0xEF);
    EXPECT_EQ(result[3], 0x01);
    EXPECT_EQ(result[4], 0x23);
    EXPECT_EQ(result[5], 0x45);

    // Test with all zeros
    std::string zeros = "000000000000";
    result = util::split_nodelim_hex_str(zeros, 6);
    EXPECT_EQ(result.size(), 6);
    for (size_t i = 0; i < 6; i++) {
        EXPECT_EQ(result[i], 0x00);
    }

    // Test with all F's
    std::string ffs = "ffffffffffff";
    result = util::split_nodelim_hex_str(ffs, 6);
    EXPECT_EQ(result.size(), 6);
    for (size_t i = 0; i < 6; i++) {
        EXPECT_EQ(result[i], 0xFF);
    }

    // Test invalid length (too short)
    std::string too_short = "0123456789";
    result = util::split_nodelim_hex_str(too_short, 6);
    EXPECT_TRUE(result.empty());

    // Test invalid length (too long)
    std::string too_long = "0123456789abcd";
    result = util::split_nodelim_hex_str(too_long, 6);
    EXPECT_TRUE(result.empty());

    // Test invalid hex characters
    std::string invalid_hex = "01234567XY89";
    result = util::split_nodelim_hex_str(invalid_hex, 6);
    EXPECT_TRUE(result.empty());

    // Test empty string
    std::string empty = "";
    result = util::split_nodelim_hex_str(empty, 0);
    EXPECT_TRUE(result.empty());

    // Test single byte
    std::string single = "5a";
    result = util::split_nodelim_hex_str(single, 1);
    EXPECT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], 0x5a);

    // Test mixed case
    std::string mixed = "aB1Cd2";
    result = util::split_nodelim_hex_str(mixed, 3);
    EXPECT_EQ(result.size(), 3);
    EXPECT_EQ(result[0], 0xaB);
    EXPECT_EQ(result[1], 0x1C);
    EXPECT_EQ(result[2], 0xd2);
}

class EmUtilByteOrderTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        // Print information for debugging
        int n = 1;
        bool is_little_endian = *reinterpret_cast<char *> (&n) == 1;
        printf("Host is %s endian\n", is_little_endian ? "little" : "big");
        printf("misaligned_t is %ld bytes long\n", sizeof(misaligned_t));
    }

    // The following struct deliberately misaligns the start of `data16`
    typedef struct {
        uint8_t _padding;
        uint16_t data16;
    } __attribute__((__packed__)) misaligned_t;

    // CONSTANTS
    const uint16_t host_val16 = static_cast<uint16_t>(0x4321u);
    const uint16_t net_val16 = htons(host_val16);
};


TEST_F(EmUtilByteOrderTest, TestDerefNetUint16) {
    const misaligned_t bad_const_struct = {
        ._padding = 0x12u,
        .data16 = htons(0x3456u),
    };

    // Null inputs should return 0.
    EXPECT_EQ(util::deref_net_uint16_to_host(nullptr), 0);
    // We should be able to recover host_val16 (host order) from net_val16 (net order) with this function.
    EXPECT_EQ(util::deref_net_uint16_to_host(&net_val16), host_val16);
    // GCC/G++ emits a warning that we may have an unaligned pointer value. Disable that as it's intended here. 
    #pragma GCC diagnostic ignored "-Waddress-of-packed-member"
    // We should be able to recover the correct value from a misaligned struct.
    EXPECT_EQ(util::deref_net_uint16_to_host(&(bad_const_struct.data16)), 0x3456);
    #pragma GCC diagnostic pop
}

TEST_F(EmUtilByteOrderTest, TestSetNetUint16) {
    uint16_t mut_val16 = 0;
    misaligned_t bad_mut_struct = {
            ._padding = 0,
            .data16 = 0,
        };
    // Trying to set a value at a null address should return false
    EXPECT_FALSE(util::set_net_uint16_from_host(host_val16, nullptr));

    // mut_val16 should get set to net_val16 (with network byte order)
    EXPECT_TRUE(util::set_net_uint16_from_host(host_val16, &mut_val16));
    EXPECT_EQ(mut_val16, net_val16);

    // GCC/G++ emits a warning that we may have an unaligned pointer value. Disable that as it's intended here. 
    #pragma GCC diagnostic ignored "-Waddress-of-packed-member"
    // We should be able to set the correct value in a misaligned struct.
    EXPECT_TRUE(util::set_net_uint16_from_host(host_val16, &(bad_mut_struct.data16)));
    #pragma GCC diagnostic pop
    EXPECT_EQ(bad_mut_struct.data16, net_val16);
}
