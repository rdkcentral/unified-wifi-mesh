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
