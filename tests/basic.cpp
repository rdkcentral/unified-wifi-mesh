#include <gtest/gtest.h>
#include <string>
#include <memory>

// Include necessary headers from your project
// Adjust paths as needed based on your project structure
#include "util.h" 

// Basic sanity test
TEST(OneWifiEmTest, SanityCheck) {
    EXPECT_TRUE(true);
}

TEST(OneWifiEmTest, TestStringSplit) {
    std::string test = "Valid.Data.String";
    std::vector<std::string> result = util::split_by_delim(test, '.');
    EXPECT_EQ(result.size(), 3);
    EXPECT_EQ(result[0], "Valid");
    EXPECT_EQ(result[1], "Data");
    EXPECT_EQ(result[2], "String");
}