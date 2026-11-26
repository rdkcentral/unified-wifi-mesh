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
#include <cstdlib>
#include <cstring>
#include <string>
#include "em_ctrl.h"

/*
 * dm_easy_mesh_ctrl_t::get_table_instance(): takes the instance after the first '.' of a TR-181 path, either a number
 * ("Device.1.Radio.2") or an alias in brackets ("Device.[alias].Radio.2"), and returns what follows it. It returns NULL for
 * NULL input, a path without a '.', and a malformed alias (no closing bracket, or no '.' behind it).
 *
 * The path and the instance buffer are heap copies of exactly the right size, so reading or writing one byte too far is
 * reported by AddressSanitizer.
 */

namespace {
const size_t kMaxInstance = 32;

class Parse {
public:
    explicit Parse(const char *path, size_t max_len = kMaxInstance) : max_len_(max_len) {
        if (path != nullptr) {
            size_t n = strlen(path) + 1;
            path_ = static_cast<char *>(malloc(n));
            memcpy(path_, path, n);
        }
        instance_ = static_cast<char *>(malloc(max_len));
        memset(instance_, 'x', max_len);
        dm_easy_mesh_ctrl_t ctrl;
        rest_ = ctrl.get_table_instance(path_, instance_, max_len_, &is_num_);
    }
    ~Parse() { free(path_); free(instance_); }

    const char *rest() const { return rest_; }
    bool failed() const { return rest_ == nullptr; }
    std::string instance() const { return std::string(instance_); }
    bool is_num() const { return is_num_; }
    /* offset of the returned pointer inside the path, -1 when it is outside [path, path + strlen] */
    long offset() const {
        if (rest_ == nullptr || path_ == nullptr) return -1;
        long off = rest_ - path_;
        return (off >= 0 && off <= static_cast<long>(strlen(path_))) ? off : -1;
    }

private:
    char *path_ = nullptr;
    char *instance_ = nullptr;
    size_t max_len_;
    bool is_num_ = false;
    const char *rest_ = nullptr;
};
}  // namespace

TEST(get_table_instance_Test, NullPathIsRejected) {
    Parse p(nullptr);
    EXPECT_TRUE(p.failed());
}

TEST(get_table_instance_Test, PathWithoutDotIsRejected) {
    EXPECT_TRUE(Parse("").failed());
    EXPECT_TRUE(Parse("Device").failed());
    EXPECT_TRUE(Parse("[alias]").failed());
    EXPECT_TRUE(Parse("1").failed());
}

TEST(get_table_instance_Test, NumericInstanceReturnsTheRemainder) {
    Parse p("Device.1.Radio.2.Method");
    ASSERT_FALSE(p.failed());
    EXPECT_TRUE(p.is_num());
    EXPECT_EQ(p.instance(), "1");
    EXPECT_STREQ(p.rest(), "Radio.2.Method");
}

TEST(get_table_instance_Test, SecondInstanceIsParsedFromTheRemainder) {
    dm_easy_mesh_ctrl_t ctrl;
    char instance[kMaxInstance];
    bool is_num = false;
    const char *rest = ctrl.get_table_instance("Device.12.Radio.34.Method", instance, sizeof(instance), &is_num);
    ASSERT_NE(rest, nullptr);
    EXPECT_STREQ(instance, "12");
    rest = ctrl.get_table_instance(rest, instance, sizeof(instance), &is_num);
    ASSERT_NE(rest, nullptr);
    EXPECT_TRUE(is_num);
    EXPECT_STREQ(instance, "34");
    EXPECT_STREQ(rest, "Method");
}

/* the numeric instance is the last thing in the string: the returned pointer must stay on the terminator */
TEST(get_table_instance_Test, NumericInstanceAtTheStringTerminator) {
    Parse p("Device.7");
    ASSERT_FALSE(p.failed());
    EXPECT_TRUE(p.is_num());
    EXPECT_EQ(p.instance(), "7");
    EXPECT_EQ(p.offset(), static_cast<long>(strlen("Device.7")));
    EXPECT_STREQ(p.rest(), "");
}

TEST(get_table_instance_Test, EmptyNumericInstanceAtTheStringTerminator) {
    Parse p("Device.");
    ASSERT_FALSE(p.failed());
    EXPECT_TRUE(p.is_num());
    EXPECT_EQ(p.instance(), "");
    EXPECT_EQ(p.offset(), static_cast<long>(strlen("Device.")));
}

TEST(get_table_instance_Test, AliasInstanceReturnsTheRemainder) {
    Parse p("Device.[ab12=].Radio.2.Method");
    ASSERT_FALSE(p.failed());
    EXPECT_FALSE(p.is_num());
    EXPECT_EQ(p.instance(), "ab12=");
    EXPECT_STREQ(p.rest(), "Radio.2.Method");
}

TEST(get_table_instance_Test, AliasFollowedByAnEmptyRemainder) {
    Parse p("Device.[abc].");
    ASSERT_FALSE(p.failed());
    EXPECT_FALSE(p.is_num());
    EXPECT_EQ(p.instance(), "abc");
    EXPECT_EQ(p.offset(), static_cast<long>(strlen("Device.[abc].")));
    EXPECT_STREQ(p.rest(), "");
}

/* alias that ends at the closing bracket (the string ends there): no '.' behind it */
TEST(get_table_instance_Test, AliasEndingAtTheClosingBracketIsRejected) {
    EXPECT_TRUE(Parse("Device.[abc]").failed());
    EXPECT_TRUE(Parse("Device.[]").failed());
}

TEST(get_table_instance_Test, AliasWithoutClosingBracketIsRejected) {
    EXPECT_TRUE(Parse("Device.[abc").failed());
    EXPECT_TRUE(Parse("Device.[").failed());
    EXPECT_TRUE(Parse("Device.[abc.Radio.1").failed());
}

TEST(get_table_instance_Test, AliasWithoutADotBehindTheBracketIsRejected) {
    EXPECT_TRUE(Parse("Device.[abc]Radio").failed());
    EXPECT_TRUE(Parse("Device.[abc]x").failed());
}

TEST(get_table_instance_Test, AliasLongerThanTheBufferIsRejected) {
    /* 4 byte buffer: at most 3 characters are copied, the closing bracket is not reached */
    EXPECT_TRUE(Parse("Device.[0123456789].Radio.1", 4).failed());
    EXPECT_TRUE(Parse("Device.[012].Radio.1", 4).failed() == false);
}

TEST(get_table_instance_Test, LongNumericInstanceIsCutToTheBuffer) {
    Parse p("Device.1234567890.Radio.1", 4);
    ASSERT_FALSE(p.failed());
    EXPECT_TRUE(p.is_num());
    EXPECT_EQ(p.instance(), "123");
    EXPECT_GE(p.offset(), 0);
}
