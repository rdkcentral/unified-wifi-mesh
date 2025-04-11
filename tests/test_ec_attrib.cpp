#include <gtest/gtest.h>
#include <iomanip>
#include <memory>
#include <string>

#include <cjson/cJSON.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

#include "em_crypto.h"
#include "ec_util.h"
#include "test_utils.h"
#include "util.h"

class ECUtilAttributeTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize frame with default values
        frame = ec_util::alloc_frame(ec_frame_type_t::ec_frame_type_auth_req);
        ASSERT_NE(frame, nullptr) << "Failed to allocate frame";
    }

    void TearDown() override {

        if (frame) {
            free(frame);
            frame = nullptr;
        }
        
        if (buffer) {
            free(buffer);
            buffer = nullptr;
        }

        test_attrib_1 = nullptr;
        test_attrib_2 = nullptr;
        test_attrib_3 = nullptr;
    }

    // Helper to create a buffer with attributes
    void create_new_attrib_buf(size_t& buffer_len) {
        buffer_len = 0;
        if (buffer) {
            free(buffer);
            buffer = nullptr;
        }
        
        // Add a few test attributes
        const size_t test_attrib_1_offset = buffer_len;
        buffer = ec_util::add_attrib(buffer, &buffer_len, ec_attrib_id_dpp_status, test_val_1);
        EXPECT_NE(buffer, nullptr) << "Failed to add first attribute";
        
        const size_t test_attrib_2_offset = buffer_len;
        buffer = ec_util::add_attrib(buffer, &buffer_len, ec_attrib_id_init_bootstrap_key_hash, test_val_2);
        EXPECT_NE(buffer, nullptr) << "Failed to add second attribute";
        
        const size_t test_attrib_3_offset = buffer_len;
        buffer = ec_util::add_attrib(buffer, &buffer_len, ec_attrib_id_channel, test_val_3);
        EXPECT_NE(buffer, nullptr) << "Failed to add third attribute";

        // Save the address of each attribute
        test_attrib_1 = buffer + test_attrib_1_offset;
        test_attrib_2 = buffer + test_attrib_2_offset;
        test_attrib_3 = buffer + test_attrib_3_offset;
    }

    ec_frame_t* frame = nullptr;
    uint8_t* buffer = nullptr;

    const uint8_t test_val_1 = 0x42;
    const uint16_t test_val_2 = 0x1234;
    const std::string test_val_3 = "test_string";

    uint8_t *test_attrib_1 = nullptr;
    uint8_t *test_attrib_2 = nullptr;
    uint8_t *test_attrib_3 = nullptr;

    const ec_attrib_id_t all_ec_attribute_ids[33] = {
        ec_attrib_id_dpp_status,
        ec_attrib_id_init_bootstrap_key_hash,
        ec_attrib_id_resp_bootstrap_key_hash,
        ec_attrib_id_init_proto_key,
        ec_attrib_id_wrapped_data,
        ec_attrib_id_init_nonce,
        ec_attrib_id_init_caps,
        ec_attrib_id_resp_nonce,
        ec_attrib_id_resp_caps,
        ec_attrib_id_resp_proto_key,
        ec_attrib_id_init_auth_tag,
        ec_attrib_id_resp_auth_tag,
        ec_attrib_id_dpp_config_obj,
        ec_attrib_id_dpp_connector,
        ec_attrib_id_dpp_config_req_obj,
        ec_attrib_id_bootstrap_key,
        ec_attrib_id_finite_cyclic_group,
        ec_attrib_id_enc_key,
        ec_attrib_id_enrollee_nonce,
        ec_attrib_id_code_identifier,
        ec_attrib_id_trans_id,
        ec_attrib_id_bootstrap_info,
        ec_attrib_id_channel,
        ec_attrib_id_proto_version,
        ec_attrib_id_dpp_enveloped_data,
        ec_attrib_id_send_conn_status,
        ec_attrib_id_conn_status,
        ec_attrib_id_reconfig_flags,
        ec_attrib_id_C_sign_key_hash,
        ec_attrib_id_csr_attrs_req,
        ec_attrib_id_a_nonce,
        ec_attrib_id_e_prime_id,
        ec_attrib_id_config_nonce
    };
};

// Test attribute retrieval
TEST_F(ECUtilAttributeTest, GetAttribute) {
    size_t buffer_len = 0;
    create_new_attrib_buf(buffer_len);
    ASSERT_NE(buffer, nullptr);

    // Test retrieving existing attributes
    auto attr1 = ec_util::get_attrib(buffer, buffer_len, ec_attrib_id_dpp_status);
    ASSERT_NE(attr1, std::nullopt);
    EXPECT_EQ(attr1->attr_id, ec_attrib_id_dpp_status);
    EXPECT_EQ(attr1->length, sizeof(uint8_t));
    EXPECT_EQ(attr1->original, reinterpret_cast<ec_net_attribute_t*>(test_attrib_1));
    EXPECT_EQ(attr1->data[0], test_val_1);

    auto attr2 = ec_util::get_attrib(buffer, buffer_len, ec_attrib_id_init_bootstrap_key_hash);
    ASSERT_NE(attr2, std::nullopt);
    EXPECT_EQ(attr2->attr_id, ec_attrib_id_init_bootstrap_key_hash);
    EXPECT_EQ(attr2->length, sizeof(uint16_t));
    EXPECT_EQ(attr2->original, reinterpret_cast<ec_net_attribute_t*>(test_attrib_2));

    uint16_t data = 0;
    memcpy(&data, attr2->data, sizeof(uint16_t));
    EXPECT_EQ(data, test_val_2);

    auto attr3 = ec_util::get_attrib(buffer, buffer_len, ec_attrib_id_channel);
    ASSERT_NE(attr3, std::nullopt);
    EXPECT_EQ(attr3->attr_id, ec_attrib_id_channel);
    EXPECT_EQ(attr3->length, test_val_3.size()); // Length of "test_string"
    EXPECT_EQ(attr3->original, reinterpret_cast<ec_net_attribute_t*>(test_attrib_3));
    EXPECT_EQ(std::string(reinterpret_cast<char*>(attr3->data), attr3->length), test_val_3);

    // Test retrieving non-existent attribute
    auto attr4 = ec_util::get_attrib(buffer, buffer_len, ec_attrib_id_wrapped_data);
    EXPECT_EQ(attr4, std::nullopt);
}

// Test adding attributes with different types
TEST_F(ECUtilAttributeTest, AddAttributeDifferentTypes) {
    size_t buffer_len = 0;
    
    // Test adding uint8_t
    uint8_t u8_val = 0x42;
    const size_t u8_attrib_offset = buffer_len;
    buffer = ec_util::add_attrib(buffer, &buffer_len, ec_attrib_id_dpp_status, u8_val);
    ASSERT_NE(buffer, nullptr);
    
    // Test adding uint16_t
    uint16_t u16_val = 0x1234;
    const size_t u16_attrib_offset = buffer_len;
    buffer = ec_util::add_attrib(buffer, &buffer_len, ec_attrib_id_init_bootstrap_key_hash, u16_val);
    ASSERT_NE(buffer, nullptr);
    
    // Test adding string
    std::string str_val = "test_string";
    const size_t str_attrib_offset = buffer_len;
    buffer = ec_util::add_attrib(buffer, &buffer_len, ec_attrib_id_channel, str_val);
    ASSERT_NE(buffer, nullptr);
    
    // Test adding raw buffer
    uint8_t raw_data[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    const size_t raw_attrib_offset = buffer_len;
    buffer = ec_util::add_attrib(buffer, &buffer_len, ec_attrib_id_proto_version, 
                              sizeof(raw_data), raw_data);
    ASSERT_NE(buffer, nullptr);

    // Compute the address of each added attribute
    uint8_t *u8_attrib = buffer + u8_attrib_offset;
    uint8_t *u16_attrib = buffer + u16_attrib_offset;
    uint8_t *str_attrib = buffer + str_attrib_offset;
    uint8_t *raw_attrib = buffer + raw_attrib_offset;
    
    // Verify all attributes were added correctly
    auto attr1 = ec_util::get_attrib(buffer, buffer_len, ec_attrib_id_dpp_status);
    ASSERT_NE(attr1, std::nullopt);
    EXPECT_EQ(attr1->original, reinterpret_cast<ec_net_attribute_t*>(u8_attrib));
    EXPECT_EQ(attr1->data[0], u8_val);
    
    auto attr2 = ec_util::get_attrib(buffer, buffer_len, ec_attrib_id_init_bootstrap_key_hash);
    ASSERT_NE(attr2, std::nullopt);
    EXPECT_EQ(attr2->original, reinterpret_cast<ec_net_attribute_t*>(u16_attrib));

    uint16_t data = 0;
    memcpy(&data, attr2->data, sizeof(uint16_t));
    EXPECT_EQ(data, u16_val);
    
    auto attr3 = ec_util::get_attrib(buffer, buffer_len, ec_attrib_id_channel);
    ASSERT_NE(attr3, std::nullopt);
    EXPECT_EQ(attr3->original, reinterpret_cast<ec_net_attribute_t*>(str_attrib));
    EXPECT_EQ(std::string(reinterpret_cast<char*>(attr3->data), attr3->length), str_val);
    
    auto attr4 = ec_util::get_attrib(buffer, buffer_len, ec_attrib_id_proto_version);
    ASSERT_NE(attr4, std::nullopt);
    EXPECT_EQ(attr4->original, reinterpret_cast<ec_net_attribute_t*>(raw_attrib));
    EXPECT_EQ(attr4->length, sizeof(raw_data));
    EXPECT_EQ(memcmp(attr4->data, raw_data, sizeof(raw_data)), 0);
}

// Test attribute size calculation
TEST_F(ECUtilAttributeTest, AttributeSizeCalculation) {
    // Test various attribute sizes
    EXPECT_EQ(ec_util::get_ec_attr_size(0), offsetof(ec_net_attribute_t, data));
    EXPECT_EQ(ec_util::get_ec_attr_size(1), offsetof(ec_net_attribute_t, data) + 1);
    EXPECT_EQ(ec_util::get_ec_attr_size(10), offsetof(ec_net_attribute_t, data) + 10);
    EXPECT_EQ(ec_util::get_ec_attr_size(100), offsetof(ec_net_attribute_t, data) + 100);
}

// Test adding and retrieving multiple attributes
TEST_F(ECUtilAttributeTest, MultipleAttributes) {
    size_t buffer_len = 0;
    
    // Add multiple attributes
    const int NUM_ATTRIBUTES = 10;
    ec_attrib_id_t ids[NUM_ATTRIBUTES] = {
        ec_attrib_id_dpp_status,
        ec_attrib_id_init_bootstrap_key_hash,
        ec_attrib_id_resp_bootstrap_key_hash,
        ec_attrib_id_proto_version,
        ec_attrib_id_resp_auth_tag,
        ec_attrib_id_channel,
        ec_attrib_id_wrapped_data,
        ec_attrib_id_dpp_connector,
        ec_attrib_id_enrollee_nonce,
        ec_attrib_id_resp_nonce
    };
    
    uint8_t values[NUM_ATTRIBUTES];
    for (int i = 0; i < NUM_ATTRIBUTES; i++) {
        values[i] = static_cast<uint8_t>(i + 1);
        buffer = ec_util::add_attrib(buffer, &buffer_len, ids[i], values[i]);
        ASSERT_NE(buffer, nullptr) << "Failed to add attribute " << i;
    }
    
    // Verify all attributes
    for (int i = 0; i < NUM_ATTRIBUTES; i++) {
        auto attr = ec_util::get_attrib(buffer, buffer_len, ids[i]);
        ASSERT_NE(attr, std::nullopt) << "Failed to retrieve attribute " << i;
        EXPECT_EQ(attr->attr_id, ids[i]);
        EXPECT_EQ(attr->length, sizeof(uint8_t));
        EXPECT_EQ(attr->data[0], values[i]);
    }
}

// Test behavior with null buffer
TEST_F(ECUtilAttributeTest, NullBuffer) {
    // Test get_attrib with null buffer
    auto null_attr = ec_util::get_attrib(nullptr, 10, ec_attrib_id_dpp_status);
    EXPECT_EQ(null_attr, std::nullopt);
    
    // Test add_attrib with valid data but null buffer
    size_t buffer_len = 0;
    uint8_t test_val = 0x42;
    buffer = ec_util::add_attrib(nullptr, &buffer_len, ec_attrib_id_dpp_status, test_val);
    ASSERT_NE(buffer, nullptr) << "add_attrib should allocate a new buffer when buffer is null";
    
    // Verify the attribute was added correctly
    auto new_attr = ec_util::get_attrib(buffer, buffer_len, ec_attrib_id_dpp_status);
    ASSERT_NE(new_attr, std::nullopt);
    EXPECT_EQ(new_attr->data[0], test_val);
}

// Test copy attributes to frame
TEST_F(ECUtilAttributeTest, CopyAttrsToFrame) {
    // Create a buffer with attributes
    size_t buffer_len = 0;
    create_new_attrib_buf(buffer_len);
    ASSERT_NE(buffer, nullptr);
    
    // Copy attributes to frame
    ec_frame_t* new_frame = ec_util::copy_attrs_to_frame(frame, buffer, buffer_len);
    ASSERT_NE(new_frame, nullptr);
    
    // Update frame pointer since it might have been reallocated
    frame = new_frame;
    
    // Verify attributes were copied correctly
    auto attr1 = ec_util::get_attrib(frame->attributes, buffer_len, ec_attrib_id_dpp_status);
    ASSERT_NE(attr1, std::nullopt);
    EXPECT_EQ(attr1->data[0], 0x42);
    
    auto attr2 = ec_util::get_attrib(frame->attributes, buffer_len, ec_attrib_id_init_bootstrap_key_hash);
    ASSERT_NE(attr2, std::nullopt);
    uint16_t data = 0;
    memcpy(&data, attr2->data, sizeof(uint16_t));
    EXPECT_EQ(data, 0x1234);
    
    auto attr3 = ec_util::get_attrib(frame->attributes, buffer_len, ec_attrib_id_channel);
    ASSERT_NE(attr3, std::nullopt);
    EXPECT_EQ(std::string(reinterpret_cast<char*>(attr3->data), attr3->length), "test_string");
}

// Test adding attributes with empty data
TEST_F(ECUtilAttributeTest, AddAttributeEmptyData) {
    size_t buffer_len = 0;
    
    // Try adding attribute with null data
    uint8_t* null_data = nullptr;
    buffer = ec_util::add_attrib(buffer, &buffer_len, ec_attrib_id_dpp_status, 0, null_data);
    EXPECT_EQ(buffer, nullptr) << "add_attrib should fail with null data";
    
    // Try adding attribute with zero length
    uint8_t some_data[] = {0x01, 0x02, 0x03};
    buffer = ec_util::add_attrib(buffer, &buffer_len, ec_attrib_id_dpp_status, 0, some_data);
    EXPECT_EQ(buffer, nullptr) << "add_attrib should fail with zero length";
    
    // Adding valid data should work
    buffer = ec_util::add_attrib(buffer, &buffer_len, ec_attrib_id_dpp_status, sizeof(some_data), some_data);
    ASSERT_NE(buffer, nullptr);
    
}

// Test wrapped data attribute functionality
TEST_F(ECUtilAttributeTest, AddWrappedDataAttributeNoAAD) {
    // This is a basic test to ensure the wrapped data functions compile and link
    // For detailed testing, more mock functions would be needed for encryption/decryption
    
    size_t buffer_len = 0;
    
    // Add a basic attribute first
    uint8_t test_val = 0x42;
    buffer = ec_util::add_attrib(buffer, &buffer_len, ec_attrib_id_dpp_status, test_val);
    ASSERT_NE(buffer, nullptr);
    
    // Create a mock key for testing
    uint8_t mock_key[32];
    memset(mock_key, 0xAA, sizeof(mock_key));
    
    // Define a lambda to create wrapped attributes
    auto create_wrapped_attrs = []() -> std::pair<uint8_t*, uint16_t> {
        uint8_t* wrapped_buff = nullptr;
        size_t wrapped_len = 0;
        
        uint8_t data = 0x99;
        wrapped_buff = ec_util::add_attrib(wrapped_buff, &wrapped_len, ec_attrib_id_enrollee_nonce, data);
        
        return {wrapped_buff, static_cast<uint16_t>(wrapped_len)};
    };
    
    // Test that the function compiles and runs (though we don't expect encryption to work in this test)
    uint8_t* new_buff = ec_util::add_wrapped_data_attr(
        frame, buffer, &buffer_len, false, mock_key, create_wrapped_attrs);
    
    ASSERT_NE(new_buff, buffer);
    ASSERT_NE(new_buff, nullptr);
    buffer = new_buff;

    // Check that the wrapped data attribute was added
    auto wrapped_attr = ec_util::get_attrib(buffer, buffer_len, ec_attrib_id_wrapped_data);
    ASSERT_NE(wrapped_attr, std::nullopt);
    EXPECT_EQ(wrapped_attr->attr_id, ec_attrib_id_wrapped_data);
}

// Test wrapped data attribute functionality
TEST_F(ECUtilAttributeTest, AddWrappedDataAttributeAAD) {
    // This is a basic test to ensure the wrapped data functions compile and link
    // For detailed testing, more mock functions would be needed for encryption/decryption
    
    size_t buffer_len = 0;
    
    // Add a basic attribute first
    uint8_t test_val = 0x42;
    buffer = ec_util::add_attrib(buffer, &buffer_len, ec_attrib_id_dpp_status, test_val);
    ASSERT_NE(buffer, nullptr);
    
    // Create a mock key for testing
    uint8_t mock_key[32];
    memset(mock_key, 0xAA, sizeof(mock_key));
    
    // Define a lambda to create wrapped attributes
    auto create_wrapped_attrs = []() -> std::pair<uint8_t*, uint16_t> {
        uint8_t* wrapped_buff = nullptr;
        size_t wrapped_len = 0;
        
        uint8_t data = 0x99;
        wrapped_buff = ec_util::add_attrib(wrapped_buff, &wrapped_len, ec_attrib_id_enrollee_nonce, data);
        
        return {wrapped_buff, static_cast<uint16_t>(wrapped_len)};
    };
    
    // Test that the function compiles and runs (though we don't expect encryption to work in this test)
    uint8_t* new_buff = ec_util::add_wrapped_data_attr(
        frame, buffer, &buffer_len, true, mock_key, create_wrapped_attrs);
    
    ASSERT_NE(new_buff, buffer);
    ASSERT_NE(new_buff, nullptr);
    buffer = new_buff;

    // Check that the wrapped data attribute was added
    auto wrapped_attr = ec_util::get_attrib(buffer, buffer_len, ec_attrib_id_wrapped_data);
    ASSERT_NE(wrapped_attr, std::nullopt);
    EXPECT_EQ(wrapped_attr->attr_id, ec_attrib_id_wrapped_data);
}

// Test wrapped data attribute functionality
TEST_F(ECUtilAttributeTest, WrapUnwrapDataAttributeNoAAD) {

    size_t buffer_len = 0;
    
    // Create a mock key for testing
    uint8_t mock_key[32];
    memset(mock_key, 0xAA, sizeof(mock_key));
    
    // Define a lambda to create wrapped attributes
    auto create_wrapped_attrs = []() -> std::pair<uint8_t*, uint16_t> {
        uint8_t* wrapped_buff = nullptr;
        size_t wrapped_len = 0;
        
        uint8_t data = 0x99;
        wrapped_buff = ec_util::add_attrib(wrapped_buff, &wrapped_len, ec_attrib_id_enrollee_nonce, data);
        
        return {wrapped_buff, static_cast<uint16_t>(wrapped_len)};
    };
    
    // Test that the function compiles and runs (though we don't expect encryption to work in this test)
    uint8_t* new_buff = ec_util::add_wrapped_data_attr(
        frame, buffer, &buffer_len, false, mock_key, create_wrapped_attrs);
    
    ASSERT_NE(new_buff, nullptr);
    ASSERT_NE(new_buff, buffer);
    buffer = new_buff;

    // Check that the wrapped data attribute was added
    auto wrapped_attr = ec_util::get_attrib(buffer, buffer_len, ec_attrib_id_wrapped_data);
    ASSERT_NE(wrapped_attr, std::nullopt);
    EXPECT_EQ(wrapped_attr->attr_id, ec_attrib_id_wrapped_data);

    // Unwrap the wrapped data attribute

    auto [unwrapped_attribs, unwrapped_len] = ec_util::unwrap_wrapped_attrib(*wrapped_attr, frame, false, mock_key);
    ASSERT_NE(unwrapped_attribs, nullptr);
    ASSERT_NE(unwrapped_len, 0);
    auto unwrapped_attr = ec_util::get_attrib(unwrapped_attribs, unwrapped_len, ec_attrib_id_enrollee_nonce);
    ASSERT_NE(unwrapped_attr, std::nullopt);
    EXPECT_EQ(unwrapped_attr->attr_id, ec_attrib_id_enrollee_nonce);
    EXPECT_EQ(unwrapped_attr->length, sizeof(uint8_t));
    EXPECT_EQ(unwrapped_attr->data[0], 0x99);
    free(unwrapped_attribs);
    unwrapped_attribs = nullptr;
    unwrapped_len = 0;

}

// Test wrapped data attribute functionality
TEST_F(ECUtilAttributeTest, WrapUnwrapDataAttributeAAD) {
    
    size_t buffer_len = 0;

    create_new_attrib_buf(buffer_len);
    ASSERT_NE(buffer, nullptr);
    
    // Create a mock key for testing
    uint8_t mock_key[32];
    memset(mock_key, 0xAA, sizeof(mock_key));
    
    // Define a lambda to create wrapped attributes
    auto create_wrapped_attrs = []() -> std::pair<uint8_t*, uint16_t> {
        uint8_t* wrapped_buff = nullptr;
        size_t wrapped_len = 0;
        
        uint8_t data = 0x99;
        wrapped_buff = ec_util::add_attrib(wrapped_buff, &wrapped_len, ec_attrib_id_enrollee_nonce, data);
        
        return {wrapped_buff, static_cast<uint16_t>(wrapped_len)};
    };
    
    // Test that the function compiles and runs (though we don't expect encryption to work in this test)
    uint8_t* new_buff = ec_util::add_wrapped_data_attr(
        frame, buffer, &buffer_len, true, mock_key, create_wrapped_attrs);
    
    ASSERT_NE(new_buff, nullptr);
    ASSERT_NE(new_buff, buffer);
    buffer = new_buff;

    frame = ec_util::copy_attrs_to_frame(frame, buffer, buffer_len);
    ASSERT_NE(frame, nullptr);

    // Check that the wrapped data attribute was added
    auto wrapped_attr = ec_util::get_attrib(frame->attributes, buffer_len, ec_attrib_id_wrapped_data);
    ASSERT_NE(wrapped_attr, std::nullopt);
    EXPECT_EQ(wrapped_attr->attr_id, ec_attrib_id_wrapped_data);

    // Unwrap the wrapped data attribute

    auto [unwrapped_attribs, unwrapped_len] = ec_util::unwrap_wrapped_attrib(*wrapped_attr, frame, true, mock_key);
    ASSERT_NE(unwrapped_attribs, nullptr);
    ASSERT_NE(unwrapped_len, 0);
    auto unwrapped_attr = ec_util::get_attrib(unwrapped_attribs, unwrapped_len, ec_attrib_id_enrollee_nonce);
    ASSERT_NE(unwrapped_attr, std::nullopt);
    EXPECT_EQ(unwrapped_attr->attr_id, ec_attrib_id_enrollee_nonce);
    EXPECT_EQ(unwrapped_attr->length, sizeof(uint8_t));
    EXPECT_EQ(unwrapped_attr->data[0], 0x99);
    free(unwrapped_attribs);
    unwrapped_attribs = nullptr;
    unwrapped_len = 0;
}

// Test frame validation
TEST_F(ECUtilAttributeTest, FrameValidation) {
    // Test valid frame
    EXPECT_TRUE(ec_util::validate_frame(frame));
    
    // Test valid frame with specific type
    EXPECT_TRUE(ec_util::validate_frame(frame, ec_frame_type_t::ec_frame_type_auth_req));
    
    // Test invalid frame type
    EXPECT_FALSE(ec_util::validate_frame(frame, ec_frame_type_t::ec_frame_type_auth_rsp));
    
    // Test invalid frame (corrupt header fields)
    ec_frame_t invalid_frame = *frame;
    invalid_frame.category = 0x99; // Invalid category
    EXPECT_FALSE(ec_util::validate_frame(&invalid_frame));
    
    invalid_frame = *frame;
    invalid_frame.action = 0x99; // Invalid action
    EXPECT_FALSE(ec_util::validate_frame(&invalid_frame));
    
    invalid_frame = *frame;
    invalid_frame.oui[0] = 0x99; // Invalid OUI
    EXPECT_FALSE(ec_util::validate_frame(&invalid_frame));
    
    invalid_frame = *frame;
    invalid_frame.oui_type = 0x99; // Invalid OUI type
    EXPECT_FALSE(ec_util::validate_frame(&invalid_frame));
    
    invalid_frame = *frame;
    invalid_frame.crypto_suite = 0x99; // Invalid crypto suite
    EXPECT_FALSE(ec_util::validate_frame(&invalid_frame));
}

// Test frame initialization
TEST_F(ECUtilAttributeTest, FrameInitialization) {
    // Create a new frame
    ec_frame_t test_frame;
    
    // Initialize it
    ec_util::init_frame(&test_frame);
    
    // Verify initialization
    EXPECT_EQ(test_frame.category, 0x04);
    EXPECT_EQ(test_frame.action, 0x09);
    EXPECT_EQ(test_frame.oui[0], 0x50);
    EXPECT_EQ(test_frame.oui[1], 0x6f);
    EXPECT_EQ(test_frame.oui[2], 0x9a);
    EXPECT_EQ(test_frame.oui_type, DPP_OUI_TYPE);
    EXPECT_EQ(test_frame.crypto_suite, 0x01);
    EXPECT_EQ(test_frame.frame_type, 0); // Should be initialized to 0
}

// Test attribute reallocation
TEST_F(ECUtilAttributeTest, AttributeReallocation) {
    size_t buffer_len = 0;
    
    // Add a bunch of large attributes to trigger reallocations
    const int NUM_ATTRS = sizeof(all_ec_attribute_ids) / sizeof(all_ec_attribute_ids[0]);
    const size_t LARGE_ATTR_SIZE = 1024;
    
    // Create a large data buffer
    std::unique_ptr<uint8_t[]> large_data(new uint8_t[LARGE_ATTR_SIZE]);
    for (size_t i = 0; i < LARGE_ATTR_SIZE; i++) {
        large_data[i] = static_cast<uint8_t>(i % 256);
    }
    
    // Add multiple large attributes
    for (int i = 0; i < NUM_ATTRS; i++) {
        // Use different attribute types by cycling through some valid ones
        ec_attrib_id_t id = all_ec_attribute_ids[i];
        
        buffer = ec_util::add_attrib(buffer, &buffer_len, id, LARGE_ATTR_SIZE, large_data.get());
        ASSERT_NE(buffer, nullptr) << "Failed to add large attribute " << i;
    }
    
    // Verify total buffer size
    size_t expected_size = NUM_ATTRS * (offsetof(ec_net_attribute_t, data) + LARGE_ATTR_SIZE);
    EXPECT_EQ(buffer_len, expected_size);
    
    // Verify we can still retrieve attributes
    for (int i = 0; i < NUM_ATTRS; i++) {
        ec_attrib_id_t id = all_ec_attribute_ids[i];
        auto attr = ec_util::get_attrib(buffer, buffer_len, id);
        
        // We may have overwritten some attributes when cycling through IDs
        if (attr.has_value()) {
            EXPECT_EQ(attr->attr_id, id);
            EXPECT_EQ(attr->length, LARGE_ATTR_SIZE);
            // Check a few values in the buffer
            EXPECT_EQ(attr->data[0], 0);
            EXPECT_EQ(attr->data[10], 10 % 256);
            EXPECT_EQ(attr->data[100], 100 % 256);
        }
    }
    
}
