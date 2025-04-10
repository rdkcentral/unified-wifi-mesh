#include <gtest/gtest.h>
#include <string.h>
#include <vector>
#include "aes_siv.h"

class AESSIVTest : public ::testing::Test {
protected:
    void SetUp() override {
    }

    void TearDown() override {
    }

    // Helper to create mock key bytes of different sizes
    std::vector<uint8_t> create_key(size_t keySizeBits) {
        std::vector<uint8_t> key(keySizeBits / 8, 0);
        for (size_t i = 0; i < key.size(); i++) {
            key[i] = static_cast<uint8_t>(i & 0xFF);
        }
        return key;
    }

    // Helper to compare buffers
    bool cmp_buff(const uint8_t* a, const uint8_t* b, size_t len) {
        return memcmp(a, b, len) == 0;
    }
};

// Test basic encryption and decryption with no associated data
TEST_F(AESSIVTest, BasicEncryptionDecryption) {
    siv_ctx ctx;
    
    // Create a 256-bit key (two 128-bit keys)
    std::vector<uint8_t> key = create_key(SIV_256);
    ASSERT_EQ(siv_init(&ctx, key.data(), SIV_256), 1);
    
    // Plaintext to encrypt
    const char* plaintext = "This is a test message for SIV mode.";
    size_t plaintext_len = strlen(plaintext);
    
    // Buffers for encrypted data and tag
    uint8_t ciphertext[100];
    uint8_t tag[AES_BLOCK_SIZE];
    
    // Encrypt
    ASSERT_EQ(siv_encrypt(&ctx, 
                          reinterpret_cast<const uint8_t*>(plaintext), 
                          ciphertext,
                          static_cast<int>(plaintext_len), 
                          tag, 
                          0), 1);
    
    // Buffer for decrypted data
    uint8_t decrypted[100];
    
    // Decrypt
    ASSERT_EQ(siv_decrypt(&ctx, 
                          ciphertext, 
                          decrypted, 
                          static_cast<int>(plaintext_len), 
                          tag, 
                          0), 1);
    
    // Verify decryption worked
    ASSERT_TRUE(cmp_buff(reinterpret_cast<const uint8_t*>(plaintext), 
                               decrypted, 
                               plaintext_len));
}

// Test with associated data
TEST_F(AESSIVTest, EncryptionWithAssociatedData) {
    siv_ctx ctx;
    
    // Create a 256-bit key
    std::vector<uint8_t> key = create_key(SIV_256);
    ASSERT_EQ(siv_init(&ctx, key.data(), SIV_256), 1);
    
    // Plaintext
    const char* plaintext = "Secret message";
    size_t plaintext_len = strlen(plaintext);
    
    // Associated data
    const char* ad1 = "Header information";
    size_t ad1_len = strlen(ad1);
    const char* ad2 = "More context";
    size_t ad2_len = strlen(ad2);
    
    // Buffers for encrypted data and tag
    uint8_t ciphertext[100];
    uint8_t tag[AES_BLOCK_SIZE];
    
    // Encrypt with two associated data fields
    ASSERT_EQ(siv_encrypt(&ctx, 
                          reinterpret_cast<const uint8_t*>(plaintext), 
                          ciphertext,
                          static_cast<int>(plaintext_len), 
                          tag, 
                          2, 
                          ad1, static_cast<int>(ad1_len), 
                          ad2, static_cast<int>(ad2_len)), 1);
    
    // Buffer for decrypted data
    uint8_t decrypted[100];
    
    // Decrypt with same associated data
    ASSERT_EQ(siv_decrypt(&ctx, 
                          ciphertext, 
                          decrypted, 
                          static_cast<int>(plaintext_len), 
                          tag,
                          2, 
                          ad1, static_cast<int>(ad1_len), 
                          ad2, static_cast<int>(ad2_len)), 1);
    
    // Verify decryption worked
    ASSERT_TRUE(cmp_buff(reinterpret_cast<const uint8_t*>(plaintext), 
                               decrypted, 
                               plaintext_len));
}

// Test with different key sizes
TEST_F(AESSIVTest, DifferentKeySizes) {
    siv_ctx ctx;
    const char* plaintext = "Testing different key sizes";
    size_t plaintext_len = strlen(plaintext);
    uint8_t ciphertext[100];
    uint8_t tag[AES_BLOCK_SIZE];
    uint8_t decrypted[100];
    
    // Test with 256-bit key (two 128-bit keys)
    {
        std::vector<uint8_t> key = create_key(SIV_256);
        ASSERT_EQ(siv_init(&ctx, key.data(), SIV_256), 1);
        ASSERT_EQ(siv_encrypt(&ctx, 
                              reinterpret_cast<const uint8_t*>(plaintext), 
                              ciphertext,
                              static_cast<int>(plaintext_len), 
                              tag, 
                              0), 1);
        ASSERT_EQ(siv_decrypt(&ctx, 
                              ciphertext, 
                              decrypted,
                              static_cast<int>(plaintext_len), 
                              tag, 
                              0), 1);
        ASSERT_TRUE(cmp_buff(reinterpret_cast<const uint8_t*>(plaintext), 
                                   decrypted, 
                                   plaintext_len));
    }
    
    // Test with 384-bit key (two 192-bit keys)
    {
        std::vector<uint8_t> key = create_key(SIV_384);
        ASSERT_EQ(siv_init(&ctx, key.data(), SIV_384), 1);
        ASSERT_EQ(siv_encrypt(&ctx, 
                              reinterpret_cast<const uint8_t*>(plaintext), 
                              ciphertext,
                              static_cast<int>(plaintext_len), 
                              tag, 
                              0), 1);
        ASSERT_EQ(siv_decrypt(&ctx, 
                              ciphertext, 
                              decrypted, 
                              static_cast<int>(plaintext_len), 
                              tag, 
                              0), 1);
        ASSERT_TRUE(cmp_buff(reinterpret_cast<const uint8_t*>(plaintext), 
                                   decrypted, 
                                   plaintext_len));
    }
    
    // Test with 512-bit key (two 256-bit keys)
    {
        std::vector<uint8_t> key = create_key(SIV_512);
        ASSERT_EQ(siv_init(&ctx, key.data(), SIV_512), 1);
        ASSERT_EQ(siv_encrypt(&ctx, 
                              reinterpret_cast<const uint8_t*>(plaintext), 
                              ciphertext,
                              static_cast<int>(plaintext_len), 
                              tag, 
                              0), 1);
        ASSERT_EQ(siv_decrypt(&ctx, 
                              ciphertext, 
                              decrypted, 
                              static_cast<int>(plaintext_len), 
                              tag, 
                              0), 1);
        ASSERT_TRUE(cmp_buff(reinterpret_cast<const uint8_t*>(plaintext), 
                                   decrypted, 
                                   plaintext_len));
    }
    
    // Test with invalid key size
    {
        std::vector<uint8_t> key = create_key(128); // Invalid size (not SIV_256/384/512)
        ASSERT_EQ(siv_init(&ctx, key.data(), 128), -1); // Should return error
    }
}

// Test tampering detection
TEST_F(AESSIVTest, TamperingDetection) {
    siv_ctx ctx;
    
    // Create a 256-bit key
    std::vector<uint8_t> key = create_key(SIV_256);
    ASSERT_EQ(siv_init(&ctx, key.data(), SIV_256), 1);
    
    // Plaintext
    const char* plaintext = "Message that should not be tampered with";
    size_t plaintext_len = strlen(plaintext);
    
    // Associated data
    const char* ad = "Associated metadata";
    size_t ad_len = strlen(ad);
    
    // Buffers for encrypted data and tag
    uint8_t ciphertext[100];
    uint8_t tag[AES_BLOCK_SIZE];
    uint8_t decrypted[100];
    
    // Encrypt
    ASSERT_EQ(siv_encrypt(&ctx, 
                          reinterpret_cast<const uint8_t*>(plaintext), 
                          ciphertext,
                          static_cast<int>(plaintext_len), 
                          tag, 
                          1, 
                          ad, static_cast<int>(ad_len)), 1);
    
    // Test 1: Tamper with ciphertext
    uint8_t tampered_ciphertext[100];
    memcpy(tampered_ciphertext, ciphertext, plaintext_len);
    tampered_ciphertext[0] ^= 0x01; // Flip a bit
    
    // Decrypt should fail
    ASSERT_EQ(siv_decrypt(&ctx, 
                          tampered_ciphertext, 
                          decrypted, 
                          static_cast<int>(plaintext_len), 
                          tag,
                          1, 
                          ad, static_cast<int>(ad_len)), -1);
    
    // Test 2: Tamper with tag
    uint8_t tampered_tag[AES_BLOCK_SIZE];
    memcpy(tampered_tag, tag, AES_BLOCK_SIZE);
    tampered_tag[0] ^= 0x01; // Flip a bit
    
    // Decrypt should fail
    ASSERT_EQ(siv_decrypt(&ctx, 
                          ciphertext, 
                          decrypted, 
                          static_cast<int>(plaintext_len), 
                          tampered_tag,
                          1, 
                          ad, static_cast<int>(ad_len)), -1);
    
    // Test 3: Tamper with associated data
    const char* tampered_ad = "Associaked metadata"; // Note the typo
    size_t tampered_ad_len = strlen(tampered_ad);
    
    // Decrypt should fail
    ASSERT_EQ(siv_decrypt(&ctx, 
                          ciphertext, 
                          decrypted, 
                          static_cast<int>(plaintext_len), 
                          tag,
                          1, 
                          tampered_ad, static_cast<int>(tampered_ad_len)), -1);
}

// Test empty message
TEST_F(AESSIVTest, EmptyMessage) {
    siv_ctx ctx;
    
    // Create a 256-bit key
    std::vector<uint8_t> key = create_key(SIV_256);
    ASSERT_EQ(siv_init(&ctx, key.data(), SIV_256), 1);
    
    // Empty plaintext
    const char* plaintext = "";
    size_t plaintext_len = 0;
    
    // Associated data
    const char* ad = "Associated data with empty message";
    size_t ad_len = strlen(ad);
    
    // Buffers for encrypted data and tag
    uint8_t ciphertext[100];
    uint8_t tag[AES_BLOCK_SIZE];
    
    // Encrypt
    ASSERT_EQ(siv_encrypt(&ctx, 
                          reinterpret_cast<const uint8_t*>(plaintext), 
                          ciphertext,
                          static_cast<int>(plaintext_len), 
                          tag, 
                          1, 
                          ad, static_cast<int>(ad_len)), 1);
    
    // Buffer for decrypted data
    uint8_t decrypted[100];
    
    // Decrypt
    ASSERT_EQ(siv_decrypt(&ctx, 
                          ciphertext, 
                          decrypted, 
                          static_cast<int>(plaintext_len), 
                          tag,
                          1, 
                          ad, static_cast<int>(ad_len)), 1);
    
    // Verify decryption worked (nothing to compare for empty message)
}

// Test multiple encryption/decryption operations with same context
TEST_F(AESSIVTest, MultipleOperations) {
    siv_ctx ctx;
    
    // Create a 256-bit key
    std::vector<uint8_t> key = create_key(SIV_256);
    ASSERT_EQ(siv_init(&ctx, key.data(), SIV_256), 1);
    
    // First message
    const char* plaintext1 = "First message";
    size_t plaintext1_len = strlen(plaintext1);
    uint8_t ciphertext1[100];
    uint8_t tag1[AES_BLOCK_SIZE];
    
    // Second message
    const char* plaintext2 = "Second message with different content";
    size_t plaintext2_len = strlen(plaintext2);
    uint8_t ciphertext2[100];
    uint8_t tag2[AES_BLOCK_SIZE];
    
    // Encrypt first message
    ASSERT_EQ(siv_encrypt(&ctx, 
                          reinterpret_cast<const uint8_t*>(plaintext1), 
                          ciphertext1,
                          static_cast<int>(plaintext1_len), 
                          tag1, 
                          0), 1);
    
    // Encrypt second message with same context
    ASSERT_EQ(siv_encrypt(&ctx, 
                          reinterpret_cast<const uint8_t*>(plaintext2), 
                          ciphertext2,
                          static_cast<int>(plaintext2_len), 
                          tag2, 
                          0), 1);
    
    // Buffers for decrypted data
    uint8_t decrypted1[100];
    uint8_t decrypted2[100];
    
    // Decrypt both messages
    ASSERT_EQ(siv_decrypt(&ctx, 
                          ciphertext1, 
                          decrypted1, 
                          static_cast<int>(plaintext1_len), 
                          tag1, 
                          0), 1);
    ASSERT_EQ(siv_decrypt(&ctx, 
                          ciphertext2, 
                          decrypted2, 
                          static_cast<int>(plaintext2_len), 
                          tag2, 
                          0), 1);
    
    // Verify both decryptions worked
    ASSERT_TRUE(cmp_buff(reinterpret_cast<const uint8_t*>(plaintext1), 
                               decrypted1, 
                               plaintext1_len));
    ASSERT_TRUE(cmp_buff(reinterpret_cast<const uint8_t*>(plaintext2), 
                               decrypted2, 
                               plaintext2_len));
}

// Test with large message (multiple blocks)
TEST_F(AESSIVTest, LargeMessage) {
    siv_ctx ctx;
    
    // Create a 256-bit key
    std::vector<uint8_t> key = create_key(SIV_256);
    ASSERT_EQ(siv_init(&ctx, key.data(), SIV_256), 1);
    
    // Create a large plaintext (multiple AES blocks)
    std::vector<uint8_t> plaintext(1000);
    for (size_t i = 0; i < plaintext.size(); i++) {
        plaintext[i] = static_cast<uint8_t>(i & 0xFF);
    }
    
    // Buffers for encrypted data and tag
    std::vector<uint8_t> ciphertext(plaintext.size());
    uint8_t tag[AES_BLOCK_SIZE];
    
    // Encrypt
    ASSERT_EQ(siv_encrypt(&ctx, 
                          plaintext.data(), 
                          ciphertext.data(),
                          static_cast<int>(plaintext.size()), 
                          tag, 
                          0), 1);
    
    // Buffer for decrypted data
    std::vector<uint8_t> decrypted(plaintext.size());
    
    // Decrypt
    ASSERT_EQ(siv_decrypt(&ctx, 
                          ciphertext.data(), 
                          decrypted.data(),
                          static_cast<int>(plaintext.size()), 
                          tag, 
                          0), 1);
    
    // Verify decryption worked
    ASSERT_TRUE(cmp_buff(plaintext.data(), decrypted.data(), plaintext.size()));
}

// Test with many associated data fields
TEST_F(AESSIVTest, ManyAssociatedDataFields) {
    siv_ctx ctx;
    
    // Create a 256-bit key
    std::vector<uint8_t> key = create_key(SIV_256);
    ASSERT_EQ(siv_init(&ctx, key.data(), SIV_256), 1);
    
    // Plaintext
    const char* plaintext = "Protected message";
    size_t plaintext_len = strlen(plaintext);
    
    // Multiple associated data fields
    const char* ad1 = "Header";
    size_t ad1_len = strlen(ad1);
    const char* ad2 = "Metadata";
    size_t ad2_len = strlen(ad2);
    const char* ad3 = "Additional context";
    size_t ad3_len = strlen(ad3);
    const char* ad4 = "Even more data";
    size_t ad4_len = strlen(ad4);
    
    // Buffers for encrypted data and tag
    uint8_t ciphertext[100];
    uint8_t tag[AES_BLOCK_SIZE];
    
    // Encrypt with four associated data fields
    ASSERT_EQ(siv_encrypt(&ctx, 
                          reinterpret_cast<const uint8_t*>(plaintext), 
                          ciphertext,
                          static_cast<int>(plaintext_len), 
                          tag, 
                          4,
                          ad1, static_cast<int>(ad1_len), 
                          ad2, static_cast<int>(ad2_len), 
                          ad3, static_cast<int>(ad3_len), 
                          ad4, static_cast<int>(ad4_len)), 1);
    
    // Buffer for decrypted data
    uint8_t decrypted[100];
    
    // Decrypt with same associated data fields
    ASSERT_EQ(siv_decrypt(&ctx, 
                          ciphertext, 
                          decrypted, 
                          static_cast<int>(plaintext_len), 
                          tag, 
                          4,
                          ad1, static_cast<int>(ad1_len), 
                          ad2, static_cast<int>(ad2_len), 
                          ad3, static_cast<int>(ad3_len), 
                          ad4, static_cast<int>(ad4_len)), 1);
    
    // Verify decryption worked
    ASSERT_TRUE(cmp_buff(reinterpret_cast<const uint8_t*>(plaintext), 
                               decrypted, 
                               plaintext_len));
    
    // Decrypt with missing/different associated data should fail
    ASSERT_EQ(siv_decrypt(&ctx, 
                          ciphertext, 
                          decrypted, 
                          static_cast<int>(plaintext_len), 
                          tag, 
                          3,
                          ad1, static_cast<int>(ad1_len), 
                          ad2, static_cast<int>(ad2_len), 
                          ad3, static_cast<int>(ad3_len)), -1);
}
