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
#include "test_utils.h"
#include "util.h"

class EmCryptoTests : public ::testing::Test {
protected:
    static void SetUpTestSuite()
    {
        // Print OpenSSL Version Information
        printf("OpenSSL Version: %s\n", OpenSSL_version(OPENSSL_VERSION));
        printf("OpenSSL Version Number: 0x%lx\n", OPENSSL_VERSION_NUMBER);
    }

    void SetUp() override
    {

    }

    void TearDown() override
    {
    }

    // CONSTANTS

    const std::string basic_base64_test_str = "Hello+Mesh/World";

    /*
    JWS Data fetched from EasyConnect 4.2.2 (Figures 13, 14, and 15)
    */
    const std::string test_jws_body_data = util::remove_whitespace(R"({
        "groups":
        [
            {"groupId":"home","netRole":"sta"},
            {"groupId":"cottage","netRole":"sta"}
        ],
        "netAccessKey":
        {
            "kty":"EC",
            "crv":"P-256",
            "x":"Xj-zV2iEiH8XwyA9ijpsL6xyLvDiIBthrHO8ZVxwmpA",
            "y":"LUsDBmn7nv-LCnn6fBoXKsKpLGJiVpY_knTckGgsgeU"
        },
        "expiry":"2019-01-31T22:00:00+02:00"
    })");

    // Taken from "netAccessKey" above
    // These are the same as the Protocol Key in EasyConnect Appendix B.1 (Responder Values)
    const std::string test_sig_curve = "P-256";
    const std::string test_sig_x = "Xj-zV2iEiH8XwyA9ijpsL6xyLvDiIBthrHO8ZVxwmpA";
    const std::string test_sig_y = "LUsDBmn7nv-LCnn6fBoXKsKpLGJiVpY_knTckGgsgeU";
    // Taken Specifically from Appendix B.1
    const std::vector<uint8_t> test_priv_proto_key = {
        0xf7, 0x98, 0xed, 0x2e, 0x19, 0x28, 0x6f, 0x6a, 0x6e, 0xfe, 0x21,
        0x0b, 0x18, 0x63, 0xba, 0xdb, 0x99, 0xaf, 0x2a, 0x14, 0xb4, 0x97,
        0x63, 0x4d, 0xbf, 0xd2, 0xa9, 0x73, 0x94, 0xfb, 0x5a, 0xa5};

    const std::string test_enc_jws_body =
        "eyJncm91cHMiOlt7Imdyb3VwSWQiOiJob21lIiwibmV0Um9sZSI6InN0YSJ9LHsiZ3JvdXBJZCI6ImNvdHRh"
        "Z2UiLCJuZXRSb2xlIjoic3RhIn1dLCJuZXRBY2Nlc3NLZXkiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIs"
        "IngiOiJYai16VjJpRWlIOFh3eUE5aWpwc0w2eHlMdkRpSUJ0aHJITzhaVnh3bXBBIiwieSI6IkxVc0RCbW43"
        "bnYtTENubjZmQm9YS3NLcExHSmlWcFlfa25UY2tHZ3NnZVUifSwiZXhwaXJ5IjoiMjAxOS0wMS0zMVQyMjow"
        "MDowMCswMjowMCJ9";

    const std::string test_jws_header_data = util::remove_whitespace(R"({
        "typ":"dppCon",
        "kid":"kMcegDBPmNZVakAsBZOzOoCsvQjkr_nEAp9uF-EDmVE",
        "alg":"ES256"
    })");

    const std::string test_jws_header = "eyJ0eXAiOiJkcHBDb24iLCJraWQiOiJrTWNlZ0RCUG1OWlZha0FzQlpPek"
                                        "9vQ3N2UWprcl9uRUFwOXVGLUVEbVZFIiwiYWxnIjoiRVMyNTYifQ";

    const std::string jws_sig =
        "8fJSNCpDjv5BEFfmlqEbBNTaHx2L6c_22Uvr9KYjtAw88VfvEUWiruECUSJCUVFqv1yDEE4RJVdTIw3aUDhlMw";
};

TEST_F(EmCryptoTests, Base64UrlDecode)
{
    std::string test_data = "SGVsbG8rTWVzaC9Xb3JsZA";
    auto data = em_crypto_t::base64url_decode(test_data);
    EXPECT_NE(data, std::nullopt);
    EXPECT_EQ(data->size(), basic_base64_test_str.length());
    EXPECT_EQ(std::string(reinterpret_cast<char *>(data->data())), basic_base64_test_str);
}

TEST_F(EmCryptoTests, Base64UrlEncode)
{
    std::string result = em_crypto_t::base64url_encode(basic_base64_test_str);
    EXPECT_EQ(result, "SGVsbG8rTWVzaC9Xb3JsZA");
}

TEST_F(EmCryptoTests, Base64Decode)
{
    std::string test_data = "SGVsbG8rTWVzaC9Xb3JsZA==";
    auto data = em_crypto_t::base64url_decode(test_data);
    EXPECT_NE(data, std::nullopt);
    EXPECT_EQ(data->size(), basic_base64_test_str.length());
    EXPECT_EQ(std::string(reinterpret_cast<char *>(data->data())), basic_base64_test_str);
}

TEST_F(EmCryptoTests, Base64Encode)
{
    std::string result = em_crypto_t::base64_encode(basic_base64_test_str);
    EXPECT_EQ(result, "SGVsbG8rTWVzaC9Xb3JsZA==");
}

TEST_F(EmCryptoTests, EncodeJWSHeader)
{
    cJSON *jws_header = cJSON_Parse(test_jws_header_data.c_str());
    EXPECT_NE(jws_header, nullptr);

    char *jws_cstr = cJSON_PrintUnformatted(jws_header);
    std::string jws_str(jws_cstr);
    free(jws_cstr);
    cJSON_Delete(jws_header);
    std::string result = em_crypto_t::base64url_encode(jws_str);

    EXPECT_EQ(result, test_jws_header);
}

TEST_F(EmCryptoTests, EncodeJWSPayload)
{
    cJSON *jws_body = cJSON_Parse(test_jws_body_data.c_str());
    EXPECT_NE(jws_body, nullptr);

    char *jws_cstr = cJSON_PrintUnformatted(jws_body);
    std::string jws_str(jws_cstr);
    free(jws_cstr);
    cJSON_Delete(jws_body);
    std::string result = em_crypto_t::base64url_encode(jws_str);

    EXPECT_EQ(result, test_enc_jws_body);
}

TEST_F(EmCryptoTests, DecodeJWSHeader)
{
    auto data = em_crypto_t::base64url_decode(test_jws_header);
    EXPECT_NE(data, std::nullopt);
    EXPECT_EQ(data->size(), test_jws_header_data.length());
    EXPECT_EQ(std::string(reinterpret_cast<char *>(data->data())), test_jws_header_data);
}

TEST_F(EmCryptoTests, DecodeJWSPayload)
{
    auto data = em_crypto_t::base64url_decode(test_enc_jws_body);
    EXPECT_NE(data, std::nullopt);
    EXPECT_EQ(data->size(), test_jws_body_data.length());
    EXPECT_EQ(std::string(reinterpret_cast<char *>(data->data())), test_jws_body_data);
}

TEST_F(EmCryptoTests, SignJWSConnector)
{

    const auto sig_x = em_crypto_t::base64url_decode(test_sig_x);
    ASSERT_NE(sig_x, std::nullopt);
    const auto sig_y = em_crypto_t::base64url_decode(test_sig_y);
    ASSERT_NE(sig_y, std::nullopt);

    const auto opt_test = std::make_optional<std::vector<uint8_t>>(test_priv_proto_key);

    int nid = EC_curve_nist2nid(test_sig_curve.c_str());
    ASSERT_EQ(nid, NID_X9_62_prime256v1) << "Invalid curve name for test";

    scoped_ec_group curv_group(EC_GROUP_new_by_curve_name(nid));
    scoped_ssl_key signing_key(em_crypto_t::create_ec_key_from_coordinates(curv_group.get(), *sig_x, *sig_y, opt_test));
    ASSERT_NE(signing_key.get(), nullptr);

    printf("Signing Key\n");
    #if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (EVP_PKEY_print_public_fp(stdout, signing_key.get(), 0, NULL) < 1) {
        auto err = ERR_get_error();
        printf("Failed to print public key: %s\n", ERR_error_string(err, NULL));
    }
    if (EVP_PKEY_print_private_fp(stdout, signing_key.get(), 0, NULL) < 1) {
        auto err = ERR_get_error();
        printf("Failed to print private key: %s\n", ERR_error_string(err, NULL));
    }
#else
    // Convert EC_KEY to EVP_PKEY
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        auto err = ERR_get_error();
        printf("Failed to create EVP_PKEY: %s\n", ERR_error_string(err, NULL));
        return;
    }
    
    if (EVP_PKEY_set1_EC_KEY(pkey, signing_key.get()) != 1) {
        auto err = ERR_get_error();
        EVP_PKEY_free(pkey);
        ASSERT_TRUE(false) << "Failed to assign EC_KEY to EVP_PKEY: " << ERR_error_string(err, NULL); 
    }
    
    // Use BIO
    BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (bio == NULL) {
        auto err = ERR_get_error();
        EVP_PKEY_free(pkey);
        ASSERT_TRUE(false) << "Failed to create BIO: " << ERR_error_string(err, NULL); 
    }
    
    if (EVP_PKEY_print_public(bio, pkey, 0, NULL) < 1) {
        auto err = ERR_get_error();
        printf("Failed to print public key: %s\n", ERR_error_string(err, NULL));
    }
    
    if (EVP_PKEY_print_private(bio, pkey, 0, NULL) < 1) {
        auto err = ERR_get_error();
        printf("Failed to print private key: %s\n", ERR_error_string(err, NULL));
    }
    
    BIO_free(bio);
    EVP_PKEY_free(pkey); 
#endif


    // Get JWS Header and Payload as Strings
    cJSON *jws_header = cJSON_Parse(test_jws_header_data.c_str());
    EXPECT_NE(jws_header, nullptr);

    cJSON *jws_body = cJSON_Parse(test_jws_body_data.c_str());
    EXPECT_NE(jws_body, nullptr);

    char *jws_header_cstr = cJSON_PrintUnformatted(jws_header);
    std::string jws_header_str(jws_header_cstr);
    free(jws_header_cstr);
    cJSON_Delete(jws_header);

    char *jws_body_cstr = cJSON_PrintUnformatted(jws_body);
    std::string jws_body_str(jws_body_cstr);
    free(jws_body_cstr);
    cJSON_Delete(jws_body);

    // Convert strings to base64url encoding
    std::string jws_header_enc = em_crypto_t::base64url_encode(jws_header_str);
    std::string jws_body_enc = em_crypto_t::base64url_encode(jws_body_str);

    // Concatenate using standard seperator and sign
    std::string data = jws_header_enc + "." + jws_body_enc;
    std::vector<uint8_t> data_vec(data.begin(), data.end());

    // JWS Signature (sig)
    auto sig = em_crypto_t::sign_data_ecdsa(data_vec, signing_key.get(), EVP_sha256());
    ASSERT_NE(sig, std::nullopt) << "Failed to sign data, 'sig' could not be generated";

    // Verify that the signature was generated correctly.
    bool did_verify = em_crypto_t::verify_signature(data_vec, *sig, signing_key.get(), EVP_sha256());
    EXPECT_TRUE(did_verify) << "Failed to verify signature (sig)";
}

// Test case for key generation with different curves
TEST_F(EmCryptoTests, GenerateEcKeyWithDifferentCurves)
{
    // Test with different curves
    int curves[] = {NID_secp256k1, NID_secp384r1, NID_secp521r1};
    const char *curve_names[] = {"secp256k1", "secp384r1", "secp521r1"};

    for (int i = 0; i < 3; i++) {
        // Generate key
        scoped_ssl_key key(em_crypto_t::generate_ec_key(curves[i]));
        ASSERT_NE(key.get(), nullptr) << "Could not generate key for " << curve_names[i];

        // Get key group
        scoped_ec_group group(em_crypto_t::get_key_group(key.get()));
        ASSERT_NE(group.get(), nullptr) << "Could not get key group for " << curve_names[i];

        int curve_nid = EC_GROUP_get_curve_name(group.get());
        EXPECT_EQ(curve_nid, curves[i]) << "Generated key has wrong curve for " << curve_names[i];

        // Get private key
        scoped_bn priv(em_crypto_t::get_priv_key_bn(key.get()));
        ASSERT_NE(priv.get(), nullptr) << "Could not get private key for " << curve_names[i];

        // Get public key point
        scoped_ec_point pub(em_crypto_t::get_pub_key_point(key.get(), group.get()));
        ASSERT_NE(pub.get(), nullptr) << "Could not get public key point for " << curve_names[i];
    }
}

// Test case for key components consistency
TEST_F(EmCryptoTests, KeyComponentsConsistency)
{
    // Generate a key for testing
    scoped_ssl_key key(em_crypto_t::generate_ec_key(NID_secp256k1));
    ASSERT_NE(key.get(), nullptr) << "Could not generate key";

    // Create BN_CTX for calculations - this helps manage internal allocations
    BN_CTX* bn_ctx = BN_CTX_new();
    ASSERT_NE(bn_ctx, nullptr) << "Could not create BN_CTX";

    BN_CTX_start(bn_ctx);

    // Get components
    scoped_ec_group group(em_crypto_t::get_key_group(key.get()));
    ASSERT_NE(group.get(), nullptr) << "Could not get key group";

    scoped_bn priv(em_crypto_t::get_priv_key_bn(key.get()));
    ASSERT_NE(priv.get(), nullptr) << "Could not get private key";

    scoped_ec_point pub(em_crypto_t::get_pub_key_point(key.get(), group.get()));
    ASSERT_NE(pub.get(), nullptr) << "Could not get public key point";

    // Verify private key can generate the same public key point
    scoped_ec_point computed_pub(EC_POINT_new(group.get()));
    ASSERT_NE(computed_pub.get(), nullptr) << "Could not create new EC_POINT";

    ASSERT_TRUE(
        EC_POINT_mul(group.get(), computed_pub.get(), priv.get(), nullptr, nullptr, bn_ctx))
        << "Could not compute public key from private key";

    // Compare the public key points
    EXPECT_EQ(EC_POINT_cmp(group.get(), pub.get(), computed_pub.get(), bn_ctx), 0)
        << "Computed public key doesn't match the original";

    // End BN_CTX to free temporary BIGNUMs
    BN_CTX_end(bn_ctx); 
    BN_CTX_free(bn_ctx);
}


TEST_F(EmCryptoTests, ECKeyDERSerialization)
{
    // Generate a key for testing
    scoped_ssl_key key(em_crypto_t::generate_ec_key(NID_secp256k1));
    ASSERT_NE(key.get(), nullptr) << "Could not generate key";

    std::string base64_der = em_crypto_t::ec_key_to_base64_der(key.get());
    ASSERT_FALSE(base64_der.empty()) << "Could not convert key to base64 DER";

    scoped_ssl_key new_key(em_crypto_t::ec_key_from_base64_der(base64_der));
    ASSERT_NE(new_key.get(), nullptr) << "Could not read key from base64 DER";

    // Get new components
    scoped_ec_group new_group(em_crypto_t::get_key_group(new_key.get()));
    ASSERT_NE(new_group.get(), nullptr) << "Could not get key group";
    int curve_nid = EC_GROUP_get_curve_name(new_group.get());
    EXPECT_EQ(curve_nid, NID_secp256k1) << "Read key has wrong curve";
    scoped_ec_point new_pub(em_crypto_t::get_pub_key_point(new_key.get(), new_group.get()));
    ASSERT_NE(new_pub.get(), nullptr) << "Could not get public key point";

    // Get original components

    scoped_ec_group orig_group(em_crypto_t::get_key_group(key.get()));
    ASSERT_NE(orig_group.get(), nullptr) << "Could not get original key group";

    scoped_ec_point orig_pub(em_crypto_t::get_pub_key_point(key.get(), orig_group.get()));
    ASSERT_NE(orig_pub.get(), nullptr) << "Could not get original public key point";

    // Compare the public key points
    EXPECT_EQ(EC_POINT_cmp(new_group.get(), new_pub.get(), orig_pub.get(), nullptr), 0)
        << "Computed public key doesn't match the original after serialization/deserialization";
}

TEST_F(EmCryptoTests, ECKeyDERForwardReverseSerialization)
{
    // Generate a key for testing
    scoped_ssl_key key(em_crypto_t::generate_ec_key(NID_secp256k1));
    ASSERT_NE(key.get(), nullptr) << "Could not generate key";

    std::string base64_der = em_crypto_t::ec_key_to_base64_der(key.get());
    ASSERT_FALSE(base64_der.empty()) << "Could not convert key to base64 DER";

    scoped_ssl_key new_key(em_crypto_t::ec_key_from_base64_der(base64_der));
    ASSERT_NE(new_key.get(), nullptr) << "Could not read key from base64 DER";

    std::string new_base64_der = em_crypto_t::ec_key_to_base64_der(new_key.get());
    ASSERT_FALSE(new_base64_der.empty()) << "Could not convert new key to base64 DER";

    // Compare the original and new base64 DER strings
    EXPECT_EQ(base64_der, new_base64_der) << "Base64 DER serialization did not match after forward and reverse serialization";
}


// Test case for key serialization
TEST_F(EmCryptoTests, KeySerialization)
{
    // Generate a key for testing
    scoped_ssl_key key(em_crypto_t::generate_ec_key(NID_secp256k1));
    ASSERT_NE(key.get(), nullptr) << "Could not generate key";

    // Serialize the key to PEM format
    scoped_bio bio(BIO_new(BIO_s_mem()));
    ASSERT_NE(bio.get(), nullptr) << "Could not create BIO";

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    ASSERT_TRUE(PEM_write_bio_ECPrivateKey(bio.get(), key.get(), NULL, NULL, 0, NULL, NULL))
        << "Could not write EC key to PEM";
#else
    ASSERT_TRUE(PEM_write_bio_PrivateKey(bio.get(), key.get(), NULL, NULL, 0, NULL, NULL))
        << "Could not write EVP key to PEM";
#endif

    // Get the private key as a BIGNUM for comparison
    scoped_bn orig_priv(em_crypto_t::get_priv_key_bn(key.get()));
    ASSERT_NE(orig_priv.get(), nullptr) << "Could not get original private key";

    // Convert BIGNUM to hex string
    scoped_buff orig_priv_hex(reinterpret_cast<uint8_t *>(BN_bn2hex(orig_priv.get())));
    ASSERT_NE(orig_priv_hex.get(), nullptr) << "Could not convert original private key to hex";

    // Get the serialized data
    BUF_MEM *mem = NULL;
    BIO_get_mem_ptr(bio.get(), &mem);
    std::string pem_data(mem->data, mem->length);

    // Reset resources before creating new ones
    key.reset();
    bio.reset();

    // Deserialize the key
    bio.reset(BIO_new_mem_buf(pem_data.c_str(), static_cast<int>(pem_data.length())));
    ASSERT_NE(bio.get(), nullptr) << "Could not create BIO for reading PEM";

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    key.reset(PEM_read_bio_ECPrivateKey(bio.get(), NULL, NULL, NULL));
#else
    key.reset(PEM_read_bio_PrivateKey(bio.get(), NULL, NULL, NULL));
#endif

    ASSERT_NE(key.get(), nullptr) << "Could not read key from PEM";

    // Get the private key and convert to hex for comparison
    scoped_bn new_priv(em_crypto_t::get_priv_key_bn(key.get()));
    ASSERT_NE(new_priv.get(), nullptr) << "Could not get deserialized private key";

    scoped_buff new_priv_hex(reinterpret_cast<uint8_t *>(BN_bn2hex(new_priv.get())));
    ASSERT_NE(new_priv_hex.get(), nullptr) << "Could not convert deserialized private key to hex";

    // Compare the private keys
    EXPECT_STREQ(reinterpret_cast<char *>(orig_priv_hex.get()),
                 reinterpret_cast<char *>(new_priv_hex.get()))
        << "Deserialized private key doesn't match the original";
}

// Test case for key components consistency
TEST_F(EmCryptoTests, TestKeyReading)
{
    // Generate a key for testing
    scoped_ssl_key key(em_crypto_t::read_keypair_from_pem("./testing_key.pem"));
    ASSERT_NE(key.get(), nullptr) << "Could not read key from PEM";
    // Get components
    scoped_ec_group group(em_crypto_t::get_key_group(key.get()));
    ASSERT_NE(group.get(), nullptr) << "Could not get key group";

    // Check NID
    int curve_nid = EC_GROUP_get_curve_name(group.get());
    EXPECT_EQ(curve_nid, NID_secp256k1) << "Read key has wrong curve";

    scoped_bn priv(em_crypto_t::get_priv_key_bn(key.get()));
    ASSERT_NE(priv.get(), nullptr) << "Could not get private key";
    scoped_ec_point pub(em_crypto_t::get_pub_key_point(key.get(), group.get()));
    ASSERT_NE(pub.get(), nullptr) << "Could not get public key point";
    // Verify private key can generate the same public key point
    scoped_ec_point computed_pub(EC_POINT_new(group.get()));
    ASSERT_NE(computed_pub.get(), nullptr) << "Could not create new EC_POINT";
    ASSERT_TRUE(
        EC_POINT_mul(group.get(), computed_pub.get(), priv.get(), nullptr, nullptr, nullptr))
        << "Could not compute public key from private key";
    // Compare the public key points
    EXPECT_EQ(EC_POINT_cmp(group.get(), pub.get(), computed_pub.get(), nullptr), 0)
        << "Computed public key doesn't match the original";
}

TEST_F(EmCryptoTests, AESKeyWrap)
{
    // Test AES-128 Key Wrap with known test vectors from RFC 3394
    uint8_t kek_128[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    
    uint8_t plaintext[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                             0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    
    // Expected result from RFC 3394 Section 4.1 (with default IV)
    uint8_t expected_wrapped[24] = {0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47,
                                    0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B, 0x82,
                                    0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5};
    
    uint8_t wrapped[24];
    uint32_t wrapped_len = 0;
    
    // Test successful wrapping
    uint8_t result = em_crypto_t::aes_key_wrap(kek_128, 16, plaintext, 16, wrapped, &wrapped_len);
    EXPECT_EQ(result, 1) << "AES key wrap should succeed";
    EXPECT_EQ(wrapped_len, 24) << "Wrapped length should be plaintext length + 8";
    EXPECT_EQ(memcmp(wrapped, expected_wrapped, 24), 0) << "Wrapped result should match RFC 3394 test vector";
    
    // Test AES-256 Key Wrap
    uint8_t kek_256[32];
    for (int i = 0; i < 32; i++) {
        kek_256[i] = static_cast<uint8_t>(i);
    }
    
    uint8_t plaintext_256[32];
    for (int i = 0; i < 32; i++) {
        plaintext_256[i] = static_cast<uint8_t>(0xFF - i);
    }
    
    uint8_t wrapped_256[40];
    uint32_t wrapped_len_256 = 0;
    
    result = em_crypto_t::aes_key_wrap(kek_256, 32, plaintext_256, 32, wrapped_256, &wrapped_len_256);
    EXPECT_EQ(result, 1) << "AES-256 key wrap should succeed";
    EXPECT_EQ(wrapped_len_256, 40) << "AES-256 wrapped length should be 40 bytes";
    
    // Test error conditions
    uint32_t error_len = 0;
    
    // Invalid KEK length
    result = em_crypto_t::aes_key_wrap(kek_128, 15, plaintext, 16, wrapped, &error_len);
    EXPECT_EQ(result, 0) << "Should fail with invalid KEK length";
    
    // Invalid plaintext length (not multiple of 8)
    result = em_crypto_t::aes_key_wrap(kek_128, 16, plaintext, 15, wrapped, &error_len);
    EXPECT_EQ(result, 0) << "Should fail with plaintext length not multiple of 8";
    
    // Plaintext too short
    result = em_crypto_t::aes_key_wrap(kek_128, 16, plaintext, 8, wrapped, &error_len);
    EXPECT_EQ(result, 0) << "Should fail with plaintext length < 16";
}

TEST_F(EmCryptoTests, AESKeyUnwrap)
{
    // Test AES-128 Key Unwrap with known test vectors from RFC 3394
    uint8_t kek_128[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    
    uint8_t wrapped[24] = {0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47,
                           0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B, 0x82,
                           0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5};
    
    // Expected unwrapped result from RFC 3394
    uint8_t expected_plaintext[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                      0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    
    uint8_t unwrapped[24];  // Buffer needs to be at least as large as wrapped input
    uint32_t unwrapped_len = 0;
    
    // Test successful unwrapping
    uint8_t result = em_crypto_t::aes_key_unwrap(kek_128, 16, wrapped, 24, unwrapped, &unwrapped_len);
    EXPECT_EQ(result, 1) << "AES key unwrap should succeed";
    EXPECT_EQ(unwrapped_len, 16) << "Unwrapped length should be wrapped length - 8";
    EXPECT_EQ(memcmp(unwrapped, expected_plaintext, 16), 0) << "Unwrapped result should match original plaintext";
    
    // Test round-trip (wrap then unwrap)
    uint8_t original[32];
    for (int i = 0; i < 32; i++) {
        original[i] = static_cast<uint8_t>(0xAA + (i % 16));
    }
    
    uint8_t kek[24] = {0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A,
                       0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A,
                       0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A};
    
    uint8_t wrapped_roundtrip[40];
    uint32_t wrapped_roundtrip_len = 0;
    uint8_t unwrapped_roundtrip[40];  // Buffer needs to be at least as large as wrapped input
    uint32_t unwrapped_roundtrip_len = 0;
    
    // Wrap
    result = em_crypto_t::aes_key_wrap(kek, 24, original, 32, wrapped_roundtrip, &wrapped_roundtrip_len);
    EXPECT_EQ(result, 1) << "Round-trip wrap should succeed";
    
    // Unwrap
    result = em_crypto_t::aes_key_unwrap(kek, 24, wrapped_roundtrip, wrapped_roundtrip_len, 
                                         unwrapped_roundtrip, &unwrapped_roundtrip_len);
    EXPECT_EQ(result, 1) << "Round-trip unwrap should succeed";
    EXPECT_EQ(unwrapped_roundtrip_len, 32) << "Round-trip unwrapped length should match original";
    EXPECT_EQ(memcmp(unwrapped_roundtrip, original, 32), 0) << "Round-trip should preserve data";
    
    // Test error conditions
    uint32_t error_len = 0;
    uint8_t error_buffer[24];  // Separate buffer for error tests
    
    // Invalid KEK length
    result = em_crypto_t::aes_key_unwrap(kek_128, 17, wrapped, 24, error_buffer, &error_len);
    EXPECT_EQ(result, 0) << "Should fail with invalid KEK length";
    
    // Invalid wrapped length (not multiple of 8)
    result = em_crypto_t::aes_key_unwrap(kek_128, 16, wrapped, 23, error_buffer, &error_len);
    EXPECT_EQ(result, 0) << "Should fail with wrapped length not multiple of 8";
    
    // Wrapped data too short
    result = em_crypto_t::aes_key_unwrap(kek_128, 16, wrapped, 16, error_buffer, &error_len);
    EXPECT_EQ(result, 0) << "Should fail with wrapped length < 24";
}

TEST_F(EmCryptoTests, KDFHashLength)
{
    // Test basic KDF functionality with known inputs
    uint8_t key[32];
    for (int i = 0; i < 32; i++) {
        key[i] = static_cast<uint8_t>(i);
    }
    
    const char* label = "TestLabel";
    uint8_t context[16];
    for (int i = 0; i < 16; i++) {
        context[i] = static_cast<uint8_t>(0xFF - i);
    }
    
    uint8_t output[64];
    
    // Test successful KDF with SHA-256
    bool result = em_crypto_t::kdf_hash_length(EVP_sha256(), key, 32, label, context, 16, output, 64);
    EXPECT_TRUE(result) << "KDF should succeed with valid inputs";
    
    // Verify output is not all zeros (sanity check)
    bool all_zeros = true;
    for (int i = 0; i < 64; i++) {
        if (output[i] != 0) {
            all_zeros = false;
            break;
        }
    }
    EXPECT_FALSE(all_zeros) << "KDF output should not be all zeros";
    
    // Test deterministic behavior (same inputs produce same outputs)
    uint8_t output2[64];
    result = em_crypto_t::kdf_hash_length(EVP_sha256(), key, 32, label, context, 16, output2, 64);
    EXPECT_TRUE(result) << "Second KDF call should succeed";
    EXPECT_EQ(memcmp(output, output2, 64), 0) << "KDF should be deterministic";
    
    // Test with different output lengths
    // Note: The KDF includes the output length in the HMAC computation, so different 
    // output lengths will produce completely different results, not truncated versions
    uint8_t short_output[16];
    result = em_crypto_t::kdf_hash_length(EVP_sha256(), key, 32, label, context, 16, short_output, 16);
    EXPECT_TRUE(result) << "KDF should work with shorter output";
    // Different lengths produce different outputs due to length being included in HMAC
    
    uint8_t long_output[128];
    result = em_crypto_t::kdf_hash_length(EVP_sha256(), key, 32, label, context, 16, long_output, 128);
    EXPECT_TRUE(result) << "KDF should work with longer output";
    // Different lengths produce different outputs due to length being included in HMAC
    
    // Test with NULL context
    uint8_t output_no_context[32];
    result = em_crypto_t::kdf_hash_length(EVP_sha256(), key, 32, label, nullptr, 0, output_no_context, 32);
    EXPECT_TRUE(result) << "KDF should work with NULL context";
    
    // Test with different hash algorithms
    uint8_t sha1_output[32];
    result = em_crypto_t::kdf_hash_length(EVP_sha1(), key, 32, label, context, 16, sha1_output, 32);
    EXPECT_TRUE(result) << "KDF should work with SHA-1";
    EXPECT_NE(memcmp(output, sha1_output, 32), 0) << "Different hash algorithms should produce different outputs";
    
    // Test error conditions
    result = em_crypto_t::kdf_hash_length(nullptr, key, 32, label, context, 16, output, 32);
    EXPECT_FALSE(result) << "Should fail with NULL hash algorithm";
    
    result = em_crypto_t::kdf_hash_length(EVP_sha256(), nullptr, 32, label, context, 16, output, 32);
    EXPECT_FALSE(result) << "Should fail with NULL key";
    
    result = em_crypto_t::kdf_hash_length(EVP_sha256(), key, 0, label, context, 16, output, 32);
    EXPECT_FALSE(result) << "Should fail with zero key length";
    
    result = em_crypto_t::kdf_hash_length(EVP_sha256(), key, 32, nullptr, context, 16, output, 32);
    EXPECT_FALSE(result) << "Should fail with NULL label";
    
    result = em_crypto_t::kdf_hash_length(EVP_sha256(), key, 32, label, context, 16, nullptr, 32);
    EXPECT_FALSE(result) << "Should fail with NULL output";
    
    result = em_crypto_t::kdf_hash_length(EVP_sha256(), key, 32, label, context, 16, output, 0);
    EXPECT_FALSE(result) << "Should fail with zero output length";
    
    // Test with very large output length (should fail due to counter limit)
    // With SHA-256 (32 bytes), we need more than 65535 * 32 = 2,097,120 bytes to exceed UINT16_MAX iterations
    size_t huge_len = 2100000;  // This requires 65625 iterations, exceeding UINT16_MAX
    uint8_t* large_output = new uint8_t[huge_len];
    result = em_crypto_t::kdf_hash_length(EVP_sha256(), key, 32, label, context, 16, large_output, huge_len);
    EXPECT_FALSE(result) << "Should fail with output length requiring > UINT16_MAX iterations";
    delete[] large_output;
}

TEST_F(EmCryptoTests, BundleECKey)
{
    // Create a test EC group (P-256)
    scoped_ec_group group(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
    ASSERT_NE(group.get(), nullptr) << "Failed to create EC group";
    
    // Generate a test key to get valid public/private key components
    scoped_ssl_key test_key(em_crypto_t::generate_ec_key(NID_X9_62_prime256v1));
    ASSERT_NE(test_key.get(), nullptr) << "Failed to generate test key";
    
    // Extract components from the test key
    scoped_bn priv_bn(em_crypto_t::get_priv_key_bn(test_key.get()));
    ASSERT_NE(priv_bn.get(), nullptr) << "Failed to get private key BN";
    
    scoped_ec_point pub_point(em_crypto_t::get_pub_key_point(test_key.get(), group.get()));
    ASSERT_NE(pub_point.get(), nullptr) << "Failed to get public key point";
    
    // Test bundling with both public and private key
    scoped_ssl_key bundled_full(em_crypto_t::bundle_ec_key(group.get(), pub_point.get(), priv_bn.get()));
    ASSERT_NE(bundled_full.get(), nullptr) << "Failed to bundle EC key with private key";
    
    // Verify the bundled key has the same components
    scoped_bn bundled_priv(em_crypto_t::get_priv_key_bn(bundled_full.get()));
    ASSERT_NE(bundled_priv.get(), nullptr) << "Failed to get private key from bundled key";
    
    scoped_ec_point bundled_pub(em_crypto_t::get_pub_key_point(bundled_full.get(), group.get()));
    ASSERT_NE(bundled_pub.get(), nullptr) << "Failed to get public key from bundled key";
    
    // Compare private keys
    EXPECT_EQ(BN_cmp(priv_bn.get(), bundled_priv.get()), 0) << "Private keys should match";
    
    // Compare public keys
    EXPECT_EQ(EC_POINT_cmp(group.get(), pub_point.get(), bundled_pub.get(), nullptr), 0) 
        << "Public keys should match";
    
    // Test bundling with only public key (no private key)
    scoped_ssl_key bundled_pub_only(em_crypto_t::bundle_ec_key(group.get(), pub_point.get(), nullptr));
    ASSERT_NE(bundled_pub_only.get(), nullptr) << "Failed to bundle EC key without private key";
    
    // Verify it has the public key
    scoped_ec_point bundled_pub_only_point(em_crypto_t::get_pub_key_point(bundled_pub_only.get(), group.get()));
    ASSERT_NE(bundled_pub_only_point.get(), nullptr) << "Failed to get public key from public-only bundled key";
    
    EXPECT_EQ(EC_POINT_cmp(group.get(), pub_point.get(), bundled_pub_only_point.get(), nullptr), 0) 
        << "Public keys should match in public-only bundle";
    
    // Verify it doesn't have a private key (should return NULL)
    scoped_bn bundled_pub_only_priv(em_crypto_t::get_priv_key_bn(bundled_pub_only.get()));
    EXPECT_EQ(bundled_pub_only_priv.get(), nullptr) << "Public-only bundle should not have private key";
    
    // Test with different curve (secp384r1)
    scoped_ec_group group384(EC_GROUP_new_by_curve_name(NID_secp384r1));
    ASSERT_NE(group384.get(), nullptr) << "Failed to create secp384r1 group";
    
    scoped_ssl_key test_key384(em_crypto_t::generate_ec_key(NID_secp384r1));
    ASSERT_NE(test_key384.get(), nullptr) << "Failed to generate secp384r1 test key";
    
    scoped_bn priv_bn384(em_crypto_t::get_priv_key_bn(test_key384.get()));
    ASSERT_NE(priv_bn384.get(), nullptr) << "Failed to get secp384r1 private key BN";
    
    scoped_ec_point pub_point384(em_crypto_t::get_pub_key_point(test_key384.get(), group384.get()));
    ASSERT_NE(pub_point384.get(), nullptr) << "Failed to get secp384r1 public key point";
    
    scoped_ssl_key bundled384(em_crypto_t::bundle_ec_key(group384.get(), pub_point384.get(), priv_bn384.get()));
    ASSERT_NE(bundled384.get(), nullptr) << "Failed to bundle secp384r1 EC key";
    
    // Verify the curve of the bundled key
    scoped_ec_group bundled_group(em_crypto_t::get_key_group(bundled384.get()));
    ASSERT_NE(bundled_group.get(), nullptr) << "Failed to get group from bundled secp384r1 key";
    
    int bundled_nid = EC_GROUP_get_curve_name(bundled_group.get());
    EXPECT_EQ(bundled_nid, NID_secp384r1) << "Bundled key should have correct curve";
    
    // Test error conditions
    SSL_KEY* null_result = em_crypto_t::bundle_ec_key(nullptr, pub_point.get(), priv_bn.get());
    EXPECT_EQ(null_result, nullptr) << "Should fail with NULL group";
    
    null_result = em_crypto_t::bundle_ec_key(group.get(), nullptr, priv_bn.get());
    EXPECT_EQ(null_result, nullptr) << "Should fail with NULL public key";
}