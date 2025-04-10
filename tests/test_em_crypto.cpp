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
        const auto sig_x = em_crypto_t::base64url_decode(test_sig_x);
        ASSERT_NE(sig_x, std::nullopt);
        const auto sig_y = em_crypto_t::base64url_decode(test_sig_y);
        ASSERT_NE(sig_y, std::nullopt);

        const auto opt_test = std::make_optional<std::vector<uint8_t>>(test_priv_proto_key);
        signing_key =
            em_crypto_t::create_ec_key_from_coordinates(*sig_x, *sig_y, opt_test, test_sig_curve);
        ASSERT_NE(signing_key, nullptr);
    }

    void TearDown() override
    {
        if (signing_key) {
            em_crypto_t::free_key(signing_key);
        }
    }

    // MUTABLES
    SSL_KEY *signing_key = nullptr;

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

    ASSERT_NE(signing_key, nullptr);
    printf("Signing Key\n");
    if (EVP_PKEY_print_public_fp(stdout, signing_key, 0, NULL) < 1) {
        auto err = ERR_get_error();
        printf("Failed to print public key: %s\n", ERR_error_string(err, NULL));
    }
    if (EVP_PKEY_print_private_fp(stdout, signing_key, 0, NULL) < 1) {
        auto err = ERR_get_error();
        printf("Failed to print private key: %s\n", ERR_error_string(err, NULL));
    }

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
    auto sig = em_crypto_t::sign_data_ecdsa(data_vec, signing_key, EVP_sha256());
    ASSERT_NE(sig, std::nullopt) << "Failed to sign data, 'sig' could not be generated";

    // Verify that the signature was generated correctly.
    bool did_verify = em_crypto_t::verify_signature(data_vec, *sig, signing_key, EVP_sha256());
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
        EC_POINT_mul(group.get(), computed_pub.get(), priv.get(), nullptr, nullptr, nullptr))
        << "Could not compute public key from private key";

    // Compare the public key points
    EXPECT_EQ(EC_POINT_cmp(group.get(), pub.get(), computed_pub.get(), nullptr), 0)
        << "Computed public key doesn't match the original";
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