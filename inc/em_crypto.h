/**
 * Copyright 2023 Comcast Cable Communications Management, LLC
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
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef EM_CRYPTO_H
#define EM_CRYPTO_H

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/dh.h>
#include "em_base.h"
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/types.h>
#include <openssl/core_names.h>

#include <optional>
#include <vector>
#include <utility>
#include <string>
#include <memory>

#define SHA256_MAC_LEN 32
#define AES_BLOCK_SIZE 16
 /* Keys sizes */
#define WPS_AUTHKEY_LEN    32
#define WPS_KEYWRAPKEY_LEN 16
#define WPS_EMSK_LEN       32

class em_crypto_t {

private:
    em_crypto_info_t m_crypto_info;
    em_nonce_t e_nonce;
    uuid_t e_uuid;

    /**
    * Securely frees multiple BIGNUM objects
    * @param p, g, priv, pub BIGNUM pointers to free (can be NULL)
    */
    static void cleanup_bignums(BIGNUM *p, BIGNUM *g, BIGNUM *priv, BIGNUM *pub);

    /**
    * Helper function to compute a Diffie-Hellman shared secret using version-specific OpenSSL APIs
    * 
    * @param p              Prime modulus as BIGNUM
    * @param g              Generator as BIGNUM  
    * @param bn_priv        Local private key as BIGNUM
    * @param bn_pub         Remote public key as BIGNUM
    * @param shared_secret  Output buffer for computed shared secret (allocated within function)
    * @param secret_len     Length of computed shared secret
    * 
    * @return 1 on success, 0 on failure
    * 
    * @note For OpenSSL < 3.0: Uses legacy DH APIs
    * @note For OpenSSL >= 3.0: Uses modern EVP APIs
    */ 
    static uint8_t compute_secret_internal(BIGNUM *p, BIGNUM *g, BIGNUM *bn_priv,  BIGNUM *bn_pub, uint8_t **shared_secret, size_t *secret_len);
public:
    static uint8_t g_dh1536_g[];
    static uint8_t g_dh1536_p[];

    int init();

    /**
     * @brief Computes an HMAC hash using OpenSSL for multiple input elements
     *
     * This function calculates an HMAC hash using a specified hashing algorithm and key,
     * supporting multiple input elements. It's compatible with different OpenSSL versions
     * (pre-1.1.0, 1.1.0+, and 3.0.0+) through conditional compilation.
     *
     * @param hashing_algo The OpenSSL message digest algorithm to use (e.g., EVP_sha256())
     * @param key         Pointer to the key used for HMAC calculation
     * @param keylen      Length of the key in bytes
     * @param num_elem    Number of elements to be hashed
     * @param addr        Array of pointers to input data elements
     * @param len         Array of lengths corresponding to each input element
     * @param hmac        Output buffer where the computed HMAC will be stored
     *
     * @return uint8_t    Returns 1 on success, 0 on failure
     *
     * @note The hmac buffer must be pre-allocated with sufficient space for the output
     *       (32 bytes for SHA-256)
     */
    static uint8_t platform_hmac_hash(const EVP_MD * hashing_algo, uint8_t *key, uint32_t keylen, uint8_t num_elem, uint8_t **addr, size_t *len, uint8_t *hmac);

    /**
    * @brief Convenience wrapper to compute HMAC-SHA256 hash for multiple input elements
    *
    * @param key      Key used for HMAC calculation
    * @param keylen   Length of the key in bytes  
    * @param num_elem Number of elements to hash
    * @param addr     Array of pointers to input data elements
    * @param len      Array of lengths for each input element
    * @param hmac     Output buffer for computed HMAC
    *
    * @return 1 on success, 0 on failure
    */
    inline static uint8_t platform_hmac_SHA256(uint8_t *key, uint32_t keylen, uint8_t num_elem, uint8_t **addr, size_t *len, uint8_t *hmac){
        return platform_hmac_hash(EVP_sha256(), key, keylen, num_elem, addr, len, hmac);
    }
    
    /**
    * @brief Computes a cryptographic hash of multiple input elements using OpenSSL
    *
    * @param hashing_algo OpenSSL message digest algorithm to use (e.g., EVP_sha256())
    * @param num_elem     Number of elements to hash
    * @param addr         Array of pointers to input data elements  
    * @param len          Array of lengths for each input element
    * @param digest       Output buffer for computed hash value
    *
    * @return 1 on success, 0 on failure
    */
    static uint8_t platform_hash(const EVP_MD * hashing_algo, uint8_t num_elem, uint8_t **addr, size_t *len, uint8_t *digest);

    /**
    * @brief Convenience wrapper to compute SHA-256 hash for multiple input elements
    *
    * @param num_elem Number of elements to hash
    * @param addr     Array of pointers to input data elements
    * @param len      Array of lengths for each input element  
    * @param digest   Output buffer for computed hash
    * 
    * @return 1 on success, 0 on failure
    */
    inline static uint8_t platform_SHA256(uint8_t num_elem, uint8_t **addr, size_t *len, uint8_t *digest){
        return platform_hash(EVP_sha256(), num_elem, addr, len, digest);
    }
    

    /**
    * Appends a 32-bit value in **network byte order** to a buffer and advances the pointer
    * @param memory_pointer Pointer to 32-bit value to append (converted to network byte order)
    * @param packet_ppointer Pointer to buffer pointer (will be advanced by 4 bytes)
    */
    static void append_u32_net (const uint32_t *memory_pointer, uint8_t **packet_ppointer);

    /**
    * Key Derivation Function used in WPS (Wi-Fi Protected Setup)
    * Generates cryptographic key material using HMAC-SHA256
    * 
    * @param key              HMAC key
    * @param label_prefix     Binary prefix for the label
    * @param label_prefix_len Length of the label prefix
    * @param label            ASCII label string
    * @param res              Output buffer for generated key material
    * @param res_len          Length of requested key material in bytes
    * 
    * @return 1 on success, 0 on HMAC failure
    */
    static uint8_t wps_key_derivation_function(uint8_t *key, uint8_t *label_prefix, size_t label_prefix_len, char *label, uint8_t *res, uint32_t res_len);

    /**
    * @brief Decrypts data using OpenSSL cipher in place
    *
    * @param cipher_type Type of cipher to use (e.g., EVP_aes_256_cbc())
    * @param key        Decryption key
    * @param iv         Initialization vector
    * @param data       Buffer containing ciphertext, also used for plaintext output
    * @param data_len   Length of input ciphertext
    *
    * @return 1 on success, 0 on failure
    * 
    * @note Padding is disabled. Input length must be multiple of block size.
    */
    static uint8_t platform_cipher_decrypt(const EVP_CIPHER *cipher_type, uint8_t *key, uint8_t *iv, uint8_t *data, uint32_t data_len);

    /**
    * @brief Encrypts data using OpenSSL cipher in place
    *
    * @param cipher_type Type of cipher to use (e.g., EVP_aes_256_cbc())
    * @param key        Encryption key
    * @param iv         Initialization vector
    * @param plain      Input plaintext buffer
    * @param plain_len  Length of input plaintext
    * @param cipher     Output buffer for ciphertext
    * @param cipher_len Output parameter for length of ciphertext
    *
    * @return 1 on success, 0 on failure
    *
    * @note Padding is disabled. Input length must be multiple of block size.
    */
    static uint8_t platform_cipher_encrypt(const EVP_CIPHER *cipher_type, uint8_t *key, uint8_t *iv, uint8_t *plain, uint32_t plain_len, uint8_t *cipher_text, uint32_t *cipher_len);

    /**
    * @brief Decrypts data using AES-128 in CBC mode (in-place)
    *
    * @param key      128-bit AES key
    * @param iv       Initialization vector
    * @param data     Data to decrypt (overwritten with plaintext)
    * @param data_len Length of data
    *
    * @return 1 on success, 0 on failure
    */
    static uint8_t platform_aes_128_cbc_decrypt(uint8_t *key, uint8_t *iv, uint8_t *data, uint32_t data_len){
        return platform_cipher_decrypt(EVP_aes_128_cbc(), key, iv, data, data_len);
    }
    
    /**
    * @brief Encrypts data using AES-128 in CBC mode
    *
    * @param key         128-bit AES key
    * @param iv          Initialization vector
    * @param plain       Input plaintext
    * @param plain_len   Length of plaintext
    * @param cipher_text Output ciphertext buffer
    * @param cipher_len  Output ciphertext length
    *
    * @return 1 on success, 0 on failure
    */
    static uint8_t platform_aes_128_cbc_encrypt(uint8_t *key, uint8_t *iv, uint8_t *plain, uint32_t plain_len, uint8_t *cipher_text, uint32_t *cipher_len){
        return platform_cipher_encrypt(EVP_aes_128_cbc(), key, iv, plain, plain_len, cipher_text, cipher_len);
    }

    /**
    * Creates a DH (Diffie-Hellman) key using OpenSSL 3.0+ APIs
    * 
    * @param p         Prime modulus
    * @param g         Generator
    * @param bn_priv   Private key component (optional, can be NULL)
    * @param bn_pub    Public key component (optional, can be NULL)
    * 
    * @return EVP_PKEY object containing the DH key on success, NULL on failure
    * 
    * @note Requires OpenSSL 3.0 or later
    */
    static EVP_PKEY* create_dh_pkey(BIGNUM *p, BIGNUM *g, BIGNUM *bn_priv, BIGNUM *bn_pub);


    /**
     * Computes the Diffie-Hellman shared secret using the local private key and remote public key
     * 
     * This function uses a 1536-bit DH group (RFC 3526) to compute a shared secret.
     * It supports both legacy OpenSSL (<3.0.0) and modern OpenSSL (>=3.0.0) implementations.
     * 
     * @param[out] shared_secret     Pointer to buffer pointer where the computed shared secret will be stored. 
     *                                  Memory is allocated by the function and must be freed by the caller.
     * @param[out] shared_secret_len Pointer to store the length of the computed shared secret
     * @param[in]  remote_pub        Remote party's public key buffer
     * @param[in]  remote_pub_len    Length of the remote public key
     * @param[in]  local_priv        Local party's private key buffer
     * @param[in]  local_priv_len    Length of the local private key
     * 
     * @return 1 on success, 0 on failure
     *         If the function returns 0, any allocated memory is freed and output parameters are set to NULL/0
     * 
     * @warning Input parameters must not be NULL
     * @warning Caller is responsible for freeing the allocated shared_secret buffer **on success**
     */
    static uint8_t platform_compute_shared_secret(uint8_t **shared_secret, uint16_t *shared_secret_len,
        uint8_t *remote_pub, uint16_t remote_pub_len,
        uint8_t *local_priv, uint8_t local_priv_len);

    /**
     * Encodes binary data using standard Base64 encoding.
     * 
     * @param input Binary data to encode
     * @param length Length of the input data
     * @return Base64 encoded string or empty string on failure
     */
    static std::string base64_encode(const uint8_t *input, size_t length);

    /**
     * Encodes binary data using Base64URL encoding (URL-safe variant).
     * 
     * Replaces '+' with '-', '/' with '_', and removes padding '=' characters.
     * 
     * @param input Binary data to encode
     * @param length Length of the input data
     * @return Base64URL encoded string or empty string on failure
     */
    static std::string base64url_encode(const uint8_t *input, size_t length);

    /**
     * Encodes string data using standard Base64 encoding.
     * 
     * @param input String data to encode
     * @return Base64 encoded string or empty string on failure
     */
    static inline std::string base64_encode(const std::string &input)
    {
        return base64_encode(reinterpret_cast<const uint8_t *>(input.data()), input.length());
    }

    /**
     * Encodes string data using Base64URL encoding (URL-safe variant).
     * 
     * @param input String data to encode
     * @return Base64URL encoded string or empty string on failure
     */
    static inline std::string base64url_encode(const std::string &input)
    {
        return base64url_encode(reinterpret_cast<const uint8_t *>(input.data()), input.length());
    }

    /**
     * Encodes string data using standard Base64 encoding.
     * 
     * @param input Byte data to encode
     * @return Base64 encoded string or empty string on failure
     */
    static inline std::string base64_encode(const std::vector<uint8_t> &input)
    {
        return base64_encode(input.data(), input.size());
    }

    /**
     * Encodes string data using Base64URL encoding (URL-safe variant).
     * 
     * @param input Byte data to encode
     * @return Base64URL encoded string or empty string on failure
     */
    static inline std::string base64url_encode(const std::vector<uint8_t> &input)
    {
        return base64url_encode(input.data(), input.size());
    }

    /**
     * Decodes standard Base64 encoded data.
     * 
     * @param input Base64 encoded string
     * @return Pair containing decoded data pointer and length. Caller must free the pointer.
     *         Returns {NULL, 0} on failure.
     * 
     * @note The caller is responsible for freeing the returned memory
     */
    static std::optional<std::vector<uint8_t>> base64_decode(const std::string &input);

    /**
     * Decodes Base64URL encoded data (URL-safe variant).
     * 
     * Handles '-' instead of '+', '_' instead of '/', and missing padding.
     * 
     * @param input Base64URL encoded string
     * @return Pair containing decoded data pointer and length. Caller must free the pointer.
     *         Returns {NULL, 0} on failure.
     * 
     * @note The caller is responsible for freeing the returned memory
     */
    static std::optional<std::vector<uint8_t>> base64url_decode(const std::string &input);

    /**
    * Signs data using the provided private key and hashing algorithm with ECDSA
    * 
    * @param data_to_sign The data string to be signed
    * @param private_key OpenSSL EVP_PKEY pointer containing the private key
    * @param md Digest method to use (defaults to SHA-256)
    * @return Signature as vector of bytes or nullopt on failure
    */
    static std::optional<std::vector<uint8_t>>
    sign_data_ecdsa(const std::vector<uint8_t>& data_to_sign, EVP_PKEY *private_key,
                    const EVP_MD *md = EVP_sha256());

    /**
     * @brief Verifies a digital signature using OpenSSL's EVP API
     * 
     * This function verifies that the provided signature was created from the given message
     * using the private key corresponding to the provided public key.
     * 
     * @param message The original message data that was signed
     * @param signature The signature to verify
     * @param pkey The public key (EVP_PKEY*) to use for verification
     * @param hash_function The hash function (e.g., EVP_sha256()) used during signing
     * 
     * @return true if the signature is valid, false otherwise
     * 
     * @note This function uses OpenSSL's high-level EVP interface which works with
     *       OpenSSL 1.1.x and 3.0+
     */
    static bool verify_signature(const std::vector<uint8_t> &message,
                                 const std::vector<uint8_t> &signature, EVP_PKEY *pkey,
                                 const EVP_MD *hash_function);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    /**
     * @brief Verifies a digital signature using an EC_KEY (for pre-OpenSSL 3.0 compatibility)
     * 
     * This overloaded function provides a convenient interface for verifying signatures
     * with EC_KEY objects, which is useful for code that needs to work with 
     * pre-OpenSSL 3.0 versions. It internally converts the EC_KEY to an EVP_PKEY
     * and delegates to the primary verification function.
     * 
     * @param message The original message data that was signed
     * @param signature The signature to verify
     * @param ec_key The elliptic curve public key (EC_KEY*) to use for verification
     * @param hash_function The hash function (e.g., EVP_sha256()) used during signing
     * 
     * @return true if the signature is valid, false otherwise
     * 
     * @note This function is intended for backward compatibility with code using the
     *       EC_KEY interface directly. For new code, the EVP_PKEY version is preferred.
     */
    static bool verify_signature(const std::vector<uint8_t> &message,
                                 const std::vector<uint8_t> &signature, EC_KEY *ec_key,
                                 const EVP_MD *hash_function);
#endif
    /**
     * Creates an OpenSSL EC_KEY from a base64-encoded DER public key
     *
     * @param base64_der_pubkey Null-terminated string containing the base64-encoded DER public key
     * @return SSL_KEY* on success, NULL on failure
     *
     * @note The returned EC_KEY must be freed by the caller using EC_KEY_free()
     * @note This function assumes the input is a valid base64-encoded DER format EC public key
     */
    static SSL_KEY* ec_key_from_base64_der(const std::string& base64_der_pubkey);

    static std::string ec_key_to_base64_der(const SSL_KEY* key);

    static SSL_KEY* create_ec_key_from_coordinates(const std::vector<uint8_t>& x_bin, 
                                                   const std::vector<uint8_t>& y_bin, 
                                                   const std::optional<std::vector<uint8_t>>& priv_key_bytes = std::nullopt,
                                                   const std::string& group_name = "P-256");


    static EC_GROUP* get_key_group(const SSL_KEY* key);
    static BIGNUM* get_priv_key_bn(const SSL_KEY* key);
    static EC_POINT* get_pub_key_point(const SSL_KEY* key, EC_GROUP* key_group=NULL);
    static SSL_KEY* generate_ec_key(EC_GROUP *group);
    static SSL_KEY* generate_ec_key(int nid);
    static void free_key(SSL_KEY* key);


    static inline uint8_t generate_iv(unsigned char *iv, unsigned int len) { if (!RAND_bytes(iv, static_cast<int>(len))) { return 0; } else { return 1; } }
    static inline uint8_t generate_nonce(em_nonce_t nonce) { if (!RAND_bytes(nonce, sizeof(em_nonce_t))) { return 0; } else { return 1; } }

    // START: Object getters and setters
    inline em_crypto_info_t *get_crypto_info() { return &m_crypto_info; }

    inline unsigned int get_e_uuid(unsigned char *uuid) { memcpy(uuid, reinterpret_cast<unsigned char *>(&m_crypto_info.e_uuid), sizeof(uuid_t)); return sizeof(uuid_t); }
    inline unsigned int get_r_uuid(unsigned char *uuid) { memcpy(uuid, reinterpret_cast<unsigned char *>(&m_crypto_info.r_uuid), sizeof(uuid_t)); return sizeof(uuid_t); }
    inline unsigned int get_e_nonce(unsigned char *nonce) { memcpy(nonce, reinterpret_cast<unsigned char *>(&m_crypto_info.e_nonce), sizeof(em_nonce_t)); return sizeof(em_nonce_t); }
    inline unsigned int get_r_nonce(unsigned char *nonce) { memcpy(nonce, reinterpret_cast<unsigned char *>(&m_crypto_info.r_nonce), sizeof(em_nonce_t)); return sizeof(em_nonce_t); }

    inline unsigned char *get_e_nonce() { return reinterpret_cast<unsigned char *>(&m_crypto_info.e_nonce); }
    inline unsigned char *get_r_nonce() { return reinterpret_cast<unsigned char *>(&m_crypto_info.r_nonce); }

    inline void set_e_uuid(unsigned char *uuid, unsigned int len) { memcpy(reinterpret_cast<unsigned char *>(&m_crypto_info.e_uuid), uuid, len); }
    inline void set_r_uuid(unsigned char *uuid, unsigned int len) { memcpy(reinterpret_cast<unsigned char *>(&m_crypto_info.r_uuid), uuid, len); }
    inline void set_e_nonce(unsigned char *nonce, unsigned int len) { memcpy(reinterpret_cast<unsigned char *>(&m_crypto_info.e_nonce), nonce, len); }
    inline void set_r_nonce(unsigned char *nonce, unsigned int len) { memcpy(reinterpret_cast<unsigned char *>(&m_crypto_info.r_nonce), nonce, len); }

    inline unsigned char *get_e_public() { return m_crypto_info.e_pub; }
    inline unsigned int get_e_public_len() { return m_crypto_info.e_pub_len; }
    inline unsigned char *get_e_private() { return m_crypto_info.e_priv; }
    inline unsigned int get_e_private_len() { return m_crypto_info.e_priv_len; }
    inline unsigned char *get_r_public() { return m_crypto_info.r_pub; }
    inline unsigned int get_r_public_len() { return m_crypto_info.r_pub_len; }
    inline unsigned char *get_r_private() { return m_crypto_info.r_priv; }
    inline unsigned int get_r_private_len() { return m_crypto_info.r_priv_len; }

    inline void set_e_public(unsigned char *pub, unsigned int len) { memcpy(m_crypto_info.e_pub, pub, len); }
    inline void set_r_public(unsigned char *pub, unsigned int len) { memcpy(m_crypto_info.r_pub, pub, len); }

    inline unsigned char *get_e_mac() { return m_crypto_info.e_mac; }
    inline unsigned char *get_r_mac() { return m_crypto_info.r_mac; }

    inline void set_e_mac(unsigned char *mac) { memcpy(m_crypto_info.e_mac, mac, sizeof(mac_address_t)); }
    inline void set_r_mac(unsigned char *mac) { memcpy(m_crypto_info.r_mac, mac, sizeof(mac_address_t)); }

    em_crypto_t();
    ~em_crypto_t() {}
};


// Custom deleters for OpenSSL objects to use with std::unique_ptr
struct BIODeleter {
    void operator()(BIO* bio) const { if (bio) BIO_free(bio); }
};

struct BNDeleter {
    void operator()(BIGNUM* bn) const { if (bn) BN_free(bn); }
};

struct ECPointDeleter {
    void operator()(EC_POINT* point) const { if (point) EC_POINT_free(point); }
};

struct ECGroupDeleter {
    void operator()(EC_GROUP* group) const { 
        #if !defined(FORCE_OPENSSL_1_1) && OPENSSL_VERSION_NUMBER >= 0x30000000L
        if (group) EC_GROUP_free(group); 
        #endif
    }
};

struct SSLKeyDeleter {
    void operator()(SSL_KEY* key) const { if (key) em_crypto_t::free_key(key); }
};

struct BuffDeleter {
    void operator()(uint8_t* buff) const { if (buff) OPENSSL_free(buff); }
};


using scoped_ssl_key = std::unique_ptr<SSL_KEY, SSLKeyDeleter>;
using scoped_bio = std::unique_ptr<BIO, BIODeleter>;
using scoped_bn = std::unique_ptr<BIGNUM, BNDeleter>;
using scoped_ec_point = std::unique_ptr<EC_POINT, ECPointDeleter>;
using scoped_ec_group = std::unique_ptr<EC_GROUP, ECGroupDeleter>;
using scoped_buff = std::unique_ptr<uint8_t, BuffDeleter>;
#endif
