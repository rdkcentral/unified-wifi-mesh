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

#define SHA256_MAC_LEN 32
#define AES_BLOCK_SIZE 16
 /* Keys sizes */
#define WPS_AUTHKEY_LEN    32
#define WPS_KEYWRAPKEY_LEN 16
#define WPS_EMSK_LEN       32

class em_crypto_t {
    em_crypto_info_t m_crypto_info;
    em_nonce_t e_nonce;
    uuid_t e_uuid;
public:
    static uint8_t g_dh1536_g[];
    static uint8_t g_dh1536_p[];

    int init();

    static uint8_t get_shared_key(uint8_t **shared_secret, uint16_t *shared_secret_len, uint8_t *remote_pub, uint16_t remote_pub_len, uint8_t *local_priv, uint16_t local_priv_len);

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
    static uint8_t platform_hmac_hash(const EVP_MD * hashing_algo, uint8_t *key, uint32_t keylen, uint8_t num_elem, uint8_t **addr, uint32_t *len, uint8_t *hmac);

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
    inline static uint8_t platform_hmac_SHA256(uint8_t *key, uint32_t keylen, uint8_t num_elem, uint8_t **addr, uint32_t *len, uint8_t *hmac) {
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
    static uint8_t platform_hash(const EVP_MD * hashing_algo, uint8_t num_elem, uint8_t **addr, uint32_t *len, uint8_t *digest);

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
    inline static uint8_t platform_SHA256(uint8_t num_elem, uint8_t **addr, uint32_t *len, uint8_t *digest) {
        return platform_hash(EVP_sha256(), num_elem, addr, len, digest);
    }
    


    static void _I4B (const uint32_t *memory_pointer, uint8_t **packet_ppointer);
    static uint8_t wps_key_derivation_function(uint8_t *key, uint8_t *label_prefix, uint32_t label_prefix_len, char *label, uint8_t *res, uint32_t res_len);

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
    static inline uint8_t platform_aes_128_cbc_decrypt(uint8_t *key, uint8_t *iv, uint8_t *data, uint32_t data_len) {
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
    static inline uint8_t platform_aes_128_cbc_encrypt(uint8_t *key, uint8_t *iv, uint8_t *plain, uint32_t plain_len, uint8_t *cipher_text, uint32_t *cipher_len) {
        return platform_cipher_encrypt(EVP_aes_128_cbc(), key, iv, plain, plain_len, cipher_text, cipher_len);
    }

    static EVP_PKEY* create_dh_pkey(BIGNUM *p, BIGNUM *g, BIGNUM *bn_priv, BIGNUM *bn_pub);
    static uint8_t platform_compute_shared_secret(uint8_t **shared_secret, uint16_t *shared_secret_len,
        uint8_t *remote_pub, uint16_t remote_pub_len,
        uint8_t *local_priv, uint8_t local_priv_len);

    static inline uint8_t generate_iv(unsigned char *iv, unsigned int len) { if (!RAND_bytes(iv, len)) { return 0; } else { return 1; } }
    static inline uint8_t generate_nonce(em_nonce_t nonce) { if (!RAND_bytes(nonce, sizeof(em_nonce_t))) { return 0; } else { return 1; } }

    // START: Object getters and setters
    inline em_crypto_info_t *get_crypto_info() { return &m_crypto_info; }

    inline unsigned int get_e_uuid(unsigned char *uuid) { memcpy(uuid, (unsigned char *)&m_crypto_info.e_uuid, sizeof(uuid_t)); return sizeof(uuid_t); }
    inline unsigned int get_r_uuid(unsigned char *uuid) { memcpy(uuid, (unsigned char *)&m_crypto_info.r_uuid, sizeof(uuid_t)); return sizeof(uuid_t); }
    inline unsigned int get_e_nonce(unsigned char *nonce) { memcpy(nonce, (unsigned char *)&m_crypto_info.e_nonce, sizeof(em_nonce_t)); return sizeof(em_nonce_t); }
    inline unsigned int get_r_nonce(unsigned char *nonce) { memcpy(nonce, (unsigned char *)&m_crypto_info.r_nonce, sizeof(em_nonce_t)); return sizeof(em_nonce_t); }

    inline unsigned char *get_e_nonce() { return (unsigned char *)&m_crypto_info.e_nonce; }
    inline unsigned char *get_r_nonce() { return (unsigned char *)&m_crypto_info.r_nonce; }

    inline void set_e_uuid(unsigned char *uuid, unsigned int len) { memcpy((unsigned char *)&m_crypto_info.e_uuid, uuid, len); }
    inline void set_r_uuid(unsigned char *uuid, unsigned int len) { memcpy((unsigned char *)&m_crypto_info.r_uuid, uuid, len); }
    inline void set_e_nonce(unsigned char *nonce, unsigned int len) { memcpy((unsigned char *)&m_crypto_info.e_nonce, nonce, len); }
    inline void set_r_nonce(unsigned char *nonce, unsigned int len) { memcpy((unsigned char *)&m_crypto_info.r_nonce, nonce, len); }

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
#endif
