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
    em_crypto_info_t *get_crypto_info() { return &m_crypto_info; }
    uint8_t get_shared_key(uint8_t **shared_secret, uint16_t *shared_secret_len, uint8_t *remote_pub, uint16_t remote_pub_len, uint8_t *local_priv, uint16_t local_priv_len);
    uint8_t platform_hmac_SHA256(uint8_t *key, uint32_t keylen, uint8_t num_elem, uint8_t **addr, uint32_t *len, uint8_t *hmac);
    uint8_t platform_SHA256(uint8_t num_elem, uint8_t **addr, uint32_t *len, uint8_t *digest);
    void _I4B (const uint32_t *memory_pointer, uint8_t **packet_ppointer);
    uint8_t wps_key_derivation_function(uint8_t *key, uint8_t *label_prefix, uint32_t label_prefix_len, char *label, uint8_t *res, uint32_t res_len);
    uint8_t platform_aes_decrypt(uint8_t *key, uint8_t *iv, uint8_t *data, uint32_t data_len);
    uint8_t platform_aes_encrypt(uint8_t *key, uint8_t *iv, uint8_t *plain, uint32_t plain_len, uint8_t *cipher_text, uint32_t *cipher_len);
    EVP_PKEY* create_dh_pkey(BIGNUM *p, BIGNUM *g, BIGNUM *bn_priv, BIGNUM *bn_pub);
    static uint8_t platform_compute_shared_secret(uint8_t **shared_secret, uint16_t *shared_secret_len,
        uint8_t *remote_pub, uint16_t remote_pub_len,
        uint8_t *local_priv, uint8_t local_priv_len);
    unsigned int get_e_uuid(unsigned char *uuid) { memcpy(uuid, (unsigned char *)&m_crypto_info.e_uuid, sizeof(uuid_t)); return sizeof(uuid_t); }
    unsigned int get_r_uuid(unsigned char *uuid) { memcpy(uuid, (unsigned char *)&m_crypto_info.r_uuid, sizeof(uuid_t)); return sizeof(uuid_t); }
    unsigned int get_e_nonce(unsigned char *nonce) { memcpy(nonce, (unsigned char *)&m_crypto_info.e_nonce, sizeof(em_nonce_t)); return sizeof(em_nonce_t); }
    unsigned int get_r_nonce(unsigned char *nonce) { memcpy(nonce, (unsigned char *)&m_crypto_info.r_nonce, sizeof(em_nonce_t)); return sizeof(em_nonce_t); }

    unsigned char *get_e_nonce() { return (unsigned char *)&m_crypto_info.e_nonce; }
    unsigned char *get_r_nonce() { return (unsigned char *)&m_crypto_info.r_nonce; }

    void set_e_uuid(unsigned char *uuid, unsigned int len) { memcpy((unsigned char *)&m_crypto_info.e_uuid, uuid, len); }
    void set_r_uuid(unsigned char *uuid, unsigned int len) { memcpy((unsigned char *)&m_crypto_info.r_uuid, uuid, len); }
    void set_e_nonce(unsigned char *nonce, unsigned int len) { memcpy((unsigned char *)&m_crypto_info.e_nonce, nonce, len); }
    void set_r_nonce(unsigned char *nonce, unsigned int len) { memcpy((unsigned char *)&m_crypto_info.r_nonce, nonce, len); }

    unsigned char *get_e_public() { return m_crypto_info.e_pub; }
    unsigned int get_e_public_len() { return m_crypto_info.e_pub_len; }
    unsigned char *get_e_private() { return m_crypto_info.e_priv; }
    unsigned int get_e_private_len() { return m_crypto_info.e_priv_len; }
    unsigned char *get_r_public() { return m_crypto_info.r_pub; }
    unsigned int get_r_public_len() { return m_crypto_info.r_pub_len; }
    unsigned char *get_r_private() { return m_crypto_info.r_priv; }
    unsigned int get_r_private_len() { return m_crypto_info.r_priv_len; }

    uint8_t generate_iv(unsigned char *iv, unsigned int len) { if (!RAND_bytes(iv, len)) { return 0; } else { return 1; } }

    void set_e_public(unsigned char *pub, unsigned int len) { memcpy(m_crypto_info.e_pub, pub, len); }
    void set_r_public(unsigned char *pub, unsigned int len) { memcpy(m_crypto_info.r_pub, pub, len); }

    unsigned char *get_e_mac() { return m_crypto_info.e_mac; }
    unsigned char *get_r_mac() { return m_crypto_info.r_mac; }

    void set_e_mac(unsigned char *mac) { memcpy(m_crypto_info.e_mac, mac, sizeof(mac_address_t)); }
    void set_r_mac(unsigned char *mac) { memcpy(m_crypto_info.r_mac, mac, sizeof(mac_address_t)); }
    em_crypto_t();
    ~em_crypto_t() {}
};
#endif
