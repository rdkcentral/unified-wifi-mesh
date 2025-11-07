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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <ifaddrs.h>

#include "em.h"
#include "em_crypto.h"
#include "util.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/dh.h>


#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif

// Initialize the static member variables
// From RFC 3526
uint8_t em_crypto_t::g_dh1536_p[] =  {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xC9,0x0F,0xDA,0xA2,
    0x21,0x68,0xC2,0x34,0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1,
    0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,0x02,0x0B,0xBE,0xA6,
    0x3B,0x13,0x9B,0x22,0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
    0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B,0x30,0x2B,0x0A,0x6D,
    0xF2,0x5F,0x14,0x37,0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45,
    0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,0xF4,0x4C,0x42,0xE9,
    0xA6,0x37,0xED,0x6B,0x0B,0xFF,0x5C,0xB6,0xF4,0x06,0xB7,0xED,
    0xEE,0x38,0x6B,0xFB,0x5A,0x89,0x9F,0xA5,0xAE,0x9F,0x24,0x11,
    0x7C,0x4B,0x1F,0xE6,0x49,0x28,0x66,0x51,0xEC,0xE4,0x5B,0x3D,
    0xC2,0x00,0x7C,0xB8,0xA1,0x63,0xBF,0x05,0x98,0xDA,0x48,0x36,
    0x1C,0x55,0xD3,0x9A,0x69,0x16,0x3F,0xA8,0xFD,0x24,0xCF,0x5F,
    0x83,0x65,0x5D,0x23,0xDC,0xA3,0xAD,0x96,0x1C,0x62,0xF3,0x56,
    0x20,0x85,0x52,0xBB,0x9E,0xD5,0x29,0x07,0x70,0x96,0x96,0x6D,
    0x67,0x0C,0x35,0x4E,0x4A,0xBC,0x98,0x04,0xF1,0x74,0x6C,0x08,
    0xCA,0x23,0x73,0x27,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
};
uint8_t em_crypto_t::g_dh1536_g[] = { 0x02 };

static pthread_once_t init_once = PTHREAD_ONCE_INIT;

em_crypto_t::em_crypto_t() {

    #if OPENSSL_VERSION_NUMBER >= 0x30000000L
    memset(&m_crypto_info, 0, sizeof(em_crypto_info_t));
    pthread_once(&init_once, []() {
        if (OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL) == 0) {
            fprintf(stderr, "OpenSSL initialization failed\n");
            exit(1);
        }

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        if (OSSL_PROVIDER_load(NULL, "default") == NULL) {
            fprintf(stderr, "Failed to load default provider\n");
            exit(1);
        }
#endif
    });
    #endif
}

int em_crypto_t::init()
{

    BIGNUM *priv_key = NULL, *pub_key = NULL;

    RAND_bytes(m_crypto_info.e_nonce, sizeof(em_nonce_t));
    uuid_generate(m_crypto_info.e_uuid);

    BIGNUM *p = NULL;
    BIGNUM *g = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_PKEY *param_pkey = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *pkey = NULL;
#else
    DH *dh = NULL;
#endif
    /* Create prime and generator by converting binary to BIGNUM format */
    p = BN_bin2bn(g_dh1536_p, sizeof(g_dh1536_p), NULL);
    if (!p) { goto bail; }
    g = BN_bin2bn(g_dh1536_g, sizeof(g_dh1536_g), NULL);
    if (!g) { goto bail; }

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    if (NULL == (dh = DH_new())) {
        goto bail;
    }

    /* Set prime and generator */

    #if OPENSSL_VERSION_NUMBER < 0x10100000L
    dh->p = p;
    dh->g = g;

    #else 
    if (DH_set0_pqg(dh, p, NULL, g) != 1) {
        goto bail;
    }
    #endif

    /* Obtain key pair */
    if (0 == DH_generate_key(dh)) {
        goto bail;
    }

    // Get private and public keys (pre 3.0)
    DH_get0_key(dh, const_cast<const BIGNUM**> (&pub_key), const_cast<const BIGNUM**> (&priv_key));
    DH_get0_key(dh, const_cast<const BIGNUM**> (&pub_key), const_cast<const BIGNUM**> (&priv_key));
#else

    if (NULL == (param_pkey = create_dh_pkey(p, g, NULL, NULL))){
        printf("%s:%d Failed to create DH parameter key\n", __func__, __LINE__);
        goto bail;
    }

    /* Create new context for key generation using the parameters */
    pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, param_pkey, NULL);
    if (pkey_ctx == NULL) {
        printf("%s:%d Failed to create key generation context\n", __func__, __LINE__);
        goto bail;
    }

    /* Initialize for key generation */
    if (EVP_PKEY_keygen_init(pkey_ctx) != 1) {
        printf("%s:%d Failed to initialize key generation\n", __func__, __LINE__);
        goto bail;
    }

    /* Create key pair */
    if (EVP_PKEY_keygen(pkey_ctx, &pkey) != 1) {
        printf("%s:%d Failed to generate key pair\n", __func__, __LINE__);
        goto bail;
    }

    // Get private and public keys (post 3.0)
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, &pub_key) != 1) {
        printf("%s:%d Failed to get public key\n", __func__, __LINE__);
        goto bail;
    }
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv_key) != 1) {
        printf("%s:%d Failed to get private key\n", __func__, __LINE__);
        goto bail;
    }
#endif

    // now generate the keys
    BN_bn2bin(pub_key, m_crypto_info.e_pub);
    BN_bn2bin(priv_key, m_crypto_info.e_priv);
    m_crypto_info.e_pub_len = static_cast<unsigned int> (BN_num_bytes(pub_key));
    m_crypto_info.e_priv_len = static_cast<unsigned int> (BN_num_bytes(priv_key));
    
    BN_bn2bin(pub_key, m_crypto_info.r_pub);
    BN_bn2bin(priv_key, m_crypto_info.r_priv);
    m_crypto_info.r_pub_len = static_cast<unsigned int> (BN_num_bytes(pub_key));
    m_crypto_info.r_priv_len = static_cast<unsigned int> (BN_num_bytes(priv_key));
    
    return 0;
bail:

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    if (dh) {
        DH_free(dh);
        cleanup_bignums(NULL, NULL, priv_key, pub_key);
    }else{
        cleanup_bignums(p, g, priv_key, pub_key);
    }
#else
    if (param_pkey) EVP_PKEY_free(param_pkey);
    if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
    if (pkey) EVP_PKEY_free(pkey);

    cleanup_bignums(p, g, priv_key, pub_key);
#endif

    EVP_cleanup();
    ERR_free_strings();

    printf("%s:%d Failed to initialize crypto\n", __func__, __LINE__);
    return -1;
}

uint8_t em_crypto_t::platform_hash(const EVP_MD * hashing_algo, uint8_t num_elem, uint8_t **addr, size_t *len, uint8_t *digest)
{  
    EVP_MD_CTX   *ctx;
    unsigned int  mac_len;
    uint8_t       res = 1;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return 0;
    }
#else
    EVP_MD_CTX  ctx_aux;
    ctx = &ctx_aux;

    EVP_MD_CTX_init(ctx);
#endif

    if (!EVP_DigestInit_ex(ctx, hashing_algo, NULL)) {
        res = 0;
    }

    if (1 == res) {
        size_t i;

        for (i = 0; i < num_elem; i++) {
            if (!EVP_DigestUpdate(ctx, addr[i], len[i])) {
                res = 0;
                break;
            }
        }
    }

    if (1 == res) {
        if (!EVP_DigestFinal(ctx, digest, &mac_len)) {
            res = 0;
        }
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    EVP_MD_CTX_free(ctx);
#endif

    return res;
}
uint8_t em_crypto_t::platform_hmac_hash(const EVP_MD * hashing_algo, uint8_t *key, size_t keylen, uint8_t num_elem, uint8_t **addr, size_t *len, uint8_t *hmac)
{

    if (!key || !addr || !len || !hmac || keylen == 0) {
        return 0;
    }

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_MD_CTX   *ctx;
    EVP_PKEY     *pkey;
#else
    HMAC_CTX     *ctx;
#endif
    size_t        i;
    unsigned int mdlen = static_cast<unsigned int> (EVP_MD_size(hashing_algo));

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    ctx = EVP_MD_CTX_new();
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
    ctx = HMAC_CTX_new();
#else
    HMAC_CTX  ctx_aux;
    ctx = &ctx_aux;

    HMAC_CTX_init(ctx);
#endif
    if (!ctx) {
        return 0;
    }

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key, keylen);
    if (pkey == NULL) {
        goto bail;
    }
    if (EVP_DigestSignInit(ctx, NULL, hashing_algo, NULL, pkey) != 1) {
        goto bail;
    }

    for (i = 0; i < num_elem; i++) {
        if (EVP_DigestSignUpdate(ctx, addr[i], len[i]) != 1) {
            goto bail;
        }
    }

    if (EVP_DigestSignFinal(ctx, hmac, reinterpret_cast<size_t*>(&mdlen)) != 1) {
        goto bail;
    }
#else
    if (HMAC_Init_ex(ctx, key, static_cast<int> (keylen), hashing_algo, NULL) != 1) {
        goto bail;
    }

    for (i = 0; i < num_elem; i++) {
        HMAC_Update(ctx, addr[i], len[i]);
    }

    if (HMAC_Final(ctx, hmac, &mdlen) != 1) {
        goto bail;
    }
#endif

    /* Release resources */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (pkey)
        EVP_PKEY_free(pkey);
    if (ctx)
        EVP_MD_CTX_free(ctx);
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
    HMAC_CTX_free(ctx);
#else
    HMAC_CTX_cleanup(ctx);
#endif

    return 1;

bail:
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (pkey)
        EVP_PKEY_free(pkey);
    if (ctx)
        EVP_MD_CTX_free(ctx);
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
    HMAC_CTX_free(ctx);
#else
    HMAC_CTX_cleanup(ctx);
#endif

    //em_util_info_print(EM_CONF," %s:%d\n",__func__,__LINE__);
    return 0;
}
void em_crypto_t:: append_u32_net(const uint32_t *memory_pointer, uint8_t **packet_ppointer)
{
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    **packet_ppointer = *(((uint8_t *)memory_pointer)+0); (*packet_ppointer)++;
    **packet_ppointer = *(((uint8_t *)memory_pointer)+1); (*packet_ppointer)++;
    **packet_ppointer = *(((uint8_t *)memory_pointer)+2); (*packet_ppointer)++;
    **packet_ppointer = *(((uint8_t *)memory_pointer)+3); (*packet_ppointer)++;
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    **packet_ppointer = *((reinterpret_cast<uint8_t *> (const_cast<uint32_t*>(memory_pointer))+3)); (*packet_ppointer)++;
    **packet_ppointer = *((reinterpret_cast<uint8_t *> (const_cast<uint32_t*>(memory_pointer))+2)); (*packet_ppointer)++;
    **packet_ppointer = *((reinterpret_cast<uint8_t *> (const_cast<uint32_t*>(memory_pointer))+1)); (*packet_ppointer)++;
    **packet_ppointer = *((reinterpret_cast<uint8_t *> (const_cast<uint32_t*>(memory_pointer))+0)); (*packet_ppointer)++;
#else
#error You must specify your architecture endianess
#endif
}

uint8_t em_crypto_t:: wps_key_derivation_function(uint8_t *key, uint8_t *label_prefix, size_t label_prefix_len, char *label, uint8_t *res, uint32_t res_len)
{
    uint8_t i_buf[4];
    uint8_t key_bits[4];

    uint8_t   *addr[4];
    size_t   len[4];

    uint32_t i, iter;

    uint8_t  hash[SHA256_MAC_LEN] = {0};
    uint8_t *opos;

    uint32_t left;

    uint8_t  *p;
    uint32_t  aux;

    aux = res_len * 8;
    p   = key_bits;

    append_u32_net(&aux, &p);

    addr[0] = i_buf;
    addr[1] = label_prefix;
    addr[2] = reinterpret_cast<uint8_t *> (label);
    addr[3] = key_bits;
    len[0]  = sizeof(i_buf);
    len[1]  = label_prefix_len;
    len[2]  = strlen(label);
    len[3]  = sizeof(key_bits);

    iter = (res_len + SHA256_MAC_LEN - 1) / SHA256_MAC_LEN;
    opos = res;
    left = res_len;

    for (i = 1; i <= iter; i++) {
        p = i_buf;
        append_u32_net(&i, &p);

        if (platform_hmac_SHA256(key, SHA256_MAC_LEN, 4, addr, len, hash) != 1) {
            //em_util_info_print(EM_CONF,"platform_hmac_SHA256 error %s:%d\n" ,__func__,__LINE__);
            return 0;
        }

        if (i < iter) {
            memcpy(opos, hash, SHA256_MAC_LEN);
            opos += SHA256_MAC_LEN;
            left -= SHA256_MAC_LEN;
        } else {
            memcpy(opos, hash, left);
        }
    }
    return 1; 
}
uint8_t em_crypto_t::platform_cipher_encrypt(const EVP_CIPHER *cipher_type, uint8_t *key, uint8_t *iv, uint8_t *plain, uint32_t plain_len, uint8_t *cipher_text, uint32_t *cipher_len, bool disable_padding)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX _ctx;
#endif
    EVP_CIPHER_CTX *ctx;
    int len = static_cast<int> (plain_len + AES_BLOCK_SIZE - 1), final_len = 0;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX_init(&_ctx);
    ctx = &_ctx;
#else
    ctx=EVP_CIPHER_CTX_new();
    if (!ctx) {
        return 0;
    }
#endif
    
    // For wrap ciphers, set the appropriate flags BEFORE init
    if (EVP_CIPHER_mode(cipher_type) == EVP_CIPH_WRAP_MODE) {
        EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    }
    
    if (EVP_EncryptInit_ex(ctx, cipher_type, NULL, key, iv) != 1) {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        printf("%s:%d EVP_EncryptInit_ex failed: %s\n", __func__, __LINE__, err_buf);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        EVP_CIPHER_CTX_cleanup(ctx);
#else
        EVP_CIPHER_CTX_free(ctx);
#endif
        return 0;
    }

    if (disable_padding) {
        EVP_CIPHER_CTX_set_padding(ctx, 0);
    }

    
    if (EVP_EncryptUpdate(ctx, cipher_text, &len, plain, static_cast<int> (plain_len)) != 1) {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        printf("%s:%d EVP_EncryptUpdate failed: %s\n", __func__, __LINE__, err_buf);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        EVP_CIPHER_CTX_cleanup(ctx);
#else
        EVP_CIPHER_CTX_free(ctx);
#endif
        return 0;
    }

    if (EVP_EncryptFinal_ex(ctx, cipher_text + len, &final_len) != 1) {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        printf("%s:%d EVP_EncryptFinal_ex failed: %s\n", __func__, __LINE__, err_buf);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        EVP_CIPHER_CTX_cleanup(ctx);
#else
        EVP_CIPHER_CTX_free(ctx);
#endif
        return 0;
    }

    *cipher_len = static_cast<uint32_t> (len + final_len);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX_cleanup(ctx);
#else
    EVP_CIPHER_CTX_free(ctx);
#endif

    return 1;
}
uint8_t em_crypto_t::platform_cipher_decrypt(const EVP_CIPHER *cipher_type, uint8_t *key, uint8_t *iv, uint8_t *data, uint32_t data_len, bool disable_padding)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX _ctx;
#endif
    EVP_CIPHER_CTX *ctx;
    int             plen, len;
    uint8_t         buf[AES_BLOCK_SIZE];

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX_init(&_ctx);
    ctx = &_ctx;
#else
    ctx=EVP_CIPHER_CTX_new();
    if (!ctx) {
        return 0;
    }
#endif
    
    // For wrap ciphers, set the appropriate flags BEFORE init
    if (EVP_CIPHER_mode(cipher_type) == EVP_CIPH_WRAP_MODE) {
        EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    }
    
    if (EVP_DecryptInit_ex(ctx, cipher_type, NULL, key, iv) != 1) {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        printf("%s:%d EVP_DecryptInit_ex failed: %s\n", __func__, __LINE__, err_buf);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        EVP_CIPHER_CTX_cleanup(ctx);
#else
        EVP_CIPHER_CTX_free(ctx);
#endif
        return 0;
    }

    if (disable_padding) {
        EVP_CIPHER_CTX_set_padding(ctx, 0);
    }
    

    plen = static_cast<int> (data_len);
    if (EVP_DecryptUpdate(ctx, data, &plen, data, static_cast<int> (data_len)) != 1) {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        printf("%s:%d EVP_DecryptUpdate failed: %s\n", __func__, __LINE__, err_buf);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        EVP_CIPHER_CTX_cleanup(ctx);
#else
        EVP_CIPHER_CTX_free(ctx);
#endif
        return 0;
    }

    len = sizeof(buf);
    if (EVP_DecryptFinal_ex(ctx, buf, &len) != 1) {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        printf("%s:%d EVP_DecryptFinal_ex failed: %s\n", __func__, __LINE__, err_buf);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        EVP_CIPHER_CTX_cleanup(ctx);
#else
        EVP_CIPHER_CTX_free(ctx);
#endif
        return 0;
    }
    
    // For non-wrap ciphers, len should be 0 after final
    if (EVP_CIPHER_mode(cipher_type) != EVP_CIPH_WRAP_MODE && len != 0) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        EVP_CIPHER_CTX_cleanup(ctx);
#else
        EVP_CIPHER_CTX_free(ctx);
#endif
        return 0;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX_cleanup(ctx);
#else
    EVP_CIPHER_CTX_free(ctx);
#endif

    return 1;
}

uint8_t em_crypto_t::aes_key_wrap(uint8_t *kek, size_t kek_len, 
                                  uint8_t *plain, uint32_t plain_len,
                                  uint8_t *wrapped, uint32_t *wrapped_len)
{
    const EVP_CIPHER *cipher;
    
    // Default IV for AES Key Wrap (RFC 3394 2.2.3.1)
    uint8_t iv[8] = {0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6};

    
    // Select cipher based on KEK length (bytes)
    switch(kek_len) {
        case 16: cipher = EVP_aes_128_wrap(); break;
        case 24: cipher = EVP_aes_192_wrap(); break;
        case 32: cipher = EVP_aes_256_wrap(); break;
        default: return 0;
    }
    
    // Validate input length (must be multiple of 8, minimum 16)
    if (plain_len < 16 || (plain_len % 8) != 0) {
        return 0;
    }
    
    // Use platform_cipher_encrypt with padding DISABLED for wrap mode (true = disable padding)
    return platform_cipher_encrypt(cipher, kek, iv, plain, plain_len, wrapped, wrapped_len, true);
}

uint8_t em_crypto_t::aes_key_unwrap(uint8_t *kek, size_t kek_len,
                                    uint8_t *wrapped, uint32_t wrapped_len,
                                    uint8_t *unwrapped, uint32_t *unwrapped_len)
{
    const EVP_CIPHER *cipher;
    
    // Default IV for AES Key Wrap (RFC 3394 2.2.3.1)
    uint8_t iv[8] = {0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6};
    
    // Select cipher based on KEK length
    switch(kek_len) {
        case 16: cipher = EVP_aes_128_wrap(); break;
        case 24: cipher = EVP_aes_192_wrap(); break;
        case 32: cipher = EVP_aes_256_wrap(); break;
        default: return 0;
    }
    
    // Validate wrapped key length (must be multiple of 8, minimum 24)
    if (wrapped_len < 24 || (wrapped_len % 8) != 0) {
        return 0;
    }
    
    // Copy to output buffer first since platform_cipher_decrypt works in-place
    memcpy(unwrapped, wrapped, wrapped_len);
    
    // Use platform_cipher_decrypt with padding DISABLED for wrap mode (true = disable padding)
    if (platform_cipher_decrypt(cipher, kek, iv, unwrapped, wrapped_len, true) != 1) {
        return 0;
    }
    
    // Output length is 8 bytes less than wrapped length
    *unwrapped_len = wrapped_len - 8;
    
    return 1;
}



#if OPENSSL_VERSION_NUMBER >= 0x30000000L
EVP_PKEY* em_crypto_t::create_dh_pkey(BIGNUM *p, BIGNUM *g, BIGNUM *bn_priv, BIGNUM *bn_pub)
{
    OSSL_PARAM_BLD *param_bld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *dh_ctx = NULL;
    EVP_PKEY *dh_pkey = NULL;
    int selection;
    if (bn_priv) {
        selection = EVP_PKEY_KEYPAIR;
    } else if (bn_pub) {
        selection = EVP_PKEY_PUBLIC_KEY;
    } else {
        selection = EVP_PKEY_KEY_PARAMETERS;
    }

    param_bld = OSSL_PARAM_BLD_new();
    if (param_bld == NULL) {
        goto bail;
    }

    /* Set prime, generator and private or public key */
    if (OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_FFC_P, p) != 1 ||
            OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_FFC_G, g) != 1) {
        goto bail;
    }
    if (bn_priv) {
        if (OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_PRIV_KEY, bn_priv) != 1) {
            goto bail;
        }
    }
    if (bn_pub) {
        if (OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_PUB_KEY, bn_pub) != 1) {
            goto bail;
        }
    }
    params = OSSL_PARAM_BLD_to_param(param_bld);
    if (params == NULL) {
        goto bail;
    }

    dh_ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
    if (dh_ctx == NULL) {
	    printf("%s:%d Failed to create context\n", __func__, __LINE__);
        goto bail;
    }

    if (EVP_PKEY_fromdata_init(dh_ctx) != 1) {
        goto bail;
    }
    
    if (EVP_PKEY_fromdata(dh_ctx, &dh_pkey, selection, params) != 1 || dh_pkey == NULL) {
        goto bail;
    }   
    /* Release resources */
    EVP_PKEY_CTX_free(dh_ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);

    return dh_pkey;

bail:
    EVP_PKEY_free(dh_pkey);
    EVP_PKEY_CTX_free(dh_ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);

    return NULL;
}
#endif

uint8_t em_crypto_t::platform_compute_shared_secret(uint8_t **shared_secret, uint16_t *shared_secret_len,
        uint8_t *remote_pub, uint16_t remote_pub_len,
        uint8_t *local_priv, uint8_t local_priv_len) 
{
    if (!shared_secret || !shared_secret_len || !remote_pub || !local_priv) {
        printf("%s:%d Invalid arguments\n", __func__, __LINE__);
        return 0;
    }

    *shared_secret = NULL;
    *shared_secret_len = 0;

    if (remote_pub_len == 0 || local_priv_len == 0) {
        printf("%s:%d Invalid key lengths: remote_pub_len=%d, local_priv_len=%d\n", __func__, __LINE__,
               remote_pub_len, local_priv_len);
        return 0;
    }

    BIGNUM *p = BN_bin2bn(g_dh1536_p, sizeof(g_dh1536_p), NULL);
    BIGNUM *g = BN_bin2bn(g_dh1536_g, sizeof(g_dh1536_g), NULL);
    BIGNUM *bn_priv = BN_bin2bn(local_priv, local_priv_len, NULL);
    BIGNUM *bn_pub = BN_bin2bn(remote_pub, remote_pub_len, NULL);

    if (!p || !g || !bn_priv || !bn_pub) {
        cleanup_bignums(p, g, bn_priv, bn_pub);
        printf("%s:%d Failed to initialize BIGNUMs\n", __func__, __LINE__);
        return 0;
    }

    size_t secret_len = 0;
    uint8_t did_succeed = compute_secret_internal(p, g, bn_priv, bn_pub, 
                                           shared_secret, &secret_len);
    
    if (did_succeed) {
        *shared_secret_len = static_cast<uint16_t> (secret_len);
        return 1;
    }

    if (*shared_secret != NULL) OPENSSL_free(*shared_secret);
    *shared_secret = NULL;
    *shared_secret_len = 0;
    printf("%s:%d Internal failed\n", __func__, __LINE__);
    return 0;
}

/**
 * Encodes binary data using standard Base64 encoding.
 * 
 * @param input Binary data to encode
 * @param length Length of the input data
 * @return Base64 encoded string or empty string on failure
 */
std::string em_crypto_t::base64_encode(const uint8_t *input, size_t length) {
    if (!input || length == 0) {
        return "";
    }

    BIO *bio, *b64;
    
    // Create a base64 filter BIO and a memory BIO
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);  // Chain them together

    // Disable newlines in the output
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    
    // Write data through the BIO chain
    BIO_write(bio, input, static_cast<int>(length));
    BIO_flush(bio);

    // Extract the encoded data
    size_t data_length = 0;
    char* data_ptr = nullptr;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    BUF_MEM *bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);
    data_length = bufferPtr->length;
    data_ptr = bufferPtr->data; 
#elif OPENSSL_VERSION_NUMBER < 0x30000000L
    const BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    data_length = bptr->length;
    data_ptr = bptr->data;
#else
    data_length = static_cast<size_t>(BIO_get_mem_data(bio, &data_ptr));
#endif
    
    // Create string from the encoded data
    std::string result(data_ptr, data_length);
    
    // Clean up
    BIO_free_all(bio);
    
    return result;
}

/**
 * Encodes binary data using Base64URL encoding (URL-safe variant).
 * 
 * Replaces '+' with '-', '/' with '_', and removes padding '=' characters.
 * 
 * @param input Binary data to encode
 * @param length Length of the input data
 * @return Base64URL encoded string or empty string on failure
 */
std::string em_crypto_t::base64url_encode(const uint8_t *input, size_t length) {
    // First encode using standard Base64
    std::string base64 = base64_encode(input, length);
    
    if (base64.empty()) {
        return "";
    }
    
    // Convert to Base64URL format
    for (char& c : base64) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }
    
    // Remove padding characters
    size_t pos = base64.find_last_not_of('=');
    if (pos != std::string::npos) {
        base64.erase(pos + 1);
    }
    
    return base64;
}


std::optional<std::vector<uint8_t>> em_crypto_t::base64url_decode(const std::string& input) {
    // Convert Base64URL to standard Base64
    std::string base64_input = input;
    
    // Replace URL-safe characters with standard Base64 characters
    for (char& c : base64_input) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    
    // Add padding if necessary
    size_t mod4 = base64_input.length() % 4;
    if (mod4) {
        base64_input.append(4 - mod4, '=');
    }
    
    // Now delegate to the existing base64_decode function
    return base64_decode(base64_input);
}

std::optional<std::vector<uint8_t>> em_crypto_t::sign_data_ecdsa(const std::vector<uint8_t>& data_to_sign, EVP_PKEY* private_key, const EVP_MD * md)
{
    // Create signature context
    #if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_MD_CTX md_ctx_obj;
    EVP_MD_CTX_init(&md_ctx_obj);
    EVP_MD_CTX* md_ctx = &md_ctx_obj;
    #else
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        std::cerr << "Failed to create signature context" << std::endl;
        return std::nullopt;
    }
    #endif
    
    // Initialize the signature operation with provided digest
    if (EVP_DigestSignInit(md_ctx, nullptr, md, nullptr, private_key) != 1) {
        auto err = ERR_get_error();
        std::cerr << "Failed to initialize signature operation: " << ERR_error_string(err, nullptr) << std::endl;
        #if OPENSSL_VERSION_NUMBER < 0x10100000L
        EVP_MD_CTX_cleanup(md_ctx);
        #else
        EVP_MD_CTX_free(md_ctx);
        #endif
        return std::nullopt;
    }
    
    // Provide the data to be signed
    if (EVP_DigestSignUpdate(md_ctx, data_to_sign.data(), data_to_sign.size()) != 1) {
        auto err = ERR_get_error();
        std::cerr << "Failed to provide data to be signed: " << ERR_error_string(err, nullptr) << std::endl;
        #if OPENSSL_VERSION_NUMBER < 0x10100000L
        EVP_MD_CTX_cleanup(md_ctx);
        #else
        EVP_MD_CTX_free(md_ctx);
        #endif
        return std::nullopt;
    }
    
    // Determine the signature length
    size_t sig_len = 0;
    if (EVP_DigestSignFinal(md_ctx, nullptr, &sig_len) != 1) {
        auto err = ERR_get_error();
        std::cerr << "Failed to determine signature length: " << ERR_error_string(err, nullptr) << std::endl;
        #if OPENSSL_VERSION_NUMBER < 0x10100000L
        EVP_MD_CTX_cleanup(md_ctx);
        #else
        EVP_MD_CTX_free(md_ctx);
        #endif
        return std::nullopt;
    }
    
    // Get the signature
    std::vector<uint8_t> signature(sig_len);
    if (EVP_DigestSignFinal(md_ctx, signature.data(), &sig_len) != 1) {
        auto err = ERR_get_error();
        std::cerr << "Failed to create signature: " << ERR_error_string(err, nullptr) << std::endl;
        #if OPENSSL_VERSION_NUMBER < 0x10100000L
        EVP_MD_CTX_cleanup(md_ctx);
        #else
        EVP_MD_CTX_free(md_ctx);
        #endif
        return std::nullopt;
    }
    
    // Resize in case the actual signature is smaller than the buffer
    signature.resize(sig_len);
    
    // Clean up
    #if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_MD_CTX_cleanup(md_ctx);
    #else
    EVP_MD_CTX_free(md_ctx);
    #endif
    
    return signature;
}

std::optional<std::vector<uint8_t>> em_crypto_t::base64_decode(const std::string& input) {
    BIO *bio, *b64;

    // Create a vector to hold the decoded data
    std::vector<uint8_t> output;
    
    if (input.empty()) {
        return output;
    }
    
    // Calculate maximum possible decoded length (3/4 of input size)
    size_t max_decoded_len = (input.length() * 3) / 4 + 1;
    
    output.resize(max_decoded_len);
    
    bio = BIO_new_mem_buf(input.c_str(), -1);
    if (!bio) {
        return std::nullopt;
    }
    
    b64 = BIO_new(BIO_f_base64());
    if (!b64) {
        BIO_free(bio);
        return std::nullopt;
    }
    
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    
    int output_length = BIO_read(bio, output.data(), static_cast<int>(max_decoded_len));
    
    BIO_free_all(bio);
    
    if (output_length <= 0) {
        return std::nullopt;
    }
    
    // Resize the vector to the actual decoded size
    output.resize(static_cast<size_t>(output_length));
    
    return output;
}

void em_crypto_t::cleanup_bignums(BIGNUM *p, BIGNUM *g, BIGNUM *priv, BIGNUM *pub) {
    BN_clear_free(p);
    BN_clear_free(g);
    BN_clear_free(priv);
    BN_clear_free(pub);
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
uint8_t em_crypto_t::compute_secret_internal(BIGNUM *p, BIGNUM *g, BIGNUM *bn_priv, 
                                BIGNUM *bn_pub, uint8_t **shared_secret,
                                size_t *secret_len) {
    if (!p || !g || !bn_priv || !bn_pub) {
        printf("%s:%d Failed to initialize BIGNUMs\n", __func__, __LINE__);
        return 0;
    }

    EVP_PKEY* dh_priv = create_dh_pkey(p, g, bn_priv, NULL);
    EVP_PKEY* dh_pub = create_dh_pkey(p, g, NULL, bn_pub);
    if (!dh_priv || !dh_pub) {
        printf("%s:%d Failed to create DH keys\n", __func__, __LINE__);
        return 0;
    }

    EVP_PKEY_CTX *ctx;
    int ret = 0;

    // Thread-local library context (if needed for thread isolation)
    static thread_local OSSL_LIB_CTX *libctx = nullptr;
    if (!libctx) {
        libctx = OSSL_LIB_CTX_new(); // Create a new thread-local context
        if (!libctx) {
            printf("%s:%d Failed to create thread-local context\n", __func__, __LINE__);
            return 0;
        }
        // Load providers into the thread-local context
        if (!OSSL_PROVIDER_load(libctx, "default")) {
            printf("%s:%d Failed to load default provider\n", __func__, __LINE__);
            OSSL_LIB_CTX_free(libctx);
            libctx = nullptr;
            return 0;
        }
    }

    if (NULL == (ctx = EVP_PKEY_CTX_new_from_pkey(libctx, dh_priv, NULL))){
        printf("%s:%d EVP_PKEY_CTX_new failed\n", __func__, __LINE__);
        goto cleanup;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0){
        printf("%s:%d EVP_PKEY_derive_init failed\n", __func__, __LINE__);
        goto cleanup;
    }

    if (EVP_PKEY_derive_set_peer(ctx, dh_pub) <= 0){
        printf("%s:%d EVP_PKEY_derive_set_peer failed\n", __func__, __LINE__);
        goto cleanup;
    }

    /* Determine buffer length */
    if (EVP_PKEY_derive(ctx, NULL, secret_len) <= 0) {
        printf("%s:%d EVP_PKEY_derive failed\n", __func__, __LINE__);
        goto cleanup;
    }

    *shared_secret = (uint8_t*)OPENSSL_malloc(*secret_len);

    if (!*shared_secret) {
        printf("%s:%d shared secret malloc failed\n", __func__, __LINE__);
        goto cleanup;
    }
    
    if (EVP_PKEY_derive(ctx, *shared_secret, secret_len) <= 0) {
        printf("%s:%d EVP_PKEY_derive failed\n", __func__, __LINE__);
        goto cleanup;
    }

    ret = 1;

cleanup:
    // Cleanup

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(dh_priv);
    EVP_PKEY_free(dh_pub);

    cleanup_bignums(p, g, bn_priv, bn_pub);
    return static_cast<uint8_t> (ret);
}
#else
uint8_t em_crypto_t::compute_secret_internal(BIGNUM *p, BIGNUM *g, BIGNUM *bn_priv,
                                BIGNUM *bn_pub, uint8_t **shared_secret,
                                size_t *secret_len) {
    DH *dh = DH_new();
    if (!dh) {
        BN_clear_free(bn_pub);
        return 0;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    dh->p = p;
    dh->g = g;
    dh->priv_key = bn_priv;
#else
    if (DH_set0_pqg(dh, p, NULL, g) != 1 ||
        DH_set0_key(dh, NULL, bn_priv) != 1) {
        DH_free(dh);
        BN_clear_free(bn_pub);
        return 0;
    }
#endif
    int size = DH_size(dh);
    if (size <= 0) {
        DH_free(dh);
        BN_clear_free(bn_pub);
        return 0;
    }
    *shared_secret = static_cast<uint8_t*> (calloc(static_cast<size_t> (size), sizeof(uint8_t)));
    if (!*shared_secret) {
        // Memory allocation failed
        DH_free(dh);
        BN_clear_free(bn_pub);
        return 0;
    }
    *secret_len = static_cast<size_t> (DH_compute_key(*shared_secret, bn_pub, dh));
    
    DH_free(dh);
    BN_clear_free(bn_pub);

    return (*secret_len > 0) ? 1 : 0;
}
#endif

SSL_KEY* em_crypto_t::ec_key_from_base64_der(const std::string& base64_der_pubkey) 
{

    uint8_t key[1024];
    
    memset(key, 0, sizeof(key));

    int len = EVP_DecodeBlock(key, reinterpret_cast<const uint8_t*>(base64_der_pubkey.c_str()), static_cast<int> (base64_der_pubkey.length()));
    if (len < 0) {
        printf("%s:%d Failed to decode base 64 public key\n", __func__, __LINE__);
        return NULL;
    }

    const uint8_t *ptr = key;
#if OPENSSL_VERSION_NUMBER < 0x30000000L 
    EC_KEY *ec_key = d2i_EC_PUBKEY(NULL, &ptr, len);
    if (ec_key == NULL) {
        printf("%s:%d Failed to create EC key from DER\n", __func__, __LINE__);
        return NULL;
    }

    EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);

    return ec_key;
#else
    EVP_PKEY* pkey = d2i_PUBKEY(NULL, &ptr, len);

    if (!pkey) {
        printf("%s:%d Failed to create EVP_PKEY from DER\n", __func__, __LINE__);
        return NULL;
    }
    return pkey;
#endif

}

std::string em_crypto_t::ec_key_to_base64_der(const SSL_KEY *key) { 
    if (!key) {
        printf("%s:%d Invalid key parameter\n", __func__, __LINE__);
        return "";
    }

    unsigned char *der_buffer = NULL;
    int der_length = 0;

    // Convert the key to DER format
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    der_length = i2d_EC_PUBKEY(const_cast<SSL_KEY*>(key), &der_buffer);
#else
    der_length = i2d_PUBKEY(key, &der_buffer);
#endif

    if (der_length <= 0 || !der_buffer) {
        printf("%s:%d Failed to convert key to DER format\n", __func__, __LINE__);
        return "";
    }

    // Base64 encode the DER data
    std::string base64_der = base64_encode(der_buffer, static_cast<size_t>(der_length));
    
    // Clean up
    OPENSSL_free(der_buffer);
    
    return base64_der;
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
EC_GROUP *em_crypto_t::get_key_group(const SSL_KEY *key)
{
    // key = EVP_PKEY
    if (EVP_PKEY_get_id(key) != EVP_PKEY_EC) {
        return NULL;
    }

    EC_GROUP* group = NULL;
    
    // Get the EC group from the key
    if (EVP_PKEY_get_group_name(key, NULL, 0, NULL) <= 0) return NULL;
    
    char group_name[64];
    size_t group_name_len = 0;
    if (EVP_PKEY_get_group_name(key, group_name, sizeof(group_name), &group_name_len) <= 0) return NULL;
    
    // Create a group from the name
    group = EC_GROUP_new_by_curve_name(OBJ_txt2nid(group_name));
    if (!group) return NULL;

    return group;
}

BIGNUM *em_crypto_t::get_priv_key_bn(const SSL_KEY *key)
{
    if (!key) return NULL;
    // Check if the key is an EC key
    if (EVP_PKEY_get_id(key) != EVP_PKEY_EC) {
        return NULL;
    }
    BIGNUM *priv = NULL;
    
    if (!EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_PRIV_KEY, &priv)) {
        em_printfout("Failed to get private key BIGNUM");
        return NULL;
    }

    return priv;
}

EC_POINT *em_crypto_t::get_pub_key_point(const SSL_KEY *key, EC_GROUP* key_group)
{

    if (!key) return NULL;
    // Check if the key is an EC key
    if (EVP_PKEY_get_id(key) != EVP_PKEY_EC) {
        return NULL;
    }

    // Use the existing method to get the group
    EC_GROUP* group = key_group;
    bool free_group = false;
    if (group == NULL){
        group = get_key_group(key);
        free_group = true;
    }
    if (!group) return NULL;
    
    EC_POINT* point = NULL;
    BIGNUM *x = BN_new(), *y = BN_new();
    
    if (!x || !y) {
        goto cleanup;
    }
    
    // Extract the X and Y coordinates
    if (!EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_X, &x) ||
        !EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_Y, &y)) {
        em_printfout("Failed to get public key coordinates");
        goto cleanup;
    }
    
    // Create an EC_POINT from the coordinates
    point = EC_POINT_new(group);
    if (!point) goto cleanup;
    
    if (!EC_POINT_set_affine_coordinates(group, point, x, y, NULL)) {
        EC_POINT_free(point);
        point = NULL;
    }
    
cleanup:

    if (x) BN_free(x);
    if (y) BN_free(y);
    if (group && free_group) EC_GROUP_free(group);
    
    return point;
}

SSL_KEY *em_crypto_t::generate_ec_key(EC_GROUP *group)
{
    if (!group) return NULL;
    return generate_ec_key(EC_GROUP_get_curve_name(group));
}

SSL_KEY *em_crypto_t::generate_ec_key(int nid)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *param_ctx = NULL;

    // Create a parameter generation context for the curve
    param_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!param_ctx) return NULL;

    // Initialize the parameter generation
    if (EVP_PKEY_paramgen_init(param_ctx) <= 0) {
        EVP_PKEY_CTX_free(param_ctx);
        return NULL;
    }

    // Set the curve name parameter
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(param_ctx, nid) <= 0) {
        EVP_PKEY_CTX_free(param_ctx);
        return NULL;
    }

    // Generate the parameters
    if (EVP_PKEY_paramgen(param_ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(param_ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(param_ctx);

    // Generate the key pair
    EVP_PKEY_CTX *key_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!key_ctx) {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    
    if (EVP_PKEY_keygen_init(key_ctx) <= 0) {
        EVP_PKEY_CTX_free(key_ctx);
        EVP_PKEY_free(pkey);
        return NULL;
    }
    
    EVP_PKEY *key = NULL;
    if (EVP_PKEY_keygen(key_ctx, &key) <= 0) {
        EVP_PKEY_CTX_free(key_ctx);
        EVP_PKEY_free(pkey);
        return NULL;
    }
    
    EVP_PKEY_CTX_free(key_ctx);
    EVP_PKEY_free(pkey);
    
    return key;
}
void em_crypto_t::free_key(SSL_KEY *key)
{
    if (!key) return;
    EVP_PKEY_free(key);
}
bool em_crypto_t::write_keypair_to_pem(const SSL_KEY *key, const std::string &file_path) { 
    
    FILE *fp = NULL;
    bool ret = false;
    
    ASSERT_NOT_NULL(key, false, "%s:%d NULL key parameter", __func__, __LINE__);
    ASSERT_MSG_TRUE(file_path.length() > 0, false, "%s:%d Invalid file path", __func__, __LINE__);
    ASSERT_MSG_TRUE(file_path.length() < 1024, false, "%s:%d File path too long", __func__, __LINE__);
    
    fp = fopen(file_path.c_str(), "wb");
    ASSERT_NOT_NULL(fp, false, "%s:%d Failed to open file (%s)", __func__, __LINE__, file_path.c_str());
    
    // Write private key to PEM file
    if (!PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL)) {
        printf("%s:%d Failed to write private key to PEM file\n", __func__, __LINE__);
        goto err;
    }
    
    // Write public key to the same PEM file
    if (!PEM_write_PUBKEY(fp, key)) {
        printf("%s:%d Failed to write public key to PEM file\n", __func__, __LINE__);
        goto err;
    }
    
    ret = true;
    printf("%s:%d Successfully wrote keypair to %s\n", __func__, __LINE__, file_path.c_str());

err:
    if (fp) fclose(fp);
    return ret;

}
SSL_KEY *em_crypto_t::read_keypair_from_pem(const std::string &file_path) { 
    FILE *fp = NULL;
    SSL_KEY *pkey = NULL;
    
    fp = fopen(file_path.c_str(), "rb");
    EM_ASSERT_NOT_NULL(fp, NULL, "Failed to open file (%s)", file_path.c_str());
    
    // Read private key - this will contain both private and public key information
    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    if (!pkey) {
        em_printfout("Failed to read private key from PEM file");
        goto err;
    }
    
    fclose(fp);
    return pkey;

err:
    if (pkey) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    if (fp) fclose(fp);
    return pkey;
}
#else
EC_GROUP *em_crypto_t::get_key_group(const SSL_KEY *key)
{
    if (!key) return NULL;

    const EC_GROUP* group = EC_KEY_get0_group(key);
    if (!group) return NULL;

    // Provides consistent behavior across different OpenSSL versions
    // since OpenSSL 3.0+ creates a new EC_GROUP object.
    int nid = EC_GROUP_get_curve_name(group);
    return EC_GROUP_new_by_curve_name(nid);
}
BIGNUM *em_crypto_t::get_priv_key_bn(const SSL_KEY *key)
{
    if (!key) return NULL;
    
    // Get the original point
    const BIGNUM* original = EC_KEY_get0_private_key(key);
    if (!original) return NULL;
    
    // Provides consistent behavior across different OpenSSL versions
    // since OpenSSL 3.0+ creates a new BIGNUM object.
    return BN_dup(original);
}

EC_POINT *em_crypto_t::get_pub_key_point(const SSL_KEY *key, EC_GROUP* key_group)
{
    if (!key) return NULL;
    
    // Get the original point
    const EC_POINT* original = EC_KEY_get0_public_key(key);
    if (!original) return NULL;
    
    // Use provided group or get it from the key
    EC_GROUP* group = key_group;
    if (!group) {
        group = const_cast<EC_GROUP*>(EC_KEY_get0_group(key));
        if (!group) return NULL;
    }
    // Provides consistent behavior across different OpenSSL versions
    // since OpenSSL 3.0+ creates a new EC_POINT object. 
    return EC_POINT_dup(original, const_cast<const EC_GROUP*>(group));
}
SSL_KEY *em_crypto_t::generate_ec_key(EC_GROUP *group)
{
    if (!group) return NULL;
    return generate_ec_key(EC_GROUP_get_curve_name(group));
}

SSL_KEY *em_crypto_t::generate_ec_key(int nid)
{
    SSL_KEY *proto_key = EC_KEY_new_by_curve_name(nid);
    if (proto_key == NULL) return NULL;

    if (EC_KEY_generate_key(proto_key) == 0) {
        EC_KEY_free(proto_key);
        return NULL;
    }
    return proto_key;
}

void em_crypto_t::free_key(SSL_KEY *key)
{
    if (!key) return;
    EC_KEY_free(key);
}

bool em_crypto_t::write_keypair_to_pem(const SSL_KEY *key, const std::string &file_path) { 
    
    FILE *fp = NULL;
    bool ret = false;
    
    ASSERT_NOT_NULL(key, false, "%s:%d NULL key parameter", __func__, __LINE__);
    ASSERT_MSG_TRUE(file_path.length() > 0, false, "%s:%d Invalid file path", __func__, __LINE__);
    ASSERT_MSG_TRUE(file_path.length() < 1024, false, "%s:%d File path too long", __func__, __LINE__);
    
    fp = fopen(file_path.c_str(), "wb");
    ASSERT_NOT_NULL(fp, false, "%s:%d Failed to open file (%s)", __func__, __LINE__, file_path.c_str());
    
    // Write private key to PEM file
    if (!PEM_write_ECPrivateKey(fp, const_cast<SSL_KEY*>(key), NULL, NULL, 0, NULL, NULL)) {
        printf("%s:%d Failed to write private key to PEM file\n", __func__, __LINE__);
        goto err;
    }
    
    // Write public key to the same PEM file
    if (!PEM_write_EC_PUBKEY(fp, const_cast<SSL_KEY*>(key))) {
        printf("%s:%d Failed to write public key to PEM file\n", __func__, __LINE__);
        goto err;
    }
    
    ret = true;

err:
    if (fp) fclose(fp);
    return ret;

}
SSL_KEY *em_crypto_t::read_keypair_from_pem(const std::string &file_path) { 
    FILE *fp = NULL;
    SSL_KEY *ec_key = NULL;
    
    fp = fopen(file_path.c_str(), "rb");
    ASSERT_NOT_NULL(fp, NULL, "%s:%d Failed to open file (%s)", __func__, __LINE__, file_path.c_str());
    
    // Read private key - this will contain both private and public key information 
    ec_key = PEM_read_ECPrivateKey(fp, NULL, NULL, NULL);
    if (!ec_key) {
        printf("%s:%d Failed to read private key from PEM file\n", __func__, __LINE__);
        goto err;
    }
    
    // Successfully read the key, return it
    fclose(fp);
    return ec_key;

err:
    if (ec_key) {
        free_key(ec_key);
        ec_key = NULL;
    }
    if (fp) fclose(fp);
    return ec_key;
}
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
SSL_KEY *em_crypto_t::create_ec_key_from_coordinates(const EC_GROUP* group,
    const std::vector<uint8_t> &x_bin, const std::vector<uint8_t> &y_bin,
    const std::optional<std::vector<uint8_t>> &priv_key_bytes)
{
    EVP_PKEY *pkey = nullptr;
    OSSL_PARAM_BLD *param_bld = nullptr;
    OSSL_PARAM *params = nullptr;
    EVP_PKEY_CTX *ctx = nullptr;
    BIGNUM *x = nullptr, *y = nullptr, *priv_key_bn = nullptr;
    uint8_t *buf = nullptr;
    size_t buf_len = 0;
    int nid = NID_undef;
    const char* group_name;

    // Create BIGNUMs for coordinates
    x = BN_bin2bn(x_bin.data(), static_cast<int>(x_bin.size()), nullptr);
    y = BN_bin2bn(y_bin.data(), static_cast<int>(y_bin.size()), nullptr);
    if (!x || !y) {
        printf("Failed to convert X or Y coordinates to BIGNUM\n");
        goto err;
    }

    if ((param_bld = OSSL_PARAM_BLD_new()) == NULL) goto err;

    nid = EC_GROUP_get_curve_name(group);
    if (nid == NID_undef) {
        printf("Failed to get curve name from group\n");
        goto err;
    }
    group_name = EC_curve_nid2nist(nid);
    if (!group_name) {
        printf("Failed to get NIST name for curve NID %d\n", nid);
        goto err;
    }

    // Set the EC group name
    if (!OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME, group_name, 0))
        goto err;

    // Create a properly formatted uncompressed EC point from X and Y
    // Format: 0x04 || X || Y (where 0x04 indicates uncompressed point)
    // Reference: https://mta.openssl.org/pipermail/openssl-users/2021-October/014494.html
    buf_len = 1 + x_bin.size() + y_bin.size();
    buf = reinterpret_cast<uint8_t *>(OPENSSL_malloc(buf_len));
    if (!buf) {
        printf("Failed to allocate memory for EC point\n");
        goto err;
    }

    buf[0] = 0x04;                                              // Uncompressed point format
    memcpy(buf + 1, x_bin.data(), x_bin.size());                // Copy X coordinate
    memcpy(buf + 1 + x_bin.size(), y_bin.data(), y_bin.size()); // Copy Y coordinate after X

    // Set the Public Key as Uncompressed EC Point byte buffer
    if (!OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PUB_KEY, buf, buf_len)) {
        printf("Failed to set public key\n");
        goto err;
    }

    // Add private key if provided
    if (priv_key_bytes.has_value()) {
        priv_key_bn =
            BN_bin2bn(priv_key_bytes->data(), static_cast<int>(priv_key_bytes->size()), nullptr);
        if (!priv_key_bn) {
            printf("Failed to convert private key to BIGNUM\n");
            goto err;
        }

        if (!OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_PRIV_KEY, priv_key_bn)) {
            printf("Failed to set private key\n");
            goto err;
        }
    }

    if ((params = OSSL_PARAM_BLD_to_param(param_bld)) == NULL) goto err;
    if ((ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL)) == NULL) goto err;
    if (EVP_PKEY_fromdata_init(ctx) <= 0) goto err;

    // Create the key with the appropriate type
    if (priv_key_bytes.has_value()) {
        if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
            printf("Failed to create keypair from parameters\n");
            goto err;
        }
    } else {
        if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
            printf("Failed to create public key from parameters\n");
            goto err;
        }
    }

    goto cleanup;

err:
    if (pkey) {
        EVP_PKEY_free(pkey);
        pkey = nullptr;
    }

cleanup:
    if (buf) OPENSSL_free(buf);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (param_bld) OSSL_PARAM_BLD_free(param_bld);
    if (params) OSSL_PARAM_free(params);
    if (priv_key_bn) BN_free(priv_key_bn);
    if (x) BN_free(x);
    if (y) BN_free(y);

    return pkey;
}
#else

SSL_KEY *em_crypto_t::create_ec_key_from_coordinates(const EC_GROUP* group,
    const std::vector<uint8_t> &x_bin, const std::vector<uint8_t> &y_bin,
    const std::optional<std::vector<uint8_t>> &priv_key_bytes)
{

    int nid = EC_GROUP_get_curve_name(group);
    if (nid == NID_undef) {
        printf("Failed to get curve name from group\n");
        return nullptr;
    }

    EC_KEY *ec_key = EC_KEY_new_by_curve_name(nid);
    if (!ec_key) return nullptr;

    BIGNUM *x = BN_bin2bn(x_bin.data(), x_bin.size(), nullptr);
    BIGNUM *y = BN_bin2bn(y_bin.data(), y_bin.size(), nullptr);
    if (!x || !y) {
        EC_KEY_free(ec_key);
        if (x) BN_free(x);
        if (y) BN_free(y);
        return nullptr;
    }

    if (!EC_KEY_set_public_key_affine_coordinates(ec_key, x, y)) {
        printf("Failed to set public key coordinates\n");
        EC_KEY_free(ec_key);
        BN_free(x);
        BN_free(y);
        return nullptr;
    }

    if (priv_key_bytes.has_value()) {
        BIGNUM *priv = BN_bin2bn(priv_key_bytes->data(), priv_key_bytes->size(), nullptr);
        if (!priv || !EC_KEY_set_private_key(ec_key, priv)) {
            printf("Failed to set private key\n");
            if (priv) BN_free(priv);
            EC_KEY_free(ec_key);
            BN_free(x);
            BN_free(y);
            return nullptr;
        }
        BN_free(priv);
    }

    // Verify that the key is valid
    if (!EC_KEY_check_key(ec_key)) {
        printf("EC_KEY_check_key failed\n");
        EC_KEY_free(ec_key);
        BN_free(x);
        BN_free(y);
        return nullptr;
    }

    BN_free(x);
    BN_free(y);
    return ec_key;
}
#endif

bool em_crypto_t::verify_signature(const std::vector<uint8_t> &message,
                                   const std::vector<uint8_t> &signature, EVP_PKEY *pkey,
                                   const EVP_MD *hash_function)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create verification context\n");
        return false;
    }

    // Initialize the verification context with provided key and hash function
    if (EVP_DigestVerifyInit(ctx, nullptr, hash_function, nullptr, pkey) != 1) {
        fprintf(stderr, "Failed to initialize verification context\n");
        EVP_MD_CTX_free(ctx);
        return false;
    }

    // Update the context with the message
    if (EVP_DigestVerifyUpdate(ctx, message.data(), message.size()) != 1) {
        fprintf(stderr, "Failed to update verification context\n");
        EVP_MD_CTX_free(ctx);
        return false;
    }

    // Verify the signature
    int verify_result = EVP_DigestVerifyFinal(ctx, signature.data(), signature.size());
    if (verify_result == 1) {
        // Signature is valid
        EVP_MD_CTX_free(ctx);
        return true;
    }
    if (verify_result == 0) {
        // Signature is invalid
        fprintf(stderr, "Signature verification failed\n");
        EVP_MD_CTX_free(ctx);
        return false;
    }
    fprintf(stderr, "Error during signature verification: %s\n",
            ERR_error_string(ERR_get_error(), nullptr));

    // Clean up
    EVP_MD_CTX_free(ctx);

    return false;
}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
bool em_crypto_t::verify_signature(const std::vector<uint8_t> &message,
                                   const std::vector<uint8_t> &signature, EC_KEY *ec_key,
                                   const EVP_MD *hash_function)
{
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) {
        fprintf(stderr, "Failed to create EVP_PKEY\n");
        return false;
    }

    if (EVP_PKEY_assign_EC_KEY(pkey, EC_KEY_dup(ec_key)) != 1) {
        fprintf(stderr, "Failed to assign EC_KEY to EVP_PKEY\n");
        EVP_PKEY_free(pkey);
        return false;
    }

    bool result = verify_signature(message, signature, pkey, hash_function);

    EVP_PKEY_free(pkey);
    return result;
}

std::optional<std::vector<uint8_t>> em_crypto_t::sign_data_ecdsa(const std::vector<uint8_t> &data_to_sign, EC_KEY *private_key, const EVP_MD *md)
{
    // Validate the EC_KEY before using it
    if (!EC_KEY_check_key(private_key)) {
        fprintf(stderr, "Invalid EC_KEY provided to sign_data_ecdsa\n");
        return std::nullopt;
    }

    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) {
        fprintf(stderr, "Failed to create EVP_PKEY\n");
        return std::nullopt;
    }

    // Use reference counting instead of duplication to avoid thread-safety issues
    EC_KEY_up_ref(private_key);
    if (EVP_PKEY_assign_EC_KEY(pkey, private_key) != 1) {
        fprintf(stderr, "Failed to assign EC_KEY to EVP_PKEY\n");
        EC_KEY_free(private_key); // Decrement the reference count we just added
        EVP_PKEY_free(pkey);
        return std::nullopt;
    }

    auto result = sign_data_ecdsa(data_to_sign, pkey, md);

    EVP_PKEY_free(pkey); // This will decrement the EC_KEY reference count
    return result;
}
#endif

SSL_KEY *em_crypto_t::bundle_ec_key(const EC_GROUP* group, const EC_POINT *public_key, const BIGNUM *private_key) {
    EM_ASSERT_NOT_NULL(public_key, NULL, "Public key is NULL");
    EM_ASSERT_NOT_NULL(group, NULL, "Group is NULL");

    auto [x, y] = ec_crypto::get_ec_x_y(group, public_key);
    if (!x || !y) {
        return NULL;
    }
    
    // Use scoped_bn to ensure proper cleanup
    scoped_bn x_scoped(x);
    scoped_bn y_scoped(y);
    
    if (private_key == NULL){
        return em_crypto_t::create_ec_key_from_coordinates(group, ec_crypto::BN_to_vec(x_scoped.get()), ec_crypto::BN_to_vec(y_scoped.get()));
    }
    return em_crypto_t::create_ec_key_from_coordinates(group, ec_crypto::BN_to_vec(x_scoped.get()), ec_crypto::BN_to_vec(y_scoped.get()), ec_crypto::BN_to_vec(private_key));
}

std::string em_crypto_t::hash_to_hex_string(const uint8_t *hash, size_t hash_len) {
    char output[hash_len * 2 + 1];
    for (size_t i = 0; i < hash_len; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[hash_len * 2] = '\0'; // Null-terminate the string
    return std::string(output);
}

std::string em_crypto_t::hash_to_hex_string(const std::vector<uint8_t>& hash)
{
    return hash_to_hex_string(hash.data(), hash.size());
}

// KDF implementation based on 802.11 specification
bool em_crypto_t::kdf_hash_length(const EVP_MD *algo,
                     const uint8_t *key, size_t key_len,
                     const char *label,
                     const uint8_t *context, size_t context_len,
                     uint8_t *output, size_t output_len) {
    
    // Input validation
    if (!algo || !key || key_len == 0 || !label || !output || output_len == 0) {
        return false;
    }
    
    size_t hash_len = static_cast<size_t>(EVP_MD_size(algo));
    if (hash_len == 0 || hash_len > 64) {  // Sanity check on hash size
        return false;
    }
    
    size_t iterations = (output_len + hash_len - 1) / hash_len;
    if (iterations > UINT16_MAX) {  // Counter must fit in uint16_t
        return false;
    }
    
    size_t offset = 0;
    uint8_t hash[SHA512_DIGEST_LENGTH]; // Max hash size
    
    uint8_t *addr[4];
    size_t len[4];
    
    addr[1] = reinterpret_cast<uint8_t *>(const_cast<char *>(label));
    len[1] = strlen(label);
    
    addr[2] = const_cast<uint8_t *>(context);
    len[2] = context_len;
    
    // Length encoded as 16-bit little-endian
    uint16_t length_bits = SWAP_LITTLE_ENDIAN(static_cast<uint16_t>(output_len * 8));
    addr[3] = reinterpret_cast<uint8_t*>(&length_bits);
    len[3] = 2;
    
    // Loop counter encoded as 16-bit little-endian
    uint16_t counter_le;
    
    for (size_t i = 1; i <= iterations; i++) {
        // Encode counter in little-endian
        counter_le = SWAP_LITTLE_ENDIAN(static_cast<uint16_t>(i));
        addr[0] = reinterpret_cast<uint8_t*>(&counter_le);
        len[0] = 2;
        
        // Compute HMAC
        if (!em_crypto_t::platform_hmac_hash(algo, const_cast<uint8_t*>(key), key_len, 4, addr, len, hash)) {
            return false;
        }
        
        // Copy to output
        size_t to_copy = (offset + hash_len > output_len) ? 
                         (output_len - offset) : hash_len;
        memcpy(output + offset, hash, to_copy);
        
        offset += to_copy;
    }

    return true;
}