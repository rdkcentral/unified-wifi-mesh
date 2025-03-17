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
#include <linux/filter.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/provider.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include "em.h"
#include "em_crypto.h"
#include "util.h"
#include <iostream>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <fstream>
#include <sstream>
#include <string>

/**
 * @paragraph Versions of OpenSSL greater than 1.1 are currently not supported.
 *            This is due to the fact that OpenSSL made significant changes with thread-safety 
 *            in version 3.0+ which does not work well with the current multi-threaded nature
 *            of unified-wifi-mesh. The OpenSSL support that exists here is valid, however when enabled,
 *            certain race conditions appear that are not present prior to version 3.0.
 */
#ifndef OPENSSL_VERSION_NUMBER
#define OPENSSL_VERSION_NUMBER 0x10100000L
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


    pthread_once(&init_once, []() {
        if (OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL) == 0) {
            fprintf(stderr, "OpenSSL initialization failed\n");
            exit(1);
        }

        if (OSSL_PROVIDER_load(NULL, "default") == NULL) {
            fprintf(stderr, "Failed to load default provider\n");
            exit(1);
        }
    });
    m_crypto_info.dh = DH_new();
}

/*static void print_key(const char* label, const uint8_t* key, uint16_t len) {
    printf("%s (%d bytes): ", label, len);
    for(int i = 0; i < len; i++) {
        printf("%02X", key[i]);
    }
    printf("\n");
}*/ //unused function

int em_crypto_t::init()
{

    BIGNUM *priv_key = NULL, *pub_key = NULL;
	//DH *dh = NULL;

    RAND_bytes(m_crypto_info.e_nonce, sizeof(em_nonce_t));
    uuid_generate(m_crypto_info.e_uuid);

    BIGNUM *p = NULL;
    BIGNUM *g = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_PKEY *param_pkey = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *pkey = NULL;
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
uint8_t em_crypto_t::platform_hmac_hash(const EVP_MD * hashing_algo, uint8_t *key, uint32_t keylen, uint8_t num_elem, uint8_t **addr, size_t *len, uint8_t *hmac)
{
    //em_util_info_print(EM_CONF," %s:%d\n",__func__,__LINE__);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_MD_CTX   *ctx;
    EVP_PKEY     *pkey;
    size_t        mdlen = 32;
#else
    HMAC_CTX     *ctx;
    unsigned int  mdlen = 32;
#endif
    size_t        i;

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
        EVP_DigestSignUpdate(ctx, addr[i], len[i]);
    }

    if (EVP_DigestSignFinal(ctx, hmac, &mdlen) != 1) {
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
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(ctx);
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
    HMAC_CTX_free(ctx);
#else
    HMAC_CTX_cleanup(ctx);
#endif

    return 1;

bail:
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_PKEY_free(pkey);
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
uint8_t em_crypto_t::platform_cipher_encrypt(const EVP_CIPHER *cipher_type, uint8_t *key, uint8_t *iv, uint8_t *plain, uint32_t plain_len, uint8_t *cipher_text, uint32_t *cipher_len)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX _ctx;
#endif
    EVP_CIPHER_CTX *ctx;
    int             len = static_cast<int> (plain_len + AES_BLOCK_SIZE - 1), final_len = 0;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX_init(&_ctx);
    ctx = &_ctx;
#else
    ctx=EVP_CIPHER_CTX_new();
    if (!ctx) {
        return 0;
    }
#endif
    if (EVP_EncryptInit_ex(ctx, cipher_type, NULL, key, iv) != 1) {
        return 0;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    
    if (EVP_EncryptUpdate(ctx, cipher_text, &len, plain, static_cast<int> (plain_len)) != 1) {
        return 0;
    }


    if (EVP_EncryptFinal_ex(ctx, cipher_text + len, &final_len) != 1) {
        return 0;
    }

    *cipher_len = static_cast<uint32_t> (len);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX_cleanup(ctx);
#else
    EVP_CIPHER_CTX_free(ctx);
#endif

    return 1;
}
uint8_t em_crypto_t::platform_cipher_decrypt(const EVP_CIPHER *cipher_type, uint8_t *key, uint8_t *iv, uint8_t *data, uint32_t data_len)
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
    if (EVP_DecryptInit_ex(ctx, cipher_type, NULL, key, iv) != 1) {
        return 0;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    plen = static_cast<int> (data_len);
    if (EVP_DecryptUpdate(ctx, data, &plen, data, static_cast<int> (data_len)) != 1 || plen != static_cast<int> (data_len)) {
        return 0;
    }

    len = sizeof(buf);
    if (EVP_DecryptFinal_ex(ctx, buf, &len) != 1 || len != 0) {
        return 0;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX_cleanup(ctx);
#else
    EVP_CIPHER_CTX_free(ctx);
#endif

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

    free(*shared_secret);
    *shared_secret = NULL;
    *shared_secret_len = 0;
    printf("%s:%d Internal failed\n", __func__, __LINE__);
    return 0;
}

char *em_crypto_t::base64_encode(const uint8_t *input, size_t length, size_t *output_length) {
    BIO *bio, *b64;
	//BUF_MEM *bufferPtr;

    // Create a base64 filter BIO and a memory BIO
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);  // Chain them together

    // Disable newlines in the output
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    
    // Write data through the BIO chain
    BIO_write(bio, input, static_cast<int> (length));
    BIO_flush(bio);

    // Extract the encoded data

    size_t temp_out_length = 0;
    char* data_ptr = NULL;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    BIO_get_mem_ptr(bio, &bufferPtr);
    temp_out_length = bufferPtr->length;
    data_ptr = bufferPtr->data; 
#elif OPENSSL_VERSION_NUMBER < 0x30000000L
    const BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    temp_out_length = bptr->length;
    data_ptr = bptr->data;
#else
    temp_out_length = static_cast<size_t> (BIO_get_mem_data(bio, &data_ptr));
#endif

    // Allocate and copy the encoded data
    char* result = static_cast<char*> (malloc(temp_out_length + 1));
    memcpy(result, data_ptr, temp_out_length);
    result[temp_out_length] = '\0';

    if (output_length) {
        *output_length = temp_out_length;
    }
    BIO_free_all(bio);
    return result;
}

uint8_t* em_crypto_t::base64_decode(const char* input, size_t length, size_t* output_length) {
    BIO *bio, *b64;
    unsigned char* result;

    result = static_cast<unsigned char*> (malloc(length));
    bio = BIO_new_mem_buf(input, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    *output_length = static_cast<size_t> (BIO_read(bio, result, static_cast<int> (length)));

    // Free the BIO chain
    BIO_free_all(bio);

    return result;
}


EC_KEY* em_crypto_t::create_ec_key_from_base64_der(const char* base64_der_pubkey) 
{

    if (!base64_der_pubkey) {
        printf("%s:%d NULL parameter\n", __func__, __LINE__);
        return NULL;
    }
    uint8_t key[1024];
    int len = 1024;
    
    memset(key, 0, static_cast<size_t> (len));

    if ((len = EVP_DecodeBlock(key, const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(base64_der_pubkey)), static_cast<int> (strlen(base64_der_pubkey)))) < 0) {
        printf("%s:%d Failed to decode base 64 public key\n", __func__, __LINE__);
        return NULL;
    }

    const unsigned char *ptr = key;
    EC_KEY *ec_key = d2i_EC_PUBKEY(NULL, &ptr, len);

    if (ec_key == NULL) {
        printf("%s:%d Failed to create EC key from DER\n", __func__, __LINE__);
        return NULL;
    }

    EC_KEY_set_conv_form(ec_key, POINT_CONVERSION_COMPRESSED);
    EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);

    return ec_key;
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

