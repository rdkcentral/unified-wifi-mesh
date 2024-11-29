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

#define OPENSSL_VERSION_NUMBER 0x10100000L
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

em_crypto_t::em_crypto_t()
{
    m_crypto_info.dh = DH_new();
}

int em_crypto_t::init()
{
    const BIGNUM *priv_key = NULL, *pub_key = NULL;
    //em_util_info_print(EM_CONF,"em_crypto_t::init %s:%d\n",__func__,__LINE__);

    RAND_bytes(m_crypto_info.e_nonce, sizeof(em_nonce_t));
    uuid_generate(m_crypto_info.e_uuid);

    //em_util_info_print(EM_CONF,"em_crypto_t::init %s:%d\n",__func__,__LINE__);
    BIGNUM *p = NULL;
    BIGNUM *g = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
#else
    OSSL_PARAM_BLD *param_bld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *dh_ctx = NULL;
    EVP_PKEY *param_pkey = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *pkey = NULL;
    BIGNUM *bn_priv = NULL;
    BIGNUM *bn_pub = NULL;
    int selection = OSSL_KEYMGMT_SELECT_ALL;
#endif
    /* Create prime and generator by converting binary to BIGNUM format */
    p = BN_bin2bn(g_dh1536_p, sizeof(g_dh1536_p), NULL);
    if (p == NULL) {
        goto bail;
    }
    g = BN_bin2bn(g_dh1536_g, sizeof(g_dh1536_g), NULL);
    if (g == NULL) {
        goto bail;
    }

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    if (NULL == (m_crypto_info.dh = DH_new())) {
        goto bail;
    }
#else
    param_bld = OSSL_PARAM_BLD_new();
    if (param_bld == NULL) {
        goto bail;
    }
#endif

    /* Set prime and generator */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    m_crypto_info.dh->p = p;
    m_crypto_info.dh->g = g;
#elif OPENSSL_VERSION_NUMBER < 0x30000000L
    if (DH_set0_pqg(m_crypto_info.dh, p, NULL, g) != 1) {
        goto bail;
    }
#else
    if (OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_FFC_P, p) != 1 ||
            OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_FFC_G, g) != 1) {
        goto bail;
    }
    params = OSSL_PARAM_BLD_to_param(param_bld);
    if (params == NULL) {
        goto bail;
    }
#endif

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    /* Obtain key pair */
    if (0 == DH_generate_key(m_crypto_info.dh)) {
        goto bail;
    }
#else
    /* Create DH context */
    dh_ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
    if (dh_ctx == NULL) {
        goto bail;
    }
    if (EVP_PKEY_fromdata_init(dh_ctx) != 1) {
        goto bail;
    }
    if (EVP_PKEY_fromdata(dh_ctx, &param_pkey, selection, params) != 1 || param_pkey == NULL) {
        goto bail;
    }

    /* Create key pair */
    pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, param_pkey, NULL);
    if (pkey_ctx == NULL) {
        goto bail;
    }
    if (EVP_PKEY_keygen_init(pkey_ctx) != 1) {
        goto bail;
    }
    if (EVP_PKEY_keygen(pkey_ctx, &pkey) != 1 || pkey == NULL) {
        goto bail;
    }
#endif

    // now generate the keys
    DH_get0_key(m_crypto_info.dh, &pub_key, &priv_key);
    BN_bn2bin(pub_key, m_crypto_info.e_pub);
    BN_bn2bin(priv_key, m_crypto_info.e_priv);
    m_crypto_info.e_pub_len = BN_num_bytes(pub_key);
    m_crypto_info.e_priv_len = BN_num_bytes(priv_key);
    
    DH_get0_key(m_crypto_info.dh, &pub_key, &priv_key);
    BN_bn2bin(pub_key, m_crypto_info.r_pub);
    BN_bn2bin(priv_key, m_crypto_info.r_priv);
    m_crypto_info.r_pub_len = BN_num_bytes(pub_key);
    m_crypto_info.r_priv_len = BN_num_bytes(priv_key);
    
    return 0;
bail:

    // Clean up
    EVP_cleanup();
    ERR_free_strings();
    return -1;
}

uint8_t em_crypto_t::get_shared_key(uint8_t **shared_secret, uint16_t *shared_secret_len,
                                          uint8_t *remote_pub, uint16_t remote_pub_len,
                                          uint8_t *local_priv, uint16_t local_priv_len)
{
    BIGNUM *p = NULL;
    BIGNUM *g = NULL;
    BIGNUM *bn_priv = NULL;
    BIGNUM *bn_pub = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    DH *dh = NULL;
    size_t rlen;
#else
    EVP_PKEY *dh_priv = NULL;
    EVP_PKEY *dh_pub = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
#endif
    size_t secret_len = 0;
    if (NULL == shared_secret     ||
            NULL == shared_secret_len ||
            NULL == remote_pub        ||
            NULL == local_priv) {
        return 0;
    }

    /* Create prime and generator by converting binary to BIGNUM format */
    p = BN_bin2bn(g_dh1536_p, sizeof(g_dh1536_p), NULL);
    if (p == NULL) {
        goto bail;
    }
    g = BN_bin2bn(g_dh1536_g, sizeof(g_dh1536_g), NULL);
    if (g == NULL) {
        goto bail;
    }
    bn_priv = BN_bin2bn(local_priv, local_priv_len, NULL);
    if (bn_priv == NULL) {
        goto bail;
    }
    bn_pub = BN_bin2bn(remote_pub, remote_pub_len, NULL);
    if (bn_pub == NULL) {
        goto bail;
    }

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    if (NULL == (m_crypto_info.dh = DH_new())) {
        goto bail;
    }
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    m_crypto_info.dh->p = p;
    m_crypto_info.dh->g = g;
    m_crypto_info.dh->priv_key = bn_priv;
#elif OPENSSL_VERSION_NUMBER < 0x30000000L
    if (DH_set0_pqg(m_crypto_info.dh, p, NULL, g) != 1) {
        BN_clear_free(bn_priv);
        goto bail;
    }
    if (DH_set0_key(m_crypto_info.dh, NULL, bn_priv) != 1) {
        goto bail;
    }
#else
    dh_priv = create_dh_pkey(p, g, bn_priv, NULL);
    if (dh_priv == NULL) {
        goto bail;
    }
    dh_pub = create_dh_pkey(p, g, NULL, bn_pub);
    if (dh_pub == NULL) {
        goto bail;
    }
#endif

    /* Allocate output buffer and extract secret onto it */
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    rlen = DH_size(dh);
    *shared_secret = (uint8_t*)malloc(rlen);
    secret_len = DH_compute_key(*shared_secret, bn_pub, dh);
    if (secret_len <= 0) {
        goto bail;
    }

    DH_free(dh);
    BN_clear_free(bn_pub);
#else
    pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, dh_priv, NULL);
    if (pkey_ctx == NULL) {
        goto bail;
    }
    if (EVP_PKEY_derive_init(pkey_ctx) != 1) {
        goto bail;
    }
    if (EVP_PKEY_derive_set_peer(pkey_ctx, dh_pub) != 1) {
        goto bail;
    }
    if (EVP_PKEY_derive(pkey_ctx, NULL, &secret_len) != 1 || secret_len == 0) {
        goto bail;
    }
    *shared_secret = (uint8_t*) malloc(secret_len);
    if (EVP_PKEY_derive(pkey_ctx, *shared_secret, &secret_len) != 1) {
        goto bail;
    }

    /* Release resources */
    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_PKEY_free(dh_pub);
    EVP_PKEY_free(dh_priv);
    BN_clear_free(bn_pub);
    BN_clear_free(g);
    BN_clear_free(p);
#endif

    *shared_secret_len = secret_len;

    return 1;

bail:
    *shared_secret_len = 0;
    if (*shared_secret) {
        free(*shared_secret);
        *shared_secret = NULL;
    }
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    if (m_crypto_info.dh) {
        DH_free(m_crypto_info.dh);
    } else {
        BN_clear_free(bn_priv);
        BN_clear_free(g);
        BN_clear_free(p);
    }
    BN_clear_free(bn_pub);
#else
    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_PKEY_free(dh_pub);
    EVP_PKEY_free(dh_priv);
    BN_clear_free(bn_pub);
    BN_clear_free(bn_priv);
    BN_clear_free(g);
    BN_clear_free(p);
#endif

    return 0;
}

uint8_t em_crypto_t::platform_SHA256(uint8_t num_elem, uint8_t **addr, uint32_t *len, uint8_t *digest)
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

    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) {
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
uint8_t em_crypto_t::platform_hmac_SHA256(uint8_t *key, uint32_t keylen, uint8_t num_elem, uint8_t **addr,
        uint32_t *len, uint8_t *hmac)
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
    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        goto bail;
    }

    for (i = 0; i < num_elem; i++) {
        EVP_DigestSignUpdate(ctx, addr[i], len[i]);
    }

    if (EVP_DigestSignFinal(ctx, hmac, &mdlen) != 1) {
        goto bail;
    }
#else
    if (HMAC_Init_ex(ctx, key, keylen, EVP_sha256(), NULL) != 1) {
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
void em_crypto_t:: _I4B(const uint32_t *memory_pointer, uint8_t **packet_ppointer)
{
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    **packet_ppointer = *(((uint8_t *)memory_pointer)+0); (*packet_ppointer)++;
    **packet_ppointer = *(((uint8_t *)memory_pointer)+1); (*packet_ppointer)++;
    **packet_ppointer = *(((uint8_t *)memory_pointer)+2); (*packet_ppointer)++;
    **packet_ppointer = *(((uint8_t *)memory_pointer)+3); (*packet_ppointer)++;
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    **packet_ppointer = *(((uint8_t *)memory_pointer)+3); (*packet_ppointer)++;
    **packet_ppointer = *(((uint8_t *)memory_pointer)+2); (*packet_ppointer)++;
    **packet_ppointer = *(((uint8_t *)memory_pointer)+1); (*packet_ppointer)++;
    **packet_ppointer = *(((uint8_t *)memory_pointer)+0); (*packet_ppointer)++;
#else
#error You must specify your architecture endianess
#endif
}

uint8_t em_crypto_t:: wps_key_derivation_function(uint8_t *key, uint8_t *label_prefix, uint32_t label_prefix_len, char *label, uint8_t *res, uint32_t res_len)
{
    uint8_t i_buf[4];
    uint8_t key_bits[4];

    uint8_t   *addr[4];
    uint32_t   len[4];

    uint32_t i, iter;

    uint8_t  hash[SHA256_MAC_LEN] = {0};
    uint8_t *opos;

    uint32_t left;

    uint8_t  *p;
    uint32_t  aux;

    aux = res_len * 8;
    p   = key_bits;

    _I4B(&aux, &p);

    addr[0] = i_buf;
    addr[1] = label_prefix;
    addr[2] = (uint8_t *) label;
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
        _I4B(&i, &p);

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
uint8_t em_crypto_t::platform_aes_encrypt(uint8_t *key, uint8_t *iv, uint8_t *plain, uint32_t plain_len, uint8_t *cipher, uint32_t *cipher_len)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX _ctx;
#endif
    EVP_CIPHER_CTX *ctx;
    int             len = plain_len + AES_BLOCK_SIZE - 1, final_len = 0;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX_init(&_ctx);
    ctx = &_ctx;
#else
    ctx=EVP_CIPHER_CTX_new();
    if (!ctx) {
        return 0;
    }
#endif
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
        return 0;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    
    if (EVP_EncryptUpdate(ctx, cipher, &len, plain, plain_len) != 1) {
        return 0;
    }

    //printf("%s:%d: plain len: %d cipher len: %d\n", __func__, __LINE__, plain_len, len);

    if (EVP_EncryptFinal_ex(ctx, cipher + len, &final_len) != 1) {
        return 0;
    }

    *cipher_len = len;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX_cleanup(ctx);
#else
    EVP_CIPHER_CTX_free(ctx);
#endif

    return 1;
}
uint8_t em_crypto_t::platform_aes_decrypt(uint8_t *key, uint8_t *iv, uint8_t *data, uint32_t data_len)
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
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
        return 0;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    plen = data_len;
    if (EVP_DecryptUpdate(ctx, data, &plen, data, data_len) != 1 || plen != (int) data_len) {
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
    int selection = EVP_PKEY_KEYPAIR;

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
    BIGNUM *p = NULL;
    BIGNUM *g = NULL;
    BIGNUM *bn_priv = NULL;
    BIGNUM *bn_pub = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    DH *dh = NULL;
    size_t rlen;
#else
    EVP_PKEY *dh_priv = NULL;
    EVP_PKEY *dh_pub = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
#endif
    size_t secret_len = 0;

    if (NULL == shared_secret     ||
            NULL == shared_secret_len ||
            NULL == remote_pub        ||
            NULL == local_priv) {
        return 0;
    }

    /* Create prime and generator by converting binary to BIGNUM format */
    p = BN_bin2bn(g_dh1536_p, sizeof(g_dh1536_p), NULL);
    if (p == NULL) {
        goto bail;
    }
    g = BN_bin2bn(g_dh1536_g, sizeof(g_dh1536_g), NULL);
    if (g == NULL) {
        goto bail;
    }
    bn_priv = BN_bin2bn(local_priv, local_priv_len, NULL);
    if (bn_priv == NULL) {
        goto bail;
    }
    bn_pub = BN_bin2bn(remote_pub, remote_pub_len, NULL);
    if (bn_pub == NULL) {
        goto bail;
    }

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    if (NULL == (dh = DH_new())) {
        goto bail;
    }
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    dh->p = p;
    dh->g = g;
    dh->priv_key = bn_priv;
#elif OPENSSL_VERSION_NUMBER < 0x30000000L
    if (DH_set0_pqg(dh, p, NULL, g) != 1) {
        BN_clear_free(bn_priv);
        goto bail;
    }
    if (DH_set0_key(dh, NULL, bn_priv) != 1) {
        goto bail;
    }
#else
    dh_priv = create_dh_pkey(p, g, bn_priv, NULL);
    if (dh_priv == NULL) {
        goto bail;
    }
    dh_pub = create_dh_pkey(p, g, NULL, bn_pub);
    if (dh_pub == NULL) {
        goto bail;
    }
#endif

    /* Allocate output buffer and extract secret onto it */
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    rlen = DH_size(dh);
    *shared_secret = (uint8_t*)malloc(rlen);
    secret_len = DH_compute_key(*shared_secret, bn_pub, dh);
    if (secret_len <= 0) {
        goto bail;
    }

    DH_free(dh);
    BN_clear_free(bn_pub);
#else
    pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, dh_priv, NULL);
    if (pkey_ctx == NULL) {
        goto bail;
    }
    if (EVP_PKEY_derive_init(pkey_ctx) != 1) {
        goto bail;
    }
    if (EVP_PKEY_derive_set_peer(pkey_ctx, dh_pub) != 1) {
        goto bail;
    }
    if (EVP_PKEY_derive(pkey_ctx, NULL, &secret_len) != 1 || secret_len == 0) {
        goto bail;
    }
    *shared_secret = malloc(secret_len);
    if (EVP_PKEY_derive(pkey_ctx, *shared_secret, &secret_len) != 1) {
        goto bail;
    }

    /* Release resources */
    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_PKEY_free(dh_pub);
    EVP_PKEY_free(dh_priv);
    BN_clear_free(bn_pub);
    BN_clear_free(g);
    BN_clear_free(p);
#endif

    *shared_secret_len = secret_len;

    return 1;

bail:
    *shared_secret_len = 0;
    if (*shared_secret) {
        free(*shared_secret);
        *shared_secret = NULL;
    }
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    if (dh) {
        DH_free(dh);
    } else {
        BN_clear_free(bn_priv);
        BN_clear_free(g);
        BN_clear_free(p);
    }
    BN_clear_free(bn_pub);
#else
    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_PKEY_free(dh_pub);
    EVP_PKEY_free(dh_priv);
    BN_clear_free(bn_pub);
    BN_clear_free(bn_priv);
    BN_clear_free(g);
    BN_clear_free(p);
#endif

    return 0;
}

