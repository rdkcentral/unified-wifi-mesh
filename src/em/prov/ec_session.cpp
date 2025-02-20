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
#include <errno.h>
#include <ctype.h>
#include <assert.h>
#include <signal.h>
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
#include <unistd.h>
#include <pthread.h>
#include <openssl/rand.h>
#include <assert.h>
#include "ec_base.h"
#include "ec_session.h"
#include "em.h"
#include "aes_siv.h"

int ec_session_t::create_auth_req(unsigned char *buff)
{
    unsigned char keyasn1[1024];
    EC_KEY *responder_boot_key, *initiator_boot_key;
    unsigned int wrapped_len;
    ec_frame_t    *frame;
    ec_tlv_t *tlv;
    unsigned short tlv_len, chann_attr;;
    unsigned char protocol_key_buff[1024];
    ULONG hm_channel = 0;
    ULONG ch_freq = 0;

    printf("%s:%d Enter\n", __func__, __LINE__);

    frame = (ec_frame_t *)buff;
    tlv_len = 0;

    prepare_frame(frame, ec_frame_type_auth_req);

    responder_boot_key = get_responder_boot_key(keyasn1, sizeof(keyasn1));
    initiator_boot_key = get_initiator_boot_key(keyasn1, sizeof(keyasn1));

    if (init_session() != 0) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d Failed to initialize session parameters\n", __func__, __LINE__);
        return -1;
    }

    if (compute_intermediate_key(true) != 0) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d failed to generate key\n", __func__, __LINE__);
        return -1;
    }

    tlv = (ec_tlv_t *)frame->body.attrib;

    if (compute_key_hash(initiator_boot_key, m_params.initiator_keyhash) < 1) {
        m_activation_status = ActStatus_Failed;
        return -1;
    }

    tlv = set_tlv((unsigned char *)tlv, ec_attrib_id_initiator_boot_hash, 
            SHA256_DIGEST_LENGTH, m_params.initiator_keyhash);
    tlv_len += (SHA256_DIGEST_LENGTH + 4);

    if (compute_key_hash(responder_boot_key, m_params.responder_keyhash) < 1) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
        return -1;
    }

    tlv = set_tlv((unsigned char *)tlv, ec_attrib_id_responder_boot_hash, 
            SHA256_DIGEST_LENGTH, m_params.responder_keyhash);
    tlv_len += (SHA256_DIGEST_LENGTH + 4);

    if (m_cfgrtr_ver > 1) {
        tlv = set_tlv((unsigned char *)tlv, ec_attrib_id_proto_version, sizeof(m_cfgrtr_ver), &m_cfgrtr_ver);
        tlv_len += (sizeof(m_cfgrtr_ver) + 4);
    }

    BN_bn2bin((const BIGNUM *)m_params.x,
            &protocol_key_buff[BN_num_bytes(m_params.prime) - BN_num_bytes(m_params.x)]);
    BN_bn2bin((const BIGNUM *)m_params.y,
            &protocol_key_buff[2*BN_num_bytes(m_params.prime) - BN_num_bytes(m_params.x)]);
    tlv = set_tlv((unsigned char *)tlv, ec_attrib_id_initiator_protocol_key, 2*BN_num_bytes(m_params.prime), protocol_key_buff);
    tlv_len += (2*BN_num_bytes(m_params.prime) + 4);

    chann_attr = freq_to_channel(channel_to_frequency(hm_channel)); //channel attrib shall be home channel
    tlv = set_tlv((unsigned char*)tlv, ec_attrib_id_channel, sizeof(unsigned short), (unsigned char *)&chann_attr);
    tlv_len += 6;

    wrapped_len = set_auth_frame_wrapped_data(&frame->body, tlv_len, true);
    tlv_len += (wrapped_len + 4);

    printf("%s:%d Exit\n", __func__, __LINE__);

    return tlv_len;

}

int ec_session_t::create_auth_rsp(unsigned char *buff)
{
    return -1;
}

int ec_session_t::create_auth_cnf(unsigned char *buff)
{
    return -1;
}

int ec_session_t::create_pres_ann(unsigned char *buff)
{
    ec_frame_t    *frame;
    ec_tlv_t *tlv;
    unsigned short tlv_len;

    unsigned char keyasn1[1024];
    EC_KEY *responder_boot_key;

    frame = (ec_frame_t *)buff;
    tlv_len = 0;

    prepare_frame(frame, ec_frame_type_presence_announcement);

    responder_boot_key = get_responder_boot_key(keyasn1, sizeof(keyasn1));

    if (compute_key_hash(responder_boot_key, m_params.responder_keyhash) < 1) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
        return -1;
    }

    tlv = (ec_tlv_t *)frame->body.attrib;

    tlv = set_tlv((unsigned char *)tlv, ec_attrib_id_responder_boot_hash, 
            SHA256_DIGEST_LENGTH, m_params.responder_keyhash);
    tlv_len += (SHA256_DIGEST_LENGTH + 4);

    return tlv_len;
}

int ec_session_t::handle_pres_ann(unsigned char *buff, unsigned int len)
{
    ec_frame_t *frame;
    ec_tlv_t *tlv = NULL;
    int tlv_len;

    frame = (ec_frame_t *)buff;
    tlv_len = 0;

    if (validate_frame(frame, ec_frame_type_presence_announcement) == false) {
        printf("%s:%d: frame validation failed\n", __func__, __LINE__);
        return -1;
    }

    if ((tlv = get_tlv(frame->body.attrib, ec_attrib_id_responder_boot_hash, len)) == NULL) {
        return -1;
    }

    memcpy(m_params.responder_keyhash, tlv->value, tlv->length);

    return 0;	
}

void ec_session_t::prepare_frame(ec_frame_t *frame, ec_frame_type_t type)
{
    frame->hdr.cat = 0x04;
    frame->hdr.action = 0x09;
    frame->body.ec_oui.oui[0] = 0x50;
    frame->body.ec_oui.oui[1] = 0x6f;
    frame->body.ec_oui.oui[2] = 0x9a;

    frame->body.ec_oui.oui_type = DPP_OUI_TYPE;

    frame->body.crypto = 1; // Cryptographic suite 1 consists of the SHA2 family of hash algorithms and AES-SIV
    frame->body.frame_type = type;
}

bool ec_session_t::validate_frame(ec_frame_t *frame, ec_frame_type_t type)
{
    if ((frame->hdr.cat != 0x04) 
            || (frame->hdr.action != 0x09)
            || (frame->body.ec_oui.oui[0] != 0x50)
            || (frame->body.ec_oui.oui[1] != 0x6f)
            || (frame->body.ec_oui.oui[2] != 0x9a)
            || (frame->body.ec_oui.oui_type != DPP_OUI_TYPE)
            || (frame->body.crypto != 1)
            || (frame->body.frame_type != type)) {
        return false;
    }

    return true;
}

int ec_session_t::init_session()
{
    unsigned char keyasn1[1024];
    const unsigned char *key;
    unsigned int asn1len;
    EC_KEY *responder_key, *initiator_key;
    const EC_POINT *ipt, *rpt = NULL;
    const BIGNUM *proto_priv;

    if (m_data.type == ec_session_type_cfg) {
        memset(keyasn1, 0, sizeof(keyasn1));
        if ((asn1len = EVP_DecodeBlock(keyasn1, (unsigned char *)m_data.rPubKey, strlen(m_data.rPubKey))) < 0) {
            printf("%s:%d Failed to decode base 64 responder public key\n", __func__, __LINE__);
            return -1;
        }

        key = keyasn1;
        responder_key = d2i_EC_PUBKEY(NULL, &key, asn1len);

        EC_KEY_set_conv_form(responder_key, POINT_CONVERSION_COMPRESSED);
        EC_KEY_set_asn1_flag(responder_key, OPENSSL_EC_NAMED_CURVE);

        // get the group from responder's boot strap key information
        if ((m_params.group = EC_KEY_get0_group(responder_key)) == NULL) {
            printf("%s:%d Failed to get group from ec key\n", __func__, __LINE__);
            return -1;
        }

        rpt = EC_KEY_get0_public_key(responder_key);
        if (rpt == NULL) {
            printf("%s:%d Could not get responder bootstrap public key\n", __func__, __LINE__);
            return -1;
        }

        memset(keyasn1, 0, sizeof(keyasn1));
        if ((asn1len = EVP_DecodeBlock(keyasn1, (unsigned char *)m_data.iPubKey, strlen(m_data.iPubKey))) < 0) {
            printf("%s:%d Failed to decode base 64 initiator public key\n", __func__, __LINE__);
            return -1;
        }

        key = keyasn1;
        initiator_key = d2i_EC_PUBKEY(NULL, &key, asn1len);

        EC_KEY_set_conv_form(initiator_key, POINT_CONVERSION_COMPRESSED);
        EC_KEY_set_asn1_flag(initiator_key, OPENSSL_EC_NAMED_CURVE);

    } else if (m_data.type == ec_session_type_recfg) {
        memset(keyasn1, 0, sizeof(keyasn1));
        if ((asn1len = EVP_DecodeBlock(keyasn1, (unsigned char *)m_data.iPubKey, strlen(m_data.iPubKey))) < 0) {
            printf("%s:%d Failed to decode base 64 initiator public key\n", __func__, __LINE__);
            return -1;
        }

        key = keyasn1;
        initiator_key = d2i_EC_PUBKEY(NULL, &key, asn1len);

        EC_KEY_set_conv_form(initiator_key, POINT_CONVERSION_COMPRESSED);
        EC_KEY_set_asn1_flag(initiator_key, OPENSSL_EC_NAMED_CURVE);

        m_params.group = EC_KEY_get0_group(initiator_key);
        m_params.responder_connector = EC_POINT_new(m_params.group);
    }


    m_params.x = BN_new();
    m_params.y = BN_new();
    m_params.m = BN_new();
    m_params.n = BN_new();
    m_params.prime = BN_new();
    m_params.bnctx = BN_CTX_new();

    m_params.responder_proto_pt = EC_POINT_new(m_params.group);
    m_params.nid = EC_GROUP_get_curve_name(m_params.group);

    //printf("%s:%d nid: %d\n", __func__, __LINE__, m_params.nid);
    switch (m_params.nid) {
        case NID_X9_62_prime256v1:
            m_params.group_num = 19;
            m_params.digestlen = 32;
            m_params.hashfcn = EVP_sha256();
            break;
        case NID_secp384r1:
            m_params.group_num = 20;
            m_params.digestlen = 48;
            m_params.hashfcn = EVP_sha384();
            break;
        case NID_secp521r1:
            m_params.group_num = 21;
            m_params.digestlen = 64;
            m_params.hashfcn = EVP_sha512();
            break;
        case NID_X9_62_prime192v1:
            m_params.group_num = 25;
            m_params.digestlen = 32;
            m_params.hashfcn = EVP_sha256();
            break;
        case NID_secp224r1:
            m_params.group_num = 26;
            m_params.digestlen = 32;
            m_params.hashfcn = EVP_sha256();
            break;
        default:
            printf("%s:%d nid:%d not handled\n", __func__, __LINE__, m_params.nid);
            return -1;
    }

    m_params.noncelen = m_params.digestlen/2;

    //printf("%s:%d group_num:%d digestlen:%d\n", __func__, __LINE__, m_params.group_num, m_params.digestlen);

    m_params.initiator_proto_key = EC_KEY_new_by_curve_name(m_params.nid);
    if (m_params.initiator_proto_key == NULL) {
        printf("%s:%d Could not create protocol key\n", __func__, __LINE__);
        return -1;
    }

    if (EC_KEY_generate_key(m_params.initiator_proto_key) == 0) {
        printf("%s:%d Could not generate protocol key\n", __func__, __LINE__);
        return -1;
    }

    ipt = EC_KEY_get0_public_key(m_params.initiator_proto_key);
    if (ipt == NULL) {
        printf("%s:%d Could not get initiator protocol public key\n", __func__, __LINE__);
        return -1;
    }

    proto_priv = EC_KEY_get0_private_key(m_params.initiator_proto_key);
    if (proto_priv == NULL) {
        printf("%s:%d Could not get initiator protocol private key\n", __func__, __LINE__);
        return -1;
    }

    if ((m_params.N = EC_POINT_new(m_params.group)) == NULL) {
        printf("%s:%d unable to create bignums to initiate DPP!\n", __func__, __LINE__);
        return -1;
    }


    if ((m_params.M = EC_POINT_new(m_params.group)) == NULL) {
        printf("%s:%d unable to create bignums to initiate DPP!\n", __func__, __LINE__);
        return -1;
    }


    if (EC_POINT_get_affine_coordinates_GFp(m_params.group, ipt, m_params.x,
                m_params.y, m_params.bnctx) == 0) {
        printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
        return -1;
    }

    if (m_data.type == ec_session_type_cfg) {

        if (EC_POINT_mul(m_params.group, m_params.M, NULL, rpt, proto_priv, m_params.bnctx) == 0) {
            printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
            return -1;
        }


        printf("Point M:\n");
        print_ec_point(m_params.group, m_params.bnctx, m_params.M);

        if (EC_POINT_get_affine_coordinates_GFp(m_params.group, m_params.M,
                    m_params.m, NULL, m_params.bnctx) == 0) {
            printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
            return -1;

        }
    }

    RAND_bytes(m_params.initiator_nonce, m_params.noncelen);
    if (EC_GROUP_get_curve_GFp(m_params.group, m_params.prime, NULL, NULL,
                m_params.bnctx) == 0) {
        printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
        return -1;
    }


    return 0;

}

int ec_session_t::compute_intermediate_key(bool first)
{       
    unsigned int primelen, offset, keylen;
    unsigned char m[2048];

    BIGNUM *x = (first == true)?m_params.m:m_params.n;
    const char *info = (first == true)?"first intermediate key":"second intermediate key";
    unsigned char *key = (first == true)?m_params.k1:m_params.k2;

    primelen = BN_num_bytes(m_params.prime);

    memset(m, 0, primelen);
    offset = primelen - BN_num_bytes(x);
    BN_bn2bin(x, m + offset);
    if ((keylen = hkdf(m_params.hashfcn, 0, m, primelen, NULL, 0, 
                    (unsigned char *)info, strlen(info),
                    key, m_params.digestlen)) == 0) {
        printf("%s:%d: Failed in hashing\n", __func__, __LINE__);
        return -1;
    }

    printf("Key:\n"); 
    print_hex_dump(m_params.digestlen, key);

    return 0;
}       

int ec_session_t::compute_key_hash(EC_KEY *key, unsigned char *digest)
{
    int asn1len;
    BIO *bio;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_MD_CTX ctx;
#else
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
#endif
    unsigned int mdlen = SHA256_DIGEST_LENGTH;
    unsigned char *asn1;

    memset(digest, 0, SHA256_DIGEST_LENGTH);

    if ((bio = BIO_new(BIO_s_mem())) == NULL) {
        return -1;
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_MD_CTX_init(&ctx);
#else
    EVP_MD_CTX_reset(ctx);
#endif
    (void)i2d_EC_PUBKEY_bio(bio, key);
    (void)BIO_flush(bio);
    asn1len = BIO_get_mem_data(bio, &asn1);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_DigestInit(&ctx, EVP_sha256());
    EVP_DigestUpdate(&ctx, asn1, asn1len);
    EVP_DigestFinal(&ctx, digest, &mdlen);
#else
    EVP_DigestInit(ctx, EVP_sha256());
    EVP_DigestUpdate(ctx, asn1, asn1len);
    EVP_DigestFinal(ctx, digest, &mdlen);
#endif

    BIO_free(bio);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_MD_CTX_cleanup(&ctx);
#else
    EVP_MD_CTX_free(ctx);
#endif
    return mdlen;
}

int ec_session_t::set_auth_frame_wrapped_data(ec_frame_body_t *frame, unsigned int non_wrapped_len, bool auth_init)
{
    siv_ctx ctx;
    unsigned char plain[512];
    ec_tlv_t *tlv;
    unsigned char caps = 2;
    unsigned int wrapped_len = 0;
    ec_tlv_t *wrapped_tlv;
    unsigned char *key;

    key = (auth_init == true) ? m_params.k1:m_params.ke;

    switch(m_params.digestlen) {
        case SHA256_DIGEST_LENGTH:
            siv_init(&ctx, key, SIV_256);
            break;
        case SHA384_DIGEST_LENGTH:
            siv_init(&ctx, key, SIV_384);
            break;
        case SHA512_DIGEST_LENGTH:
            siv_init(&ctx, key, SIV_512);
            break;
        default:
            printf("%s:%d Unknown digest length\n", __func__, __LINE__);
            return -1;
    }


    tlv = (ec_tlv_t *)plain;

    if (auth_init == true) {
        tlv = set_tlv((unsigned char*)tlv, ec_attrib_id_initiator_nonce, m_params.noncelen, m_params.initiator_nonce);
        wrapped_len += (4 + m_params.noncelen);

        tlv = set_tlv((unsigned char*)tlv, ec_attrib_id_initiator_cap, 1, &caps);
        wrapped_len += 5;
    } else {
        tlv = set_tlv((unsigned char*)tlv, ec_attrib_id_initiator_auth_tag, m_params.digestlen, m_params.iauth);
        wrapped_len += (4 + m_params.digestlen);

    }

    wrapped_tlv = (ec_tlv_t *)(frame->attrib + non_wrapped_len);
    wrapped_tlv->type = ec_attrib_id_wrapped_data;
    wrapped_tlv->length = wrapped_len + AES_BLOCK_SIZE;

    siv_encrypt(&ctx, plain, &wrapped_tlv->value[AES_BLOCK_SIZE], wrapped_len, wrapped_tlv->value, 2,
            frame, sizeof(ec_frame_body_t),
            frame->attrib, non_wrapped_len);

    //printf("%s:%d: Plain text:\n", __func__, __LINE__);
    //print_hex_dump(noncelen, plain);

    return wrapped_len + AES_BLOCK_SIZE;
}

unsigned short ec_session_t::channel_to_frequency(unsigned int channel)
{
    unsigned short frequency = 0;

    if (channel <= 14) {
        frequency = 2412 + 5*(channel - 1);
    } else if ((channel >= 36) && (channel <= 64)) {
        frequency = 5180 + 5*(channel - 36);
    } else if ((channel >= 100) && (channel <= 140)) {
        frequency = 5500 + 5*(channel - 100);
    } else if ((channel >= 149) && (channel <= 165)) {
        frequency = 5745 + 5*(channel - 149);
    }

    return frequency;
}

unsigned short ec_session_t::freq_to_channel(unsigned int freq)
{
    unsigned int temp = 0;
    int sec_channel = -1;
    unsigned int op_class = 0;
    if (freq) {
        if (freq >= 2412 && freq <= 2472){
            if (sec_channel == 1)
                op_class = 83;
            else if (sec_channel == -1)
                op_class = 84;
            else
                op_class = 81;

            temp = ((freq - 2407) / 5);
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }

        /** In Japan, 100 MHz of spectrum from 4900 MHz to 5000 MHz
          can be used for both indoor and outdoor connection
         */
        if (freq >= 4900 && freq < 5000) {
            if ((freq - 4000) % 5)
                return 0;
            temp = (freq - 4000) / 5;
            op_class = 0; /* TODO */
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }
        if (freq == 2484) {
            op_class = 82; /* channel 14 */
            temp = 14;
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }
        /* 5 GHz, channels 36..48 */
        if (freq >= 5180 && freq <= 5240) {
            if ((freq - 5000) % 5)
                return 0;

            if (sec_channel == 1)
                op_class = 116;
            else if (sec_channel == -1)
                op_class = 117;
            else
                op_class = 115;

            temp = (freq - 5000) / 5;
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }
        /* 5 GHz, channels 52..64 */
        if (freq >= 5260 && freq <= 5320) {
            if ((freq - 5000) % 5)
                return 0;

            if (sec_channel == 1)
                op_class = 119;
            else if (sec_channel == -1)
                op_class = 120;
            else
                op_class = 118;

            temp = (freq - 5000) / 5;
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }
        /* 5 GHz, channels 100..140 */
        if (freq >= 5000 && freq <= 5700) {
            if (sec_channel == 1)
                op_class = 122;
            else if (sec_channel == -1)
                op_class = 123;
            else
                op_class = 121;

            temp = (freq - 5000) / 5;
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }
        /* 5 GHz, channels 149..169 */
        if (freq >= 5745 && freq <= 5845) {
            if (sec_channel == 1)
                op_class = 126;
            else if (sec_channel == -1)
                op_class = 127;
            else if (freq <= 5805)
                op_class = 124;
            else
                op_class = 125;

            temp = (freq - 5000) / 5;
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }

#if HOSTAPD_VERSION >= 210 //2.10
        if (is_6ghz_freq(freq)) {
            if (freq == 5935) {
                temp = 2;
                op_class = 131;
            } else {
                temp = (freq - 5950) % 5;
                op_class = 131 + center_idx_to_bw_6ghz((freq - 5950) / 5);
            }
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }
#endif
    }
    printf("error: No case for given Freq\n");
    return 0;
}

void ec_session_t::print_hex_dump(unsigned int length, unsigned char *buffer)
{
    int i;
    unsigned char buff[512] = {};
    const unsigned char * pc = (const unsigned char *)buffer;

    if ((pc == NULL) || (length <= 0)) {
        printf ("buffer NULL or BAD LENGTH = %d :\n", length);
        return;
    }

    for (i = 0; i < length; i++) {
        if ((i % 16) == 0) {
            if (i != 0)
                printf ("  %s\n", buff);
            printf ("  %04x ", i);
        }

        printf (" %02x", pc[i]);

        if (!isprint(pc[i]))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    printf ("  %s\n", buff);
}

void ec_session_t::print_bignum (BIGNUM *bn)
{
    unsigned char *buf;
    int len;

    len = BN_num_bytes(bn);
    if ((buf = (unsigned char *)malloc(len)) == NULL) {
        printf("Could not print bignum\n");
        return;
    }
    BN_bn2bin(bn, buf);
    print_hex_dump(len, buf);
    free(buf);
}

void ec_session_t::print_ec_point (const EC_GROUP *group, BN_CTX *bnctx, EC_POINT *point)
{
    BIGNUM *x = NULL, *y = NULL;

    if ((x = BN_new()) == NULL) {
        printf("%s:%d:Could not print ec_point\n", __func__, __LINE__);
        return;
    }

    if ((y = BN_new()) == NULL) {
        BN_free(x);
        printf("%s:%d:Could not print ec_point\n", __func__, __LINE__);
        return;
    }

    if (EC_POINT_get_affine_coordinates_GFp(group, point, x, y, bnctx) == 0) {
        BN_free(y);
        BN_free(x);
        printf("%s:%d:Could not print ec_point\n", __func__, __LINE__);
        return;

    }

    printf("POINT.x:\n");
    print_bignum(x);
    printf("POINT.y:\n");
    print_bignum(y);

    BN_free(y);
    BN_free(x);
}

ec_tlv_t *ec_session_t::get_tlv(unsigned char *buff, ec_attrib_id_t id, unsigned short len)
{
    unsigned int total_len = 0;
    bool found = false;
    ec_tlv_t *tlv = (ec_tlv_t *)buff;

    while (total_len < len) {
        if (tlv->type == id) {
            found = true;
            break;
        }

        total_len += (2*sizeof(unsigned short) + tlv->length);
        tlv = (ec_tlv_t *)((unsigned char *)tlv + 2*sizeof(unsigned short) + tlv->length);
    }

    return (found == true) ? tlv:NULL;
}


ec_tlv_t *ec_session_t::set_tlv(unsigned char *buff, ec_attrib_id_t id, unsigned short len, unsigned char *val)
{
    ec_tlv_t *tlv = (ec_tlv_t *)buff;

    tlv->type = id;
    tlv->length = len;
    memcpy(tlv->value, val, len);

    return (ec_tlv_t *)(buff + 2*sizeof(unsigned short) + len);
}

ec_session_t::ec_session_t(ec_data_t *data)
{
    memcpy(&m_data, data, sizeof(ec_data_t));
}

ec_session_t::~ec_session_t()
{

}

EC_KEY *ec_session_t::get_responder_boot_key(unsigned char *key, unsigned int len)
{
    EC_KEY *responder_boot_key;
    unsigned int asn1len;

    memset(key, 0, len);
    if ((asn1len = EVP_DecodeBlock(key, (unsigned char *)m_data.rPubKey, strlen(m_data.rPubKey))) < 0) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d Failed to decode base 64 initiator public key\n", __func__, __LINE__);
        return NULL;
    }

    responder_boot_key = d2i_EC_PUBKEY(NULL, (const unsigned char **)&key, asn1len);

    EC_KEY_set_conv_form(responder_boot_key, POINT_CONVERSION_COMPRESSED);
    EC_KEY_set_asn1_flag(responder_boot_key, OPENSSL_EC_NAMED_CURVE);

    return responder_boot_key;
}

EC_KEY *ec_session_t::get_initiator_boot_key(unsigned char *key, unsigned int len)
{
    EC_KEY *initiator_boot_key;
    unsigned int asn1len;

    memset(key, 0, len);
    if ((asn1len = EVP_DecodeBlock(key, (unsigned char *)m_data.iPubKey, strlen(m_data.iPubKey))) < 0) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d Failed to decode base 64 initiator public key\n", __func__, __LINE__);
        return NULL;
    }

    initiator_boot_key = d2i_EC_PUBKEY(NULL, (const unsigned char **)&key, asn1len);

    EC_KEY_set_conv_form(initiator_boot_key, POINT_CONVERSION_COMPRESSED);
    EC_KEY_set_asn1_flag(initiator_boot_key, OPENSSL_EC_NAMED_CURVE);

    return initiator_boot_key;
}

int ec_session_t::hkdf (const EVP_MD *h, int skip, unsigned char *ikm, int ikmlen,
        unsigned char *salt, int saltlen, unsigned char *info, int infolen,
        unsigned char *okm, int okmlen)
{
    unsigned char *prk, *tweak, ctr, *digest;
    int len;
    unsigned int digestlen, prklen, tweaklen;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX ctx;
#else
    HMAC_CTX *ctx = HMAC_CTX_new();
#endif

    digestlen = prklen = EVP_MD_size(h);
    if ((digest = (unsigned char *)malloc(digestlen)) == NULL) {
        perror("malloc");
        return 0;
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX_init(&ctx);
#else
    HMAC_CTX_reset(ctx);
#endif

    if (!skip) {
        /*
         * if !skip then do HKDF-extract
         */
        if ((prk = (unsigned char *)malloc(digestlen)) == NULL) {
            free(digest);
            perror("malloc");
            return 0;
        }
        /*
         * if there's no salt then use all zeros
         */
        if (!salt || (saltlen == 0)) {
            if ((tweak = (unsigned char *)malloc(digestlen)) == NULL) {
                free(digest);
                free(prk);
                perror("malloc");
                return 0;
            }
            memset(tweak, 0, digestlen);
            tweaklen = saltlen;
        } else {
            tweak = salt;
            tweaklen = saltlen;
        }
        (void)HMAC(h, tweak, tweaklen, ikm, ikmlen, prk, &prklen);
        if (!salt || (saltlen == 0)) {
            free(tweak);
        }
    } else {
        prk = ikm;
        prklen = ikmlen;
    }
    memset(digest, 0, digestlen);
    digestlen = 0;
    ctr = 0;
    len = 0;
    while (len < okmlen) {
        /*
         * T(0) = all zeros
         * T(n) = HMAC(prk, T(n-1) | info | counter)
         * okm = T(0) | ... | T(n)
         */
        ctr++;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        HMAC_Init_ex(&ctx, prk, prklen, h, NULL);
        HMAC_Update(&ctx, digest, digestlen);
#else
        HMAC_Init_ex(ctx, prk, prklen, h, NULL);
        HMAC_Update(ctx, digest, digestlen);
#endif
        if (info && (infolen != 0)) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
            HMAC_Update(&ctx, info, infolen);
#else
            HMAC_Update(ctx, info, infolen);
#endif
        }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        HMAC_Update(&ctx, &ctr, sizeof(unsigned char));
        HMAC_Final(&ctx, digest, &digestlen);
#else
        HMAC_Update(ctx, &ctr, sizeof(unsigned char));
        HMAC_Final(ctx, digest, &digestlen);
#endif
        if ((len + digestlen) > okmlen) {
            memcpy(okm + len, digest, okmlen - len);
        } else {
            memcpy(okm + len, digest, digestlen);
        }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        HMAC_CTX_cleanup(&ctx);
#else
        HMAC_CTX_free(ctx);
#endif
        len += digestlen;
    }
    if (!skip) {
        free(prk);
    }
    free(digest);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX_cleanup(&ctx);
#else
    HMAC_CTX_free(ctx);
#endif

    return okmlen;
}
