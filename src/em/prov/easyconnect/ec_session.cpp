/**
 * Copyright 2025 Comcast Cable Communications Management, LLC
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
#include "ec_base.h"
#include "ec_session.h"
#include "em.h"
#include "aes_siv.h"

int ec_session_t::create_auth_req(unsigned char *buff)
{

    EC_KEY *responder_boot_key, *initiator_boot_key;
    unsigned int wrapped_len;

    unsigned short attrib_len, chann_attr;;
    unsigned char protocol_key_buff[1024];
    ULONG hm_channel = 0;
    ULONG ch_freq = 0;

    printf("%s:%d Enter\n", __func__, __LINE__);

    ec_frame_t    *frame = (ec_frame_t *)buff;

    attrib_len = 0;

    frame->frame_type = ec_frame_type_auth_req;

    if (init_session(NULL) != 0) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d Failed to initialize session parameters\n", __func__, __LINE__);
        return -1;
    }

    if (compute_intermediate_key(true) != 0) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d failed to generate key\n", __func__, __LINE__);
        return -1;
    }

    uint8_t* attribs = frame->attributes;

    // Responder Bootstrapping Key Hash
    if (compute_key_hash(m_data.responder_boot_key, m_params.responder_keyhash) < 1) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
        return -1;
    }

    attribs = add_attrib(attribs, ec_attrib_id_resp_bootstrap_key_hash, SHA256_DIGEST_LENGTH, m_params.responder_keyhash);
    attrib_len += get_ec_attr_size(SHA256_DIGEST_LENGTH);

    // Initiator Bootstrapping Key Hash
    if (compute_key_hash(m_data.initiator_boot_key, m_params.initiator_keyhash) < 1) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
        return -1;
    }

    attribs = add_attrib(attribs, ec_attrib_id_init_bootstrap_key_hash, SHA256_DIGEST_LENGTH, m_params.initiator_keyhash);
    attrib_len += get_ec_attr_size(SHA256_DIGEST_LENGTH);

    // Initiator Protocol Key
    BN_bn2bin((const BIGNUM *)m_params.x,
            &protocol_key_buff[BN_num_bytes(m_params.prime) - BN_num_bytes(m_params.x)]);
    BN_bn2bin((const BIGNUM *)m_params.y,
            &protocol_key_buff[2*BN_num_bytes(m_params.prime) - BN_num_bytes(m_params.x)]);

    attribs = add_attrib(attribs, ec_attrib_id_init_proto_key, 2*BN_num_bytes(m_params.prime), protocol_key_buff);
    attrib_len += get_ec_attr_size(2*BN_num_bytes(m_params.prime));

    // Protocol Version
    if (m_cfgrtr_ver > 1) {
        attribs = add_attrib(attribs, ec_attrib_id_proto_version, m_cfgrtr_ver);
        attrib_len += get_ec_attr_size(sizeof(m_cfgrtr_ver));
    }

    // Channel Attribute
    chann_attr = freq_to_channel(channel_to_frequency(hm_channel)); //channel attrib shall be home channel
    attribs = add_attrib(attribs, ec_attrib_id_channel, sizeof(unsigned short), (unsigned char *)&chann_attr);
    attrib_len += get_ec_attr_size(sizeof(unsigned short));

    // Wrapped Data (with Initiator Nonce and Initiator Capabilities)
    wrapped_len = set_auth_frame_wrapped_data(frame, attrib_len, true);
    attrib_len += get_ec_attr_size(wrapped_len);

    printf("%s:%d Exit\n", __func__, __LINE__);

    return attrib_len;

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

    ec_frame_t *frame = (ec_frame_t *)buff;
    frame->frame_type = ec_frame_type_presence_announcement; 

    // Compute the hash of the responder boot key 
    unsigned char resp_boot_key_chirp_hash[SHA512_DIGEST_LENGTH];
    if (compute_key_hash(m_data.responder_boot_key, resp_boot_key_chirp_hash, "chirp") < 1) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d unable to compute \"chirp\" responder bootstrapping key hash\n", __func__, __LINE__);
        return -1;
    }

    uint8_t* attribs = frame->attributes;
    unsigned short attrib_len = 0;

    attribs = add_attrib(attribs, ec_attrib_id_resp_bootstrap_key_hash, SHA256_DIGEST_LENGTH, resp_boot_key_chirp_hash);
    attrib_len += get_ec_attr_size(SHA256_DIGEST_LENGTH); 

    return attrib_len;
}

int ec_session_t::handle_pres_ann(unsigned char *buff, unsigned int len)
{
    ec_frame_t *frame = (ec_frame_t *)buff;

    if (validate_frame(frame, ec_frame_type_presence_announcement) == false) {
        printf("%s:%d: frame validation failed\n", __func__, __LINE__);
        return -1;
    }

    ec_attribute_t *attrib = get_attrib(frame->attributes, len-EC_FRAME_BASE_SIZE, ec_attrib_id_resp_bootstrap_key_hash);
    if (!attrib) {
        return -1;
    }

    // TODO: Come back to this
    memcpy(m_params.responder_keyhash, attrib->data, attrib->length);

    return 0;	
}

bool ec_session_t::validate_frame(ec_frame_t *frame, ec_frame_type_t type)
{
    if ((frame->category != 0x04) 
            || (frame->action != 0x09)
            || (frame->oui[0] != 0x50)
            || (frame->oui[1] != 0x6f)
            || (frame->oui[2] != 0x9a)
            || (frame->oui_type != DPP_OUI_TYPE)
            || (frame->crypto_suite != 0x01)
            || (frame->frame_type != type)) {
        return false;
    }

    return true;
}

int ec_session_t::init_session(ec_data_t* ec_data)
{
    const EC_POINT *ipt, *rpt = NULL;
    const BIGNUM *proto_priv;

    if (ec_data != NULL) {
        memset(&m_data, 0, sizeof(ec_data_t));
        memcpy(&m_data, ec_data, sizeof(ec_data_t));
    }

    if (m_data.type == ec_session_type_cfg) {
        // Set in DPP URI 

        rpt = EC_KEY_get0_public_key(m_data.responder_boot_key);
        if (rpt == NULL) {
            printf("%s:%d Could not get responder bootstrap public key\n", __func__, __LINE__);
            return -1;
        }

    } else if (m_data.type == ec_session_type_recfg) {

        m_params.group = EC_KEY_get0_group(m_data.initiator_boot_key);
        m_params.responder_connector = EC_POINT_new(m_params.group);
    }


    m_params.x = BN_new();
    m_params.y = BN_new();
    m_params.m = BN_new();
    m_params.n = BN_new();
    m_params.prime = BN_new();
    m_params.bnctx = BN_CTX_new();

    if (!m_params.x || !m_params.y || !m_params.m || !m_params.n || 
        !m_params.prime || !m_params.bnctx) {
        // error print
        BN_free(m_params.x);
        BN_free(m_params.y);
        BN_free(m_params.m);
        BN_free(m_params.n);
        BN_free(m_params.prime);
        BN_CTX_free(m_params.bnctx);
        return -1;
    }

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

int ec_session_t::handle_chirp_notification(em_dpp_chirp_value_t *chirp_tlv, uint8_t **out_frame)
{

    // Parse TLV
    bool mac_addr_present = chirp_tlv->mac_present;
    bool hash_valid = chirp_tlv->hash_valid;

    uint8_t *data_ptr = chirp_tlv->data;
    mac_addr_t mac = {0};
    if (mac_addr_present) {
        memcpy(mac, data_ptr, sizeof(mac_addr_t));
        data_ptr += sizeof(mac_addr_t);
    }

    if (!hash_valid) {
        // Clear (Re)configuration state, agent side
        return 0;
    }

    uint8_t hash[255] = {0}; // Max hash length to avoid dynamic allocation
    uint8_t hash_len = 0;

    hash_len = *data_ptr;
    data_ptr++;
    memcpy(hash, data_ptr, hash_len);

    // Validate hash
    if (compute_key_hash(m_data.responder_boot_key, m_params.responder_keyhash) < 1) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
        return -1;
    }

    if (memcmp(hash, m_params.responder_keyhash, hash_len) != 0) {
        // Hashes don't match, don't initiate DPP authentication
        *out_frame = NULL;
        printf("%s:%d: Chirp notification hash and DPP URI hash did not match! Stopping DPP!\n", __func__, __LINE__);
        return -1;
    }

    // TODO: 
    // create_auth_req(*out_frame);

    return 0;

}

int ec_session_t::set_auth_frame_wrapped_data(ec_frame_t *frame, unsigned int non_wrapped_len, bool do_init_auth)
{
    siv_ctx ctx;
    
    ec_attribute_t *attrib;
    ec_dpp_capabilities_t caps = {{
        .enrollee = 0,
        .configurator = 1
    }};
    unsigned int wrapped_len = 0;
    ec_attribute_t *wrapped_attrib;

    unsigned char *key = do_init_auth ? m_params.k1 : m_params.ke;

    // Initialize AES-SIV context
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

    unsigned char plain[512];
    uint8_t* attribs = plain;

    if (do_init_auth) {
        attribs = add_attrib(attribs, ec_attrib_id_init_nonce, m_params.noncelen, m_params.initiator_nonce);
        wrapped_len += get_ec_attr_size(m_params.noncelen); 

        attribs = add_attrib(attribs, ec_attrib_id_init_caps, caps.byte);
        wrapped_len += get_ec_attr_size(1);
    } else {
        attribs = add_attrib(attribs, ec_attrib_id_init_auth_tag, m_params.digestlen, m_params.iauth);
        wrapped_len += get_ec_attr_size(m_params.digestlen);

    }

    // Encapsulate the attributes in a wrapped data attribute
    wrapped_attrib = (ec_attribute_t *)(frame->attributes + non_wrapped_len);
    wrapped_attrib->attr_id = ec_attrib_id_wrapped_data;
    wrapped_attrib->length = wrapped_len + AES_BLOCK_SIZE;

    // Encrypt the attributes
    siv_encrypt(&ctx, plain, &wrapped_attrib->data[AES_BLOCK_SIZE], wrapped_len, wrapped_attrib->data, 2,
            frame, sizeof(ec_frame_t), // Used for SIV (authentication)
            frame->attributes, non_wrapped_len); // Used for SIV (authentication)

    //printf("%s:%d: Plain text:\n", __func__, __LINE__);
    //print_hex_dump(noncelen, plain);

    return wrapped_len + AES_BLOCK_SIZE;
}

ec_session_t::ec_session_t() 
{
    // Initialize member variables
    m_cfgrtr_ver = 0;
    m_enrollee_ver = 0;
    m_activation_status = ActStatus_Idle;
    memset(&m_enrollee_mac, 0, sizeof(mac_address_t));
    memset(&m_params, 0, sizeof(ec_params_t));
    memset(&m_data, 0, sizeof(ec_data_t));
}

ec_session_t::~ec_session_t() 
{
    // Clean up any allocated resources if necessary
}

