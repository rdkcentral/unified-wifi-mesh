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
#include "ec_util.h"
#include "em.h"
#include "aes_siv.h"

std::pair<uint8_t*, uint16_t> ec_session_t::create_auth_request()
{

    EC_KEY *responder_boot_key, *initiator_boot_key;

    ec_dpp_capabilities_t caps = {{
        .enrollee = 0,
        .configurator = 1
    }};

    printf("%s:%d Enter\n", __func__, __LINE__);

    uint8_t* buff = (uint8_t*) calloc(EC_FRAME_BASE_SIZE, 1);

    ec_frame_t    *frame = (ec_frame_t *)buff;
    frame->frame_type = ec_frame_type_auth_req;

    if (init_session(NULL) != 0) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d Failed to initialize session parameters\n", __func__, __LINE__);
        return std::make_pair<uint8_t*, uint16_t>(NULL, 0);
    }

    if (compute_intermediate_key(true) != 0) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d failed to generate key\n", __func__, __LINE__);
        return std::make_pair<uint8_t*, uint16_t>(NULL, 0);
    }

    uint8_t* attribs = NULL;
    uint16_t attrib_len = 0;

    // Responder Bootstrapping Key Hash
    if (compute_key_hash(m_data.responder_boot_key, m_params.responder_keyhash) < 1) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
        return std::make_pair<uint8_t*, uint16_t>(NULL, 0);
    }

    attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_resp_bootstrap_key_hash, SHA256_DIGEST_LENGTH, m_params.responder_keyhash);

    // Initiator Bootstrapping Key Hash
    if (compute_key_hash(m_data.initiator_boot_key, m_params.initiator_keyhash) < 1) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
        return std::make_pair<uint8_t*, uint16_t>(NULL, 0);
    }

    attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_init_bootstrap_key_hash, SHA256_DIGEST_LENGTH, m_params.initiator_keyhash);

    // Initiator Protocol Key
    uint8_t protocol_key_buff[1024];
    BN_bn2bin((const BIGNUM *)m_params.x,
            &protocol_key_buff[BN_num_bytes(m_params.prime) - BN_num_bytes(m_params.x)]);
    BN_bn2bin((const BIGNUM *)m_params.y,
            &protocol_key_buff[2*BN_num_bytes(m_params.prime) - BN_num_bytes(m_params.x)]);

    attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_init_proto_key, 2*BN_num_bytes(m_params.prime), protocol_key_buff);

    // Protocol Version
    if (m_cfgrtr_ver > 1) {
        attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_proto_version, m_cfgrtr_ver);
    }

    // Channel Attribute (optional)
    //TODO: REVISIT THIS
    if (m_data.ec_freqs[0] != 0){
        int base_freq = m_data.ec_freqs[0]; 
        uint16_t chann_attr = ec_util::freq_to_channel_attr(base_freq);
        attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_channel, sizeof(uint16_t), (uint8_t *)&chann_attr);
    }


    // Wrapped Data (with Initiator Nonce and Initiator Capabilities)
    // EasyMesh 8.2.2 Table 36
    attribs = add_wrapped_data_attr(frame, attribs, &attrib_len, true, m_params.k1, [&](){
        uint8_t* wrap_attribs = NULL;
        uint16_t wrapped_len = 0;
        wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_init_nonce, m_params.noncelen, m_params.initiator_nonce);
        wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_init_caps, caps.byte);
        return std::make_pair(wrap_attribs, wrapped_len);
    });

    // Add attributes to the frame
    uint16_t new_len = EC_FRAME_BASE_SIZE + attrib_len;
    buff = (uint8_t*) realloc(buff, new_len);
    if (buff == NULL) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d unable to realloc memory\n", __func__, __LINE__);
        return std::make_pair<uint8_t*, uint16_t>(NULL, 0);
    }
    frame = (ec_frame_t *)buff;
    memcpy(frame->attributes, attribs, attrib_len);

    free(attribs);

    return std::make_pair(buff, new_len);

}

int ec_session_t::create_auth_rsp(uint8_t *buff)
{
    return -1;
}

int ec_session_t::create_auth_cnf(uint8_t *buff)
{
    return -1;
}

int ec_session_t::create_pres_ann(uint8_t *buff)
{

    ec_frame_t *frame = (ec_frame_t *)buff;
    frame->frame_type = ec_frame_type_presence_announcement; 

    // Compute the hash of the responder boot key 
    uint8_t resp_boot_key_chirp_hash[SHA512_DIGEST_LENGTH];
    if (compute_key_hash(m_data.responder_boot_key, resp_boot_key_chirp_hash, "chirp") < 1) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d unable to compute \"chirp\" responder bootstrapping key hash\n", __func__, __LINE__);
        return -1;
    }

    uint8_t* attribs = frame->attributes;
    uint16_t attrib_len = 0;

    attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_resp_bootstrap_key_hash, SHA256_DIGEST_LENGTH, resp_boot_key_chirp_hash);
    attrib_len += ec_util::get_ec_attr_size(SHA256_DIGEST_LENGTH); 

    return attrib_len;
}

int ec_session_t::handle_pres_ann(uint8_t *buff, unsigned int len)
{
    ec_frame_t *frame = (ec_frame_t *)buff;

    if (ec_util::validate_frame(frame, ec_frame_type_presence_announcement) == false) {
        printf("%s:%d: frame validation failed\n", __func__, __LINE__);
        return -1;
    }

    ec_attribute_t *attrib = ec_util::get_attrib(frame->attributes, len-EC_FRAME_BASE_SIZE, ec_attrib_id_resp_bootstrap_key_hash);
    if (!attrib) {
        return -1;
    }

    // TODO: Come back to this
    memcpy(m_params.responder_keyhash, attrib->data, attrib->length);

    return 0;	
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
        printf("%s:%d Some BN NULL\n", __func__, __LINE__);
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
    if (m_params.initiator_proto_key != NULL){
        EC_KEY_free(m_params.initiator_proto_key);
        m_params.initiator_proto_key = NULL;
    }
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
        ec_util::print_ec_point(m_params.group, m_params.bnctx, m_params.M);

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
    // TODO: Currently only handling controller side

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
    // Compute the hash of the responder boot key 
    uint8_t resp_boot_key_chirp_hash[SHA512_DIGEST_LENGTH];
    if (compute_key_hash(m_data.responder_boot_key, resp_boot_key_chirp_hash, "chirp") < 1) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d unable to compute \"chirp\" responder bootstrapping key hash\n", __func__, __LINE__);
        return -1;
    }

    if (memcmp(hash, resp_boot_key_chirp_hash, hash_len) != 0) {
        // Hashes don't match, don't initiate DPP authentication
        *out_frame = NULL;
        printf("%s:%d: Chirp notification hash and DPP URI hash did not match! Stopping DPP!\n", __func__, __LINE__);
        return -1;
    }

    auto [auth_frame, auth_frame_len] = create_auth_request();
    if (auth_frame == NULL || auth_frame_len == 0) {
        printf("%s:%d: Failed to create authentication request frame\n", __func__, __LINE__);
        return -1;
    }

    // Create Auth Request Encap TLV: EasyMesh 5.3.4
    em_encap_dpp_t* encap_dpp_tlv = (em_encap_dpp_t*)calloc(sizeof(em_encap_dpp_t) + auth_frame_len , 1);
    if (encap_dpp_tlv == NULL) {
        printf("%s:%d: Failed to allocate memory for Encap DPP TLV\n", __func__, __LINE__);
        return -1;
    }
    encap_dpp_tlv->dpp_frame_indicator = 0;
    encap_dpp_tlv->frame_type = 0; // DPP Authentication Request Frame
    encap_dpp_tlv->enrollee_mac_addr_present = 1;

    memcpy(encap_dpp_tlv->dest_mac_addr, mac, sizeof(mac_addr_t));
    encap_dpp_tlv->encap_frame_len = auth_frame_len;
    memcpy(encap_dpp_tlv->encap_frame, auth_frame, auth_frame_len);

    free(auth_frame);

    // Create Auth Request Chirp TLV: EasyMesh 5.3.4
    size_t data_size = sizeof(mac_addr_t) + hash_len + sizeof(uint8_t);
    em_dpp_chirp_value_t* chirp = (em_dpp_chirp_value_t*)calloc(sizeof(em_dpp_chirp_value_t) + data_size, 1);
    if (chirp == NULL) {
        printf("%s:%d: Failed to allocate memory for chirp TLV\n", __func__, __LINE__);
        free(encap_dpp_tlv);
        return -1;
    }
    chirp->mac_present = 1;
    chirp->hash_valid = 1;

    uint8_t* tmp = chirp->data;
    memcpy(tmp, mac, sizeof(mac_addr_t));
    tmp += sizeof(mac_addr_t);

    *tmp = hash_len;
    tmp++;

    memcpy(tmp, hash, hash_len); 

    // Send the encapsulated DPP message (with Encap TLV and Chirp TLV)
    this->m_send_prox_encap_dpp_msg(encap_dpp_tlv, sizeof(em_encap_dpp_t) + auth_frame_len, chirp, sizeof(em_dpp_chirp_value_t) + data_size);

    free(encap_dpp_tlv);
    free(chirp);
    
    return 0;

}

int ec_session_t::handle_proxy_encap_dpp_tlv(em_encap_dpp_t *encap_tlv, uint8_t **out_frame) {

}

uint8_t* ec_session_t::add_wrapped_data_attr(ec_frame_t *frame, uint8_t* frame_attribs, uint16_t* non_wrapped_len, bool use_aad, uint8_t* key, std::function<std::pair<uint8_t*, uint16_t>()> create_wrap_attribs)
{
    siv_ctx ctx;

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
            return NULL;
    }

    // Use the provided function to create wrap_attribs and wrapped_len
    auto [wrap_attribs, wrapped_len] = create_wrap_attribs();

    // Encapsulate the attributes in a wrapped data attribute
    uint16_t wrapped_attrib_len = wrapped_len + AES_BLOCK_SIZE;
    ec_attribute_t *wrapped_attrib = (ec_attribute_t *)calloc(sizeof(ec_attribute_t) + wrapped_attrib_len, 1); 
    wrapped_attrib->attr_id = ec_attrib_id_wrapped_data;
    wrapped_attrib->length = wrapped_attrib_len;
    memset(wrapped_attrib->data, 0, wrapped_attrib_len);

    /**
    * Encrypt attributes using SIV mode with two additional authenticated data (AAD) inputs:
    * 1. The frame structure and 2. Non-wrapped attributes (per EasyMesh 6.3.1.4)
    * The synthetic IV/tag is stored in the first AES_BLOCK_SIZE bytes of wrapped_attrib->data
    */
   if (use_aad) {
        if (frame == NULL || frame_attribs == NULL || non_wrapped_len == NULL) {
            printf("%s:%d: AAD input is NULL, AAD encryption failed!\n", __func__, __LINE__);
            return NULL;
        }
        siv_encrypt(&ctx, wrap_attribs, &wrapped_attrib->data[AES_BLOCK_SIZE], wrapped_len, wrapped_attrib->data, 2,
            frame, sizeof(ec_frame_t),
            frame_attribs, *non_wrapped_len);
    } else {
        siv_encrypt(&ctx, wrap_attribs, &wrapped_attrib->data[AES_BLOCK_SIZE], wrapped_len, wrapped_attrib->data, 0);
    }

    // Add the wrapped data attribute to the frame
    uint8_t* ret_frame_attribs = ec_util::add_attrib(frame_attribs, non_wrapped_len, ec_attrib_id_wrapped_data, wrapped_attrib_len, (uint8_t *)wrapped_attrib);


    free(wrap_attribs);

    return ret_frame_attribs;
}

int ec_session_t::handle_recv_ec_action_frame(ec_frame_t *frame, size_t len)
{
    if (!ec_util::validate_frame(frame)) {
        printf("%s:%d: frame validation failed\n", __func__, __LINE__);
        return -1;
    }
    switch (frame->frame_type) {
        case ec_frame_type_presence_announcement:
            return handle_pres_ann((uint8_t *)frame, len);
        default:
            printf("%s:%d: frame type (%d) not handled\n", __func__, __LINE__, frame->frame_type);
            break;
    }
    return 0;
}

ec_session_t::ec_session_t(std::function<int(em_dpp_chirp_value_t*, size_t)> send_chirp_notification,
                            std::function<int(em_encap_dpp_t*, size_t, em_dpp_chirp_value_t*, size_t)> send_prox_encap_dpp_msg)
                            : m_send_chirp_notification(send_chirp_notification), m_send_prox_encap_dpp_msg(send_prox_encap_dpp_msg)
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

