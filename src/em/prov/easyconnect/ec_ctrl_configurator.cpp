#include "ec_ctrl_configurator.h"

#include "ec_base.h"
#include "ec_util.h"

int ec_ctrl_configurator_t::process_chirp_notification(em_dpp_chirp_value_t *chirp_tlv, uint16_t tlv_len)
{
    // TODO: Currently only handling controller side

    mac_addr_t mac = {0};
    uint8_t hash[255] = {0}; // Max hash length to avoid dynamic allocation
    uint8_t hash_len = 0;

    if (ec_util::parse_dpp_chirp_tlv(chirp_tlv, tlv_len, &mac, (uint8_t**)&hash, &hash_len) < 0) {
        printf("%s:%d: Failed to parse DPP Chirp TLV\n", __func__, __LINE__);
        return -1;
    }

    // Validate hash
    // Compute the hash of the responder boot key 
    uint8_t resp_boot_key_chirp_hash[SHA512_DIGEST_LENGTH];
    if (ec_crypto::compute_key_hash(m_boot_data.responder_boot_key, resp_boot_key_chirp_hash, "chirp") < 1) {
        printf("%s:%d unable to compute \"chirp\" responder bootstrapping key hash\n", __func__, __LINE__);
        return -1;
    }

    if (memcmp(hash, resp_boot_key_chirp_hash, hash_len) != 0) {
        // Hashes don't match, don't initiate DPP authentication
        printf("%s:%d: Chirp notification hash and DPP URI hash did not match! Stopping DPP!\n", __func__, __LINE__);
        return -1;
    }

    auto [auth_frame, auth_frame_len] = create_auth_request();
    if (auth_frame == NULL || auth_frame_len == 0) {
        printf("%s:%d: Failed to create authentication request frame\n", __func__, __LINE__);
        return -1;
    }

    // Create Auth Request Encap TLV: EasyMesh 5.3.4
    em_encap_dpp_t* encap_dpp_tlv = ec_util::create_encap_dpp_tlv(0, 0, &mac, 0, auth_frame, auth_frame_len);
    if (encap_dpp_tlv == NULL) {
        printf("%s:%d: Failed to create Encap DPP TLV\n", __func__, __LINE__);
        return -1;
    }

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

int ec_ctrl_configurator_t::process_proxy_encap_dpp_msg(em_encap_dpp_t *encap_tlv, uint16_t encap_tlv_len, em_dpp_chirp_value_t *chirp_tlv, uint16_t chirp_tlv_len)
{
    if (encap_tlv == NULL || encap_tlv_len == 0) {
        printf("%s:%d: Encap DPP TLV is empty\n", __func__, __LINE__);
        return -1;
    }

    
    mac_addr_t dest_mac = {0};
    uint8_t frame_type = 0;
    uint8_t* encap_frame = NULL;
    uint8_t encap_frame_len = 0;

    if (ec_util::parse_encap_dpp_tlv(encap_tlv, encap_tlv_len, &dest_mac, &frame_type, &encap_frame, &encap_frame_len) < 0) {
        printf("%s:%d: Failed to parse Encap DPP TLV\n", __func__, __LINE__);
        return -1;
    }

    mac_addr_t chirp_mac = {0};
    uint8_t chirp_hash[255] = {0}; // Max hash length to avoid dynamic allocation
    uint8_t chirp_hash_len = 0;

    ec_frame_type_t ec_frame_type = (ec_frame_type_t)frame_type;
    switch (ec_frame_type) {
        case ec_frame_type_recfg_announcement: {
            auto [recfg_auth_frame, recfg_auth_frame_len] = create_recfg_auth_request();
            if (recfg_auth_frame == NULL || recfg_auth_frame_len == 0) {
                printf("%s:%d: Failed to create reconfiguration authentication request frame\n", __func__, __LINE__);
                return -1;
            }
            em_encap_dpp_t* encap_dpp_tlv = ec_util::create_encap_dpp_tlv(0, 0, &dest_mac, ec_frame_type_recfg_auth_req, recfg_auth_frame, recfg_auth_frame_len);
            if (encap_dpp_tlv == NULL) {
                printf("%s:%d: Failed to create Encap DPP TLV\n", __func__, __LINE__);
                free(recfg_auth_frame);
                return -1;
            }
            free(recfg_auth_frame);
            // Send the encapsulated ReCfg Auth Request message (with Encap TLV)
            // TODO: SEND TO ALL AGENTS
            this->m_send_prox_encap_dpp_msg(encap_dpp_tlv, sizeof(em_encap_dpp_t) + recfg_auth_frame_len, NULL, 0);
            free(encap_dpp_tlv);
            break;
        }
        case ec_frame_type_auth_rsp: {
            break;
        }
        case ec_frame_type_recfg_auth_rsp: {

            break;
        }
        case ec_frame_type_auth_cnf:
        case ec_frame_type_recfg_auth_cnf: {
            break;
        }
            
        default:
            printf("%s:%d: Encap DPP frame type (%d) not handled\n", __func__, __LINE__, ec_frame_type);
            break;
    }
    // Parse out dest STA mac address and hash value then validate against the hash in the 
    // ec_session dpp uri info public key. 
    // Then construct an Auth request frame and send back in an Encap message
}

std::pair<uint8_t*, uint16_t> ec_ctrl_configurator_t::create_auth_request()
{

    // EC_KEY *responder_boot_key, *initiator_boot_key;

    // ec_dpp_capabilities_t caps = {{
    //     .enrollee = 0,
    //     .configurator = 1
    // }};

    // printf("%s:%d Enter\n", __func__, __LINE__);

    // uint8_t* buff = (uint8_t*) calloc(EC_FRAME_BASE_SIZE, 1);

    // ec_frame_t    *frame = (ec_frame_t *)buff;
    // frame->frame_type = ec_frame_type_auth_req;

    // if (init_session(NULL) != 0) {
    //     printf("%s:%d Failed to initialize session parameters\n", __func__, __LINE__);
    //     return std::make_pair<uint8_t*, uint16_t>(NULL, 0);
    // }

    // if (ec_util::compute_intermediate_key(m_params, true) != 0) {
    //     printf("%s:%d failed to generate key\n", __func__, __LINE__);
    //     return std::make_pair<uint8_t*, uint16_t>(NULL, 0);
    // }

    // uint8_t* attribs = NULL;
    // uint16_t attrib_len = 0;

    // // Responder Bootstrapping Key Hash
    // if (ec_util::compute_key_hash(m_boot_data.responder_boot_key, m_params.responder_keyhash) < 1) {
    //     printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
    //     return std::make_pair<uint8_t*, uint16_t>(NULL, 0);
    // }

    // attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_resp_bootstrap_key_hash, SHA256_DIGEST_LENGTH, m_params.responder_keyhash);

    // // Initiator Bootstrapping Key Hash
    // if (compute_key_hash(m_boot_data.initiator_boot_key, m_params.initiator_keyhash) < 1) {
    //     printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
    //     return std::make_pair<uint8_t*, uint16_t>(NULL, 0);
    // }

    // attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_init_bootstrap_key_hash, SHA256_DIGEST_LENGTH, m_params.initiator_keyhash);

    // // Initiator Protocol Key
    // uint8_t protocol_key_buff[1024];
    // BN_bn2bin((const BIGNUM *)m_params.x,
    //         &protocol_key_buff[BN_num_bytes(m_params.prime) - BN_num_bytes(m_params.x)]);
    // BN_bn2bin((const BIGNUM *)m_params.y,
    //         &protocol_key_buff[2*BN_num_bytes(m_params.prime) - BN_num_bytes(m_params.x)]);

    // attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_init_proto_key, 2*BN_num_bytes(m_params.prime), protocol_key_buff);

    // // Protocol Version
    // if (m_cfgrtr_ver > 1) {
    //     attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_proto_version, m_cfgrtr_ver);
    // }

    // // Channel Attribute (optional)
    // //TODO: REVISIT THIS
    // if (m_boot_data.ec_freqs[0] != 0){
    //     int base_freq = m_boot_data.ec_freqs[0]; 
    //     uint16_t chann_attr = ec_util::freq_to_channel_attr(base_freq);
    //     attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_channel, sizeof(uint16_t), (uint8_t *)&chann_attr);
    // }


    // // Wrapped Data (with Initiator Nonce and Initiator Capabilities)
    // // EasyMesh 8.2.2 Table 36
    // attribs = ec_util::add_wrapped_data_attr(frame, attribs, &attrib_len, true, m_params.k1, [&](){
    //     uint8_t* wrap_attribs = NULL;
    //     uint16_t wrapped_len = 0;
    //     wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_init_nonce, m_params.noncelen, m_params.initiator_nonce);
    //     wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_init_caps, caps.byte);
    //     return std::make_pair(wrap_attribs, wrapped_len);
    // });

    // // Add attributes to the frame
    // uint16_t new_len = EC_FRAME_BASE_SIZE + attrib_len;
    // buff = (uint8_t*) realloc(buff, new_len);
    // if (buff == NULL) {
    //     printf("%s:%d unable to realloc memory\n", __func__, __LINE__);
    //     return std::make_pair<uint8_t*, uint16_t>(NULL, 0);
    // }
    // frame = (ec_frame_t *)buff;
    // memcpy(frame->attributes, attribs, attrib_len);

    // free(attribs);

    // return std::make_pair(buff, new_len);

}

std::pair<uint8_t *, uint16_t> ec_ctrl_configurator_t::create_recfg_auth_request()
{
    return std::pair<uint8_t *, uint16_t>();
}

std::pair<uint8_t *, uint16_t> ec_ctrl_configurator_t::create_auth_confirm()
{
    uint8_t* buff = (uint8_t*) calloc(EC_FRAME_BASE_SIZE, 1);

    ec_frame_t    *frame = (ec_frame_t *)buff;
    frame->frame_type = ec_frame_type_auth_cnf; 

    uint8_t* attribs = NULL;
    uint16_t attrib_len = 0;

    // TODO: Move DPP status outside
    ec_status_code_t dpp_status = DPP_STATUS_OK; // TODO

    // uint8_t* key = (dpp_status == DPP_STATUS_OK ? m_params.k2 : m_params.ke);

    // attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_dpp_status, (uint8_t)dpp_status);
    // attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_resp_bootstrap_key_hash, sizeof(m_params.responder_keyhash), m_params.responder_keyhash);
    // // Conditional (Only included for mutual authentication)
    // if (m_params.mutual) {
    //     attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_init_bootstrap_key_hash, sizeof(m_params.initiator_keyhash), m_params.initiator_keyhash);
    // }

    // attribs = ec_util::add_wrapped_data_attr(frame, attribs, &attrib_len, true, key, [&](){
    //     uint8_t* wrap_attribs = NULL;
    //     uint16_t wrapped_len = 0;
    //     if (dpp_status == DPP_STATUS_OK) {
    //         wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_init_auth_tag, sizeof(m_params.iauth), m_params.iauth);
    //     } else {
    //         wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_resp_nonce, m_params.noncelen, m_params.responder_nonce);
    //     }
    //     return std::make_pair(wrap_attribs, wrapped_len);
    // });

    if (!(frame = ec_util::copy_attrs_to_frame(frame, attribs, attrib_len))) {
        printf("%s:%d unable to copy attributes to frame\n", __func__, __LINE__);
        free(attribs);
        return std::make_pair<uint8_t*, uint16_t>(NULL, 0);
    }
    free(attribs);

    return std::make_pair((uint8_t*)frame, EC_FRAME_BASE_SIZE + attrib_len);
}

std::pair<uint8_t *, uint16_t> ec_ctrl_configurator_t::create_recfg_auth_confirm()
{
    uint8_t* buff = (uint8_t*) calloc(EC_FRAME_BASE_SIZE, 1);

    ec_frame_t    *frame = (ec_frame_t *)buff;
    frame->frame_type = ec_frame_type_auth_cnf; 

    uint8_t* attribs = NULL;
    uint16_t attrib_len = 0;

    // TODO: Move DPP status outside
    ec_status_code_t dpp_status = DPP_STATUS_OK; // TODO

    // TODO: Add transaction ID outside this function
    uint8_t trans_id = 0;
    ec_dpp_reconfig_flags_t reconfig_flags = {
        .connector_key = 1, // DONT REUSE
    };

    attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_dpp_status, (uint8_t)dpp_status);

    // attribs = ec_util::add_wrapped_data_attr(frame, attribs, &attrib_len, false, m_params.ke, [&](){
    //     uint8_t* wrap_attribs = NULL;
    //     uint16_t wrapped_len = 0;

    //     wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_trans_id, trans_id);
    //     wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_proto_version, (uint8_t)m_boot_data.version);
    //     wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_config_nonce, m_params.noncelen, m_params.initiator_nonce);
    //     wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_enrollee_nonce, m_params.noncelen, m_params.enrollee_nonce);
    //     wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_reconfig_flags, sizeof(reconfig_flags), (uint8_t*)&reconfig_flags);

    //     return std::make_pair(wrap_attribs, wrapped_len);
    // });

    if (!(frame = ec_util::copy_attrs_to_frame(frame, attribs, attrib_len))) {
        printf("%s:%d unable to copy attributes to frame\n", __func__, __LINE__);
        free(attribs);
        return std::make_pair<uint8_t*, uint16_t>(NULL, 0);
    }
    free(attribs);

    return std::make_pair((uint8_t*)frame, EC_FRAME_BASE_SIZE + attrib_len);
}

std::pair<uint8_t *, uint16_t> ec_ctrl_configurator_t::create_config_response()
{
    return std::pair<uint8_t *, uint16_t>();
}
