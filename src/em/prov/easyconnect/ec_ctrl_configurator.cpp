#include "ec_ctrl_configurator.h"

#include "ec_base.h"

int ec_ctrl_configurator_t::process_chirp_notification(em_dpp_chirp_value_t *chirp_tlv, uint8_t **out_frame)
{


//     // Parse TLV
//     bool mac_addr_present = chirp_tlv->mac_present;
//     bool hash_valid = chirp_tlv->hash_valid;

//     uint8_t *data_ptr = chirp_tlv->data;
//     mac_addr_t mac = {0};
//     if (mac_addr_present) {
//         memcpy(mac, data_ptr, sizeof(mac_addr_t));
//         data_ptr += sizeof(mac_addr_t);
//     }

//     if (!hash_valid) {
//         // Clear (Re)configuration state, agent side
//         return 0;
//     }

//     uint8_t hash[255] = {0}; // Max hash length to avoid dynamic allocation
//     uint8_t hash_len = 0;

//     hash_len = *data_ptr;
//     data_ptr++;
//     memcpy(hash, data_ptr, hash_len);

//     // Validate hash
//     // Compute the hash of the responder boot key 
//     uint8_t resp_boot_key_chirp_hash[SHA512_DIGEST_LENGTH];
//     if (compute_key_hash(m_boot_data.responder_boot_key, resp_boot_key_chirp_hash, "chirp") < 1) {
// printf("%s:%d unable to compute \"chirp\" responder bootstrapping key hash\n", __func__, __LINE__);
//         return -1;
//     }

//     if (memcmp(hash, resp_boot_key_chirp_hash, hash_len) != 0) {
//         // Hashes don't match, don't initiate DPP authentication
//         *out_frame = NULL;
//         printf("%s:%d: Chirp notification hash and DPP URI hash did not match! Stopping DPP!\n", __func__, __LINE__);
//         return -1;
//     }

//     auto [auth_frame, auth_frame_len] = create_auth_request();
//     if (auth_frame == NULL || auth_frame_len == 0) {
//         printf("%s:%d: Failed to create authentication request frame\n", __func__, __LINE__);
//         return -1;
//     }

//     // Create Auth Request Encap TLV: EasyMesh 5.3.4
//     em_encap_dpp_t* encap_dpp_tlv = (em_encap_dpp_t*)calloc(sizeof(em_encap_dpp_t) + auth_frame_len , 1);
//     if (encap_dpp_tlv == NULL) {
//         printf("%s:%d: Failed to allocate memory for Encap DPP TLV\n", __func__, __LINE__);
//         return -1;
//     }
//     encap_dpp_tlv->dpp_frame_indicator = 0;
//     encap_dpp_tlv->frame_type = 0; // DPP Authentication Request Frame
//     encap_dpp_tlv->enrollee_mac_addr_present = 1;

//     memcpy(encap_dpp_tlv->dest_mac_addr, mac, sizeof(mac_addr_t));
//     encap_dpp_tlv->encap_frame_len = auth_frame_len;
//     memcpy(encap_dpp_tlv->encap_frame, auth_frame, auth_frame_len);

//     free(auth_frame);

//     // Create Auth Request Chirp TLV: EasyMesh 5.3.4
//     size_t data_size = sizeof(mac_addr_t) + hash_len + sizeof(uint8_t);
//     em_dpp_chirp_value_t* chirp = (em_dpp_chirp_value_t*)calloc(sizeof(em_dpp_chirp_value_t) + data_size, 1);
//     if (chirp == NULL) {
//         printf("%s:%d: Failed to allocate memory for chirp TLV\n", __func__, __LINE__);
//         free(encap_dpp_tlv);
//         return -1;
//     }
//     chirp->mac_present = 1;
//     chirp->hash_valid = 1;

//     uint8_t* tmp = chirp->data;
//     memcpy(tmp, mac, sizeof(mac_addr_t));
//     tmp += sizeof(mac_addr_t);

//     *tmp = hash_len;
//     tmp++;

//     memcpy(tmp, hash, hash_len); 

//     // Send the encapsulated DPP message (with Encap TLV and Chirp TLV)
//     this->m_send_prox_encap_dpp_msg(encap_dpp_tlv, sizeof(em_encap_dpp_t) + auth_frame_len, chirp, sizeof(em_dpp_chirp_value_t) + data_size);

//     free(encap_dpp_tlv);
//     free(chirp);
    
//     return 0;
}

int ec_ctrl_configurator_t::process_proxy_encap_dpp_tlv(em_encap_dpp_t *encap_tlv, uint8_t **out_frame)
{
    return 0;
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

std::pair<uint8_t *, uint16_t> ec_ctrl_configurator_t::create_auth_confirm()
{
    return std::pair<uint8_t *, uint16_t>();
}

std::pair<uint8_t *, uint16_t> ec_ctrl_configurator_t::create_config_response()
{
    return std::pair<uint8_t *, uint16_t>();
}
