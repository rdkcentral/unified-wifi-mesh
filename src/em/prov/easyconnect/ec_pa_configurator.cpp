#include "ec_pa_configurator.h"

#include "ec_util.h"

bool ec_pa_configurator_t::handle_presence_announcement(uint8_t *buff, unsigned int len)
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

    return true;	
}

bool ec_pa_configurator_t::handle_auth_response(uint8_t *buff, unsigned int len)
{
    return true;
}

bool ec_pa_configurator_t::handle_cfg_request(uint8_t *buff, unsigned int len, uint8_t sa[ETH_ALEN])
{
    printf("%s:%d: Rx'd a DPP Configuration Request from " MACSTRFMT "\n", __func__, __LINE__, MAC2STR(sa));
    uint8_t *p = buff;
    ec_gas_frame_base_t *gas_frame_base = (ec_gas_frame_base_t *)p;
    p += sizeof(ec_gas_frame_base_t);
    ec_gas_initial_request_frame_t *gas_initial_request = (ec_gas_initial_request_frame_t *)p;
    printf(
        "%s:%d: Got a DPP config request! category=%02x action=%02x dialog_token=%02x ape=" APEFMT
        " ape_id=" APEIDFMT " query_len=%d\n",
        __func__, __LINE__, gas_frame_base->action, gas_frame_base->category,
        gas_frame_base->dialog_token, APE2STR(gas_initial_request->ape),
        APEID2STR(gas_initial_request->ape_id), gas_initial_request->query_len);
    printf("%s:%d: IMPLEMENT ME!\n", __func__, __LINE__);
    return true;
}

bool ec_pa_configurator_t::handle_cfg_result(uint8_t *buff, unsigned int len)
{
    return true;
}

bool ec_pa_configurator_t::process_chirp_notification(em_dpp_chirp_value_t *chirp_tlv, uint16_t tlv_len)
{
    return true;
}

bool ec_pa_configurator_t::process_proxy_encap_dpp_msg(em_encap_dpp_t *encap_tlv, uint16_t encap_tlv_len, em_dpp_chirp_value_t *chirp_tlv, uint16_t chirp_tlv_len)
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
        case ec_frame_type_auth_req: {
            if (chirp_tlv == NULL || chirp_tlv_len == 0) {
                printf("%s:%d: Chirp TLV is empty\n", __func__, __LINE__);
                return -1;
            }
            if (ec_util::parse_dpp_chirp_tlv(chirp_tlv, chirp_tlv_len, &chirp_mac, (uint8_t**)&chirp_hash, &chirp_hash_len) < 0) {
                printf("%s:%d: Failed to parse DPP Chirp TLV\n", __func__, __LINE__);
                return -1;
            }
            std::string chirp_hash_str = ec_util::hash_to_hex_string(chirp_hash, chirp_hash_len);
            printf("%s:%d: Chirp TLV Hash: %s\n", __func__, __LINE__, chirp_hash_str.c_str());
            
            // Store the encap frame keyed by the chirp hash in the map
            std::vector<uint8_t> encap_frame_vec(encap_frame, encap_frame + encap_frame_len);
            m_chirp_hash_frame_map[chirp_hash_str] = encap_frame_vec;
            break;
        }
        case ec_frame_type_recfg_auth_req: {
            printf("%s:%d: Encap DPP frame type (%d) not handled\n", __func__, __LINE__, ec_frame_type);
            std::vector<uint8_t> encap_frame_vec(encap_frame, encap_frame + encap_frame_len);
            // Will be compared against incoming presence announcement hash and mac-addr
            m_stored_recfg_auth_frames.push_back(encap_frame_vec); 
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
