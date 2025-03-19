#include "ec_pa_configurator.h"

#include "ec_util.h"

bool ec_pa_configurator_t::handle_presence_announcement(ec_frame_t *frame, size_t len, uint8_t src_mac[ETHER_ADDR_LEN])
{
    ec_attribute_t *attrib = ec_util::get_attrib(frame->attributes, static_cast<uint16_t> (len - EC_FRAME_BASE_SIZE), ec_attrib_id_resp_bootstrap_key_hash);
    if (!attrib) {
        return -1;
    }

    return true;	
}

bool ec_pa_configurator_t::handle_auth_response(ec_frame_t *frame, size_t len, uint8_t src_mac[ETHER_ADDR_LEN])
{
    // Encapsulate 802.11 frame into 1905 Encap DPP TLV and send to controller
    auto [encap_dpp_tlv, encap_dpp_size] = ec_util::create_encap_dpp_tlv(false, src_mac, ec_frame_type_auth_rsp, reinterpret_cast<uint8_t*>(frame), len);
    ASSERT_NOT_NULL(encap_dpp_tlv, false, "%s:%d Failed to create Encap DPP TLV\n", __func__, __LINE__);

    // Only create and forward an Encap TLV
    bool did_succeed = m_send_prox_encap_dpp_msg(encap_dpp_tlv, encap_dpp_size, NULL, 0);
    free(encap_dpp_tlv);
    return did_succeed;
}

bool ec_pa_configurator_t::handle_cfg_request(uint8_t *buff, unsigned int len, uint8_t sa[ETH_ALEN])
{
    printf("%s:%d: Rx'd a DPP Configuration Request from " MACSTRFMT "\n", __func__, __LINE__, MAC2STR(sa));
    // EasyMesh R6 5.3.4
    // If a Proxy Agent receives a DPP Configuration Request frame in a GAS frame from an Enrollee Multi-AP Agent, it shall
    // generate a Proxied Encap DPP message that includes a 1905 Encap DPP TLV that encapsulates the received DPP
    // Configuration Request frame and shall set the Enrollee MAC Address Present field to one, include the Enrollee's MAC
    // address in the Destination STA MAC Address field, set the DPP Frame Indicator field to one and the Frame Type field to
    // 255, and send the message to the Multi-AP Controller.
    auto [encap_dpp_tlv, encap_dpp_tlv_len] = ec_util::create_encap_dpp_tlv(true, sa, static_cast<ec_frame_type_t>(ec_frame_type_easymesh), buff, len);
    ASSERT_NOT_NULL(encap_dpp_tlv, false, "%s:%d: Could not create Encap DPP TLV!\n", __func__, __LINE__);
    bool sent = m_send_prox_encap_dpp_msg(encap_dpp_tlv, encap_dpp_tlv_len, nullptr, 0);
    if (!sent) {
        printf("%s:%d: Failed to send Proxied Encap DPP message!\n", __func__, __LINE__);
    }
    free(encap_dpp_tlv);
    return sent;
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
    uint16_t encap_frame_len = 0;

    if (!ec_util::parse_encap_dpp_tlv(encap_tlv, encap_tlv_len, &dest_mac, &frame_type, &encap_frame, &encap_frame_len)) {
        printf("%s:%d: Failed to parse Encap DPP TLV\n", __func__, __LINE__);
        return false;
    }

    mac_addr_t chirp_mac = {0};
    uint8_t chirp_hash[255] = {0}; // Max hash length to avoid dynamic allocation
    uint8_t chirp_hash_len = 0;

    ec_frame_type_t ec_frame_type = static_cast<ec_frame_type_t>(frame_type);

    bool did_finish = false;

    // Pre-processing according to EM spec 5.4.3 Page 43
    // If a Proxy Agent receives a Proxied Encap DPP message from the Multi-AP Controller, it shall extract the DPP frame from
    // the Encapsulated Frame field of the 1905 Encap DPP TLV and:

    // 1. If the 1905 Encap DPP TLV DPP Frame Indicator bit field is set to one and the Frame Type field is set to 255, the
    // Proxy Agent shall decapsulate the DPP Configuration Response frame from the TLV and send it to the Enrollee Multi-
    // AP Agent using a GAS frame as described in [18]
    if (encap_tlv->dpp_frame_indicator && ec_frame_type == ec_frame_type_t::ec_frame_type_easymesh) {
        if (!encap_tlv->enrollee_mac_addr_present) {
            printf("%s:%d: Cannot forward DPP Configuration Result to Enrollee, MAC addr not present!\n", __func__, __LINE__);
            return false;
        }
        bool sent = m_send_action_frame(dest_mac, encap_frame, encap_frame_len, 0);
        if (!sent) {
            printf("%s:%d: Failed to forward DPP Configuration Result to Enrollee '" MACSTRFMT "'\n", __func__, __LINE__, MAC2STR(dest_mac));
        }
        free(encap_frame);
        return sent;
    }

    // 2. If the 1905 Encap DPP TLV DPP Frame Indicator bit field is set to one and the Frame Type field set to a value other
    // than 255, the Proxy Agent shall discard the message
    // 3. If the 1905 Encap DPP TLV DPP Frame Indicator bit field is set to zero and the Frame Type field set to 255, the Proxy
    // Agent shall discard the message
    if ((encap_tlv->dpp_frame_indicator && ec_frame_type != ec_frame_type_t::ec_frame_type_easymesh) ||
        (!encap_tlv->dpp_frame_indicator && ec_frame_type == ec_frame_type_t::ec_frame_type_easymesh)) {
            printf("%s:%d: Invalid Encap DPP fields, discarding message. DPP Frame Indicator=%d, DPP frame type=%d\n", __func__, __LINE__, encap_tlv->dpp_frame_indicator, ec_frame_type);
            free(encap_frame);
            return true;
    }
    // 4. If the 1905 Encap DPP TLV DPP Frame Indicator bit field is set to zero and the Frame Type field is set to a valid
    // value, the Proxy Agent shall process the message following the procedures described in sections 5.3.4 or 5.3.10.
    // Case 4 --  see next pile of text

    // EasyMesh R6 5.4.3 Page 42
    // If a Proxy Agent receives a Proxied Encap DPP message from the Controller, it shall extract the DPP frame from the
    // Encapsulated Frame field of the 1905 Encap DPP TLV. If the DPP Frame Indicator field value is zero, and if the Frame
    // Type field is not equal to zero or 15, then:
    if ((ec_frame_type != ec_frame_type_t::ec_frame_type_auth_req && ec_frame_type != ec_frame_type_t::ec_frame_type_recfg_auth_req)) {
        // 1. If the DPP Frame Indicator bit field in the 1905 Encap DPP TLV is set to zero and the Enrollee MAC Address Present
        // bit is set to one, then the Proxy Agent shall send the frame as a unicast Public Action frame to the Enrollee MAC
        // address
        if (!encap_tlv->dpp_frame_indicator && encap_tlv->enrollee_mac_addr_present) {
            bool sent = m_send_action_frame(dest_mac, encap_frame, encap_frame_len, 0);
            if (!sent) {
                printf("%s:%d: Failed to send non-DPP unicast action frame to '" MACSTRFMT "'\n", __func__, __LINE__, MAC2STR(dest_mac));
            }
            free(encap_frame);
            return sent;
        }
        // 2. If the DPP Frame Indicator bit field in the 1905 Encap DPP TLV is set to zero and the Enrollee MAC Address Present
        // bit is set to zero, then the Proxy Agent shall send the frame as a broadcast Public Action frame
        else if (!encap_tlv->dpp_frame_indicator && !encap_tlv->enrollee_mac_addr_present) {
            bool sent = m_send_action_frame(const_cast<uint8_t *>(BROADCAST_MAC_ADDR), encap_frame, encap_frame_len, 0);
            if (!sent) {
                printf("%s:%d: Failed to sent non-DPP broadcast action frame!\n", __func__, __LINE__);
            }
            free(encap_frame);
            return sent;
        }
        // 3. If the DPP Frame Indicator bit field in the 1905 Encap DPP TLV is set to one and the Enrollee MAC Address Present
        // bit is set to one, then the Proxy Agent shall send the frame as a unicast GAS frame to the Enrollee MAC address
        else if (encap_tlv->dpp_frame_indicator && encap_tlv->enrollee_mac_addr_present) {
            bool sent = m_send_action_frame(dest_mac, encap_frame, encap_frame_len, 0);
            if (!sent) {
                printf("%s:%d: Sent DPP unicast GAS frame to '" MACSTRFMT "'\n", __func__, __LINE__, MAC2STR(dest_mac));
            }
            free(encap_frame);
            return sent;
        }
        // 4. If the DPP Frame Indicator bit field in the 1905 Encap DPP TLV is set to one and the Enrollee MAC Address Present
        // bit is set to zero, then the Proxy Agent shall discard the message
        else if (encap_tlv->dpp_frame_indicator && !encap_tlv->enrollee_mac_addr_present) {
            printf("%s:%d: Proxied Encap DPP Message with DPP Frame Indicator set, but Enrollee MAC Addr Present false! Discarding.\n", __func__, __LINE__);
            free(encap_frame);
            return true;
        }
    }

    // Handlers for frame types 0, 15 "ec_frame_type_auth_req" and "ec_frame_type_recfg_auth_req"
    switch (ec_frame_type) {
        case ec_frame_type_auth_req: {
            if (chirp_tlv == NULL || chirp_tlv_len == 0) {
                printf("%s:%d: Chirp TLV is empty\n", __func__, __LINE__);
                break;
            }
            if (!ec_util::parse_dpp_chirp_tlv(chirp_tlv, chirp_tlv_len, &chirp_mac, reinterpret_cast<uint8_t**>(&chirp_hash), &chirp_hash_len)) {
                printf("%s:%d: Failed to parse DPP Chirp TLV\n", __func__, __LINE__);
                break;
            }
            std::string chirp_hash_str = ec_util::hash_to_hex_string(chirp_hash, chirp_hash_len);
            printf("%s:%d: Chirp TLV Hash: %s\n", __func__, __LINE__, chirp_hash_str.c_str());
            
            // Store the encap frame keyed by the chirp hash in the map
            std::vector<uint8_t> encap_frame_vec(encap_frame, encap_frame + encap_frame_len);
            m_chirp_hash_frame_map[chirp_hash_str] = encap_frame_vec;
            did_finish = true;
            break;
        }
        case ec_frame_type_recfg_auth_req: {
            printf("%s:%d: Encap DPP frame type (%d) not handled\n", __func__, __LINE__, ec_frame_type);
            std::vector<uint8_t> encap_frame_vec(encap_frame, encap_frame + encap_frame_len);
            // Will be compared against incoming presence announcement hash and mac-addr
            m_stored_recfg_auth_frames.push_back(encap_frame_vec); 
            did_finish = true;
            break;
        }
        default:
            printf("%s:%d: Encap DPP frame type (%d) not handled\n", __func__, __LINE__, ec_frame_type);
            break;
    }
    // Parse out dest STA mac address and hash value then validate against the hash in the 
    // ec_session dpp uri info public key. 
    // Then construct an Auth request frame and send back in an Encap message

    free(encap_frame);
    return did_finish;
}
