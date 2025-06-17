#include "ec_pa_configurator.h"

#include "ec_util.h"
#include "util.h"

ec_pa_configurator_t::ec_pa_configurator_t(const std::string& mac_addr, ec_ops_t& ops)
    : ec_configurator_t(mac_addr, ops)
{
    m_toggle_cce = ops.toggle_cce;
}

bool ec_pa_configurator_t::handle_presence_announcement(ec_frame_t *frame, size_t len, uint8_t src_mac[ETHER_ADDR_LEN])
{
    em_printfout("Recieved a DPP Presence Announcement Frame from '" MACSTRFMT "'\n", MAC2STR(src_mac));
    size_t attrs_len = len - EC_FRAME_BASE_SIZE;

    auto B_r_hash_attr = ec_util::get_attrib(frame->attributes, static_cast<uint16_t> (attrs_len), ec_attrib_id_resp_bootstrap_key_hash);
    ASSERT_OPT_HAS_VALUE(B_r_hash_attr, false, "%s:%d No responder bootstrapping key hash attribute found\n", __func__, __LINE__);
    std::string B_r_hash_str = em_crypto_t::hash_to_hex_string(B_r_hash_attr->data, B_r_hash_attr->length);

    // EasyMesh R6 5.3.4
    // If a Proxy Agent receives a DPP Presence Announcement frame, the Proxy Agent shall check if the bootstrapping
    // key hash in the DPP Presence Announcement frame matches any values of bootstrapping key hash of a stored DPP 
    // Authentication Request frame received from the Multi-AP Controller. 
    bool sent = false;
    auto hash_frame_iter = m_chirp_hash_frame_map.find(B_r_hash_str);
    if (hash_frame_iter == m_chirp_hash_frame_map.end()) {
        // If no matching hash value is found, the Proxy Agent shall send a Chirp Notification message to the 
        // Controller with a DPP Chirp Value TLV
        em_printfout("No matching hash value found for '%s' in the DPP Presence Announcement frame", B_r_hash_str.c_str());
        const auto [chirp_tlv, chirp_tlv_len] = ec_util::create_dpp_chirp_tlv(true, true, src_mac, B_r_hash_attr->data, B_r_hash_attr->length);
        ASSERT_NOT_NULL(chirp_tlv, false, "%s:%d Failed to create DPP Chirp Value TLV\n", __func__, __LINE__);
        sent = m_send_chirp_notification(chirp_tlv, chirp_tlv_len);
        free(chirp_tlv);
    } else {

        // If a Proxy Agent receives a Presence Announcement frame (chirp) with bootstrapping key hash from the
        // Enrollee MultiAP Agent that matches the Hash Value field of the DPP Chirp Value TLV received from the
        // Multi-AP Controller, the Proxy Agent shall send the DPP Authentication Request frame to the Enrollee within
        // 1 second of receiving the Presence Announcement frame from that Enrollee, using a DPP Public Action frame to
        // the MAC address from where the Presence Announcement frame was received.
        em_printfout("Found matching hash value for '%s' in the DPP Presence Announcement frame", B_r_hash_str.c_str());
        std::vector<uint8_t> encap_frame_vec  = hash_frame_iter->second;
        sent = m_send_action_frame(src_mac, encap_frame_vec.data(), encap_frame_vec.size(), 0, 0);
    }

    return sent;	
}

bool ec_pa_configurator_t::handle_recfg_announcement(ec_frame_t *frame, size_t len, uint8_t sa[ETH_ALEN])
{
    em_printfout("Received a DPP Reconfiguration Announcement frame from '" MACSTRFMT "'", MAC2STR(sa));

    // EasyMesh 5.3.10.2
    size_t attrs_len = len - EC_FRAME_BASE_SIZE;
    auto c_sign_key_hash_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_C_sign_key_hash);
    ASSERT_OPT_HAS_VALUE(c_sign_key_hash_attr, false, "%s:%d: No C-sign key hash attribute found in DPP Reconfiguration Announcement frame\n", __func__, __LINE__);

    std::string c_sign_key_hash_str = em_crypto_t::hash_to_hex_string(c_sign_key_hash_attr->data, c_sign_key_hash_attr->length);
    bool sent = false;
    bool hash_known = (m_stored_recfg_auth_frames_map.find(c_sign_key_hash_str) != m_stored_recfg_auth_frames_map.end());
    if (hash_known) {
        em_printfout("Found matching C-sign key hash in DPP Reconfiguration Announcement frame, sending Reconfiguration Authentication Request frame");
        std::vector<uint8_t> encap_frame_vec = m_stored_recfg_auth_frames_map[c_sign_key_hash_str];
        sent = m_send_action_frame(sa, encap_frame_vec.data(), encap_frame_vec.size(), 0, 0);
    } else {
        em_printfout("No matching C-sign key hash found in DPP Reconfiguration Announcement frame, sending Reconfiguration Announcement frame to controller");
        auto [encap_frame, encap_frame_len] = ec_util::create_encap_dpp_tlv(false, sa, ec_frame_type_recfg_announcement, reinterpret_cast<uint8_t*>(frame), len);
        ASSERT_NOT_NULL(encap_frame, false, "%s:%d: Failed to create Encap DPP TLV for Reconfiguration Announcement frame\n", __func__, __LINE__);
        sent = m_send_prox_encap_dpp_msg(encap_frame, encap_frame_len, nullptr, 0);
        free(encap_frame);
    }
    return sent;
}

bool ec_pa_configurator_t::handle_auth_response(ec_frame_t *frame, size_t len, uint8_t src_mac[ETHER_ADDR_LEN])
{
    em_printfout("Received a DPP Authentication Response frame from '" MACSTRFMT "'\n", MAC2STR(src_mac));
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
    em_printfout("Rx'd a DPP Configuration Request from " MACSTRFMT "", MAC2STR(sa));
    ec_gas_initial_request_frame_t *req_frame = reinterpret_cast<ec_gas_initial_request_frame_t *>(buff);
    m_gas_session_dialog_tokens[util::mac_to_string(sa)] = req_frame->base.dialog_token;

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
        em_printfout("Failed to send Proxied Encap DPP message!");
    }
    free(encap_dpp_tlv);
    return sent;
}

bool ec_pa_configurator_t::handle_cfg_result(ec_frame_t *frame, size_t len, uint8_t sa[ETH_ALEN])
{
    em_printfout("Received a Configuration Result frame from '" MACSTRFMT "'", MAC2STR(sa));
    // EasyMesh 5.3.4
    // If a Proxy Agent receives a DPP Configuration Result frame from an Enrollee Multi-AP Agent, it shall encapsulate the
    // frame into a 1905 Encap DPP TLV, set the Enrollee MAC Address Present field to one, set the Destination STA MAC
    // Address field to the MAC address of the Enrollee, set the DPP Frame Indicator field to 0 and the Frame Type field to 11,
    // and send the Proxied Encap DPP message to the Multi-AP Controller.

    auto [encap_dpp_tlv, encap_dpp_tlv_len] = ec_util::create_encap_dpp_tlv(false, sa, ec_frame_type_cfg_result, reinterpret_cast<uint8_t*>(frame), len);
    ASSERT_NOT_NULL(encap_dpp_tlv, false, "%s:%d: Failed to create Encap DPP TLV\n", __func__, __LINE__);
    bool sent = m_send_prox_encap_dpp_msg(encap_dpp_tlv, encap_dpp_tlv_len, nullptr, 0);
    if (!sent) {
        em_printfout("Failed to send Encap DPP TLV");
    }
    em_printfout("Sent Encap DPP TLV");
    free(encap_dpp_tlv);
    return sent;
}

bool ec_pa_configurator_t::handle_connection_status_result(ec_frame_t *frame, size_t len, uint8_t sa[ETH_ALEN])
{
    em_printfout("Received a Connection Status Result frame from '" MACSTRFMT "'", MAC2STR(sa));
    // EasyMesh 5.3.4
    // If a Proxy Agent receives a DPP Connection Status Result frame from an Enrollee Multi-AP Agent, it shall encapsulate the
    // frame into a 1905 Encap DPP TLV, set the Enrollee MAC Address Present field to one, set the Destination STA MAC
    // Address field to the MAC address of the Enrollee, set the DPP Frame Indicator field to 0 and the Frame Type field to 12,
    // and send the Proxied Encap DPP message to the Multi-AP Controller

    auto [encap_dpp_tlv, encap_dpp_tlv_len] = ec_util::create_encap_dpp_tlv(false, sa, ec_frame_type_conn_status_result, reinterpret_cast<uint8_t*>(frame), len);
    ASSERT_NOT_NULL(encap_dpp_tlv, false, "%s:%d: Failed to create Encap DPP TLV\n", __func__, __LINE__);
    bool sent = m_send_prox_encap_dpp_msg(encap_dpp_tlv, encap_dpp_tlv_len, nullptr, 0);
    if (!sent) {
        em_printfout("Failed to send Encap DPP TLV");
    }
    em_printfout("Sent Encap DPP TLV");
    free(encap_dpp_tlv);
    return sent;
}

bool ec_pa_configurator_t::process_chirp_notification(em_dpp_chirp_value_t *chirp_tlv, uint16_t tlv_len)
{
    return true;
}

bool ec_pa_configurator_t::process_proxy_encap_dpp_msg(em_encap_dpp_t *encap_tlv, uint16_t encap_tlv_len, em_dpp_chirp_value_t *chirp_tlv, uint16_t chirp_tlv_len)
{
    if (encap_tlv == NULL || encap_tlv_len == 0) {
        em_printfout("Encap DPP TLV is empty");
        return -1;
    }

    
    mac_addr_t dest_mac = {0};
    uint8_t frame_type = 0;
    uint8_t* encap_frame = NULL;
    uint16_t encap_frame_len = 0;

    if (!ec_util::parse_encap_dpp_tlv(encap_tlv, encap_tlv_len, &dest_mac, &frame_type, &encap_frame, &encap_frame_len)) {
        em_printfout("Failed to parse Encap DPP TLV");
        return false;
    }

    ec_frame_type_t ec_frame_type = static_cast<ec_frame_type_t>(frame_type);

    bool did_finish = false;

    std::string dest_mac_str = util::mac_to_string(dest_mac);

    bool needs_fragmentation = (encap_frame_len > WIFI_MTU_SIZE);
    if (needs_fragmentation) {
        auto it = m_gas_session_dialog_tokens.find(dest_mac_str);
        if (it == m_gas_session_dialog_tokens.end()) {
            em_printfout("No GAS session dialog token found for '" MACSTRFMT "', not sending 802.11 frame.", MAC2STR(dest_mac));
            return false;
        }
        uint8_t dialog_token = it->second;
        // If peer is not ready to receive GAS Comeback Frames, we must first send a "dummy" GAS Initial Response frame inidicating to the 
        // peer that GAS Comeback Response frames will be coming.
        // Fragment the frame and store the fragments and wait for a GAS Comeback Request prior to sending.
        em_printfout("Sending fragmentation prepare GAS Initial Response frame to '" MACSTRFMT "'", MAC2STR(dest_mac));
        m_gas_frames_to_be_sent[dest_mac_str] = fragment_large_frame(encap_frame, encap_frame_len, dialog_token);
        return send_prepare_for_fragmented_frames_frame(dest_mac);
    }

    // Pre-processing according to EM spec 5.4.3 Page 43
    // If a Proxy Agent receives a Proxied Encap DPP message from the Multi-AP Controller, it shall extract the DPP frame from
    // the Encapsulated Frame field of the 1905 Encap DPP TLV and:

    // 1. If the 1905 Encap DPP TLV DPP Frame Indicator bit field is set to one and the Frame Type field is set to 255, the
    // Proxy Agent shall decapsulate the DPP Configuration Response frame from the TLV and send it to the Enrollee Multi-
    // AP Agent using a GAS frame as described in [18]
    if (encap_tlv->dpp_frame_indicator && ec_frame_type == ec_frame_type_t::ec_frame_type_easymesh) {
        if (!encap_tlv->enrollee_mac_addr_present) {
            em_printfout("Cannot forward DPP Configuration Result to Enrollee, MAC addr not present!");
            return false;
        }
        bool sent = m_send_action_frame(dest_mac, encap_frame, encap_frame_len, 0, 0);
        if (!sent) {
            em_printfout("Failed to forward DPP Configuration Result to Enrollee '" MACSTRFMT "'", MAC2STR(dest_mac));
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
            em_printfout("Invalid Encap DPP fields, discarding message. DPP Frame Indicator=%d, DPP frame type=%d", encap_tlv->dpp_frame_indicator, ec_frame_type);
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
            bool sent = m_send_action_frame(dest_mac, encap_frame, encap_frame_len, 0, 0);
            if (!sent) {
                em_printfout("Failed to send non-DPP unicast action frame to '" MACSTRFMT "'", MAC2STR(dest_mac));
            }
            free(encap_frame);
            return sent;
        }
        // 2. If the DPP Frame Indicator bit field in the 1905 Encap DPP TLV is set to zero and the Enrollee MAC Address Present
        // bit is set to zero, then the Proxy Agent shall send the frame as a broadcast Public Action frame
        else if (!encap_tlv->dpp_frame_indicator && !encap_tlv->enrollee_mac_addr_present) {
            bool sent = m_send_action_frame(const_cast<uint8_t *>(BROADCAST_MAC_ADDR), encap_frame, encap_frame_len, 0, 0);
            if (!sent) {
                em_printfout("Failed to sent non-DPP broadcast action frame!");
            }
            free(encap_frame);
            return sent;
        }
        // 3. If the DPP Frame Indicator bit field in the 1905 Encap DPP TLV is set to one and the Enrollee MAC Address Present
        // bit is set to one, then the Proxy Agent shall send the frame as a unicast GAS frame to the Enrollee MAC address
        else if (encap_tlv->dpp_frame_indicator && encap_tlv->enrollee_mac_addr_present) {
            bool sent = m_send_action_frame(dest_mac, encap_frame, encap_frame_len, 0, 0);
            if (!sent) {
                em_printfout("Sent DPP unicast GAS frame to '" MACSTRFMT "'", MAC2STR(dest_mac));
            }
            free(encap_frame);
            return sent;
        }
        // 4. If the DPP Frame Indicator bit field in the 1905 Encap DPP TLV is set to one and the Enrollee MAC Address Present
        // bit is set to zero, then the Proxy Agent shall discard the message
        else if (encap_tlv->dpp_frame_indicator && !encap_tlv->enrollee_mac_addr_present) {
            em_printfout("Proxied Encap DPP Message with DPP Frame Indicator set, but Enrollee MAC Addr Present false! Discarding.");
            free(encap_frame);
            return true;
        }
    }

    // Handlers for frame types 0, 15 "ec_frame_type_auth_req" and "ec_frame_type_recfg_auth_req"
    switch (ec_frame_type) {
        case ec_frame_type_auth_req: {
            if (chirp_tlv == NULL || chirp_tlv_len == 0) {
                em_printfout("Chirp TLV is empty");
                break;
            }
            mac_addr_t chirp_mac = {0};
            uint8_t* chirp_hash = NULL;
            uint16_t chirp_hash_len = 0;
            if (!ec_util::parse_dpp_chirp_tlv(chirp_tlv, chirp_tlv_len, &chirp_mac, &chirp_hash, &chirp_hash_len)) {
                em_printfout("Failed to parse DPP Chirp TLV");
                break;
            }
            std::string chirp_hash_str = em_crypto_t::hash_to_hex_string(chirp_hash, chirp_hash_len);
            em_printfout("Chirp TLV Hash: %s", chirp_hash_str.c_str());

            free(chirp_hash);
            
            // Store the encap frame keyed by the chirp hash in the map
            std::vector<uint8_t> encap_frame_vec(encap_frame, encap_frame + encap_frame_len);
            m_chirp_hash_frame_map[chirp_hash_str] = encap_frame_vec;
            did_finish = true;
            break;
        }
        case ec_frame_type_recfg_auth_req: {
            ec_frame_t *frame = reinterpret_cast<ec_frame_t*>(encap_frame);
            auto c_sign_key_hash_attr = ec_util::get_attrib(frame->attributes, static_cast<uint16_t>(encap_frame_len - EC_FRAME_BASE_SIZE), ec_attrib_id_C_sign_key_hash);
            if (!c_sign_key_hash_attr.has_value()) {
                em_printfout("No C-sign key hash attribute found in DPP Reconfiguration Authentication Request frame");
                free(encap_frame);
                return false;
            }
            std::vector<uint8_t> encap_frame_vec(encap_frame, encap_frame + encap_frame_len);
            const std::string c_sign_key_hash_str = em_crypto_t::hash_to_hex_string(c_sign_key_hash_attr->data, c_sign_key_hash_attr->length);
            m_stored_recfg_auth_frames_map[c_sign_key_hash_str] = encap_frame_vec;
            did_finish = true;
            break;
        }
        default:
            em_printfout("Encap DPP frame type (%d) not handled", ec_frame_type);
            break;
    }
    // Parse out dest STA mac address and hash value then validate against the hash in the 
    // ec_session dpp uri info public key. 
    // Then construct an Auth request frame and send back in an Encap message

    free(encap_frame);
    return did_finish;
}



bool ec_pa_configurator_t::process_direct_encap_dpp_msg(uint8_t* dpp_frame, uint16_t dpp_frame_len)
{
    if (dpp_frame == NULL || dpp_frame_len == 0) {
        em_printfout("DPP Message Frame is empty");
        return false;
    }

    ec_frame_t* ec_frame = reinterpret_cast<ec_frame_t*>(dpp_frame);

    ec_frame_type_t ec_frame_type = static_cast<ec_frame_type_t>(ec_frame->frame_type);

    bool did_finish = false;

    // TODO: I am VERY explicitly commenting out the buisness logic for the other frame types here,
    // because the dpp frame given here is just a buffer, not any other info so more stuff has to be worked out with config.
/*
    std::string dest_mac_str = util::mac_to_string(dest_mac);

    bool needs_fragmentation = (encap_frame_len > WIFI_MTU_SIZE);
    if (needs_fragmentation) {
        auto it = m_gas_session_dialog_tokens.find(dest_mac_str);
        if (it == m_gas_session_dialog_tokens.end()) {
            em_printfout("No GAS session dialog token found for '" MACSTRFMT "', not sending 802.11 frame.", MAC2STR(dest_mac));
            return false;
        }
        uint8_t dialog_token = it->second;
        // If peer is not ready to receive GAS Comeback Frames, we must first send a "dummy" GAS Initial Response frame inidicating to the 
        // peer that GAS Comeback Response frames will be coming.
        // Fragment the frame and store the fragments and wait for a GAS Comeback Request prior to sending.
        em_printfout("Sending fragmentation prepare GAS Initial Response frame to '" MACSTRFMT "'", MAC2STR(dest_mac));
        m_gas_frames_to_be_sent[dest_mac_str] = fragment_large_frame(encap_frame, encap_frame_len, dialog_token);
        return send_prepare_for_fragmented_frames_frame(dest_mac);
    }

    // Pre-processing according to EM spec 5.4.3 Page 43
    // If a Proxy Agent receives a Proxied Encap DPP message from the Multi-AP Controller, it shall extract the DPP frame from
    // the Encapsulated Frame field of the 1905 Encap DPP TLV and:

    // 1. If the 1905 Encap DPP TLV DPP Frame Indicator bit field is set to one and the Frame Type field is set to 255, the
    // Proxy Agent shall decapsulate the DPP Configuration Response frame from the TLV and send it to the Enrollee Multi-
    // AP Agent using a GAS frame as described in [18]
    if (encap_tlv->dpp_frame_indicator && ec_frame_type == ec_frame_type_t::ec_frame_type_easymesh) {
        if (!encap_tlv->enrollee_mac_addr_present) {
            em_printfout("Cannot forward DPP Configuration Result to Enrollee, MAC addr not present!");
            return false;
        }
        bool sent = m_send_action_frame(dest_mac, encap_frame, encap_frame_len, 0, 0);
        if (!sent) {
            em_printfout("Failed to forward DPP Configuration Result to Enrollee '" MACSTRFMT "'", MAC2STR(dest_mac));
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
            em_printfout("Invalid Encap DPP fields, discarding message. DPP Frame Indicator=%d, DPP frame type=%d", encap_tlv->dpp_frame_indicator, ec_frame_type);
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
            bool sent = m_send_action_frame(dest_mac, encap_frame, encap_frame_len, 0, 0);
            if (!sent) {
                em_printfout("Failed to send non-DPP unicast action frame to '" MACSTRFMT "'", MAC2STR(dest_mac));
            }
            free(encap_frame);
            return sent;
        }
        // 2. If the DPP Frame Indicator bit field in the 1905 Encap DPP TLV is set to zero and the Enrollee MAC Address Present
        // bit is set to zero, then the Proxy Agent shall send the frame as a broadcast Public Action frame
        else if (!encap_tlv->dpp_frame_indicator && !encap_tlv->enrollee_mac_addr_present) {
            bool sent = m_send_action_frame(const_cast<uint8_t *>(BROADCAST_MAC_ADDR), encap_frame, encap_frame_len, 0, 0);
            if (!sent) {
                em_printfout("Failed to sent non-DPP broadcast action frame!");
            }
            free(encap_frame);
            return sent;
        }
        // 3. If the DPP Frame Indicator bit field in the 1905 Encap DPP TLV is set to one and the Enrollee MAC Address Present
        // bit is set to one, then the Proxy Agent shall send the frame as a unicast GAS frame to the Enrollee MAC address
        else if (encap_tlv->dpp_frame_indicator && encap_tlv->enrollee_mac_addr_present) {
            bool sent = m_send_action_frame(dest_mac, encap_frame, encap_frame_len, 0, 0);
            if (!sent) {
                em_printfout("Sent DPP unicast GAS frame to '" MACSTRFMT "'", MAC2STR(dest_mac));
            }
            free(encap_frame);
            return sent;
        }
        // 4. If the DPP Frame Indicator bit field in the 1905 Encap DPP TLV is set to one and the Enrollee MAC Address Present
        // bit is set to zero, then the Proxy Agent shall discard the message
        else if (encap_tlv->dpp_frame_indicator && !encap_tlv->enrollee_mac_addr_present) {
            em_printfout("Proxied Encap DPP Message with DPP Frame Indicator set, but Enrollee MAC Addr Present false! Discarding.");
            free(encap_frame);
            return true;
        }
    }

    // Handlers for frame types 0, 15 "ec_frame_type_auth_req" and "ec_frame_type_recfg_auth_req"
*/
    switch (ec_frame_type) {
        case ec_frame_type_auth_req: {
            /*
            if (chirp_tlv == NULL || chirp_tlv_len == 0) {
                em_printfout("Chirp TLV is empty");
                break;
            }
            mac_addr_t chirp_mac = {0};
            uint8_t* chirp_hash = NULL;
            uint16_t chirp_hash_len = 0;
            if (!ec_util::parse_dpp_chirp_tlv(chirp_tlv, chirp_tlv_len, &chirp_mac, &chirp_hash, &chirp_hash_len)) {
                em_printfout("Failed to parse DPP Chirp TLV");
                break;
            }
            std::string chirp_hash_str = em_crypto_t::hash_to_hex_string(chirp_hash, chirp_hash_len);
            em_printfout("Chirp TLV Hash: %s", chirp_hash_str.c_str());

            free(chirp_hash);
            
            // Store the encap frame keyed by the chirp hash in the map
            std::vector<uint8_t> encap_frame_vec(encap_frame, encap_frame + encap_frame_len);
            m_chirp_hash_frame_map[chirp_hash_str] = encap_frame_vec;
            did_finish = true;
            */
            break;
        }
        case ec_frame_type_recfg_auth_req: {
            /*
            ec_frame_t *frame = reinterpret_cast<ec_frame_t*>(encap_frame);
            auto c_sign_key_hash_attr = ec_util::get_attrib(frame->attributes, static_cast<uint16_t>(encap_frame_len - EC_FRAME_BASE_SIZE), ec_attrib_id_C_sign_key_hash);
            if (!c_sign_key_hash_attr.has_value()) {
                em_printfout("No C-sign key hash attribute found in DPP Reconfiguration Authentication Request frame");
                free(encap_frame);
                return false;
            }
            std::vector<uint8_t> encap_frame_vec(encap_frame, encap_frame + encap_frame_len);
            const std::string c_sign_key_hash_str = em_crypto_t::hash_to_hex_string(c_sign_key_hash_attr->data, c_sign_key_hash_attr->length);
            m_stored_recfg_auth_frames_map[c_sign_key_hash_str] = encap_frame_vec;
            did_finish = true;
            */
            break;
        }
        case ec_frame_type_peer_disc_rsp: {
            break;
        }
        default:
            em_printfout("Encap DPP frame type (%d) not handled", ec_frame_type);
            break;
    }
    return did_finish;
}

bool ec_pa_configurator_t::handle_gas_comeback_request([[maybe_unused]] uint8_t *buff, [[maybe_unused]] unsigned int len, uint8_t sa[ETH_ALEN])
{
    em_printfout("Received a GAS Comeback Request frame from '" MACSTRFMT "'", MAC2STR(sa));
    auto frame_it = m_gas_frames_to_be_sent.find(util::mac_to_string(sa));
    if (frame_it == m_gas_frames_to_be_sent.end()) {
        // Nothing to do
        em_printfout("Received potentially spurious GAS Comeback Request frame from '" MACSTRFMT "', not doing anything with it", MAC2STR(sa));
        return true;
    }

    // Ensure we already have a GAS session with this peer
    auto dialog_it = m_gas_session_dialog_tokens.find(util::mac_to_string(sa));
    if (dialog_it == m_gas_session_dialog_tokens.end()) {
        em_printfout("Received GAS Comeback Request from '" MACSTRFMT "', we have a frame waiting for them, but no dialog token known!", MAC2STR(sa));
        return false;
    }

    // Get the fragments to send
    std::vector<ec_gas_comeback_response_frame_t*>& fragments = frame_it->second;

    if (fragments.empty()) {
        em_printfout("Received GAS Comeback Request, but we have no more fragments to send to '" MACSTRFMT "'", MAC2STR(sa));
        return false;
    }

    // This code assumes that m_gas_frames_to_be_sent stores fragments with linearly increasing frag ID
    // Grab 0th, send it, delete it
    ec_gas_comeback_response_frame_t *fragment = fragments.front();
    fragments.erase(fragments.begin());

    bool sent = m_send_action_frame(sa, reinterpret_cast<uint8_t*>(fragment), sizeof(ec_gas_comeback_response_frame_t) + fragment->comeback_resp_len, 0, 0);
    
    if (!sent) {
        em_printfout("Failed to send fragment #%d to '" MACSTRFMT "'", fragment->fragment_id, MAC2STR(sa));
        free(fragment);
        return false;
    }

    em_printfout("Sent fragment #%d (more frags = %d) to '" MACSTRFMT "'", fragment->fragment_id, fragment->more_fragments, MAC2STR(sa));
    free(fragment);
    return sent;
}

bool ec_pa_configurator_t::send_prepare_for_fragmented_frames_frame(uint8_t dest_mac[ETH_ALEN])
{
    auto it = m_gas_session_dialog_tokens.find(util::mac_to_string(dest_mac));
    if (it == m_gas_session_dialog_tokens.end()) {
        em_printfout("No GAS session dialog token found for '" MACSTRFMT "', cannot send fragmentation indication message to peer!",  MAC2STR(dest_mac));
        return false;
    }
    uint8_t dialog_token = it->second;

    // Inform GAS peer that we're going to be sending them a fragmented frame via the 
    // GAS Comeback mechanism by first sending a GAS Initial Response with resp_len = 0  and / or delay > 0
    auto [gas_initial_resp_frame, gas_initial_resp_frame_len] = ec_util::alloc_gas_frame(dpp_gas_initial_resp, dialog_token);
    if (gas_initial_resp_frame == nullptr) {
        em_printfout("Could not allocate GAS Initial Response frame");
        return false;
    }
    ec_gas_initial_response_frame_t *frame = reinterpret_cast<ec_gas_initial_response_frame_t*>(gas_initial_resp_frame);
    frame->resp_len = 0;
    frame->gas_comeback_delay = 1;
    em_printfout("Sending GAS Comeback Response preparation GAS Initial Response frame to '" MACSTRFMT "'", MAC2STR(dest_mac));
    return m_send_action_frame(dest_mac, reinterpret_cast<uint8_t*>(frame), gas_initial_resp_frame_len, 0, 0);
}

std::vector<ec_gas_comeback_response_frame_t *> ec_pa_configurator_t::fragment_large_frame(const uint8_t *payload, size_t len, uint8_t dialog_token)
{
    // Fragments will be stored by increasing frag ID
    std::vector<ec_gas_comeback_response_frame_t *> fragments;
    size_t offset = 0;
    uint8_t frag_id = 0;

    while (offset < len) {
        size_t chunk_size = std::min(WIFI_MTU_SIZE, len - offset);

        auto [base_frame, base_len] = ec_util::alloc_gas_frame(dpp_gas_comeback_resp, dialog_token);
        if (!base_frame) {
            em_printfout("Failed to allocate GAS Comeback Response frame for frag #%d", frag_id);
            for (auto *f : fragments) {
                free(f);
            }
            return {};
        }

        ec_gas_comeback_response_frame_t *frame = static_cast<ec_gas_comeback_response_frame_t *>(base_frame);
        frame->comeback_resp_len = static_cast<uint16_t>(chunk_size);

        frame->fragment_id = frag_id;
        frame->more_fragments = ((offset + chunk_size) < len) ? 1 : 0;

        em_printfout("Copying data into fragment #%d:\n", frag_id);
        util::print_hex_dump(static_cast<unsigned int>(chunk_size), const_cast<uint8_t*>(payload + offset));
        // Copy the actual chunk of the payload into the frame
        frame = ec_util::copy_payload_to_gas_resp(frame, const_cast<uint8_t *>(payload + offset), chunk_size);
        if (!frame) {
            em_printfout("Failed to copy payload into Comeback Response frame for frag #%d", frag_id);
            for (auto *f : fragments) {
                free(f);
            }
            return {};
        }
        fragments.push_back(frame);


        offset += chunk_size;
        frag_id++;
    }

    return fragments;
}
