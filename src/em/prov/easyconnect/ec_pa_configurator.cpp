#include "ec_pa_configurator.h"

#include "ec_util.h"
#include "util.h"

bool ec_pa_configurator_t::handle_presence_announcement(ec_frame_t *frame, size_t len, uint8_t src_mac[ETHER_ADDR_LEN])
{
    size_t attrs_len = len - EC_FRAME_BASE_SIZE;

    ec_attribute_t *B_r_hash_attr = ec_util::get_attrib(frame->attributes, static_cast<uint16_t> (attrs_len), ec_attrib_id_resp_bootstrap_key_hash);
    ASSERT_NOT_NULL(B_r_hash_attr, false, "%s:%d No responder bootstrapping key hash attribute found\n", __func__, __LINE__);
    std::string B_r_hash_str = ec_util::hash_to_hex_string(B_r_hash_attr->data, B_r_hash_attr->length);

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
    em_printfout("Rx'd a DPP Configuration Request from " MACSTRFMT "", MAC2STR(sa));
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
            std::string chirp_hash_str = ec_util::hash_to_hex_string(chirp_hash, chirp_hash_len);
            em_printfout("Chirp TLV Hash: %s", chirp_hash_str.c_str());

            free(chirp_hash);
            
            // Store the encap frame keyed by the chirp hash in the map
            std::vector<uint8_t> encap_frame_vec(encap_frame, encap_frame + encap_frame_len);
            m_chirp_hash_frame_map[chirp_hash_str] = encap_frame_vec;
            did_finish = true;
            break;
        }
        case ec_frame_type_recfg_auth_req: {
            em_printfout("Encap DPP frame type (%d) not handled", ec_frame_type);
            std::vector<uint8_t> encap_frame_vec(encap_frame, encap_frame + encap_frame_len);
            // Will be compared against incoming presence announcement hash and mac-addr
            m_stored_recfg_auth_frames.push_back(encap_frame_vec); 
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
