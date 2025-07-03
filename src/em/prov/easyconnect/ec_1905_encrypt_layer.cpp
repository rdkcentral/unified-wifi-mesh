#include "ec_1905_encrypt_layer.h"

#include "util.h"
#include "ec_crypto.h"
#include "ec_util.h"

ec_1905_encrypt_layer_t::ec_1905_encrypt_layer_t(std::string local_al_mac, 
                                                 send_dir_encap_dpp_func send_direct_encap_dpp_msg, 
                                                 send_1905_eapol_encap_func send_1905_eapol_encap_msg) : 
                                                 m_send_dir_encap_dpp_msg(send_direct_encap_dpp_msg), 
                                                 m_send_1905_eapol_encap_msg(send_1905_eapol_encap_msg) {
        
    m_al_mac_addr = util::macstr_to_vector(local_al_mac);
    if (m_al_mac_addr.empty()) {
        em_printfout("Invalid AL MAC address format: %s", local_al_mac.c_str());
        throw std::invalid_argument("Invalid AL MAC address format");
    }
}

bool ec_1905_encrypt_layer_t::handle_peer_disc_req_frame(ec_frame_t *frame, uint16_t len, uint8_t src_mac[ETH_ALEN])
{
    em_printfout("Enter");
    
    EM_ASSERT_NOT_NULL(m_C_signing_key, false, "C-signing key is not set, cannot handle Peer Discovery Request frame");
    EM_ASSERT_NOT_NULL(m_net_access_key, false, "Net Access key is not set, cannot handle Peer Discovery Request frame");
    EM_ASSERT_MSG_FALSE(m_connector_1905.empty(), false, "Connector 1905 is not set, cannot handle Peer Discovery Request frame");
    EM_ASSERT_NOT_NULL(src_mac, false, "Source MAC address is null in Peer Discovery Request frame");
    EM_ASSERT_NOT_NULL(frame, false, "Peer Discovery Request frame is null");
    
    size_t attrs_len = len - EC_FRAME_BASE_SIZE;

    auto trans_id_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_trans_id);
    EM_ASSERT_OPT_HAS_VALUE(trans_id_attr, false, "No Transaction ID attribute found in Peer Discovery Request frame");

    uint8_t trans_id = trans_id_attr->data[0];

    auto recv_1905_connector_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_dpp_connector);
    EM_ASSERT_OPT_HAS_VALUE(recv_1905_connector_attr, false, "No DPP Connector attribute found in Peer Discovery Request frame");

    std::string recv_1905_connector_str(reinterpret_cast<const char *>(recv_1905_connector_attr->data), static_cast<size_t>(recv_1905_connector_attr->length));

    // Conditional
    auto version_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_proto_version);

    /* EasyConnect 6.6.2
    If device A finds any problem in the received Connector, for example:
        • A syntax error in the received Connector such as a misspelled field name
        • A wrong or missing value in the received Connector such as a missing kid field, erroneous NAK expiry value
        • An expired NAK in the Connector
        • A failing signature verification if device A possesses the matching C-sign-key
    it sends a DPP Peer Discovery Response frame with DPP Status field set to STATUS_INVALID_CONNECTOR and the
    received Transaction ID:
    */

    auto send_peer_disc_response = [&](ec_status_code_t status) {
        auto [resp_frame, resp_len] = create_peer_disc_resp(src_mac, status, trans_id);
        bool sent = m_send_dir_encap_dpp_msg(resp_frame, resp_len, src_mac);
        free(resp_frame);
        return sent;
    };

    if (m_C_signing_key == nullptr) {
        /*
        If device A did not find any problem in the received Connector, and does not possess the matching C-sign-key for checking
        its signature, it sends a DPP Peer Discovery Response frame with DPP Status field set to STATUS_NO_MATCH and the
        received Transaction ID:
        */
        // Since the last bullet point of EasyConnect 6.6.2 says " A failing signature verification if device A possesses the matching C-sign-key",
        // we can assume that if we don't have the C-signing key, we cannot verify the signature, and thus we should return STATUS_NO_MATCH before
        // attempting earlier validations.
        em_printfout("No C-signing key available, cannot verify Enrollee 1905 Connector signature");
        return send_peer_disc_response(DPP_STATUS_NO_MATCH);
    }

    // Checks JSON decoding and signature verification
    auto conn_parts = ec_crypto::split_decode_connector(recv_1905_connector_str.c_str(), m_C_signing_key);
    if (!conn_parts.has_value()) {
        em_printfout("Failed to decode E-1905 Connector or verify signature");
        return send_peer_disc_response(DPP_STATUS_INVALID_CONNECTOR);
    }

    auto [header, payload, sig] = *conn_parts;
    (void)sig;

    if (!ec_crypto::validate_jws_header(header, "dppConn")) {
        em_printfout("Invalid JWS header in Enrollee 1905 Connector");
        return send_peer_disc_response(DPP_STATUS_INVALID_CONNECTOR);
    }
    // Don't check isExpired since we need to do so later with a different error code
    if (!ec_crypto::validate_jws_payload(payload, false)) {
        em_printfout("Invalid JWS payload in Enrollee 1905 Connector");
        return send_peer_disc_response(DPP_STATUS_INVALID_CONNECTOR);
    }

    /*
    If device A has not been permitted to establish a link to this device, or
    if device B’s netAccessKey, PK, in all matching Connectors has expired, or 
    if the version member in Connector B has value 3 or higher and the Protocol Version field is not present or
    (it) has a different value than the one in the version member in Connector B ,
    
    it sends a DPP Peer Discovery Response frame with DPP Status field set to STATUS_NO_MATCH and the received Transaction ID:
    
    */
    cJSON *version = cJSON_GetObjectItem(payload, "version");
    if (version != nullptr && cJSON_IsNumber(version) && version->valueint >= 3) {
        /*
        if the version member in Connector B has value 3 or higher and the Protocol Version field is not present or
        has a different value than the one in the version member in Connector B ,
        */
        if (!version_attr.has_value()){
            return send_peer_disc_response(DPP_STATUS_NO_MATCH);
        }
        if (version->valueint != static_cast<int>(version_attr->data[0])) {
            em_printfout("Mismatched Protocol Version in Peer Discovery Request frame, expected %d, got %d", version->valueint, static_cast<int>(version_attr->data[0]));
            return send_peer_disc_response(DPP_STATUS_NO_MATCH);
        }
    }

    // Check that it hasn't expired
    cJSON *expiry = cJSON_GetObjectItem(payload, "expiry");
    if (expiry != NULL) {
        struct tm tm = {};
        // Validated in ec_crypto::validate_jws_payload
        strptime(expiry->valuestring, "%Y-%m-%dT%H:%M:%S%z", &tm);
        time_t expiry_time = mktime(&tm);
        if (expiry_time < time(NULL)) {
            em_printfout("JWS payload has expired");
            return send_peer_disc_response(DPP_STATUS_NO_MATCH);
        }
    }

    // NOTE: We are now permitted to perform key establishment with this agent

    /*
    EasyConnect 7.5.4
    Upon receipt of a DPP Peer Discovery Request frame, any receiving Peer shall perform the following actions:
    ...
    Derives a PMK and PMKID by using its private key and the new Peer’s public key.
    */

    auto [pmk, pmkid] = compute_pmk_pmkid(payload);
    if (pmk.empty() || pmkid.empty()) {
        em_printfout("Failed to compute PMK or PMKID from Recieved 1905 Connector");
        return false;
    }

    std::string src_mac_str = util::mac_to_string(src_mac);

    ec_1905_key_ctx ctx;
    memset(&ctx, 0, sizeof(ec_1905_key_ctx));
    memcpy(ctx.pmk, pmk.data(), pmk.size());
    memcpy(ctx.pmkid, pmkid.data(), pmkid.size());
    memset(this->m_gtk, 0, sizeof(this->m_gtk)); // Not set yet, will be set later in the 4-way handshake

    if (!m_gmk.empty() && memcmp(m_gtk, empty_nonce, SHA256_DIGEST_LENGTH) == 0) {
        em_printfout("Controller has GMK and hasn't generated a GTK yet, deriving GTK");
        if (!compute_gtk(m_hash_fn, m_al_mac_addr.data())){
            em_printfout("Failed to derive GTK");
            return false;
        }
    }
    
    if (m_1905_mac_key_mac.find(src_mac_str) != m_1905_mac_key_mac.end()) {
        em_printfout("Key context for '%s' already exists, overwriting", src_mac_str.c_str());
    }

    m_1905_mac_key_mac[src_mac_str] = ctx;

    /* EasyMesh 5.3.7.1

    If a Multi-AP Device receives a DPP Peer Discovery Request frame from an Enrollee Multi-AP Agent, an already enrolled
    Multi-AP Agent or a Multi-AP Controller, it shall process it according to section 6.6 of [18]. After successfully deriving 
    the 1905 PMK, the Multi-AP Device which sent the 1905 DPP Peer Discovery Response shall initiate a 1905 4-way handshake 
    to derive a new 1905 PTK with the Multi-AP Agent.
    */
    if (!send_peer_disc_response(DPP_STATUS_OK)) {
        em_printfout("Failed to send Peer Discovery Response frame to Agent '%s'", src_mac_str.c_str());
        return false;
    }

    if (!begin_1905_4way_handshake(src_mac, false)) {
        em_printfout("Failed to begin 1905 4-way handshake with Agent '%s'", src_mac_str.c_str());
        return false;
    }

    return true;
}

bool ec_1905_encrypt_layer_t::handle_peer_disc_resp_frame(ec_frame_t *frame, uint16_t len, uint8_t src_mac[ETH_ALEN]) {
    em_printfout("Enter");

    EM_ASSERT_NOT_NULL(m_C_signing_key, false, "C-signing key is not set, cannot handle Peer Discovery Response frame");
    EM_ASSERT_MSG_FALSE(m_connector_1905.empty(), false, "Connector 1905 is not set, cannot handle Peer Discovery Response frame");
    EM_ASSERT_NOT_NULL(src_mac, false, "Source MAC address is null in Peer Discovery Response frame");
    EM_ASSERT_NOT_NULL(frame, false, "Peer Discovery Response frame is null");

    std::string src_mac_str = util::mac_to_string(src_mac);

    size_t attrs_len = len - EC_FRAME_BASE_SIZE;

    auto status_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_dpp_status);
    EM_ASSERT_OPT_HAS_VALUE(status_attr, false, "No Status attribute found in Peer Discovery Request frame");

    ec_status_code_t dpp_status = static_cast<ec_status_code_t>(status_attr->data[0]);

    auto trans_id_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_trans_id);
    EM_ASSERT_OPT_HAS_VALUE(trans_id_attr, false, "No Transaction ID attribute found in Peer Discovery Request frame");

    uint8_t trans_id = trans_id_attr->data[0];

    // EasyConnect 6.6.2 (end of section)
    switch (dpp_status) {
        case DPP_STATUS_NO_MATCH:
            em_printfout("Peer Discovery Failed (NO_MATCH)! There is a configuration problem in device B (Self)");
            return false;
        case DPP_STATUS_INVALID_CONNECTOR:
            em_printfout("Peer Discovery Failed (INVALID_CONNECTOR)! There is a configuration problem in device A (Peer)");
            return false;
        case DPP_STATUS_OK:
            break;
        default:
            em_printfout("Peer Discovery Failed with unknown status code %d", dpp_status);
            // Drop frame
            return false;
    }

    if (trans_id != m_transaction_id) {
        em_printfout("Transaction ID in Peer Discovery Response frame (%d) does not match expected Transaction ID (%d) for Agent '%s'", 
            trans_id, m_transaction_id, src_mac_str.c_str());
        // Drop frame
        return false;
    }

    auto connector_attr_1905 = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_dpp_connector);
    EM_ASSERT_OPT_HAS_VALUE(connector_attr_1905, false, "No DPP Connector attribute found in Peer Discovery Request frame");

    std::string connector_1905_str(reinterpret_cast<const char *>(connector_attr_1905->data), static_cast<size_t>(connector_attr_1905->length));

    auto parts = ec_crypto::split_decode_connector(connector_1905_str.c_str(), m_C_signing_key);
    EM_ASSERT_OPT_HAS_VALUE(parts, false, "Failed to decoderecieved 1905 Connector or verify signature");

    auto [header, payload, sig] = *parts;
    (void)sig;

    if (!ec_crypto::validate_jws_header(header, "dppConn")){
        em_printfout("Invalid JWS header in recieved 1905 Connector");
        return false;
    }
    if (!ec_crypto::validate_jws_payload(payload)) {
        em_printfout("Invalid JWS payload in recieved 1905 Connector");
        return false;
    }

    // Conditional
    auto version_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_proto_version);

    cJSON *version = cJSON_GetObjectItem(payload, "version");
    if (version != nullptr && cJSON_IsNumber(version) && version->valueint >= 3) {
        /*
        if the version member in Connector B has value 3 or higher and the Protocol Version field is not present or
        has a different value than the one in the version member in Connector B ,
        */
        if (!version_attr.has_value()) return false;
        if (version->valueint != static_cast<int>(version_attr->data[0])) {
            em_printfout("Mismatched Protocol Version in Peer Discovery Request frame, expected %d, got %d", version->valueint, static_cast<int>(version_attr->data[0]));
            return false;
        }
    }

    // NOTE: Ready to perform key establishment with this agent
    em_printfout("Peer Discovery successful with Agent '%s', proceeding to secure 1905 layer", src_mac_str.c_str());

    /*
    EasyConnect 7.5.4
    Upon receipt of a DPP Peer Discovery Response frame, ... 
    At this point, each Peer derives the PMK and PMKID using its private key 
    and the other Peer’s public key from the Connector.
    */
    auto [pmk, pmkid] = compute_pmk_pmkid(payload);
    if (pmk.empty() || pmkid.empty()) {
        em_printfout("Failed to compute PMK or PMKID from Recieved 1905 Connector");
        return false;
    }

    ec_1905_key_ctx ctx;
    memset(&ctx, 0, sizeof(ctx)); // Initialize the context to zero
    memcpy(ctx.pmk, pmk.data(), pmk.size());
    memcpy(ctx.pmkid, pmkid.data(), pmkid.size());
    
    if (m_1905_mac_key_mac.find(src_mac_str) != m_1905_mac_key_mac.end()) {
        em_printfout("Key context for '%s' already exists, overwriting", src_mac_str.c_str());
    }

    m_1905_mac_key_mac[src_mac_str] = ctx;

    return true;
}

bool ec_1905_encrypt_layer_t::handle_eapol_frame(uint8_t *frame, uint16_t len, uint8_t src_mac[ETH_ALEN]) {
    if (!frame || len == 0) {
        em_printfout("Invalid EAPOL frame or length.");
        return false;
    }
    EM_ASSERT_NOT_NULL(src_mac, false, "Source MAC address is null in EAPOL frame");

    std::string src_mac_str = util::mac_to_string(src_mac);

    em_printfout("Handling EAPOL frame from '%s'", src_mac_str.c_str());

    bool key_ctx_exists = m_1905_mac_key_mac.find(src_mac_str) != m_1905_mac_key_mac.end();
    if (!key_ctx_exists) {
        // We don't have an existing key context, this means that we just recieved/sent our first frame and are therefore
        // the peer who is doing the second frame of the 4-way handshake.
        em_printfout("No existing key context for '%s', assuming this first EAPOL frame in the 4-way handshake", src_mac_str.c_str());
        ec_1905_key_ctx ctx;
        memset(&ctx, 0, sizeof(ec_1905_key_ctx));
        m_1905_mac_key_mac[src_mac_str] = ctx;
    }

    ec_1905_key_ctx& ctx = m_1905_mac_key_mac[src_mac_str];

    eapol_packet_t *eapol_packet = validate_eapol_frame(ctx, frame, len);
    EM_ASSERT_NOT_NULL(eapol_packet, false, "Invalid EAPOL frame received");

    bool is_group = (eapol_packet->key_info.bits.key_type == 0);

    if (is_group) {
        bool ret = false;
        if (ctx.sent_eapol_idx == 0) {
            // Empty context, recieved first frame of group key handshake
            em_printfout("Received frame 1/2 of group key handshake from '%s'", src_mac_str.c_str());
            ret = handle_group_eapol_frame_1(ctx, frame, len, src_mac);
        } else if (ctx.sent_eapol_idx == 1) {
            // Existing context, already sent first frame of group key handshake
            // Assuming we just recieved the second frame of the group key handshake
            em_printfout("Received frame 2/2 of group key handshake from '%s'", src_mac_str.c_str());
            ret = handle_group_eapol_frame_2(ctx, frame, len, src_mac);
        } else {
            em_printfout("Received EAPOL frame with unexpected sent EAPOL index %d for group key handshake with '%s', ignoring", 
                ctx.sent_eapol_idx, src_mac_str.c_str());
        }

        free(eapol_packet);
        return ret;
    }

    // If we are here, we are handling a pairwise key handshake (4-way handshake)
    bool ret = false;
    if (ctx.sent_eapol_idx == 0) {
        // Empty context, recieved first frame of the 4-way handshake
        em_printfout("Received frame 1/4 of 4-way handshake from '%s'", src_mac_str.c_str());
        ret = handle_pw_eapol_frame_1(ctx, frame, len, src_mac);
    }  else if (ctx.sent_eapol_idx == 1) {
        // Existing context, already sent first frame of the 4-way handshake
        // Assuming we just recieved the second frame of the 4-way handshake
        em_printfout("Received frame 2/4 of 4-way handshake from '%s'", src_mac_str.c_str());
        ret = handle_pw_eapol_frame_2(ctx, frame, len, src_mac);
    } else if (ctx.sent_eapol_idx == 2) {
        // Existing context, already sent second frame of the 4-way handshake
        // Assuming we just recieved the third frame of the 4-way handshake
        em_printfout("Received frame 3/4 of 4-way handshake from '%s'", src_mac_str.c_str());
        ret = handle_pw_eapol_frame_3(ctx, frame, len, src_mac);
    } else if (ctx.sent_eapol_idx == 3) {
        // Existing context, already sent third frame of the 4-way handshake
        // Assuming we just recieved the fourth frame of the 4-way handshake
        em_printfout("Received frame 4/4 of 4-way handshake from '%s'", src_mac_str.c_str());
        ret = handle_pw_eapol_frame_4(ctx, frame, len, src_mac);
    } else {
        em_printfout("Received EAPOL frame with unexpected sent EAPOL index %d for 4-way handshake with '%s', ignoring", 
                    ctx.sent_eapol_idx, src_mac_str.c_str());
    }

    free(eapol_packet);
    return ret;

}

bool ec_1905_encrypt_layer_t::start_secure_1905_layer(uint8_t dest_al_mac[ETH_ALEN]) {
    EM_ASSERT_NOT_NULL(dest_al_mac, false, "Destination AL MAC address is null.");
    EM_ASSERT_NOT_NULL(m_C_signing_key, false, "C-signing key is not set, cannot start 1905 layer security");
    EM_ASSERT_MSG_FALSE(m_connector_1905.empty(), false, "Connector 1905 is not set, cannot start 1905 layer security");

    em_printfout("Starting to secure 1905 layer for '" MACSTRFMT "'", MAC2STR(dest_al_mac));


    auto [disc_req_frame, disc_req_len] = create_peer_disc_req(dest_al_mac);
    if (disc_req_frame == NULL || disc_req_len == 0){
        em_printfout("Could not secure 1905 layer, failed to create peer discovery request");
        return false;
    }

    return m_send_dir_encap_dpp_msg(disc_req_frame, disc_req_len, dest_al_mac);
}

bool ec_1905_encrypt_layer_t::rekey_1905_layer_ptk(uint8_t dest_al_mac[ETH_ALEN])
{
    EM_ASSERT_NOT_NULL(m_C_signing_key, false, "C-signing key is not set, cannot rekey 1905 layer PTK");
    EM_ASSERT_MSG_FALSE(m_connector_1905.empty(), false, "Connector 1905 is not set, cannot rekey 1905 layer PTK");
    EM_ASSERT_NOT_NULL(dest_al_mac, false, "Destination AL MAC address is null.");

    std::string dest_mac_str = util::mac_to_string(dest_al_mac);
    EM_ASSERT_MSG_FALSE(m_1905_mac_key_mac.find(dest_mac_str) != m_1905_mac_key_mac.end(), false, 
        "Cannot rekey 1905 layer PTK with '%s', key context does not exist", dest_mac_str.c_str());

    ec_1905_key_ctx& ctx = m_1905_mac_key_mac[dest_mac_str];

    if (memcmp(ctx.pmk, empty_nonce, sizeof(ctx.pmk)) == 0) {
        em_printfout("Cannot rekey 1905 layer PTK with '%s', PMK is not set", dest_mac_str.c_str());
        return false;
    }

    if (!begin_1905_4way_handshake(dest_al_mac, true)) {
        em_printfout("Failed to begin 1905 4-way handshake (REKEY) with Agent '%s'", dest_mac_str.c_str());
        return false;
    }

    return true;
}

bool ec_1905_encrypt_layer_t::rekey_1905_layer_ptk()
{
    EM_ASSERT_NOT_NULL(m_C_signing_key, false, "C-signing key is not set, cannot rekey 1905 layer PTK");
    EM_ASSERT_MSG_FALSE(m_connector_1905.empty(), false, "Connector 1905 is not set, cannot rekey 1905 layer PTK");

    /* EasyMesh 5.3.7.4
    Multi-AP Agent...shall perform the 1905 4-way handshake procedure (see section 5.3.7.2) to establish a new 1905 PTK with
    every Multi-AP device it is communicating with.
    */

    for (auto& [mac_str, ctx] : m_1905_mac_key_mac) {

        if (memcmp(ctx.pmk, empty_nonce, sizeof(ctx.pmk)) == 0) {
            em_printfout("Cannot rekey 1905 layer PTK with '%s', PMK is not set", mac_str.c_str());
            return false;
        }

        if (!begin_1905_4way_handshake(util::macstr_to_vector(mac_str).data(), true)) {
            em_printfout("Failed to begin 1905 4-way handshake (REKEY) with Agent '%s'", mac_str.c_str());
            return false;
        }
    }

    return true;
}


bool ec_1905_encrypt_layer_t::rekey_1905_layer_gtk()
{

    EM_ASSERT_NOT_NULL(m_C_signing_key, false, "C-signing key is not set, cannot rekey 1905 layer PTK");
    EM_ASSERT_MSG_FALSE(m_connector_1905.empty(), false, "Connector 1905 is not set, cannot rekey 1905 layer PTK");
    EM_ASSERT_MSG_FALSE(m_gmk.empty(), false, "Cannot rekey 1905 layer GTK, GMK is not set");

    em_printfout("Rekeying 1905 layer GTK");

    // Regenerate GTK
    if (!compute_gtk(m_hash_fn, m_al_mac_addr.data())) {
        em_printfout("Failed to derive GTK");
        return false;
    }
    m_gtk_rekey_counter++;

    // Send GTK to all agents
    for (auto& [mac_str, ctx] : m_1905_mac_key_mac) {

        // Build and send the first frame of the group key handshake
        auto [eapol_frame, frame_len] = build_group_eapol_frame_1(ctx);
        if (eapol_frame == nullptr || frame_len == 0) {
            em_printfout("Failed to build EAPOL frame for group key handshake with Agent '%s'", mac_str.c_str());
            return false;
        }
        std::vector<uint8_t> mac_vec = util::macstr_to_vector(mac_str);
        if (!m_send_1905_eapol_encap_msg(eapol_frame, frame_len, mac_vec.data())) {
            em_printfout("Failed to send EAPOL frame for group key handshake with Agent '%s'", mac_str.c_str());
            free(eapol_frame);
            return false;
        }

        // Increment sent EAPOL index
        ctx.sent_eapol_idx = 1; // We just sent the first frame of the group key handshake
        em_printfout("Sent first EAPOL frame for group key handshake with Agent '%s'", mac_str.c_str());
    }
    return false;
}

bool ec_1905_encrypt_layer_t::set_sec_params(SSL_KEY *c_sign_key, SSL_KEY* net_access_key, std::string connector_1905, const EVP_MD *hash_fn, std::vector<uint8_t> gmk)
{
    
    EM_ASSERT_NOT_NULL(c_sign_key, false, "Could not set 1905 encryption layer security params, NULL C-sign-key");
    EM_ASSERT_NOT_NULL(net_access_key, false, "Could not set 1905 encryption layer security params, NULL Net Access Key");
    EM_ASSERT_NOT_EQUALS(connector_1905, "", false, "Could not set 1905 encryption layer security params, empty 1905 connector"); 
    
    // Validate 1905 Connector before attempting to use it for 1905 layer
    auto parts = ec_crypto::split_decode_connector(connector_1905.c_str(), c_sign_key);
    EM_ASSERT_OPT_HAS_VALUE(parts, false, "Could not set 1905 encryption layer security params, failed to decode 1905 connector or verify signature");
    auto [header, payload, sig] = *parts;
    if (!ec_crypto::validate_jws_header(header, "dppConn")) {
        em_printfout("Could not set 1905 encryption layer security params, invalid JWS header in 1905 Connector");
        return false;
    }
    if (!ec_crypto::validate_jws_payload(payload)) {
        em_printfout("Could not set 1905 encryption layer security params, invalid JWS payload in 1905 Connector");
        return false;
    }

    if (!hash_fn) {
        em_printfout("Could not set 1905 encryption layer security params, NULL hash function");
        return false; 
    }
    m_hash_fn = hash_fn;
    /*
    Based on descriptions in the EasyConnect and EasyMesh specifications, the AKM appears to be
    00-0F-AC:25 (SAE) although it's not explicitly stated.
    This means:
    - The hash function is SHA-256, SHA-384, or SHA-512.
    - The KCK_bits are 128, 192, or 256 bits respectively.
    - The size of the MIC (bytes) is 16, 24, or 32 bytes respectively.
    - The KEK_bits are 128, 256, or **256**, respectively.
    - There are no KCK2 or KEK2 bits.
    - KDF is used inplace of PRF (although it is still referenced as PRF in the IEEE spec in multiple places).
    */

    /* EasyConnect 8.4.2
    The Nonce length in Table 4 shall be used as the length of KCK and EAPOL-Key MIC.
    The length of KEK shall be 128 if the Nonce length is 128; otherwise, the length of KEK shall be 256. 
    */
    if (m_hash_fn == EVP_sha256()) {
        mic_kck_bits = SHA256_DIGEST_LENGTH*4;
        kek_bits = 128; 
    } else if (m_hash_fn == EVP_sha384()) {
        mic_kck_bits = SHA384_DIGEST_LENGTH*4;
        kek_bits = 256;
    } else if (m_hash_fn == EVP_sha512()) {
        mic_kck_bits = SHA512_DIGEST_LENGTH*4;
        kek_bits = 256;
    } else {
        em_printfout("Unsupported hash function for 1905 encrypt layer");
        return false;
    }

    m_C_signing_key = c_sign_key;
    m_net_access_key = net_access_key;
    m_connector_1905 = connector_1905;
    m_gmk = gmk;
    return true;
}

bool ec_1905_encrypt_layer_t::begin_1905_4way_handshake(uint8_t dest_al_mac[ETH_ALEN], bool do_rekey) {
    EM_ASSERT_NOT_NULL(dest_al_mac, false, "Destination AL MAC address is null.");

    std::string dest_mac_str = util::mac_to_string(dest_al_mac);
    EM_ASSERT_MSG_FALSE(m_1905_mac_key_mac.find(dest_mac_str) == m_1905_mac_key_mac.end(), false, 
        "Cannot start 1905 4-way handshake with '%s', key context does not exist", dest_mac_str.c_str());

    ec_1905_key_ctx& ctx = m_1905_mac_key_mac[dest_mac_str];
    uint8_t empty[SHA256_DIGEST_LENGTH] = {0};
    EM_ASSERT_MSG_TRUE(memcmp(ctx.pmk, empty, sizeof(ctx.pmk)) != 0, false, 
        "Cannot start 1905 4-way handshake with '%s', PMK is not set", dest_mac_str.c_str());
    EM_ASSERT_MSG_TRUE(memcmp(ctx.pmkid, empty, sizeof(ctx.pmkid)) != 0, false,
        "Cannot start 1905 4-way handshake with '%s', PMKID is not set", dest_mac_str.c_str());


    // Build the the 1st frame of the 4 way EAPOL handshake
    em_printfout("Starting 1905 4-way handshake with '" MACSTRFMT "'", MAC2STR(dest_al_mac));

    ctx.is_ptk_rekeying = do_rekey; 

    auto [eapol_frame, frame_len] = build_pw_eapol_frame_1(ctx);
    if (eapol_frame == nullptr || frame_len == 0) {
        em_printfout("Failed to build EAPOL frame 1 for 1905 4-way handshake with '%s'", dest_mac_str.c_str());
        return false;
    }

    if (!m_send_1905_eapol_encap_msg(eapol_frame, frame_len, dest_al_mac)){
        em_printfout("Failed to send EAPOL frame 1 for 1905 4-way handshake with '%s'", dest_mac_str.c_str());
        free(eapol_frame);
        return false;
    }
    em_printfout("Sent EAPOL frame 1 for 1905 4-way handshake with '%s'", dest_mac_str.c_str());
    free(eapol_frame);
    // Increment the transaction ID for the next frame
    m_transaction_id++;
    // Set the sent EAPOL index to 1, since we just sent the first frame
    ctx.sent_eapol_idx = 1;

    return true;
}

std::pair<std::vector<uint8_t>,std::vector<uint8_t>> ec_1905_encrypt_layer_t::compute_pmk_pmkid(cJSON *recv_conn_payload)
{

    /*
        EasyConnect 6.6.4
        After exchanging connectors, each peer derives a shared secret N, using the private analog to its netAccesskey, nk, 
        and the Peer’s public network access provisioning key PK derived from the peer's Connector, a PMK, and a PMKID using
        both the device's and the peer's public keys, NK and PK ,respectively:

        N = nk * PK
        PMK = HKDF(<>, “DPP PMK”, N.x)
        PMKID = Truncate-128(SHA-256(min(NK.x, PK.x) | max(NK.x, PK.x)))
    */

    // START: Get crypto parameters 

    // Get n_k and N_K from the Local Net Access Key 
    scoped_bn nk(em_crypto_t::get_priv_key_bn(m_net_access_key)); // nk is the private key of the Net Access Key
    EM_ASSERT_NOT_NULL(nk.get(), {}, "Failed to get private key from Net Access Key");
    scoped_ec_point N_K(em_crypto_t::get_pub_key_point(m_net_access_key)); // N_K is the public key of the Net Access Key
    EM_ASSERT_NOT_NULL(N_K.get(), {}, "Failed to get public key point from Net Access Key");

    // Decode the recieved "netAccessKey" using the same curve as the local Net Access Key
    cJSON *net_access_key = cJSON_GetObjectItem(recv_conn_payload, "netAccessKey");
    EM_ASSERT_NOT_NULL(net_access_key, {}, "No netAccessKey in received 1905 Connector");

    // Public key of the peer's Net Access Key (P_K)
    auto [group_raw, PK_raw] = ec_crypto::decode_jwk(net_access_key);
    EM_ASSERT_NOT_NULL(group_raw, {}, "Failed to decode group from received Net Access Key");
    EM_ASSERT_NOT_NULL(PK_raw, {}, "Failed to decode public key from received Net Access Key");

    scoped_ec_group group(group_raw);
    scoped_ec_point PK(PK_raw);

    scoped_bn prime(BN_new());
    EM_ASSERT_NOT_NULL(prime.get(), {}, "Failed to create BIGNUM for prime");
    if (EC_GROUP_get_curve(group.get(), prime.get(), NULL, NULL, NULL) == 0) {
        em_printfout("unable to get prime of the curve");
        return {};
    }

    // START: Compute PMK and PMKID

    // N = nk * PK
    scoped_bn N_x(ec_crypto::compute_ec_ss_x(group.get(), nk.get(), PK.get()));
    EM_ASSERT_NOT_NULL(N_x.get(), {}, "Failed to compute shared secret X coordinate");

    const BIGNUM *bn_inputs[1] = { N_x.get() };
    // PMK = HKDF(<>, “DPP PMK”, N.x)
    uint8_t pmk[SHA256_DIGEST_LENGTH];
    if (ec_crypto::compute_hkdf_key(prime.get(), EVP_sha256(), pmk, SHA256_DIGEST_LENGTH, "DPP PMK", bn_inputs, 1, NULL, 0) == 0) {
        em_printfout("Failed to compute PMK!");
        return {};
    }

    // START: PMKID = Truncate-128(SHA-256(min(NK.x, PK.x) | max(NK.x, PK.x)))

    scoped_bn NK_x(ec_crypto::get_ec_x(group.get(), N_K.get()));
    EM_ASSERT_NOT_NULL(NK_x.get(), {}, "Failed to get X coordinate of Net Access Key");
    scoped_bn PK_x(ec_crypto::get_ec_x(group.get(), PK.get()));
    EM_ASSERT_NOT_NULL(PK_x.get(), {}, "Failed to get X coordinate of received Net Access Key (P_K_x)");

    // These don't need to be scoped since their scope is already managed by their parent objects

    // min(NK.x, PK.x)
    BIGNUM* min = em_crypto_t::bn_min(NK_x.get(), PK_x.get());
    // max(NK.x, PK.x)
    BIGNUM* max = em_crypto_t::bn_max(NK_x.get(), PK_x.get());

    // min(NK.x, PK.x) | max(NK.x, PK.x))
    easyconnect::hash_buffer_t hash_buff;
    ec_crypto::add_to_hash(hash_buff, min);
    ec_crypto::add_to_hash(hash_buff, max);

    // SHA-256(min(NK.x, PK.x) | max(NK.x, PK.x))
    uint8_t* hash = ec_crypto::compute_hash(EVP_sha256(), SHA256_DIGEST_LENGTH, hash_buff);

    EM_ASSERT_NOT_NULL(hash, {}, "Failed to compute hash for PMKID");
    
    // Truncate-128(SHA-256(min(NK.x, PK.x) | max(NK.x, PK.x)))
    std::vector<uint8_t> pmkid_vec(hash, hash + SHA256_DIGEST_LENGTH/2);
    std::vector<uint8_t> pmk_vec(pmk, pmk + SHA256_DIGEST_LENGTH);
    free(hash);

    return std::make_pair(pmk_vec, pmkid_vec);
}

std::pair<uint8_t *, size_t> ec_1905_encrypt_layer_t::create_peer_disc_req(uint8_t dest_al_mac[ETH_ALEN])
{

    EM_ASSERT_NOT_NULL(m_C_signing_key, {}, "C-signing key is not set, cannot create Peer Discovery Request frame");
    EM_ASSERT_MSG_FALSE(m_connector_1905.empty(), {}, "Connector 1905 is not set, cannot create Peer Discovery Request frame");
    EM_ASSERT_NOT_NULL(dest_al_mac, {}, "Destination MAC address is null in Peer Discovery Request frame");


    ec_frame_t *frame = ec_util::alloc_frame(ec_frame_type_peer_disc_req);
    EM_ASSERT_NOT_NULL(frame, {}, "failed to allocate memory for frame");

    size_t attribs_len = 0;

    static uint8_t trans_id = 0;

    uint8_t* attribs = ec_util::add_attrib(NULL, &attribs_len, ec_attrib_id_trans_id, static_cast<uint8_t>(trans_id++));
    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_dpp_connector, m_connector_1905);

    // Won't run into the reconfig case here since this use is in the PA / Agent not in the Controller
    m_transaction_id = trans_id;


    if (DPP_VERSION >= 2){
        attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_proto_version, static_cast<uint8_t>(DPP_VERSION));
    }
    
    EM_ASSERT_NOT_NULL_FREE(attribs, {}, frame, "failed to allocate peer discovery request attributes");

    if (!(frame = ec_util::copy_attrs_to_frame(frame, attribs, attribs_len))) {
        em_printfout("Failed to copy attributes to Peer Discovery Request Frame");
        free(attribs);
        free(frame);
        return {};
    }

    return std::make_pair(reinterpret_cast<uint8_t *>(frame), EC_FRAME_BASE_SIZE + attribs_len);
}

std::pair<uint8_t *, size_t> ec_1905_encrypt_layer_t::create_peer_disc_resp(uint8_t dest_mac[ETH_ALEN], ec_status_code_t dpp_status, uint8_t trans_id)
{

    EM_ASSERT_NOT_NULL(m_C_signing_key, {}, "C-signing key is not set, cannot crete Peer Discovery Response frame");
    EM_ASSERT_MSG_FALSE(m_connector_1905.empty(), {}, "Connector 1905 is not set, cannot create Peer Discovery Response frame");
    EM_ASSERT_NOT_NULL(dest_mac, {}, "Source MAC address is null in Peer Discovery Request frame");

    ec_frame_t *frame = ec_util::alloc_frame(ec_frame_type_peer_disc_rsp);
    EM_ASSERT_NOT_NULL(frame, {}, "failed to allocate memory for frame");

    size_t attribs_len = 0;

    uint8_t* attribs = ec_util::add_attrib(NULL, &attribs_len, ec_attrib_id_trans_id, static_cast<uint8_t>(trans_id));
    attribs = ec_util::add_attrib(NULL, &attribs_len, ec_attrib_id_dpp_status, static_cast<uint8_t>(dpp_status));

    if (dpp_status == DPP_STATUS_OK) {
        // If DPP Status is OK, include the 1905 Connector
        attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_dpp_connector, m_connector_1905);
    }
    
    if (DPP_VERSION >= 2) {
        // Protocol Version
        attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_proto_version, static_cast<uint8_t>(DPP_VERSION));
    }
    
    EM_ASSERT_NOT_NULL_FREE(attribs, {}, frame, "failed to allocate peer discovery response attributes");

    if (!(frame = ec_util::copy_attrs_to_frame(frame, attribs, attribs_len))) {
        em_printfout("Failed to copy attributes to Peer Discovery Request Frame");
        free(attribs);
        free(frame);
        return {};
    }

    return std::make_pair(reinterpret_cast<uint8_t *>(frame), EC_FRAME_BASE_SIZE + attribs_len);
}

std::pair<uint8_t*, size_t> ec_1905_encrypt_layer_t::append_key_data_buff(uint8_t* eapol_frame, size_t eapol_frame_size, uint8_t* kde, size_t kde_len) {

    EM_ASSERT_NOT_NULL(eapol_frame, {}, "EAPOL frame is null");
    EM_ASSERT_MSG_TRUE(eapol_frame_size > sizeof(ieee802_1x_hdr_t) + sizeof(eapol_packet_t), {}, 
        "EAPOL frame size is too small to contain EAPOL header and packet");
    EM_ASSERT_NOT_NULL(kde, {}, "KDE is null");
    EM_ASSERT_MSG_TRUE(kde_len >= EAPOL_KDE_BASE_SIZE, {}, "KDE length is too small, must be at least %zu bytes", EAPOL_KDE_BASE_SIZE);

    uint8_t* new_frame = reinterpret_cast<uint8_t*>(realloc(eapol_frame, eapol_frame_size + kde_len));
    EM_ASSERT_NOT_NULL(new_frame, {}, "Failed to allocate memory for EAPOL frame with KDE");

    eapol_packet_t* eapol_packet = reinterpret_cast<eapol_packet_t*>(new_frame + sizeof(ieee802_1x_hdr_t));

    bool mic_present = eapol_packet->key_info.bits.key_mic == 1;
    
    uint8_t* data_ptr = reinterpret_cast<uint8_t*>(eapol_packet) + sizeof(eapol_packet_t);

    if (mic_present) {
        data_ptr += (mic_kck_bits / 8); // Skip MIC field if present
    }
    uint16_t key_data_len = 0;
    memcpy(&key_data_len, data_ptr, sizeof(uint16_t));

    key_data_len += static_cast<uint16_t>(kde_len); // Add New KDE length to key data length

    memcpy(data_ptr, &key_data_len, sizeof(uint16_t)); // Update Key Data Length in EAPOL packet
    data_ptr += sizeof(uint16_t); // Move pointer to Key Data field 

    // Copy the KDE to the end of the EAPOL packet
    memcpy(data_ptr, kde, kde_len);

    return {new_frame, eapol_frame_size + kde_len};
}

std::pair<uint8_t *, size_t> ec_1905_encrypt_layer_t::alloc_eapol_frame(bool is_mic_present)
{
    size_t eapol_frame_size = sizeof(ieee802_1x_hdr_t) + sizeof(eapol_packet_t);
    if (is_mic_present) {
        eapol_frame_size += static_cast<size_t>(mic_kck_bits / 8); // Add MIC length (bytes) to EAPOL frame size
    }
    uint8_t* eapol_frame = reinterpret_cast<uint8_t*>(calloc(eapol_frame_size, 1));
    EM_ASSERT_NOT_NULL(eapol_frame, {}, "Failed to allocate memory for EAPOL frame");

    ieee802_1x_hdr_t* eapol_hdr = reinterpret_cast<ieee802_1x_hdr_t*>(eapol_frame);
    eapol_hdr->version = EAPOL_VERSION;
    eapol_hdr->type = IEEE802_1X_TYPE_EAPOL_KEY; // Set the EAPOL type to Key

    return {eapol_frame, eapol_frame_size};
}

std::pair<uint8_t *, size_t> ec_1905_encrypt_layer_t::encrypt_key_data(ec_1905_key_ctx &ctx, uint8_t* key_data_plain, size_t key_data_len)
{

    // Copy the Key Data to a new buffer to pad if necessary
    size_t new_key_data_len = key_data_len;
    size_t remaining_pad_bytes = 8 - (key_data_len % 8);

    uint8_t* key_data_plain_copy = reinterpret_cast<uint8_t*>(calloc(new_key_data_len + remaining_pad_bytes, 1));
    EM_ASSERT_NOT_NULL(key_data_plain_copy, {}, "Failed to allocate memory for Key Data padding");

    memcpy(key_data_plain_copy, key_data_plain, key_data_len); // Copy the original Key Data


    /* IEEE 802.11 12.7.2j

    If the Key Data field uses the NIST AES key wrap, then the Key Data field shall be padded before
    encrypting if the length of the key data is nonzero and less than 16 octets, or if it is not a multiple of 8
    octets. The padding consists of appending a single octet 0xdd followed by zero or more 0x00 octets.
    */
    if (new_key_data_len % 8 != 0 || new_key_data_len < 16) {
        key_data_plain_copy[new_key_data_len] = 0xDD;  // Padding byte
        new_key_data_len += remaining_pad_bytes;
    }

    // Encrypt Key Data using NIST AES Key Wrap
    uint8_t empty_kek[sizeof(ctx.ptk_kek)];
    memset(empty_kek, 0, sizeof(empty_kek));
    if (memcmp(ctx.ptk_kek, empty_kek, sizeof(empty_kek)) == 0) {
        em_printfout("PTK KEK is null, cannot encrypt Key Data");
        free(key_data_plain_copy);
        return {};
    }

    uint8_t* wrapped_key_data = reinterpret_cast<uint8_t*>(calloc(new_key_data_len+8, 1)); // +8 for integrity check
    uint32_t wrapped_key_data_len = 0;

    if (!em_crypto_t::aes_key_wrap(ctx.ptk_kek, kek_bits / 8, key_data_plain_copy, static_cast<uint32_t>(new_key_data_len), wrapped_key_data, &wrapped_key_data_len)){
        em_printfout("Failed to encrypt Key Data using AES Key Wrap");
        free(wrapped_key_data);
        free(key_data_plain_copy);
        return {};
    }
    free(key_data_plain_copy);
    return {wrapped_key_data, wrapped_key_data_len};
}

std::pair<uint8_t *, size_t> ec_1905_encrypt_layer_t::decrypt_key_data(ec_1905_key_ctx &ctx, uint8_t *wrapped_key_data, size_t key_data_len)
{

    EM_ASSERT_NOT_NULL(wrapped_key_data, {}, "Wrapped Key Data is null");
    EM_ASSERT_MSG_TRUE(key_data_len > 0, {}, "Wrapped Key Data length must be greater than 0");

    uint8_t empty_kek[sizeof(ctx.ptk_kek)];
    memset(empty_kek, 0, sizeof(empty_kek));
    if (memcmp(ctx.ptk_kek, empty_kek, sizeof(empty_kek)) == 0) {
        em_printfout("PTK KEK is null, cannot decrypt Key Data");
        return {};
    }

    uint8_t* unwrapped_key_data = reinterpret_cast<uint8_t*>(calloc(key_data_len, 1));
    uint32_t unwrapped_len = 0;

    if (!em_crypto_t::aes_key_unwrap(ctx.ptk_kek, kek_bits / 8, wrapped_key_data, static_cast<uint32_t>(key_data_len), unwrapped_key_data, &unwrapped_len)){
        em_printfout("Failed to decrypt Key Data using AES Key Wrap");
        free(unwrapped_key_data);
        return {};
    }

    // Remove (IEEE 802.11 12.7.2j) padding from back to front
    for (uint32_t i = unwrapped_len-1; i > 0; i--) {
        if (unwrapped_key_data[i] == 0x00) {
            continue; //Ignore continuous 0x00 padding bytes
        }

        if (unwrapped_key_data[i] == 0xDD) {
            // Found the padding byte, truncate the unwrapped key data
            unwrapped_len = i; // Set the new length to the position of the padding byte
            break;
        }

        // Found a non-padding byte (0xDD or 0x00) stop truncating
        break;
    }

    // Resize the unwrapped key data to the new (unpadded) length
    unwrapped_key_data = reinterpret_cast<uint8_t*>(realloc(unwrapped_key_data, unwrapped_len));
    EM_ASSERT_NOT_NULL(unwrapped_key_data, {}, "Failed to reallocate memory for unwrapped Key Data");

    return {unwrapped_key_data, unwrapped_len};
}

bool ec_1905_encrypt_layer_t::verify_mic(ec_1905_key_ctx &ctx, uint8_t *eapol_frame, size_t eapol_frame_size)
{
    std::vector<uint8_t> mic = calculate_mic(ctx, eapol_frame, eapol_frame_size);
    if (mic.empty()) {
        em_printfout("Failed to calculate MIC for EAPOL frame");
        return false;
    }
    eapol_packet_t* eapol_packet = reinterpret_cast<eapol_packet_t*>(eapol_frame + sizeof(ieee802_1x_hdr_t));
    if (memcmp(eapol_packet->mic_len_key, mic.data(), mic.size()) != 0) {
        em_printfout("MIC verification failed for EAPOL frame");
        return false;
    }

    return true;
}

std::vector<uint8_t> ec_1905_encrypt_layer_t::calculate_mic(ec_1905_key_ctx &ctx, uint8_t* eapol_frame, size_t eapol_frame_size) {
    EM_ASSERT_NOT_NULL(eapol_frame, {}, "EAPOL header is null");
    EM_ASSERT_MSG_TRUE(eapol_frame_size > sizeof(ieee802_1x_hdr_t) + sizeof(eapol_packet_t), {}, 
        "EAPOL frame size is too small to contain EAPOL header and packet");
    EM_ASSERT_NOT_NULL(m_hash_fn, {}, "Hash function is not set, cannot calculate MIC");
    EM_ASSERT_MSG_TRUE(mic_kck_bits > 0, {}, "MIC KCK bits must be greater than 0 to calculate MIC");


    uint8_t* eapol_frame_copy = reinterpret_cast<uint8_t*>(malloc(eapol_frame_size));
    EM_ASSERT_NOT_NULL(eapol_frame_copy, {}, "Failed to allocate memory for EAPOL frame copy");
    memcpy(eapol_frame_copy, eapol_frame, eapol_frame_size);

    eapol_packet_t* eapol_packet = reinterpret_cast<eapol_packet_t*>(eapol_frame_copy + sizeof(ieee802_1x_hdr_t));
    if (eapol_packet->key_info.bits.key_mic == 0) {
        em_printfout("EAPOL frame does not have MIC set, not calculating MIC");
        free(eapol_frame_copy);
        return {};
    }

    // While they are the same value, they are used for different purposes 
    // so we keep them separate
    size_t mic_len_bytes = mic_kck_bits / 8; // MIC length in bytes

    // Set Key MIC field to 0 before calculating MIC
    // MIC is at the end of the EAPOL packet, before Key Len and Key Data
    memset(eapol_packet->mic_len_key, 0, mic_len_bytes); 


    // Calculate the MIC for the EAPOL frame

    // Initialize temp MIC buffer to the max algorithm digest length since it will be truncated
    uint8_t temp_mic[SHA512_DIGEST_LENGTH];
    memset(temp_mic, 0, sizeof(temp_mic));

    uint8_t *addr[1] = { reinterpret_cast<uint8_t*>(eapol_frame_copy) };
    size_t len[1] = { eapol_frame_size };

    if (!em_crypto_t::platform_hmac_hash(m_hash_fn, ctx.ptk_kck, (mic_kck_bits / 8), 1, addr, len, temp_mic)) {
        free(eapol_frame_copy);
        em_printfout("Failed to calculate MIC for EAPOL frame");
        return {};
    }

    std::vector<uint8_t> mic(temp_mic, temp_mic + mic_len_bytes); // Truncate to MIC length
    free(eapol_frame_copy);
    return mic;
}

std::pair<uint8_t*, size_t> ec_1905_encrypt_layer_t::build_pw_eapol_frame_1(ec_1905_key_ctx &ctx)
{
    auto [eapol_frame, eapol_frame_size] = alloc_eapol_frame(false);

    eapol_packet_t* eapol_packet = reinterpret_cast<eapol_packet_t*>(eapol_frame + sizeof(ieee802_1x_hdr_t));
    // Set the key_info field
    eapol_packet->key_info.bits.key_descriptor_version = 0; // EasyConnect 8.4.2
    eapol_packet->key_info.bits.key_type = 1; // (Pairwise Key)
    eapol_packet->key_info.bits.install = 0;
    eapol_packet->key_info.bits.key_ack = 1;
    eapol_packet->key_info.bits.key_mic = 0; 
    eapol_packet->key_info.bits.secure = ctx.is_ptk_rekeying ? 1 : 0; // Set secure to 1 if rekeying, otherwise 0
    eapol_packet->key_info.bits.error = 0; 
    eapol_packet->key_info.bits.request = 0;
    eapol_packet->key_info.bits.encrypted_key_data = 0;

    eapol_packet->key_length = sizeof(ctx.ptk); // Key Length = Temporal Key Length
    eapol_packet->key_replay_counter = ctx.curr_replay_counter++; // Increment the replay counter for the first frame
    
    // Generate A-nonce
    if (RAND_bytes(ctx.a_nonce, sizeof(ctx.a_nonce)) != 1) {
        em_printfout("Failed to generate A-nonce for 1905 4-way handshake");
        free(eapol_frame);
        return {};
    }
    memcpy(eapol_packet->key_nonce, ctx.a_nonce, sizeof(ctx.a_nonce));

    memset(eapol_packet->key_iv, 0, sizeof(eapol_packet->key_iv)); // Set IV to zero
    memset(eapol_packet->key_rsc, 0, sizeof(eapol_packet->key_rsc)); // Set RSC to zero

    // KDE is at the end of the EAPOL packet, after the length field
    eapol_kde_t* kde = reinterpret_cast<eapol_kde_t*>(calloc(1, sizeof(eapol_kde_t) + sizeof(ctx.pmkid)));
    EM_ASSERT_NOT_NULL(kde, {}, "Failed to allocate memory for EAPOL KDE");

    kde->type = 0xDD;
    kde->length = sizeof(ctx.pmkid) + EAPOL_KDE_BASE_SIZE;
    memcpy(kde->oui, EAPOL_KDE_OUI, sizeof(EAPOL_KDE_OUI));
    kde->data_type = EAPOL_KDE_TYPE_PMKID;
    memcpy(kde->data, ctx.pmkid, sizeof(ctx.pmkid));

    auto [final_eapol_frame, final_eapol_frame_size] = append_key_data_buff(eapol_frame, eapol_frame_size, reinterpret_cast<uint8_t*>(kde), sizeof(eapol_kde_t) + sizeof(ctx.pmkid)); // Append the KDE to the EAPOL packet
    free(kde);
    ASSERT_NOT_NULL(final_eapol_frame, {}, "Failed to append KDE to EAPOL frame");

    return {final_eapol_frame, final_eapol_frame_size};
}

std::pair<uint8_t*, size_t> ec_1905_encrypt_layer_t::build_pw_eapol_frame_2(ec_1905_key_ctx &ctx)
{
    
    auto [eapol_frame, eapol_frame_size] = alloc_eapol_frame(true);

    eapol_packet_t* eapol_packet = reinterpret_cast<eapol_packet_t*>(eapol_frame + sizeof(ieee802_1x_hdr_t));
    // Set the key_info field
    eapol_packet->key_info.bits.key_descriptor_version = 0; // EasyConnect 8.4.2
    eapol_packet->key_info.bits.key_type = 1; // (Pairwise Key)
    eapol_packet->key_info.bits.install = 0;
    eapol_packet->key_info.bits.key_ack = 0;
    eapol_packet->key_info.bits.key_mic = 1; //  0 when using an AEAD cipher or 1 otherwise 
    eapol_packet->key_info.bits.secure = ctx.is_ptk_rekeying ? 1 : 0; // Set secure to 1 if rekeying, otherwise 0
    eapol_packet->key_info.bits.error = 0; 
    eapol_packet->key_info.bits.request = 0;
    eapol_packet->key_info.bits.encrypted_key_data = 0; //  1 when using an AEAD cipher or 0 otherwise

    eapol_packet->key_length = 0;
    eapol_packet->key_replay_counter = ctx.curr_replay_counter; // Same replay counter as the first frame
    
    // Key Nonce = SNonce
    if (memcmp(ctx.s_nonce, empty_nonce, sizeof(ctx.s_nonce)) == 0) {
        em_printfout("Empty SNonce in 4-way handshake, cannot continue 4 way handshake with '%s'", util::mac_to_string(m_al_mac_addr.data()).c_str());
        free(eapol_frame);
        return {};
    }
    memcpy(eapol_packet->key_nonce, ctx.s_nonce, sizeof(ctx.s_nonce));

    memset(eapol_packet->key_iv, 0, sizeof(eapol_packet->key_iv)); // Set IV to zero
    memset(eapol_packet->key_rsc, 0, sizeof(eapol_packet->key_rsc)); // Set RSC to zero


    /* EasyMesh 5.3.7.2
    A Multi-AP device should not include any RSNE in the messages belonging to the 1905 4-way handshake. 
    A Multi-AP device shall ignore any RSNE received in the 1905 4-way handshake messages.
    */

    // Key Data Length = 0, since we are not sending any key data in this frame
    // Key Data = []

    std::vector<uint8_t> mic = calculate_mic(ctx, eapol_frame, eapol_frame_size);
    if (mic.empty()) {
        em_printfout("Failed to calculate MIC for EAPOL frame 2 in 4-way handshake with '%s'", util::mac_to_string(m_al_mac_addr.data()).c_str());
        free(eapol_frame);
        return {};
    }
    // Copy the MIC to the end of the EAPOL packet
    memcpy(eapol_packet->mic_len_key, mic.data(), mic.size());

    return {eapol_frame, eapol_frame_size};
}

std::pair<uint8_t*, size_t> ec_1905_encrypt_layer_t::build_pw_eapol_frame_3(ec_1905_key_ctx &ctx)
{
    auto [eapol_frame, eapol_frame_size] = alloc_eapol_frame(true);

    eapol_packet_t* eapol_packet = reinterpret_cast<eapol_packet_t*>(eapol_frame + sizeof(ieee802_1x_hdr_t));
    
    // Set the key_info field
    eapol_packet->key_info.bits.key_descriptor_version = 0; // EasyConnect 8.4.2
    eapol_packet->key_info.bits.key_type = 1; // (Pairwise Key)
    eapol_packet->key_info.bits.install = 1;
    eapol_packet->key_info.bits.key_ack = 1;
    eapol_packet->key_info.bits.key_mic = 1; //  0 when using an AEAD cipher or 1 otherwise 
    eapol_packet->key_info.bits.secure = 1; // (keys installed)
    eapol_packet->key_info.bits.error = 0; 
    eapol_packet->key_info.bits.request = 0;
    eapol_packet->key_info.bits.encrypted_key_data = 1;

    eapol_packet->key_length = sizeof(ctx.ptk); // Key Length = Temporal Key Length 
    eapol_packet->key_replay_counter = ++ctx.curr_replay_counter; // Incremented replay counter for the third frame
    
    // Key Nonce = ANonce
    if (memcmp(ctx.a_nonce, empty_nonce, sizeof(ctx.a_nonce)) == 0) {
        em_printfout("Empty ANonce in 4-way handshake, cannot continue 4 way handshake");
        free(eapol_frame);
        return {};
    }
    memcpy(eapol_packet->key_nonce, ctx.a_nonce, sizeof(ctx.a_nonce));

    memset(eapol_packet->key_iv, 0, sizeof(eapol_packet->key_iv)); //  0 (Version 2)
    memcpy(eapol_packet->key_rsc, &m_gtk_rekey_counter, sizeof(m_gtk_rekey_counter)); // Set RSC to GTK Rekey Counter (PN)


    /* EasyMesh 5.3.7.2
        A Multi-AP device should not include any RSNE in the messages belonging to the 1905 4-way handshake. 
        A Multi-AP device shall ignore any RSNE received in the 1905 4-way handshake messages.
    */

    /* EasyMesh 5.3.7.3
        The Multi-AP Controller shall generate the 1905 GTK and include it in message 3 of the 1905 4-way handshake. 
        The 1905 GTK shall be a random or pseudorandom number as per section 12.7.1.2 of [1].  If a Multi-AP Agent is 
        performing a 1905 4-way handshake with another Multi-AP Agent, a new 1905 GTK shall not be generated and included in Message 3. 
        A Multi-AP Agent shall use the 1905 GTK provided by the Multi-AP Controller.
    */

    // Therefore:
    // Key Data Length = 1905 GTK KDE Length
    // Key Data = [1905 GTK KDE]
    if (memcmp(this->m_gtk, empty_nonce, sizeof(this->m_gtk)) == 0) {
        em_printfout("Empty GTK in 4-way handshake, cannot continue 4 way handshake");
        free(eapol_frame);
        return {};
    }

    uint8_t key_data_plain[256] = {0}; // Unencrypted key data buffer
    size_t key_data_len = 0;

    eapol_kde_t* kde = reinterpret_cast<eapol_kde_t*>(key_data_plain);

    kde->type = 0xDD;
    kde->length = sizeof(this->m_gtk) + EAPOL_KDE_BASE_SIZE;
    memcpy(kde->oui, EAPOL_KDE_OUI_WFA, sizeof(EAPOL_KDE_OUI_WFA));
    kde->data_type = EAPOL_KDE_TYPE_1905_GTK;

    // EasyMesh Table 12
    gtk_1905_kde_t* gtk_kde = reinterpret_cast<gtk_1905_kde_t*>(kde->data);
    gtk_kde->key_id = this->m_gtk_id & 0x3; // Ensure only 2 bits are used
    memcpy(gtk_kde->gtk, this->m_gtk, sizeof(this->m_gtk));

    key_data_len = sizeof(eapol_kde_t) + sizeof(gtk_1905_kde_t);


    auto [wrapped_key_data, wrapped_key_data_len] = encrypt_key_data(ctx, key_data_plain, key_data_len);
    if (wrapped_key_data == NULL || wrapped_key_data_len == 0) {
        em_printfout("Failed to encrypt Key Data for EAPOL frame 3 in 4-way handshake with '%s'", util::mac_to_string(m_al_mac_addr.data()).c_str());
        free(eapol_frame);
        return {};
    }

    // Add encrypted Key Data to the EAPOL frame
    auto [final_eapol_frame, final_eapol_frame_size] = append_key_data_buff(eapol_frame, eapol_frame_size, wrapped_key_data, wrapped_key_data_len);

    EM_ASSERT_NOT_NULL(final_eapol_frame, {}, "Failed to append encrypted Key Data to EAPOL frame");

    // Calculate the MIC for the EAPOL frame
    std::vector<uint8_t> mic = calculate_mic(ctx, final_eapol_frame, final_eapol_frame_size);
    EM_ASSERT_NOT_NULL_FREE(mic.data(), {}, final_eapol_frame, "Failed to calculate MIC for EAPOL frame 3 in 4-way handshake with '%s'", util::mac_to_string(m_al_mac_addr.data()).c_str());
    if (mic.empty()) {
        em_printfout("Failed to calculate MIC for EAPOL frame 3 in 4-way handshake with '%s'", util::mac_to_string(m_al_mac_addr.data()).c_str());
        free(final_eapol_frame);
        return {};
    }

    // Copy the MIC to the end of the EAPOL packet (before Key Len and Key Data)
    memcpy(eapol_packet->mic_len_key, mic.data(), mic.size()); 

    return {final_eapol_frame, final_eapol_frame_size};
}

std::pair<uint8_t*, size_t> ec_1905_encrypt_layer_t::build_pw_eapol_frame_4(ec_1905_key_ctx &ctx)
{
    auto [eapol_frame, eapol_frame_size] = alloc_eapol_frame(true);

    eapol_packet_t* eapol_packet = reinterpret_cast<eapol_packet_t*>(eapol_frame + sizeof(ieee802_1x_hdr_t));
    // Set the key_info field
    eapol_packet->key_info.bits.key_descriptor_version = 0; // EasyConnect 8.4.2
    eapol_packet->key_info.bits.key_type = 1; // (Pairwise Key)
    eapol_packet->key_info.bits.install = 0;
    eapol_packet->key_info.bits.key_ack = 0;
    eapol_packet->key_info.bits.key_mic = 1; //  0 when using an AEAD cipher or 1 otherwise 
    eapol_packet->key_info.bits.secure = 1;
    eapol_packet->key_info.bits.error = 0; 
    eapol_packet->key_info.bits.request = 0;
    eapol_packet->key_info.bits.encrypted_key_data = 0; //  1 when using an AEAD cipher or 0 otherwise

    eapol_packet->key_length = 0;
    eapol_packet->key_replay_counter = ctx.curr_replay_counter; // Same replay counter as the third frame
    
    // Key Nonce = Empty Nonce
    memcpy(eapol_packet->key_nonce, empty_nonce, sizeof(empty_nonce));

    memset(eapol_packet->key_iv, 0, sizeof(eapol_packet->key_iv)); // Set IV to zero
    memset(eapol_packet->key_rsc, 0, sizeof(eapol_packet->key_rsc)); // Set RSC to zero


    /* EasyMesh 5.3.7.2
    A Multi-AP device should not include any RSNE in the messages belonging to the 1905 4-way handshake. 
    A Multi-AP device shall ignore any RSNE received in the 1905 4-way handshake messages.
    */

    // Key Data Length = 0, none required 
    // Key Data = []

    std::vector<uint8_t> mic = calculate_mic(ctx, eapol_frame, eapol_frame_size);
    if (mic.empty()) {
        em_printfout("Failed to calculate MIC for EAPOL frame 2 in 4-way handshake with '%s'", util::mac_to_string(m_al_mac_addr.data()).c_str());
        free(eapol_frame);
        return {};
    }
    // Copy the MIC to the end of the EAPOL packet
    memcpy(eapol_packet->mic_len_key, mic.data(), mic.size());

    return {eapol_frame, eapol_frame_size};
}

std::pair<uint8_t *, size_t> ec_1905_encrypt_layer_t::build_group_eapol_frame_1(ec_1905_key_ctx &ctx)
{
    auto [eapol_frame, eapol_frame_size] = alloc_eapol_frame(true);

    eapol_packet_t* eapol_packet = reinterpret_cast<eapol_packet_t*>(eapol_frame + sizeof(ieee802_1x_hdr_t));
    // Set the key_info field
    eapol_packet->key_info.bits.key_descriptor_version = 0; // EasyConnect 8.4.2
    eapol_packet->key_info.bits.key_type = 0; // (Group Key)
    eapol_packet->key_info.bits.install = 0;
    eapol_packet->key_info.bits.key_ack = 1;
    eapol_packet->key_info.bits.key_mic = 1; //  0 when using an AEAD cipher or 1 otherwise 
    eapol_packet->key_info.bits.secure = 1; //
    eapol_packet->key_info.bits.error = 0; 
    eapol_packet->key_info.bits.request = 0;
    eapol_packet->key_info.bits.encrypted_key_data = 1;

    eapol_packet->key_length = 0;
    eapol_packet->key_replay_counter = ++ctx.curr_replay_counter; // greater than in the last (#1836)EAPOL-Key PDU transmitted that was not an EAPOL-Key request frame 
    
    // Key Nonce = 0
    memcpy(eapol_packet->key_nonce, empty_nonce, sizeof(empty_nonce));

    memset(eapol_packet->key_iv, 0, sizeof(eapol_packet->key_iv)); //  0 (Version 2)
    memcpy(eapol_packet->key_rsc, &m_gtk_rekey_counter, sizeof(m_gtk_rekey_counter)); // Set RSC to GTK Rekey Counter (PN)

    /* EasyMesh 5.3.7.2
        A Multi-AP device should not include any RSNE in the messages belonging to the 1905 4-way handshake. 
        A Multi-AP device shall ignore any RSNE received in the 1905 4-way handshake messages.
    */

    /* EasyMesh 5.3.7.3
        The Multi-AP Controller shall generate the 1905 GTK and include it in message 3 of the 1905 4-way handshake. 
        The 1905 GTK shall be a random or pseudorandom number as per section 12.7.1.2 of [1].  If a Multi-AP Agent is 
        performing a 1905 4-way handshake with another Multi-AP Agent, a new 1905 GTK shall not be generated and included in Message 3. 
        A Multi-AP Agent shall use the 1905 GTK provided by the Multi-AP Controller.
    */

    /*
    GTK and the GTK’s (#3493)key ID (see 12.7.2 (EAPOL-Key frames))
    */

    // Therefore:
    // Key Data Length = 1905 GTK KDE Length
    // Key Data = [1905 GTK KDE]
    if (memcmp(this->m_gtk, empty_nonce, sizeof(this->m_gtk)) == 0) {
        em_printfout("Empty GTK in 4-way handshake, cannot continue 4 way handshake");
        free(eapol_frame);
        return {};
    }

    uint8_t key_data_plain[256] = {0}; // Unencrypted key data buffer
    size_t key_data_len = 0;

    eapol_kde_t* kde = reinterpret_cast<eapol_kde_t*>(key_data_plain);

    kde->type = 0xDD;
    kde->length = sizeof(this->m_gtk) + EAPOL_KDE_BASE_SIZE;
    memcpy(kde->oui, EAPOL_KDE_OUI_WFA, sizeof(EAPOL_KDE_OUI_WFA));
    kde->data_type = EAPOL_KDE_TYPE_1905_GTK;

    // EasyMesh Table 12
    gtk_1905_kde_t* gtk_kde = reinterpret_cast<gtk_1905_kde_t*>(kde->data);
    gtk_kde->key_id = this->m_gtk_id & 0x3; // Ensure only 2 bits are used
    memcpy(gtk_kde->gtk, this->m_gtk, sizeof(this->m_gtk));

    key_data_len = sizeof(eapol_kde_t) + sizeof(gtk_1905_kde_t);

    auto [wrapped_key_data, wrapped_key_data_len] = encrypt_key_data(ctx, key_data_plain, key_data_len);

    // Add encrypted Key Data to the EAPOL frame
    auto [final_eapol_frame, final_eapol_frame_size] = append_key_data_buff(eapol_frame, eapol_frame_size, wrapped_key_data, wrapped_key_data_len);

    EM_ASSERT_NOT_NULL(final_eapol_frame, {}, "Failed to append encrypted Key Data to EAPOL frame");

    // Calculate the MIC for the EAPOL frame
    std::vector<uint8_t> mic = calculate_mic(ctx, final_eapol_frame, final_eapol_frame_size);
    if (mic.empty()) {
        em_printfout("Failed to calculate MIC for EAPOL frame 3 in 4-way handshake with '%s'", util::mac_to_string(m_al_mac_addr.data()).c_str());
        free(final_eapol_frame);
        return {};
    }

    // Copy the MIC to the end of the EAPOL packet (before Key Len and Key Data)
    memcpy(eapol_packet->mic_len_key, mic.data(), mic.size()); 

    return {final_eapol_frame, final_eapol_frame_size};
}

std::pair<uint8_t *, size_t> ec_1905_encrypt_layer_t::build_group_eapol_frame_2(ec_1905_key_ctx &ctx)
{
    auto [eapol_frame, eapol_frame_size] = alloc_eapol_frame(true);

    eapol_packet_t* eapol_packet = reinterpret_cast<eapol_packet_t*>(eapol_frame + sizeof(ieee802_1x_hdr_t));
    // Set the key_info field
    eapol_packet->key_info.bits.key_descriptor_version = 0; // EasyConnect 8.4.2
    eapol_packet->key_info.bits.key_type = 1; // (Pairwise Key)
    eapol_packet->key_info.bits.install = 0;
    eapol_packet->key_info.bits.key_ack = 0;
    eapol_packet->key_info.bits.key_mic = 1; //  0 when using an AEAD cipher or 1 otherwise 
    eapol_packet->key_info.bits.secure = 1;
    eapol_packet->key_info.bits.error = 0; 
    eapol_packet->key_info.bits.request = 0;
    eapol_packet->key_info.bits.encrypted_key_data = 0; //  1 when using an AEAD cipher or 0 otherwise

    eapol_packet->key_length = 0;
    eapol_packet->key_replay_counter = ctx.curr_replay_counter; // Same replay counter as the third frame
    
    // Key Nonce = Empty Nonce
    memcpy(eapol_packet->key_nonce, empty_nonce, sizeof(empty_nonce));

    memset(eapol_packet->key_iv, 0, sizeof(eapol_packet->key_iv)); // Set IV to zero
    memset(eapol_packet->key_rsc, 0, sizeof(eapol_packet->key_rsc)); // Set RSC to zero


    /* EasyMesh 5.3.7.2
    A Multi-AP device should not include any RSNE in the messages belonging to the 1905 4-way handshake. 
    A Multi-AP device shall ignore any RSNE received in the 1905 4-way handshake messages.
    */

    // Key Data Length = 0, none required 
    // Key Data = []

    std::vector<uint8_t> mic = calculate_mic(ctx, eapol_frame, eapol_frame_size);
    if (mic.empty()) {
        em_printfout("Failed to calculate MIC for EAPOL frame 2 in 4-way handshake with '%s'", util::mac_to_string(m_al_mac_addr.data()).c_str());
        free(eapol_frame);
        return {};
    }
    // Copy the MIC to the end of the EAPOL packet
    memcpy(eapol_packet->mic_len_key, mic.data(), mic.size());

    return {eapol_frame, eapol_frame_size};
}

bool ec_1905_encrypt_layer_t::handle_pw_eapol_frame_1(ec_1905_key_ctx &ctx, uint8_t *frame, uint16_t len, uint8_t src_mac[ETH_ALEN])
{
    EM_ASSERT_NOT_NULL(frame, {}, "EAPOL frame is null");
    EM_ASSERT_MSG_TRUE(len >= sizeof(ieee802_1x_hdr_t) + sizeof(eapol_packet_t), {}, 
        "EAPOL frame length is too small to contain EAPOL header and packet");
    EM_ASSERT_NOT_NULL(src_mac, {}, "Source MAC address is null in EAPOL frame");

    eapol_packet_t *eapol_packet = reinterpret_cast<eapol_packet_t *>(frame + sizeof(ieee802_1x_hdr_t));

    /* IEEE 802.11 12.7.6.2 (minimized for 1905)
    On reception of message 1, the Supplicant determines whether the Key Replay Counter field value has been used before with the current PMKSA. 
    If the Key Replay Counter field value is less than or equal to the current local value:
        the Supplicant discards the message. 
    Otherwise, the Supplicant:
        a) Generates a new nonce SNonce, if no SNonce has yet been generated for this 4-way handshake. 
        The same SNonce is reused within this 4-way handshake until a valid message 3 has been received.
        b) Derives PTK(11ba)
        c) Constructs message 2.
    */
    if (eapol_packet->key_replay_counter <= ctx.curr_replay_counter) {
        em_printfout("Received EAPOL frame with replay counter %llu that is less than or equal to current replay counter %llu, discarding",
            eapol_packet->key_replay_counter, ctx.curr_replay_counter);
        return false;
    }
    em_printfout("Received EAPOL frame with replay counter %llu, setting current replay counter to this value", eapol_packet->key_replay_counter);
    ctx.curr_replay_counter = eapol_packet->key_replay_counter;

    if (memcmp(eapol_packet->key_nonce, empty_nonce, sizeof(eapol_packet->key_nonce)) == 0) {
        em_printfout("Received EAPOL frame with empty ANonce, discarding");
        return false;
    }
    memcpy(ctx.a_nonce, eapol_packet->key_nonce, sizeof(ctx.a_nonce));

    // During the first and second frames of the 4-way handshake
    // the secure bit is only set if PTK rekeying
    // IEEE 802.11-2020 12.7.2 b7
    ctx.is_ptk_rekeying = (eapol_packet->key_info.bits.secure == 1);

    // Generate a new SNonce if not already generated
    if (memcmp(ctx.s_nonce, empty_nonce, sizeof(ctx.s_nonce)) == 0) {
        em_printfout("Generating new SNonce for 4-way handshake with '" MACSTRFMT "'", MAC2STR(src_mac)); 
        RAND_bytes(ctx.s_nonce, sizeof(ctx.s_nonce));
    } else {
        em_printfout("Reusing existing SNonce for 4-way handshake with '" MACSTRFMT "'", MAC2STR(src_mac));
    }

    // Derive PTK
    if (!compute_ptk(m_hash_fn, ctx, m_al_mac_addr.data(), src_mac)){
        em_printfout("Failed to derive PTK for frame 1 in 4-way handshake with '" MACSTRFMT "'", MAC2STR(src_mac));
        return false;
    }

    // Save the PTK-KCK and the PTK-KEK
    uint16_t kck_bytes = mic_kck_bits / 8; // KCK length in bytes
    /* IEEE 802.11 12.7.1.3
    The PTK-KCK shall be computed as the first KCK_bits bits (bits 0 to KCK_bits–1) of the PTK:
        PTK-KCK= ExtractBits(PTK, 0, KCK_bits)
    The PTK-KCK is used by IEEE Std 802.1X-2020 to provided data origin authenticity in the 4-way handshake and group key handshake messages.
    */
    memcpy(ctx.ptk_kck, ctx.ptk, kck_bytes); 

    /* IEEE 802.11 12.7.1.3
    The PTK-KEK shall be computed as the next KEK_bits bits of the PTK:
        PTK-KEK = ExtractBits(PTK, KCK_bits, KEK_bits)
    The PTK-KEK is used by the EAPOL-Key frames to provide data confidentiality in the 4-way handshake and group key handshake messages.
    */
    memcpy(ctx.ptk_kek, ctx.ptk + kck_bytes, kek_bits / 8); 

    // Build the second frame of the 4-way handshake
    em_printfout("Building EAPOL frame 2 for 4-way handshake with '" MACSTRFMT "'", MAC2STR(src_mac));
    auto [eapol_frame_2, frame_len] = build_pw_eapol_frame_2(ctx);
    if (eapol_frame_2 == nullptr || frame_len == 0) {
        em_printfout("Failed to build EAPOL frame 2 for 4-way handshake with '" MACSTRFMT "'", MAC2STR(src_mac));
        return false;
    }
    if (!m_send_1905_eapol_encap_msg(eapol_frame_2, frame_len, src_mac)){
        em_printfout("Failed to send EAPOL frame 2 for 4-way handshake with '" MACSTRFMT "'", MAC2STR(src_mac));
        free(eapol_frame_2);
        return false;
    }
    em_printfout("Sent EAPOL frame 2 for 4-way handshake with '" MACSTRFMT "'", MAC2STR(src_mac));
    ctx.sent_eapol_idx = 2; // Update the sent EAPOL index to 2, indicating we sent the second frame of the 4-way handshake
    return true;
}

bool ec_1905_encrypt_layer_t::handle_pw_eapol_frame_2(ec_1905_key_ctx &ctx, uint8_t *frame, uint16_t len, uint8_t src_mac[ETH_ALEN])
{

    EM_ASSERT_NOT_NULL(frame, {}, "EAPOL frame is null");
    EM_ASSERT_MSG_TRUE(len >= sizeof(ieee802_1x_hdr_t) + sizeof(eapol_packet_t), {}, 
        "EAPOL frame length is too small to contain EAPOL header and packet");
    EM_ASSERT_NOT_NULL(src_mac, {}, "Source MAC address is null in EAPOL frame");

    eapol_packet_t *eapol_packet = reinterpret_cast<eapol_packet_t *>(frame + sizeof(ieee802_1x_hdr_t));

    /* 802.11 12.7.6.3 (minimized for 1905/EasyMesh)
    On reception of message 2, the Authenticator checks that the key replay counter corresponds to the outstanding message 1. 
    If not, the Authenticator shall silently discard the message.

    Otherwise, the Authenticator:
    a) Derives PTK.
    b) Verifies the message 2 MIC or AEAD decryption operation result.
        1) If the calculated MIC does not match the MIC that the Supplicant included in the EAPOL-Key PDU or 
        the AEAD decryption operation returns failure, the Authenticator shall silently discard message 2.
        2) If all these conditions are met, the Authenticator constructs message 3.
    */

    if (eapol_packet->key_replay_counter != ctx.curr_replay_counter) {
        em_printfout("Received EAPOL frame with replay counter %llu that does not match current replay counter %llu, discarding",
            eapol_packet->key_replay_counter, ctx.curr_replay_counter);
        return false;
    }
    em_printfout("Received EAPOL frame with replay counter %llu, proceeding with 4-way handshake", eapol_packet->key_replay_counter);

    if (!compute_ptk(m_hash_fn, ctx, src_mac, m_al_mac_addr.data())){
        em_printfout("Failed to derive PTK for frame 2 in 4-way handshake with '" MACSTRFMT "'", MAC2STR(src_mac));
        return false;
    }

    // Save the PTK-KCK and the PTK-KEK
    uint16_t kck_bytes = mic_kck_bits / 8; // KCK length in bytes
    /* IEEE 802.11 12.7.1.3
    The PTK-KCK shall be computed as the first KCK_bits bits (bits 0 to KCK_bits–1) of the PTK:
        PTK-KCK= ExtractBits(PTK, 0, KCK_bits)
    The PTK-KCK is used by IEEE Std 802.1X-2020 to provided data origin authenticity in the 4-way handshake and group key handshake messages.
    */
    memcpy(ctx.ptk_kck, ctx.ptk, kck_bytes); 

    /* IEEE 802.11 12.7.1.3
    The PTK-KEK shall be computed as the next KEK_bits bits of the PTK:
        PTK-KEK = ExtractBits(PTK, KCK_bits, KEK_bits)
    The PTK-KEK is used by the EAPOL-Key frames to provide data confidentiality in the 4-way handshake and group key handshake messages.
    */
    memcpy(ctx.ptk_kek, ctx.ptk + kck_bytes, kek_bits / 8); 

    em_printfout("Derived PTK for 4-way handshake with '" MACSTRFMT "'", MAC2STR(src_mac));

    // Verify the MIC
    if (!verify_mic(ctx, frame, len)) {
        em_printfout("MIC verification failed for EAPOL frame 2 in 4-way handshake with '" MACSTRFMT "'", MAC2STR(src_mac));
        return false;
    }
    em_printfout("MIC verification succeeded for EAPOL frame 2 in 4-way handshake with '" MACSTRFMT "'", MAC2STR(src_mac));

    // Build the third frame of the 4-way handshake
    em_printfout("Building EAPOL frame 3 for 4-way handshake with '" MACSTRFMT "'", MAC2STR(src_mac));
    auto [eapol_frame_3, frame_len] = build_pw_eapol_frame_3(ctx);
    if (eapol_frame_3 == nullptr || frame_len == 0) {
        em_printfout("Failed to build EAPOL frame 3 for 4-way handshake with '" MACSTRFMT "'", MAC2STR(src_mac));
        return false;
    }
    if (!m_send_1905_eapol_encap_msg(eapol_frame_3, frame_len, src_mac)){
        em_printfout("Failed to send EAPOL frame 3 for 4-way handshake with '" MACSTRFMT "'", MAC2STR(src_mac));
        free(eapol_frame_3);
        return false;
    }
    em_printfout("Sent EAPOL frame 3 for 4-way handshake with '" MACSTRFMT "'", MAC2STR(src_mac));
    ctx.sent_eapol_idx = 3; // Update the sent EAPOL index to 3, indicating we sent the third frame of the 4-way handshake

    return true;
}

bool ec_1905_encrypt_layer_t::handle_pw_eapol_frame_3(ec_1905_key_ctx &ctx, uint8_t *frame, uint16_t len, uint8_t src_mac[ETH_ALEN])
{

    EM_ASSERT_NOT_NULL(frame, {}, "EAPOL frame is null");
    EM_ASSERT_MSG_TRUE(len >= sizeof(ieee802_1x_hdr_t) + sizeof(eapol_packet_t), {}, 
        "EAPOL frame length is too small to contain EAPOL header and packet");
    EM_ASSERT_NOT_NULL(src_mac, {}, "Source MAC address is null in EAPOL frame");

    eapol_packet_t *eapol_packet = reinterpret_cast<eapol_packet_t *>(frame + sizeof(ieee802_1x_hdr_t));

    /* IEEE 802.11 12.7.6.4 (minimized for 1905/EasyMesh)

    On reception of message 3, the Supplicant shall silently discard the message if the Key Replay Counter field value 
    has already been used or if the ANonce value in message 3 differs from the ANonce value in message 1.

    b) Verify the message 3 MIC or AEAD decryption operation result. If the calculated MIC does not match the MIC that 
    the Authenticator included in the EAPOL-Key PDU or AEAD decryption operation returns failure, the Supplicant shall silently discard message 3.
    c) Update the last-seen value of the Key Replay Counter field.
    e) Construct message 4.
    f)  Send message 4 to the Authenticator.
    g) Use the MLME-SETKEYS.request primitive to configure the IEEE 802.11 MAC to send and, if the receive key has not yet been installed, 
    to receive individually addressed MPDUs proected by the PTK. The GTK is also configured by using the (#7191)MLME-SETKEYS.request
    primitive.
    */

    em_printfout("Received EAPOL frame 3 for 4-way handshake with '" MACSTRFMT "'", MAC2STR(src_mac));

    if (eapol_packet->key_replay_counter <= ctx.curr_replay_counter) {
        em_printfout("Received EAPOL frame with replay counter %llu that is less than or equal to current replay counter %llu, discarding",
            eapol_packet->key_replay_counter, ctx.curr_replay_counter);
        return false;
    }
    
    if (memcmp(eapol_packet->key_nonce, ctx.a_nonce, sizeof(ctx.a_nonce)) != 0) {
        em_printfout("Received EAPOL frame with ANonce that does not match stored ANonce, discarding");
        return false;
    }

    // Verify MIC
    if (!verify_mic(ctx, frame, len)) {
        em_printfout("MIC verification failed for EAPOL frame 3 in 4-way handshake with '" MACSTRFMT "'", MAC2STR(src_mac));
        return false;
    }
    em_printfout("MIC verification succeeded for EAPOL frame 3 in 4-way handshake with '" MACSTRFMT "'", MAC2STR(src_mac));

    // The wrapped key data is located after the MIC and the length field in the EAPOL packet
    uint16_t mic_len_bytes = mic_kck_bits / 8; // Length of the MIC in bytes
    uint16_t wrapped_len = 0;
    memcpy(&wrapped_len, eapol_packet->mic_len_key + mic_len_bytes, sizeof(uint16_t));
    uint8_t* wrapped_data = eapol_packet->mic_len_key + mic_len_bytes + sizeof(uint16_t); 
    
    auto [unwrapped_key_data, unwrapped_key_data_len] = decrypt_key_data(ctx, wrapped_data, wrapped_len);
    if (unwrapped_key_data == nullptr || unwrapped_key_data_len == 0) {
        em_printfout("Failed to decrypt Key Data for EAPOL frame 3 in 4-way handshake with '" MACSTRFMT "'", MAC2STR(src_mac));
        return false;
    }

    eapol_kde_t* gtk_kde = reinterpret_cast<eapol_kde_t*>(unwrapped_key_data);
    if (gtk_kde->data_type != EAPOL_KDE_TYPE_1905_GTK) {
        em_printfout("Unwrapped key data is not a Group Key, discarding");
        return false;
    }
    // EasyMesh Table 12
    gtk_1905_kde_t* gtk_kde_data = reinterpret_cast<gtk_1905_kde_t*>(gtk_kde->data);
    EM_ASSERT_MSG_TRUE(gtk_kde_data->key_id != 0, false, "Key ID must not be 0 in 1905 group key handshake");
    memcpy(this->m_gtk, gtk_kde_data->gtk, sizeof(this->m_gtk));
    this->m_gtk_id = gtk_kde_data->key_id;

    em_printfout("Unwrapped Group Key Data for 4-way handshake with '" MACSTRFMT "'", MAC2STR(src_mac));

    // Update the current replay counter
    ctx.curr_replay_counter = eapol_packet->key_replay_counter;

    // Build and send the fourth frame of the 4-way handshake
    em_printfout("Building EAPOL frame 4 for 4-way handshake with '" MACSTRFMT "'", MAC2STR(src_mac));
    auto [eapol_frame_4, frame_len] = build_pw_eapol_frame_3(ctx);
    if (eapol_frame_4 == nullptr || frame_len == 0) {
        em_printfout("Failed to build EAPOL frame 4 for 4-way handshake with '" MACSTRFMT "'", MAC2STR(src_mac));
        return false;
    }
    if (!m_send_1905_eapol_encap_msg(eapol_frame_4, frame_len, src_mac)){
        em_printfout("Failed to send EAPOL frame 4 for 4-way handshake with '" MACSTRFMT "'", MAC2STR(src_mac));
        free(eapol_frame_4);
        return false;
    }

    em_printfout("Sent EAPOL frame 4 for 4-way handshake with '" MACSTRFMT "'", MAC2STR(src_mac));
    ctx.sent_eapol_idx = 4; // Update the sent EAPOL index to 4, indicating we sent the fourth frame of the 4-way handshake

    //MLME-SETKEYS.request (GTK, PTK)
    if (!set_key(ctx.ptk, sizeof(ctx.ptk), 0, true, src_mac, 0)){
        em_printfout("Failed to save PTK for 4-way handshake with '" MACSTRFMT "'", MAC2STR(src_mac));
        free(eapol_frame_4);
        return false;
    }
    if (!set_key(this->m_gtk, sizeof(this->m_gtk), this->m_gtk_id, false, src_mac, m_gtk_rekey_counter)){
        em_printfout("Failed to save GTK for 4-way handshake with '" MACSTRFMT "'", MAC2STR(src_mac));
        free(eapol_frame_4);
        return false;
    }

    // Installed keys, removing from the context
    ec_crypto::rand_zero(ctx.ptk, sizeof(ctx.ptk));
    ec_crypto::rand_zero(this->m_gtk, sizeof(this->m_gtk));
    
    return true;
}

bool ec_1905_encrypt_layer_t::handle_pw_eapol_frame_4(ec_1905_key_ctx &ctx, uint8_t *frame, uint16_t len, uint8_t src_mac[ETH_ALEN])
{
    EM_ASSERT_NOT_NULL(frame, {}, "EAPOL frame is null");
    EM_ASSERT_MSG_TRUE(len >= sizeof(ieee802_1x_hdr_t) + sizeof(eapol_packet_t), {}, 
        "EAPOL frame length is too small to contain EAPOL header and packet");
    EM_ASSERT_NOT_NULL(src_mac, {}, "Source MAC address is null in EAPOL frame");

    eapol_packet_t *eapol_packet = reinterpret_cast<eapol_packet_t *>(frame + sizeof(ieee802_1x_hdr_t));
    
    /* IEEE 802.11 12.7.6.5 (minimized for 1905/EasyMesh)

    On reception of message 4, the Authenticator verifies that the Key Replay Counter field value is one that it 
    used on this 4-way handshake and is strictly larger than that in any other EAPOL-Key PDU that has the Request bit 
    in the Key Information field set to 0 and that has been received during this session; if it is not, 
    it silently discards the message. Otherwise:

    a) The Authenticator checks the MIC or AEAD decryption operation result. If the calculated MIC does not match the MIC 
    that the Supplicant included in the EAPOL-Key PDU or AEAD decryption operation returns failure, 
    the Authenticator shall silently discard message 4.

    b) If the MIC is valid, the Authenticator uses the MLME-SETKEYS.request primitive to configure the 
    IEEE 802.11 MAC to send and, if the receive key has not yet been installed, to receive protected, 
    individually addressed MPDUs using for the new PTK. 

    c) The Authenticator updates the Key Replay Counter field so that it uses a fresh value if a rekey becomes necessary.
    */

    em_printfout("Received EAPOL frame 4 for 4-way handshake with '" MACSTRFMT "'", MAC2STR(src_mac));

    if (eapol_packet->key_replay_counter != ctx.curr_replay_counter) {
        em_printfout("Received EAPOL frame with replay counter %llu that does not match current replay counter %llu, discarding",
            eapol_packet->key_replay_counter, ctx.curr_replay_counter);
        return false;
    }

    if (!verify_mic(ctx, frame, len)) {
        em_printfout("MIC verification failed for EAPOL frame 4 in 4-way handshake with '" MACSTRFMT "'", MAC2STR(src_mac));
        return false;
    }

    // MLME-SETKEYS.request
    if (!set_key(ctx.ptk, sizeof(ctx.ptk), 0, true, src_mac, 0)){
        em_printfout("Failed to save PTK for 4-way handshake with '" MACSTRFMT "'", MAC2STR(src_mac));
        return false;
    }
    ctx.curr_replay_counter++; // Update the current replay counter to a fresh value

    em_printfout("4-way handshake with '" MACSTRFMT "' completed successfully", MAC2STR(src_mac));

    // Installed key, removing from the context
    ec_crypto::rand_zero(ctx.ptk, sizeof(ctx.ptk));
    return true;
}

bool ec_1905_encrypt_layer_t::handle_group_eapol_frame_1(ec_1905_key_ctx &ctx, uint8_t *frame, uint16_t len, uint8_t src_mac[ETH_ALEN])
{
    EM_ASSERT_NOT_NULL(frame, {}, "EAPOL frame is null");
    EM_ASSERT_MSG_TRUE(len >= sizeof(ieee802_1x_hdr_t) + sizeof(eapol_packet_t), {}, 
        "EAPOL frame length is too small to contain EAPOL header and packet");
    EM_ASSERT_NOT_NULL(src_mac, {}, "Source MAC address is null in EAPOL frame");

    eapol_packet_t *eapol_packet = reinterpret_cast<eapol_packet_t *>(frame + sizeof(ieee802_1x_hdr_t));

    /* IEEE 802.11 12.7.7.2 (minimized for 1905/EasyMesh)
    
    On reception of message 1, the Supplicant:
        a) Verifies that the Key Replay Counter field value has not yet been seen before, i.e., its value is
        strictly larger than that in any other EAPOL-Key PDU received thus far during this session.
        c) Verifies that the MIC is valid, i.e., it uses the PTK-KCK that is part of the PTK to verify that
        there is no data integrity error, or that the AEAD decryption steps succeed.
        d) Uses the MLME-SETKEYS.request primitive to configure the GTK...
        e) Responds by creating and sending message 2 of the group key handshake to the Authenticator and
        incrementing the replay counter.
    */

    if (eapol_packet->key_replay_counter <= ctx.curr_replay_counter) {
        em_printfout("Received EAPOL frame with replay counter %llu that is less than or equal to current replay counter %llu, discarding",
            eapol_packet->key_replay_counter, ctx.curr_replay_counter);
        return false;
    }
    ctx.curr_replay_counter = eapol_packet->key_replay_counter;

    if (!verify_mic(ctx, frame, len)) {
        em_printfout("MIC verification failed for EAPOL frame 1 in group key handshake with '" MACSTRFMT "'", MAC2STR(src_mac));
        return false;
    }
    em_printfout("MIC verification succeeded for EAPOL frame 1 in group key handshake with '" MACSTRFMT "'", MAC2STR(src_mac));

    // The wrapped key data is located after the MIC and the length field in the EAPOL packet
    uint16_t mic_len_bytes = mic_kck_bits / 8; // Length of the MIC in bytes
    uint16_t wrapped_len = 0;
    memcpy(&wrapped_len, eapol_packet->mic_len_key + mic_len_bytes, sizeof(uint16_t));
    uint8_t* wrapped_data = eapol_packet->mic_len_key + mic_len_bytes + sizeof(uint16_t); 
    

    auto [unwrapped_key_data, unwrapped_len] = decrypt_key_data(ctx, wrapped_data, wrapped_len);
    if (unwrapped_key_data == nullptr || unwrapped_len == 0) {
        em_printfout("Failed to decrypt key data in EAPOL frame 1 in group key handshake with '" MACSTRFMT "'", MAC2STR(src_mac));
        return false;
    }

    eapol_kde_t* gtk_kde = reinterpret_cast<eapol_kde_t*>(unwrapped_key_data);
    if (gtk_kde->data_type != EAPOL_KDE_TYPE_1905_GTK) {
        em_printfout("Unwrapped key data is not a Group Key, discarding");
        return false;
    }

    // EasyMesh Table 12
    gtk_1905_kde_t* gtk_kde_data = reinterpret_cast<gtk_1905_kde_t*>(gtk_kde->data);
    EM_ASSERT_MSG_TRUE(gtk_kde_data->key_id != 0, false, "Key ID must not be 0 in 1905 group key handshake");
    memcpy(this->m_gtk, gtk_kde_data->gtk, sizeof(this->m_gtk));
    this->m_gtk_id = gtk_kde_data->key_id;

    em_printfout("Unwrapped Group Key Data for 4-way handshake with '" MACSTRFMT "'", MAC2STR(src_mac));

    // Update the current replay counter
    ctx.curr_replay_counter = eapol_packet->key_replay_counter;

    if (!set_key(this->m_gtk, sizeof(this->m_gtk), this->m_gtk_id, false, src_mac, m_gtk_rekey_counter)){
        em_printfout("Failed to save GTK for group key handshake with '" MACSTRFMT "'", MAC2STR(src_mac));
        return false;
    }

    // Installed key, removing from the context
    ec_crypto::rand_zero(this->m_gtk, sizeof(this->m_gtk));

    em_printfout("Saved GTK for group key handshake with '" MACSTRFMT "'", MAC2STR(src_mac));

    // Build and send the second frame of the group key handshake
    auto [eapol_frame_2, frame_len] = build_group_eapol_frame_2(ctx);
    if (eapol_frame_2 == nullptr || frame_len == 0) {
        em_printfout("Failed to build EAPOL frame 2 for group key handshake with '" MACSTRFMT "'", MAC2STR(src_mac));
        return false;
    }
    if (!m_send_1905_eapol_encap_msg(eapol_frame_2, frame_len, src_mac)){
        em_printfout("Failed to send EAPOL frame 2 for group key handshake with '" MACSTRFMT "'", MAC2STR(src_mac));
        free(eapol_frame_2);
        return false;
    }
    em_printfout("Sent EAPOL frame 2 for group key handshake with '" MACSTRFMT "'", MAC2STR(src_mac));
    ctx.sent_eapol_idx = 2; // Update the sent EAPOL index to 2, indicating we sent the second frame of the group key handshake

    // Increment the replay counter 
    ctx.curr_replay_counter++;
    return true;
}

bool ec_1905_encrypt_layer_t::handle_group_eapol_frame_2(ec_1905_key_ctx &ctx, uint8_t *frame, uint16_t len, uint8_t src_mac[ETH_ALEN])
{

    EM_ASSERT_NOT_NULL(frame, {}, "EAPOL frame is null");
    EM_ASSERT_MSG_TRUE(len >= sizeof(ieee802_1x_hdr_t) + sizeof(eapol_packet_t), {}, 
        "EAPOL frame length is too small to contain EAPOL header and packet");
    EM_ASSERT_NOT_NULL(src_mac, {}, "Source MAC address is null in EAPOL frame");

    eapol_packet_t *eapol_packet = reinterpret_cast<eapol_packet_t *>(frame + sizeof(ieee802_1x_hdr_t));

    /* IEEE 802.11 12.7.7.3 (minimized for 1905/EasyMesh)
    On reception of message 2, the Authenticator:
        a) Verifies that the Key Replay Counter field value matches one it has used in the group key
        handshake.
        c) Verifies that the MIC is valid, i.e., it uses the PTK-KCK that is part of the PTK to verify that
        there is no data integrity error, or that the AEAD decryption steps succeed
    */

    em_printfout("Received EAPOL frame 2 for group key handshake with '" MACSTRFMT "'", MAC2STR(src_mac));

    if (eapol_packet->key_replay_counter != ctx.curr_replay_counter) {
        em_printfout("Received EAPOL frame with replay counter %llu that does not match current replay counter %llu, discarding",
            eapol_packet->key_replay_counter, ctx.curr_replay_counter);
        return false;
    }
    
    if (!verify_mic(ctx, frame, len)) {
        em_printfout("MIC verification failed for EAPOL frame 2 in group key handshake with '" MACSTRFMT "'", MAC2STR(src_mac));
        return false;
    }
    em_printfout("MIC verification succeeded for EAPOL frame 2 in group key handshake with '" MACSTRFMT "'", MAC2STR(src_mac));

    em_printfout("Group key handshake with '" MACSTRFMT "' completed successfully", MAC2STR(src_mac)); 

    return true;
}

eapol_packet_t* ec_1905_encrypt_layer_t::validate_eapol_frame(ec_1905_key_ctx &ctx, uint8_t *eapol_frame, size_t eapol_frame_len)
{
    ieee802_1x_hdr_t* eapol_hdr = reinterpret_cast<ieee802_1x_hdr_t*>(eapol_frame);
    EM_ASSERT_EQUALS(eapol_hdr->version, EAPOL_VERSION, NULL, "802.1X version mismatch in frame parsing");
    EM_ASSERT_EQUALS(eapol_hdr->type, IEEE802_1X_TYPE_EAPOL_KEY, NULL, "802.1X type mismatch in frame parsing");

    eapol_packet_t* eapol_packet = reinterpret_cast<eapol_packet_t*>(eapol_frame + sizeof(ieee802_1x_hdr_t));

    auto key_info = eapol_packet->key_info.bits;

    if (key_info.key_descriptor_version != 0) {
        em_printfout("Unsupported key descriptor version %d in EAPOL frame", key_info.key_descriptor_version);
        return NULL;
    }
    return eapol_packet;
}

bool ec_1905_encrypt_layer_t::compute_gtk(const EVP_MD *algo, uint8_t aa[ETH_ALEN]) {
    
    // Generate GNonce (32 bytes)
    uint8_t g_nonce[32];
    if (RAND_bytes(g_nonce, sizeof(g_nonce)) != 1) {
        return false;
    }
    
    // Build context: AA || GNonce
    // Total context length: 6 + 32 = 38 bytes
    uint8_t context[38];
    size_t offset = 0;
    
    // AA (Authenticator Address)
    memcpy(context + offset, aa, ETH_ALEN);
    offset += ETH_ALEN;
    
    // GNonce
    memcpy(context + offset, g_nonce, sizeof(g_nonce));
    offset += sizeof(g_nonce);
    
    // Call KDF: GTK = KDF-ALGO-Sizeof(GTK)(GMK, "Group key expansion", AA || GNonce)
    if (!em_crypto_t::kdf_hash_length(algo, m_gmk.data(), m_gmk.size(), "Group key expansion", 
                                      context, sizeof(context), m_gtk, sizeof(m_gtk))){
        return false;
    }

    this->m_gtk_id++;
    if (this->m_gtk_id > 3) {
        this->m_gtk_id = 1; // Wrap around GTK ID
    }
    return true;
}

bool ec_1905_encrypt_layer_t::compute_ptk(const EVP_MD *algo, ec_1905_key_ctx &ctx, uint8_t aa[ETH_ALEN], uint8_t spa[ETH_ALEN]) {
    
    uint8_t *min_aa_spa, *max_aa_spa;
    uint8_t *min_nonce, *max_nonce;
    
    if (memcmp(aa, spa, 6) <= 0) {
        min_aa_spa = aa;
        max_aa_spa = spa;
    } else {
        min_aa_spa = spa;
        max_aa_spa = aa;
    }
    
    if (memcmp(ctx.a_nonce, ctx.s_nonce, 32) <= 0) {
        min_nonce = ctx.a_nonce;
        max_nonce = ctx.s_nonce;
    } else {
        min_nonce = ctx.s_nonce;
        max_nonce = ctx.a_nonce;
    }
    
    // Build context: Min(AA,SPA) || Max(AA,SPA) || Min(ANonce,SNonce) || Max(ANonce,SNonce)
    // Total context length: 6 + 6 + 32 + 32 = 76 bytes
    uint8_t context[76];
    size_t offset = 0;
    
    // Min(AA,SPA)
    memcpy(context + offset, min_aa_spa, ETH_ALEN);
    offset += ETH_ALEN;
    
    // Max(AA,SPA)
    memcpy(context + offset, max_aa_spa, ETH_ALEN);
    offset += ETH_ALEN;
    
    // Min(ANonce,SNonce)
    memcpy(context + offset, min_nonce, 32);
    offset += 32;
    
    // Max(ANonce,SNonce)
    memcpy(context + offset, max_nonce, 32);
    offset += 32;
    
    // Call KDF: PTK = KDF-ALGO-Sizeof(PTK)(PMK, "Pairwise key expansion", context)
    return em_crypto_t::kdf_hash_length(algo, ctx.pmk, sizeof(ctx.pmk), "Pairwise key expansion", 
                                        context, sizeof(context), ctx.ptk, sizeof(ctx.ptk));
}

bool ec_1905_encrypt_layer_t::set_key(uint8_t *key, size_t key_len, uint16_t key_id, bool is_pairwise, uint8_t mac[ETH_ALEN], uint64_t recv_seq_counter)
{
    // TODO: SoftHSM
    // if (is_pairwise) ignore `recv_seq_counter`
    return false;
}