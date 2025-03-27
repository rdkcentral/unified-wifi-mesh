#include "ec_ctrl_configurator.h"

#include "ec_base.h"
#include "ec_util.h"
#include "util.h"
#include "cjson/cJSON.h"
#include "cjson_util.h"
#include "em_crypto.h"

bool ec_ctrl_configurator_t::process_chirp_notification(em_dpp_chirp_value_t *chirp_tlv, uint16_t tlv_len)
{

    mac_addr_t mac = {0};
    uint8_t hash[255] = {0}; // Max hash length to avoid dynamic allocation
    uint8_t hash_len = 0;

    if (!ec_util::parse_dpp_chirp_tlv(chirp_tlv, tlv_len, &mac, reinterpret_cast<uint8_t**>(&hash), &hash_len)) {
        printf("%s:%d: Failed to parse DPP Chirp TLV\n", __func__, __LINE__);
        return false;
    }

    // Validate hash
    // Compute the hash of the responder boot key 
    uint8_t *resp_boot_key_chirp_hash = ec_crypto::compute_key_hash(m_boot_data.responder_boot_key, "chirp");
    if (resp_boot_key_chirp_hash == NULL) {
        printf("%s:%d unable to compute \"chirp\" responder bootstrapping key hash\n", __func__, __LINE__);
        return false;
    }

    if (memcmp(hash, resp_boot_key_chirp_hash, hash_len) != 0) {
        // Hashes don't match, don't initiate DPP authentication
        printf("%s:%d: Chirp notification hash and DPP URI hash did not match! Stopping DPP!\n", __func__, __LINE__);
        free(resp_boot_key_chirp_hash);
        return false;
    }

    free(resp_boot_key_chirp_hash);
    std::string mac_str = util::mac_to_string(mac);
    if (m_connections.find(mac_str) == m_connections.end()) {
        // New connection context
        ec_connection_context_t conn_ctx;
        m_connections[mac_str] = conn_ctx;
    }
    auto [auth_frame, auth_frame_len] = create_auth_request(mac_str);
    if (auth_frame == NULL || auth_frame_len == 0) {
        printf("%s:%d: Failed to create authentication request frame\n", __func__, __LINE__);
        return false;
    }

    // Create Auth Request Encap TLV: EasyMesh 5.3.4
    auto [encap_dpp_tlv, encap_dpp_size] = ec_util::create_encap_dpp_tlv(0, mac, ec_frame_type_auth_req, auth_frame, static_cast<uint8_t> (auth_frame_len));
    if (encap_dpp_tlv == NULL) {
        printf("%s:%d: Failed to create Encap DPP TLV\n", __func__, __LINE__);
        return false;
    }

    free(auth_frame);

    // Create Auth Request Chirp TLV: EasyMesh 5.3.4
    size_t data_size = sizeof(mac_addr_t) + hash_len + sizeof(uint8_t);
    em_dpp_chirp_value_t* chirp = reinterpret_cast<em_dpp_chirp_value_t*>(calloc(sizeof(em_dpp_chirp_value_t) + data_size, 1));
    if (chirp == NULL) {
        printf("%s:%d: Failed to allocate memory for chirp TLV\n", __func__, __LINE__);
        free(encap_dpp_tlv);
        return false;
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
    this->m_send_prox_encap_dpp_msg(encap_dpp_tlv, encap_dpp_size, chirp, sizeof(em_dpp_chirp_value_t) + data_size);

    free(encap_dpp_tlv);
    free(chirp);
    
    return true; 
}

bool ec_ctrl_configurator_t::process_proxy_encap_dpp_msg(em_encap_dpp_t *encap_tlv, uint16_t encap_tlv_len, em_dpp_chirp_value_t *chirp_tlv, uint16_t chirp_tlv_len)
{
    if (encap_tlv == NULL || encap_tlv_len == 0) {
        printf("%s:%d: Encap DPP TLV is empty\n", __func__, __LINE__);
        return false;
    }

    
    mac_addr_t dest_mac = {0};
    uint8_t frame_type = 0;
    uint8_t* encap_frame = NULL;
    uint16_t encap_frame_len = 0;

    if (!ec_util::parse_encap_dpp_tlv(encap_tlv, encap_tlv_len, &dest_mac, &frame_type, &encap_frame, &encap_frame_len)) {
        printf("%s:%d: Failed to parse Encap DPP TLV\n", __func__, __LINE__);
        return false;
    }

    bool did_finish = false;

    ec_frame_type_t ec_frame_type = static_cast<ec_frame_type_t>(frame_type);
    switch (ec_frame_type) {
        case ec_frame_type_recfg_announcement: {
            auto [recfg_auth_frame, recfg_auth_frame_len] = create_recfg_auth_request();
            if (recfg_auth_frame == NULL || recfg_auth_frame_len == 0) {
                printf("%s:%d: Failed to create reconfiguration authentication request frame\n", __func__, __LINE__);
                break;
            }
            auto [encap_dpp_tlv, encap_dpp_size] = ec_util::create_encap_dpp_tlv(0, dest_mac, ec_frame_type_recfg_auth_req, recfg_auth_frame, static_cast<uint8_t> (recfg_auth_frame_len));
            if (encap_dpp_tlv == NULL) {
                printf("%s:%d: Failed to create Encap DPP TLV\n", __func__, __LINE__);
                free(recfg_auth_frame);
                break;
            }
            free(recfg_auth_frame);
            // Send the encapsulated ReCfg Auth Request message (with Encap TLV)
            // TODO: SEND TO ALL AGENTS
            this->m_send_prox_encap_dpp_msg(encap_dpp_tlv, encap_dpp_size, NULL, 0);
            did_finish = true;
            free(encap_dpp_tlv);
            break;
        }
        case ec_frame_type_auth_rsp: {
            did_finish = handle_auth_response(reinterpret_cast<ec_frame_t*>(encap_frame), encap_frame_len, dest_mac);
            break;
        }
        case ec_frame_type_easymesh: {
            did_finish = handle_proxied_dpp_configuration_request(encap_frame, encap_frame_len, dest_mac);
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

bool ec_ctrl_configurator_t::handle_proxied_dpp_configuration_request(uint8_t *encap_frame, uint16_t encap_frame_len, uint8_t src_mac[ETH_ALEN])
{
    // EasyConnect 6.4.3.1 DPP Configuration Response Configurator Handling
    if (!encap_frame || encap_frame_len == 0) {
        printf("%s:%d: Invalid encapsulated frame!\n", __func__, __LINE__);
        return false;
    }
    std::string e_mac = util::mac_to_string(src_mac);
    auto conn_ctx = get_conn_ctx(e_mac);
    auto e_ctx = get_eph_ctx(e_mac);
    ASSERT_NOT_NULL(conn_ctx, false, "%s:%d: No Configurator connection context for Enrollee '" MACSTRFMT "'\n", __func__, __LINE__, MAC2STR(src_mac));
    ASSERT_NOT_NULL(conn_ctx->net_access_key, false, "%s:%d: Enrollee '" MACSTRFMT "' netAccessKey is NULL!\n", __func__, __LINE__, MAC2STR(src_mac));
    ASSERT_NOT_NULL(e_ctx, false, "%s:%d: No ephemeral context found for Enrollee '" MACSTRFMT "'\n", __func__, __LINE__, MAC2STR(src_mac));
    ec_gas_initial_request_frame_t *initial_request_frame = reinterpret_cast<ec_gas_initial_request_frame_t *>(encap_frame);

    uint8_t session_dialog_token = initial_request_frame->base.dialog_token;
    ec_attribute_t *wrapped_attrs = ec_util::get_attrib(initial_request_frame->query, initial_request_frame->query_len, ec_attrib_id_wrapped_data);
    ASSERT_NOT_NULL(wrapped_attrs, false, "%s:%d: No wrapped data attribute found!\n", __func__, __LINE__);
    
    ASSERT_NOT_NULL(e_ctx->ke, false, "%s:%d: Ephemeral context for Enrollee '" MACSTRFMT "' does not contain valid key 'ke'!\n", __func__, __LINE__, MAC2STR(src_mac));
    auto [unwrapped_attrs, unwrapped_attrs_len] = ec_util::unwrap_wrapped_attrib(wrapped_attrs, reinterpret_cast<uint8_t*>(initial_request_frame), encap_frame_len, initial_request_frame->query, true, e_ctx->ke);
    if (unwrapped_attrs == nullptr || unwrapped_attrs_len == 0) {
        printf("%s:%d: Failed to unwraped wrapped data, aborting!\n", __func__, __LINE__);
        return false;
    }
    auto e_nonce_attr = ec_util::get_attrib(unwrapped_attrs, unwrapped_attrs_len, ec_attrib_id_enrollee_nonce);
    ASSERT_NOT_NULL_FREE(e_nonce_attr, false, unwrapped_attrs, "%s:%d: No Enrollee nonce attribute found!\n", __func__, __LINE__);
    uint16_t e_nonce_len = e_nonce_attr->length;

    auto dpp_config_request_obj_attr = ec_util::get_attrib(unwrapped_attrs, unwrapped_attrs_len, ec_attrib_id_dpp_config_req_obj);
    ASSERT_NOT_NULL_FREE(dpp_config_request_obj_attr, false, unwrapped_attrs, "%s:%d: No DPP Configuration Request Object found in DPP Configuration Request frame!\n", __func__, __LINE__);

    // If the Configurator does not want to configure the Enrollee, for example if the Enrollee wishes to be enrolled as an AP and
    // there are already enough APs in the network, the Configurator shall respond with a DPP Configuration Response
    // indicating failure by adding the DPP Status field set to STATUS_CONFIGURE_FAILURE and wrapped data consisting of
    // the Enrollee’s nonce wrapped in ke:
    // Configurator → Enrollee: DPP Status, { E-nonce }ke

    // If the Configurator is not able to proceed immediately with the DPP Configuration protocol and the delay would be too long
    // to handle using the GAS Comeback mechanism specified below, e.g. because a user decision is required, the
    // Configurator shall respond with a DPP Configuration Response by adding the DPP Status field set to
    // STATUS_CONFIGURE_PENDING and wrapped data consisting of the Enrollee’s nonce wrapped in ke:
    // Configurator → Enrollee: DPP Status, { E-nonce }ke
    bool cannot_onboard_more = (m_can_onboard_additional_aps == nullptr || !m_can_onboard_additional_aps());
    if (cannot_onboard_more) {
        printf("%s:%d: DPP Configuration Request frame received, but we cannot onboard any more APs! Rejecting with status %s\n", __func__, __LINE__, ec_util::status_code_to_string(DPP_STATUS_CONFIGURATION_FAILURE).c_str());
        auto [frame, frame_len] = ec_util::alloc_gas_frame(dpp_gas_action_type_t::dpp_gas_comeback_resp, session_dialog_token);
        if (frame == nullptr || frame_len == 0) {
            printf("%s:%d: Failed to create DPP Configuration Response frame!\n", __func__, __LINE__);
            return false;
        }
        ec_gas_initial_response_frame_t *response_frame = reinterpret_cast<ec_gas_initial_response_frame_t *>(frame);
        // XXX: Note: for GAS comeback case, all logic in this scope remains, but status code becomes STATUS_CONFIGURE_PENDING
        response_frame->status_code = DPP_STATUS_CONFIGURATION_FAILURE;
        uint8_t *attribs = nullptr;
        size_t attribs_len = 0;
        attribs = ec_util::add_wrapped_data_attr(reinterpret_cast<uint8_t *>(response_frame), sizeof(ec_gas_initial_response_frame_t), attribs, &attribs_len, true, e_ctx->ke, [&](){
            size_t wrapped_len = 0;
            uint8_t *wrapped_attribs = ec_util::add_attrib(nullptr, &wrapped_len, ec_attrib_id_enrollee_nonce, e_nonce_len, e_ctx->e_nonce);
            return std::make_pair(wrapped_attribs, wrapped_len);
        });
        if ((response_frame = reinterpret_cast<ec_gas_initial_response_frame_t*>(ec_util::copy_attrs_to_frame(reinterpret_cast<uint8_t*>(response_frame), sizeof(ec_gas_initial_response_frame_t), attribs, attribs_len))) == nullptr) {
            printf("%s:%d: Failed to copy attribs to DPP Configuration Response frame!\n", __func__, __LINE__);
            free(attribs);
            free(response_frame);
            return false;
        }
        response_frame->resp_len = static_cast<uint16_t>(attribs_len);
        auto [proxy_encap_frame, proxy_encap_frame_len] = ec_util::create_encap_dpp_tlv(true, src_mac, ec_frame_type_easymesh, reinterpret_cast<uint8_t*>(response_frame), sizeof(*response_frame) + attribs_len);
        if (proxy_encap_frame == nullptr || proxy_encap_frame_len == 0) {
            printf("%s:%d: Could not create Proxied Encap DPP TLV!\n", __func__, __LINE__);
            free(response_frame);
            free(attribs);
            return false;
        }
        printf("%s:%d: Sending DPP Configuration Response frame for Enrollee '" MACSTRFMT "' over 1905 with DPP status code %s\n", __func__, __LINE__, MAC2STR(src_mac), ec_util::status_code_to_string(static_cast<ec_status_code_t>(response_frame->status_code)).c_str());
        bool sent = m_send_prox_encap_dpp_msg(proxy_encap_frame, proxy_encap_frame_len, nullptr, proxy_encap_frame_len);
        if (!sent) {
            printf("%s:%d: Failed to send DPP Configuration Response for Enrollee '" MACSTRFMT "'\n", __func__, __LINE__, MAC2STR(src_mac));
        }
        free(response_frame);
        free(attribs);
        return sent;
    }

    // GAS frame fragmentation / comeback delay / MUD URL
    SPEC_TODO_NOT_FATAL("EasyConnect", "v3.0", "6.4.3.1",
        "If the Enrollee included a new protocol key in the DPP Configuration Request frame but the Configurator did not request "
        "one, the Configurator shall fail provisioning. If the Enrollee included a new protocol key in the DPP Configuration Request "
        "frame and the Configurator requested a new protocol key with a previous STATUS_NEW_KEY_NEEDED response, the "
        "Configurator extracts the Enrollee's new protocol key, Pe, and the Enrollee's Proof-of-Possession (POP) tag, Auth-I. It "
        "then verifies that Pe is a valid point on the curve, and generates shared secrets and a provisional POP tag, Auth-I', as "
        "follows:\n"
        "    S = pc * Pe\n"
        "    k = HKDF(bk, \"New DPP Protocol Key\", S.x)\n"
        "    Auth-I' = HMAC (k, E-nonce | Pc.x | Pe.x)\n"
        "where bk is the base key generated in section 6.3. The underlying hash function used with both HKDF and HMAC shall "
        "be the one used to generate bk in the DPP Authentication protocol and Reconfiguration Authentication protocol. If Auth-I "
        "differs from Auth-I', the Configurator shall terminate the DPP Configuration exchange. Otherwise, it generates (a) DPP "
        "Configuration object(s) containing the Enrollee's new protocol key and replies indicating success.\n"
        "If the Configurator is provisioning for an 802.1X/EAP network using certificates to authenticate and the configRequest did "
        "not contain a Certification Request, the Configurator responds with a DPP Configuration Response frame with the DPP "
        "Status field set to STATUS_CSR_NEEDED and wrapped data consisting of the Enrollee's nonce and a base64-encoded "
        "CSR Attributes Request attribute, encoded according to the ASN.1 type definition of \"CsrAttrs\" in section 4.5.2 of RFC "
        "7030 [47], wrapped in ke:\n"
        "Configurator → Enrollee: DPP Status, { E-nonce, CSR Attributes Request }ke"
    );


    // Re-keying
    SPEC_TODO_NOT_FATAL("EasyConnect", "v3.0", "6.4.3.1",
        "If the Enrollee included a new protocol key in the DPP Configuration Request frame but the Configurator did not request "
        "one, the Configurator shall fail provisioning. If the Enrollee included a new protocol key in the DPP Configuration Request "
        "frame and the Configurator requested a new protocol key with a previous STATUS_NEW_KEY_NEEDED response, the "
        "Configurator extracts the Enrollee's new protocol key, Pe, and the Enrollee's Proof-of-Possession (POP) tag, Auth-I. It "
        "then verifies that Pe is a valid point on the curve, and generates shared secrets and a provisional POP tag, Auth-I', as "
        "follows:\n"
        "    S = pc * Pe\n"
        "    k = HKDF(bk, \"New DPP Protocol Key\", S.x)\n"
        "    Auth-I' = HMAC (k, E-nonce | Pc.x | Pe.x)\n"
        "where bk is the base key generated in section 6.3. The underlying hash function used with both HKDF and HMAC shall "
        "be the one used to generate bk in the DPP Authentication protocol and Reconfiguration Authentication protocol. If Auth-I "
        "differs from Auth-I', the Configurator shall terminate the DPP Configuration exchange. Otherwise, it generates (a) DPP "
        "Configuration object(s) containing the Enrollee's new protocol key and replies indicating success.\n"
        "If the Configurator is provisioning for an 802.1X/EAP network using certificates to authenticate and the configRequest did "
        "not contain a Certification Request, the Configurator responds with a DPP Configuration Response frame with the DPP "
        "Status field set to STATUS_CSR_NEEDED and wrapped data consisting of the Enrollee's nonce and a base64-encoded "
        "CSR Attributes Request attribute, encoded according to the ASN.1 type definition of \"CsrAttrs\" in section 4.5.2 of RFC "
        "7030 [47], wrapped in ke:\n"
        "Configurator → Enrollee: DPP Status, { E-nonce, CSR Attributes Request }ke"
    );
    

    // Enterprise provisioning
    SPEC_TODO_NOT_FATAL("EasyConnect", "v3.0", "6.4.3.1",
        "If the Configurator is provisioning for a network that requires 802.1X/EAP using certificate authentication and the "
        "configRequest contains a Certification Signing Request, the Configurator validates the Certification Signing Request by "
        "checking that the signature in the CSR is valid and that the challengePassword string in the CSR is correct (see below). If "
        "the CSR is invalid, the Configurator shall respond with a DPP Configuration Response frame with DPP Status field set to "
        "STATUS_CSR_BAD with the Enrollee's nonce wrapped in ke. It shall then terminate DPP. If the CSR is valid, the "
        "Configurator forwards the Certification Signing Request on to the CA/RA for certification and responds with a DPP "
        "Configuration Response frame with the GAS Comeback Delay set to how long the Enrollee should wait.\n"
        "The Configurator will respond to subsequent DPP Configuration Request frames (using a GAS Comeback Request frame) "
        "with a DPP Configuration Response frame (using a GAS Comeback Response frame) with a GAS Comeback Delay set to "
        "how long the Enrollee should wait. When a certificate is received, the Configurator shall place the CA's signature "
        "certificate in the CA Certificate parameter and the Enrollee's certificate, and any intermediate certificates, in the Certificate "
        "Bag parameter in the configurationPayload. The next time the Enrollee sends a GAS Comeback Request frame, the full "
        "response is sent.\n"
        "For an example of the enterprise configuration message flow, see Appendix A.1 Using DPP to Configure Enterprise "
        "Credentials."
    );

    // Parse attributes to determine which DPP Configuration Request Object(s) we need to create and reply with.
    cJSON *configuration_request_object = cJSON_ParseWithLength(reinterpret_cast<const char *>(dpp_config_request_obj_attr->data), dpp_config_request_obj_attr->length);
    ASSERT_NOT_NULL_FREE(configuration_request_object, false, unwrapped_attrs, "%s:%d: Failed to parse DPP Configuration Request object!\n", __func__, __LINE__);
    printf("%s:%d: Received JSON configuration request object:\n%s\n", __func__, __LINE__, cJSON_Print(configuration_request_object));

    m_p_ctx.ppk = ec_crypto::create_ppkey_public(m_p_ctx.C_signing_key);
    if (!m_p_ctx.ppk) {
        printf("%s:%d: Failed to generate ppk\n", __func__, __LINE__);
        free(wrapped_attrs);
        return false;
    }
    
    // Create 1905.1 Configuration Object
    cJSON *ieee1905_config_obj = nullptr;
    ASSERT_NOT_NULL_FREE(m_get_1905_info, false, unwrapped_attrs, "%s:%d: Cannot generate 1905 Configuration Object, no callback!\n", __func__, __LINE__);
    {
        // EasyMesh 5.3.3
        // If a Multi-AP Controller sends a DPP Configuration Object for the 1905-layer, it shall set the fields described in Table 6 as
        // follows:
        // - DPP Configuration Object
        // - wi-fi_tech = "map"
        // - Decryption Failure Counter threshold
        // - Credential Object
        // o akm = dpp
        // o DPP Connector with netRole = "mapAgent"
        // o C-sign-key
        ieee1905_config_obj = m_get_1905_info(conn_ctx);
        ASSERT_NOT_NULL_FREE(ieee1905_config_obj, false, unwrapped_attrs, "%s:%d: Get 1905 info callback returned nullptr!\n", __func__, __LINE__);
        cJSON *cred = cJSON_GetObjectItem(ieee1905_config_obj, "cred");
        ASSERT_NOT_NULL_FREE2(cred, false, unwrapped_attrs, ieee1905_config_obj, "%s:%d: Could not get \"cred\" from IEEE1905 DPP Configuration Object\n", __func__, __LINE__);
        // Create / add Connector.

        // Header
        cJSON *jwsHeaderObj = ec_crypto::create_jws_header("dppCon", m_p_ctx.C_signing_key);

        // Payload
        std::vector<std::unordered_map<std::string, std::string>> groups = {
            {{"groupID", "mapNW"}, {"netRole", "mapAgent"}}
        };
        
        cJSON *jwsPayloadObj = ec_crypto::create_jws_payload(m_p_ctx, groups, conn_ctx->net_access_key);
        // Create / add connector
        const char *connector = ec_crypto::generate_connector(jwsHeaderObj, jwsPayloadObj, m_p_ctx.C_signing_key);
        cJSON_AddStringToObject(cred, "signedConnector", connector);

        // Add csign
        cJSON *cSignObj = ec_crypto::create_csign_object(m_p_ctx, m_p_ctx.C_signing_key);
        cJSON_AddItemToObject(cred, "csign", cSignObj);

        // Add ppKey
        cJSON *ppKeyObj = ec_crypto::create_ppkey_object(m_p_ctx);
        cJSON_AddItemToObject(cred, "ppKey", ppKeyObj);
    }



    bool needs_bsta_config_response = true;
    cJSON *bsta_config_object = nullptr;
    if (needs_bsta_config_response) {
        // Ensure callback exists.
        ASSERT_NOT_NULL_FREE(m_get_backhaul_sta_info, false, unwrapped_attrs, "%s:%d: Enrollee '" MACSTRFMT "' requests bSTA config, but bSTA config callback is nullptr!\n", __func__, __LINE__, MAC2STR(src_mac));
        bsta_config_object = m_get_backhaul_sta_info(conn_ctx);
        ASSERT_NOT_NULL_FREE(bsta_config_object, false, unwrapped_attrs, "%s:%d: Could not create bSTA configuration object.\n", __func__, __LINE__);
        // If a Multi-AP Controller sends a DPP Configuration Object for the backhaul STA, it shall set the fields described in Table 6
        // as follows:
        // - DPP Configuration Object
        // - wi-fi_tech = "map"
        // - Discovery Object
        // - SSID
        // - Credential Object
        // - akm = AKM suite selectors configured for the backhaul BSS and supported by the backhaul STA
        // as indicated in the DPP Configuration Request object.
        // - DPP Connector with netRole = "mapBackhaulSta"
        // - C-sign-key
        // - Pre-shared key
        // - WPA2 Passphrase and/or SAE password

        cJSON *cred = cJSON_GetObjectItem(bsta_config_object, "cred");
        ASSERT_NOT_NULL_FREE2(cred, false, unwrapped_attrs, bsta_config_object, "%s:%d: Could not get \"cred\" from IEEE1905 DPP Configuration Object\n", __func__, __LINE__);

        // Create / add Connector.

        // Header

        cJSON *jwsHeaderObj = ec_crypto::create_jws_header("dppCon", m_p_ctx.C_signing_key);

        std::vector<std::unordered_map<std::string, std::string>> groups = {
            {{"groupID", "mapNW"}, {"netRole", "mapBackhaulSta"}}
        };

        // Payload

        cJSON *jwsPayloadObj = ec_crypto::create_jws_payload(m_p_ctx, groups, conn_ctx->net_access_key);

        // Create connector
        const char *connector = ec_crypto::generate_connector(jwsHeaderObj, jwsPayloadObj, m_p_ctx.C_signing_key);

        cJSON_AddStringToObject(cred, "signedConnector", connector);

        // Add csign.

        cJSON *cSignObj = ec_crypto::create_csign_object(m_p_ctx, m_p_ctx.C_signing_key);

        cJSON_AddItemToObject(cred, "csign", cSignObj);

        // Add ppKey

        cJSON *ppKeyObj = ec_crypto::create_ppkey_object(m_p_ctx);
        cJSON_AddItemToObject(cred, "ppKey", ppKeyObj);

    }
    // For debugging
    {
        printf("%s:%d: IEEE1905 Configuration Object:\n%s\n", __func__, __LINE__, cJSON_Print(ieee1905_config_obj));
        printf("%s:%d: bSTA Configuration Object:\n%s\n", __func__, __LINE__, cJSON_Print(bsta_config_object));
    }
    size_t ieee1905_config_obj_len = cjson_utils::get_cjson_blob_size(ieee1905_config_obj);
    size_t bsta_config_object_len = cjson_utils::get_cjson_blob_size(bsta_config_object);

    // Create DPP Configuration frame.
    auto [frame, frame_len] = ec_util::alloc_gas_frame(dpp_gas_action_type_t::dpp_gas_initial_resp, session_dialog_token);
    ASSERT_NOT_NULL_FREE(frame, false, unwrapped_attrs, "%s:%d: Could not allocate DPP Configuration Response frame!\n", __func__, __LINE__);
    ec_gas_initial_response_frame_t *response_frame = reinterpret_cast<ec_gas_initial_response_frame_t *>(frame);

    uint8_t *attribs = nullptr;
    size_t attribs_len = 0;
    attribs = ec_util::add_wrapped_data_attr(reinterpret_cast<uint8_t *>(response_frame), sizeof(ec_gas_initial_response_frame_t), attribs, &attribs_len, true, e_ctx->ke, [&]() {
        size_t wrapped_len = 0;
        uint8_t *wrapped_attribs = ec_util::add_attrib(nullptr, &wrapped_len, ec_attrib_id_enrollee_nonce, e_nonce_len, e_ctx->e_nonce);
        wrapped_attribs = ec_util::add_attrib(wrapped_attribs, &wrapped_len, ec_attrib_id_dpp_config_obj, static_cast<uint16_t>(ieee1905_config_obj_len), reinterpret_cast<uint8_t*>(ieee1905_config_obj));
        wrapped_attribs = ec_util::add_attrib(wrapped_attribs, &wrapped_len, ec_attrib_id_dpp_config_obj, static_cast<uint16_t>(bsta_config_object_len), reinterpret_cast<uint8_t*>(bsta_config_object));
        return std::make_pair(wrapped_attribs, wrapped_len);
    });

    response_frame = reinterpret_cast<ec_gas_initial_response_frame_t*>(ec_util::copy_attrs_to_frame(reinterpret_cast<uint8_t*>(response_frame), sizeof(ec_gas_initial_response_frame_t), attribs, attribs_len));
    if (response_frame == nullptr) {
        printf("%s:%d: Failed to copy attributes to DPP Configuration frame!\n", __func__, __LINE__);
        free(attribs);
        free(unwrapped_attrs);
        free(response_frame);
        free(ieee1905_config_obj);
        free(bsta_config_object);
    }
    response_frame->resp_len = static_cast<uint16_t>(attribs_len);

    // If a Multi-AP Controller receives a Proxied Encap DPP message from an Enrollee Multi-AP Agent carrying a DPP
    // Configuration Request frame, it shall generate a DPP Configuration Response frame and include one DPP Configuration
    // Object for the 1905-layer and one DPP Configuration Object for the backhaul STA of the Enrollee, encapsulate them into
    // a 1905 Encap DPP TLV, set the DPP Frame Indicator bit to one, set the Enrollee MAC Address Present bit to one, set the
    // Frame Type field to 255 and include the Enrollee MAC Address into the Destination STA MAC Address field. 
    auto [encap_response_frame, encap_response_frame_len] = ec_util::create_encap_dpp_tlv(true, src_mac, ec_frame_type_easymesh, reinterpret_cast<uint8_t*>(response_frame), frame_len + attribs_len);
    ASSERT_NOT_NULL_FREE(encap_response_frame, false, unwrapped_attrs, "%s:%d: Failed to alloc DPP Configuration frame!\n", __func__, __LINE__);
    bool sent = m_send_prox_encap_dpp_msg(encap_response_frame, encap_response_frame_len, nullptr, 0);
    if (!sent) {
        printf("%s:%d: Failed to send Proxied Encap DPP message containing DPP Configuration frame to '" MACSTRFMT "'\n", __func__, __LINE__, MAC2STR(src_mac));
        free(encap_response_frame);
        free(response_frame);
        free(attribs);
        free(unwrapped_attrs);
        free(ieee1905_config_obj);
        free(bsta_config_object);
        return false;
    }
    return true;
}

bool ec_ctrl_configurator_t::handle_auth_response(ec_frame_t *frame, size_t len, uint8_t src_mac[ETHER_ADDR_LEN])
{

    std::string enrollee_mac = util::mac_to_string(src_mac);

    auto e_ctx = get_eph_ctx(enrollee_mac);
    ASSERT_NOT_NULL(e_ctx, false, "%s:%d: Ephemeral context not found for enrollee MAC %s\n", __func__, __LINE__, enrollee_mac.c_str());

    if (ec_util::validate_frame(frame, ec_frame_type_auth_rsp) == false) {
        printf("%s:%d: frame validation failed\n", __func__, __LINE__);
        return false;
    }

    size_t attrs_len = len - EC_FRAME_BASE_SIZE;

    ec_attribute_t* status_attrib = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_dpp_status);
    ASSERT_NOT_NULL(status_attrib, false, "%s:%d: No DPP status attribute found\n", __func__, __LINE__);
    
    ec_status_code_t dpp_status = static_cast<ec_status_code_t>(status_attrib->data[0]);

    ec_attribute_t *prim_wrapped_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_wrapped_data);
    ASSERT_NOT_NULL(prim_wrapped_attr, false, "%s:%d: No wrapped data attribute found\n", __func__, __LINE__);

    if (dpp_status != DPP_STATUS_OK) {
        printf("%s:%d: DPP Status not OK\n", __func__, __LINE__);

        // Unwrap the wrapped data with the K1 key

        auto [unwrapped_data, unwrapped_data_len] =  ec_util::unwrap_wrapped_attrib(prim_wrapped_attr, frame, true, e_ctx->k1);
        if (unwrapped_data == NULL || unwrapped_data_len == 0) {
            printf("%s:%d: Failed to unwrap wrapped data\n", __func__, __LINE__);
            // Abort the exchange
            return false;
        }

        free(unwrapped_data);
        
        if (dpp_status == DPP_STATUS_NOT_COMPATIBLE) {
            // Abort the exchange and may initiate back to the Responder with a different set of Initiator capabilities
            // NOTE: Since EasyMesh, this can't really happen since the Controller is the only one who can be the configurator
            return false;
        }
        if (dpp_status == DPP_STATUS_RESPONSE_PENDING) {
            // Do not abort the exchange and wait for a full DPP Authentication Response frame
            // TODO: The Initiator should set a timer to clean up the nascent connection if a response is not received in an acceptable amount of time
            // The time limit is not specified in this specification
            return true;
        }

        printf("%s:%d: Recieved Improper DPP Status: \"%s\"\n", __func__, __LINE__, ec_util::status_code_to_string(dpp_status).c_str());
        return false;
    }

    // DPP Status is OK

    // Initiator Bootstrapping Key Hash is present, allow mutual auth.
    auto B_i_hash_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_init_bootstrap_key_hash);
    e_ctx->is_mutual_auth = (B_i_hash_attr != NULL); // If the attribute is present, mutual authentication is possible

    auto P_r_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_resp_proto_key);
    ASSERT_NOT_NULL(P_r_attr, false, "%s:%d: No Responder Public Protocol Key attribute found\n", __func__, __LINE__);

    // Decode the Responder Public Protocol Key
    e_ctx->public_resp_proto_key = ec_crypto::decode_proto_key(m_p_ctx, P_r_attr->data);
    ASSERT_NOT_NULL(e_ctx->public_resp_proto_key, false, "%s:%d: Failed to decode Responder Public Protocol Key\n", __func__, __LINE__);

    // Compute the N.x
    ASSERT_NOT_NULL(e_ctx->priv_init_proto_key, false, "%s:%d: initiator (self) protocol private key was never generated\n", __func__, __LINE__);
    e_ctx->n = ec_crypto::compute_ec_ss_x(m_p_ctx, e_ctx->priv_init_proto_key, e_ctx->public_resp_proto_key);
    const BIGNUM *bn_inputs[1] = { e_ctx->n };
    // Compute the "second intermediate key" (k2)
    if (ec_crypto::compute_hkdf_key(m_p_ctx, e_ctx->k2, m_p_ctx.digest_len, "second intermediate key", bn_inputs, 1, NULL, 0) == 0) {
        printf("%s:%d: Failed to compute k2\n", __func__, __LINE__); 
        return false;
    }

    printf("Key K_2:\n");
    util::print_hex_dump(m_p_ctx.digest_len, e_ctx->k2);

    // Unwrap the wrapped data with the K2 key
    auto [prim_unwrapped_data, prim_unwrapped_len] =  ec_util::unwrap_wrapped_attrib(prim_wrapped_attr, frame, true, e_ctx->k2);
    if (prim_unwrapped_data == NULL || prim_unwrapped_len == 0) {
        printf("%s:%d: Failed to unwrap wrapped data\n", __func__, __LINE__);
        // Abort the exchange
        return false;
    }

    // Verify the recieved I-nonce is the same sent in the Authentication Request
    auto i_nonce_attr = ec_util::get_attrib(prim_unwrapped_data, prim_unwrapped_len, ec_attrib_id_init_nonce);
    ASSERT_NOT_NULL_FREE(i_nonce_attr, false, prim_unwrapped_data, "%s:%d: No Initiator Nonce attribute found\n", __func__, __LINE__);

    if (!e_ctx->i_nonce || memcmp(e_ctx->i_nonce, i_nonce_attr->data, i_nonce_attr->length) != 0) {
        printf("%s:%d: Initiator Nonce does not match, aborting exchange\n", __func__, __LINE__);
        // Abort the exchange
        return false;
    }

    auto r_nonce_attr = ec_util::get_attrib(prim_unwrapped_data, prim_unwrapped_len, ec_attrib_id_resp_nonce);
    ASSERT_NOT_NULL_FREE(r_nonce_attr, false, prim_unwrapped_data, "%s:%d: No Responder Nonce attribute found\n", __func__, __LINE__);

    // Set the Responder Nonce
    e_ctx->r_nonce = new uint8_t[r_nonce_attr->length]();
    ASSERT_NOT_NULL_FREE(e_ctx->r_nonce, false, prim_unwrapped_data, "%s:%d: Failed to allocate memory for Responder Nonce\n", __func__, __LINE__);
    memcpy(e_ctx->r_nonce, r_nonce_attr->data, r_nonce_attr->length);

    // Get Responder Capabilities
    auto resp_caps_attr = ec_util::get_attrib(prim_unwrapped_data, prim_unwrapped_len, ec_attrib_id_resp_caps);
    ASSERT_NOT_NULL_FREE(resp_caps_attr, false, prim_unwrapped_data, "%s:%d: No Responder Capabilities attribute found\n", __func__, __LINE__);
    const ec_dpp_capabilities_t resp_caps = {
        .byte = resp_caps_attr->data[0]
    };

    // Verify Responder Capabilities
    if (!ec_util::check_caps_compatible(m_dpp_caps, resp_caps)) {
        printf("%s:%d: Responder capabilities not supported\n", __func__, __LINE__);
        free(prim_unwrapped_data);

        auto [resp_frame, resp_len] = create_auth_confirm(enrollee_mac, DPP_STATUS_NOT_COMPATIBLE, NULL);
        ASSERT_NOT_NULL(resp_frame, false, "%s:%d: Failed to create response frame\n", __func__, __LINE__);

        auto [encap_dpp_tlv, encap_dpp_size] = ec_util::create_encap_dpp_tlv(0, src_mac, ec_frame_type_auth_cnf, resp_frame, resp_len);
        free(resp_frame);
        ASSERT_NOT_NULL(encap_dpp_tlv, false, "%s:%d: Failed to create Encap DPP TLV\n", __func__, __LINE__);

        // Send the encapsulated DPP message (with Encap TLV)
        if (!this->m_send_prox_encap_dpp_msg(encap_dpp_tlv, encap_dpp_size, NULL, 0)){
            printf("%s:%d: Failed to send Encap DPP TLV\n", __func__, __LINE__);
        }
        free(encap_dpp_tlv);

        return false;
    }

    // b_I
    ASSERT_NOT_NULL(m_boot_data.init_priv_boot_key, false, "%s:%d: failed to get initiator bootstrapping private key\n", __func__, __LINE__);
    // B_R
    ASSERT_NOT_NULL(m_boot_data.resp_pub_boot_key, false, "%s:%d: failed to get responder bootstrapping public key\n", __func__, __LINE__);
    // P_R
    ASSERT_NOT_NULL(e_ctx->public_resp_proto_key, false, "%s:%d: Responder Public Protocol Key was not recieved/set\n", __func__, __LINE__);

    if (e_ctx->is_mutual_auth){
        // Perform **Initiator** L.x calculation (L = bI * (BR + PR))

        EC_POINT* sum = EC_POINT_new(m_p_ctx.group);
        // Calculate (B_R + P_R)
        if (!EC_POINT_add(m_p_ctx.group, sum, m_boot_data.resp_pub_boot_key, e_ctx->public_resp_proto_key, m_p_ctx.bn_ctx)){
            EC_POINT_free(sum);
            free(prim_unwrapped_data);
            printf("%s:%d: failed to add public responder boot key and public responder protocol key\n", __func__, __LINE__);
            return false;
        }
        // Calculate b_I * (B_R + P_R)
        EC_POINT* L = EC_POINT_new(m_p_ctx.group);
        if (!EC_POINT_mul(m_p_ctx.group, L, NULL, sum, m_boot_data.init_priv_boot_key, m_p_ctx.bn_ctx)){
            EC_POINT_free(sum);
            EC_POINT_free(L);
            free(prim_unwrapped_data);
            printf("%s:%d: failed to multiply private initiator boot key and sum of public responder boot key and public responder protocol key\n", __func__, __LINE__);
            return false;
        }
        EC_POINT_free(sum);
        BIGNUM* L_x = ec_crypto::get_ec_x(m_p_ctx, L);
        EC_POINT_free(L);
        if (L_x == NULL) {
            free(prim_unwrapped_data);
            printf("%s:%d: failed to get x-coordinate of L\n", __func__, __LINE__);
            return false;
        }
        e_ctx->l = L_x;
    }

    if (ec_crypto::compute_ke(m_p_ctx, e_ctx, e_ctx->ke) == 0) {
        printf("%s:%d: Failed to compute ke\n", __func__, __LINE__);
        free(prim_unwrapped_data);
        return false;
    }

    // Get secondary wrapped data from inside the primary wrapped data component
    //  EasyConnect 8.2.3

    auto sec_wrapped_attr = ec_util::get_attrib(prim_unwrapped_data, prim_unwrapped_len, ec_attrib_id_wrapped_data);
    ASSERT_NOT_NULL_FREE(sec_wrapped_attr, false, prim_unwrapped_data, "%s:%d: No secondary wrapped data attribute found\n", __func__, __LINE__);

    // Unwrap the secondary wrapped data with the KE key
    auto [sec_unwrapped_data, sec_unwrapped_len] =  ec_util::unwrap_wrapped_attrib(sec_wrapped_attr, frame, true, e_ctx->ke);
    ASSERT_NOT_NULL_FREE(sec_unwrapped_data, false, prim_unwrapped_data, "%s:%d: Failed to unwrap secondary wrapped data\n", __func__, __LINE__);

    // Free the primary unwrapped data since it is no longer needed (secondary unwrapped data is heap allocated)
    free(prim_unwrapped_data);

    // Get Responder Auth Tag
    auto resp_auth_tag_attr = ec_util::get_attrib(sec_unwrapped_data, sec_unwrapped_len, ec_attrib_id_resp_auth_tag);
    ASSERT_NOT_NULL_FREE(resp_auth_tag_attr, false, sec_unwrapped_data, "%s:%d: No Responder Auth Tag attribute found\n", __func__, __LINE__);
    uint8_t resp_auth_tag[resp_auth_tag_attr->length] = {0};
    memcpy(resp_auth_tag, resp_auth_tag_attr->data, resp_auth_tag_attr->length);
    free(sec_unwrapped_data);


    // Compute R-auth’ = H(I-nonce | R-nonce | PI.x | PR.x | [ BI.x | ] BR.x | 0)

    // Get P_I.x, P_R.x, B_I.x, and B_R.x
    BIGNUM* P_I_x = ec_crypto::get_ec_x(m_p_ctx, e_ctx->public_init_proto_key);
    BIGNUM* P_R_x = ec_crypto::get_ec_x(m_p_ctx, e_ctx->public_resp_proto_key);
    BIGNUM* B_I_x = ec_crypto::get_ec_x(m_p_ctx, m_boot_data.init_pub_boot_key);
    BIGNUM* B_R_x = ec_crypto::get_ec_x(m_p_ctx, m_boot_data.resp_pub_boot_key);

    if (P_I_x == NULL || P_R_x == NULL || B_R_x == NULL) {
        printf("%s:%d: Failed to get x-coordinates of P_I, P_R, and B_R\n", __func__, __LINE__);
        if (P_I_x) BN_free(P_I_x);
        if (P_R_x) BN_free(P_R_x);
        if (B_R_x) BN_free(B_R_x);
        if (B_I_x) BN_free(B_I_x);
        return false;
    }

    // B_I.x is not needed (can be null) if mutual authentication is not supported
    if (e_ctx->is_mutual_auth && B_I_x == NULL) {
        printf("%s:%d: Failed to get x-coordinate of B_I\n", __func__, __LINE__);
        BN_free(P_I_x);
        BN_free(P_R_x);
        BN_free(B_R_x);
        return false;
    }

    easyconnect::hash_buffer_t r_auth_hb;
    ec_crypto::add_to_hash(r_auth_hb, e_ctx->i_nonce, m_p_ctx.nonce_len);
    ec_crypto::add_to_hash(r_auth_hb, e_ctx->r_nonce, m_p_ctx.nonce_len);
    ec_crypto::add_to_hash(r_auth_hb, P_I_x); //P_I
    ec_crypto::add_to_hash(r_auth_hb, P_R_x); //P_R
    if (e_ctx->is_mutual_auth) ec_crypto::add_to_hash(r_auth_hb, B_I_x); //B_I
    ec_crypto::add_to_hash(r_auth_hb, B_R_x); //B_R
    ec_crypto::add_to_hash(r_auth_hb, static_cast<uint8_t>(0)); // 0 octet

    uint8_t* r_auth_prime = ec_crypto::compute_hash(m_p_ctx, r_auth_hb);

    BN_free(P_I_x);
    BN_free(P_R_x);
    BN_free(B_R_x);
    if (B_I_x) BN_free(B_I_x);

    ASSERT_NOT_NULL(r_auth_prime, false, "%s:%d: Failed to compute R-auth'\n", __func__, __LINE__);

    if (memcmp(r_auth_prime, resp_auth_tag, sizeof(resp_auth_tag) != 0)) {
        printf("%s:%d: R-auth' does not match Responder Auth Tag\n", __func__, __LINE__);
        free(r_auth_prime);
        /*
        The Initiator should generate an alert indicating its inability to authenticate the Responder. The Initiator then aborts the
        exchange.
        */
        auto [resp_frame, resp_len] = create_auth_confirm(enrollee_mac, DPP_STATUS_AUTH_FAILURE, NULL);
        ASSERT_NOT_NULL(resp_frame, false, "%s:%d: Failed to create response frame\n", __func__, __LINE__);

        auto [encap_dpp_tlv, encap_dpp_size] = ec_util::create_encap_dpp_tlv(0, src_mac, ec_frame_type_auth_cnf, resp_frame, resp_len);
        free(resp_frame);
        ASSERT_NOT_NULL(encap_dpp_tlv, false, "%s:%d: Failed to create Encap DPP TLV\n", __func__, __LINE__);

        // Send the encapsulated DPP message (with Encap TLV)
        if (!this->m_send_prox_encap_dpp_msg(encap_dpp_tlv, encap_dpp_size, NULL, 0)){
            printf("%s:%d: Failed to send encapsulated DPP message\n", __func__, __LINE__);
        }

        free(encap_dpp_tlv);
        return false;
    }

    free(r_auth_prime);

    // Generate I-auth = H(R-nonce | I-nonce | PR.x | PI.x | BR.x | [ BI.x | ] 1)
    easyconnect::hash_buffer_t i_auth_hb;
    ec_crypto::add_to_hash(i_auth_hb, e_ctx->r_nonce, m_p_ctx.nonce_len);
    ec_crypto::add_to_hash(i_auth_hb, e_ctx->i_nonce, m_p_ctx.nonce_len);
    ec_crypto::add_to_hash(i_auth_hb, P_R_x); //P_R
    ec_crypto::add_to_hash(i_auth_hb, P_I_x); //P_I
    ec_crypto::add_to_hash(i_auth_hb, B_R_x); //B_R
    if (e_ctx->is_mutual_auth) ec_crypto::add_to_hash(i_auth_hb, B_I_x); //B_I
    ec_crypto::add_to_hash(i_auth_hb, static_cast<uint8_t> (1)); // 1 octet

    uint8_t* i_auth = ec_crypto::compute_hash(m_p_ctx, i_auth_hb);
    ASSERT_NOT_NULL(i_auth, false, "%s:%d: Failed to compute I-auth\n", __func__, __LINE__);

    auto [resp_frame, resp_len] = create_auth_confirm(enrollee_mac, DPP_STATUS_OK, i_auth);
    free(i_auth);
    ASSERT_NOT_NULL(resp_frame, false, "%s:%d: Failed to create response frame\n", __func__, __LINE__);

    // TODO: Send frame
    auto [encap_dpp_tlv, encap_dpp_size] = ec_util::create_encap_dpp_tlv(0, src_mac, ec_frame_type_auth_cnf, resp_frame, resp_len);
    free(resp_frame);
    ASSERT_NOT_NULL(encap_dpp_tlv, false, "%s:%d: Failed to create Encap DPP TLV\n", __func__, __LINE__);

    // Send the encapsulated DPP message (with Encap TLV)
    if (!this->m_send_prox_encap_dpp_msg(encap_dpp_tlv, encap_dpp_size, NULL, 0)){
        printf("%s:%d: Failed to send encapsulated DPP message\n", __func__, __LINE__);
        free(encap_dpp_tlv);
        return false;
    }

    free(encap_dpp_tlv);
    return true;
}

std::pair<uint8_t *, size_t> ec_ctrl_configurator_t::create_auth_request(std::string enrollee_mac)
{

    printf("%s:%d Enter\n", __func__, __LINE__);
    auto e_ctx = get_eph_ctx(enrollee_mac);
    ASSERT_NOT_NULL(e_ctx, {}, "%s:%d: Ephemeral context not found for enrollee MAC %s\n", __func__, __LINE__, enrollee_mac.c_str());

    ec_frame_t *frame =  ec_util::alloc_frame(ec_frame_type_auth_req);
    ASSERT_NOT_NULL(frame, {}, "%s:%d failed to allocate memory for frame\n", __func__, __LINE__);

    // Start EasyConnect 6.3.2

    // Generate initiator nonce
    RAND_bytes(e_ctx->i_nonce, m_p_ctx.nonce_len);

    // Generate initiator protocol key pair (p_i/P_I)
    auto [priv_init_proto_key, pub_init_proto_key] = ec_crypto::generate_proto_keypair(m_p_ctx);
    if (priv_init_proto_key == NULL || pub_init_proto_key == NULL) {
        printf("%s:%d failed to generate initiator protocol key pair\n", __func__, __LINE__);
        return {};
    }
    e_ctx->priv_init_proto_key = const_cast<BIGNUM*>(priv_init_proto_key);
    e_ctx->public_init_proto_key = const_cast<EC_POINT*>(pub_init_proto_key);

    // Compute the M.x
    ASSERT_NOT_NULL_FREE(m_boot_data.resp_pub_boot_key, {}, frame, "%s:%d failed to get responder bootstrapping public key\n", __func__, __LINE__);

    e_ctx->m = ec_crypto::compute_ec_ss_x(m_p_ctx, e_ctx->priv_init_proto_key, m_boot_data.resp_pub_boot_key);
    const BIGNUM *bn_inputs[1] = { e_ctx->m };
    // Compute the "first intermediate key" (k1)
    if (ec_crypto::compute_hkdf_key(m_p_ctx, e_ctx->k1, m_p_ctx.digest_len, "first intermediate key", bn_inputs, 1, NULL, 0) == 0) {
        printf("%s:%d: Failed to compute k1\n", __func__, __LINE__); 
        return {};
    }

    printf("Key K_1:\n");
    util::print_hex_dump(static_cast<unsigned int> (m_p_ctx.digest_len), e_ctx->k1);
    
    uint8_t* attribs = NULL;
    size_t attribs_len = 0;

    // Responder Bootstrapping Key Hash: SHA-256(B_R)
    uint8_t* responder_keyhash = ec_crypto::compute_key_hash(m_boot_data.responder_boot_key);
    ASSERT_NOT_NULL_FREE2(responder_keyhash, {}, frame, attribs, "%s:%d failed to compute responder bootstrapping key hash\n", __func__, __LINE__);

    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_resp_bootstrap_key_hash, SHA256_DIGEST_LENGTH, responder_keyhash);
    free(responder_keyhash);

    // Initiator Bootstrapping Key Hash: SHA-256(B_I)
    uint8_t* initiator_keyhash = ec_crypto::compute_key_hash(m_boot_data.initiator_boot_key);
    ASSERT_NOT_NULL_FREE2(initiator_keyhash, {}, frame, attribs, "%s:%d failed to compute initiator bootstrapping key hash\n", __func__, __LINE__); 

    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_init_bootstrap_key_hash, SHA256_DIGEST_LENGTH, initiator_keyhash);
    free(initiator_keyhash);

    // Public Initiator Protocol Key: P_I
    uint8_t* protocol_key_buff = ec_crypto::encode_proto_key(m_p_ctx, e_ctx->public_init_proto_key);
    ASSERT_NOT_NULL_FREE2(protocol_key_buff, {}, frame, attribs, "%s:%d failed to encode public initiator protocol key\n", __func__, __LINE__);

    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_init_proto_key, static_cast<uint16_t>(2*BN_num_bytes(m_p_ctx.prime)), protocol_key_buff);
    free(protocol_key_buff);

    // Protocol Version
    // if (m_cfgrtr_ver > 1) {
    //     attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_proto_version, m_cfgrtr_ver);
    // }

    // Channel Attribute (optional)
    //TODO: REVISIT THIS
    if (m_boot_data.ec_freqs[0] != 0){
        unsigned int base_freq = m_boot_data.ec_freqs[0]; 
        uint16_t chann_attr = ec_util::freq_to_channel_attr(base_freq);
        attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_channel, sizeof(uint16_t), reinterpret_cast<uint8_t*>(&chann_attr));
    }


    // Wrapped Data (with Initiator Nonce and Initiator Capabilities)
    // EasyMesh 8.2.2 Table 36
    attribs = ec_util::add_wrapped_data_attr(frame, attribs, &attribs_len, true, e_ctx->k1, [&](){
        uint8_t* wrap_attribs = NULL;
        size_t wrapped_len = 0;
        wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_init_nonce, static_cast<uint16_t>(m_p_ctx.nonce_len), e_ctx->i_nonce);
        wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_init_caps, m_dpp_caps.byte);
        return std::make_pair(wrap_attribs, wrapped_len);
    });

    // Add attributes to the frame
    if (!(frame = ec_util::copy_attrs_to_frame(frame, attribs, attribs_len))) {
        printf("%s:%d unable to copy attributes to frame\n", __func__, __LINE__);
        free(frame);
        free(attribs);
        return {};
    }

    free(attribs);

    return std::make_pair(reinterpret_cast<uint8_t*>(frame), EC_FRAME_BASE_SIZE + attribs_len);

}

std::pair<uint8_t *, size_t> ec_ctrl_configurator_t::create_auth_confirm(std::string enrollee_mac, ec_status_code_t dpp_status, uint8_t* i_auth_tag)
{

/*
STATUS_NOT_COMPATIBLE: 
    Initiator → Responder: DPP Status, SHA-256(B_R), [ SHA-256(B_I), ] { R-nonce }k2
STATUS_AUTH_FAILURE:
    Initiator → Responder: DPP Status, SHA-256(B_R), [ SHA-256(B_I), ] { R-nonce }k2
STATUS_OK:
    Initiator → Responder: DPP Status, SHA-256(B_R), [ SHA-256(B_I), ] { I-auth }ke

*/

    auto e_ctx = get_eph_ctx(enrollee_mac);
    ASSERT_NOT_NULL(e_ctx, {}, "%s:%d: Ephemeral context not found for enrollee MAC %s\n", __func__, __LINE__, enrollee_mac.c_str());

    if (dpp_status == DPP_STATUS_OK && i_auth_tag == NULL) {
        printf("%s:%d: I-auth tag is NULL\n", __func__, __LINE__);
        return {};
    }

    ec_frame_t *frame =  ec_util::alloc_frame(ec_frame_type_auth_cnf);
    ASSERT_NOT_NULL(frame, {}, "%s:%d failed to allocate memory for frame\n", __func__, __LINE__);

    uint8_t* attribs = NULL;
    size_t attribs_len = 0;
    
    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_dpp_status, static_cast<uint8_t>(dpp_status));

    // Add Responder Bootstrapping Key Hash (SHA-256(B_R))
    uint8_t* responder_keyhash = ec_crypto::compute_key_hash(m_boot_data.responder_boot_key);
    ASSERT_NOT_NULL_FREE2(responder_keyhash, {}, frame, attribs, "%s:%d failed to compute responder bootstrapping key hash\n", __func__, __LINE__);

    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_resp_bootstrap_key_hash, SHA256_DIGEST_LENGTH, responder_keyhash);
    free(responder_keyhash);
    // Conditional (Only included for mutual authentication) (SHA-256(B_I))
    if (e_ctx->is_mutual_auth) {
        uint8_t* initiator_keyhash = ec_crypto::compute_key_hash(m_boot_data.initiator_boot_key);
        if (initiator_keyhash != NULL) {
            attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_init_bootstrap_key_hash, SHA256_DIGEST_LENGTH, initiator_keyhash);
            free(initiator_keyhash);
        }

    }

    uint8_t* key = (dpp_status == DPP_STATUS_OK) ? e_ctx->ke : e_ctx->k2;
    ASSERT_NOT_NULL_FREE2(key, {}, frame, attribs, "%s:%d: k_e or k_2 was not created!\n", __func__, __LINE__);

    // If DPP Status is OK, wrap the I-auth with the KE key, otherwise wrap the Responder Nonce with the K2 key
    attribs = ec_util::add_wrapped_data_attr(frame, attribs, &attribs_len, true, key, [&](){
        uint8_t* wrap_attribs = NULL;
        size_t wrapped_len = 0;
        if (dpp_status == DPP_STATUS_OK) {
            wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_init_auth_tag, m_p_ctx.digest_len, i_auth_tag);
        } else {
            wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_resp_nonce, m_p_ctx.nonce_len, e_ctx->r_nonce);
        }
        return std::make_pair(wrap_attribs, wrapped_len);
    });

    if (!(frame = ec_util::copy_attrs_to_frame(frame, attribs, attribs_len))) {
        printf("%s:%d unable to copy attributes to frame\n", __func__, __LINE__);
        free(frame);
        free(attribs);
        return {};
    }
    free(attribs);

    return std::make_pair(reinterpret_cast<uint8_t*>(frame), EC_FRAME_BASE_SIZE + attribs_len);
}

std::pair<uint8_t *, size_t> ec_ctrl_configurator_t::create_recfg_auth_request()
{
    return {};
}

std::pair<uint8_t *, size_t> ec_ctrl_configurator_t::create_recfg_auth_confirm(std::string enrollee_mac, ec_status_code_t dpp_status)
{

    auto e_ctx = get_eph_ctx(enrollee_mac);
    ASSERT_NOT_NULL(e_ctx, {}, "%s:%d: Ephemeral context not found for enrollee MAC %s\n", __func__, __LINE__, enrollee_mac.c_str());

    ec_frame_t *frame =  ec_util::alloc_frame(ec_frame_type_recfg_auth_cnf);
    ASSERT_NOT_NULL(frame, {}, "%s:%d failed to allocate memory for frame\n", __func__, __LINE__);

    uint8_t* attribs = NULL;
    size_t attribs_len = 0;

    // TODO: Add transaction ID outside this function
    uint8_t trans_id = 0;
    ec_dpp_reconfig_flags_t reconfig_flags = {
        .connector_key = 1, // DONT REUSE
        .reserved = 0
    };



    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_dpp_status, static_cast<uint8_t>(dpp_status));

    attribs = ec_util::add_wrapped_data_attr(frame, attribs, &attribs_len, false, e_ctx->ke, [&](){
        uint8_t* wrap_attribs = NULL;
        size_t wrapped_len = 0;

        wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_trans_id, trans_id);
        wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_proto_version, static_cast<uint8_t>(m_boot_data.version));
        wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_config_nonce, m_p_ctx.nonce_len, e_ctx->i_nonce);
        wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_enrollee_nonce, m_p_ctx.nonce_len, e_ctx->e_nonce);
        wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_reconfig_flags, sizeof(reconfig_flags), reinterpret_cast<uint8_t*>(&reconfig_flags));

        return std::make_pair(wrap_attribs, wrapped_len);
    });

    if (!(frame = ec_util::copy_attrs_to_frame(frame, attribs, attribs_len))) {
        printf("%s:%d unable to copy attributes to frame\n", __func__, __LINE__);
        free(frame);
        free(attribs);
        return {};
    }
    free(attribs);

    return std::make_pair(reinterpret_cast<uint8_t*>(frame), EC_FRAME_BASE_SIZE + attribs_len);
}

std::pair<uint8_t *, size_t> ec_ctrl_configurator_t::create_config_response()
{
    return {};
}
