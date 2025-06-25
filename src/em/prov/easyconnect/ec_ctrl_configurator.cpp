#include "ec_ctrl_configurator.h"

#include "ec_base.h"
#include "ec_util.h"
#include "util.h"
#include "cjson/cJSON.h"
#include "cjson_util.h"
#include "em_crypto.h"
#include <netinet/in.h>

bool ec_ctrl_configurator_t::onboard_enrollee(ec_data_t *bootstrapping_data)
{

    if (bootstrapping_data == NULL) {
        em_printfout("Bootstrapping data is NULL");
        return false;
    }
    if (bootstrapping_data->version < 2) {
        em_printfout("Bootstrapping Version '%d' not supported!", bootstrapping_data->version);
        return false;
    }
    if (memcmp(bootstrapping_data->mac_addr, ZERO_MAC_ADDR, ETHER_ADDR_LEN) == 0) {
        em_printfout("Bootstrapping data MAC address is 0 ");
        return false;
    }
    if (bootstrapping_data->responder_boot_key == NULL) {
        em_printfout("Bootstrapping data initiator key is NULL");
        return false;
    }

    // Check if the MAC address is already in use
    // TODO: Not sure what to do if the MAC address is already in use
    std::string mac_str = util::mac_to_string(bootstrapping_data->mac_addr);
    if (m_connections.find(mac_str) != m_connections.end()) {
        em_printfout("Bootstrapping data MAC address already in use");
        return false;
    }
    // Create a new connection context
    ec_connection_context_t conn_ctx;
    m_connections[mac_str] = conn_ctx;
    auto& c_ctx = m_connections[mac_str];
    

    // Initialize bootstrapping data
    memset(&c_ctx.boot_data, 0, sizeof(ec_data_t));
    memcpy(&c_ctx.boot_data, bootstrapping_data, sizeof(ec_data_t));

    // Not all of these will be present but it is better to compute them now.
    c_ctx.boot_data.resp_priv_boot_key = em_crypto_t::get_priv_key_bn(c_ctx.boot_data.responder_boot_key);
    c_ctx.boot_data.resp_pub_boot_key = em_crypto_t::get_pub_key_point(c_ctx.boot_data.responder_boot_key);

    c_ctx.boot_data.init_priv_boot_key = em_crypto_t::get_priv_key_bn(c_ctx.boot_data.initiator_boot_key);    
    c_ctx.boot_data.init_pub_boot_key = em_crypto_t::get_pub_key_point(c_ctx.boot_data.initiator_boot_key);


    if (c_ctx.boot_data.resp_pub_boot_key == NULL) {
        em_printfout("Could not get responder bootstrap public key");
        return false;
    }

    printf("Configurator MAC: %s\n", m_mac_addr.c_str());
    return ec_crypto::init_connection_ctx(c_ctx, c_ctx.boot_data.responder_boot_key);
}

bool ec_ctrl_configurator_t::process_chirp_notification(em_dpp_chirp_value_t *chirp_tlv, uint16_t tlv_len)
{

    mac_addr_t mac = {0};
    uint8_t* hash = NULL; // Max hash length to avoid dynamic allocation
    uint16_t hash_len = 0;

    if (!ec_util::parse_dpp_chirp_tlv(chirp_tlv, tlv_len, &mac, reinterpret_cast<uint8_t**>(&hash), &hash_len)) {
        em_printfout("Failed to parse DPP Chirp TLV");
        return false;
    }

    std::string mac_str = util::mac_to_string(mac);
    auto c_ctx = get_conn_ctx(mac_str);
    ASSERT_NOT_NULL_FREE(c_ctx, false, hash, "%s:%d: Connection context not found for enrollee MAC %s. Has the DPP URI been given?\n", __func__, __LINE__, mac_str.c_str());

    // Validate hash
    // Compute the hash of the responder boot key 
    uint8_t *resp_boot_key_chirp_hash = ec_crypto::compute_key_hash(c_ctx->boot_data.responder_boot_key, "chirp");
    ASSERT_NOT_NULL_FREE(resp_boot_key_chirp_hash, false, hash, "%s:%d: unable to compute \"chirp\" responder bootstrapping key hash\n", __func__, __LINE__);

    if (memcmp(hash, resp_boot_key_chirp_hash, hash_len) != 0) {
        // Hashes don't match, don't initiate DPP authentication
        em_printfout("Chirp notification hash and DPP URI hash did not match! Stopping DPP!");
        em_printfout("Expected hash: ");
        util::print_hex_dump(hash_len, resp_boot_key_chirp_hash);
        printf("\n%s:%d: Received hash: \n", __func__, __LINE__);
        util::print_hex_dump(hash_len, hash);
        free(resp_boot_key_chirp_hash);
        free(hash);
        return false;
    }

    free(resp_boot_key_chirp_hash);


    auto [auth_frame, auth_frame_len] = create_auth_request(mac_str);
    if (auth_frame == NULL || auth_frame_len == 0) {
        em_printfout("Failed to create authentication request frame");
        free(hash);
        return false;
    }

    // Create Auth Request Encap TLV: EasyMesh 5.3.4
    auto [encap_dpp_tlv, encap_dpp_size] = ec_util::create_encap_dpp_tlv(0, mac, ec_frame_type_auth_req, auth_frame, auth_frame_len);
    ASSERT_NOT_NULL_FREE2(encap_dpp_tlv, false, auth_frame, hash, "%s:%d: Failed to create Encap DPP TLV\n", __func__, __LINE__);

    free(auth_frame);

    // Create Auth Request Chirp TLV: EasyMesh 5.3.4

    auto [chirp, chirp_tlv_size] = ec_util::create_dpp_chirp_tlv(true, true, mac, hash, hash_len);
    ASSERT_NOT_NULL_FREE2(chirp, false, encap_dpp_tlv, hash, "%s:%d: Failed to create Chirp TLV\n", __func__, __LINE__);
    free(hash);

    // Send the encapsulated DPP message (with Encap TLV and Chirp TLV)
    this->m_send_prox_encap_dpp_msg(encap_dpp_tlv, encap_dpp_size, chirp, chirp_tlv_size);

    free(encap_dpp_tlv);
    free(chirp);
    
    return true; 
}

bool ec_ctrl_configurator_t::process_proxy_encap_dpp_msg(em_encap_dpp_t *encap_tlv, uint16_t encap_tlv_len, em_dpp_chirp_value_t *chirp_tlv, uint16_t chirp_tlv_len)
{
    if (encap_tlv == NULL || encap_tlv_len == 0) {
        em_printfout("Encap DPP TLV is empty");
        return false;
    }

    
    mac_addr_t dest_mac = {0};
    uint8_t frame_type = 0;
    uint8_t* encap_frame = NULL;
    uint16_t encap_frame_len = 0;

    if (!ec_util::parse_encap_dpp_tlv(encap_tlv, encap_tlv_len, &dest_mac, &frame_type, &encap_frame, &encap_frame_len)) {
        em_printfout("Failed to parse Encap DPP TLV");
        return false;
    }

    bool did_finish = false;

    ec_frame_type_t ec_frame_type = static_cast<ec_frame_type_t>(frame_type);
    switch (ec_frame_type) {
        case ec_frame_type_recfg_announcement: {
            did_finish = handle_recfg_announcement(reinterpret_cast<ec_frame_t*>(encap_frame), encap_frame_len, dest_mac);
            break;
        }
        case ec_frame_type_recfg_auth_rsp: {
            did_finish = handle_recfg_auth_response(reinterpret_cast<ec_frame_t*>(encap_frame), encap_frame_len, dest_mac);
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
        case ec_frame_type_cfg_result: {
            did_finish = handle_proxied_config_result_frame(encap_frame, encap_frame_len, dest_mac);
            break;
        }
        case ec_frame_type_conn_status_result: {
            did_finish = handle_proxied_conn_status_result_frame(encap_frame, encap_frame_len, dest_mac);
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

bool ec_ctrl_configurator_t::process_direct_encap_dpp_msg(uint8_t* dpp_frame, uint16_t dpp_frame_len)
{
    if (dpp_frame == NULL || dpp_frame_len == 0) {
        em_printfout("DPP Message Frame is empty");
        return false;
    }

    bool did_finish = false;
    ec_frame_t* ec_frame = reinterpret_cast<ec_frame_t*>(dpp_frame);

    ec_frame_type_t ec_frame_type = static_cast<ec_frame_type_t>(ec_frame->frame_type);
    switch (ec_frame_type) {
        case ec_frame_type_recfg_announcement: {
            //did_finish = handle_recfg_announcement(reinterpret_cast<ec_frame_t*>(encap_frame), encap_frame_len, dest_mac);
            break;
        }
        case ec_frame_type_recfg_auth_rsp: {
            //did_finish = handle_recfg_auth_response(reinterpret_cast<ec_frame_t*>(encap_frame), encap_frame_len, dest_mac);
            break;
        }
        case ec_frame_type_auth_rsp: {
            //did_finish = handle_auth_response(reinterpret_cast<ec_frame_t*>(encap_frame), encap_frame_len, dest_mac);
            break;
        }
        case ec_frame_type_easymesh: {
            //did_finish = handle_proxied_dpp_configuration_request(encap_frame, encap_frame_len, dest_mac);
            break;
        }
        case ec_frame_type_cfg_result: {
            //did_finish = handle_proxied_config_result_frame(encap_frame, encap_frame_len, dest_mac);
            break;
        }
        case ec_frame_type_conn_status_result: {
            //did_finish = handle_proxied_conn_status_result_frame(encap_frame, encap_frame_len, dest_mac);
            break;
        }
        case ec_frame_type_peer_disc_req: {
            break;
        }
        default:
            em_printfout("Encap DPP frame type (%d) not handled", ec_frame_type);
            break;
    }

    return did_finish;
}

bool ec_ctrl_configurator_t::handle_proxied_config_result_frame(uint8_t *encap_frame, uint16_t encap_frame_len, uint8_t src_mac[ETH_ALEN])
{
    if (!encap_frame || encap_frame_len == 0) {
        em_printfout("Invalid encapsulated frame");
        return false;
    }

    std::string enrollee_mac = util::mac_to_string(src_mac);

    auto conn_ctx = get_conn_ctx(enrollee_mac);
    ASSERT_NOT_NULL(conn_ctx, false, "%s:%d: No connection context for Enrollee '" MACSTRFMT "'\n", __func__, __LINE__, MAC2STR(src_mac));
    auto e_ctx = get_eph_ctx(enrollee_mac);
    ASSERT_NOT_NULL(e_ctx, false, "%s:%d: Ephemeral context not found for enrollee MAC %s\n", __func__, __LINE__, enrollee_mac.c_str());

    // EasyMesh 5.3.4
    // If the Multi-AP Controller receives the DPP Configuration Result frame encapsulated in a Proxied Encap DPP message
    // with DPP Status field set to STATUS_OK, the Multi-AP Controller shall retain the information that it successfully
    // onboarded and configured the newly onboarded Multi-AP Agent using the AL MAC Address of the Enrollee Multi-AP
    // Agent.
    size_t attrs_len = encap_frame_len - EC_FRAME_BASE_SIZE;

    ec_frame_t *frame = reinterpret_cast<ec_frame_t *>(encap_frame);
    
    auto wrapped_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_wrapped_data);
    ASSERT_OPT_HAS_VALUE(wrapped_attr, false, "%s:%d: No wrapped data in Proxied DPP Configuration Result frame\n", __func__, __LINE__);

    // Unwrap with k_e
    auto [unwrapped_attrs, unwrapped_attrs_len] = ec_util::unwrap_wrapped_attrib(*wrapped_attr, frame, false, e_ctx->ke);
    if (unwrapped_attrs == nullptr || unwrapped_attrs_len == 0) {
        em_printfout("Failed to unwrap attributes.");
        return false;
    }

    auto e_nonce_attr = ec_util::get_attrib(unwrapped_attrs, unwrapped_attrs_len, ec_attrib_id_enrollee_nonce);
    ASSERT_OPT_HAS_VALUE_FREE(e_nonce_attr, false, unwrapped_attrs, "%s:%d: DPP Configuration Result frame did not contain E-nonce\n", __func__, __LINE__);

    if (conn_ctx->nonce_len != e_nonce_attr->length || memcmp(e_ctx->e_nonce, e_nonce_attr->data, e_nonce_attr->length) != 0) {
        em_printfout("E-nonce contained in DPP Configuration Result frame for '%s' does not match E-nonce in stored connection context.", enrollee_mac.c_str());
        free(unwrapped_attrs);
        return false;
    }

    auto status_attr = ec_util::get_attrib(unwrapped_attrs, unwrapped_attrs_len, ec_attrib_id_dpp_status);
    ASSERT_OPT_HAS_VALUE_FREE(status_attr, false, unwrapped_attrs, "%s:%d: DPP Configuration Result frame did not contain DPP Status\n", __func__, __LINE__);

    ec_status_code_t dpp_status = static_cast<ec_status_code_t>(status_attr->data[0]);
    if (dpp_status == DPP_STATUS_OK) {
        m_enrollee_successfully_onboarded[enrollee_mac] = true;
    } else if (dpp_status == DPP_STATUS_CONFIG_REJECTED) {
        m_enrollee_successfully_onboarded[enrollee_mac] = false;
    } else {
        em_printfout("Invalid DPP Status %d (%s)", static_cast<int>(dpp_status), ec_util::status_code_to_string(dpp_status).c_str());
        free(unwrapped_attrs);
        return false;
    }

    free(unwrapped_attrs);
    return true;
}

bool ec_ctrl_configurator_t::handle_proxied_conn_status_result_frame(uint8_t *encap_frame, uint16_t encap_frame_len, uint8_t src_mac[ETH_ALEN])
{
    if (!encap_frame || encap_frame_len == 0) {
        em_printfout("Invalid encapsulated frame");
        return false;
    }

    // Neither EasyMesh nor EasyConnect specify what to do with the information in this frame ...

    std::string enrollee_mac = util::mac_to_string(src_mac);

    auto conn_ctx = get_conn_ctx(enrollee_mac);
    ASSERT_NOT_NULL(conn_ctx, false, "%s:%d: No connection context for Enrollee '" MACSTRFMT "'\n", __func__, __LINE__, MAC2STR(src_mac));
    auto e_ctx = get_eph_ctx(enrollee_mac);
    ASSERT_NOT_NULL(e_ctx, false, "%s:%d: Ephemeral context not found for enrollee MAC %s\n", __func__, __LINE__, enrollee_mac.c_str());

    size_t attrs_len = encap_frame_len - EC_FRAME_BASE_SIZE;

    ec_frame_t *frame = reinterpret_cast<ec_frame_t *>(encap_frame);
    
    auto wrapped_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_wrapped_data);
    ASSERT_OPT_HAS_VALUE(wrapped_attr, false, "%s:%d: No wrapped data in Proxied DPP Configuration Result frame\n", __func__, __LINE__);

    // Unwrap with k_e
    auto [unwrapped_attrs, unwrapped_attrs_len] = ec_util::unwrap_wrapped_attrib(*wrapped_attr, frame, false, e_ctx->ke);
    if (unwrapped_attrs == nullptr || unwrapped_attrs_len == 0) {
        em_printfout("Failed to unwrap attributes.");
        return false;
    }

    auto e_nonce_attr = ec_util::get_attrib(unwrapped_attrs, unwrapped_attrs_len, ec_attrib_id_enrollee_nonce);
    ASSERT_OPT_HAS_VALUE_FREE(e_nonce_attr, false, unwrapped_attrs, "%s:%d: DPP Connection Status Result frame did not contain E-nonce\n", __func__, __LINE__);

    if (conn_ctx->nonce_len != e_nonce_attr->length || memcmp(e_ctx->e_nonce, e_nonce_attr->data, e_nonce_attr->length) != 0) {
        em_printfout("E-nonce contained in DPP Connection Status Result frame for '%s' does not match E-nonce in stored connection context.", enrollee_mac.c_str());
        free(unwrapped_attrs);
        return false;
    }

    auto conn_status_attr = ec_util::get_attrib(unwrapped_attrs, unwrapped_attrs_len, ec_attrib_id_conn_status);
    ASSERT_OPT_HAS_VALUE_FREE(conn_status_attr, false, unwrapped_attrs, "%s:%d: DPP Connection Status frame did not contain a Connection Status attribute\n", __func__, __LINE__);

    cJSON *conn_status_obj = cJSON_ParseWithLength(reinterpret_cast<const char *>(conn_status_attr->data), conn_status_attr->length);

    std::string connection_status_str = cjson_utils::stringify(conn_status_obj);
    em_printfout("Received Connection Status object from Enrollee '" MACSTRFMT "':\n%s", MAC2STR(src_mac), connection_status_str.c_str());

    cJSON_Delete(conn_status_obj);
    free(unwrapped_attrs);
    return true;
}

bool ec_ctrl_configurator_t::handle_proxied_dpp_configuration_request(uint8_t *encap_frame, uint16_t encap_frame_len, uint8_t src_mac[ETH_ALEN])
{
    // EasyConnect 6.4.3.1 DPP Configuration Response Configurator Handling
    if (!encap_frame || encap_frame_len == 0) {
        em_printfout("Invalid encapsulated frame!");
        return false;
    }
    std::string e_mac = util::mac_to_string(src_mac);
    auto conn_ctx = get_conn_ctx(e_mac);
    auto e_ctx = get_eph_ctx(e_mac);
    ASSERT_NOT_NULL(conn_ctx, false, "%s:%d: No connection context for Enrollee '" MACSTRFMT "'\n", __func__, __LINE__, MAC2STR(src_mac));
    ASSERT_NOT_NULL(conn_ctx->net_access_key, false, "%s:%d: Enrollee '" MACSTRFMT "' netAccessKey is NULL!\n", __func__, __LINE__, MAC2STR(src_mac));
    ASSERT_NOT_NULL(e_ctx, false, "%s:%d: No ephemeral context found for Enrollee '" MACSTRFMT "'\n", __func__, __LINE__, MAC2STR(src_mac));
    ec_gas_initial_request_frame_t *initial_request_frame = reinterpret_cast<ec_gas_initial_request_frame_t *>(encap_frame);

    uint8_t session_dialog_token = initial_request_frame->base.dialog_token;
    auto wrapped_attrs = ec_util::get_attrib(initial_request_frame->query, initial_request_frame->query_len, ec_attrib_id_wrapped_data);
    ASSERT_OPT_HAS_VALUE(wrapped_attrs, false, "%s:%d: No wrapped data attribute found!\n", __func__, __LINE__);
    
    ASSERT_NOT_NULL(e_ctx->ke, false, "%s:%d: Ephemeral context for Enrollee '" MACSTRFMT "' does not contain valid key 'ke'!\n", __func__, __LINE__, MAC2STR(src_mac));
    auto [unwrapped_attrs, unwrapped_attrs_len] = ec_util::unwrap_wrapped_attrib(*wrapped_attrs, initial_request_frame->query, false, e_ctx->ke);
    if (unwrapped_attrs == nullptr || unwrapped_attrs_len == 0) {
        em_printfout("Failed to unwraped wrapped data, aborting!");
        return false;
    }
    auto e_nonce_attr = ec_util::get_attrib(unwrapped_attrs, unwrapped_attrs_len, ec_attrib_id_enrollee_nonce);
    ASSERT_OPT_HAS_VALUE_FREE(e_nonce_attr, false, unwrapped_attrs, "%s:%d: No Enrollee nonce attribute found!\n", __func__, __LINE__);
    uint16_t e_nonce_len = e_nonce_attr->length;
    if (e_nonce_len != conn_ctx->nonce_len) {
        em_printfout("Enrollee nonce length (%d) does not match expected length (%d)!", e_nonce_len, conn_ctx->nonce_len);
        free(unwrapped_attrs);
        return false;
    }
    // Copy the Enrollee nonce to the context
    if (!(e_ctx->e_nonce = static_cast<uint8_t *>(calloc(1, e_nonce_len)))) {
        em_printfout("Failed to allocate memory for Enrollee nonce!");
        free(unwrapped_attrs);
        return false;
    }
    memcpy(e_ctx->e_nonce, e_nonce_attr->data, e_nonce_len);

    auto proto_key_attr = ec_util::get_attrib(unwrapped_attrs, unwrapped_attrs_len, ec_attrib_id_init_proto_key);
    // This is conditionally included if Configurator has requested the Enrollee to create a new keypair as part of Reconfiguration.
    if (proto_key_attr) {
        // EC 6.3.1:
        // The protocol key of the Enrollee is used as Network Access key (netAccessKey) later in the DPP Configuration and DPP Introduction protocol
        // For initial auth/config, Configurator holds the Initator role and the Enrollee is the Respondor
        auto [x, y] = ec_crypto::get_ec_x_y(*conn_ctx, e_ctx->public_resp_proto_key);
        conn_ctx->net_access_key = em_crypto_t::create_ec_key_from_coordinates(ec_crypto::BN_to_vec(x), ec_crypto::BN_to_vec(y), ec_crypto::BN_to_vec(e_ctx->priv_resp_proto_key));
        if (conn_ctx->net_access_key == nullptr) {
            em_printfout("Could not derive net access key from Enrollee protocol keypair");
            BN_free(x);
            BN_free(y);
            free(unwrapped_attrs);
            return false;
        }
    }

    auto dpp_config_request_obj_attr = ec_util::get_attrib(unwrapped_attrs, unwrapped_attrs_len, ec_attrib_id_dpp_config_req_obj);
    ASSERT_OPT_HAS_VALUE_FREE(dpp_config_request_obj_attr, false, unwrapped_attrs, "%s:%d: No DPP Configuration Request Object found in DPP Configuration Request frame!\n", __func__, __LINE__);

    cJSON *dpp_config_request_json = cJSON_ParseWithLength(reinterpret_cast<const char *>(dpp_config_request_obj_attr->data), dpp_config_request_obj_attr->length);
    ASSERT_NOT_NULL_FREE(dpp_config_request_json, false, unwrapped_attrs, "%s:%d: Failed to parse DPP Configuration Request Object JSON!\n", __func__, __LINE__);
    cJSON *wifi_tech = cJSON_GetObjectItem(dpp_config_request_json, "wi-fi_tech");
    ASSERT_NOT_NULL_FREE(wifi_tech, false, unwrapped_attrs, "%s:%d: DPP Configuration Request Object does not contain 'wi-fi_tech' field!\n", __func__, __LINE__);
    cJSON *netRole = cJSON_GetObjectItem(dpp_config_request_json, "netRole");
    ASSERT_NOT_NULL_FREE(netRole, false, unwrapped_attrs, "%s:%d: DPP Configuration Request Object does not contain 'netRole' field!\n", __func__, __LINE__);
    bool onboarding_sta_device = (std::string(wifi_tech->valuestring) == "infra" && std::string(netRole->valuestring) == "sta");

    // Copy the DPP Configuration Request Object string to an std::string to free the unwrapped attributes
    std::string dpp_config_request_obj_str(reinterpret_cast<char *>(dpp_config_request_obj_attr->data), dpp_config_request_obj_attr->length);
    free(unwrapped_attrs);

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
        em_printfout("DPP Configuration Request frame received, but we cannot onboard any more APs! Rejecting with status %s", ec_util::status_code_to_string(DPP_STATUS_CONFIGURATION_FAILURE).c_str());
        auto [config_response_frame, config_response_frame_len] = create_config_response_frame(src_mac, session_dialog_token, DPP_STATUS_CONFIGURATION_FAILURE);
        std::string status_code_str =  ec_util::status_code_to_string(DPP_STATUS_CONFIGURATION_FAILURE);

        em_printfout("Sending DPP Configuration Response frame for Enrollee '" MACSTRFMT "' over 1905 with DPP status code %s", MAC2STR(src_mac), status_code_str.c_str());
        bool sent = m_send_prox_encap_dpp_msg(reinterpret_cast<em_encap_dpp_t*>(config_response_frame), config_response_frame_len, nullptr, config_response_frame_len);
        if (!sent) {
            em_printfout("Failed to send DPP Configuration Response for Enrollee '" MACSTRFMT "'", MAC2STR(src_mac));
        }
        free(config_response_frame);
        return sent;
    }

    /*
    EasyConnect 7.5
    When a device is set-up as a Configurator, it generates the key pair (c-sign-key, C-sign-key), to sign and verify Connectors, respectively.
    */
    conn_ctx->C_signing_key = em_crypto_t::generate_ec_key(conn_ctx->nid);


    /*
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
    */
    auto [config_response_frame, config_response_frame_len] = create_config_response_frame(src_mac, session_dialog_token, DPP_STATUS_OK, onboarding_sta_device);
    if (config_response_frame == nullptr || config_response_frame_len == 0) {
        em_printfout("Failed to create Configuration Respone frame");
        return false;
    }
    bool sent = m_send_prox_encap_dpp_msg(reinterpret_cast<em_encap_dpp_t*>(config_response_frame), config_response_frame_len, nullptr, 0);
    if (!sent) {
        em_printfout("Failed to send Proxied Encap DPP message containing DPP Configuration frame to '" MACSTRFMT "'", MAC2STR(src_mac));
        free(config_response_frame);
        return false;
    }
    return true;
}

bool ec_ctrl_configurator_t::handle_auth_response(ec_frame_t *frame, size_t len, uint8_t src_mac[ETHER_ADDR_LEN])
{

    std::string enrollee_mac = util::mac_to_string(src_mac);

    auto conn_ctx = get_conn_ctx(enrollee_mac);
    ASSERT_NOT_NULL(conn_ctx, false, "%s:%d: No connection context for Enrollee '" MACSTRFMT "'\n", __func__, __LINE__, MAC2STR(src_mac));
    auto e_ctx = get_eph_ctx(enrollee_mac);
    ASSERT_NOT_NULL(e_ctx, false, "%s:%d: Ephemeral context not found for enrollee MAC %s\n", __func__, __LINE__, enrollee_mac.c_str());

    if (ec_util::validate_frame(frame, ec_frame_type_auth_rsp) == false) {
        em_printfout("frame validation failed");
        return false;
    }

    size_t attrs_len = len - EC_FRAME_BASE_SIZE;

    auto status_attrib = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_dpp_status);
    ASSERT_OPT_HAS_VALUE(status_attrib, false, "%s:%d: No DPP status attribute found\n", __func__, __LINE__);
    
    ec_status_code_t dpp_status = static_cast<ec_status_code_t>(status_attrib->data[0]);

    auto prim_wrapped_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_wrapped_data);
    ASSERT_OPT_HAS_VALUE(prim_wrapped_attr, false, "%s:%d: No wrapped data attribute found\n", __func__, __LINE__);

    if (dpp_status != DPP_STATUS_OK) {
        em_printfout("DPP Status not OK");

        // Unwrap the wrapped data with the K1 key

        auto [unwrapped_data, unwrapped_data_len] =  ec_util::unwrap_wrapped_attrib(*prim_wrapped_attr, frame, true, e_ctx->k1);
        if (unwrapped_data == NULL || unwrapped_data_len == 0) {
            em_printfout("Failed to unwrap wrapped data");
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

        em_printfout("Recieved Improper DPP Status: \"%s\"", ec_util::status_code_to_string(dpp_status).c_str());
        return false;
    }

    // DPP Status is OK

    // Initiator Bootstrapping Key Hash is present, allow mutual auth.
    auto B_i_hash_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_init_bootstrap_key_hash);
    e_ctx->is_mutual_auth = B_i_hash_attr.has_value(); // If the attribute is present, mutual authentication is possible

    auto P_r_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_resp_proto_key);
    ASSERT_OPT_HAS_VALUE(P_r_attr, false, "%s:%d: No Responder Public Protocol Key attribute found\n", __func__, __LINE__);

    // Decode the Responder Public Protocol Key
    e_ctx->public_resp_proto_key = ec_crypto::decode_ec_point(*conn_ctx, P_r_attr->data);
    ASSERT_NOT_NULL(e_ctx->public_resp_proto_key, false, "%s:%d: Failed to decode Responder Public Protocol Key\n", __func__, __LINE__);

    // Compute the N.x
    ASSERT_NOT_NULL(e_ctx->priv_init_proto_key, false, "%s:%d: initiator (self) protocol private key was never generated\n", __func__, __LINE__);
    e_ctx->n = ec_crypto::compute_ec_ss_x(*conn_ctx, e_ctx->priv_init_proto_key, e_ctx->public_resp_proto_key);
    const BIGNUM *bn_inputs[1] = { e_ctx->n };
    // Compute the "second intermediate key" (k2)
    e_ctx->k2 = static_cast<uint8_t *>(calloc(conn_ctx->digest_len, 1));
    if (ec_crypto::compute_hkdf_key(*conn_ctx, e_ctx->k2, conn_ctx->digest_len, "second intermediate key", bn_inputs, 1, NULL, 0) == 0) {
        em_printfout("Failed to compute k2"); 
        return false;
    }

    printf("Key K_2:\n");
    util::print_hex_dump(conn_ctx->digest_len, e_ctx->k2);

    // Unwrap the wrapped data with the K2 key
    auto [prim_unwrapped_data, prim_unwrapped_len] =  ec_util::unwrap_wrapped_attrib(*prim_wrapped_attr, frame, true, e_ctx->k2);
    if (prim_unwrapped_data == NULL || prim_unwrapped_len == 0) {
        em_printfout("Failed to unwrap wrapped data");
        // Abort the exchange
        return false;
    }

    // Verify the recieved I-nonce is the same sent in the Authentication Request
    auto i_nonce_attr = ec_util::get_attrib(prim_unwrapped_data, prim_unwrapped_len, ec_attrib_id_init_nonce);
    ASSERT_OPT_HAS_VALUE_FREE(i_nonce_attr, false, prim_unwrapped_data, "%s:%d: No Initiator Nonce attribute found\n", __func__, __LINE__);

    if (e_ctx->i_nonce == nullptr) {
        em_printfout("Initiator Nonce is nullptr! Aborting.");
        free(prim_unwrapped_data);
        return false;
    }

    if (memcmp(e_ctx->i_nonce, i_nonce_attr->data, i_nonce_attr->length) != 0) {
        em_printfout("Initiator Nonce does not match ephemeral context's initiator nonce! Aborting.");
        em_printfout("Ephemeral context i-nonce:");
        util::print_hex_dump(conn_ctx->nonce_len, e_ctx->i_nonce);
        em_printfout("Received i-nonce:");
        util::print_hex_dump(i_nonce_attr->length, i_nonce_attr->data);
        free(prim_unwrapped_data);
        return false;
    }

    auto r_nonce_attr = ec_util::get_attrib(prim_unwrapped_data, prim_unwrapped_len, ec_attrib_id_resp_nonce);
    ASSERT_OPT_HAS_VALUE_FREE(r_nonce_attr, false, prim_unwrapped_data, "%s:%d: No Responder Nonce attribute found\n", __func__, __LINE__);

    // Set the Responder Nonce
    e_ctx->r_nonce = reinterpret_cast<uint8_t*>(calloc(r_nonce_attr->length, 1));
    ASSERT_NOT_NULL_FREE(e_ctx->r_nonce, false, prim_unwrapped_data, "%s:%d: Failed to allocate memory for Responder Nonce\n", __func__, __LINE__);
    memcpy(e_ctx->r_nonce, r_nonce_attr->data, r_nonce_attr->length);

    // Get Responder Capabilities
    auto resp_caps_attr = ec_util::get_attrib(prim_unwrapped_data, prim_unwrapped_len, ec_attrib_id_resp_caps);
    ASSERT_OPT_HAS_VALUE_FREE(resp_caps_attr, false, prim_unwrapped_data, "%s:%d: No Responder Capabilities attribute found\n", __func__, __LINE__);
    const ec_dpp_capabilities_t resp_caps = {
        .byte = resp_caps_attr->data[0]
    };

    // Verify Responder Capabilities
    if (!ec_util::check_caps_compatible(m_dpp_caps, resp_caps)) {
        em_printfout("Responder capabilities not supported");
        free(prim_unwrapped_data);

        auto [resp_frame, resp_len] = create_auth_confirm(enrollee_mac, DPP_STATUS_NOT_COMPATIBLE, NULL);
        ASSERT_NOT_NULL(resp_frame, false, "%s:%d: Failed to create response frame\n", __func__, __LINE__);

        auto [encap_dpp_tlv, encap_dpp_size] = ec_util::create_encap_dpp_tlv(0, src_mac, ec_frame_type_auth_cnf, resp_frame, resp_len);
        free(resp_frame);
        ASSERT_NOT_NULL(encap_dpp_tlv, false, "%s:%d: Failed to create Encap DPP TLV\n", __func__, __LINE__);

        // Send the encapsulated DPP message (with Encap TLV)
        if (!this->m_send_prox_encap_dpp_msg(encap_dpp_tlv, encap_dpp_size, NULL, 0)){
            em_printfout("Failed to send Encap DPP TLV");
        }
        free(encap_dpp_tlv);

        return false;
    }

    // B_R
    ASSERT_NOT_NULL(conn_ctx->boot_data.resp_pub_boot_key, false, "%s:%d: failed to get responder bootstrapping public key\n", __func__, __LINE__);
    // P_R
    ASSERT_NOT_NULL(e_ctx->public_resp_proto_key, false, "%s:%d: Responder Public Protocol Key was not recieved/set\n", __func__, __LINE__);

    if (e_ctx->is_mutual_auth){
        // b_I
        ASSERT_NOT_NULL(conn_ctx->boot_data.init_priv_boot_key, false, "%s:%d: failed to get initiator bootstrapping private key\n", __func__, __LINE__);

        // Perform **Initiator** L.x calculation (L = bI * (BR + PR))

        EC_POINT* sum = EC_POINT_new(conn_ctx->group);
        // Calculate (B_R + P_R)
        if (!EC_POINT_add(conn_ctx->group, sum, conn_ctx->boot_data.resp_pub_boot_key, e_ctx->public_resp_proto_key, conn_ctx->bn_ctx)){
            EC_POINT_free(sum);
            free(prim_unwrapped_data);
            em_printfout("failed to add public responder boot key and public responder protocol key");
            return false;
        }
        // Calculate b_I * (B_R + P_R)
        EC_POINT* L = EC_POINT_new(conn_ctx->group);
        if (!EC_POINT_mul(conn_ctx->group, L, NULL, sum, conn_ctx->boot_data.init_priv_boot_key, conn_ctx->bn_ctx)){
            EC_POINT_free(sum);
            EC_POINT_free(L);
            free(prim_unwrapped_data);
            em_printfout("failed to multiply private initiator boot key and sum of public responder boot key and public responder protocol key");
            return false;
        }
        EC_POINT_free(sum);
        BIGNUM* L_x = ec_crypto::get_ec_x(*conn_ctx, L);
        EC_POINT_free(L);
        if (L_x == NULL) {
            free(prim_unwrapped_data);
            em_printfout("failed to get x-coordinate of L");
            return false;
        }
        e_ctx->l = L_x;
    }

    e_ctx->k1 = static_cast<uint8_t *>(calloc(conn_ctx->digest_len, 1));
    if (ec_crypto::compute_ke(*conn_ctx, e_ctx, e_ctx->ke) == 0) {
        em_printfout("Failed to compute ke");
        free(prim_unwrapped_data);
        return false;
    }

    // Get secondary wrapped data from inside the primary wrapped data component
    //  EasyConnect 8.2.3

    auto sec_wrapped_attr = ec_util::get_attrib(prim_unwrapped_data, prim_unwrapped_len, ec_attrib_id_wrapped_data);
    ASSERT_OPT_HAS_VALUE_FREE(sec_wrapped_attr, false, prim_unwrapped_data, "%s:%d: No secondary wrapped data attribute found\n", __func__, __LINE__);

    // Unwrap the secondary wrapped data with the KE key
    auto [sec_unwrapped_data, sec_unwrapped_len] =  ec_util::unwrap_wrapped_attrib(*sec_wrapped_attr, frame, false, e_ctx->ke);
    ASSERT_NOT_NULL_FREE(sec_unwrapped_data, false, prim_unwrapped_data, "%s:%d: Failed to unwrap secondary wrapped data\n", __func__, __LINE__);

    // Free the primary unwrapped data since it is no longer needed (secondary unwrapped data is heap allocated)
    free(prim_unwrapped_data);

    // Get Responder Auth Tag
    auto resp_auth_tag_attr = ec_util::get_attrib(sec_unwrapped_data, sec_unwrapped_len, ec_attrib_id_resp_auth_tag);
    ASSERT_OPT_HAS_VALUE_FREE(resp_auth_tag_attr, false, sec_unwrapped_data, "%s:%d: No Responder Auth Tag attribute found\n", __func__, __LINE__);
    uint8_t resp_auth_tag[resp_auth_tag_attr->length] = {0};
    memcpy(resp_auth_tag, resp_auth_tag_attr->data, resp_auth_tag_attr->length);
    free(sec_unwrapped_data);


    // Compute R-auth’ = H(I-nonce | R-nonce | PI.x | PR.x | [ BI.x | ] BR.x | 0)

    // Get P_I.x, P_R.x, B_I.x, and B_R.x
    BIGNUM* P_I_x = ec_crypto::get_ec_x(*conn_ctx, e_ctx->public_init_proto_key);
    BIGNUM* P_R_x = ec_crypto::get_ec_x(*conn_ctx, e_ctx->public_resp_proto_key);
    BIGNUM* B_I_x = ec_crypto::get_ec_x(*conn_ctx, conn_ctx->boot_data.init_pub_boot_key);
    BIGNUM* B_R_x = ec_crypto::get_ec_x(*conn_ctx, conn_ctx->boot_data.resp_pub_boot_key);

    if (P_I_x == NULL || P_R_x == NULL || B_R_x == NULL) {
        em_printfout("Failed to get x-coordinates of P_I, P_R, and B_R");
        if (P_I_x) BN_free(P_I_x);
        if (P_R_x) BN_free(P_R_x);
        if (B_R_x) BN_free(B_R_x);
        if (B_I_x) BN_free(B_I_x);
        return false;
    }

    // B_I.x is not needed (can be null) if mutual authentication is not supported
    if (e_ctx->is_mutual_auth && B_I_x == NULL) {
        em_printfout("Failed to get x-coordinate of B_I");
        BN_free(P_I_x);
        BN_free(P_R_x);
        BN_free(B_R_x);
        return false;
    }

    easyconnect::hash_buffer_t r_auth_hb;
    ec_crypto::add_to_hash(r_auth_hb, e_ctx->i_nonce, conn_ctx->nonce_len);
    ec_crypto::add_to_hash(r_auth_hb, e_ctx->r_nonce, conn_ctx->nonce_len);
    ec_crypto::add_to_hash(r_auth_hb, P_I_x); //P_I
    ec_crypto::add_to_hash(r_auth_hb, P_R_x); //P_R
    if (e_ctx->is_mutual_auth) ec_crypto::add_to_hash(r_auth_hb, B_I_x); //B_I
    ec_crypto::add_to_hash(r_auth_hb, B_R_x); //B_R
    ec_crypto::add_to_hash(r_auth_hb, static_cast<uint8_t>(0)); // 0 octet

    uint8_t* r_auth_prime = ec_crypto::compute_hash(*conn_ctx, r_auth_hb);

    ASSERT_NOT_NULL(r_auth_prime, false, "%s:%d: Failed to compute R-auth'\n", __func__, __LINE__);

    if (memcmp(r_auth_prime, resp_auth_tag, sizeof(resp_auth_tag) != 0)) {
        em_printfout("R-auth' does not match Responder Auth Tag");
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
            em_printfout("Failed to send encapsulated DPP message");
        }

        free(encap_dpp_tlv);
        return false;
    }

    free(r_auth_prime);

    // Generate I-auth = H(R-nonce | I-nonce | PR.x | PI.x | BR.x | [ BI.x | ] 1)
    easyconnect::hash_buffer_t i_auth_hb;
    ec_crypto::add_to_hash(i_auth_hb, e_ctx->r_nonce, conn_ctx->nonce_len);
    ec_crypto::add_to_hash(i_auth_hb, e_ctx->i_nonce, conn_ctx->nonce_len);
    ec_crypto::add_to_hash(i_auth_hb, P_R_x); //P_R
    ec_crypto::add_to_hash(i_auth_hb, P_I_x); //P_I
    ec_crypto::add_to_hash(i_auth_hb, B_R_x); //B_R
    if (e_ctx->is_mutual_auth) ec_crypto::add_to_hash(i_auth_hb, B_I_x); //B_I
    ec_crypto::add_to_hash(i_auth_hb, static_cast<uint8_t> (1)); // 1 octet


    BN_free(P_I_x);
    BN_free(P_R_x);
    BN_free(B_R_x);
    if (B_I_x) BN_free(B_I_x);

    uint8_t* i_auth = ec_crypto::compute_hash(*conn_ctx, i_auth_hb);
    ASSERT_NOT_NULL(i_auth, false, "%s:%d: Failed to compute I-auth\n", __func__, __LINE__);

    auto [resp_frame, resp_len] = create_auth_confirm(enrollee_mac, DPP_STATUS_OK, i_auth);
    free(i_auth);
    ASSERT_NOT_NULL(resp_frame, false, "%s:%d: Failed to create response frame\n", __func__, __LINE__);

    auto [encap_dpp_tlv, encap_dpp_size] = ec_util::create_encap_dpp_tlv(0, src_mac, ec_frame_type_auth_cnf, resp_frame, resp_len);
    free(resp_frame);
    ASSERT_NOT_NULL(encap_dpp_tlv, false, "%s:%d: Failed to create Encap DPP TLV\n", __func__, __LINE__);

    // Send the encapsulated DPP message (with Encap TLV)
    if (!this->m_send_prox_encap_dpp_msg(encap_dpp_tlv, encap_dpp_size, NULL, 0)){
        em_printfout("Failed to send encapsulated DPP message");
        free(encap_dpp_tlv);
        return false;
    }

    free(encap_dpp_tlv);
    return true;
}

bool ec_ctrl_configurator_t::handle_recfg_announcement(ec_frame_t *encap_frame, size_t len, uint8_t sa[ETH_ALEN])
{
    if (encap_frame == nullptr || len == 0) {
        em_printfout("Malformed Reconfiguration Authentication Announcement frame");
        return false;
    }
    std::string enrollee_mac = util::mac_to_string(sa);


    size_t attrs_len = len - EC_FRAME_BASE_SIZE;

    ec_frame_t *frame = reinterpret_cast<ec_frame_t *>(encap_frame);
    auto conf_c_sign_key_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_C_sign_key_hash);
    ASSERT_OPT_HAS_VALUE(conf_c_sign_key_attr, false, "%s:%d: No Configurator C-sign-key hash in Reconfiguration Announcement frame\n", __func__, __LINE__);

    auto finite_cyclic_group_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_finite_cyclic_group);
    ASSERT_OPT_HAS_VALUE(finite_cyclic_group_attr, false, "%s:%d: No Finite Cyclic Group attribute in Reconfiguration Announcement frame\n", __func__, __LINE__);

    auto a_nonce_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_a_nonce);
    ASSERT_OPT_HAS_VALUE(a_nonce_attr, false, "%s:%d: No A-Nonce attribute in Reconfiguration Announcement frame\n", __func__, __LINE__);

    auto e_id_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_e_prime_id);
    ASSERT_OPT_HAS_VALUE(e_id_attr, false, "%s:%d: No E'-id attribute found in Reconfiguration Announcement frame\n", __func__, __LINE__);

    // In case there are multiple Configurators within RF range of the Enrollee, check the C-sign-key hash to ensure that this frame was
    // indeed meant for us and not some other Configurator.
    auto conn_ctx = get_conn_ctx(enrollee_mac);
    ASSERT_NOT_NULL(conn_ctx, false, "%s:%d: No known connection context for Enrollee '" MACSTRFMT "'\n", __func__, __LINE__, MAC2STR(sa));

    uint8_t *configurator_c_sign_hash = ec_crypto::compute_key_hash(conn_ctx->C_signing_key);
    if (memcmp(configurator_c_sign_hash, conf_c_sign_key_attr->data, conf_c_sign_key_attr->length) != 0) {
        em_printfout("Mismatched C-sign-key hash, perhaps meant for another Configurator? Ignoring Reconfiguration Announcement from '" MACSTRFMT "'", MAC2STR(sa));
        free(configurator_c_sign_hash);
        // Not an error.
        return true;
    }
    free(configurator_c_sign_hash);

    // TODO
    // Derive E-id from E'-id, used to index if Reconfiguration is already under-way.
    // scoped_ec_group group(ec_crypto::get_ec_group_from_tls_id(SWAP_LITTLE_ENDIAN(*reinterpret_cast<uint16_t*>(finite_cyclic_group_attr->data))));
    // scoped_ec_point a_nonce(ec_crypto::decode_ec_point(*conn_ctx, a_nonce_attr->data));
    // scoped_ec_point e_prime_id(ec_crypto::decode_ec_point(*conn_ctx, e_id_attr->data));

    // A-Nonce, FCG and E-prime-id are included here so that we can derive E-id from E'-id,
    // and use that as a unique ID by which we can determine if a given Enrollee's Reconfiguration is
    // currently being blocked by user intervention, or is already undergoing.
    // EC 6.5.3:
    // The Configurator determines from E-id if it already has serviced a DPP Reconfiguration Announcement frame from this
    // Enrollee and had to postpone that reconfiguration process, e.g., in case the user first had to solve a problem preventing a
    // successful connection of the Enrollee to the network. If that is still the case, the Configurator silently discards this DPP
    // Reconfiguration Announcement frame. Else, the Configurator continues with the DPP Reconfiguration protocol.

    // Instead, why not just use the Enrollee MAC?
    if (m_currently_undergoing_recfg.find(enrollee_mac) != m_currently_undergoing_recfg.end()) {
        em_printfout("Received Reconfiguration Announcement frame from '" MACSTRFMT "' but they're already undergoing Reconfiguration. Ignoring frame.", MAC2STR(sa));
        // Not an error.
        return true;
    }

    auto [recfg_auth_req_frame, recfg_auth_req_frame_len] = create_recfg_auth_request(enrollee_mac);
    ASSERT_NOT_NULL(recfg_auth_req_frame, false, "%s:%d: Failed to create Reconfiguration Authentication Request frame\n", __func__, __LINE__);

    auto [encap_dpp_tlv, encap_dpp_tlv_len] = ec_util::create_encap_dpp_tlv(0, sa, ec_frame_type_recfg_auth_req, recfg_auth_req_frame, recfg_auth_req_frame_len);
    ASSERT_NOT_NULL_FREE(encap_dpp_tlv, false, recfg_auth_req_frame, "%s:%d: Failed to create Encap DPP TLV\n", __func__, __LINE__);

    bool sent = m_send_prox_encap_dpp_msg(encap_dpp_tlv, encap_dpp_tlv_len, nullptr, 0);
    free(encap_dpp_tlv);
    free(recfg_auth_req_frame);
    if (sent) {
        m_currently_undergoing_recfg[enrollee_mac] = true;
        m_enrollee_successfully_onboarded[enrollee_mac] = false;
    }
    return sent;
}

bool ec_ctrl_configurator_t::handle_recfg_auth_response(ec_frame_t *frame, size_t len, uint8_t sa[ETH_ALEN])
{
    if (frame == nullptr || len == 0) {
        em_printfout("Malformed Reconfiguration Authentication Response frame");
        return false;
    }
    std::string enrollee_mac = util::mac_to_string(sa);


    auto conn_ctx = get_conn_ctx(enrollee_mac);
    ASSERT_NOT_NULL(conn_ctx, false, "%s:%d: No known connection context for Enrollee '" MACSTRFMT "'\n", __func__, __LINE__, MAC2STR(sa));
    auto e_ctx = get_eph_ctx(enrollee_mac);
    ASSERT_NOT_NULL(e_ctx, false, "%s:%d: Ephemeral context not found for enrollee MAC %s\n", __func__, __LINE__, enrollee_mac.c_str());

    size_t attrs_len = len - EC_FRAME_BASE_SIZE;

    auto trans_id_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_trans_id);
    ASSERT_OPT_HAS_VALUE(trans_id_attr, false, "%s:%d: No Transaction ID attribute found in Reconfiguration Authentication Response frame\n", __func__, __LINE__);

    auto version_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_proto_version);
    ASSERT_OPT_HAS_VALUE(version_attr, false, "%s:%d: No DPP Status attribute found in Reconfiguration Authentication Response frame\n", __func__, __LINE__);

    auto e_connector_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_dpp_connector);
    ASSERT_OPT_HAS_VALUE(e_connector_attr, false, "%s:%d: No DPP Connector attribute found in Reconfiguration Authentication Response frame\n", __func__, __LINE__);

    auto e_nonce_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_enrollee_nonce);
    ASSERT_OPT_HAS_VALUE(e_nonce_attr, false, "%s:%d: No E-Nonce attribute found in Reconfiguration Authentication Response frame\n", __func__, __LINE__);

    auto pr_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_resp_proto_key);
    ASSERT_OPT_HAS_VALUE(pr_attr, false, "%s:%d: No Resp Pub Proto Key attribute in Reconfiguration Authentication Response frame\n", __func__, __LINE__);

    auto wrapped_data_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_wrapped_data);
    ASSERT_OPT_HAS_VALUE(wrapped_data_attr, false, "%s:%d: No wrapped data attribute found in Reconfiguration Authentication Response frame\n", __func__, __LINE__);

    // EasyConnect 6.5.5: It verifies that the protocol version is 2 or higher
    uint8_t dpp_version = static_cast<uint8_t>(version_attr->data[0]);
    if (dpp_version < 2) {
        em_printfout("DPP Version %d not supported for Reconfiguration, must be at least 2", dpp_version);
        return false;
    }

    // Ensure transaction ID matches
    if (static_cast<uint8_t>(trans_id_attr->data[0]) != e_ctx->transaction_id) {
        em_printfout("Mis-matched transaction ID for Enrollee '%s', expected %d, got %d", enrollee_mac.c_str(), e_ctx->transaction_id, static_cast<uint8_t>(trans_id_attr->data[0]));
        return false;
    }

    // It also verifies that the E-Connector is valid
    // Spec doesn't specifiy what "valid" means, but we can assume it means well-formed and contains the correct netRole
    auto payload = ec_crypto::get_jws_payload(std::string(reinterpret_cast<const char *>(e_connector_attr->data), static_cast<size_t>(e_connector_attr->length)).c_str());
    ASSERT_OPT_HAS_VALUE(payload, false, "%s:%d: Failed to split and decode E-Connector\n", __func__, __LINE__);

    cJSON *net_role = cJSON_GetObjectItem(payload.value(), "netRole");
    if (net_role == nullptr || !cJSON_IsString(net_role) || strcmp(net_role->valuestring, "ap")) {
        em_printfout("Invalid E-Connector netRole, expected \"ap\", got \"%s\"", net_role ? net_role->valuestring : "null");
        return false;
    }

    // Get public netAccessKey (C_R) from E-Connector
    cJSON *net_access_key = cJSON_GetObjectItem(payload.value(), "netAccessKey");
    ASSERT_NOT_NULL(net_access_key, false, "%s:%d: No netAccessKey in E-Connector body\n", __func__, __LINE__);
    cJSON_Delete(payload.value());
    scoped_ec_point C_R(ec_crypto::decode_ec_point_from_connector_netaccesskey(*conn_ctx, net_access_key));
    ASSERT_NOT_NULL(C_R.get(), false, "%s:%d: Failed to decode public key from netAccessKey in E-Connector\n", __func__, __LINE__);

    // Decode P_R generated by Enrollee
    e_ctx->public_resp_proto_key = ec_crypto::decode_ec_point(*conn_ctx, pr_attr->data);
    ASSERT_NOT_NULL(e_ctx->public_resp_proto_key, false, "%s:%d: Failed to decode Responder Public Protocol Key\n", __func__, __LINE__);

    // Get c_I from our own C-Connector
    scoped_bn c_I(em_crypto_t::get_priv_key_bn(conn_ctx->net_access_key));
    ASSERT_NOT_NULL(c_I.get(), false, "%s:%d: Failed to get private key from C-Connector\n", __func__, __LINE__);

    // Compute M = (C_R + P_R) * c_I

    // (C_R + P_R)
    scoped_ec_point sum(EC_POINT_new(conn_ctx->group));
    ASSERT_NOT_NULL(sum.get(), false, "%s:%d: Failed to allocate EC_POINT\n", __func__, __LINE__);
    if (!EC_POINT_add(conn_ctx->group, sum.get(), C_R.get(), e_ctx->public_resp_proto_key, conn_ctx->bn_ctx)) {
        em_printfout("Failed to compute C_R + P_R");
        return false;
    }

    // sum * c_I = M.x
    BN_free(e_ctx->m);
    e_ctx->m = ec_crypto::compute_ec_ss_x(*conn_ctx, c_I.get(), sum.get());
    ASSERT_NOT_NULL(e_ctx->m, false, "%s:%d: Failed to compute M.x\n", __func__, __LINE__);

    // Concat C-Nonce | E-Nonce as salt for ke
    std::vector<uint8_t> salt = ec_crypto::concat_nonces({
        std::vector<uint8_t>(e_ctx->c_nonce, e_ctx->c_nonce + conn_ctx->nonce_len),
        std::vector<uint8_t>(e_nonce_attr->data, e_nonce_attr->data + e_nonce_attr->length)
    });

    if (salt.empty()) {
        em_printfout("Failed to concatenate C-Nonce and E-Nonce for ke derivation");
        return false;
    }

    // ke = HKDF(C-nonce | E-nonce, "dpp reconfig key", M.x)
    const BIGNUM *inputs[] = { e_ctx->m };
    if (ec_crypto::compute_hkdf_key(*conn_ctx, e_ctx->ke, conn_ctx->digest_len, "dpp reconfig key", inputs, 1, salt.data(), salt.size()) == 0) {
        em_printfout("Failed to compute ke");
        return false;
    }

    // EasyConnect 6.5.5:
    // It uses the derived ke and attempts to decrypt the encrypted object. If the Configurator successfully decrypts the payload, it
    // verifies that the C-nonce in it matches the value sent in the DPP Reconfiguration Authentication Request frame. If the
    // value matches, the Configurator can use the information in the Connection Status object to set the values in the Reconfig-
    // Flags attribute. It also saves the Enrollee's nonce

    // The Configurator shall set the value of DPP Status field to STATUS_OK when all of the above checks passes
    // successfully and when the Configurator is able to proceed immediately with the DPP Configuration protocol.
    // The Configurator shall set the value of DPP Status field to STATUS_AUTH_FAILURE if one or more of the above checks
    // did not pass successfully.
    ec_status_code_t dpp_status = DPP_STATUS_OK;
    auto [wrapped_data, wrapped_data_len] = ec_util::unwrap_wrapped_attrib(*wrapped_data_attr, frame, true, e_ctx->ke);
    if (wrapped_data == nullptr || wrapped_data_len == 0) {
        em_printfout("Failed to unwrap wrapped data in Reconfiguration Authentication Response frame using new ke");
        dpp_status = DPP_STATUS_AUTH_FAILURE;
    }

    if (wrapped_data) {
        auto c_nonce_attr = ec_util::get_attrib(wrapped_data, wrapped_data_len, ec_attrib_id_config_nonce);
        if (!c_nonce_attr.has_value()) {
            em_printfout("No C-Nonce attribute found in wrapped data of Reconfiguration Authentication Response frame");
            dpp_status = DPP_STATUS_AUTH_FAILURE;
        } else if (memcmp(e_ctx->c_nonce, c_nonce_attr->data, c_nonce_attr->length) != 0) {
            em_printfout("Mis-matched C-Nonce in Reconfiguration Authentication Response frame");
            dpp_status = DPP_STATUS_AUTH_FAILURE;
        }
    }

    //  If the value matches, the Configurator can use the information in the Connection Status object to set the values in the Reconfig-
    // Flags attribute. It also saves the Enrollee's nonce.
    ec_crypto::rand_zero(e_ctx->e_nonce, conn_ctx->nonce_len);
    memcpy(e_ctx->e_nonce, e_nonce_attr->data, conn_ctx->nonce_len);

    ec_status_code_t enrollee_status = DPP_STATUS_OK;
    // Note: spec does not specify **how** to use the Conn Status object to set the Reconfig Flags attr,
    // so assume STATUS_OK == REUSE, != STATUS_OK == REPLACE
    auto conn_status_attr = ec_util::get_attrib(wrapped_data, wrapped_data_len, ec_attrib_id_conn_status);
    if (!conn_status_attr.has_value()) {
        em_printfout("Connection Status Result attribute missing from Reconfiguration Authentication Response frame, assuming Enrollee DPP STATUS != STATUS_OK");
        dpp_status = DPP_STATUS_AUTH_FAILURE;
        enrollee_status = DPP_STATUS_AUTH_FAILURE;
    }

    cJSON *conn_status_json = cJSON_ParseWithLength(reinterpret_cast<const char *>(conn_status_attr->data), static_cast<size_t>(conn_status_attr->length));
    cJSON *status = cJSON_GetObjectItem(conn_status_json, "result");
    if (status != nullptr && cJSON_IsNumber(status)) dpp_status = static_cast<ec_status_code_t>(status->valueint);


    auto [auth_confirm_frame, auth_confirm_frame_len] = create_recfg_auth_confirm(enrollee_mac, dpp_status, enrollee_status, static_cast<uint8_t>(trans_id_attr->data[0]));
    if (auth_confirm_frame == nullptr || auth_confirm_frame_len == 0) {
        em_printfout("Failed to create Reconfiguration Authentication Confirm frame");
        if (wrapped_data) free(wrapped_data);
        return false;
    }

    // The Configurator sets a timer for 2 seconds and waits for the Enrollee to start the DPP Configuration (2s dwell)
    bool sent = m_send_action_frame(sa, reinterpret_cast<uint8_t*>(auth_confirm_frame), auth_confirm_frame_len, 0, 2);
    if (wrapped_data) free(wrapped_data);
    free(auth_confirm_frame);
    return sent;
}

std::pair<uint8_t *, size_t> ec_ctrl_configurator_t::create_auth_request(std::string enrollee_mac)
{

    em_printfout("Enter");
    auto conn_ctx = get_conn_ctx(enrollee_mac);
    ASSERT_NOT_NULL(conn_ctx, {}, "%s:%d: No connection context for Enrollee '" MACSTRFMT "'\n", __func__, __LINE__, MAC2STR(enrollee_mac));
    auto e_ctx = get_eph_ctx(enrollee_mac);
    ASSERT_NOT_NULL(e_ctx, {}, "%s:%d: Ephemeral context not found for enrollee MAC %s\n", __func__, __LINE__, enrollee_mac.c_str());

    ec_frame_t *frame =  ec_util::alloc_frame(ec_frame_type_auth_req);
    ASSERT_NOT_NULL(frame, {}, "%s:%d failed to allocate memory for frame\n", __func__, __LINE__);

    // Start EasyConnect 6.3.2

    // Generate initiator nonce
    if (RAND_bytes(e_ctx->i_nonce, conn_ctx->nonce_len) != 1) {
        em_printfout("Failed to generate i-nonce!");
        free(frame);
        return {};
    }

    em_printfout("i-nonce");
    util::print_hex_dump(conn_ctx->nonce_len, e_ctx->i_nonce);

    // Generate initiator protocol key pair (p_i/P_I)
    auto [priv_init_proto_key, pub_init_proto_key] = ec_crypto::generate_proto_keypair(*conn_ctx);
    if (priv_init_proto_key == NULL || pub_init_proto_key == NULL) {
        em_printfout("failed to generate initiator protocol key pair");
        free(frame);
        return {};
    }
    e_ctx->priv_init_proto_key = const_cast<BIGNUM*>(priv_init_proto_key);
    e_ctx->public_init_proto_key = const_cast<EC_POINT*>(pub_init_proto_key);

    // Compute the M.x
    ASSERT_NOT_NULL_FREE(conn_ctx->boot_data.resp_pub_boot_key, {}, frame, "%s:%d failed to get responder bootstrapping public key\n", __func__, __LINE__);

    e_ctx->m = ec_crypto::compute_ec_ss_x(*conn_ctx, e_ctx->priv_init_proto_key, conn_ctx->boot_data.resp_pub_boot_key);
    const BIGNUM *bn_inputs[1] = { e_ctx->m };
    // Compute the "first intermediate key" (k1)
    e_ctx->k1 = static_cast<uint8_t *>(calloc(conn_ctx->digest_len, 1));
    if (ec_crypto::compute_hkdf_key(*conn_ctx, e_ctx->k1, conn_ctx->digest_len, "first intermediate key", bn_inputs, 1, NULL, 0) == 0) {
        em_printfout("Failed to compute k1");
        free(frame);
        return {};
    }

    printf("Key K_1:\n");
    util::print_hex_dump(static_cast<unsigned int> (conn_ctx->digest_len), e_ctx->k1);
    
    uint8_t* attribs = NULL;
    size_t attribs_len = 0;

    // Responder Bootstrapping Key Hash: SHA-256(B_R)
    uint8_t* responder_keyhash = ec_crypto::compute_key_hash(conn_ctx->boot_data.responder_boot_key);
    ASSERT_NOT_NULL_FREE2(responder_keyhash, {}, frame, attribs, "%s:%d failed to compute responder bootstrapping key hash\n", __func__, __LINE__);

    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_resp_bootstrap_key_hash, SHA256_DIGEST_LENGTH, responder_keyhash);
    free(responder_keyhash);

    // Initiator Bootstrapping Key Hash: SHA-256(B_I)
    if (conn_ctx->boot_data.initiator_boot_key != NULL){
        // If != NULL, mutual authentication can be performed.
        uint8_t* initiator_keyhash = ec_crypto::compute_key_hash(conn_ctx->boot_data.initiator_boot_key);
        ASSERT_NOT_NULL_FREE2(initiator_keyhash, {}, frame, attribs, "%s:%d failed to compute initiator bootstrapping key hash\n", __func__, __LINE__); 
    
        attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_init_bootstrap_key_hash, SHA256_DIGEST_LENGTH, initiator_keyhash);
        free(initiator_keyhash);
    }


    // Public Initiator Protocol Key: P_I
    auto protocol_key_buff = ec_crypto::encode_ec_point(*conn_ctx, e_ctx->public_init_proto_key);
    ASSERT_NOT_NULL_FREE2(protocol_key_buff, {}, frame, attribs, "%s:%d failed to encode public initiator protocol key\n", __func__, __LINE__);

    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_init_proto_key, static_cast<uint16_t>(2*BN_num_bytes(conn_ctx->prime)), protocol_key_buff);

    // Protocol Version
    // if (m_cfgrtr_ver > 1) {
    //     attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_proto_version, m_cfgrtr_ver);
    // }

    // Channel Attribute (optional)
    //TODO: REVISIT THIS
    if (conn_ctx->boot_data.ec_freqs[0] != 0){
        unsigned int base_freq = conn_ctx->boot_data.ec_freqs[0]; 
        uint16_t chann_attr = ec_util::freq_to_channel_attr(base_freq);
        attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_channel, sizeof(uint16_t), reinterpret_cast<uint8_t*>(&chann_attr));
    }


    // Wrapped Data (with Initiator Nonce and Initiator Capabilities)
    // EasyMesh 8.2.2 Table 36
    attribs = ec_util::add_wrapped_data_attr(frame, attribs, &attribs_len, true, e_ctx->k1, [&](){
        uint8_t* wrap_attribs = NULL;
        size_t wrapped_len = 0;
        wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_init_nonce, static_cast<uint16_t>(conn_ctx->nonce_len), e_ctx->i_nonce);
        wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_init_caps, m_dpp_caps.byte);
        return std::make_pair(wrap_attribs, wrapped_len);
    });

    // Add attributes to the frame
    if (!(frame = ec_util::copy_attrs_to_frame(frame, attribs, attribs_len))) {
        em_printfout("unable to copy attributes to frame");
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

    auto conn_ctx = get_conn_ctx(enrollee_mac);
    ASSERT_NOT_NULL(conn_ctx, {}, "%s:%d: Connection context not found\n", __func__, __LINE__);
    auto e_ctx = get_eph_ctx(enrollee_mac);
    ASSERT_NOT_NULL(e_ctx, {}, "%s:%d: Ephemeral context not found for enrollee MAC %s\n", __func__, __LINE__, enrollee_mac.c_str());

    if (dpp_status == DPP_STATUS_OK && i_auth_tag == NULL) {
        em_printfout("I-auth tag is NULL");
        return {};
    }

    ec_frame_t *frame =  ec_util::alloc_frame(ec_frame_type_auth_cnf);
    ASSERT_NOT_NULL(frame, {}, "%s:%d failed to allocate memory for frame\n", __func__, __LINE__);

    uint8_t* attribs = NULL;
    size_t attribs_len = 0;
    
    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_dpp_status, static_cast<uint8_t>(dpp_status));

    // Add Responder Bootstrapping Key Hash (SHA-256(B_R))
    uint8_t* responder_keyhash = ec_crypto::compute_key_hash(conn_ctx->boot_data.responder_boot_key);
    ASSERT_NOT_NULL_FREE2(responder_keyhash, {}, frame, attribs, "%s:%d failed to compute responder bootstrapping key hash\n", __func__, __LINE__);

    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_resp_bootstrap_key_hash, SHA256_DIGEST_LENGTH, responder_keyhash);
    free(responder_keyhash);
    // Conditional (Only included for mutual authentication) (SHA-256(B_I))
    if (e_ctx->is_mutual_auth) {
        uint8_t* initiator_keyhash = ec_crypto::compute_key_hash(conn_ctx->boot_data.initiator_boot_key);
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
            wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_init_auth_tag, conn_ctx->digest_len, i_auth_tag);
        } else {
            wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_resp_nonce, conn_ctx->nonce_len, e_ctx->r_nonce);
        }
        return std::make_pair(wrap_attribs, wrapped_len);
    });

    if (!(frame = ec_util::copy_attrs_to_frame(frame, attribs, attribs_len))) {
        em_printfout("unable to copy attributes to frame");
        free(frame);
        free(attribs);
        return {};
    }
    free(attribs);

    return std::make_pair(reinterpret_cast<uint8_t*>(frame), EC_FRAME_BASE_SIZE + attribs_len);
}

std::pair<uint8_t *, size_t> ec_ctrl_configurator_t::create_recfg_auth_request(const std::string& enrollee_mac)
{
    auto conn_ctx = get_conn_ctx(enrollee_mac);
    ASSERT_NOT_NULL(conn_ctx, {}, "%s:%d: No connection context for Enrolle '" MACSTRFMT "'\n", __func__, __LINE__, MAC2STR(enrollee_mac.c_str()));
    auto e_ctx = get_eph_ctx(enrollee_mac);
    ASSERT_NOT_NULL(e_ctx, {}, "%s:%d: No ephemeral context found for Enrollee '" MACSTRFMT "'\n", __func__, __LINE__, MAC2STR(enrollee_mac.c_str()));

    ec_frame_t *frame = ec_util::alloc_frame(ec_frame_type_recfg_auth_req);
    ASSERT_NOT_NULL(frame, {}, "%s:%d: Could not allocate memory for Reconfiguration Authentication Request frame\n", __func__, __LINE__);

    // C-Nonce
    memset(e_ctx->c_nonce, 0, conn_ctx->nonce_len);
    if (RAND_bytes(e_ctx->c_nonce, conn_ctx->nonce_len) != 1) {
        free(frame);
        em_printfout("Failed to generate C-Nonce");
        return {};
    }

    em_printfout("C-Nonce:");
    util::print_hex_dump(conn_ctx->nonce_len, e_ctx->c_nonce);

    static uint8_t transId = 0;

    uint8_t *attribs = nullptr;
    size_t attribs_len = 0UL;

    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_trans_id, transId++);
    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_proto_version, static_cast<uint8_t>(DPP_VERSION));
    // The Configurator issues itself a Connector, called C-Connector, that includes an netAccessKey on the curve indicated by
    // the received group attribute and that is signed with the signing key that corresponds to the received SHA-256 (C-sign-
    // key). The version in the C-Connector shall be set to the highest version that the Configurator supports.
    // The Configurator shall include a single octet transaction identifier TransId, a Protocol Version attribute containing the
    // same number as the version member in the C-Connector, the generated C-Connector and the generated C-nonce to
    // generated the DPP Reconfiguration Authentication Request frame and send this frame to the Enrollee.
    e_ctx->transaction_id = transId;

    cJSON *jwsHeaderObj = ec_crypto::create_jws_header("dppCon", conn_ctx->C_signing_key);

    std::vector<std::unordered_map<std::string, std::string>> groups = {
        {{"groupID", "mapNW"}, {"netRole", "configurator"}},
    };

    std::optional<std::string> null_expiry = std::nullopt;
    cJSON *jwsPayloadObj = ec_crypto::create_jws_payload(*conn_ctx, groups, conn_ctx->net_access_key, null_expiry, DPP_VERSION);

    auto connector = ec_crypto::generate_connector(jwsHeaderObj, jwsPayloadObj, conn_ctx->C_signing_key);
    ASSERT_OPT_HAS_VALUE(connector, {}, "%s:%d: Failed to generate C-Connector\n", __func__, __LINE__);
    e_ctx->connector = strdup(connector->c_str());

    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_dpp_connector, std::string(e_ctx->connector));
    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_config_nonce, conn_ctx->nonce_len, e_ctx->c_nonce);

    if ((frame = ec_util::copy_attrs_to_frame(frame, attribs, attribs_len)) == nullptr) {
        em_printfout("Failed to copy attributes to Reconfiguration Authentication Request frame");
        free(frame);
        free(attribs);
        return {};
    }

    free(attribs);
    return std::make_pair(reinterpret_cast<uint8_t *>(frame), EC_FRAME_BASE_SIZE + attribs_len);
}

std::pair<uint8_t *, size_t> ec_ctrl_configurator_t::create_recfg_auth_confirm(std::string enrollee_mac, ec_status_code_t dpp_status, ec_status_code_t enrollee_dpp_status, uint8_t trans_id)
{

    auto conn_ctx = get_conn_ctx(enrollee_mac);
    ASSERT_NOT_NULL(conn_ctx, {}, "%s:%d: Connection context not found\n", __func__, __LINE__);
    auto e_ctx = get_eph_ctx(enrollee_mac);
    ASSERT_NOT_NULL(e_ctx, {}, "%s:%d: Ephemeral context not found for enrollee MAC %s\n", __func__, __LINE__, enrollee_mac.c_str());

    ec_frame_t *frame =  ec_util::alloc_frame(ec_frame_type_recfg_auth_cnf);
    ASSERT_NOT_NULL(frame, {}, "%s:%d failed to allocate memory for frame\n", __func__, __LINE__);

    uint8_t* attribs = NULL;
    size_t attribs_len = 0;

    ec_dpp_reconfig_flags_t reconfig_flags = {.byte = 0};

    switch (enrollee_dpp_status) {
        case ec_status_code_t::DPP_STATUS_OK: {
            reconfig_flags.connector_key = DPP_CONFIG_REUSEKEY;
            break;
        }
        default: {
            reconfig_flags.connector_key = DPP_CONFIG_REPLACEKEY;
            break;
        }
    }

    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_dpp_status, static_cast<uint8_t>(dpp_status));

    attribs = ec_util::add_wrapped_data_attr(frame, attribs, &attribs_len, false, e_ctx->ke, [&](){
        uint8_t* wrap_attribs = NULL;
        size_t wrapped_len = 0;

        wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_trans_id, trans_id);
        wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_proto_version, static_cast<uint8_t>(conn_ctx->boot_data.version));
        wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_config_nonce, conn_ctx->nonce_len, e_ctx->c_nonce);
        wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_enrollee_nonce, conn_ctx->nonce_len, e_ctx->e_nonce);
        wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_reconfig_flags, sizeof(reconfig_flags), reinterpret_cast<uint8_t*>(&reconfig_flags));

        return std::make_pair(wrap_attribs, wrapped_len);
    });

    if (!(frame = ec_util::copy_attrs_to_frame(frame, attribs, attribs_len))) {
        em_printfout("unable to copy attributes to frame");
        free(frame);
        free(attribs);
        return {};
    }
    free(attribs);

    return std::make_pair(reinterpret_cast<uint8_t*>(frame), EC_FRAME_BASE_SIZE + attribs_len);
}

cJSON *ec_ctrl_configurator_t::finalize_config_obj(cJSON *base, ec_connection_context_t& conn_ctx, dpp_config_obj_type_e config_obj_type)
{
    if (base == nullptr) {
        em_printfout("Based a nullptr base Configuration object");
        return nullptr;
    }

    std::vector<std::unordered_map<std::string, std::string>> groups;

    switch(config_obj_type) {
        case dpp_config_obj_type_e::dpp_config_obj_bsta: {
            groups = {
                {{"groupID", "mapNW"}, {"netRole", "mapBackhaulSta"}}
            };
            break;
        }
        case dpp_config_obj_type_e::dpp_config_obj_ieee1905: {
            groups = {
                {{"groupID", "mapNW"}, {"netRole", "mapAgent"}}
            };
            break;
        }
        case dpp_config_obj_type_e::dpp_config_obj_fbss: {
            groups = {
                {{"groupID", "mapNW"}, {"netRole", "sta"}}
            };
            break;
        }
        default: {
            em_printfout("Unknown DPP Configuration object type %d", static_cast<int>(config_obj_type));
            return nullptr;
        }
    }

    cJSON *cred = cJSON_GetObjectItem(base, "cred");
    ASSERT_NOT_NULL_FREE(cred, nullptr, base, "%s:%d: Could not get \"cred\" from IEEE1905 DPP Configuration Object\n", __func__, __LINE__);
    // Create / add Connector.

    // Header
    cJSON *jwsHeaderObj = ec_crypto::create_jws_header("dppCon", conn_ctx.C_signing_key);

    cJSON *jwsPayloadObj = ec_crypto::create_jws_payload(conn_ctx, groups, conn_ctx.net_access_key);
    // Create / add connector
    std::optional<std::string> connector = ec_crypto::generate_connector(jwsHeaderObj, jwsPayloadObj, conn_ctx.C_signing_key);
    ASSERT_OPT_HAS_VALUE(connector, nullptr, "%s:%d: Failed to generate connector\n", __func__, __LINE__);
    cJSON_AddStringToObject(cred, "signedConnector", connector->c_str());

    // Add csign
    cJSON *cSignObj = ec_crypto::create_csign_object(conn_ctx, conn_ctx.C_signing_key);
    cJSON_AddItemToObject(cred, "csign", cSignObj);

    // Add ppKey
    cJSON *ppKeyObj = ec_crypto::create_ppkey_object(conn_ctx);
    cJSON_AddItemToObject(cred, "ppKey", ppKeyObj);
    return base;
}

std::pair<uint8_t *, size_t> ec_ctrl_configurator_t::create_config_response_frame(uint8_t dest_mac[ETH_ALEN], const uint8_t dialog_token, ec_status_code_t dpp_status, bool is_sta)
{
    const std::string enrollee_mac = util::mac_to_string(dest_mac);
    auto conn_ctx = get_conn_ctx(enrollee_mac);
    auto e_ctx = get_eph_ctx(enrollee_mac);
    ASSERT_NOT_NULL(conn_ctx, {}, "%s:%d: No connection context for Enrollee '" MACSTRFMT "'\n", __func__, __LINE__, MAC2STR(enrollee_mac.c_str()));
    ASSERT_NOT_NULL(e_ctx, {}, "%s:%d: No ephemeral context found for Enrollee '" MACSTRFMT "'\n", __func__, __LINE__, MAC2STR(enrollee_mac.c_str()));

    if (dpp_status != DPP_STATUS_OK) {
        auto [frame, frame_len] = ec_util::alloc_gas_frame(dpp_gas_action_type_t::dpp_gas_initial_resp, dialog_token);
        if (frame == nullptr || frame_len == 0) {
            em_printfout("Failed to create DPP Configuration Response frame!");
            return {};
        }
        ec_gas_initial_response_frame_t *response_frame = reinterpret_cast<ec_gas_initial_response_frame_t *>(frame);

        uint8_t *attribs = nullptr;
        size_t attribs_len = 0;

        // Configurator → Enrollee: DPP Status, { E-nonce }ke
        attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_dpp_status, static_cast<uint8_t>(dpp_status));
        attribs = ec_util::add_cfg_wrapped_data_attr(attribs, &attribs_len, true, e_ctx->ke, [&](){
            size_t wrapped_len = 0;
            uint8_t *wrapped_attribs = ec_util::add_attrib(nullptr, &wrapped_len, ec_attrib_id_enrollee_nonce, conn_ctx->nonce_len, e_ctx->e_nonce);
            return std::make_pair(wrapped_attribs, wrapped_len);
        });
        if ((response_frame = ec_util::copy_attrs_to_frame(response_frame, attribs, attribs_len)) == nullptr) {
            em_printfout("Failed to copy attribs to DPP Configuration Response frame!");
            free(response_frame);
            return {};
        }
        free(attribs);

        response_frame->resp_len = static_cast<uint16_t>(attribs_len);

        auto [proxy_encap_frame, proxy_encap_frame_len] = ec_util::create_encap_dpp_tlv(true, dest_mac, ec_frame_type_easymesh, reinterpret_cast<uint8_t*>(response_frame), sizeof(*response_frame) + attribs_len);
        if (proxy_encap_frame == nullptr || proxy_encap_frame_len == 0) {
            em_printfout("Could not create Proxied Encap DPP TLV!");
            free(response_frame);
            return {};
        }
        return std::make_pair(reinterpret_cast<uint8_t*>(proxy_encap_frame), proxy_encap_frame_len);
    }

    // DPP_STATUS_OK case.
    // 1905 Config Obj Always required
    conn_ctx->ppk = ec_crypto::create_ppkey_public(conn_ctx->C_signing_key);
    ASSERT_NOT_NULL(conn_ctx->ppk, {}, "%s:%d: Failed to generate ppK!\n", __func__, __LINE__);
    ASSERT_NOT_NULL(m_get_1905_info, {}, "%s:%d: Cannot generate 1905 Configuration Object, no callback!\n", __func__, __LINE__);

    cJSON *ieee1905_config_obj = m_get_1905_info(conn_ctx);
    if (ieee1905_config_obj == nullptr) {
        em_printfout("Failed to create IEEE1905 Configuration object");
        return {};
    }
    ieee1905_config_obj = finalize_config_obj(ieee1905_config_obj, *conn_ctx, dpp_config_obj_ieee1905);
    if (ieee1905_config_obj == nullptr) {
        em_printfout("Failed to finalize IEEE1905 Configuration object");
        return {};
    }
    std::string ieee1905_config_obj_str = cjson_utils::stringify(ieee1905_config_obj);
    cJSON_Delete(ieee1905_config_obj);
    em_printfout("IEEE1905 Configuration object:\n%s", ieee1905_config_obj_str.c_str());

    std::string bsta_config_obj_str, fbss_config_obj_str;
    // If not STA onboarding (i.e. onboarding an AP Enrollee), create backhaul STA configuration object
    if (!is_sta) {
        ASSERT_NOT_NULL(m_get_backhaul_sta_info, {}, "%s:%d: Enrollee '" MACSTRFMT "' requests bSTA config, but bSTA config callback is nullptr!\n", __func__, __LINE__, MAC2STR(dest_mac));
        cJSON *bsta_config_obj = m_get_backhaul_sta_info(conn_ctx);
        if (bsta_config_obj == nullptr) {
            em_printfout("Failed to create bSTA Configuration object");
            return {};
        }
        bsta_config_obj = finalize_config_obj(bsta_config_obj, *conn_ctx, dpp_config_obj_bsta);
        if (bsta_config_obj == nullptr) {
            em_printfout("Failed to finalize bSTA Configuration object");
            return {};
        }
        bsta_config_obj_str = cjson_utils::stringify(bsta_config_obj);
        cJSON_Delete(bsta_config_obj);
        em_printfout("bSTA Configuration object:\n%s", bsta_config_obj_str.c_str());
    } else {
        // If STA onboarding, send fBSS credentials
        ASSERT_NOT_NULL(m_get_fbss_info, {}, "%s:%d: Enrollee '" MACSTRFMT "' requests STA onboarding (fBSS credentials) but fBSS config callback is nullptr!\n", __func__, __LINE__, MAC2STR(dest_mac));
        cJSON *fbss_config_obj = m_get_fbss_info(conn_ctx);
        if (fbss_config_obj == nullptr) {
            em_printfout("Failed to create fBSS Configuration object");
            return {};
        }
        fbss_config_obj = finalize_config_obj(fbss_config_obj, *conn_ctx, dpp_config_obj_fbss);
        if (fbss_config_obj == nullptr) {
            em_printfout("Failed to finalize fBSS Configuration object");
            return {};
        }
        fbss_config_obj_str = cjson_utils::stringify(fbss_config_obj);
        cJSON_Delete(fbss_config_obj);
        em_printfout("fBSS Configuration object:\n%s", fbss_config_obj_str.c_str());
    }


    // Create DPP Configuration frame.
    auto [frame, frame_len] = ec_util::alloc_gas_frame(dpp_gas_action_type_t::dpp_gas_initial_resp, dialog_token);
    ASSERT_NOT_NULL(frame, {}, "%s:%d: Could not allocate DPP Configuration Response frame!\n", __func__, __LINE__);
    ec_gas_initial_response_frame_t *response_frame = reinterpret_cast<ec_gas_initial_response_frame_t *>(frame);

    uint8_t *attribs = nullptr;
    size_t attribs_len = 0;
    // Configurator → Enrollee: DPP Status, { E-nonce, configurationPayload [, sendConnStatus]}ke
    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_dpp_status, static_cast<uint8_t>(DPP_STATUS_OK));
    attribs = ec_util::add_cfg_wrapped_data_attr(attribs, &attribs_len, true, e_ctx->ke, [&]() {
        size_t wrapped_len = 0;
        uint8_t *wrapped_attribs = ec_util::add_attrib(nullptr, &wrapped_len, ec_attrib_id_enrollee_nonce, conn_ctx->nonce_len, e_ctx->e_nonce);
        wrapped_attribs = ec_util::add_attrib(wrapped_attribs, &wrapped_len, ec_attrib_id_dpp_config_obj, ieee1905_config_obj_str);
        if (!is_sta) {
            wrapped_attribs = ec_util::add_attrib(wrapped_attribs, &wrapped_len, ec_attrib_id_dpp_config_obj, bsta_config_obj_str);
        } else {
            wrapped_attribs = ec_util::add_attrib(wrapped_attribs, &wrapped_len, ec_attrib_id_dpp_config_obj, fbss_config_obj_str);
        }
        wrapped_attribs = ec_util::add_attrib(wrapped_attribs, &wrapped_len, ec_attrib_id_send_conn_status, 0, NULL);
        return std::make_pair(wrapped_attribs, wrapped_len);
    });

    response_frame = ec_util::copy_attrs_to_frame(response_frame, attribs, attribs_len);
    free(attribs);
    ASSERT_NOT_NULL(response_frame, {}, "%s:%d: Failed to copy attributes to DPP Configuration frame!\n", __func__, __LINE__);
    response_frame->resp_len = static_cast<uint16_t>(attribs_len);
    auto [encap_response_frame, encap_response_frame_len] = ec_util::create_encap_dpp_tlv(true, dest_mac, ec_frame_type_easymesh, reinterpret_cast<uint8_t*>(response_frame), frame_len + attribs_len);
    ASSERT_NOT_NULL(encap_response_frame, {}, "%s:%d: Failed to alloc DPP Configuration frame!\n", __func__, __LINE__);


    return std::make_pair(reinterpret_cast<uint8_t*>(encap_response_frame), encap_response_frame_len);
}
