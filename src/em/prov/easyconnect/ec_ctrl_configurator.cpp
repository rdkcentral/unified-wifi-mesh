#include "ec_ctrl_configurator.h"

#include "ec_base.h"
#include "ec_util.h"
#include "util.h"

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
    const BIGNUM* priv_init_boot_key = EC_KEY_get0_private_key(m_boot_data.initiator_boot_key);
    ASSERT_NOT_NULL(priv_init_boot_key, false, "%s:%d: failed to get initiator bootstrapping private key\n", __func__, __LINE__);
    // B_R
    const EC_POINT* pub_resp_boot_key = EC_KEY_get0_public_key(m_boot_data.responder_boot_key);
    ASSERT_NOT_NULL(pub_resp_boot_key, false, "%s:%d: failed to get responder bootstrapping public key\n", __func__, __LINE__);
    // P_R
    ASSERT_NOT_NULL(e_ctx->public_resp_proto_key, false, "%s:%d: Responder Public Protocol Key was not recieved/set\n", __func__, __LINE__);

    if (e_ctx->is_mutual_auth){
        // Perform **Initiator** L.x calculation (L = bI * (BR + PR))

        EC_POINT* sum = EC_POINT_new(m_p_ctx.group);
        // Calculate (B_R + P_R)
        if (!EC_POINT_add(m_p_ctx.group, sum, pub_resp_boot_key, e_ctx->public_resp_proto_key, m_p_ctx.bn_ctx)){
            EC_POINT_free(sum);
            free(prim_unwrapped_data);
            printf("%s:%d: failed to add public responder boot key and public responder protocol key\n", __func__, __LINE__);
            return false;
        }
        // Calculate b_I * (B_R + P_R)
        EC_POINT* L = EC_POINT_new(m_p_ctx.group);
        if (!EC_POINT_mul(m_p_ctx.group, L, NULL, sum, priv_init_boot_key, m_p_ctx.bn_ctx)){
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
    BIGNUM* B_I_x = ec_crypto::get_ec_x(m_p_ctx, EC_KEY_get0_public_key(m_boot_data.initiator_boot_key));
    BIGNUM* B_R_x = ec_crypto::get_ec_x(m_p_ctx, EC_KEY_get0_public_key(m_boot_data.responder_boot_key));

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
    const EC_POINT *pub_resp_boot_key = EC_KEY_get0_public_key(m_boot_data.responder_boot_key);
    ASSERT_NOT_NULL_FREE(pub_resp_boot_key, {}, frame, "%s:%d failed to get responder bootstrapping public key\n", __func__, __LINE__);

    e_ctx->m = ec_crypto::compute_ec_ss_x(m_p_ctx, e_ctx->priv_init_proto_key, pub_resp_boot_key);
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
