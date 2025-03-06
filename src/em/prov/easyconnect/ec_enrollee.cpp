#include "ec_enrollee.h"

#include "ec_util.h"
#include "ec_crypto.h"
#include "util.h"

ec_enrollee_t::ec_enrollee_t(std::string mac_addr, send_act_frame_func send_action_frame)
                            : m_mac_addr(mac_addr), m_send_action_frame(send_action_frame)
{
}

ec_enrollee_t::~ec_enrollee_t()
{
}

bool ec_enrollee_t::start(bool do_reconfig, ec_data_t* boot_data)
{
    memset(&m_boot_data, 0, sizeof(ec_data_t));
    memcpy(&m_boot_data, boot_data, sizeof(ec_data_t));

    // Baseline test to ensure the bootstrapping key is present
    if (EC_KEY_get0_public_key(m_boot_data.responder_boot_key) == NULL) {
        printf("%s:%d Could not get responder bootstrap public key\n", __func__, __LINE__);
        return false;
    }

    printf("Configurator MAC: %s\n", m_mac_addr.c_str());
    if (!ec_crypto::init_persistent_ctx(m_p_ctx, m_boot_data.responder_boot_key)){
        printf("%s:%d failed to initialize persistent context\n", __func__, __LINE__);
        return false;
    }

    if (do_reconfig) {
        return true;
    }
    return true;
}

bool ec_enrollee_t::handle_auth_request(ec_frame_t *frame, size_t len, uint8_t src_mac[ETHER_ADDR_LEN])
{
    size_t attrs_len = len - EC_FRAME_BASE_SIZE;

    ec_attribute_t *B_r_hash_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_resp_bootstrap_key_hash);
    ASSERT_NOT_NULL(B_r_hash_attr, false, "%s:%d No responder bootstrapping key hash attribute found\n", __func__, __LINE__);

    uint8_t* responder_keyhash = ec_crypto::compute_key_hash(m_boot_data.responder_boot_key);
    ASSERT_NOT_NULL(responder_keyhash, false, "%s:%d failed to compute responder bootstrapping key hash\n", __func__, __LINE__);

    if (memcmp(B_r_hash_attr->data, responder_keyhash, B_r_hash_attr->length) != 0) {
        printf("%s:%d Responder key hash mismatch\n", __func__, __LINE__);
        free(responder_keyhash);
        return false;
    }
    free(responder_keyhash);
    
    ec_attribute_t *B_i_hash_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_init_bootstrap_key_hash);
    ASSERT_NOT_NULL(B_i_hash_attr, false, "%s:%d No initiator bootstrapping key hash attribute found\n", __func__, __LINE__);

    if (m_boot_data.initiator_boot_key != NULL){
        // Initiator bootstrapping key is present on enrollee, mutual authentication is possible
        uint8_t* initiator_keyhash = ec_crypto::compute_key_hash(m_boot_data.initiator_boot_key);
        if (initiator_keyhash != NULL) {
            if (memcmp(B_i_hash_attr->data, initiator_keyhash, B_i_hash_attr->length) == 0) {
                printf("%s:%d Initiator key hash matched, mutual authentication can now occur\n", __func__, __LINE__);
                // Hashes match, mutual authentication can occur
                m_eph_ctx.is_mutual_auth = true;
                /*
                Specifically, the Responder shall request mutual authentication when the hash of the Responder
            bootstrapping key in the authentication request indexes an entry in the bootstrapping table corresponding to a
            bidirectional bootstrapping method, for example, PKEX or BTLE.
                */
            }
            free(initiator_keyhash);
        }     
    }

   ec_attribute_t *channel_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_channel);
    if (channel_attr && channel_attr->length == sizeof(uint16_t)) {
        /*
        the Responder determines whether it can use the requested channel for the
following exchanges. If so, it sends the DPP Authentication Response frame on that channel. If not, it discards the DPP
Authentication Request frame without replying to it.
        */
        uint16_t op_chan = *(uint16_t*)channel_attr->data;
        printf("%s:%d Channel attribute: %d\n", __func__, __LINE__, op_chan);

        uint8_t op_class = (uint8_t)(op_chan >> 8);
        uint8_t channel = (uint8_t)(op_chan & 0x00ff);
        printf("%s:%d op_class: %d channel %d\n", __func__, __LINE__, op_class, channel);
        //TODO: Check One-Wifi for channel selection if possible
        // Maybe just attempt to send it on the channel
    }

    ec_attribute_t *pub_init_proto_key_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_init_proto_key);

    ASSERT_NOT_NULL(pub_init_proto_key_attr, false, "%s:%d No public initiator protocol key attribute found\n", __func__, __LINE__);
    ASSERT_EQUALS(pub_init_proto_key_attr->length, BN_num_bytes(m_p_ctx.prime) * 2, false, "%s:%d Invalid public initiator protocol key length\n", __func__, __LINE__);

    if (m_eph_ctx.public_init_proto_key) {
        EC_POINT_free(m_eph_ctx.public_init_proto_key);
    }

    m_eph_ctx.public_init_proto_key = ec_crypto::decode_proto_key(m_p_ctx, pub_init_proto_key_attr->data);
    ASSERT_NOT_NULL(m_eph_ctx.public_init_proto_key, false, "%s:%d failed to decode public initiator protocol key\n", __func__, __LINE__);

    // START Crypto in EasyConnect 6.3.3
    // Compute the M.x
    const BIGNUM *priv_resp_boot_key = EC_KEY_get0_private_key(m_boot_data.responder_boot_key);
    ASSERT_NOT_NULL(priv_resp_boot_key, false, "%s:%d failed to get responder bootstrapping private key\n", __func__, __LINE__);

    m_eph_ctx.m = ec_crypto::compute_ec_ss_x(m_p_ctx, priv_resp_boot_key, m_eph_ctx.public_init_proto_key);
    const BIGNUM *bn_inputs[1] = { m_eph_ctx.m };
    // Compute the "first intermediate key" (k1)
    if (ec_crypto::compute_hkdf_key(m_p_ctx, m_eph_ctx.k1, m_p_ctx.digest_len, "first intermediate key", bn_inputs, 1, NULL, 0) == 0) {
        printf("%s:%d: Failed to compute k1\n", __func__, __LINE__); 
        return false;
    }

    printf("Key K_1:\n");
    util::print_hex_dump(m_p_ctx.digest_len, m_eph_ctx.k1);

    ec_attribute_t *wrapped_data_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_wrapped_data);
    ASSERT_NOT_NULL(wrapped_data_attr, false, "%s:%d No wrapped data attribute found\n", __func__, __LINE__);

    // Attempt to unwrap the wrapped data with generated k1 (from sent keys)
    auto [wrapped_data, wrapped_len] = ec_util::unwrap_wrapped_attrib(wrapped_data_attr, frame, false, m_eph_ctx.k1); 
    if (wrapped_data == NULL || wrapped_len == 0) {
        printf("%s:%d failed to unwrap wrapped data\n", __func__, __LINE__);
        // "Abondon the exchange"
        return false;
    }

    ec_attribute_t *init_caps_attr = ec_util::get_attrib(wrapped_data, wrapped_len, ec_attrib_id_init_caps);
    ASSERT_NOT_NULL_FREE(init_caps_attr, false, wrapped_data, "%s:%d No initiator capabilities attribute found\n", __func__, __LINE__);

    const ec_dpp_capabilities_t init_caps = {
        .byte = init_caps_attr->data[0]
    };

    // Fetched all of the wrapped data attributes (init caps), free the wrapped data
    free(wrapped_data);

    uint8_t init_proto_version = 0; // Undefined
    ec_attribute_t *proto_version_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_proto_version);
    if (proto_version_attr && proto_version_attr->length == 1) {
        init_proto_version = proto_version_attr->data[0];
    }

    if (!ec_util::check_caps_compatible(init_caps, m_dpp_caps)) {
        printf("%s:%d Initiator capabilities not supported\n", __func__, __LINE__);

        /*
        STATUS_NOT_COMPATIBLE:
        Responder → Initiator: DPP Status, SHA-256(BR), [ SHA-256(BI),][ Protocol Version ], { I-nonce, R-capabilities}k1
        */
        auto [resp_frame, resp_len] = create_auth_response(DPP_STATUS_NOT_COMPATIBLE, init_proto_version);
        if (resp_frame == NULL || resp_len == 0) {
            printf("%s:%d failed to create response frame\n", __func__, __LINE__);
            return false;
        }
        // TODO: Send frame
        return false;
    }

    // TODO/NOTE: Unknown: If need more time to process, respond `STATUS_RESPONSE_PENDING` (EasyConnect 6.3.3)
    // If the Responder needs more time to respond, e.g., to complete bootstrapping of the Initiator’s bootstrapping key
    if (false) {
        /*
        STATUS_RESPONSE_PENDING:
        Responder → Initiator: DPP Status, SHA-256(BR), [ SHA-256(BI),][ Protocol Version ], { I-nonce, R-capabilities}k1
        */
        auto [resp_frame, resp_len] = create_auth_response(DPP_STATUS_RESPONSE_PENDING, init_proto_version);
        if (resp_frame == NULL || resp_len == 0) {
            printf("%s:%d failed to create response frame\n", __func__, __LINE__);
            return false;
        }
        // TODO: Send frame
        return true;
    }

    /*
    STATUS_OK:
    Responder → Initiator: DPP Status, SHA-256(BR), [ SHA-256(BI), ] PR, [Protocol Version], { R-nonce, I-nonce, R-capabilities, { R-auth }ke }k2
    */
    auto [resp_frame, resp_len] = create_auth_response(DPP_STATUS_OK, init_proto_version);
    if (resp_frame == NULL || resp_len == 0) {
        printf("%s:%d failed to create response frame\n", __func__, __LINE__);
        return false;
    }
    // TODO: Send the response frame
}

bool ec_enrollee_t::handle_auth_confirm(ec_frame_t *frame, size_t len, uint8_t src_mac[ETHER_ADDR_LEN])
{
    size_t attrs_len = len - EC_FRAME_BASE_SIZE;

    ec_attribute_t *status_attrib = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_dpp_status);
    ASSERT_NOT_NULL(status_attrib, false, "%s:%d: No DPP status attribute found\n", __func__, __LINE__);

    ec_status_code_t dpp_status = (ec_status_code_t)status_attrib->data[0];

    if (dpp_status != DPP_STATUS_OK && dpp_status != DPP_STATUS_AUTH_FAILURE && dpp_status != DPP_STATUS_NOT_COMPATIBLE) {
        printf("%s:%d: Recieved Improper DPP Status: \"%s\"\n", __func__, __LINE__, ec_util::status_code_to_string(dpp_status).c_str());
        return false;
    }

    ec_attribute_t *wrapped_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_wrapped_data);
    ASSERT_NOT_NULL(wrapped_attr, false, "%s:%d: No wrapped data attribute found\n", __func__, __LINE__);

    uint8_t* key = (dpp_status == DPP_STATUS_OK) ? m_eph_ctx.ke : m_eph_ctx.k2;
    ASSERT_NOT_NULL(key, false, "%s:%d: k_e or k_2 is NULL!\n", __func__, __LINE__);

    // If DPP Status is OK, wrap the I-auth with the KE key, otherwise wrap the Responder Nonce with the K2 key
    auto [unwrapped_data, unwrapped_data_len] = ec_util::unwrap_wrapped_attrib(wrapped_attr, frame, true, key);
    if (unwrapped_data == NULL || unwrapped_data_len == 0) {
        printf("%s:%d: Failed to unwrap wrapped data, aborting exchange\n", __func__, __LINE__);
        // Aborts exchange
        return false;
    }
    if (dpp_status != DPP_STATUS_OK) {
        // Unwrapping successfully occured but there is an error, "generate an alert"
        free(unwrapped_data);
        std::string status_str = ec_util::status_code_to_string(dpp_status);
        printf("%s:%d: Authentication Failed with DPP Status: %s\n", __func__, __LINE__, status_str.c_str());
        return false;
    }

    auto i_auth_tag_attr = ec_util::get_attrib(unwrapped_data, unwrapped_data_len, ec_attrib_id_init_auth_tag);
    ASSERT_NOT_NULL_FREE(i_auth_tag_attr, false, unwrapped_data, "%s:%d: No initiator authentication tag attribute found\n", __func__, __LINE__);
    
    uint8_t i_auth_tag[i_auth_tag_attr->length] = {0};
    memcpy(i_auth_tag, i_auth_tag_attr->data, i_auth_tag_attr->length);

    free(unwrapped_data);

    // Generate I-auth’ = H(R-nonce | I-nonce | PR.x | PI.x | BR.x | [ BI.x | ] 1)
    // Get P_I.x, P_R.x, B_I.x, and B_R.x
    BIGNUM* P_I_x = ec_crypto::get_ec_x(m_p_ctx, m_eph_ctx.public_init_proto_key);
    BIGNUM* P_R_x = ec_crypto::get_ec_x(m_p_ctx, m_eph_ctx.public_resp_proto_key);
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
    if (m_eph_ctx.is_mutual_auth && B_I_x == NULL) {
        printf("%s:%d: Failed to get x-coordinate of B_I\n", __func__, __LINE__);
        BN_free(P_I_x);
        BN_free(P_R_x);
        BN_free(B_R_x);
        return false;
    }

    easyconnect::hash_buffer_t i_auth_hb;
    ec_crypto::add_to_hash(i_auth_hb, m_eph_ctx.r_nonce, m_p_ctx.nonce_len);
    ec_crypto::add_to_hash(i_auth_hb, m_eph_ctx.i_nonce, m_p_ctx.nonce_len);
    ec_crypto::add_to_hash(i_auth_hb, P_R_x); //P_R
    ec_crypto::add_to_hash(i_auth_hb, P_I_x); //P_I
    ec_crypto::add_to_hash(i_auth_hb, B_R_x); //B_R
    if (m_eph_ctx.is_mutual_auth) ec_crypto::add_to_hash(i_auth_hb, B_I_x); //B_I
    ec_crypto::add_to_hash(i_auth_hb, (uint8_t)1); // 1 octet

    uint8_t* i_auth_prime = ec_crypto::compute_hash(m_p_ctx, i_auth_hb);

    BN_free(P_I_x);
    BN_free(P_R_x);
    BN_free(B_R_x);
    if (B_I_x) BN_free(B_I_x);

    if (i_auth_prime == NULL) {
        printf("%s:%d: Failed to compute I-auth'\n", __func__, __LINE__);
        return false;
    }

    if (memcmp(i_auth_prime, i_auth_tag, sizeof(i_auth_tag)) != 0) {
        printf("%s:%d: I-auth' does not match Initiator Auth Tag, authentication failed!\n", __func__, __LINE__);
        // TODO: "ALERT" The user that authentication failed
        free(i_auth_prime);
        return false;
    }

    return true;
}

bool ec_enrollee_t::handle_config_response(uint8_t *buff, unsigned int len, uint8_t sa[ETH_ALEN])
{
    printf("%s:%d: Got a DPP Configuration Response from " MACSTRFMT "\n", __func__, __LINE__, MAC2STR(sa));
    uint8_t *p = buff;

    ec_gas_frame_base_t *gas_base_frame = (ec_gas_frame_base_t *)p;
    p += sizeof(ec_gas_frame_base_t);
    ec_gas_initial_response_frame_t *gas_initial_response = (ec_gas_initial_response_frame_t *)p;
    printf(
        "%s:%d: Got a DPP config response! category=%02x action=%02x dialog_token=%02x ape=" APEFMT
        " ape_id=" APEIDFMT " resp_len=%d\n",
        __func__, __LINE__, gas_base_frame->category, gas_base_frame->action,
        gas_base_frame->dialog_token, APE2STR(gas_initial_response->ape),
        APEID2STR(gas_initial_response->ape_id), gas_initial_response->resp_len);
    return true;
}

std::pair<uint8_t *, uint16_t> ec_enrollee_t::create_presence_announcement()
{
    printf("%s:%d Enter\n", __func__, __LINE__);

    auto err_pair = std::make_pair<uint8_t*, uint16_t>(NULL, 0);

    ec_frame_t *frame =  ec_util::alloc_frame(ec_frame_type_presence_announcement);
    ASSERT_NOT_NULL(frame, err_pair, "%s:%d failed to allocate memory for frame\n", __func__, __LINE__);

    // Compute the hash of the responder boot key 
    uint8_t *resp_boot_key_chirp_hash = ec_crypto::compute_key_hash(m_boot_data.responder_boot_key, "chirp");
    ASSERT_NOT_NULL_FREE(resp_boot_key_chirp_hash, err_pair, frame, "%s:%d unable to compute \"chirp\" responder bootstrapping key hash\n", __func__, __LINE__);

    uint8_t* attribs = NULL;
    uint16_t attrib_len = 0;

    attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_resp_bootstrap_key_hash, SHA256_DIGEST_LENGTH, resp_boot_key_chirp_hash);
    free(resp_boot_key_chirp_hash);

    if (!(frame = ec_util::copy_attrs_to_frame(frame, attribs, attrib_len))) {
        printf("%s:%d unable to copy attributes to frame\n", __func__, __LINE__);
        free(attribs);
        free(frame);
        return std::make_pair<uint8_t*, uint16_t>(NULL, 0);
    }
    free(attribs);

    return std::pair<uint8_t *, uint16_t>();
}


std::pair<uint8_t *, uint16_t> ec_enrollee_t::create_auth_response(ec_status_code_t dpp_status, uint8_t init_proto_version)
{

    /*
    STATUS_NOT_COMPATIBLE:
        Responder → Initiator: DPP Status, SHA-256(BR), [ SHA-256(BI),][ Protocol Version ], { I-nonce, R-capabilities}k1
    STATUS_RESPONSE_PENDING:
        Responder → Initiator: DPP Status, SHA-256(BR), [ SHA-256(BI),][ Protocol Version ], { I-nonce, R-capabilities}k1
    STATUS_OK:
        Responder → Initiator: DPP Status, SHA-256(BR), [ SHA-256(BI), ] PR, [Protocol Version], { R-nonce, I-nonce, R-capabilities, { R-auth }ke }k2
    */

    auto err_pair = std::make_pair<uint8_t*, uint16_t>(NULL, 0);

    ec_frame_t *frame =  ec_util::alloc_frame(ec_frame_type_auth_cnf);
    ASSERT_NOT_NULL(frame, err_pair, "%s:%d failed to allocate memory for frame\n", __func__, __LINE__);

    uint8_t* attribs = NULL;
    uint16_t attrib_len = 0;

    attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_dpp_status, (uint8_t)dpp_status);

    // Add Responder Bootstrapping Key Hash (SHA-256(B_R))
    uint8_t* responder_keyhash = ec_crypto::compute_key_hash(m_boot_data.responder_boot_key);
    ASSERT_NOT_NULL_FREE2(responder_keyhash, err_pair, frame, attribs, "%s:%d failed to compute responder bootstrapping key hash\n", __func__, __LINE__);

    attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_resp_bootstrap_key_hash, SHA256_DIGEST_LENGTH, responder_keyhash);
    free(responder_keyhash);
    // Conditional (Only included for mutual authentication) (SHA-256(B_I))
    if (m_eph_ctx.is_mutual_auth) {
        uint8_t* initiator_keyhash = ec_crypto::compute_key_hash(m_boot_data.initiator_boot_key);
        if (initiator_keyhash != NULL) {
            attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_init_bootstrap_key_hash, SHA256_DIGEST_LENGTH, initiator_keyhash);
            free(initiator_keyhash);
        }

    }


    // Add remaining NON-OK attributes and return due to complexity with OK attributes
    if (dpp_status != DPP_STATUS_OK) {
        if (init_proto_version >= 2) {
            // Add Protocol Version (TOOD: Add variable for responder protocol version)
            attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_proto_version, (uint8_t)1);
        }
        attribs = ec_util::add_wrapped_data_attr(frame, attribs, &attrib_len, true, m_eph_ctx.k1, [&](){
            uint16_t wrapped_len = 0;
            uint8_t* wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_init_nonce, m_p_ctx.nonce_len, m_eph_ctx.i_nonce);
            wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_resp_caps, m_dpp_caps.byte);
            return std::make_pair(wrap_attribs, wrapped_len);
        });
        
        if (!(frame = ec_util::copy_attrs_to_frame(frame, attribs, attrib_len))) {
            printf("%s:%d unable to copy attributes to frame\n", __func__, __LINE__);
            free(frame);
            free(attribs);
            return err_pair;
        }
        free(attribs);
        return std::make_pair((uint8_t*)frame, EC_FRAME_BASE_SIZE + attrib_len);
    }
    
    // STATUS_OK

    // Generate R-nonce
    if (!RAND_bytes(m_eph_ctx.r_nonce, m_p_ctx.nonce_len)) {
        printf("%s:%d failed to generate R-nonce\n", __func__, __LINE__);
        free(attribs);
        free(frame);
        return err_pair;
    }

    // Generate initiator protocol key pair (p_i/P_I)
    auto [priv_resp_proto_key, pub_resp_proto_key] = ec_crypto::generate_proto_keypair(m_p_ctx);
    if (priv_resp_proto_key == NULL || pub_resp_proto_key == NULL) {
        printf("%s:%d failed to generate responder protocol keypair\n", __func__, __LINE__);
        free(attribs);
        free(frame);
        return err_pair;
    }
    m_eph_ctx.public_resp_proto_key = (EC_POINT*)pub_resp_proto_key;
    m_eph_ctx.priv_resp_proto_key = (BIGNUM*)priv_resp_proto_key;

    ASSERT_NOT_NULL_FREE2(m_eph_ctx.public_init_proto_key, err_pair, frame, attribs, "%s:%d initiator protocol keypair was never generated!\n", __func__, __LINE__);
    m_eph_ctx.n = ec_crypto::compute_ec_ss_x(m_p_ctx, m_eph_ctx.priv_resp_proto_key, m_eph_ctx.public_init_proto_key);
    const BIGNUM *bn_inputs[1] = { m_eph_ctx.n };
    // Compute the "second intermediate key" (k2)
    if (ec_crypto::compute_hkdf_key(m_p_ctx, m_eph_ctx.k2, m_p_ctx.digest_len, "second intermediate key", bn_inputs, 1, NULL, 0) == 0) {
        printf("%s:%d: Failed to compute k2\n", __func__, __LINE__); 
        free(attribs);
        free(frame);
        return err_pair;
    }

    printf("Key K_2:\n");
    util::print_hex_dump(m_p_ctx.digest_len, m_eph_ctx.k2);

    const BIGNUM* b_R = EC_KEY_get0_private_key(m_boot_data.responder_boot_key);
    ASSERT_NOT_NULL_FREE2(b_R, err_pair, frame, attribs, "%s:%d failed to get responder bootstrapping private key\n", __func__, __LINE__);

    // Compute L.x
    if (m_eph_ctx.is_mutual_auth){
        const EC_POINT* B_I = EC_KEY_get0_public_key(m_boot_data.initiator_boot_key);
        if (B_I != NULL){
            m_eph_ctx.l = ec_crypto::calculate_Lx(m_p_ctx, b_R, m_eph_ctx.priv_resp_proto_key, B_I);
            EC_POINT_free((EC_POINT*)B_I);
        }
    }

    if (m_eph_ctx.is_mutual_auth && m_eph_ctx.l == NULL) {
        printf("%s:%d failed to compute L.x\n", __func__, __LINE__);
        free(attribs);
        free(frame);
        if (b_R) BN_free((BIGNUM*)b_R);
        return err_pair;
    }
    

    // Compute k_e
    if (ec_crypto::compute_ke(m_p_ctx, &m_eph_ctx, m_eph_ctx.ke) == 0){
        printf("%s:%d: Failed to compute ke\n", __func__, __LINE__);
        free(attribs);
        free(frame);
        return err_pair;
    }

    // Compute R-auth = H(I-nonce | R-nonce | PI.x | PR.x | [ BI.x | ] BR.x | 0)
    BIGNUM* P_I_x = ec_crypto::get_ec_x(m_p_ctx, m_eph_ctx.public_init_proto_key);
    BIGNUM* P_R_x = ec_crypto::get_ec_x(m_p_ctx, m_eph_ctx.public_resp_proto_key);
    BIGNUM* B_I_x = ec_crypto::get_ec_x(m_p_ctx, EC_KEY_get0_public_key(m_boot_data.initiator_boot_key));
    BIGNUM* B_R_x = ec_crypto::get_ec_x(m_p_ctx, EC_KEY_get0_public_key(m_boot_data.responder_boot_key));

    if (P_I_x == NULL || P_R_x == NULL || B_R_x == NULL) {
        printf("%s:%d: Failed to get x-coordinates of P_I, P_R, and B_R\n", __func__, __LINE__);
        if (P_I_x) BN_free(P_I_x);
        if (P_R_x) BN_free(P_R_x);
        if (B_R_x) BN_free(B_R_x);
        if (B_I_x) BN_free(B_I_x);
        return err_pair;
    }

    // B_I.x is not needed (can be null) if mutual authentication is not supported
    if (m_eph_ctx.is_mutual_auth && B_I_x == NULL) {
        printf("%s:%d: Failed to get x-coordinate of B_I when mutal authentication is occuring\n", __func__, __LINE__);
        BN_free(P_I_x);
        BN_free(P_R_x);
        BN_free(B_R_x);
        return err_pair;
    }

    easyconnect::hash_buffer_t r_auth_hb;
    ec_crypto::add_to_hash(r_auth_hb, m_eph_ctx.i_nonce, m_p_ctx.nonce_len);
    ec_crypto::add_to_hash(r_auth_hb, m_eph_ctx.r_nonce, m_p_ctx.nonce_len);
    ec_crypto::add_to_hash(r_auth_hb, P_I_x); //P_I
    ec_crypto::add_to_hash(r_auth_hb, P_R_x); //P_R
    if (m_eph_ctx.is_mutual_auth) ec_crypto::add_to_hash(r_auth_hb, B_I_x); //B_I
    ec_crypto::add_to_hash(r_auth_hb, B_R_x); //B_R
    ec_crypto::add_to_hash(r_auth_hb, (uint8_t)0); // 1 octet

    uint8_t* r_auth = ec_crypto::compute_hash(m_p_ctx, r_auth_hb);
    if (P_I_x) BN_free(P_I_x);
    if (P_R_x) BN_free(P_R_x);
    if (B_R_x) BN_free(B_R_x);
    if (B_I_x) BN_free(B_I_x);
    ASSERT_NOT_NULL_FREE2(r_auth, err_pair, frame, attribs, "%s:%d: Failed to compute R-auth\n", __func__, __LINE__);

    // Add P_R
    uint8_t* encoded_P_R = ec_crypto::encode_proto_key(m_p_ctx, m_eph_ctx.public_resp_proto_key);
    ASSERT_NOT_NULL_FREE2(encoded_P_R, err_pair, frame, attribs, "%s:%d failed to encode responder protocol key\n", __func__, __LINE__);

    attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_resp_proto_key, BN_num_bytes(m_p_ctx.prime) * 2, encoded_P_R);
    free(encoded_P_R);

    // Add Protocol Version
    if (init_proto_version >= 2) {
        // Add Protocol Version (TOOD: Add variable for responder protocol version)
        attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_proto_version, (uint8_t)1);
    }

    // Add `{ R-nonce, I-nonce, R-capabilities, { R-auth }k_e }k_2`
    attribs = ec_util::add_wrapped_data_attr(frame, attribs, &attrib_len, true, m_eph_ctx.k2, [&](){
        uint16_t wrapped_len = 0;
        uint8_t* wrap_attribs = ec_util::add_attrib(NULL, &wrapped_len, ec_attrib_id_resp_nonce, m_p_ctx.nonce_len, m_eph_ctx.r_nonce);
        wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_init_nonce, m_p_ctx.nonce_len, m_eph_ctx.i_nonce);
        wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_resp_caps, m_dpp_caps.byte);

        // R-auth is wrapped in an additional wrapped data attribute (k_e) inside the main wrapped data attribute (k_2)
        wrap_attribs = ec_util::add_wrapped_data_attr(frame, wrap_attribs, &wrapped_len, true, m_eph_ctx.ke, [&](){
            uint16_t int_wrapped_len = 0;
            uint8_t* int_wrapped_attrs = ec_util::add_attrib(NULL, &int_wrapped_len, ec_attrib_id_resp_auth_tag, m_p_ctx.digest_len, r_auth);
            return std::make_pair(int_wrapped_attrs, int_wrapped_len);
        });
        return std::make_pair(wrap_attribs, wrapped_len);
    });

    free(r_auth);

    if (!(frame = ec_util::copy_attrs_to_frame(frame, attribs, attrib_len))) {
        printf("%s:%d unable to copy attributes to frame\n", __func__, __LINE__);
        free(frame);
        free(attribs);
        return err_pair;
    }
    free(attribs);

    return std::make_pair((uint8_t*)frame, EC_FRAME_BASE_SIZE + attrib_len);

}

std::pair<uint8_t *, uint16_t> ec_enrollee_t::create_recfg_presence_announcement()
{
    return std::pair<uint8_t *, uint16_t>();
}

std::pair<uint8_t *, uint16_t> ec_enrollee_t::create_recfg_auth_response(ec_status_code_t dpp_status)
{
    return std::pair<uint8_t *, uint16_t>();
}

std::pair<uint8_t *, uint16_t> ec_enrollee_t::create_config_request()
{
    return std::pair<uint8_t *, uint16_t>();
}

std::pair<uint8_t *, uint16_t> ec_enrollee_t::create_config_result()
{
    return std::pair<uint8_t *, uint16_t>();
}
