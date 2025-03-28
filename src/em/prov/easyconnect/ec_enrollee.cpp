#include "ec_enrollee.h"

#include "ec_util.h"
#include "ec_crypto.h"
#include "em_crypto.h"
#include "util.h"
#include "cjson/cJSON.h"
#include "cjson_util.h"
#include <unistd.h>

ec_enrollee_t::ec_enrollee_t(std::string mac_addr, send_act_frame_func send_action_frame, get_backhaul_sta_info_func get_bsta_info)
                            : m_mac_addr(mac_addr), m_send_action_frame(send_action_frame), m_get_bsta_info(get_bsta_info)
{
}

ec_enrollee_t::~ec_enrollee_t()
{
    ec_util::free_connection_ctx(m_c_ctx);
}

bool ec_enrollee_t::start_onboarding(bool do_reconfig, ec_data_t* boot_data)
{

    ASSERT_NOT_NULL(boot_data, false, "%s:%d Bootstrapping data is NULL\n", __func__, __LINE__);
    if (boot_data->version < 2) {
        printf("%s:%d Bootstrapping Version '%d' not supported!\n", __func__, __LINE__, boot_data->version);
        return false;
    }
    if (memcmp(boot_data->mac_addr, ZERO_MAC_ADDR, ETHER_ADDR_LEN) == 0) {
        printf("%s:%d Bootstrapping data MAC address is 0 \n", __func__, __LINE__);
        return false;
    }
    if (boot_data->responder_boot_key == NULL) {
        printf("%s:%d Bootstrapping data responder key is NULL\n", __func__, __LINE__);
        return false;
    }

    memset(&m_boot_data(), 0, sizeof(ec_data_t));
    memcpy(&m_boot_data(), boot_data, sizeof(ec_data_t));


    printf("Configurator MAC: %s\n", m_mac_addr.c_str());

    const SSL_KEY* resp_key = do_reconfig ? m_c_ctx.C_signing_key : m_boot_data().responder_boot_key;
    if (resp_key == NULL) {
        printf("%s:%d No bootstrapping key found\n", __func__, __LINE__);
        return false;
    }
    // Not all of these will be present but it is better to compute them now.
    m_boot_data().resp_priv_boot_key = em_crypto_t::get_priv_key_bn(resp_key);
    m_boot_data().resp_pub_boot_key = em_crypto_t::get_pub_key_point(resp_key);

    m_boot_data().init_priv_boot_key= em_crypto_t::get_priv_key_bn(m_boot_data().initiator_boot_key);    
    m_boot_data().init_pub_boot_key = em_crypto_t::get_pub_key_point(m_boot_data().initiator_boot_key);

    // Baseline test to ensure the bootstrapping key is present
    if (m_boot_data().resp_pub_boot_key == NULL) {
        printf("%s:%d Could not get responder bootstrap public key\n", __func__, __LINE__);
        return false;
    }
    
    if (!ec_crypto::init_persistent_ctx(m_c_ctx, resp_key)){
        printf("%s:%d failed to initialize persistent context\n", __func__, __LINE__);
        return false;
    }

    return true;
}

bool ec_enrollee_t::handle_auth_request(ec_frame_t *frame, size_t len, uint8_t src_mac[ETHER_ADDR_LEN])
{
    size_t attrs_len = len - EC_FRAME_BASE_SIZE;

    ec_attribute_t *B_r_hash_attr = ec_util::get_attrib(frame->attributes, static_cast<uint16_t> (attrs_len), ec_attrib_id_resp_bootstrap_key_hash);
    ASSERT_NOT_NULL(B_r_hash_attr, false, "%s:%d No responder bootstrapping key hash attribute found\n", __func__, __LINE__);

    uint8_t* responder_keyhash = ec_crypto::compute_key_hash(m_boot_data().responder_boot_key);
    ASSERT_NOT_NULL(responder_keyhash, false, "%s:%d failed to compute responder bootstrapping key hash\n", __func__, __LINE__);

    if (memcmp(B_r_hash_attr->data, responder_keyhash, B_r_hash_attr->length) != 0) {
        printf("%s:%d Responder key hash mismatch\n", __func__, __LINE__);
        free(responder_keyhash);
        return false;
    }
    free(responder_keyhash);
    
    ec_attribute_t *B_i_hash_attr = ec_util::get_attrib(frame->attributes, static_cast<uint16_t> (attrs_len), ec_attrib_id_init_bootstrap_key_hash);
    ASSERT_NOT_NULL(B_i_hash_attr, false, "%s:%d No initiator bootstrapping key hash attribute found\n", __func__, __LINE__);

    if (m_boot_data().initiator_boot_key != NULL){
        // Initiator bootstrapping key is present on enrollee, mutual authentication is possible
        uint8_t* initiator_keyhash = ec_crypto::compute_key_hash(m_boot_data().initiator_boot_key);
        if (initiator_keyhash != NULL) {
            if (memcmp(B_i_hash_attr->data, initiator_keyhash, B_i_hash_attr->length) == 0) {
                printf("%s:%d Initiator key hash matched, mutual authentication can now occur\n", __func__, __LINE__);
                // Hashes match, mutual authentication can occur
                m_eph_ctx().is_mutual_auth = true;
                /*
                Specifically, the Responder shall request mutual authentication when the hash of the Responder
            bootstrapping key in the authentication request indexes an entry in the bootstrapping table corresponding to a
            bidirectional bootstrapping method, for example, PKEX or BTLE.
                */
            }
            free(initiator_keyhash);
        }     
    }

   ec_attribute_t *channel_attr = ec_util::get_attrib(frame->attributes, static_cast<uint16_t> (attrs_len), ec_attrib_id_channel);
    if (channel_attr && channel_attr->length == sizeof(uint16_t)) {
        /*
        the Responder determines whether it can use the requested channel for the
following exchanges. If so, it sends the DPP Authentication Response frame on that channel. If not, it discards the DPP
Authentication Request frame without replying to it.
        */
        uint16_t op_chan = *reinterpret_cast<uint16_t*>(channel_attr->data);
        printf("%s:%d Channel attribute: %d\n", __func__, __LINE__, op_chan);

        uint8_t op_class = static_cast<uint8_t>(op_chan >> 8);
        uint8_t channel = static_cast<uint8_t>(op_chan & 0x00ff);
        printf("%s:%d op_class: %d channel %d\n", __func__, __LINE__, op_class, channel);
        //TODO: Check One-Wifi for channel selection if possible
        // Maybe just attempt to send it on the channel
    }

    ec_attribute_t *pub_init_proto_key_attr = ec_util::get_attrib(frame->attributes, static_cast<uint16_t> (attrs_len), ec_attrib_id_init_proto_key);

    ASSERT_NOT_NULL(pub_init_proto_key_attr, false, "%s:%d No public initiator protocol key attribute found\n", __func__, __LINE__);
    ASSERT_EQUALS(pub_init_proto_key_attr->length, BN_num_bytes(m_c_ctx.prime) * 2, false, "%s:%d Invalid public initiator protocol key length\n", __func__, __LINE__);

    if (m_eph_ctx().public_init_proto_key) {
        EC_POINT_free(m_eph_ctx().public_init_proto_key);
    }

    m_eph_ctx().public_init_proto_key = ec_crypto::decode_ec_point(m_c_ctx, pub_init_proto_key_attr->data);
    ASSERT_NOT_NULL(m_eph_ctx().public_init_proto_key, false, "%s:%d failed to decode public initiator protocol key\n", __func__, __LINE__);

    // START Crypto in EasyConnect 6.3.3
    // Compute the M.x
    ASSERT_NOT_NULL(m_boot_data().resp_priv_boot_key, false, "%s:%d failed to get responder bootstrapping private key\n", __func__, __LINE__);

    m_eph_ctx().m = ec_crypto::compute_ec_ss_x(m_c_ctx, m_boot_data().resp_priv_boot_key, m_eph_ctx().public_init_proto_key);
    const BIGNUM *bn_inputs[1] = { m_eph_ctx().m };
    // Compute the "first intermediate key" (k1)
    if (ec_crypto::compute_hkdf_key(m_c_ctx, m_eph_ctx().k1, m_c_ctx.digest_len, "first intermediate key", bn_inputs, 1, NULL, 0) == 0) {
        printf("%s:%d: Failed to compute k1\n", __func__, __LINE__); 
        return false;
    }

    printf("Key K_1:\n");
    util::print_hex_dump(static_cast<unsigned int> (m_c_ctx.digest_len), m_eph_ctx().k1);

    ec_attribute_t *wrapped_data_attr = ec_util::get_attrib(frame->attributes, static_cast<uint16_t> (attrs_len), ec_attrib_id_wrapped_data);
    ASSERT_NOT_NULL(wrapped_data_attr, false, "%s:%d No wrapped data attribute found\n", __func__, __LINE__);

    // Attempt to unwrap the wrapped data with generated k1 (from sent keys)
    auto [wrapped_data, wrapped_len] = ec_util::unwrap_wrapped_attrib(wrapped_data_attr, frame, false, m_eph_ctx().k1); 
    if (wrapped_data == NULL || wrapped_len == 0) {
        printf("%s:%d failed to unwrap wrapped data\n", __func__, __LINE__);
        // "Abondon the exchange"
        return false;
    }

    ec_attribute_t *init_caps_attr = ec_util::get_attrib(wrapped_data, static_cast<uint16_t> (wrapped_len), ec_attrib_id_init_caps);
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
        if (m_send_action_frame(src_mac, resp_frame, resp_len, 0)){
            printf("%s:%d Successfully sent DPP Status Not Compatible response frame\n", __func__, __LINE__);
        } else {
            printf("%s:%d Failed to send DPP Status Not Compatible response frame\n", __func__, __LINE__);
        }
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
        if (m_send_action_frame(src_mac, resp_frame, resp_len, 0)){
            printf("%s:%d Successfully sent DPP Status Response Pending response frame\n", __func__, __LINE__);
        } else {
            printf("%s:%d Failed to send DPP Status Response Pending response frame\n", __func__, __LINE__);
        }
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
    bool did_succeed = m_send_action_frame(src_mac, resp_frame, resp_len, 0);
    if (did_succeed){
        printf("%s:%d Successfully sent DPP Status OK response frame\n", __func__, __LINE__);
    } else {
        printf("%s:%d Failed to send DPP Status OK response frame\n", __func__, __LINE__);
    }

    return did_succeed;
}

bool ec_enrollee_t::handle_auth_confirm(ec_frame_t *frame, size_t len, uint8_t src_mac[ETHER_ADDR_LEN])
{
    size_t attrs_len = len - EC_FRAME_BASE_SIZE;

    ec_attribute_t *status_attrib = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_dpp_status);
    ASSERT_NOT_NULL(status_attrib, false, "%s:%d: No DPP status attribute found\n", __func__, __LINE__);

    ec_status_code_t dpp_status = static_cast<ec_status_code_t>(status_attrib->data[0]);

    if (dpp_status != DPP_STATUS_OK && dpp_status != DPP_STATUS_AUTH_FAILURE && dpp_status != DPP_STATUS_NOT_COMPATIBLE) {
        printf("%s:%d: Recieved Improper DPP Status: \"%s\"\n", __func__, __LINE__, ec_util::status_code_to_string(dpp_status).c_str());
        return false;
    }

    ec_attribute_t *wrapped_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_wrapped_data);
    ASSERT_NOT_NULL(wrapped_attr, false, "%s:%d: No wrapped data attribute found\n", __func__, __LINE__);

    uint8_t* key = (dpp_status == DPP_STATUS_OK) ? m_eph_ctx().ke : m_eph_ctx().k2;
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
    BIGNUM* P_I_x = ec_crypto::get_ec_x(m_c_ctx, m_eph_ctx().public_init_proto_key);
    BIGNUM* P_R_x = ec_crypto::get_ec_x(m_c_ctx, m_eph_ctx().public_resp_proto_key);
    BIGNUM* B_I_x = ec_crypto::get_ec_x(m_c_ctx, m_boot_data().resp_pub_boot_key);
    BIGNUM* B_R_x = ec_crypto::get_ec_x(m_c_ctx, m_boot_data().init_pub_boot_key);

    if (P_I_x == NULL || P_R_x == NULL || B_R_x == NULL) {
        printf("%s:%d: Failed to get x-coordinates of P_I, P_R, and B_R\n", __func__, __LINE__);
        if (P_I_x) BN_free(P_I_x);
        if (P_R_x) BN_free(P_R_x);
        if (B_R_x) BN_free(B_R_x);
        if (B_I_x) BN_free(B_I_x);
        return false;
    }

    // B_I.x is not needed (can be null) if mutual authentication is not supported
    if (m_eph_ctx().is_mutual_auth && B_I_x == NULL) {
        printf("%s:%d: Failed to get x-coordinate of B_I\n", __func__, __LINE__);
        BN_free(P_I_x);
        BN_free(P_R_x);
        BN_free(B_R_x);
        return false;
    }

    easyconnect::hash_buffer_t i_auth_hb;
    ec_crypto::add_to_hash(i_auth_hb, m_eph_ctx().r_nonce, m_c_ctx.nonce_len);
    ec_crypto::add_to_hash(i_auth_hb, m_eph_ctx().i_nonce, m_c_ctx.nonce_len);
    ec_crypto::add_to_hash(i_auth_hb, P_R_x); //P_R
    ec_crypto::add_to_hash(i_auth_hb, P_I_x); //P_I
    ec_crypto::add_to_hash(i_auth_hb, B_R_x); //B_R
    if (m_eph_ctx().is_mutual_auth) ec_crypto::add_to_hash(i_auth_hb, B_I_x); //B_I
    ec_crypto::add_to_hash(i_auth_hb, static_cast<uint8_t>(1)); // 1 octet

    uint8_t* i_auth_prime = ec_crypto::compute_hash(m_c_ctx, i_auth_hb);

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

    const auto [config_req, config_req_len] = create_config_request();
    if (config_req == nullptr || config_req_len == 0) {
        printf("%s:%d: Could not create DPP Configuration Request!\n", __func__, __LINE__);
        return false;
    }

    // EasyMesh R6 5.3.1:
    // The DPP onboarding process begins when the Multi-AP Controller receives the bootstrapping information of the Enrollee
    // Multi-AP Agent in the form of a DPP URI. Upon receipt of the DPP URI, the Multi-AP Controller instructs one or more
    // existing Multi-AP Agents to advertise the CCE IE in their Beacon and Probe Response frames, if they are not doing so
    // already, and listen to the Enrollee's DPP Presence Announcement frame. Once the Multi-AP Controller receives a DPP
    // Presence Announcement frame from an Enrollee Multi-AP Agent, it initiates the DPP Authentication procedure by
    // generating a DPP Authentication Request frame. A Multi-AP Agent, acting as a proxy, relays the DPP Authentication
    // messages received from the Multi-AP Controller to the Enrollee when the DPP Presence Announcement frame with the
    // correct hash is received from the Enrollee. The proxy performs a bi-directional conversation between a DPP frame carried
    // in an 802.11 frame to a DPP frame encapsulated in a Multi-AP CMDU message. **Upon successful authentication**, the
    // Enrollee Multi-AP Agent requests configuration by exchanging DPP Configuration Protocol messages (see 6.6 of [18])
    // with the Multi-AP Controller.
    bool sent_dpp_config_gas_frame = m_send_action_frame(src_mac, config_req, config_req_len, 0);
    if (sent_dpp_config_gas_frame) {
        printf("%s:%d: Sent DPP Configuration Request 802.11 frame to Proxy Agent!\n", __func__, __LINE__);
    } else {
        printf("%s:%d: Failed to send DPP Configuration Request GAS frame\n", __func__, __LINE__);
    }
    free(config_req);

    return sent_dpp_config_gas_frame;
}

bool ec_enrollee_t::handle_config_response(uint8_t *buff, unsigned int len, uint8_t sa[ETH_ALEN])
{
    printf("%s:%d: Got a DPP Configuration Response from " MACSTRFMT "\n", __func__, __LINE__, MAC2STR(sa));
    uint8_t *p = buff;

    ec_gas_frame_base_t *gas_base_frame = reinterpret_cast<ec_gas_frame_base_t *>(p);
    p += sizeof(ec_gas_frame_base_t);
    ec_gas_initial_response_frame_t *gas_initial_response = reinterpret_cast<ec_gas_initial_response_frame_t *>(p);
    printf(
        "%s:%d: Got a DPP config response! category=%02x action=%02x dialog_token=%02x ape=" APEFMT
        " ape_id=" APEIDFMT " resp_len=%u\n",
        __func__, __LINE__, gas_base_frame->category, gas_base_frame->action,
        gas_base_frame->dialog_token, APE2STR(gas_initial_response->ape),
        APEID2STR(gas_initial_response->ape_id), gas_initial_response->resp_len);
    return true;
}

std::pair<uint8_t *, size_t> ec_enrollee_t::create_presence_announcement()
{
    printf("%s:%d Enter\n", __func__, __LINE__);

    ec_frame_t *frame =  ec_util::alloc_frame(ec_frame_type_presence_announcement);
    ASSERT_NOT_NULL(frame, {}, "%s:%d failed to allocate memory for frame\n", __func__, __LINE__);

    // Compute the hash of the responder boot key 
    uint8_t *resp_boot_key_chirp_hash = ec_crypto::compute_key_hash(m_boot_data().responder_boot_key, "chirp");
    ASSERT_NOT_NULL_FREE(resp_boot_key_chirp_hash, {}, frame, "%s:%d unable to compute \"chirp\" responder bootstrapping key hash\n", __func__, __LINE__);

    uint8_t* attribs = NULL;
    size_t attribs_len = 0;

    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_resp_bootstrap_key_hash, SHA256_DIGEST_LENGTH, resp_boot_key_chirp_hash);
    free(resp_boot_key_chirp_hash);

    if (!(frame = ec_util::copy_attrs_to_frame(frame, attribs, attribs_len))) {
        printf("%s:%d unable to copy attributes to frame\n", __func__, __LINE__);
        free(attribs);
        free(frame);
        return {};
    }
    free(attribs);

    return {};
}


std::pair<uint8_t *, size_t> ec_enrollee_t::create_auth_response(ec_status_code_t dpp_status, uint8_t init_proto_version)
{

    /*
    STATUS_NOT_COMPATIBLE:
        Responder → Initiator: DPP Status, SHA-256(BR), [ SHA-256(BI),][ Protocol Version ], { I-nonce, R-capabilities}k1
    STATUS_RESPONSE_PENDING:
        Responder → Initiator: DPP Status, SHA-256(BR), [ SHA-256(BI),][ Protocol Version ], { I-nonce, R-capabilities}k1
    STATUS_OK:
        Responder → Initiator: DPP Status, SHA-256(BR), [ SHA-256(BI), ] PR, [Protocol Version], { R-nonce, I-nonce, R-capabilities, { R-auth }ke }k2
    */

    ec_frame_t *frame =  ec_util::alloc_frame(ec_frame_type_auth_cnf);
    ASSERT_NOT_NULL(frame, {}, "%s:%d failed to allocate memory for frame\n", __func__, __LINE__);

    uint8_t* attribs = NULL;
    size_t attribs_len = 0;

    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_dpp_status, static_cast<uint8_t>(dpp_status));

    // Add Responder Bootstrapping Key Hash (SHA-256(B_R))
    uint8_t* responder_keyhash = ec_crypto::compute_key_hash(m_boot_data().responder_boot_key);
    ASSERT_NOT_NULL_FREE2(responder_keyhash, {}, frame, attribs, "%s:%d failed to compute responder bootstrapping key hash\n", __func__, __LINE__);

    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_resp_bootstrap_key_hash, SHA256_DIGEST_LENGTH, responder_keyhash);
    free(responder_keyhash);
    // Conditional (Only included for mutual authentication) (SHA-256(B_I))
    if (m_eph_ctx().is_mutual_auth) {
        uint8_t* initiator_keyhash = ec_crypto::compute_key_hash(m_boot_data().initiator_boot_key);
        if (initiator_keyhash != NULL) {
            attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_init_bootstrap_key_hash, SHA256_DIGEST_LENGTH, initiator_keyhash);
            free(initiator_keyhash);
        }

    }


    // Add remaining NON-OK attributes and return due to complexity with OK attributes
    if (dpp_status != DPP_STATUS_OK) {
        if (init_proto_version >= 2) {
            // Add Protocol Version (TOOD: Add variable for responder protocol version)
            attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_proto_version, static_cast<uint8_t>(1));
        }
        attribs = ec_util::add_wrapped_data_attr(frame, attribs, &attribs_len, true, m_eph_ctx().k1, [&](){
            size_t wrapped_len = 0;
            uint8_t* wrap_attribs = ec_util::add_attrib(NULL, &wrapped_len, ec_attrib_id_init_nonce, m_c_ctx.nonce_len, m_eph_ctx().i_nonce);
            wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_resp_caps, m_dpp_caps.byte);
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
    
    // STATUS_OK

    // Generate R-nonce
    if (!RAND_bytes(m_eph_ctx().r_nonce, m_c_ctx.nonce_len)) {
        printf("%s:%d failed to generate R-nonce\n", __func__, __LINE__);
        free(attribs);
        free(frame);
        return {};
    }

    // Generate initiator protocol key pair (p_i/P_I)
    auto [priv_resp_proto_key, pub_resp_proto_key] = ec_crypto::generate_proto_keypair(m_c_ctx);
    if (priv_resp_proto_key == NULL || pub_resp_proto_key == NULL) {
        printf("%s:%d failed to generate responder protocol keypair\n", __func__, __LINE__);
        free(attribs);
        free(frame);
        return {};
    }
    
    // Use const_cast instead of old-style cast
    m_eph_ctx().public_resp_proto_key = const_cast<EC_POINT*>(pub_resp_proto_key);
    m_eph_ctx().priv_resp_proto_key = const_cast<BIGNUM*>(priv_resp_proto_key);

    ASSERT_NOT_NULL_FREE2(m_eph_ctx().public_init_proto_key, {}, frame, attribs, "%s:%d initiator protocol keypair was never generated!\n", __func__, __LINE__);
    m_eph_ctx().n = ec_crypto::compute_ec_ss_x(m_c_ctx, m_eph_ctx().priv_resp_proto_key, m_eph_ctx().public_init_proto_key);
    const BIGNUM *bn_inputs[1] = { m_eph_ctx().n };
    // Compute the "second intermediate key" (k2)
    if (ec_crypto::compute_hkdf_key(m_c_ctx, m_eph_ctx().k2, m_c_ctx.digest_len, "second intermediate key", bn_inputs, 1, NULL, 0) == 0) {
        printf("%s:%d: Failed to compute k2\n", __func__, __LINE__); 
        free(attribs);
        free(frame);
        return {};
    }

    printf("Key K_2:\n");
    util::print_hex_dump(m_c_ctx.digest_len, m_eph_ctx().k2);

    ASSERT_NOT_NULL_FREE2(m_boot_data().resp_priv_boot_key, {}, frame, attribs, "%s:%d failed to get responder bootstrapping private key\n", __func__, __LINE__);

    // Compute L.x
    if (m_eph_ctx().is_mutual_auth){
        if (m_boot_data().init_pub_boot_key != NULL){
            m_eph_ctx().l = ec_crypto::calculate_Lx(m_c_ctx, m_boot_data().resp_priv_boot_key, m_eph_ctx().priv_resp_proto_key, m_boot_data().init_pub_boot_key);
        }
    }

    if (m_eph_ctx().is_mutual_auth && m_eph_ctx().l == NULL) {
        printf("%s:%d failed to compute L.x\n", __func__, __LINE__);
        free(attribs);
        free(frame);
        return {};
    }
    

    // Compute k_e
    if (ec_crypto::compute_ke(m_c_ctx, &m_eph_ctx(), m_eph_ctx().ke) == 0){
        printf("%s:%d: Failed to compute ke\n", __func__, __LINE__);
        free(attribs);
        free(frame);
        return {};
    }

    // Compute R-auth = H(I-nonce | R-nonce | PI.x | PR.x | [ BI.x | ] BR.x | 0)
    BIGNUM* P_I_x = ec_crypto::get_ec_x(m_c_ctx, m_eph_ctx().public_init_proto_key);
    BIGNUM* P_R_x = ec_crypto::get_ec_x(m_c_ctx, m_eph_ctx().public_resp_proto_key);
    BIGNUM* B_I_x = ec_crypto::get_ec_x(m_c_ctx, m_boot_data().init_pub_boot_key);
    BIGNUM* B_R_x = ec_crypto::get_ec_x(m_c_ctx, m_boot_data().resp_pub_boot_key);

    if (P_I_x == NULL || P_R_x == NULL || B_R_x == NULL) {
        printf("%s:%d: Failed to get x-coordinates of P_I, P_R, and B_R\n", __func__, __LINE__);
        if (P_I_x) BN_free(P_I_x);
        if (P_R_x) BN_free(P_R_x);
        if (B_R_x) BN_free(B_R_x);
        if (B_I_x) BN_free(B_I_x);
        return {};
    }

    // B_I.x is not needed (can be null) if mutual authentication is not supported
    if (m_eph_ctx().is_mutual_auth && B_I_x == NULL) {
        printf("%s:%d: Failed to get x-coordinate of B_I when mutal authentication is occuring\n", __func__, __LINE__);
        BN_free(P_I_x);
        BN_free(P_R_x);
        BN_free(B_R_x);
        return {};
    }

    easyconnect::hash_buffer_t r_auth_hb;
    ec_crypto::add_to_hash(r_auth_hb, m_eph_ctx().i_nonce, m_c_ctx.nonce_len);
    ec_crypto::add_to_hash(r_auth_hb, m_eph_ctx().r_nonce, m_c_ctx.nonce_len);
    ec_crypto::add_to_hash(r_auth_hb, P_I_x); //P_I
    ec_crypto::add_to_hash(r_auth_hb, P_R_x); //P_R
    if (m_eph_ctx().is_mutual_auth) ec_crypto::add_to_hash(r_auth_hb, B_I_x); //B_I
    ec_crypto::add_to_hash(r_auth_hb, B_R_x); //B_R
    ec_crypto::add_to_hash(r_auth_hb, static_cast<uint8_t>(0)); // 1 octet

    uint8_t* r_auth = ec_crypto::compute_hash(m_c_ctx, r_auth_hb);
    if (P_I_x) BN_free(P_I_x);
    if (P_R_x) BN_free(P_R_x);
    if (B_R_x) BN_free(B_R_x);
    if (B_I_x) BN_free(B_I_x);
    ASSERT_NOT_NULL_FREE2(r_auth, {}, frame, attribs, "%s:%d: Failed to compute R-auth\n", __func__, __LINE__);

    // Add P_R
    auto encoded_P_R = ec_crypto::encode_ec_point(m_c_ctx, m_eph_ctx().public_resp_proto_key);
    ASSERT_NOT_NULL_FREE2(encoded_P_R, {}, frame, attribs, "%s:%d failed to encode responder protocol key\n", __func__, __LINE__);

    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_resp_proto_key, static_cast<uint16_t>(BN_num_bytes(m_c_ctx.prime) * 2), encoded_P_R);

    // Add Protocol Version
    if (init_proto_version >= 2) {
        // Add Protocol Version (TOOD: Add variable for responder protocol version)
        attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_proto_version, static_cast<uint8_t>(1));
    }

    // Add `{ R-nonce, I-nonce, R-capabilities, { R-auth }k_e }k_2`
    attribs = ec_util::add_wrapped_data_attr(frame, attribs, &attribs_len, true, m_eph_ctx().k2, [&](){
        size_t wrapped_len = 0;
        uint8_t* wrap_attribs = ec_util::add_attrib(NULL, &wrapped_len, ec_attrib_id_resp_nonce, m_c_ctx.nonce_len, m_eph_ctx().r_nonce);
        wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_init_nonce, m_c_ctx.nonce_len, m_eph_ctx().i_nonce);
        wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_resp_caps, m_dpp_caps.byte);

        // R-auth is wrapped in an additional wrapped data attribute (k_e) inside the main wrapped data attribute (k_2)
        wrap_attribs = ec_util::add_wrapped_data_attr(frame, wrap_attribs, &wrapped_len, true, m_eph_ctx().ke, [&](){
            size_t int_wrapped_len = 0;
            uint8_t* int_wrapped_attrs = ec_util::add_attrib(NULL, &int_wrapped_len, ec_attrib_id_resp_auth_tag, m_c_ctx.digest_len, r_auth);
            return std::make_pair(int_wrapped_attrs, int_wrapped_len);
        });
        return std::make_pair(wrap_attribs, wrapped_len);
    });

    free(r_auth);

    if (!(frame = ec_util::copy_attrs_to_frame(frame, attribs, attribs_len))) {
        printf("%s:%d unable to copy attributes to frame\n", __func__, __LINE__);
        free(frame);
        free(attribs);
        return {};
    }
    free(attribs);

    return std::make_pair(reinterpret_cast<uint8_t*>(frame), EC_FRAME_BASE_SIZE + attribs_len);

}

std::pair<uint8_t *, size_t> ec_enrollee_t::create_recfg_presence_announcement()
{
    /*
    EasyConnect 6.5.2
    Before every transmission of a DPP Reconfiguration Announcement frame, 
    the Enrollee generates a random nonce a-nonce, with 0 ≤ a-nonce < q, 
    where q is the order of the elliptic curve group of the Configurator signing key, 
    and the corresponding ECC point A-NONCE
        A-NONCE = a-nonce * G
    where G is the generator of the elliptic curve group of the Configurator signing key.
    */

    if (m_c_ctx.group == NULL || m_c_ctx.order == NULL || m_c_ctx.bn_ctx == NULL) {
        printf("%s:%d: Pre-initialized EC parameters not initialized!\n", __func__, __LINE__);
        return {};
    }

    uint8_t a_nonce_buf[m_c_ctx.nonce_len];
    if (!RAND_bytes(a_nonce_buf, m_c_ctx.nonce_len)) {
        printf("%s:%d: Failed to generate A-nonce\n", __func__, __LINE__);
        return {};
    }

    scoped_bn a_nonce(BN_new());
    scoped_ec_point A_NONCE(EC_POINT_new(m_c_ctx.group));
    // a-nonce * Ppk
    scoped_ec_point a_nonce_ppk(EC_POINT_new(m_c_ctx.group));
    scoped_ec_point E_prime_Id(EC_POINT_new(m_c_ctx.group));

    if (a_nonce == NULL || A_NONCE == NULL || a_nonce_ppk == NULL || E_prime_Id == NULL) {
        printf("%s:%d: Failed to allocate memory for a-nonce, A-NONCE, a-nonce * Ppk temp, and "
               "E'-id\n",
               __func__, __LINE__);
        return {};
    }

    // Convert the random bytes to a BIGNUM
    if (!BN_bin2bn(a_nonce_buf, m_c_ctx.nonce_len, a_nonce.get())) {
        printf("%s:%d: Failed to convert a-nonce to BIGNUM\n", __func__, __LINE__);
        return {};
    }

    // modulo to ensure the value is less than the order
    if (!BN_mod(a_nonce.get(), a_nonce.get(), m_c_ctx.order, m_c_ctx.bn_ctx)) {
        printf("%s:%d: Failed to modulo a-nonce\n", __func__, __LINE__);
        return {};
    }

    // Compute A-NONCE = a-nonce * G
    if (!EC_POINT_mul(m_c_ctx.group, A_NONCE.get(), a_nonce.get(), NULL, NULL, m_c_ctx.bn_ctx)) {
        printf("%s:%d: Failed to compute A-NONCE\n", __func__, __LINE__);
        return {};
    }

    // Calculate a-nonce * Ppk
    if (!EC_POINT_mul(m_c_ctx.group, a_nonce_ppk.get(), NULL, m_c_ctx.ppk, a_nonce.get(),
                      m_c_ctx.bn_ctx)) {
        printf("%s:%d: Failed to compute a-nonce * Ppk\n", __func__, __LINE__);
        return {};
    }

    // Calculate E'-id = E-id + (a-nonce * Ppk)
    if (!EC_POINT_add(m_c_ctx.group, E_prime_Id.get(), m_eph_ctx().E_Id, a_nonce_ppk.get(),
                      m_c_ctx.bn_ctx)) {
        printf("%s:%d: Failed to compute E'-id\n", __func__, __LINE__);
        return {};
    }

    /**
     * Reconfiguration Announcement frame (EasyConnect 8.2.15)
     * -------------------------------------------------------
     *   The Reconfiguration Announcement frame uses the DPP Action frame format and is transmitted 
     *   by a DPP Enrollee to signal the DPP Configurator that it wishes to perform a reconfiguration 
     *   exchange with the Configurator.
     * 
     * Frame Attributes:
     *   - Configurator C-sign-key Hash (Required)
     *      - SHA-256 hash of the uncompressed form of the Configurator's public C-sign-key
     *      - This is the base64url decoded value of the "kid" from the JWS Protected Header 
     *        of the Enrollee's Connector
     * 
     *   - Finite Cyclic Group (Required)
     *      - The group from which the Enrollee NAK is drawn
     * 
     *   - A-NONCE (Required)
     *      - The ECC point representing the a-nonce
     * 
     *   - E'-id (Required)
     *      - The ECC point representing the randomly encrypted E-id
     */

    // Create the DPP Reconfiguration Presence Announcement frame
    ec_frame_t *frame = ec_util::alloc_frame(ec_frame_type_recfg_announcement);
    ASSERT_NOT_NULL(frame, {}, "%s:%d failed to allocate memory for frame\n", __func__, __LINE__);

    size_t attribs_len = 0;

    // C-sign-key hash attribute
    // Might need to replace with "kid"
    uint8_t *c_sign_hash = ec_crypto::compute_key_hash(m_c_ctx.C_signing_key);
    uint8_t *attribs = ec_util::add_attrib(NULL, &attribs_len, ec_attrib_id_C_sign_key_hash,
                                           SHA256_DIGEST_LENGTH, c_sign_hash);
    free(c_sign_hash);
    ASSERT_NOT_NULL_FREE2(attribs, {}, frame, attribs,
                          "%s:%d: Failed to add C-signing key hash attribute\n", __func__,
                          __LINE__);

    // Finite Cyclic Group attribute
    scoped_ec_group group(em_crypto_t::get_key_group(m_c_ctx.net_access_key));
    ASSERT_NOT_NULL_FREE2(group.get(), {}, frame, attribs,
                          "%s:%d: Failed to get elliptic curve group from network access key\n",
                          __func__, __LINE__);
    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_finite_cyclic_group,
                                  ec_crypto::get_tls_group_id_from_ec_group(group.get()));
    ASSERT_NOT_NULL_FREE2(attribs, {}, frame, attribs,
                          "%s:%d: Failed to add finite cyclic group attribute\n", __func__,
                          __LINE__);

    uint16_t encoded_len = static_cast<uint16_t>(BN_num_bytes(m_c_ctx.prime) * 2);
    // A-NONCE attribute
    auto encoded_A_NONCE = ec_crypto::encode_ec_point(m_c_ctx, A_NONCE.get());
    ASSERT_NOT_NULL_FREE2(encoded_A_NONCE, {}, frame, attribs, "%s:%d: Failed to encode A-NONCE\n",
                          __func__, __LINE__);
    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_a_nonce, encoded_len,
                                  encoded_A_NONCE);
    ASSERT_NOT_NULL_FREE2(attribs, {}, frame, attribs, "%s:%d: Failed to add A-NONCE attribute\n",
                          __func__, __LINE__);

    // E'-id attribute
    auto encoded_E_prime_Id = ec_crypto::encode_ec_point(m_c_ctx, E_prime_Id.get());
    ASSERT_NOT_NULL_FREE2(encoded_E_prime_Id, {}, frame, attribs, "%s:%d: Failed to encode E'-id\n",
                          __func__, __LINE__);
    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_e_prime_id, encoded_len,
                                  encoded_E_prime_Id);
    ASSERT_NOT_NULL_FREE2(attribs, {}, frame, attribs, "%s:%d: Failed to add E'-id attribute\n",
                          __func__, __LINE__);

    if (!(frame = ec_util::copy_attrs_to_frame(frame, attribs, attribs_len))) {
        printf("%s:%d unable to copy attributes to frame\n", __func__, __LINE__);
        free(frame);
        free(attribs);
        return {};
    }
    free(attribs);

    return std::make_pair(reinterpret_cast<uint8_t *>(frame), EC_FRAME_BASE_SIZE + attribs_len);
}

std::pair<uint8_t *, size_t> ec_enrollee_t::create_recfg_auth_response(ec_status_code_t dpp_status)
{
    return std::pair<uint8_t *, size_t>();
}

std::pair<uint8_t *, size_t> ec_enrollee_t::create_config_request()
{
    // EasyConnect 6.4.2 DPP Configuration Request
    // Regardless of whether the Initiator or Responder took the role of Configurator, the DPP Configuration protocol is always
    // initiated by the Enrollee. To start, the Enrollee generates one or more DPP Configuration Request objects (see section
    // 4.4) and generates a new nonce, E-nonce, whose length is determined according to Table 4. When the Configurator has
    // not indicated support for protocol version number 2 or higher, no more than one DPP Configuration Request object shall
    // be included. The E-nonce attribute and the DPP Configuration Request object attribute(s) are wrapped with ke. The
    // wrapped attributes are then placed in a DPP Configuration Request frame, and sent to the Configurator.
    // Enrollee → Configurator: { E-nonce, configRequest }ke
    if ((m_eph_ctx().e_nonce = static_cast<uint8_t *>(malloc(m_c_ctx.nonce_len))) == NULL) {
        printf("%s:%d: Could not malloc for E-nonce!\n", __func__, __LINE__);
        return {};
    }

    if (RAND_bytes(m_eph_ctx().e_nonce, m_c_ctx.nonce_len) != 1) {
        printf("%s:%d: Could not generate E-nonce!\n", __func__, __LINE__);
        free(m_eph_ctx().e_nonce);
        return {};
    }

    if (m_boot_data().version <= 1) {
        printf("%s:%d: EasyMesh R >= 5 mandates DPP version >= 2, current version is %d, bailing.\n", __func__, __LINE__, m_boot_data().version);
        return {};
    }

    // EasyMesh R6 5.3.3
    // If an Enrollee Multi-AP Agent sends a DPP Configuration Request frame (see section 6.4.2 of [18] and Table 5), it shall:
    // - Include one DPP Configuration Request Object (see Table 5)
    // - set the netRole to "mapAgent"
    // - set wi-fi_tech to "map"
    // - include the akm parameter, and
    // - set the akm parameter value to the supported akm of its backhaul STA.
    cJSON *dpp_config_request_obj = cJSON_CreateObject();
    cJSON *netRole = cJSON_CreateString("mapAgent");
    cJSON *wifi_tech = cJSON_CreateString("map");
    char hostname[256] = {0};
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        printf("%s:%d: `gethostname` failed, defaulting DPP Configuration Request object key \"name\" to \"Enrollee\"", __func__, __LINE__);
        static const char *default_name = "Enrollee";
        strncpy(hostname, default_name, strlen(default_name));
    }
    cJSON *name = cJSON_CreateString(hostname);
    if (!dpp_config_request_obj || !netRole || !wifi_tech) {
        printf("%s:%d: Failed to create DPP Configuration Request Object!\n", __func__, __LINE__);
        free(m_eph_ctx().e_nonce);
        return {};
    }
    cJSON_AddItemToObject(dpp_config_request_obj, "netRole", netRole);
    cJSON_AddItemToObject(dpp_config_request_obj, "wi-fi_tech", wifi_tech);
    cJSON_AddItemToObject(dpp_config_request_obj, "name", name);
    if (m_get_bsta_info == nullptr) {
        printf("%s:%d: Get bSTA info callback is nullptr! Cannot create DPP Configuration Request Object, bailing.\n", __func__, __LINE__);
        free(m_eph_ctx().e_nonce);
        return {};
    }
    cJSON *bsta_info = m_get_bsta_info(nullptr);
    ASSERT_NOT_NULL_FREE(bsta_info, {}, m_eph_ctx().e_nonce, "%s:%d: bSTA info is nullptr!\n", __func__, __LINE__);
    cJSON_AddItemToObject(dpp_config_request_obj, "bSTAList", bsta_info);
    size_t config_obj_len = cjson_utils::get_cjson_blob_size(dpp_config_request_obj);

    // XXX: Dialog token can be thought of as a session key between Enrollee and Configurator regarding configuration
    // From specs (EasyMesh, EasyConnect, 802.11), it seems this is just arbitrarily chosen (1 byte), but
    // must be unique per GAS frame "session" exchange.
    // See: 802.11-2020 9.4.1.12 Dialog Token field
    unsigned char dialog_token = 1;
    auto [frame, frame_len] = ec_util::alloc_gas_frame(dpp_gas_initial_req, dialog_token);
    if (frame == nullptr || frame_len == 0) {
        printf("%s:%d: Could not create DPP Configuration Request GAS frame!\n", __func__, __LINE__);
        free(m_eph_ctx().e_nonce);
        return {};
    }

    ec_gas_initial_request_frame_t *initial_req_frame = static_cast<ec_gas_initial_request_frame_t *> (frame);
    uint8_t *attribs = nullptr;
    size_t attribs_len = 0;
    // Wrap e-nonce and config req obj(s) with k_e
    attribs = ec_util::add_wrapped_data_attr(reinterpret_cast<uint8_t *> (initial_req_frame), sizeof(ec_gas_initial_request_frame_t), attribs, &attribs_len, true, m_eph_ctx().ke, [&](){
        size_t wrapped_len = 0;
        uint8_t* wrapped_attribs = ec_util::add_attrib(nullptr, &wrapped_len, ec_attrib_id_enrollee_nonce, m_c_ctx.nonce_len, m_eph_ctx().e_nonce);
        wrapped_attribs = ec_util::add_attrib(wrapped_attribs, &wrapped_len, ec_attrib_id_dpp_config_req_obj, static_cast<uint16_t> (config_obj_len), reinterpret_cast<uint8_t *> (dpp_config_request_obj));
        return std::make_pair(wrapped_attribs, wrapped_len);
    });

    if ((initial_req_frame = reinterpret_cast<ec_gas_initial_request_frame_t*>(
        ec_util::copy_attrs_to_frame(reinterpret_cast<uint8_t*> (initial_req_frame), sizeof(ec_gas_initial_request_frame_t), attribs, attribs_len))) == nullptr) {
        printf("%s:%d: unable to copy attribs to GAS frame\n", __func__, __LINE__);
        free(attribs);
        free(frame);
        free(m_eph_ctx().e_nonce);
        return {};
    }
    initial_req_frame->query_len = static_cast<uint16_t>(attribs_len);
    
    return std::make_pair(reinterpret_cast<uint8_t*>(initial_req_frame), sizeof(ec_gas_initial_request_frame_t) + attribs_len);
}

std::pair<uint8_t *, size_t> ec_enrollee_t::create_config_result(ec_status_code_t dpp_status)
{
    // EasyConnect 6.4.4 DPP Configuration Result
    // When both the Enrollee and the Configurator indicate their protocol version numbers to be 2 or higher, the Enrollee
    // reports the result of configuration processing to the Configurator to allow clear indication of the results on the
    // Configurator's user interface. The result is indicated in the DPP Configuration Result frame sent on the same channel
    // immediately after the final DPP Configuration Response frame. The DPP Status field value indicates the result of the
    // configuration: STATUS_OK indicates success and STATUS_CONFIG_REJECTED indicates failure.
    // Enrollee → Configurator: { DPP Status, E-nonce }ke

    ec_frame_t *frame = ec_util::alloc_frame(ec_frame_type_cfg_result);
    ASSERT_NOT_NULL(frame, {}, "%s:%d: Failed to allocate DPP Configuration Result frame\n", __func__, __LINE__);

    uint8_t *attribs = nullptr;
    size_t attribs_len = 0;

    attribs = ec_util::add_wrapped_data_attr(frame, attribs, &attribs_len, true, m_eph_ctx().ke, [&]() {
        size_t wrapped_len = 0;
        uint8_t *wrapped_attrs = ec_util::add_attrib(nullptr, &wrapped_len, ec_attrib_id_dpp_status, static_cast<uint8_t>(dpp_status));
        wrapped_attrs = ec_util::add_attrib(wrapped_attrs, &wrapped_len, ec_attrib_id_enrollee_nonce, m_c_ctx.nonce_len, m_eph_ctx().e_nonce);
        return std::make_pair(wrapped_attrs, wrapped_len);
    });

    if (!(frame = ec_util::copy_attrs_to_frame(frame, attribs, attribs_len))) {
        printf("%s:%d: Failed to copy attributes to DPP Configuration Result frame\n", __func__, __LINE__);
        free(attribs);
        free(frame);
        return {};
    }
    return std::make_pair(reinterpret_cast<uint8_t*>(frame), EC_FRAME_BASE_SIZE + attribs_len);
}
