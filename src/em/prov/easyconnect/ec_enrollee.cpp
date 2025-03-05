#include "ec_enrollee.h"

#include "ec_util.h"
#include "ec_crypto.h"
#include "util.h"

ec_enrollee_t::ec_enrollee_t()
{
}

ec_enrollee_t::~ec_enrollee_t()
{
}

int ec_enrollee_t::start(bool do_reconfig)
{
    return 0;
}

int ec_enrollee_t::handle_auth_request(uint8_t *buff, unsigned int len)
{
    ec_frame_t *frame = (ec_frame_t *)buff;

    size_t attrs_len = len - EC_FRAME_BASE_SIZE;

    ec_attribute_t *B_r_hash_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_resp_bootstrap_key_hash);
    if (!B_r_hash_attr) return -1;

    uint8_t* responder_keyhash = ec_crypto::compute_key_hash(m_boot_data.responder_boot_key);

    if (memcmp(B_r_hash_attr->data, responder_keyhash, B_r_hash_attr->length) != 0) {
        printf("%s:%d Responder key hash mismatch\n", __func__, __LINE__);
        return -1;
    }
    free(responder_keyhash);
    
    ec_attribute_t *B_i_hash_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_init_bootstrap_key_hash);
    if (!B_i_hash_attr) return -1;

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
    if (!pub_init_proto_key_attr) {
        printf("%s:%d No public initiator protocol key attribute found\n", __func__, __LINE__);
        return -1;
    }
    if (pub_init_proto_key_attr->length != BN_num_bytes(m_p_ctx.prime) * 2){
        printf("%s:%d Invalid public initiator protocol key length\n", __func__, __LINE__);
        return -1;
    }
    if (m_eph_ctx.public_init_proto_key) {
        EC_POINT_free(m_eph_ctx.public_init_proto_key);
    }

    m_eph_ctx.public_init_proto_key = ec_crypto::decode_proto_key(m_p_ctx, pub_init_proto_key_attr->data);

    // START Crypto in EasyConnect 6.3.3
    // Compute the M.x
    const BIGNUM *priv_resp_boot_key = EC_KEY_get0_private_key(m_boot_data.responder_boot_key);
    if (priv_resp_boot_key == NULL) {
        printf("%s:%d failed to get responder bootstrapping private key\n", __func__, __LINE__);
        return -1;
    }
    m_eph_ctx.m = ec_crypto::compute_ec_ss_x(m_p_ctx, priv_resp_boot_key, m_eph_ctx.public_init_proto_key);
    const BIGNUM *bn_inputs[1] = { m_eph_ctx.m };
    // Compute the "first intermediate key" (k1)
    if (ec_crypto::compute_hkdf_key(m_p_ctx, m_eph_ctx.k1, m_p_ctx.digest_len, "first intermediate key", bn_inputs, 1, NULL, 0) == 0) {
        printf("%s:%d: Failed to compute k1\n", __func__, __LINE__); 
        return -1;
    }

    printf("Key K_1:\n");
    util::print_hex_dump(m_p_ctx.digest_len, m_eph_ctx.k1);

    ec_attribute_t *wrapped_data_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_wrapped_data);
    if (!wrapped_data_attr) {
        printf("%s:%d No wrapped data attribute found\n", __func__, __LINE__);
        return -1;
    }

    // Attempt to unwrap the wrapped data with generated k1 (from sent keys)
    auto [wrapped_data, wrapped_len] = ec_util::unwrap_wrapped_attrib(wrapped_data_attr, frame, false, m_eph_ctx.k1); 
    if (wrapped_data == NULL || wrapped_len == 0) {
        printf("%s:%d failed to unwrap wrapped data\n", __func__, __LINE__);
        // "Abondon the exchange"
        return -1;
    }

    ec_attribute_t *init_caps_attr = ec_util::get_attrib(wrapped_data, wrapped_len, ec_attrib_id_init_caps);
    if (!init_caps_attr) {
        printf("%s:%d No initiator capabilities attribute found\n", __func__, __LINE__);
        return -1;
    }
    ec_dpp_capabilities_t init_caps = {
        .byte = init_caps_attr->data[0]
    };

    if (!check_supports_init_caps(init_caps)) {
        printf("%s:%d Initiator capabilities not supported\n", __func__, __LINE__);

        auto [resp_frame, resp_len] = create_auth_response(DPP_STATUS_NOT_COMPATIBLE);
        if (resp_frame == NULL || resp_len == 0) {
            printf("%s:%d failed to create response frame\n", __func__, __LINE__);
            return -1;
        }
/*
it shall respond with a DPP Authentication
Response frame indicating failure by adding the DPP Status field set to STATUS_NOT_COMPATIBLE, a hash of its
public bootstrapping key, a hash of the Initiator’s public bootstrapping key if it is doing mutual authentication, Protocol
Version attribute if it was sent in the DPP Authentication Request frame and is version 2 or higher, and Wrapped Data
element consisting of the Initiator’s nonce and the Responder’s desired capabilities wrapped with k1:
*/
        return -1;
    }

    //TODO/NOTE: Unknown: If need more time to process, respond `STATUS_RESPONSE_PENDING` (EasyConnect 6.3.3)
    // If the Responder needs more time to respond, e.g., to complete bootstrapping of the Initiator’s bootstrapping key

    //The Responder first selects capabilities that support the Initiator—for example,
    //  if the Initiator states it is a Configurator, then the Responder takes on the Enrollee role.
    auto [resp_frame, resp_len] = create_auth_response(DPP_STATUS_OK);
    if (resp_frame == NULL || resp_len == 0) {
        printf("%s:%d failed to create response frame\n", __func__, __LINE__);
        return -1;
    }
    // TODO: Send the response frame
}

int ec_enrollee_t::handle_auth_confirm(uint8_t *buff, unsigned int len)
{
    return 0;
}

int ec_enrollee_t::handle_config_response(uint8_t *buff, unsigned int len)
{
    return 0;
}

bool ec_enrollee_t::check_supports_init_caps(ec_dpp_capabilities_t caps)
{
    // Currently just returning true for all capabilities
    return true;
}

std::pair<uint8_t *, uint16_t> ec_enrollee_t::create_presence_announcement()
{
    // ec_frame_t *frame = (ec_frame_t *)buff;
    // frame->frame_type = ec_frame_type_presence_announcement; 

    // // Compute the hash of the responder boot key 
    // uint8_t resp_boot_key_chirp_hash[SHA512_DIGEST_LENGTH];
    // if (ec_util::compute_key_hash(m_params, m_data.responder_boot_key, resp_boot_key_chirp_hash, "chirp") < 1) {
    //     printf("%s:%d unable to compute \"chirp\" responder bootstrapping key hash\n", __func__, __LINE__);
    //     return -1;
    // }

    // uint8_t* attribs = frame->attributes;
    // uint16_t attrib_len = 0;

    // attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_resp_bootstrap_key_hash, SHA256_DIGEST_LENGTH, resp_boot_key_chirp_hash);
    // attrib_len += ec_util::get_ec_attr_size(SHA256_DIGEST_LENGTH); 

    // return attrib_len;
    return std::pair<uint8_t *, uint16_t>();
}

std::pair<uint8_t *, uint16_t> ec_enrollee_t::create_recfg_presence_announcement()
{
    return std::pair<uint8_t *, uint16_t>();
}

std::pair<uint8_t *, uint16_t> ec_enrollee_t::create_auth_response(ec_status_code_t dpp_status)
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
