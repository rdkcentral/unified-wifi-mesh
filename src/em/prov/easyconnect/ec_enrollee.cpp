#include "ec_enrollee.h"

#include "ec_util.h"
#include "ec_crypto.h"
#include "util.h"
#include "cjson/cJSON.h"

// TODO: Hard-coded! This should maybe be a func ptr
// Needs to know all about Enrollee's Wi-Fi caps
// Radios, supported AKM suites, etc.
// See: EasyMesh 5.3.2 Table 5
static cJSON *gen_config_obj() {
    cJSON *obj = cJSON_CreateObject();
    if (!obj) return nullptr;
    cJSON *name = cJSON_CreateString("EasyMesh Agent");
    if (!name) return nullptr;
    cJSON_AddItemToObject(obj, "name", name);
    cJSON *tech = cJSON_CreateString("map");
    if (!tech) return nullptr;
    cJSON_AddItemToObject(obj, "wi-fi_tech", tech);
    cJSON *role = cJSON_CreateString("mapAgent");
    if (!role) return nullptr;
    cJSON_AddItemToObject(obj, "netRole", role);
    return obj;
}

ec_enrollee_t::ec_enrollee_t(std::string mac_addr) : m_mac_addr(mac_addr)
{
}

ec_enrollee_t::~ec_enrollee_t()
{
}

bool ec_enrollee_t::start(bool do_reconfig)
{
    return true;
}

bool ec_enrollee_t::handle_auth_request(uint8_t *buff, unsigned int len)
{
    ec_frame_t *frame = (ec_frame_t *)buff;

    size_t attrs_len = len - EC_FRAME_BASE_SIZE;

    ec_attribute_t *B_r_hash_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_resp_bootstrap_key_hash);
    if (!B_r_hash_attr) return false;

    uint8_t* responder_keyhash = ec_crypto::compute_key_hash(m_boot_data.responder_boot_key);

    if (memcmp(B_r_hash_attr->data, responder_keyhash, B_r_hash_attr->length) != 0) {
        printf("%s:%d Responder key hash mismatch\n", __func__, __LINE__);
        return false;
    }
    free(responder_keyhash);
    
    ec_attribute_t *B_i_hash_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_init_bootstrap_key_hash);
    if (!B_i_hash_attr) return false;

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
        return false;
    }
    if (pub_init_proto_key_attr->length != BN_num_bytes(m_p_ctx.prime) * 2){
        printf("%s:%d Invalid public initiator protocol key length\n", __func__, __LINE__);
        return false;
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
        return false;
    }
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
    if (!wrapped_data_attr) {
        printf("%s:%d No wrapped data attribute found\n", __func__, __LINE__);
        return false;
    }

    // Attempt to unwrap the wrapped data with generated k1 (from sent keys)
    auto [wrapped_data, wrapped_len] = ec_util::unwrap_wrapped_attrib(wrapped_data_attr, frame, false, m_eph_ctx.k1); 
    if (wrapped_data == NULL || wrapped_len == 0) {
        printf("%s:%d failed to unwrap wrapped data\n", __func__, __LINE__);
        // "Abondon the exchange"
        return false;
    }

    ec_attribute_t *init_caps_attr = ec_util::get_attrib(wrapped_data, wrapped_len, ec_attrib_id_init_caps);
    if (!init_caps_attr) {
        printf("%s:%d No initiator capabilities attribute found\n", __func__, __LINE__);
        return false;
    }
    ec_dpp_capabilities_t init_caps = {
        .byte = init_caps_attr->data[0]
    };

    if (!check_supports_init_caps(init_caps)) {
        printf("%s:%d Initiator capabilities not supported\n", __func__, __LINE__);

        auto [resp_frame, resp_len] = create_auth_response(DPP_STATUS_NOT_COMPATIBLE);
        if (resp_frame == NULL || resp_len == 0) {
            printf("%s:%d failed to create response frame\n", __func__, __LINE__);
            return false;
        }
/*
it shall respond with a DPP Authentication
Response frame indicating failure by adding the DPP Status field set to STATUS_NOT_COMPATIBLE, a hash of its
public bootstrapping key, a hash of the Initiator’s public bootstrapping key if it is doing mutual authentication, Protocol
Version attribute if it was sent in the DPP Authentication Request frame and is version 2 or higher, and Wrapped Data
element consisting of the Initiator’s nonce and the Responder’s desired capabilities wrapped with k1:
*/
        return false;
    }

    //TODO/NOTE: Unknown: If need more time to process, respond `STATUS_RESPONSE_PENDING` (EasyConnect 6.3.3)
    // If the Responder needs more time to respond, e.g., to complete bootstrapping of the Initiator’s bootstrapping key

    //The Responder first selects capabilities that support the Initiator—for example,
    //  if the Initiator states it is a Configurator, then the Responder takes on the Enrollee role.
    auto [resp_frame, resp_len] = create_auth_response(DPP_STATUS_OK);
    if (resp_frame == NULL || resp_len == 0) {
        printf("%s:%d failed to create response frame\n", __func__, __LINE__);
        return false;
    }
    // TODO: Send the response frame
}

bool ec_enrollee_t::handle_auth_confirm(uint8_t *buff, unsigned int len)
{

    const auto [frame, frame_len] = create_config_request();
    if (frame == nullptr || frame_len == 0) {
        printf("%s:%d: Could not create DPP Configuration Request!\n", __func__, __LINE__);
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

bool ec_enrollee_t::check_supports_init_caps(ec_dpp_capabilities_t caps)
{
    // Currently just returning true for all capabilities
    return true;
}

std::pair<uint8_t *, uint16_t> ec_enrollee_t::create_presence_announcement()
{
    printf("%s:%d Enter\n", __func__, __LINE__);

    ec_frame_t *frame =  ec_util::alloc_frame(ec_frame_type_presence_announcement);
    if (frame == NULL) {
        printf("%s:%d failed to allocate memory for frame\n", __func__, __LINE__);
        return std::make_pair<uint8_t*, uint16_t>(NULL, 0);
    }

    // Compute the hash of the responder boot key 
    uint8_t *resp_boot_key_chirp_hash = ec_crypto::compute_key_hash(m_boot_data.responder_boot_key, "chirp");
    if (resp_boot_key_chirp_hash == NULL) {
        printf("%s:%d unable to compute \"chirp\" responder bootstrapping key hash\n", __func__, __LINE__);
        return std::pair<uint8_t *, uint16_t>(NULL, 0);
    }

    uint8_t* attribs = NULL;
    uint16_t attrib_len = 0;

    attribs = ec_util::add_attrib(attribs, &attrib_len, ec_attrib_id_resp_bootstrap_key_hash, SHA256_DIGEST_LENGTH, resp_boot_key_chirp_hash);
    free(resp_boot_key_chirp_hash);

    if (!(frame = ec_util::copy_attrs_to_frame(frame, attribs, attrib_len))) {
        printf("%s:%d unable to copy attributes to frame\n", __func__, __LINE__);
        free(attribs);
        return std::make_pair<uint8_t*, uint16_t>(NULL, 0);
    }
    free(attribs);

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
    // EasyConnect 6.4.2 DPP Configuration Request
    // Regardless of whether the Initiator or Responder took the role of Configurator, the DPP Configuration protocol is always
    // initiated by the Enrollee. To start, the Enrollee generates one or more DPP Configuration Request objects (see section
    // 4.4) and generates a new nonce, E-nonce, whose length is determined according to Table 4. When the Configurator has
    // not indicated support for protocol version number 2 or higher, no more than one DPP Configuration Request object shall
    // be included. The E-nonce attribute and the DPP Configuration Request object attribute(s) are wrapped with ke. The
    // wrapped attributes are then placed in a DPP Configuration Request frame, and sent to the Configurator.
    // Enrollee → Configurator: { E-nonce, configRequest }ke

    if ((m_eph_ctx.e_nonce = (uint8_t *)malloc(m_p_ctx.nonce_len)) == NULL) {
        printf("%s:%d: Could not malloc for E-nonce!\n", __func__, __LINE__);
        return {};
    }
    if (RAND_bytes(m_eph_ctx.e_nonce, m_p_ctx.nonce_len) != 1) {
        printf("%s:%d: Could not generate E-nonce!\n", __func__, __LINE__);
        return {};
    }
    cJSON *config_obj = nullptr;
    size_t config_obj_len = 0UL;

    // XXX: EasyMesh R >= 5 mandates all entities to support _at least_ DPP version 2, but this check is here to align with EasyConnect spec
    if (m_boot_data.version >= 2) {
        // XXX: multiple request objects
    } else {
        // XXX: single request object
        config_obj = gen_config_obj();
    }

    if (!config_obj) {
        printf("%s:%d: Failed to create DPP Configuration Request object(s)!\n", __func__, __LINE__);
        return {};
    }

    // XXX: Dialog token can be thought of as a session key between Enrollee and Configurator regarding configuration
    // From specs (EasyMesh, EasyConnect, 802.11), it seems this is just arbitrarily chosen (1 byte), but
    // must be unique per GAS frame "session" exchange.
    // See: 802.11-2020 9.4.1.12 Dialog Token field
    int dialog_token = 1;
    auto [frame, frame_len] = ec_util::alloc_gas_frame(dpp_gas_initial_req, dialog_token);
    if (frame == nullptr || frame_len == 0) {
        printf("%s:%d: Could not create DPP Configuration Request GAS frame!\n", __func__, __LINE__);
        return {};
    }
    {
        // cJSON doesn't provide an API for getting length of an obj, so we gotta do this
        char *s = cJSON_Print(config_obj);
        if (s) {
            config_obj_len = strlen(s);
            cJSON_Delete(s);
        }
    }
    ec_gas_initial_request_frame_t *initial_req_frame = (ec_gas_initial_request_frame_t *)frame;
    memcpy(initial_req_frame->query, (void *)config_obj, config_obj_len);
    initial_req_frame->query_len = (sizeof(ec_gas_initial_request_frame_t) + config_obj_len);
    // XXX: TODO: Wrap with ke, requires refactor of ec_util::add_wrapped_data_attr since it currently takes an ec_frame *

    return std::pair<uint8_t *, uint16_t>();
}

std::pair<uint8_t *, uint16_t> ec_enrollee_t::create_config_result()
{
    return std::pair<uint8_t *, uint16_t>();
}
