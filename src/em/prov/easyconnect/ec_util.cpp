#include <ctype.h>
#include <functional>
#include <arpa/inet.h>
#include <cstddef>
#include <fstream>
#include <sstream>

#include "ec_util.h"
#include "util.h"
#include "aes_siv.h"
#include "em_crypto.h"
#include "dm_easy_mesh.h"
#include "cjson_util.h"

void ec_util::init_frame(ec_frame_t *frame)
{
    memset(frame, 0, sizeof(ec_frame_t));
    frame->category = 0x04;
    frame->action = 0x09;
    frame->oui[0] = 0x50;
    frame->oui[1] = 0x6f;
    frame->oui[2] = 0x9a;
    frame->oui_type = DPP_OUI_TYPE;
    frame->crypto_suite = 0x01; // Section 3.3 (Currently only 0x01 is defined)
}

std::optional<const ec_attribute_t> ec_util::get_attrib(uint8_t *buff, size_t len, ec_attrib_id_t id)
{
    if (buff == NULL || len == 0) {
        fprintf(stderr, "Invalid input\n");
        return std::nullopt;
    }
    size_t total_len = 0;
    ec_net_attribute_t *attrib = reinterpret_cast<ec_net_attribute_t *>(buff);

    while (total_len < len) {
        const uint16_t curr_id = SWAP_LITTLE_ENDIAN(attrib->attr_id);
        const uint16_t curr_data_len = SWAP_LITTLE_ENDIAN(attrib->length);
        const size_t attr_len = get_ec_attr_size(curr_data_len);
        if (curr_id == id) {
            // Create a copy of the found attrib, but with host byte ordering
            ec_attribute_t host_attr = {
                .attr_id = curr_id,
                .length = curr_data_len,
                .original = attrib,
                .data = attrib->data
            };
            return host_attr;
        }

        total_len += attr_len;
        attrib = reinterpret_cast<ec_net_attribute_t *>(reinterpret_cast<uint8_t*>(attrib) + attr_len);
    }

    return std::nullopt;
}


uint8_t* ec_util::add_attrib(uint8_t *buff, size_t* buff_len, ec_attrib_id_t id, uint16_t len, uint8_t *data)
{
    if (data == NULL || len == 0) {
        fprintf(stderr, "Invalid input\n");
        return NULL;
    }

    
    // Add extra space for the new attribute
    size_t new_len = *buff_len + get_ec_attr_size(len);
    uint8_t* base_ptr = buff;
    // If the buffer is NULL, `realloc` will allocate a new buffer
    if ((base_ptr = reinterpret_cast<uint8_t*>(realloc(base_ptr, new_len))) == NULL) {
        fprintf(stderr, "Failed to realloc\n");
        return NULL;
    }

    // Get the start of the new section based on the re-allocated pointer
    uint8_t* tmp = base_ptr + *buff_len;

    memset(tmp, 0, get_ec_attr_size(len));
    ec_net_attribute_t *attr = reinterpret_cast<ec_net_attribute_t *>(tmp);
    // EC attribute id and length are little endian according to the spec (8.1)
    attr->attr_id = SWAP_LITTLE_ENDIAN(id);
    attr->length = SWAP_LITTLE_ENDIAN(len);
    memcpy(attr->data, data, len);

    *buff_len += get_ec_attr_size(len);
    // Return the start of the next attribute in the buffer
    return base_ptr;
}

uint16_t ec_util::freq_to_channel_attr(unsigned int freq)
{
    auto op_chan = util::em_freq_to_chan(freq);

    auto [op_class, channel] = op_chan;
    
    return static_cast<uint16_t>((channel << 8) | (0x00ff & op_class));
}

bool ec_util::validate_frame(const ec_frame_t *frame)
{
    if ((frame->category != 0x04) 
            || (frame->action != 0x09)
            || (frame->oui[0] != 0x50)
            || (frame->oui[1] != 0x6f)
            || (frame->oui[2] != 0x9a)
            || (frame->oui_type != DPP_OUI_TYPE)
            || (frame->crypto_suite != 0x01) ) {
        return false;
    }

    return true;
}

uint8_t *ec_util::add_wrapped_data_attr(ec_frame_t *frame, uint8_t *frame_attribs, size_t *non_wrapped_len, bool use_aad, uint8_t *key, std::function<std::pair<uint8_t *, uint16_t>()> create_wrap_attribs)
{
    return add_wrapped_data_attr(reinterpret_cast<uint8_t*>(frame), sizeof(ec_frame_t), frame_attribs, non_wrapped_len, use_aad, key, create_wrap_attribs);
}

uint8_t *ec_util::add_wrapped_data_attr(ec_gas_initial_request_frame_t *frame, uint8_t *frame_attribs, size_t *non_wrapped_len, bool use_aad, uint8_t *key, std::function<std::pair<uint8_t *, uint16_t>()> create_wrap_attribs)
{
    return add_wrapped_data_attr(reinterpret_cast<uint8_t*>(frame), sizeof(ec_gas_initial_request_frame_t), frame_attribs, non_wrapped_len, use_aad, key, create_wrap_attribs);
}

uint8_t *ec_util::add_wrapped_data_attr(ec_gas_initial_response_frame_t *frame, uint8_t *frame_attribs, size_t *non_wrapped_len, bool use_aad, uint8_t *key, std::function<std::pair<uint8_t *, uint16_t>()> create_wrap_attribs)
{
    return add_wrapped_data_attr(reinterpret_cast<uint8_t*>(frame), sizeof(ec_gas_initial_response_frame_t), frame_attribs, non_wrapped_len, use_aad, key, create_wrap_attribs);
}

uint8_t *ec_util::add_wrapped_data_attr(uint8_t *frame, size_t frame_len, uint8_t *frame_attribs, size_t *non_wrapped_len,
                                        bool use_aad, uint8_t *key, std::function<std::pair<uint8_t *, uint16_t>()> create_wrap_attribs)
{

    ASSERT_NOT_NULL(non_wrapped_len, NULL, "Non-wrapped length cannot be NULL\n");

    siv_ctx ctx;

    // NOTE: HARDCODING AS SIV_256 FOR NOW
    //  The spec technically only specifies P-256 so technically this is all that's allowed but for future proofing it's better to add more 
    //  I just want to avoid adding the digest_len as a parameter...
    siv_init(&ctx, key, SIV_256);

    /*
    Initialize AES-SIV context
    switch(m_params.digestlen) {
        case SHA256_DIGEST_LENGTH:
            siv_init(&ctx, key, SIV_256);
            break;
        case SHA384_DIGEST_LENGTH:
            siv_init(&ctx, key, SIV_384);
            break;
        case SHA512_DIGEST_LENGTH:
            siv_init(&ctx, key, SIV_512);
            break;
        default:
            em_printfout("Unknown digest length");
            return {nullptr, 0};
    }
    */

    // Use the provided function to create wrap_attribs and wrapped_len
    auto [wrap_attribs, wrapped_len] = create_wrap_attribs();

    // Encapsulate the attributes in a wrapped data attribute
    uint16_t wrapped_attrib_len = wrapped_len + AES_BLOCK_SIZE;
    ec_net_attribute_t *wrapped_attrib = static_cast<ec_net_attribute_t *>(calloc(sizeof(ec_net_attribute_t) + wrapped_attrib_len, 1));
    ASSERT_NOT_NULL_FREE(wrapped_attrib, NULL, wrap_attribs, "Failed to allocate wrapped attribute\n");
    // EC attribute id and length are little endian according to the spec (8.1)
    wrapped_attrib->attr_id = SWAP_LITTLE_ENDIAN(ec_attrib_id_wrapped_data);
    wrapped_attrib->length = SWAP_LITTLE_ENDIAN(wrapped_attrib_len);
    memset(wrapped_attrib->data, 0, wrapped_attrib_len);

    /**
    * Encrypt attributes using SIV mode with two additional authenticated data (AAD) inputs:
    * 1. The frame structure and 2. Non-wrapped attributes (per EasyMesh 6.3.1.4)
    * The synthetic IV/tag is stored in the first AES_BLOCK_SIZE bytes of wrapped_attrib->data
    */
   int siv_result = 0;
   if (use_aad) {

        ASSERT_NOT_NULL_FREE2(frame_attribs, NULL, wrapped_attrib, wrap_attribs, "Frame attributes cannot be NULL for AAD encryption\n");
        ASSERT_NOT_NULL_FREE2(frame, NULL, wrapped_attrib, wrap_attribs, "Frame cannot be NULL for AAD encryption\n");
        
        siv_result = siv_encrypt(&ctx, wrap_attribs, &wrapped_attrib->data[AES_BLOCK_SIZE], wrapped_len, wrapped_attrib->data, 2,
            frame, frame_len,
            frame_attribs, *non_wrapped_len);
    } else {
        siv_result = siv_encrypt(&ctx, wrap_attribs, &wrapped_attrib->data[AES_BLOCK_SIZE], wrapped_len, wrapped_attrib->data, 0);
    }
    if (siv_result < 0) {
        em_printfout("Failed to encrypt and authenticate wrapped data");
        free(wrap_attribs);
        free(wrapped_attrib);
        return NULL;
    }

    // Add the wrapped data attribute to the frame
    uint8_t* ret_frame_attribs = ec_util::add_attrib(frame_attribs, non_wrapped_len, ec_attrib_id_wrapped_data, wrapped_attrib_len, wrapped_attrib->data);

    free(wrapped_attrib);
    free(wrap_attribs);

    return ret_frame_attribs;
}

std::pair<uint8_t*, uint16_t> ec_util::unwrap_wrapped_attrib(const ec_attribute_t& wrapped_attrib, ec_frame_t *frame, bool uses_aad, uint8_t* key)
{
    return unwrap_wrapped_attrib(wrapped_attrib, reinterpret_cast<uint8_t*>(frame), sizeof(ec_frame_t), frame->attributes, uses_aad, key);
}

std::pair<uint8_t*, uint16_t> ec_util::unwrap_wrapped_attrib(const ec_attribute_t& wrapped_attrib, uint8_t *frame, size_t frame_len, uint8_t *frame_attribs, bool uses_aad, uint8_t *key)
{
    siv_ctx ctx;

    // NOTE: HARDCODING AS SIV_256 FOR NOW
    //  The spec technically only specifies P-256 so technically this is all that's allowed but for future proofing it's better to add more 
    //  I just want to avoid adding the digest_len as a parameter...
    siv_init(&ctx, key, SIV_256);

    /*
    Initialize AES-SIV context
    switch(m_params.digestlen) {
        case SHA256_DIGEST_LENGTH:
            siv_init(&ctx, key, SIV_256);
            break;
        case SHA384_DIGEST_LENGTH:
            siv_init(&ctx, key, SIV_384);
            break;
        case SHA512_DIGEST_LENGTH:
            siv_init(&ctx, key, SIV_512);
            break;
        default:
            em_printfout("Unknown digest length");
            return {nullptr, 0};
    }
    */

    uint8_t* wrapped_ciphertext = wrapped_attrib.data + AES_BLOCK_SIZE;
    // wrapped_len is host byte ordered as long as wrapped_attrib was gotten by `ec_util::get_attrib`
    uint16_t wrapped_len = wrapped_attrib.length - AES_BLOCK_SIZE;

    uint8_t* unwrap_attribs = reinterpret_cast<uint8_t*>(calloc(wrapped_len, 1));
    int result = -1;
    if (uses_aad) {
        if (frame == NULL) {
            em_printfout("AAD input is NULL, AAD decryption failed!");
            return {nullptr, 0};
        }
        size_t pre_wrapped_attribs_size = static_cast<size_t>(reinterpret_cast<uint8_t*>(wrapped_attrib.original) - frame_attribs);
        result = siv_decrypt(&ctx, wrapped_ciphertext, unwrap_attribs, wrapped_len,
                             wrapped_attrib.data, 2,
                             frame, frame_len,
                             frame_attribs, pre_wrapped_attribs_size);
    } else {
        result = siv_decrypt(&ctx, wrapped_ciphertext, unwrap_attribs, wrapped_len,
                             wrapped_attrib.data, 0);
    }

    if (result < 0) {
        em_printfout("Failed to decrypt and authenticate wrapped data");
        free(unwrap_attribs);
        return {nullptr, 0};
    }

    return {unwrap_attribs, wrapped_len};
}

bool ec_util::parse_dpp_chirp_tlv(em_dpp_chirp_value_t* chirp_tlv, uint16_t chirp_tlv_len, mac_addr_t *mac, uint8_t **hash, uint16_t *hash_len)
{
    if (chirp_tlv == NULL || chirp_tlv_len == 0) {
        fprintf(stderr, "Invalid input\n");
        return false;
    }

    uint16_t data_len = chirp_tlv_len - static_cast<uint16_t>(sizeof(em_dpp_chirp_value_t));
    // Parse TLV
    bool mac_addr_present = chirp_tlv->mac_present;
    bool hash_valid = chirp_tlv->hash_valid;

    uint8_t *data_ptr = chirp_tlv->data;
    if (mac_addr_present && data_len >= ETH_ALEN) {
        memcpy(*mac, data_ptr, ETH_ALEN);
        data_ptr += ETH_ALEN;
        data_len -= ETH_ALEN;
    }

    if (!hash_valid || data_len <= 0) {
        // Clear (Re)configuration state, agent side
        return true;
    }

    *hash_len = util::deref_net_uint16_to_host(data_ptr);
    data_ptr += sizeof(uint16_t);
    data_len -= static_cast<uint16_t>(sizeof(uint16_t));
    if (*hash_len == 0) {
        *hash = NULL;
        fprintf(stderr, "%s:%d: Invalid chirp tlv, hash length is 0 when hash_valid flag is set\n", __func__, __LINE__);
        return false;
    }

    if (data_len < *hash_len) {
        fprintf(stderr, "%s:%d: Invalid chirp tlv, %d bytes of data remaining, %d bytes of hash requested\n", __func__, __LINE__, data_len, *hash_len);
        fprintf(stderr, "%s:%d: %d < %d\n", __func__, __LINE__, data_len, *hash_len);
        return false;
    }
    if (*hash_len > 0) {
        *hash = reinterpret_cast<uint8_t*>(calloc(*hash_len, 1));
        if (*hash == NULL) {
            fprintf(stderr, "Failed to allocate memory\n");
            return false;
        }
        memcpy(*hash, data_ptr, *hash_len);
    } else {
        *hash = NULL;
    }

    return true;
}

std::pair<em_dpp_chirp_value_t*, uint16_t> ec_util::create_dpp_chirp_tlv(bool mac_present, bool hash_validity, mac_addr_t dest_mac, uint8_t* hash, uint16_t hash_len)
{
    if (dest_mac == NULL && mac_present) {
        em_printfout("mac_present argument is true, but dest_mac was not provided");
        return {};
    }

    size_t full_tlv_size = sizeof(em_dpp_chirp_value_t);
    if (dest_mac != NULL) full_tlv_size += sizeof(mac_addr_t);
    if (hash_validity) full_tlv_size += (sizeof(uint16_t) + hash_len);
    if (hash_validity && !hash) {
        fprintf(stderr, "Hash is NULL but hash_validity is true\n");
        return {};
    }
    em_dpp_chirp_value_t *chirp_tlv = NULL;
    if ((chirp_tlv = static_cast<em_dpp_chirp_value_t *>(calloc(full_tlv_size, 1))) == NULL){
        fprintf(stderr, "Failed to allocate memory\n");
        return {};
    }

    (chirp_tlv)->mac_present = mac_present;
    (chirp_tlv)->hash_valid = hash_validity;

    uint8_t *data_ptr = (chirp_tlv)->data;
    if (mac_present) {
        memcpy(data_ptr, dest_mac, sizeof(mac_addr_t));
        data_ptr += sizeof(mac_addr_t);
    }
    if (hash_validity) {
        util::set_net_uint16_from_host(hash_len, data_ptr);
        data_ptr += sizeof(uint16_t); 
    }
    if (hash_len > 0 && hash_validity) {
        memcpy(data_ptr, hash, hash_len);
        data_ptr += hash_len;
    }

    return std::pair<em_dpp_chirp_value_t*, uint16_t>(chirp_tlv, static_cast<uint16_t>(full_tlv_size));
}

bool ec_util::parse_encap_dpp_tlv(em_encap_dpp_t *encap_tlv, uint16_t encap_tlv_len, mac_addr_t *dest_mac, uint8_t *frame_type, uint8_t **encap_frame, uint16_t *encap_frame_len)
{
    if (encap_tlv == NULL || encap_tlv_len == 0) {
        fprintf(stderr, "Invalid input\n");
        return false;
    }

    uint16_t data_len = encap_tlv_len - static_cast<uint16_t>(sizeof(em_encap_dpp_t));
    // Parse TLV
    bool mac_addr_present = encap_tlv->enrollee_mac_addr_present;

    // Copy mac address if present
    uint8_t *data_ptr = encap_tlv->data;
    if (mac_addr_present && data_len >= sizeof(mac_addr_t)) {
        memcpy(*dest_mac, data_ptr, sizeof(mac_addr_t));
        data_ptr += sizeof(mac_addr_t);
        data_len = static_cast<uint16_t>(data_len - sizeof(mac_addr_t));
    } else {
        memset(*dest_mac, 0, sizeof(mac_addr_t));
    }

    if (data_len < sizeof(uint8_t) + sizeof(uint16_t)) {
        fprintf(stderr, "Invalid encap tlv\n");
        return false;
    }

    // Get frame type
    *frame_type = *data_ptr;
    data_ptr++;

    // Get frame length - Fix for alignment issue
    *encap_frame_len = util::deref_net_uint16_to_host(data_ptr);
    data_ptr += sizeof(uint16_t);

    if (data_len < *encap_frame_len) {
        fprintf(stderr, "Invalid encap tlv\n");
        return false;
    }

    // Copy frame
    *encap_frame = reinterpret_cast<uint8_t*>(calloc(*encap_frame_len, 1));
    ASSERT_NOT_NULL(*encap_frame, false, "Failed to allocate memory\n");
    memcpy(*encap_frame, data_ptr, *encap_frame_len);

    return true;
}

std::pair<em_encap_dpp_t*, uint16_t> ec_util::create_encap_dpp_tlv(bool dpp_frame_indicator, mac_addr_t dest_mac, ec_frame_type_t frame_type, uint8_t *encap_frame, size_t encap_frame_len)
{
    size_t data_size = sizeof(em_encap_dpp_t) + sizeof(uint8_t) + sizeof(uint16_t) + encap_frame_len;
    if (dest_mac != NULL) {
        data_size += sizeof(mac_addr_t);
    }
    em_encap_dpp_t *encap_tlv = NULL;
    if (encap_frame_len > UINT16_MAX) {
        fprintf(stderr, "Encap frame too large\n");
        return {};
    }

    if ((encap_tlv = static_cast<em_encap_dpp_t *>(calloc(data_size, 1))) == NULL){
        fprintf(stderr, "Failed to allocate memory\n");
        return {};
    }
    (encap_tlv)->dpp_frame_indicator = dpp_frame_indicator;
    (encap_tlv)->enrollee_mac_addr_present = (dest_mac != NULL) ? 1 : 0;

    uint8_t *data_ptr = (encap_tlv)->data;
    if (dest_mac != NULL) {
        memcpy(data_ptr, dest_mac, sizeof(mac_addr_t));
        data_ptr += sizeof(mac_addr_t);
    }

    *data_ptr = frame_type;
    data_ptr++;

    util::set_net_uint16_from_host(static_cast<uint16_t>(encap_frame_len), data_ptr);
    data_ptr += sizeof(uint16_t);

    memcpy(data_ptr, encap_frame, encap_frame_len);

    return std::pair<em_encap_dpp_t*, uint16_t>(encap_tlv, static_cast<uint16_t>(data_size));
}

ec_frame_t *ec_util::copy_attrs_to_frame(ec_frame_t *frame, uint8_t *attrs, size_t attrs_len)
{
    return reinterpret_cast<ec_frame_t*>(copy_attrs_to_frame(
        reinterpret_cast<uint8_t*>(frame), sizeof(ec_frame_t), attrs, attrs_len
    ));
}

ec_gas_initial_request_frame_t *ec_util::copy_attrs_to_frame(ec_gas_initial_request_frame_t *frame, uint8_t *attrs, size_t attrs_len)
{
    return reinterpret_cast<ec_gas_initial_request_frame_t*>(copy_attrs_to_frame(
        reinterpret_cast<uint8_t*>(frame), sizeof(ec_gas_initial_request_frame_t), attrs, attrs_len
    ));
}

ec_gas_initial_response_frame_t *ec_util::copy_attrs_to_frame(ec_gas_initial_response_frame_t *frame, uint8_t *attrs, size_t attrs_len)
{
    return reinterpret_cast<ec_gas_initial_response_frame_t*>(copy_attrs_to_frame(
        reinterpret_cast<uint8_t*>(frame), sizeof(ec_gas_initial_response_frame_t), attrs, attrs_len
    ));
}

uint8_t *ec_util::copy_attrs_to_frame(uint8_t *frame, size_t frame_base_size, uint8_t *attrs, size_t attrs_len)
{
    size_t new_len = frame_base_size + attrs_len;
    uint8_t *new_frame = reinterpret_cast<uint8_t *>(realloc(frame, new_len));
    if (new_frame == nullptr) {
        em_printfout("unable to realloc");
        return nullptr;
    }

    memcpy(new_frame + frame_base_size, attrs, attrs_len);
    return new_frame;
}

uint8_t *ec_util::copy_payload_to_gas_resp(uint8_t *frame, size_t frame_base_size, uint8_t *payload, size_t payload_len)
{
    size_t new_len = frame_base_size + payload_len;
    uint8_t *new_frame = reinterpret_cast<uint8_t*>(realloc(frame, new_len));
    if (new_frame == nullptr) {
        em_printfout("Unable to realloc");
        return nullptr;
    }

    memcpy(new_frame + frame_base_size, payload, payload_len);
    return new_frame;
}

ec_gas_initial_response_frame_t *ec_util::copy_payload_to_gas_resp(ec_gas_initial_response_frame_t *frame, uint8_t *payload, size_t payload_len)
{
    return reinterpret_cast<ec_gas_initial_response_frame_t *>(copy_payload_to_gas_resp(
        reinterpret_cast<uint8_t*>(frame), sizeof(ec_gas_initial_response_frame_t), payload, payload_len
    ));
}

ec_gas_comeback_response_frame_t *ec_util::copy_payload_to_gas_resp(ec_gas_comeback_response_frame_t *frame, uint8_t *payload, size_t payload_len)
{
    return reinterpret_cast<ec_gas_comeback_response_frame_t*>(copy_payload_to_gas_resp(
        reinterpret_cast<uint8_t*>(frame), sizeof(ec_gas_comeback_response_frame_t), payload, payload_len
    ));
}

std::string ec_util::generate_channel_list(const std::string& ssid, std::unordered_map<std::string, std::vector<scanned_channels_t>> scanned_channels_map)
{
    // channelList ABNF:
    // channel-list2 = class-and-channels *(“,” class-and-channels)
    // class-and-channels = class “/” channel *(“,” channel)
    // class = 1*3DIGIT
    // channel = 1*3DIGIT
    auto it = scanned_channels_map.find(ssid);
    if (it == scanned_channels_map.end()) return std::string();

    const std::vector<scanned_channels_t> &scanned_channels = it->second;
    std::map<uint32_t, std::vector<uint32_t>> grouped_channels;

    for (const auto &entry : scanned_channels) {
        grouped_channels[entry.opclass].push_back(entry.chan);
    }

    std::string channel_list;
    bool first_group = true;

    for (const auto &[opclass, channels] : grouped_channels) {
        if (!first_group)
            channel_list += ",";
        first_group = false;

        channel_list += std::to_string(opclass) + "/";

        for (size_t i = 0; i < channels.size(); i++) {
            if (i > 0)
                channel_list += ",";
            channel_list += std::to_string(channels[i]);
        }
    }
    return channel_list;
}


bool ec_util::check_caps_compatible(const ec_dpp_capabilities_t& init_caps, const ec_dpp_capabilities_t& resp_caps)
{

/*
 EasyConnect 6.3.1.5
+--------------------------+-------------------------+------------------------+
|        Initiator         |        Responder        |       DPP Status       |
+--------------------------+-------------------------+------------------------+
| Configurator             | Configurator            | STATUS_NOT_COMPATIBLE  |
| Configurator             | Enrollee                | STATUS_OK              |
| Enrollee                 | Configurator            | STATUS_OK              |
| Enrollee                 | Enrollee                | STATUS_NOT_COMPATIBLE  |
| Configurator or Enrollee | Configurator            | STATUS_OK              |
| Configurator or Enrollee | Enrollee                | STATUS_OK              |
+--------------------------+-------------------------+------------------------+
*/
    bool resp_cfg_enrollee = resp_caps.configurator && resp_caps.enrollee;

    // The responder cannot be both (but the initiator can)
    if (resp_cfg_enrollee) {
        return false;
    }

    if (init_caps.enrollee && resp_caps.enrollee) {
        return false;
    }
    if (init_caps.configurator && resp_caps.configurator) {
        return false;
    }
    return true;
}

std::map<dpp_uri_field, std::string> ec_util::encode_bootstrap_data(ec_data_t *boot_data)
{
    std::map<dpp_uri_field, std::string> uri_map;

    char mac_str[EM_MAC_STR_LEN + 1] = {0};

    for (size_t idx = 0; idx < dpp_uri_field::DPP_URI_MAX; idx++) {
        dpp_uri_field field = static_cast<dpp_uri_field>(idx);
        std::string value;
        switch (field) {
        case DPP_URI_VERSION:
            value = std::to_string(boot_data->version);
            break;
        case DPP_URI_MAC: {
            dm_easy_mesh_t::macbytes_to_string(boot_data->mac_addr, mac_str);
            value = std::string(mac_str);
            break;
        }
        case DPP_URI_CHANNEL_LIST:
            for (size_t i = 0; i < DPP_MAX_EN_CHANNELS; i++) {
                unsigned int freq = boot_data->ec_freqs[i];
                if (freq == 0) continue;

                auto [op_class, channel] = util::em_freq_to_chan(freq);
                value += std::to_string(static_cast<int>(op_class)) + "/" +
                         std::to_string(static_cast<int>(channel));
                value += ",";
            }
            //Remove the last comma
            if (!value.empty()) {
                value.pop_back();
            }
            break;
        case DPP_URI_PUBLIC_KEY:
            value = em_crypto_t::ec_key_to_base64_der(boot_data->responder_boot_key);
            break;
        case DPP_URI_INFORMATION:
            break;
        case DPP_URI_HOST:
            break;
        case DPP_URI_SUPPORTED_CURVES:
            break;
        case DPP_URI_MAX: // This should never happen
            break;
            // Leaving off default so that compile error will be thrown if new field is added and not handled
        }
        if (!value.empty()) {
            uri_map[field] = value;
        }
    }

    return uri_map;
}

std::optional<std::string> ec_util::encode_bootstrap_data_uri(ec_data_t *boot_data)
{
    auto uri_map = ec_util::encode_bootstrap_data(boot_data);
    std::string uri = "DPP:";
    for (const auto &[uri_type, value] : uri_map) {
        auto field_char = get_dpp_uri_field_char(uri_type);
        if (!field_char) {
            printf("Found unknown DPP URI field but not encoding\n");
            return {};
        }
        uri += (*field_char + ":" + value + ";");
    }
    // Only need to add one semi colon instead of two since there is already a trailing semicolon
    uri += ";";
    return uri;
}

std::optional<std::string> ec_util::encode_bootstrap_data_json(ec_data_t *boot_data)
{
    auto uri_map = ec_util::encode_bootstrap_data(boot_data);

    cJSON *json = cJSON_CreateObject();
    ASSERT_NOT_NULL(json, {}, "Failed to create JSON object\n");

    cJSON* uri_obj = cJSON_AddObjectToObject(json, "URI");

    for (const auto &[uri_type, value] : uri_map) {
        auto field_char = get_dpp_uri_field_char(uri_type);
        if (!field_char) {
            printf("Found unknown DPP URI field but not encoding\n");
            cJSON_Delete(json);
            return {};
        }
        switch (uri_type) {
        case DPP_URI_VERSION:
            cJSON_AddNumberToObject(uri_obj, "V", std::stoi(value));
            break;
        case DPP_URI_MAC:
        case DPP_URI_CHANNEL_LIST:
        case DPP_URI_PUBLIC_KEY:
        case DPP_URI_INFORMATION:
        case DPP_URI_HOST:
        case DPP_URI_SUPPORTED_CURVES:
            cJSON_AddStringToObject(uri_obj, field_char->c_str(), value.c_str());
            break;
        case DPP_URI_MAX: // This should never happen
            printf("Found max DPP URI field but not encoding\n");
            cJSON_Delete(json);
            return {};
            // Leaving off default so that compile error will be thrown if new field is added and not handled
        }
    }
    return cjson_utils::stringify(json);
}

bool ec_util::decode_bootstrap_data(std::map<dpp_uri_field, std::string> uri_map,
                                    ec_data_t *boot_data, std::string country_code)
{
    for (const auto &[uri_type, value] : uri_map) {
        switch (uri_type) {
        case DPP_URI_VERSION: {
            auto version = strtol(value.c_str(), nullptr, 10);
            ASSERT_MSG_TRUE(version > 0 && version != LONG_MAX, false,
                            "%s:%d: Version is not valid\n", __func__, __LINE__);
            boot_data->version = static_cast<unsigned int>(version);
            break;
        }
        case DPP_URI_MAC: {
            ASSERT_MSG_TRUE(value.length() == EM_MAC_STR_LEN, false,
                            "%s:%d: MAC address is not valid\n", __func__, __LINE__);
            dm_easy_mesh_t::string_to_macbytes(const_cast<char *>(value.c_str()),
                                               boot_data->mac_addr);
            ASSERT_MSG_TRUE(memcmp(boot_data->mac_addr, ZERO_MAC_ADDR, ETH_ALEN) != 0, false,
                            "%s:%d: MAC address is zero\n", __func__, __LINE__);
            break;
        }
        case DPP_URI_CHANNEL_LIST: {
            auto class_channel_pairs = ec_util::parse_dpp_uri_channel_list(value);
            ASSERT_MSG_FALSE(class_channel_pairs.empty(), false,
                             "%s:%d: Failed to parse channel list\n", __func__, __LINE__);
            for (size_t idx = 0; idx < class_channel_pairs.size(); idx++) {
                auto [op_class, channel] = class_channel_pairs[idx];
                int freq = util::em_chan_to_freq(static_cast<uint8_t>(op_class),
                                                 static_cast<uint8_t>(channel), country_code);
                if (freq <= 0) {
                    printf("Failed to convert channel to frequency (op class: %d, channel: %d)\n",
                           op_class, channel);
                    continue;
                }
                boot_data->ec_freqs[idx] = static_cast<unsigned int>(freq);
            }
            break;
        }
        case DPP_URI_PUBLIC_KEY: {
            // Enrollee (Responder) is the one who sent the URI so that is the owner of the public key
            boot_data->responder_boot_key = em_crypto_t::ec_key_from_base64_der(value);
            ASSERT_NOT_NULL(boot_data->responder_boot_key, false,
                            "%s:%d: Failed to create EC_KEY from public key\n", __func__, __LINE__);
            break;
        }
        case DPP_URI_INFORMATION: {
            printf("Found information DPP URI field but not parsing\n");
            // Information is not used in the current implementation
            break;
        }
        case DPP_URI_HOST: {
            printf("Found host DPP URI field but not parsing\n");
            // Host is not used in the current implementation
            break;
        }
        case DPP_URI_SUPPORTED_CURVES: {
            printf("Found supported curves DPP URI field but not parsing\n");
            // Supported curves is not used in the current implementation
            break;
        }
        case DPP_URI_MAX: // This should never happen
            printf("Found max DPP URI field but not parsing\n");
            break;
            // Leaving off default so that compile error will be thrown if new field is added and not handled
        }
    }
    return true;
}

bool ec_util::decode_bootstrap_data_uri(const std::string &uri, ec_data_t *boot_data,
                                        std::string country_code)
{
    // Example input: DPP:V:2;C:81/1,115/36;K:MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADM2206avxHJaHXgLMkq/24e0rsrfMP9K1Tm8gx+ovP0I=;;
    ASSERT_MSG_FALSE(uri.empty(), false, "%s:%d: URI is empty\n", __func__, __LINE__);
    ASSERT_MSG_TRUE(uri.find("DPP:") == 0, false, "%s:%d: URI does not start with 'DPP:'\n",
                    __func__, __LINE__);
    // Check if the string ends with ;;
    ASSERT_MSG_TRUE(uri.find(";;") == uri.length() - 2, false,
                    "%s:%d: URI does not end with ';;'\n", __func__, __LINE__);
    // Remove the 'DPP:' prefix and ';;' suffix
    std::string uri_str = uri.substr(4, uri.length() - 2 - 4);
    // Split the string by ';'
    auto uri_parts = util::split_by_delim(uri_str, ';');
    ASSERT_MSG_TRUE(uri_parts.size() > 0, false, "%s:%d: URI must have at least the key present\n",
                    __func__, __LINE__);

    // Convert the vector of strings to a map between uri types and values
    std::map<dpp_uri_field, std::string> uri_map;
    for (const auto &part : uri_parts) {
        // Split the string by ':'
        auto key_value = util::split_by_delim(part, ':');
        ASSERT_MSG_TRUE(key_value.size() == 2, false, "%s:%d: URI part '%s' is not valid\n",
                        __func__, __LINE__, part.c_str());

        auto uri_type = get_dpp_uri_field(key_value[0]);
        ASSERT_MSG_TRUE(uri_type != std::nullopt, false,
                        "%s:%d: URI part '%s' is not valid. Key (%s) not valid \n", __func__,
                        __LINE__, part.c_str(), key_value[0].c_str());
        if (uri_map.find(*uri_type) != uri_map.end()) {
            em_printfout("URI part '%s' is duplicated", part.c_str());
            return false;
        }
        uri_map[*uri_type] = key_value[1];
    }

    return decode_bootstrap_data(uri_map, boot_data, country_code);
}

bool ec_util::decode_bootstrap_data_json(const cJSON *json_obj, ec_data_t *boot_data,
                                         std::string country_code)
{
    memset(boot_data, 0, sizeof(ec_data_t));

    const cJSON *object_item = NULL;

    std::map<dpp_uri_field, std::string> uri_map;

    // According to cJSON, cJSON_ArrayForEach can be used for iterating both object types and array types
    cJSON_ArrayForEach(object_item, json_obj)
    {
        char *key = object_item->string;

        auto uri_type = get_dpp_uri_field(key);
        ASSERT_MSG_TRUE(uri_type != std::nullopt, false, "%s:%d: Key (%s) not valid \n", __func__,
                        __LINE__, key);
        if (uri_map.find(*uri_type) != uri_map.end()) {
            em_printfout("Key '%s' is duplicated", key);
            return false;
        }
        if (cJSON_IsString(object_item)) {
            uri_map[*uri_type] = std::string(cJSON_GetStringValue(object_item));
        } else if (cJSON_IsNumber(object_item)) {
            uri_map[*uri_type] = std::to_string(cJSON_GetNumberValue(object_item));
        } else {
            em_printfout("Key '%s' is not a string or number", key);
            return false;
        }
    }

    return decode_bootstrap_data(uri_map, boot_data, country_code);
}

bool ec_util::read_bootstrap_data_from_files(ec_data_t *boot_data, const std::string &file_path, const std::optional<std::string> &pem_file_path)
{
    std::ifstream dpp_uri_json_fp(file_path);
    if (!dpp_uri_json_fp.is_open()) {
        printf("%s:%d: Failed to open DPP URI JSON file at path '%s'\n", __func__, __LINE__,
            file_path.c_str());
        return false;
    }

    std::stringstream json_buff;
    json_buff << dpp_uri_json_fp.rdbuf();
    std::string dpp_uri_json_str = json_buff.str();
    dpp_uri_json_fp.close();
    em_printfout("DPP URI JSON: %s", dpp_uri_json_str.c_str());

    cJSON *json = cJSON_Parse(dpp_uri_json_str.c_str());
    if (json == NULL) {
        em_printfout("Failed to parse JSON at path '%s'", file_path.c_str());
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            em_printfout("JSON parse error at %s", error_ptr);
        }
        return false;
    }

    cJSON* uri_obj = cJSON_GetObjectItemCaseSensitive(json, "URI");
    if (uri_obj == NULL) {
        printf("%s:%d: Failed to get URI object from JSON at path '%s'\n", __func__, __LINE__,
            file_path.c_str());
        cJSON_Delete(json);
        return false;
    }

    if (!ec_util::decode_bootstrap_data_json(uri_obj, boot_data)) {
        printf("%s:%d: Failed to decode DPP URI JSON at path '%s'\n", __func__, __LINE__,
            file_path.c_str());
        cJSON_Delete(json);
        return false;
    }

    cJSON_Delete(json);
    printf("%s:%d: Successfully read DPP URI JSON from path '%s'\n", __func__, __LINE__,
        file_path.c_str());

    // Read the PEM file if it is provided
    if (pem_file_path.has_value()) {
        SSL_KEY* pem_key = em_crypto_t::read_keypair_from_pem(*pem_file_path);
        if (pem_key == NULL) {
            printf("%s:%d: Failed to read PEM file at path '%s'\n", __func__, __LINE__,
                pem_file_path.value().c_str());
            return false;
        }
        // Set the responder boot key to the PEM key
        
        // Free the public key that was read from the JSON
        em_crypto_t::free_key(const_cast<SSL_KEY*>(boot_data->responder_boot_key));
        // Set the responder boot key to the PEM key
        boot_data->responder_boot_key = pem_key;
        printf("%s:%d: Successfully read PEM file from path '%s'\n", __func__, __LINE__,
            pem_file_path.value().c_str());
    }

    return true;
}

bool ec_util::write_bootstrap_data_to_files(ec_data_t *boot_data, const std::string &file_path, const std::string &pem_file_path)
{

    // Encode the DPP URI JSON
    auto json_str = encode_bootstrap_data_json(boot_data);
    if (json_str == std::nullopt) {
        em_printfout("Failed to encode DPP URI JSON");
        return false;
    }
    em_printfout("DPP URI JSON: %s", json_str->c_str());

    std::ofstream out_file(file_path);
    if (!out_file.is_open()) {
        std::error_code ec(errno, std::generic_category());
        printf("%s:%d: Failed to open DPP URI JSON file at path '%s' - %s\n", __func__, __LINE__,
               file_path.c_str(), ec.message().c_str());
        return false;
    }

    out_file << *json_str;

    if (!out_file.good()) {
        std::error_code ec(errno, std::generic_category());
        printf("%s:%d: Failed to write DPP URI JSON to file at path '%s' - %s\n", __func__,
               __LINE__, file_path.c_str(), ec.message().c_str());
        out_file.close();
        return false;
    }
    out_file.close();
    em_printfout("DPP URI JSON written to %s", file_path.c_str());

    // Write the PEM file and return
    return em_crypto_t::write_keypair_to_pem(boot_data->responder_boot_key, pem_file_path);;
}

bool ec_util::generate_dpp_boot_data(ec_data_t *boot_data, mac_addr_t al_mac,
                                     em_op_class_info_t *op_class_info)
{
    memset(boot_data, 0, sizeof(ec_data_t));
    boot_data->version = DPP_VERSION;              // DPP URI Version
    memcpy(boot_data->mac_addr, al_mac, ETH_ALEN); // AL MAC address

    boot_data->responder_boot_key = em_crypto_t::generate_ec_key(DPP_KEY_NID);
    if (boot_data->responder_boot_key == NULL) {
        em_printfout("Failed to generate EC key");
        memset(boot_data, 0, sizeof(ec_data_t));
        return false;
    }

    // Set the channel list to the op class/channel given
    if (op_class_info != NULL) {
        uint8_t op_class = static_cast<uint8_t>(op_class_info->op_class);
        uint8_t channel = static_cast<uint8_t>(op_class_info->channels[0]);
        int freq = util::em_chan_to_freq(op_class, channel, "US");
        ASSERT_MSG_TRUE(
            freq > 0, false,
            "%s:%d: Failed to convert channel to frequency (op class: %d, channel: %d)\n", __func__,
            __LINE__, op_class, channel);
        boot_data->ec_freqs[0] = static_cast<unsigned int>(freq);
    }
    return true;
}

bool ec_util::get_dpp_boot_data(ec_data_t *boot_data, mac_addr_t al_mac, bool do_recfg,
                                bool force_regen, em_op_class_info_t *op_class_info)
{

    memset(boot_data, 0, sizeof(ec_data_t));
    


    bool should_recfg = do_recfg;

    if (do_recfg) {
        if (force_regen) {
            printf("%s:%d: Force regenerating DPP bootstrapping data while reconfiguration is "
                   "requested. Reconfiguration will not occur since this is not possible with new DPP "
                   "bootstrapping data \n",
                   __func__, __LINE__);
        } else {
            should_recfg = ec_util::read_bootstrap_data_from_files(boot_data, DPP_URI_JSON_PATH, DPP_BOOT_PEM_PATH);
            if (should_recfg) {
                // Successsfully read the DPP URI JSON from the file so the parameters should be the same for reconfiguration.
                // Successfully fetched the bootstrapping data, return true.
                return true;
            } else {
                // Failed to read the DPP URI JSON from the file, so even though the user said to `do_recfg`, originally, we can't do it.
                // This is because the parameters could be different (e.g. MAC address, public key, etc.)
                // Instead, we must generate new DPP bootstrapping data and write it to the file.
                printf("%s:%d: Failed to read DPP URI JSON from file, not reconfiguring since "
                       "parameters will be different\n",
                       __func__, __LINE__);
            }
        }
    }

    if (!force_regen)  {
        bool read_successful = ec_util::read_bootstrap_data_from_files(boot_data, DPP_URI_JSON_PATH, DPP_BOOT_PEM_PATH);
        if (read_successful) {
            // Successfully fetched the bootstrapping data, return true.
            return true;
        } else {
            // Failed to read the DPP URI JSON from the file, so we need to generate new DPP bootstrapping data.
            printf("%s:%d: Failed to read DPP URI JSON from file, generating new DPP bootstrapping "
                   "data\n",
                   __func__, __LINE__);
        }
    }

    em_printfout("Force regenerating DPP bootstrapping data");

    // Generate new DPP bootstrapping data to ensure correct MAC address is used
    if (!ec_util::generate_dpp_boot_data(boot_data, al_mac, op_class_info)) {
        em_printfout("Failed to generate DPP boot data");
        return false;
    }

    // Write the DPP URI JSON to the file
    if (!ec_util::write_bootstrap_data_to_files(boot_data, DPP_URI_JSON_PATH, DPP_BOOT_PEM_PATH)) {
        em_printfout("Failed to write DPP URI JSON to file");
        return false;
    }

    return true;
}
