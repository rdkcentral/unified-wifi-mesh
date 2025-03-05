#include <ctype.h>
#include <functional>
#include <arpa/inet.h>

#include "ec_util.h"
#include "util.h"
#include "aes_siv.h"
#include "em_crypto.h"

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

ec_attribute_t *ec_util::get_attrib(uint8_t *buff, uint16_t len, ec_attrib_id_t id)
{
    unsigned int total_len = 0;
    ec_attribute_t *attrib = (ec_attribute_t *)buff;

    while (total_len < len) {
        if (attrib->attr_id == id) {
            return attrib;
        }

        total_len += (get_ec_attr_size(attrib->length));
        attrib = (ec_attribute_t *)((uint8_t*)attrib + get_ec_attr_size(attrib->length));
    }

    return NULL;
}


uint8_t* ec_util::add_attrib(uint8_t *buff, uint16_t* buff_len, ec_attrib_id_t id, uint16_t len, uint8_t *data)
{
    if (data == NULL || len == 0) {
        fprintf(stderr, "Invalid input\n");
        return NULL;
    }

    
    // Add extra space for the new attribute
    uint16_t new_len = *buff_len + get_ec_attr_size(len);
    // Original start pointer to use for realloc
    uint8_t* base_ptr = NULL;
    if (buff != NULL) base_ptr = buff - *buff_len;
    if ((base_ptr = (uint8_t*)realloc(base_ptr, new_len)) == NULL) {
        fprintf(stderr, "Failed to realloc\n");
        return NULL;
    }

    // Get the start of the new section based on the re-allocated pointer
    uint8_t* tmp = base_ptr + *buff_len;

    memset(tmp, 0, get_ec_attr_size(len));
    ec_attribute_t *attr = (ec_attribute_t *)tmp;
    // EC attribute id and length are in host byte order according to the spec (8.1)
    attr->attr_id = id;
    attr->length = len;
    memcpy(attr->data, data, len);

    *buff_len += get_ec_attr_size(len);
    // Return the next attribute in the buffer
    return tmp + get_ec_attr_size(len);
}

uint16_t ec_util::freq_to_channel_attr(unsigned int freq)
{
    auto op_chan = util::em_freq_to_chan(freq);

    auto [op_class, channel] = op_chan;
    return ((channel << 8) | (0x00ff & op_class));
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



uint8_t* ec_util::add_wrapped_data_attr(ec_frame_t *frame, uint8_t* frame_attribs, uint16_t* non_wrapped_len, bool use_aad, uint8_t* key, std::function<std::pair<uint8_t*, uint16_t>()> create_wrap_attribs)
{
    siv_ctx ctx;

    // Initialize AES-SIV context
// TODO: Come back to
    // switch(params.digestlen) {
    //     case SHA256_DIGEST_LENGTH:
    //         siv_init(&ctx, key, SIV_256);
    //         break;
    //     case SHA384_DIGEST_LENGTH:
    //         siv_init(&ctx, key, SIV_384);
    //         break;
    //     case SHA512_DIGEST_LENGTH:
    //         siv_init(&ctx, key, SIV_512);
    //         break;
    //     default:
    //         printf("%s:%d Unknown digest length\n", __func__, __LINE__);
    //         return NULL;
    // }

    // Use the provided function to create wrap_attribs and wrapped_len
    auto [wrap_attribs, wrapped_len] = create_wrap_attribs();

    // Encapsulate the attributes in a wrapped data attribute
    uint16_t wrapped_attrib_len = wrapped_len + AES_BLOCK_SIZE;
    ec_attribute_t *wrapped_attrib = (ec_attribute_t *)calloc(sizeof(ec_attribute_t) + wrapped_attrib_len, 1); 
    wrapped_attrib->attr_id = ec_attrib_id_wrapped_data;
    wrapped_attrib->length = wrapped_attrib_len;
    memset(wrapped_attrib->data, 0, wrapped_attrib_len);

    /**
    * Encrypt attributes using SIV mode with two additional authenticated data (AAD) inputs:
    * 1. The frame structure and 2. Non-wrapped attributes (per EasyMesh 6.3.1.4)
    * The synthetic IV/tag is stored in the first AES_BLOCK_SIZE bytes of wrapped_attrib->data
    */
   if (use_aad) {
        if (frame == NULL || frame_attribs == NULL || non_wrapped_len == NULL) {
            printf("%s:%d: AAD input is NULL, AAD encryption failed!\n", __func__, __LINE__);
            return NULL;
        }
        siv_encrypt(&ctx, wrap_attribs, &wrapped_attrib->data[AES_BLOCK_SIZE], wrapped_len, wrapped_attrib->data, 2,
            frame, sizeof(ec_frame_t),
            frame_attribs, *non_wrapped_len);
    } else {
        siv_encrypt(&ctx, wrap_attribs, &wrapped_attrib->data[AES_BLOCK_SIZE], wrapped_len, wrapped_attrib->data, 0);
    }

    // Add the wrapped data attribute to the frame
    uint8_t* ret_frame_attribs = ec_util::add_attrib(frame_attribs, non_wrapped_len, ec_attrib_id_wrapped_data, wrapped_attrib_len, (uint8_t *)wrapped_attrib);


    free(wrap_attribs);

    return ret_frame_attribs;
}

std::pair<uint8_t*, size_t> ec_util::unwrap_wrapped_attrib(ec_attribute_t* wrapped_attrib, ec_frame_t *frame, bool uses_aad, uint8_t* key)
{
    siv_ctx ctx;

    // Initialize AES-SIV context
    // switch(m_params.digestlen) {
    //     case SHA256_DIGEST_LENGTH:
    //         siv_init(&ctx, key, SIV_256);
    //         break;
    //     case SHA384_DIGEST_LENGTH:
    //         siv_init(&ctx, key, SIV_384);
    //         break;
    //     case SHA512_DIGEST_LENGTH:
    //         siv_init(&ctx, key, SIV_512);
    //         break;
    //     default:
    //         printf("%s:%d Unknown digest length\n", __func__, __LINE__);
    //         return std::pair<uint8_t*, size_t>(NULL, 0);
    // }

    uint8_t* wrapped_ciphertext = wrapped_attrib->data + AES_BLOCK_SIZE;
    size_t wrapped_len = wrapped_attrib->length - AES_BLOCK_SIZE;

    uint8_t* unwrap_attribs = (uint8_t*)calloc(wrapped_len, 1);
    int result = -1;
    if (uses_aad) {
        if (frame == NULL) {
            printf("%s:%d: AAD input is NULL, AAD decryption failed!\n", __func__, __LINE__);
            return std::pair<uint8_t*, size_t>(NULL, 0);
        }
        result = siv_decrypt(&ctx, wrapped_ciphertext, unwrap_attribs, wrapped_len, wrapped_attrib->data, 2,
            frame, sizeof(ec_frame_t),
            frame->attributes, ((uint8_t*)wrapped_attrib) - frame->attributes); // Non-wrapped attributes
    } else {
        result = siv_decrypt(&ctx, wrapped_ciphertext, unwrap_attribs, wrapped_len, wrapped_attrib->data, 0);
    }

    if (result < 0) {
        printf("%s:%d: Failed to decrypt and authenticate wrapped data\n", __func__, __LINE__);
        free(unwrap_attribs);
        return std::pair<uint8_t*, size_t>(NULL, 0);
    }

    return std::pair<uint8_t*, size_t>(unwrap_attribs, wrapped_len);
}

bool ec_util::parse_dpp_chirp_tlv(em_dpp_chirp_value_t* chirp_tlv, uint16_t chirp_tlv_len, mac_addr_t *mac, uint8_t **hash, uint8_t *hash_len)
{
    if (chirp_tlv == NULL || chirp_tlv_len == 0) {
        fprintf(stderr, "Invalid input\n");
        return false;
    }

    uint16_t data_len = chirp_tlv_len - sizeof(em_dpp_chirp_value_t);
    // Parse TLV
    bool mac_addr_present = chirp_tlv->mac_present;
    bool hash_valid = chirp_tlv->hash_valid;

    uint8_t *data_ptr = chirp_tlv->data;
    if (mac_addr_present && data_len >= sizeof(mac_addr_t)) {
        memcpy(*mac, data_ptr, sizeof(mac_addr_t));
        data_ptr += sizeof(mac_addr_t);
        data_len -= sizeof(mac_addr_t);
    }

    if (!hash_valid || data_len <= 0) {
        // Clear (Re)configuration state, agent side
        return true;
    }

    *hash_len = *data_ptr;
    data_ptr++;
    if (data_len < *hash_len) {
        fprintf(stderr, "Invalid chirp tlv\n");
        return NULL;
    }
    memcpy(*hash, data_ptr, *hash_len);

    return true;
}

bool ec_util::parse_encap_dpp_tlv(em_encap_dpp_t *encap_tlv, uint16_t encap_tlv_len, mac_addr_t *dest_mac, uint8_t *frame_type, uint8_t **encap_frame, uint8_t *encap_frame_len)
{
    if (encap_tlv == NULL || encap_tlv_len == 0) {
        fprintf(stderr, "Invalid input\n");
        return false;
    }

    uint16_t data_len = encap_tlv_len - sizeof(em_encap_dpp_t);
    // Parse TLV
    bool mac_addr_present = encap_tlv->enrollee_mac_addr_present;

    // Copy mac address if present
    uint8_t *data_ptr = encap_tlv->data;
    if (mac_addr_present && data_len >= sizeof(mac_addr_t)) {
        memcpy(*dest_mac, data_ptr, sizeof(mac_addr_t));
        data_ptr += sizeof(mac_addr_t);
        data_len -= sizeof(mac_addr_t);
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

    // Get frame length
    *encap_frame_len = htons(*((uint16_t *)data_ptr));
    data_ptr += sizeof(uint16_t);

    if (data_len < *encap_frame_len) {
        fprintf(stderr, "Invalid encap tlv\n");
        return false;
    }

    // Copy frame
    memcpy(*encap_frame, data_ptr, *encap_frame_len);

    return true;
}

em_encap_dpp_t * ec_util::create_encap_dpp_tlv(bool dpp_frame_indicator, uint8_t content_type, mac_addr_t *dest_mac, uint8_t frame_type, uint8_t *encap_frame, uint8_t encap_frame_len)
{
    size_t data_size = sizeof(em_encap_dpp_t) + sizeof(uint8_t) + sizeof(uint16_t) + encap_frame_len;
    if (dest_mac != NULL) {
        data_size += sizeof(mac_addr_t);
    }
    em_encap_dpp_t *encap_tlv = NULL;

    if ((encap_tlv = (em_encap_dpp_t *)calloc(data_size, 1)) == NULL){
        fprintf(stderr, "Failed to allocate memory\n");
        return NULL;
    }
    (encap_tlv)->dpp_frame_indicator = dpp_frame_indicator;
    (encap_tlv)->content_type = content_type;
    (encap_tlv)->enrollee_mac_addr_present = (dest_mac != NULL) ? 1 : 0;

    uint8_t *data_ptr = (encap_tlv)->data;
    if (dest_mac != NULL) {
        memcpy(data_ptr, dest_mac, sizeof(mac_addr_t));
        data_ptr += sizeof(mac_addr_t);
    }

    *data_ptr = frame_type;
    data_ptr++;

    *((uint16_t *)data_ptr) = htons(encap_frame_len);
    data_ptr += sizeof(uint16_t);

    memcpy(data_ptr, encap_frame, encap_frame_len);

    return encap_tlv;
}

ec_frame_t *ec_util::copy_attrs_to_frame(ec_frame_t *frame, uint8_t *attrs, uint16_t attrs_len)
{
    uint16_t new_len = EC_FRAME_BASE_SIZE + attrs_len;
    ec_frame_t* new_frame = (ec_frame_t *) realloc((uint8_t*)frame, new_len);
    if (new_frame == NULL) {
        printf("%s:%d unable to realloc memory\n", __func__, __LINE__);
        return NULL; 
    }
    memcpy(new_frame->attributes, attrs, attrs_len);

    return new_frame;

}

std::string ec_util::hash_to_hex_string(const uint8_t *hash, size_t hash_len) {
    char output[hash_len * 2 + 1];
    for (size_t i = 0; i < hash_len; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[hash_len * 2] = '\0'; // Null-terminate the string
    return std::string(output);
}

