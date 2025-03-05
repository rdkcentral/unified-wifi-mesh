#include "ec_enrollee.h"

#include "ec_util.h"

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
    return 0;
}

int ec_enrollee_t::handle_auth_confirm(uint8_t *buff, unsigned int len)
{
    return 0;
}

int ec_enrollee_t::handle_config_response(uint8_t *buff, unsigned int len)
{
    return 0;
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

std::pair<uint8_t *, uint16_t> ec_enrollee_t::create_auth_response()
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
