#include "ec_pa_configurator.h"

int ec_pa_configurator_t::handle_presence_announcement(uint8_t *buff, unsigned int len)
{
    ec_frame_t *frame = (ec_frame_t *)buff;

    if (ec_util::validate_frame(frame, ec_frame_type_presence_announcement) == false) {
        printf("%s:%d: frame validation failed\n", __func__, __LINE__);
        return -1;
    }

    ec_attribute_t *attrib = ec_util::get_attrib(frame->attributes, len-EC_FRAME_BASE_SIZE, ec_attrib_id_resp_bootstrap_key_hash);
    if (!attrib) {
        return -1;
    }

    return 0;	
}

int ec_pa_configurator_t::handle_auth_response(uint8_t *buff, unsigned int len)
{
    return 0;
}

int ec_pa_configurator_t::handle_cfg_request(uint8_t *buff, unsigned int len)
{
    return 0;
}

int ec_pa_configurator_t::handle_cfg_result(uint8_t *buff, unsigned int len)
{
    return 0;
}

int ec_pa_configurator_t::process_chirp_notification(em_dpp_chirp_value_t *chirp_tlv, uint8_t **out_frame)
{
    return 0;
}

int ec_pa_configurator_t::process_proxy_encap_dpp_tlv(em_encap_dpp_t *encap_tlv, uint8_t **out_frame)
{
    return 0;
}
