#ifndef EC_CTRL_CONFIGURATOR_H
#define EC_CTRL_CONFIGURATOR_H

#include "ec_configurator.h" 

class ec_ctrl_configurator_t : public ec_configurator_t {
public:
    ec_ctrl_configurator_t(send_chirp_func send_chirp_notification, send_encap_dpp_func send_prox_encap_dpp_msg) :
        ec_configurator_t(send_chirp_notification, send_prox_encap_dpp_msg) {};

    /**
     * @brief Handle a chirp notification TLV and direct to 1905 agent
     * 
     * @param chirp_tlv The chirp TLV to parse and handle
     * @param out_frame The buffer to store the output frame (NULL if no frame is needed)
     * @return int 0 if successful, -1 otherwise
     */
    int process_chirp_notification(em_dpp_chirp_value_t* chirp_tlv, uint8_t **out_frame);

    /**
     * @brief Handle a proxied encapsulated DPP TLV and direct to 1905 agent
     * 
     * @param encap_tlv The 1905 Encap DPP TLV to parse and handle
     * @param out_frame The buffer to store the output frame (NULL if no frame is needed)
     * @return int 0 if successful, -1 otherwise
     */
    int process_proxy_encap_dpp_tlv(em_encap_dpp_t *encap_tlv, uint8_t **out_frame);

private:
    // Private member variables can be added here

    std::pair<uint8_t*, uint16_t> create_auth_request();
    std::pair<uint8_t*, uint16_t> create_auth_confirm();
    std::pair<uint8_t*, uint16_t> create_config_response();
};

#endif // EC_CTRL_CONFIGURATOR_H