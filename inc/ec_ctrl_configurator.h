#ifndef EC_CTRL_CONFIGURATOR_H
#define EC_CTRL_CONFIGURATOR_H

#include "ec_configurator.h" 

class ec_ctrl_configurator_t : public ec_configurator_t {
public:
    ec_ctrl_configurator_t(std::string mac_addr, send_chirp_func send_chirp_notification, send_encap_dpp_func send_prox_encap_dpp_msg) :
        ec_configurator_t(mac_addr, send_chirp_notification, send_prox_encap_dpp_msg) {};
        // No MAC address needed for controller configurator

    /**
     * @brief Handle a chirp notification msg tlv and direct to 1905 agent
     * 
     * @param chirp_tlv The chirp TLV to parse and handle
     * @param tlv_len The length of the chirp TLV
     * @return bool true if successful, false otherwise
     */
    bool process_chirp_notification(em_dpp_chirp_value_t* chirp_tlv, uint16_t tlv_len);

    /**
     * @brief Handle a proxied encapsulated DPP message TLVs (including chirp value) and direct to 1905 agent
     * 
     * @param encap_tlv The 1905 Encap DPP TLV to parse and handle
     * @param encap_tlv_len The length of the 1905 Encap DPP TLV
     * @param chirp_tlv The DPP Chirp Value TLV to parse and handle (NULL if not present)
     * @param chirp_tlv_len The length of the DPP Chirp Value TLV (0 if not present)
     * @return bool true if successful, false otherwise
     */
    bool process_proxy_encap_dpp_msg(em_encap_dpp_t *encap_tlv, uint16_t encap_tlv_len, em_dpp_chirp_value_t *chirp_tlv, uint16_t chirp_tlv_len);

private:
    // Private member variables can be added here

    std::pair<uint8_t*, uint16_t> create_auth_request(std::string enrollee_mac);
    std::pair<uint8_t*, uint16_t> create_recfg_auth_request();
    std::pair<uint8_t*, uint16_t> create_auth_confirm();
    std::pair<uint8_t*, uint16_t> create_recfg_auth_confirm(std::string enrollee_mac);
    std::pair<uint8_t*, uint16_t> create_config_response();
};

#endif // EC_CTRL_CONFIGURATOR_H