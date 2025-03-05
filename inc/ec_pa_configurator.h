#ifndef EC_PA_CONFIGURATOR_H
#define EC_PA_CONFIGURATOR_H

#include "ec_configurator.h"

#include <map>
#include <vector>

class ec_pa_configurator_t : public ec_configurator_t {
public:
    ec_pa_configurator_t(send_chirp_func send_chirp_notification, send_encap_dpp_func send_prox_encap_dpp_msg) :
        ec_configurator_t(send_chirp_notification, send_prox_encap_dpp_msg) {};


    /**
     * @brief Handles a presence announcement 802.11 frame, performing the necessary actions and possibly passing to 1905
     * 
     * @param buff The frame to handle
     * @param len The length of the frame
     * 
     * @note Optional to implement because the controller+configurator does not handle 802.11,
     *      but the proxy agent + configurator does.
     */
    int handle_presence_announcement(uint8_t *buff, unsigned int len);

    /**
     * @brief Handles an authentication request 802.11 frame, performing the necessary actions and possibly passing to 1905
     * 
     * @param buff The frame to handle
     * @param len The length of the frame
     * @return int 0 if successful, -1 otherwise
     * 
     * @note Optional to implement because the controller+configurator does not handle 802.11,
     *     but the proxy agent + configurator does.
     */
    int handle_auth_response(uint8_t *buff, unsigned int len);

    /**
     * @brief Handles an configuration request 802.11+GAS frame, performing the necessary actions and possibly passing to 1905
     * 
     * @param buff The frame to handle
     * @param len The length of the frame
     * @return int 0 if successful, -1 otherwise
     * 
     * @note Optional to implement because the controller+configurator does not handle 802.11,
     *     but the proxy agent + configurator does.
     */
    int handle_cfg_request(uint8_t *buff, unsigned int len);

    /**
     * @brief Handles an configuration result 802.11+GAS frame, performing the necessary actions and possibly passing to 1905
     * 
     * @param buff The frame to handle
     * @param len The length of the frame
     * @return int 0 if successful, -1 otherwise
     * 
     * @note Optional to implement because the controller+configurator does not handle 802.11,
     *     but the proxy agent + configurator does.
     */
    int handle_cfg_result(uint8_t *buff, unsigned int len);

    /**
     * @brief Handle a chirp notification TLV and direct to the correct place (802.11 or 1905)
     * 
     * @param chirp_tlv The chirp TLV to parse and handle
     * @param tlv_len The length of the chirp TLV
     * @return int 0 if successful, -1 otherwise
     */
    int process_chirp_notification(em_dpp_chirp_value_t* chirp_tlv, uint16_t tlv_len);

    /**
     * @brief Handle a proxied encapsulated DPP message TLVs (including chirp value) and direct to the correct place (802.11 or 1905)
     * 
     * @param encap_tlv The 1905 Encap DPP TLV to parse and handle
     * @param encap_tlv_len The length of the 1905 Encap DPP TLV
     * @param chirp_tlv The DPP Chirp Value TLV to parse and handle (NULL if not present)
     * @param chirp_tlv_len The length of the DPP Chirp Value TLV (0 if not present)
     * @return int 0 if successful, -1 otherwise
     */
    int process_proxy_encap_dpp_msg(em_encap_dpp_t *encap_tlv, uint16_t encap_tlv_len, em_dpp_chirp_value_t *chirp_tlv, uint16_t chirp_tlv_len);

private:
    // Private member variables go here
    /*
     * Map from Chirp Hash to DPP Authentication Request
     */
    std::map<std::string, std::vector<uint8_t>> m_chirp_hash_frame_map;
    /*
     * Vector of all cached DPP Reconfiguration Authentication Requests.
     * Hash does not matter since it is compared against the Controllers C-sign key
     */
    std::vector<std::vector<uint8_t>> m_stored_recfg_auth_frames;
protected:
    // Protected member variables and methods go here
};

#endif // EC_PA_CONFIGURATOR_H