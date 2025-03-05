#ifndef EC_PA_CONFIGURATOR_H
#define EC_PA_CONFIGURATOR_H

#include "ec_configurator.h"

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
     * @param out_frame The buffer to store the output frame (NULL if no frame is needed)
     * @return int 0 if successful, -1 otherwise
     */
    int process_chirp_notification(em_dpp_chirp_value_t* chirp_tlv, uint8_t **out_frame);

    /**
     * @brief Handle a proxied encapsulated DPP TLV and direct to the correct place (802.11 or 1905)
     * 
     * @param encap_tlv The 1905 Encap DPP TLV to parse and handle
     * @param out_frame The buffer to store the output frame (NULL if no frame is needed)
     * @return int 0 if successful, -1 otherwise
     */
    int process_proxy_encap_dpp_tlv(em_encap_dpp_t *encap_tlv, uint8_t **out_frame);

private:
    // Private member variables go here

protected:
    // Protected member variables and methods go here
};

#endif // EC_PA_CONFIGURATOR_H