#ifndef EC_MANAGER_H
#define EC_MANAGER_H

#include "ec_configurator.h"
#include "ec_enrollee.h"

#include <memory>
#include <functional>

class ec_manager_t {
public:
    // TODO: Add send_action_frame and send_gas_frame functions
    ec_manager_t(send_chirp_func send_chirp, send_encap_dpp_func send_encap_dpp, toggle_cce_func toggle_cce, bool is_controller);
    ~ec_manager_t();

    /**
     * @brief Handles DPP action frames directed at this nodes EC manager 
     * 
     * @param frame The frame recieved to handle
     * @param len The length of the frame
     * @return int 0 if successful, -1 otherwise
     */
    int handle_recv_ec_action_frame(ec_frame_t* frame, size_t len);

    /**
     * @brief Start the EC configurator onboarding
     * 
     * @param data The data to use for onboarding (Parsed DPP URI Data)
     * @return int 0 if successful, -1 otherwise
     */
    inline int cfg_start(ec_data_t* data) {
        if (!is_controller || m_configurator == nullptr) {
            return -1;
        }
        return m_configurator->start(data);
    }

        /**
     * @brief Handle a chirp notification TLV and direct to the correct place (802.11 or 1905)
     * 
     * @param chirp_tlv The chirp TLV to parse and handle
     * @param tlv_len The length of the chirp TLV
     * @return int 0 if successful, -1 otherwise
     */
    inline int process_chirp_notification(em_dpp_chirp_value_t* chirp_tlv, uint16_t tlv_len) {
        if (!m_configurator) {
            return -1;
        }
        return m_configurator->process_chirp_notification(chirp_tlv, tlv_len);
    }

    /**
     * @brief Handle a proxied encapsulated DPP message TLVs (including chirp value) and direct to the correct place (802.11 or 1905)
     * 
     * @param encap_tlv The 1905 Encap DPP TLV to parse and handle
     * @param encap_tlv_len The length of the 1905 Encap DPP TLV
     * @param chirp_tlv The DPP Chirp Value TLV to parse and handle (NULL if not present)
     * @param chirp_tlv_len The length of the DPP Chirp Value TLV (0 if not present)
     * @return int 0 if successful, -1 otherwise
     */
    inline int  process_proxy_encap_dpp_msg(em_encap_dpp_t *encap_tlv, uint16_t encap_tlv_len, em_dpp_chirp_value_t *chirp_tlv, uint16_t chirp_tlv_len) {
        if (!m_configurator) {
            return -1;
        }
        return m_configurator->process_proxy_encap_dpp_msg(encap_tlv, encap_tlv_len, chirp_tlv, chirp_tlv_len);
    }

private:
    std::unique_ptr<ec_configurator_t> m_configurator;
    std::unique_ptr<ec_enrollee_t> m_enrollee;
    bool is_controller;
};

#endif // EC_MANAGER_H