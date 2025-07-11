#ifndef EC_MANAGER_H
#define EC_MANAGER_H

#include "ec_configurator.h"
#include "ec_pa_configurator.h"
#include "ec_enrollee.h"
#include "ieee80211.h"
#include "ec_ops.h"

#include <memory>
#include <functional>

class ec_manager_t {
public:
    
	/**
	 * @brief The Manager (unified dispatcher of sorts) for the EasyConnect Configurator or Enrollee
	 *
	 * All non-controller devices are started as (non-onboarding) enrollees until they are told that they are on the network
	 * at which point they can be upgraded to a proxy agent.
	 * @param mac_addr The MAC address of the device
	 * @param ops Struct of callbacks per-EC entity
	 * @param is_controller Whether the EM node holding this manager is the mesh controller or not.
	 */
	ec_manager_t(const std::string& mac_addr, ec_ops_t& ops, bool is_controller);
    
	/**!
	 * @brief Destructor for ec_manager_t class.
	 *
	 * This function cleans up resources allocated by the ec_manager_t instance.
	 *
	 * @note Ensure that all operations using ec_manager_t are completed before calling this destructor.
	 */
	~ec_manager_t();

    
	/**
	 * @brief Handles DPP action frames directed at this node's EC manager.
	 *
	 * This function processes the received DPP action frames and performs
	 * necessary actions based on the frame content.
	 *
	 * @param[in] frame The frame received to handle.
	 * @param[in] len The length of the frame.
	 * @param[in] src_mac The MAC address of the source of the frame.
	 *
	 * @return true if the frame was handled successfully, false otherwise.
	 */
	bool handle_recv_ec_action_frame(ec_frame_t* frame, size_t len, uint8_t src_mac[ETHER_ADDR_LEN]);


    
	/**!
	 * @brief Handles the reception of a GAS public action frame.
	 *
	 * This function processes the received GAS (Generic Advertisement Service) public action frame.
	 *
	 * @param[in] frame Pointer to the GAS frame base structure.
	 * @param[in] len Length of the frame.
	 * @param[in] src_mac Source MAC address of the frame.
	 *
	 * @returns True if the frame was handled successfully, false otherwise.
	 */
	bool handle_recv_gas_pub_action_frame(ec_gas_frame_base_t * frame, size_t len, uint8_t src_mac[ETH_ALEN]);

    
	/**
	 * @brief Start the EC configurator onboarding
	 *
	 * This function initiates the onboarding process for the EC configurator using the provided data.
	 *
	 * @param[in] data The data to use for onboarding (Parsed DPP URI Data)
	 *
	 * @return bool True if the onboarding is successful, false otherwise.
	 */
	inline bool cfg_onboard_enrollee(ec_data_t* data) {
        if (!m_is_controller || m_configurator == nullptr) {
            return false;
        }
        return m_configurator->onboard_enrollee(data);
    }

    
	/**
	 * @brief Start the EC enrollee onboarding
	 *
	 * This function initiates the onboarding process for the EC enrollee.
	 *
	 * @param[in] do_reconfig Indicates whether to reconfigure or reauthenticate the enrollee.
	 * @param[in] boot_data Pointer to the bootstrapping data used for onboarding.
	 *
	 * @return true if the onboarding process is successful, false otherwise.
	 */
	inline bool enrollee_start_onboarding(bool do_reconfig, ec_data_t* boot_data) {
        if (m_is_controller || m_enrollee == nullptr) {
            return false;
        }
        return m_enrollee->start_onboarding(do_reconfig, boot_data);
    }

    
	/**
	 * @brief Toggle the presence of CCE (Configurator Connectivity Element) in Proxy Agent beacon and probe response IEs.
	 *
	 * This function enables or disables the presence of CCE in the specified IEs based on the input parameter.
	 *
	 * @param[in] enable A boolean indicating whether to enable or disable CCE presence.
	 * @return bool Returns true if the operation is successful, false otherwise.
	 *
	 * @note If the operation fails, all CCE IEs are removed before the function exits.
	 */
	inline bool pa_cfg_toggle_cce(bool enable) {
        if (m_is_controller || m_configurator == nullptr) {
            return false;
        }
        auto pa_cfg = dynamic_cast<ec_pa_configurator_t*>(m_configurator.get());
        if (!pa_cfg) {
            // Only a proxy agent configurator can toggle CCE
            return false;
        }
        return pa_cfg->m_toggle_cce(enable);
    }

    
	/**
	 * @brief Upgrade an enrollee to an onboarded proxy agent.
	 *
	 * Called once m1/m2 exchange verifies the enrollee agent is on the network.
	 *
	 * @return true if successful, false otherwise
	 *
	 * @note If the operation fails, all CCE IEs are removed before the function exits.
	 */
	bool upgrade_to_onboarded_proxy_agent();

    
	/**
	* @brief Handle a chirp notification TLV and direct to the correct place (802.11 or 1905).
	*
	* This function processes the chirp notification by parsing the provided TLV and
	* directing it to the appropriate handler based on its type.
	*
	* @param[in] chirp_tlv Pointer to the chirp TLV to parse and handle.
	* @param[in] tlv_len The length of the chirp TLV.
	*
	* @return true if the chirp notification was processed successfully, false otherwise.
	*/
	inline bool process_chirp_notification(em_dpp_chirp_value_t* chirp_tlv, uint16_t tlv_len) {
        if (!m_configurator) {
            return false;
        }
        return m_configurator->process_chirp_notification(chirp_tlv, tlv_len);
    }

    
	/**
	 * @brief Handle a proxied encapsulated DPP message TLVs (including chirp value) and direct to the correct place (802.11 or 1905).
	 *
	 * This function processes the encapsulated DPP message TLVs and directs them to the appropriate protocol handler.
	 *
	 * @param[in] encap_tlv The 1905 Encap DPP TLV to parse and handle.
	 * @param[in] encap_tlv_len The length of the 1905 Encap DPP TLV.
	 * @param[in] chirp_tlv The DPP Chirp Value TLV to parse and handle (NULL if not present).
	 * @param[in] chirp_tlv_len The length of the DPP Chirp Value TLV (0 if not present).
	 *
	 * @return bool True if the message was processed successfully, false otherwise.
	 *
	 * @note Ensure that the configurator is initialized before calling this function.
	 */
	inline bool process_proxy_encap_dpp_msg(em_encap_dpp_t *encap_tlv, uint16_t encap_tlv_len, em_dpp_chirp_value_t *chirp_tlv, uint16_t chirp_tlv_len) {
        if (!m_configurator) {
            return false;
        }
        return m_configurator->process_proxy_encap_dpp_msg(encap_tlv, encap_tlv_len, chirp_tlv, chirp_tlv_len);
    }

	/**
	 * @brief Handle a Direct Encapsulated DPP Message (DPP Message TLV)
	 *
	 * @param[in] dpp_frame The frame parsed from the DPP Message TLV
	 * @param[in] dpp_frame_len The length of the frame from the DPP Message TLV
	 *
	 * @return bool True if the frame was processed successfully, false otherwise.
	 *
	 * @note Ensure that the configurator is initialized before calling this function.
	 */
	inline bool process_direct_encap_dpp_msg(uint8_t* dpp_frame, uint16_t dpp_frame_len) {
        if (!m_configurator) {
            return false;
        }
        return m_configurator->process_direct_encap_dpp_msg(dpp_frame, dpp_frame_len);
    }

    /**
     * @brief Configurator Connectivity Element IE, EasyConnect v3.0 section 8.5.2
     */
    static constexpr struct ieee80211_vs_ie CCE_IE = {
        .vs_ie = IEEE80211_ELEMID_VENDOR,
        .vs_len = sizeof(struct ieee80211_vs_ie) - offsetof(struct ieee80211_vs_ie, vs_oui),
        .vs_oui = {0x50, 0x6f, 0x9a},
        .vs_type = 0x1e,
        .vs_subtype = 0x00
    };

    
	/**
	 * @brief Whether the enrollee node is **actively** onboarding or not.
	 *
	 * If the node is a configurator, this will always return false.
	 *
	 * @return true if the node is onboarding, false otherwise
	 */
	inline bool is_enrollee_onboarding() { 
		if (!m_enrollee) {
			return false;
		}
		return m_enrollee->is_onboarding();
	}


	/**
	 * @brief Handle an association status event (for the Enrollee's bSTA association attempt)
	 * 
	 * @param sta_data The STA data which contains association status
	 * @return true on success otherwise false
	 */
	bool handle_assoc_status(const rdk_sta_data_t &sta_data);

	/**
	 * @brief Handle a BSS info event. Forwards to Enrollee for handling.
	 * 
	 * @param bss_info_list The list of BSS infos heard
	 * @return true on success, otherwise false
	 */
	bool handle_bss_info_event(const std::vector<wifi_bss_info_t>& bss_info_list);


private:
    bool m_is_controller;
	ec_ops_t m_ops;
    std::string m_stored_mac_addr;
    
    std::unique_ptr<ec_configurator_t> m_configurator;
    std::unique_ptr<ec_enrollee_t> m_enrollee;
    toggle_cce_func m_toggle_cce_fn;
};

#endif // EC_MANAGER_H