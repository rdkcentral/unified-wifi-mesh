#ifndef EC_CONFIGURATOR_H
#define EC_CONFIGURATOR_H

#include <functional>
#include <map>
#include <string>

#include "em_base.h"
#include "ec_crypto.h"
#include "ec_ops.h"
#include "ec_1905_encrypt_layer.h"


class ec_configurator_t {
public:
    
	/**
	 * @brief Construct an EC configurator
	 *
	 * This constructor initializes the EC configurator with the specified functions
	 * for sending notifications and messages.
	 *
	 * @param[in] al_mac_addr The AL MAC address of the device
	 * @param ops Callbacks for this Configurator
	 * @param sec_ctx The existing security context. Either generated elsewhere or imported from the enrollee.
	 * @param is_colocated_agent True if this is a co-located agent, false if it is a non-colocated agent or a controller.
	 */
	ec_configurator_t(const std::string& al_mac_addr, ec_ops_t& ops, ec_persistent_sec_ctx_t& sec_ctx, bool is_colocated_agent, handshake_completed_handler handshake_complete);
    
	/**!
	 * @brief Destructor for ec_configurator_t class.
	 *
	 * This destructor cleans up any resources allocated by the ec_configurator_t instance.
	 *
	 * @note Ensure that all necessary cleanup operations are performed before the destructor is called.
	 */
	virtual ~ec_configurator_t(); // Destructor

    
	/**
	 * @brief Start the EC configurator onboarding process for an enrollee.
	 *
	 * This function initiates the onboarding process using the provided bootstrapping data.
	 *
	 * @param[in] bootstrapping_data The data to use for onboarding (Parsed DPP URI Data).
	 *
	 * @return bool True if the onboarding process is successful, false otherwise.
	 */
	virtual bool onboard_enrollee(ec_data_t* bootstrapping_data) {
		return true; // Only implemented by Controller Configurator, not PA
	}

    
	/**
	 * @brief Handles a presence announcement 802.11 frame, performing the necessary actions.
	 *
	 * @param[in] frame The frame to handle.
	 * @param[in] len The length of the frame.
	 * @param[in] src_mac The source MAC address.
	 *
	 * @return bool True if successful, false otherwise.
	 *
	 * @note Optional to implement because the controller+configurator does not handle 802.11,
	 *       but the proxy agent + configurator does.
	 */
	virtual bool handle_presence_announcement(ec_frame_t *frame, size_t len, uint8_t src_mac[ETHER_ADDR_LEN]) {
        return 0; // Optional to implement
    }

    
	/**
	 * @brief Handles an authentication request 802.11 frame, performing the necessary actions.
	 *
	 * This function processes the given 802.11 authentication frame and executes the required
	 * operations based on the frame's content.
	 *
	 * @param[in] frame The 802.11 frame to handle.
	 * @param[in] len The length of the frame.
	 * @param[in] src_mac The source MAC address of the frame.
	 *
	 * @return true if the frame was handled successfully, false otherwise.
	 *
	 * @note This function is optional to implement because the controller+configurator does not
	 * handle 802.11 frames, but the proxy agent + configurator does.
	 */
	virtual bool handle_auth_response(ec_frame_t *frame, size_t len, uint8_t src_mac[ETHER_ADDR_LEN], uint8_t src_al_mac[ETH_ALEN]) {
        return true; // Optional to implement
    }

    
	/**
	 * @brief Handles a configuration request 802.11+GAS frame, performing the necessary actions.
	 *
	 * This function processes the incoming 802.11+GAS frame and executes the required operations
	 * based on the frame's content and source address.
	 *
	 * @param[in] buff The frame to handle.
	 * @param[in] len The length of the frame.
	 * @param[in] sa The 802.11 source address of the frame (from Enrollee).
	 *
	 * @return bool True if the operation is successful, false otherwise.
	 *
	 * @note This function is optional to implement because the controller+configurator does not handle 802.11,
	 *       but the proxy agent + configurator does.
	 */
	virtual bool handle_cfg_request(uint8_t *buff, unsigned int len, uint8_t sa[ETH_ALEN]) {
        return true; // Optional to implement
    }

	/**
	 * @brief Handles a GAS Comeback Request frame
	 * A GAS Comeback Request frame (in the context of DPP) indicates that a peer is ready the to receive the next fragmented frame via GAS Comeback Response frame.
	 * 
	 * For each Comeback Request frame received, we will sent the next fragment (if any) to the requesting peer.
	 * @param buff The frame
	 * @param len The length of the frame
	 * @param sa The source addr of the frame (Enrollee)
	 * @return true on success, otherwise false
	 */
	virtual bool handle_gas_comeback_request(uint8_t *buff, unsigned int len, uint8_t sa[ETH_ALEN]) {
		return true; // Implemented by PA configurator only
	}

    
	/**
	 * @brief Handles a configuration result 802.11+GAS frame, performing the necessary actions.
	 *
	 * This function processes a given 802.11+GAS frame and executes the required operations based on the frame's content.
	 *
	 * @param[in] frame The frame to handle.
	 * @param[in] len The length of the frame.
	 * @param[in] sa The source address of the frame.
	 *
	 * @return bool True if the operation is successful, false otherwise.
	 *
	 * @note This function is optional to implement because the controller+configurator does not handle 802.11,
	 *       but the proxy agent + configurator does.
	 */
	virtual bool handle_cfg_result(ec_frame_t *frame, size_t len, uint8_t sa[ETH_ALEN]) {
        return true; // Optional to implement
    }

    
	/**
	 * @brief Handles Connection Status Result frame.
	 *
	 * This function processes the connection status result frame and determines
	 * the success or failure of the operation based on the frame content.
	 *
	 * @param[in] frame Pointer to the frame data structure.
	 * @param[in] len Length of the frame.
	 * @param[in] sa Source address of the frame, represented as an array of
	 *               unsigned 8-bit integers.
	 *
	 * @return true if the operation is successful, otherwise false.
	 */
	virtual bool handle_connection_status_result(ec_frame_t *frame, size_t len, uint8_t sa[ETH_ALEN]) {
        return true;
    }

	/**
	 * @brief Handles a Reconfiguration Announcement frame
	 * 
	 * If this Reconfiguration Announcement frame is meant for the Configurator that received it
	 * (determined by comparing the C-sign-key hash attribute to the Configurator's C-sign-key),
	 * then create a Reconfiguration Authentication frame and send to the Enrollee
	 * 
	 * @param frame The Reconfiguration Announcement frame
	 * @param len The length of the frame
	 * @param sa The source address (Enrollee)
	 * @return true on success, otherwise false
	 * 
	 * @note Only implemented by the Controller Configurator
	 */
	virtual bool handle_recfg_announcement(ec_frame_t *frame, size_t len, uint8_t sa[ETH_ALEN], uint8_t src_al_mac[ETH_ALEN]) {
		return true;
	}

	/**
	 * @brief Handles a Reconfiguration Authentication Response frame
	 * 
	 * @param frame The proxied encapsulated Reconfiguration Authentication Response frame
	 * @param len The length of the frame
	 * @param sa The source address (Enrollee)
	 * @return true on success, otherwise false
	 */
	virtual bool handle_recfg_auth_response(ec_frame_t *frame, size_t len, uint8_t sa[ETH_ALEN], uint8_t src_al_mac[ETH_ALEN]) {
		return true; // Optional to implement
	}
    
	/**
	 * @brief Handle a chirp notification message TLV and direct it to the correct place (802.11 or 1905).
	 *
	 * This function processes the chirp notification by parsing the provided TLV and determining
	 * the appropriate handling mechanism based on the TLV content.
	 *
	 * @param[in] chirp_tlv Pointer to the chirp TLV to parse and handle.
	 * @param[in] tlv_len The length of the chirp TLV.
	 *
	 * @return true if the chirp notification was processed successfully, false otherwise.
	 */
	virtual bool process_chirp_notification(em_dpp_chirp_value_t* chirp_tlv, uint16_t tlv_len, uint8_t src_al_mac[ETH_ALEN]) {
		return true; // Optional to implement
	}

    
	/**
	 * @brief Handle a proxied encapsulated DPP message TLVs (including chirp value) and direct to the correct place (802.11 or 1905)
	 *
	 * This function processes the encapsulated DPP message TLVs and directs them to the appropriate protocol handler.
	 *
	 * @param[in] encap_tlv The 1905 Encap DPP TLV to parse and handle.
	 * @param[in] encap_tlv_len The length of the 1905 Encap DPP TLV.
	 * @param[in] chirp_tlv The DPP Chirp Value TLV to parse and handle (NULL if not present).
	 * @param[in] chirp_tlv_len The length of the DPP Chirp Value TLV (0 if not present).
	 * @param[in] src_al_mac The source AL MAC address of this message
	 *
	 * @return bool True if the message was processed successfully, false otherwise.
	 */
	virtual bool  process_proxy_encap_dpp_msg(em_encap_dpp_t *encap_tlv, uint16_t encap_tlv_len, em_dpp_chirp_value_t *chirp_tlv, uint16_t chirp_tlv_len, uint8_t src_al_mac[ETH_ALEN]) = 0;

	/**
	 * @brief Handle a Direct Encapsulated DPP Message (DPP Message TLV)
	 *
	 * @param[in] dpp_frame The frame parsed from the DPP Message TLV
	 * @param[in] dpp_frame_len The length of the frame from the DPP Message TLV
	 * @param[in] src_mac The source MAC address of the DPP frame
	 *
	 * @return bool True if the frame was processed successfully, false otherwise.
	 */
	virtual bool  process_direct_encap_dpp_msg(uint8_t* dpp_frame, uint16_t dpp_frame_len, uint8_t src_mac[ETH_ALEN]) = 0;

	/**
	 * @brief Handles a chirp found in an Autoconf Search (extended) message.
	 * 
	 * @param chirp The DPP chirp.
	 * @param len The length of the chirp hash (can be 0).
	 * @param src_mac Where it came from (Enrollee).
	 * @param msg_id The message ID of the Autoconf Search (extended) message.
	 * @return true on success, otherwise false.
	 * 
	 */
	virtual bool handle_autoconf_chirp(em_dpp_chirp_value_t* chirp, size_t len, uint8_t src_mac[ETH_ALEN], unsigned short msg_id) {
		// impl'd by Controller Configurator only
		return false;
	} 

	/**
	 * @brief Process a 1905 EAPOL Encapsulated Message (1905 Encap EAPOL TLV)
	 *
	 * @param[in] eapol_frame The frame parsed from the 1905 Encap EAPOL TLV
	 * @param[in] eapol_frame_len The length of the frame from the 1905 Encap EAPOL TLV
	 *
	 * @return bool True if the frame was processed successfully, false otherwise.
	 * 
	 * @note Not virtual since this function only calls the encryption layer
	 */
	bool process_1905_eapol_encap_msg(uint8_t* eapol_frame, uint16_t eapol_frame_len, uint8_t src_mac[ETH_ALEN]) {
		return m_1905_encrypt_layer->handle_eapol_frame(eapol_frame, eapol_frame_len, src_mac);
	}
	
	/**
	 * @brief Handle a proxied encapsulated DPP Configuration Request frame.
	 *
	 * This function processes a DPP Configuration Request frame received from an Enrollee.
	 *
	 * @param[in] encap_frame The DPP Configuration Request frame from an Enrollee.
	 * @param[in] encap_frame_len The length of the DPP Configuration Request frame.
	 * @param[in] dest_mac The source MAC of this DPP Configuration Request frame (Enrollee).
	 *
	 * @return true on success, otherwise false.
	 *
	 * @note This function is overridden by subclass.
	 */
	virtual bool handle_proxied_dpp_configuration_request(uint8_t *encap_frame, uint16_t encap_frame_len, uint8_t dest_mac[ETH_ALEN], uint8_t src_al_mac[ETH_ALEN]) {
        return true;
    }

    
	/**
	 * @brief Handle a proxied encapsulated DPP Configuration Result frame.
	 *
	 * This function processes a DPP Configuration Result frame that has been
	 * encapsulated and proxied. It extracts necessary information from the frame
	 * and performs required operations based on the configuration result.
	 *
	 * @param[in] encap_frame Pointer to the DPP Configuration Result frame.
	 * @param[in] encap_frame_len Length of the encapsulated frame.
	 * @param[in] dest_mac Source MAC address of the DPP Configuration Result frame (Enrollee).
	 *
	 * @return true if the frame is handled successfully, otherwise false.
	 */
	virtual bool handle_proxied_config_result_frame(uint8_t *encap_frame, uint16_t encap_frame_len, uint8_t dest_mac[ETH_ALEN], uint8_t src_al_mac[ETH_ALEN]) {
        return true;
    }

    
	/**
	 * @brief Handle a proxied encapsulated DPP Connection Status Result frame.
	 *
	 * This function processes a DPP Connection Status Result frame that has been
	 * encapsulated and proxied. It extracts necessary information from the frame
	 * and performs required operations based on the connection status.
	 *
	 * @param[in] encap_frame Pointer to the DPP Connection Status Result frame.
	 * @param[in] encap_frame_len Length of the encapsulated frame.
	 * @param[in] dest_mac Source MAC address of the DPP Connection Status Result frame (Enrollee).
	 *
	 * @return true if the frame was handled successfully, otherwise false.
	 */
	virtual bool handle_proxied_conn_status_result_frame(uint8_t *encap_frame, uint16_t encap_frame_len, uint8_t dest_mac[ETH_ALEN], uint8_t src_al_mac[ETH_ALEN]) {
        return true;
    }

	/**
	 * @brief Handle a DPP peer discovery request frame.
	 *
	 * This function processes a DPP peer discovery request frame received from a peer device.
	 * It delegates the frame handling to the underlying 1905 encryption layer for processing.
	 *
	 * @param[in] frame Pointer to the DPP peer discovery request frame to be processed.
	 * @param[in] len The length of the frame in bytes.
	 * @param[in] src_mac The source MAC address of the frame sender 
	 *
	 * @return true if the frame was processed successfully, otherwise false.
	 */
	bool handle_peer_disc_req_frame(ec_frame_t *frame, uint16_t len, uint8_t src_mac[ETH_ALEN]) {
        return m_1905_encrypt_layer->handle_peer_disc_req_frame(frame, len, src_mac);
    }

	/**
	 * @brief Handle a DPP peer discovery response frame.
	 *
	 * This function processes a DPP peer discovery response frame received from a peer device.
	 * It delegates the frame handling to the underlying 1905 encryption layer for processing.
	 *
	 * @param[in] frame Pointer to the DPP peer discovery response frame to be processed.
	 * @param[in] len The length of the frame in bytes.
	 * @param[in] src_mac The source MAC address of the frame sender
	 *
	 * @return true if the frame was processed successfully, otherwise false.
	 */
	bool handle_peer_disc_resp_frame(ec_frame_t *frame, uint16_t len, uint8_t src_mac[ETH_ALEN]) {
        return m_1905_encrypt_layer->handle_peer_disc_resp_frame(frame, len, src_mac);
    }

    
	/**!
	 * @brief Tears down the connection associated with the given MAC address.
	 *
	 * This function searches for the connection using the provided MAC address and, if found,
	 * frees the associated connection and ephemeral contexts.
	 *
	 * @param[in] mac The MAC address of the connection to be torn down.
	 *
	 * @note If the connection is not found, the function returns immediately without performing any action.
	 */
	inline void teardown_connection(const std::string& mac) {
        auto conn = m_connections.find(mac);
        if (conn == m_connections.end()) return;
        auto &c_ctx = conn->second;
        ec_crypto::free_connection_ctx(&c_ctx);
        ec_crypto::free_ephemeral_context(&c_ctx.eph_ctx, c_ctx.nonce_len, c_ctx.digest_len);
    }

	/**
     * @brief Initiates secure 1905 layer establishment with peer
     * @param dest_al_mac Destination AL MAC address
     * @return true if peer discovery request sent successfully
     * 
     * @note Creates and sends DPP Peer Discovery Request to begin security establishment process.
     */
	inline bool start_secure_1905_layer(uint8_t dest_al_mac[ETH_ALEN]) {
		return m_1905_encrypt_layer->start_secure_1905_layer(dest_al_mac);
	}

	/**
     * @brief Rekeys existing PTK with established peer
     * @param dest_al_mac Destination AL MAC address
     * @return true if PTK rekey handshake initiated successfully
     * 
     * @note Requires existing key context. Initiates the same 4-way handshake 
     *       as the initial handshake with some minor flags changed.
     */
	inline bool rekey_1905_layer_ptk(uint8_t dest_al_mac[ETH_ALEN]) {
		return m_1905_encrypt_layer->rekey_1905_layer_ptk(dest_al_mac);
	}

	/**
     * @brief Rekeys existing PTK with all established peers
     * @return true if all PTK rekey handshakes initiated successfully
     * 
     * @note Requires existing key contexts. Initiates the same 4-way handshake 
     *       as the initial handshake with some minor flags changed.
     */
	inline bool rekey_1905_layer_ptk() {
		return m_1905_encrypt_layer->rekey_1905_layer_ptk();
	}

	/**
     * @brief Rekeys GTK and distributes to all enrolled agents
     * @return true if GTK regenerated and distributed successfully
     * 
     * @note Controller-only operation. Generates new GTK and sends
     *       to all agents (EM 5.4.7.5) via group key handshake (EM 5.3.7.3)
     */
	inline bool rekey_1905_layer_gtk() {
		return m_1905_encrypt_layer->rekey_1905_layer_gtk();
	}

	/**
	 * @brief Retrieves the current security context.
	 */
	inline ec_persistent_sec_ctx_t* get_sec_ctx() { return &m_sec_ctx; };

    // Disable copy construction and assignment
    // Requires use of references or pointers when working with instances of this class
    
	/**!
	 * @brief Deleted copy constructor for ec_configurator_t.
	 *
	 * This constructor is deleted to prevent copying of ec_configurator_t instances.
	 *
	 * @note Copying of ec_configurator_t is not allowed to ensure unique configuration instances.
	 */
	ec_configurator_t(const ec_configurator_t&) = delete;
    ec_configurator_t& operator=(const ec_configurator_t&) = delete;

	/**
	 * @brief Get the conn ctx object for a given peer AL MAC address.
	 * 
	 * @note Needed to retrieve the enrollee NAK for BSS Configuration Response.
	 * 
	 * @param peer_al_mac The AL MAC address of the peer for which the connection context is requested.
	 * @return ec_connection_context_t* A pointer to the connection context associated with the given AL MAC address. NULL if not found. 
	 */
	inline ec_connection_context_t* get_al_conn_ctx(uint8_t peer_al_mac[ETH_ALEN]) {
        for (auto& conn : m_connections) {
			if (memcmp(conn.second.peer_al_mac, peer_al_mac, ETH_ALEN) == 0) {
				return &conn.second;
			}
		}
		return NULL;
    }

protected:
	std::string m_al_mac_addr;

	bool m_is_colocated_agent;

    send_chirp_func m_send_chirp_notification;

    send_encap_dpp_func m_send_prox_encap_dpp_msg;

    send_dir_encap_dpp_func m_send_dir_encap_dpp_msg;

    send_act_frame_func m_send_action_frame;

    get_backhaul_sta_info_func m_get_backhaul_sta_info;

    get_1905_info_func m_get_1905_info;

	get_fbss_info_func m_get_fbss_info;

    can_onboard_additional_aps_func m_can_onboard_additional_aps;

	send_autoconf_search_resp_func m_send_autoconf_resp_fn;

	std::unique_ptr<ec_1905_encrypt_layer_t> m_1905_encrypt_layer;

    // The connections to EasyMesh Devices (the Controller, Enrollees, and Agents)
	// The key can be the phy MAC or the AL MAC, depending on the context.
	// The `peer_al_mac` field in the context will always be the AL MAC (when it's been set)
    std::map<std::string, ec_connection_context_t> m_connections = {};
    
	/**!
	 * @brief Retrieves the connection context for a given MAC address.
	 *
	 * This function searches for the connection context associated with the specified MAC address.
	 * If the MAC address is not found, it returns NULL.
	 *
	 * @param[in] mac The MAC address for which the connection context is requested.
	 *
	 * @returns A pointer to the connection context associated with the given MAC address.
	 * @retval NULL if the MAC address is not found in the connections.
	 *
	 * @note Ensure that the MAC address provided is valid and exists in the connections map.
	 */
	inline ec_connection_context_t* get_conn_ctx(const std::string& mac) {
        if (m_connections.find(mac) == m_connections.end()) {
            return NULL;
        }
        return &m_connections[mac];    
    }

    
	/**!
	 * @brief Retrieves the ephemeral context for a given MAC address.
	 *
	 * This function attempts to find the connection context associated with the provided MAC address
	 * and returns a pointer to its ephemeral context if found.
	 *
	 * @param[in] mac The MAC address of the enrollee for which the ephemeral context is requested.
	 *
	 * @returns A pointer to the ephemeral context associated with the given MAC address.
	 * @retval NULL If the connection context for the given MAC address is not found.
	 *
	 * @note Ensure that the MAC address provided is valid and corresponds to an existing connection context.
	 */
	inline ec_ephemeral_context_t* get_eph_ctx(const std::string& mac) {
        auto conn_ctx = get_conn_ctx(mac);
        if (!conn_ctx) {
            printf("%s:%d: Connection context not found for enrollee MAC %s\n", __func__, __LINE__, mac.c_str());
            return NULL;  // Return reference to static empty context
        }
        return &conn_ctx->eph_ctx;
    }

    
	/**!
	 * @brief Retrieves the boot data for a given MAC address.
	 *
	 * This function searches for the connection context associated with the provided MAC address
	 * and returns a pointer to the boot data if found.
	 *
	 * @param[in] mac The MAC address of the enrollee whose boot data is to be retrieved.
	 *
	 * @returns A pointer to the boot data associated with the given MAC address.
	 * @retval NULL if the connection context for the given MAC address is not found.
	 *
	 * @note Ensure that the MAC address provided is valid and corresponds to an existing connection.
	 */
	inline ec_data_t* get_boot_data(const std::string& mac) {
        auto conn = m_connections.find(mac);
        if (conn == m_connections.end()) {
            printf("%s:%d: Connection context not found for enrollee MAC %s\n", __func__, __LINE__, mac.c_str());
            return NULL;  // Return reference to static empty context
        }
        return &conn->second.boot_data;
    }

    
	/**!
	 * @brief Clears the ephemeral context for a given MAC address.
	 *
	 * This function searches for a connection associated with the provided MAC address
	 * and clears its ephemeral context if found.
	 *
	 * @param[in] mac The MAC address of the connection whose ephemeral context is to be cleared.
	 *
	 * @note If the MAC address is not found in the connections, the function returns without action.
	 */
	inline void clear_conn_eph_ctx(const std::string& mac) {
        auto conn = m_connections.find(mac);
        if (conn == m_connections.end()) return;
        auto &c_ctx = conn->second;
        ec_crypto::free_ephemeral_context(&c_ctx.eph_ctx, c_ctx.nonce_len, c_ctx.digest_len);
    }

	/**
	 * @brief The security context for the Controller/Configurator OR the **Onboarded** Agent
	 * 
	 * This context is used to store the security keys and other information required for secure communication with the Controller and other onboarded Agents.
	 * 	- For the Controller/Configurator, the keys/connector are generated at startup.
	 * 	- For an **Onboarded Agent** the keys/connector are generated during the onboarding process and used throughout the lifetime of the agent (or until reconfigured).
	 */
	ec_persistent_sec_ctx_t m_sec_ctx;

	/**
	 * @brief Handles the completion of a 1905 handshake.
	 * 
	 * @param mac The peer MAC address of the device that completed the handshake.
	 * @param is_group True if the handshake was for a group key, false if it was for a pairwise key.
	 */
	void handle_1905_handshake_completed(uint8_t peer_mac[ETH_ALEN], bool is_group);
};

#endif // EC_CONFIGURATOR_H