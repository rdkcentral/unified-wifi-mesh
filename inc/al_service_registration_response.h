#ifndef AL_SERVICE_REGISTRATION_RESPONSE_H
#define AL_SERVICE_REGISTRATION_RESPONSE_H

#include "al_service_registration_enums.h"
#include <array>
#include <utility>
#include <vector>

using MacAddress = std::array<uint8_t, 6>;
using MessageIdRange = std::pair<uint16_t, uint16_t>;

// Class used to manage a registration response from the IEEE1905 applicatoin
class AlServiceRegistrationResponse {
public:
    // Constructors
    
	/**!
	 * @brief Constructor for the AlServiceRegistrationResponse class.
	 *
	 * This constructor initializes a new instance of the AlServiceRegistrationResponse class.
	 *
	 * @note This is a default constructor and does not take any parameters.
	 */
	AlServiceRegistrationResponse();  
    
	/**!
	 * @brief Constructor for AlServiceRegistrationResponse class.
	 *
	 * This constructor initializes the AlServiceRegistrationResponse object with the given MAC address,
	 * message ID range, and registration result.
	 *
	 * @param[in] macAddress The MAC address associated with the service registration.
	 * @param[in] range The range of message IDs for the service registration.
	 * @param[in] result The result of the service registration process.
	 */
	AlServiceRegistrationResponse(const MacAddress& macAddress, MessageIdRange range, RegistrationResult result);

    // Setters and getters for local AL MAC address
    
	/**!
	 * @brief Sets the AL MAC address locally.
	 *
	 * This function assigns the provided MAC address to the local AL MAC address.
	 *
	 * @param[in] alMac The MAC address to be set locally.
	 *
	 * @note Ensure that the MAC address provided is valid and correctly formatted.
	 */
	void setAlMacAddressLocal(const MacAddress& alMac);
    
	/**!
	 * @brief Retrieves the local MAC address.
	 *
	 * This function returns the MAC address associated with the local AL (Access Layer).
	 *
	 * @returns A constant reference to the local MAC address.
	 */
	const MacAddress& getAlMacAddressLocal() const;

    // Setters and getters for message ID range assigned from the IEEE1905 agent
    
	/**!
	 * @brief Sets the message ID range.
	 *
	 * This function assigns a range of message IDs to be used.
	 *
	 * @param[in] range The range of message IDs to set.
	 */
	void setMessageIdRange(const MessageIdRange& range);
    
	/**!
	 * @brief Retrieves the range of message IDs.
	 *
	 * This function returns the range of message IDs that are currently registered.
	 *
	 * @returns MessageIdRange The range of message IDs.
	 *
	 * @note This function does not modify any member variables.
	 */
	MessageIdRange getMessageIdRange() const;

    // Setters and getters for registration result
    
	/**!
	 * @brief Sets the registration result.
	 *
	 * This function assigns the provided registration result to the internal state.
	 *
	 * @param[in] result The registration result to be set.
	 */
	void setResult(RegistrationResult result);
    
	/**!
	 * @brief Retrieves the registration result.
	 *
	 * This function returns the result of the registration process.
	 *
	 * @returns RegistrationResult The result of the registration.
	 */
	RegistrationResult getResult() const;

    // Serialization and deserialization functions
    
	/**!
	 * @brief Serializes the registration response into a vector of unsigned characters.
	 *
	 * This function converts the registration response data into a serialized format
	 * that can be easily transmitted or stored.
	 *
	 * @returns A vector of unsigned characters representing the serialized registration response.
	 */
	std::vector<unsigned char> serializeRegistrationResponse();
    
	/**!
	 * @brief Deserializes the registration response from the given data.
	 *
	 * This function processes the input data to extract the registration response details.
	 *
	 * @param[in] data A vector of unsigned char containing the serialized registration response data.
	 *
	 * @note Ensure that the data vector is properly formatted and contains valid registration response information.
	 */
	void deserializeRegistrationResponse(const std::vector<unsigned char>& data);

private:
    MacAddress alMacAddressLocal;
    MessageIdRange messageIdRange;
    RegistrationResult result;
};


#endif // AL_SERVICE_REGISTRATION_RESPONSE_H
