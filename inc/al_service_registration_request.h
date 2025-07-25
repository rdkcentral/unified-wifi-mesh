#ifndef AL_SERVICE_REGISTRATION_REQUEST_H
#define AL_SERVICE_REGISTRATION_REQUEST_H
#include <vector>
#include <stdexcept>

#include "al_service_registration_enums.h"

// Class used to manage a registration request to the IEEE1905 application
class AlServiceRegistrationRequest {
public:
     // Constructor

	/**!
	 * @brief Constructor for the AlServiceRegistrationRequest class.
	 *
	 * This constructor initializes a new instance of the AlServiceRegistrationRequest class.
	 *
	 * @note This is a default constructor and does not take any parameters.
	 */
	AlServiceRegistrationRequest();  // Default constructor

	/**!
	 * @brief Constructor for AlServiceRegistrationRequest.
	 *
	 * Initializes a new instance of the AlServiceRegistrationRequest class with the specified operation and type.
	 *
	 * @param[in] operation The operation to be registered.
	 * @param[in] type The type of service to be registered.
	 *
	 * @note Ensure that the operation and type are valid and supported by the service registration system.
	 */
	AlServiceRegistrationRequest(SAPActivation operation, ServiceType type);

    // Setters and getters for service operation

	/**!
	 * @brief Sets the service operation.
	 *
	 * This function assigns a specific service operation to the service.
	 *
	 * @param[in] service The service operation to be set.
	 *
	 * @note Ensure that the service operation is valid before calling this function.
	 */
	void setSAPActivationStatus(SAPActivation service);

	/**!
	 * @brief Retrieves the service operation.
	 *
	 * This function returns the current service operation associated with the request.
	 *
	 * @returns ServiceOperation The current service operation.
	 */
	SAPActivation getSAPActivationStatus() const;

    // Setters and getters for service type

	/**!
	 * @brief Sets the type of service.
	 *
	 * This function assigns a specific service type to the service registration request.
	 *
	 * @param[in] service The service type to be set.
	 *
	 * @note Ensure that the service type is valid and supported.
	 */
	void setServiceType(ServiceType service);

	/**!
	 * @brief Retrieves the service type.
	 *
	 * This function returns the type of service associated with the current object.
	 *
	 * @returns The service type.
	 */
	ServiceType getServiceType() const;

    // Serialization and deserialization methods

	/**!
	 * @brief Serializes the registration request into a vector of bytes.
	 *
	 * This function converts the registration request data into a serialized format
	 * that can be easily transmitted or stored.
	 *
	 * @returns A vector of unsigned char containing the serialized registration request.
	 */
	std::vector<unsigned char> serializeRegistrationRequest();

	/**!
	 * @brief Deserializes the registration request from the given data.
	 *
	 * This function takes a vector of unsigned characters representing serialized data
	 * and processes it to extract the registration request information.
	 *
	 * @param[in] data A vector of unsigned characters containing the serialized registration request.
	 *
	 * @note Ensure that the data vector is properly formatted and contains valid registration request information.
	 */
	void deserializeRegistrationRequest(const std::vector<unsigned char>& data);

	/*
    	Size of the registration request message in bytes
    	size of packet (4 bytes) + Service Operation (1 byte) + Service Type (1 byte) = 2 bytes
    */
    static const size_t SIZE_BYTES = 2;
    static const size_t FRAMED_SIZE_BYTES = 4 + SIZE_BYTES;

private:
    SAPActivation serviceOperation;
    ServiceType serviceType;
};

#endif // AL_SERVICE_REGISTRATION_REQUEST_H
