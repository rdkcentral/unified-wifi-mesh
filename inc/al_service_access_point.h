#ifndef AL_SERVICE_ACCESS_POINT_H
#define AL_SERVICE_ACCESS_POINT_H

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>


#include "al_service_data_unit.h"
#include "al_service_exception.h"
#include "al_service_registration_request.h"
#include "al_service_registration_response.h"

// AlServiceAccessPoint class definition
using MacAddress = std::array<uint8_t, 6>;

class AlServiceAccessPoint {
public:
    // Constructor that accepts a custom socket path
    
	/**!
	 * @brief Constructor for AlServiceAccessPoint.
	 *
	 * Initializes the service access point with the specified socket path.
	 *
	 * @param[in] socketPath The path to the socket for service access.
	 *
	 * @note Ensure the socket path is valid and accessible.
	 */
	AlServiceAccessPoint(const std::string &dataSocketPath, const std::string &controlSocketPath);

    // Destructor: Closes the Unix domain socket and releases any memory used by the SAP
    
	/**!
	 * @brief Destructor for the AlServiceAccessPoint class.
	 *
	 * Cleans up any resources used by the AlServiceAccessPoint instance.
	 *
	 * @note This is a virtual destructor to ensure proper cleanup of derived classes.
	 */
	virtual ~AlServiceAccessPoint();
    
    // Executes service request primitive (send a message)
    
	/**!
	 * @brief Initiates a data request through the service access point.
	 *
	 * This function is responsible for handling the data request operation
	 * by utilizing the provided AlServiceDataUnit message.
	 *
	 * @param[in] message The data unit message to be processed by the service access point.
	 *
	 * @note Ensure that the message is properly initialized before calling this function.
	 */
	void serviceAccessPointDataRequest(AlServiceDataUnit& message);

    // Executes service indication primitive (receive a message)
    
	/**!
	 * @brief Handles the indication of service access point data.
	 *
	 * This function is responsible for processing the data indication
	 * received at the service access point.
	 *
	 * @returns AlServiceDataUnit
	 * The data unit received at the service access point.
	 *
	 * @note Ensure that the service access point is properly initialized
	 * before calling this function.
	 */
	AlServiceDataUnit serviceAccessPointDataIndication();  // Fills and returns an AlServiceDataUnit object

     // Executes service request primitive (send a message)
    
	/**!
	 * @brief Registers a service access point with the given registration request.
	 *
	 * This function handles the registration of a service access point using the provided
	 * registration request message.
	 *
	 * @param[in] message The registration request message containing the details
	 *                    required for service access point registration.
	 *
	 * @note Ensure that the message contains all necessary information for successful
	 *       registration.
	 */
	void serviceAccessPointRegistrationRequest(AlServiceRegistrationRequest& message);

    // Executes service indication primitive (receive a message)
    
	/**!
	 * @brief Retrieves the service access point registration response.
	 *
	 * This function returns the response associated with the registration of a service access point.
	 *
	 * @returns AlServiceRegistrationResponse
	 * The response object containing the details of the registration.
	 */
	AlServiceRegistrationResponse serviceAccessPointRegistrationResponse();  // Fills and returns an AlServiceDataUnit object

    // Getter for the data socket descriptor
    
	/**!
	 * @brief Retrieves the data socket descriptor.
	 *
	 * This function returns the data socket descriptor associated with the service access point.
	 *
	 * @returns The socket descriptor as an integer.
	 * @note This function does not modify any member variables.
	 */
	int getDataSocketDescriptor() const;  // this was added method to get the socket descriptor 

    // Setter for the data socket descriptor
    
	/**!
	 * @brief Sets the data socket descriptor for the service access point.
	 *
	 * This function assigns a data socket descriptor to the service access point, which
	 * is used for network communication.
	 *
	 * @param[in] descriptor The socket descriptor to be set.
	 *
	 * @note Ensure that the descriptor is valid and open before calling this function.
	 */
	void setDataSocketDescriptor(int descriptor); // this was added method to set the socket descriptor

    // Getter for the control socket descriptor
    
	/**!
	 * @brief Retrieves the control socket descriptor.
	 *
	 * This function returns the control socket descriptor associated with the service access point.
	 *
	 * @returns The socket descriptor as an integer.
	 * @note This function does not modify any member variables.
	 */
	int getControlSocketDescriptor() const;  // this was added method to get the socket descriptor 

    // Setter for the control socket descriptor
    
	/**!
	 * @brief Sets the control socket descriptor for the service access point.
	 *
	 * This function assigns a control socket descriptor to the service access point, which
	 * is used for network communication.
	 *
	 * @param[in] descriptor The socket descriptor to be set.
	 *
	 * @note Ensure that the descriptor is valid and open before calling this function.
	 */
	void setControlSocketDescriptor(int descriptor); // this was added method to set the socket descriptor


    private:
    MacAddress alMacAddressLocal;
    int alDataSocketDescriptor;
    std::string alDataSocketpath = "/tmp/al_data_socket"; // Unix socket path initialized
    int alControlSocketDescriptor;
    std::string alControlSocketpath = "/tmp/al_control_socket"; // Unix socket path initialized
    AlServiceRegistrationResponse registrationResponse;  // Private member instance
    AlServiceRegistrationRequest registrationRequest;  // Private member instance
};

#endif // AL_SERVICE_ACCESS_POINT_H

