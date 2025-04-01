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
    AlServiceAccessPoint(const std::string& socketPath);

    // Destructor: Closes the Unix domain socket and releases any memory used by the SAP
    virtual ~AlServiceAccessPoint();
    
    // Executes service request primitive (send a message)
    void serviceAccessPointDataRequest(AlServiceDataUnit& message);

    // Executes service indication primitive (receive a message)
    AlServiceDataUnit serviceAccessPointDataIndication();  // Fills and returns an AlServiceDataUnit object

     // Executes service request primitive (send a message)
    void serviceAccessPointRegistrationRequest(AlServiceRegistrationRequest& message);

    // Executes service indication primitive (receive a message)
    AlServiceRegistrationResponse serviceAccessPointRegistrationResponse();  // Fills and returns an AlServiceDataUnit object

    // Getter for the socket descriptor
    int getSocketDescriptor() const;  // this was added method to get the socket descriptor 

    // Setter for the socket descriptor
    void setSocketDescriptor(int descriptor); // this was added method to set the socket descriptor


    private:
    MacAddress alMacAddressLocal;
    int socketDescriptor;
    std::string socketPath = "/tmp/ieee1905_socket";  // Unix socket path initialized
    AlServiceRegistrationResponse registrationResponse;  // Private member instance
    AlServiceRegistrationRequest registrationRequest;  // Private member instance
};

#endif // AL_SERVICE_ACCESS_POINT_H

