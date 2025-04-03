#ifndef AL_SERVICE_REGISTRATION_REQUEST_H
#define AL_SERVICE_REGISTRATION_REQUEST_H
#include <vector>
#include <stdexcept>

#include "al_service_registration_enums.h"

// Class used to manage a registration request to the IEEE1905 application
class AlServiceRegistrationRequest {
public:
     // Constructor
    AlServiceRegistrationRequest();  // Default constructor
    AlServiceRegistrationRequest(ServiceOperation operation, ServiceType type);
    
    // Setters and getters for service operation
    void setServiceOperation(ServiceOperation service);
    ServiceOperation getServiceOperation() const;

    // Setters and getters for service type
    void setServiceType(ServiceType service);
    ServiceType getServiceType() const;

    // Serialization and deserialization methods
    std::vector<unsigned char> serializeRegistrationRequest(); 
    void deserializeRegistrationRequest(const std::vector<unsigned char>& data);

private:
    ServiceOperation serviceOperation;
    ServiceType serviceType;
};

#endif // AL_SERVICE_REGISTRATION_REQUEST_H
