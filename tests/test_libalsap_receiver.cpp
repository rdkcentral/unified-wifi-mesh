#include <al_service_data_unit.h>
#include <al_service_access_point.h>
#include <al_service_registration_request.h>
#include <al_service_registration_response.h>
#include <al_service_exception.h>
#include <al_service_utils.h>
#include <iostream>
#include <thread> // For sleep
#include <chrono> // For sleep

#define DATA_SOCKET_PATH "/tmp/al_data_socket"
#define CONTROL_SOCKET_PATH "/tmp/al_control_socket"

int main() {
    try {
        // Step 1: Create an instance of AlServiceAccessPoint for the client side
        std::string dataSocketPath = DATA_SOCKET_PATH;
        std::string controlSocketPath = CONTROL_SOCKET_PATH;
        AlServiceAccessPoint sap(dataSocketPath, controlSocketPath);

        // **[Step 1: Registration Test]**
        std::cout << "\n[Step 1: Registration]" << std::endl;
        std::cout << "Registering client as Easy Mesh Client..." << std::endl;

        // Create and configure the registration request
        AlServiceRegistrationRequest registrationRequest(ServiceOperation::SOP_ENABLE, ServiceType::SAP_CLIENT);

        // Send the registration request
        sap.serviceAccessPointRegistrationRequest(registrationRequest);

        // Receive the registration indication response
        AlServiceRegistrationResponse registrationResponse = sap.serviceAccessPointRegistrationResponse();

        // Display the MAC address from the registration indication
        std::cout << "Registration completed with MAC Address: ";
        for (auto byte : registrationResponse.getAlMacAddressLocal()) {
            std::cout << std::hex << static_cast<int>(byte) << " ";
        }
        std::cout << std::dec << std::endl;

        while(true) {
            std::cout << "Waiting for data..." << std::endl;
            AlServiceDataUnit ackSdu1500 = sap.serviceAccessPointDataIndication();
            auto payload = ackSdu1500.getPayload();

            // Print the acknowledgment message
            std::cout << "Received  payload with size: " << ackSdu1500.getPayload().size() << " bytes." << std::endl;
            std::cout<<"PAYLOAD: <";
            for (unsigned char byte : ackSdu1500.getPayload()) {
                std::cout << std::hex << static_cast<int>(byte) << " ";
            }
            std::cout << std::dec << " >"<<std::endl;
        }

    } catch (const AlServiceException& sapException) {
        std::cerr << "Error: " << sapException.what() << std::endl;
        std::cerr << "PrimitiveReceipt Error Code: " << static_cast<int>(sapException.getPrimitiveError()) << std::endl;
        return EXIT_FAILURE;
    } catch (const std::exception& sapException) {
        std::cerr << "General Error: " << sapException.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
