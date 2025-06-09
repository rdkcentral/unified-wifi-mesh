#include <al_service_data_unit.h>
#include <al_service_access_point.h>
#include <al_service_registration_request.h>
#include <al_service_registration_response.h>
#include <al_service_exception.h>
#include <al_service_utils.h>
#include <iostream>
#include <thread> // For sleep
#include <chrono> // For sleep
#include <sstream>
#include <vector>
#include <istream>
#include <iterator>
#define DATA_SOCKET_PATH "/tmp/al_data_socket"
#define CONTROL_SOCKET_PATH "/tmp/al_control_socket"

MacAddress split(const std::string& str, char delimiter) {
    //std::cout<<"START "<<std::endl;
    MacAddress mca;
    size_t start = 0;
    size_t end = str.find(delimiter);
    size_t curr_idx = 0;
    while (end != std::string::npos) {
        //std::cout << str.substr(start, end - start) << std::endl;
        mca[curr_idx] = std::stoi(str.substr(start, end - start).c_str(),nullptr,16);
        start = end + 1;
        end = str.find(delimiter, start);
        curr_idx += 1;
    }
    //std::cout<<str.substr(start)<<std::endl;
    mca[curr_idx] = (std::stoi(str.substr(start).c_str(),nullptr,16));
    //std::cout<<"END"<<std::endl;
    return mca;
}

int main(int argc, char* argv[]) {
    if(argc != 2) {
        std::cout<<"Expected destination mac addr in format aa:1f:2d:3b:41:55"<<std::endl;
        return 0;
    }
    MacAddress destinationMac = split(std::string(argv[1]),':');
    try {
        // Step 1: Create an instance of AlServiceAccessPoint for the client side
        std::string dataSocketPath = DATA_SOCKET_PATH;
        std::string controlSocketPath = CONTROL_SOCKET_PATH;
        AlServiceAccessPoint sap(dataSocketPath, controlSocketPath);

        // **[Step 1: Registration Test]**
        std::cout << "\n[Step 1: Registration]" << std::endl;
        std::cout << "Registering client as Easy Mesh Client..." << std::endl;

        // Create and configure the registration request
        AlServiceRegistrationRequest registrationRequest(ServiceOperation::SOP_ENABLE, ServiceType::SAP_TUNNEL_CLIENT);

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

        std::cout <<"Destination MAC ADDRESS "<<std::endl;
        for (auto byte : destinationMac) {
            std::cout << std::hex << static_cast<int>(byte) << " ";
        }
        std::cout << std::dec << std::endl;

        MacAddress sourceMac = registrationResponse.getAlMacAddressLocal();
        // **[Step 2: 1500-byte SDU Test]**
        std::cout << "\n[Step 2: 1500-byte SDU Test]" << std::endl;

        // Prepare and send AlServiceDataUnit with 1500 bytes SDU
        AlServiceDataUnit sdu1500;
        sdu1500.setFragmentId(0);
        sdu1500.setIsFragment(0);
        sdu1500.setIsLastFragment(1);
        sdu1500.setSourceAlMacAddress(sourceMac);

        sdu1500.setDestinationAlMacAddress(destinationMac);

        // Create a payload of 1481 bytes
        /*
         * We assume MTU = 1500, so max packet size is less or equal MTU size.
         * Each packet contains a header and a payload. The header size is
         * 4 (size) + 6 (MAC) + 6 (MAC) + 3 x 1 (3 x 1 byte flags) = 19 bytes.
         * Because of that, the fragment (payload) size can't exceed
         * MTU - 19 = 1481 bytes
        */
        std::vector<unsigned char> payload1481 {
                                                              // here CMDU starts
            0x0  ,                                           // CMDU_message_Verson
            0x0  ,                                           // CMDU_reserved
            0x0  , 0x7 ,                                     // CMDU_message_type
            0xa  , 0x0 ,                                     // CMDU_message_id
            0x0  ,                                           // CMDU fragment
            0xc0 ,                                           // CMDU flags
                                                             // here TLVs start
                                                             // TLV 1 - type al-mac-address
            0x1  ,                                           // TLV type
            0x0  , 0x6  ,                                    // TLV len
            sourceMac[0] , sourceMac[1] , sourceMac[2] , sourceMac[3] , sourceMac[5] , sourceMac[6],  // TLV payload
                                                             // TLV 2 6-22—SearchedRole TLV
            0xd  ,                                           // TLV type
            0x0  , 0x1  ,                                    // TLV len
            0x0  ,                                           // TLV payload
            0xe  , 0x0  , 0x1 ,  0x0  ,                      // TLV 3 6-23—autoconf_freq_band TLV
            0x80  , 0x0  , 0x2  , 0x1  , 0x1  ,              // TLV 4 supported service 17.2.1
            0x81  , 0x0  , 0x2  , 0x1  , 0x0  ,              // TLV 5 searched service 17.2.2
            0xb3  , 0x0  , 0x1  , 0x3  ,                     // TLV 6 One multiAP profile tlv 17.2.47
            0x0  , 0x0  , 0x0                                // TLV 7 End of message};
        };
        sdu1500.setPayload(payload1481);

        while(true){
            // Send the message
            sap.serviceAccessPointDataRequest(sdu1500);
            std::cout << "Client sent the message successfully!" << std::endl;

            std::this_thread::sleep_for(std::chrono::seconds(3));
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
