#include "al_service_access_point.h"
#include "al_service_utils.h"

// Constructor: Connects to the Unix domain socket using the provided path --> moved from hardcoded to check in the unit test for socket creation
AlServiceAccessPoint::AlServiceAccessPoint(const std::string &dataSocketPath, const std::string &controlSocketPath) : alDataSocketpath(dataSocketPath),
                                                                                                                      alControlSocketpath(controlSocketPath)
{
    alDataSocketDescriptor = socket(AF_UNIX, SOCK_STREAM, 0);
    if (alDataSocketDescriptor == -1)
    {
        throw AlServiceException("Failed to create Unix socket for data", PrimitiveError::SocketCreationFailed);
    }
    struct sockaddr_un dataAddr = createUnixSocketAddress(dataSocketPath);
    if (connect(alDataSocketDescriptor, (struct sockaddr *)&dataAddr, sizeof(dataAddr)) == -1)
    {
        close(alDataSocketDescriptor);
        throw AlServiceException("Failed to connect to Unix socket for data", PrimitiveError::ConnectionFailed);
    }
#ifdef DEBUG_MODE
    std::cout << "Connected to Unix data socket: " << dataSocketPath << std::endl;
#endif
    alControlSocketDescriptor = socket(AF_UNIX, SOCK_STREAM, 0);
    if (alControlSocketDescriptor == -1)
    {
        throw AlServiceException("Failed to create Unix socket for control", PrimitiveError::SocketCreationFailed);
    }
    struct sockaddr_un controlAddr = createUnixSocketAddress(controlSocketPath);
    if (connect(alControlSocketDescriptor, (struct sockaddr *)&controlAddr, sizeof(controlAddr)) == -1)
    {
        close(alControlSocketDescriptor);
        throw AlServiceException("Failed to connect to Unix socket for control", PrimitiveError::ConnectionFailed);
    }
#ifdef DEBUG_MODE
    std::cout << "Connected to Unix control socket: " << controlSocketPath << std::endl;
#endif
}

// Destructor: Closes the Unix domain socket
AlServiceAccessPoint::~AlServiceAccessPoint() {
    if (alDataSocketDescriptor != -1)
    {
        close(alDataSocketDescriptor);
#ifdef DEBUG_MODE
        std::cout << "Unix socket closed." << std::endl;
        #endif
    }
}

// Getter for the socket descriptor
int AlServiceAccessPoint::getDataSocketDescriptor() const
{
    return alDataSocketDescriptor;
}

// Setter for the socket descriptor
void AlServiceAccessPoint::setDataSocketDescriptor(int descriptor)
{
    alDataSocketDescriptor = descriptor;
}

int AlServiceAccessPoint::getControlSocketDescriptor() const
{
    return alControlSocketDescriptor;
}

// Setter for the socket descriptor
void AlServiceAccessPoint::setControlSocketDescriptor(int descriptor)
{
    alControlSocketDescriptor = descriptor;
}

// Executes service registration request (send a registration message)
void AlServiceAccessPoint::serviceAccessPointRegistrationRequest(AlServiceRegistrationRequest& message) {
    
    std::vector<unsigned char> serializedData = message.serializeRegistrationRequest();
    ssize_t bytesSent = send(alControlSocketDescriptor, serializedData.data(), serializedData.size(), 0);
    if (bytesSent == -1) {
        throw AlServiceException("Failed to send registration request", PrimitiveError::RequestFailed);
    }
    #ifdef DEBUG_MODE
    printByteStream(serializedData);
    std::cout << "Registration request sent with " << bytesSent << " bytes." << std::endl;
    #endif
}

// Executes service registration indication (receive a registration indication message)
AlServiceRegistrationResponse AlServiceAccessPoint::serviceAccessPointRegistrationResponse() {
    std::vector<unsigned char> buffer(1500);
    ssize_t bytesRead = recv(alControlSocketDescriptor, buffer.data(), buffer.size(), 0);
    if (bytesRead == -1) {
        throw AlServiceException("Failed to receive registration indication", PrimitiveError::IndicationFailed);
    }

    buffer.resize(bytesRead);
    #ifdef DEBUG_MODE
    printByteStream(buffer);
    #endif
    registrationResponse.deserializeRegistrationResponse(buffer);
    #ifdef DEBUG_MODE
    std::cout << "Registration indication received with " << bytesRead << " bytes." << std::endl;
    #endif
    return registrationResponse;
}

// Message to send a SDU message to the IEEE1905 application
void AlServiceAccessPoint::serviceAccessPointDataRequest(AlServiceDataUnit& message) {
    const size_t fragmentSize = 1485;
    
    const std::vector<unsigned char>& payload = message.getPayload();

    size_t totalSize = payload.size();

    //first condition to check if the service has been correctly registered enable
    if (registrationRequest.getServiceOperation() == ServiceOperation::SOP_ENABLE || registrationResponse.getResult() == RegistrationResult::SUCCESS) {
         
        // If payload size is less than or equal to 1500, send directly without fragmentation
        if (totalSize <= fragmentSize) {
            message.setIsFragment(0);
            message.setIsLastFragment(1);

            // Serialize and send the data
            std::vector<unsigned char> serializedData = message.serialize();
            ssize_t bytesSent = send(alDataSocketDescriptor, serializedData.data(), serializedData.size(), 0);
            if (bytesSent == -1) {
                throw AlServiceException("Failed to send message through Unix socket", PrimitiveError::RequestFailed);
            }
            #ifdef DEBUG_MODE
            std::cout << "Sent single message with size " << std::dec << bytesSent << " bytes (no fragmentation)." << std::endl;
            #endif
            return; // Exit the function after sending
        }
        // For payloads larger than 1500 bytes, handle fragmentation
        size_t numFragments = (totalSize + fragmentSize - 1) / fragmentSize;
        for (size_t i = 0; i < numFragments; ++i) {
            size_t start = i * fragmentSize;
            size_t end = std::min(start + fragmentSize, totalSize);
            std::vector<unsigned char> fragmentData(payload.begin() + start, payload.begin() + end);

            message.setPayload(fragmentData);
            message.setFragmentId(static_cast<uint8_t>(i));
            message.setIsFragment(1); // Mark as a fragment

            // Mark as last fragment if this is the last iteration
            message.setIsLastFragment((i == numFragments - 1) ? 1 : 0);

            // Debugging Output for Fragmentation
            #ifdef DEBUG_MODE
            std::cout << "Sending fragment " << i << " of " << numFragments
                    << " - Size: " << fragmentData.size() << " bytes, "
                    << "isFragment: " << static_cast<int>(message.getIsFragment()) << ", "
                    << "FragmentId: " << static_cast<int>(message.getFragmentId()) << ", "
                    << "isLastFragment: " << static_cast<int>(message.getIsLastFragment()) << std::endl;
            #endif
            // Serialize and send the current fragment
            std::vector<unsigned char> serializedData = message.serialize();
            ssize_t bytesSent = send(alDataSocketDescriptor, serializedData.data(), serializedData.size(), 0);
            if (bytesSent == -1) {
                throw AlServiceException("Failed to send message fragment through Unix socket", PrimitiveError::RequestFailed);
            }
            #ifdef DEBUG_MODE
            std::cout << "Fragment " << i << " sent successfully with size " << bytesSent << " bytes." << std::endl;
            #endif
        }
    }else if (registrationResponse.getResult() != RegistrationResult::SUCCESS) {
    #ifdef DEBUG_MODE
    // If registration was unsuccessful
    #endif
    std::cout << "Cannot send data: Registration unsuccessful." << std::endl;
    throw AlServiceException("Registration unsuccessful", PrimitiveError::RegistrationError);
    } else if (registrationRequest.getServiceOperation() != ServiceOperation::SOP_ENABLE) {
        #ifdef DEBUG_MODE
        // If the service operation is not enabled
        std::cout << "Cannot send data: Service operation not enabled." << std::endl;
        #endif
        throw AlServiceException("Service operation not enabled", PrimitiveError::ServiceNotRegistered);
        }else{
                std::cout << "Cannot send data: Unknown problem." << std::endl;
                throw AlServiceException("Cannot send data: Unknown problem", PrimitiveError::UnknownError);

            }

}
// Executes service indication primitive (receive a message through the socket)
AlServiceDataUnit AlServiceAccessPoint::serviceAccessPointDataIndication() {
    std::vector<unsigned char> payload;
    int fragmentId = 0;
    bool receivingFragments = true;
    AlServiceDataUnit message;

    while (receivingFragments) {
        std::vector<unsigned char> buffer(1500, 0x00);

        // Receive data from the socket
        ssize_t bytesRead = recv(alDataSocketDescriptor, buffer.data(), buffer.size(), 0);
        if (bytesRead <= 0) {
            if (errno == EBADF || errno == ECONNRESET) {
                throw AlServiceException("Socket closed or connection reset", PrimitiveError::SocketClosed);
            }
            throw AlServiceException("Failed to receive message through Unix socket", PrimitiveError::IndicationFailed);
        }
        buffer.resize(bytesRead);
        
        std::cout << std::endl;

        // Deserialize the received fragment
        AlServiceDataUnit fragment;
        try {
            fragment.deserialize(buffer);
        } catch (const std::exception& e) {
            throw AlServiceException("Failed to deserialize AlServiceDataUnit fragment", PrimitiveError::InvalidMessage);
        }
        #ifdef DEBUG_MODE
        std::cout << "Received fragment " << static_cast<int>(fragment.getFragmentId())
                  << " - Size: " << bytesRead << " bytes, "
                  << "isFragment: " << static_cast<int>(fragment.getIsFragment()) << ", "
                  << "FragmentId: " << static_cast<int>(fragment.getFragmentId()) << ", "
                  << "isLastFragment: " << static_cast<int>(fragment.getIsLastFragment()) << std::endl;
        #endif
        // Check if this is a single message (non-fragmented)
        if (fragment.getIsFragment() == 0 && fragment.getIsLastFragment() == 1) {
            #ifdef DEBUG_MODE
            std::cout << "Received a non-fragmented message of size: " << bytesRead << " bytes." << std::endl;
            #endif
            return fragment; // Return immediately, as no reassembly is needed
        }
        #ifdef DEBUG_MODE
        // Fragmented message handling
        std::cout << "Received fragment " << static_cast<int>(fragment.getFragmentId()) << " of the message." << std::endl;
        #endif
        // Check fragment ordering
        if (fragment.getFragmentId() != fragmentId) {
            throw AlServiceException("Fragment out of order", PrimitiveError::FragmentOutOfOrder);
        }

        // Append fragment payload to full payload
        payload.insert(payload.end(), fragment.getPayload().begin(), fragment.getPayload().end());

        // Store source and destination MAC addresses from the first fragment
        if (fragmentId == 0) {
            message.setSourceAlMacAddress(fragment.getSourceAlMacAddress());
            message.setDestinationAlMacAddress(fragment.getDestinationAlMacAddress());
        }

        // Check if this is the last fragment
        receivingFragments = (fragment.getIsLastFragment() == 0);
        fragmentId++;
    }

    // Set the assembled payload on the AlServiceDataUnit object
    message.setPayload(payload);
    #ifdef DEBUG_MODE
    std::cout << "Reassembled message received with total payload size: " << payload.size() << " bytes." << std::endl;
    #endif
    return message;
}


