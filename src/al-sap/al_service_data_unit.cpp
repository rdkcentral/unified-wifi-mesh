#include "al_service_data_unit.h"
#include "al_service_exception.h"

AlServiceDataUnit::AlServiceDataUnit() {
    sourceAlMacAddress.fill(0);
    destinationAlMacAddress.fill(0);
    isFragment = 0;
    isLastFragment = 0;
    fragmentId = 0;
    payload.resize(1500, 0);
}

// Set and get MAC addresses
void AlServiceDataUnit::setSourceAlMacAddress(const MacAddress& mac) { sourceAlMacAddress = mac; }
void AlServiceDataUnit::setDestinationAlMacAddress(const MacAddress& mac) { destinationAlMacAddress = mac; }
const MacAddress& AlServiceDataUnit::getSourceAlMacAddress() const { return sourceAlMacAddress; }
const MacAddress& AlServiceDataUnit::getDestinationAlMacAddress() const { return destinationAlMacAddress; }

// Set and get isFragment flag
void AlServiceDataUnit::setIsFragment(uint8_t id) { isFragment = id; }
uint8_t AlServiceDataUnit::getIsFragment() const { return isFragment; }

// Set and get isLastFragment flag
void AlServiceDataUnit::setIsLastFragment(uint8_t id) { isLastFragment = id; }
uint8_t AlServiceDataUnit::getIsLastFragment() const { return isLastFragment; }

// Set and get Fragment ID
void AlServiceDataUnit::setFragmentId(uint8_t id) { fragmentId = id; }
uint8_t AlServiceDataUnit::getFragmentId() const { return fragmentId; }

// Set and get Payload
void AlServiceDataUnit::setPayload(const std::vector<unsigned char>& buffer) { payload = buffer; }
std::vector<unsigned char>& AlServiceDataUnit::getPayload() { return payload; }
void AlServiceDataUnit::appendToPayload(const unsigned char* data, size_t length) {
    payload.insert(payload.end(), data, data + length);
}

// Serialization method
std::vector<unsigned char> AlServiceDataUnit::serialize() const {
    std::vector<unsigned char> serializedData;

    // Add MAC addresses
    serializedData.insert(serializedData.end(), sourceAlMacAddress.begin(), sourceAlMacAddress.end());
    serializedData.insert(serializedData.end(), destinationAlMacAddress.begin(), destinationAlMacAddress.end());

    // Add fragment information
    serializedData.push_back(static_cast<uint8_t>(isFragment));      // Ensure isFragment is stored as a single byte
    serializedData.push_back(static_cast<uint8_t>(isLastFragment));  // Ensure isLastFragment is stored as a single byte
    serializedData.push_back(static_cast<uint8_t>(fragmentId));

    // Add Payload
    serializedData.insert(serializedData.end(), payload.begin(), payload.end());
    #ifdef DEBUG_MODE
    // Debugging output to confirm correct interpretation of flags
    std::cout << "Serialized Fragment Information - isFragment: " << static_cast<int>(isFragment)
              << ", isLastFragment: " << static_cast<int>(isLastFragment)
              << ", fragmentId: " << static_cast<int>(fragmentId) << std::endl;
    #endif

    return serializedData;
}

// Deserialization method
void AlServiceDataUnit::deserialize(const std::vector<unsigned char>& data) {
    // Check minimum size (6 bytes each for source and destination MAC, plus 3 bytes for flags and fragment ID)
    if (data.size() < 15) {
        throw AlServiceException("Insufficient data to deserialize AlServiceDataUnit", PrimitiveError::DeserializationError);
    }

    // Extract MAC addresses
    std::copy(data.begin(), data.begin() + 6, sourceAlMacAddress.begin());
    std::copy(data.begin() + 6, data.begin() + 12, destinationAlMacAddress.begin());

    // Extract fragment information, ensuring correct byte interpretation
    isFragment = static_cast<uint8_t>(data[12]);
    isLastFragment = static_cast<uint8_t>(data[13]);
    fragmentId = static_cast<uint8_t>(data[14]);
    #ifdef DEBUG_MODE
    // Debugging output to confirm correct interpretation of flags
    std::cout << "Deserialized Fragment Information - isFragment: " << static_cast<int>(isFragment)
              << ", isLastFragment: " << static_cast<int>(isLastFragment)
              << ", fragmentId: " << static_cast<int>(fragmentId) << std::endl;
    #endif
    // Extract Payload
    payload.assign(data.begin() + 15, data.end());
}
