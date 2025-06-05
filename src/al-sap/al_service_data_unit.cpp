#include "al_service_data_unit.h"
#include "al_service_exception.h"
#include "al_service_utils.h"

// is fragment + is last fragment + fragment id
#define FRAGMENTS_SIZE 3
// Check minimum size (4 bytes for size, 6 bytes each for source and destination MAC, plus 3 bytes for flags and fragment ID)
#define MIN_PACKET_SIZE 19

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

    // Calculate SDU size
    uint32_t packet_size = sourceAlMacAddress.size() + destinationAlMacAddress.size() + FRAGMENTS_SIZE + payload.size();

    // put 32bit size as 8bit
    serializedData = convert_u32_into_bytes(packet_size);

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

    if (data.size() < MIN_PACKET_SIZE) {
        throw AlServiceException("Insufficient data to deserialize AlServiceDataUnit", PrimitiveError::DeserializationError);
    }

    auto data_raw = remove_length_delimited_part(data);

    // Extract MAC addresses
    std::copy(data_raw.begin(), data_raw.begin() + 6, sourceAlMacAddress.begin());
    std::copy(data_raw.begin() + 6, data_raw.begin() + 12, destinationAlMacAddress.begin());

    // Extract fragment information, ensuring correct byte interpretation
    isFragment = static_cast<uint8_t>(data_raw[12]);
    isLastFragment = static_cast<uint8_t>(data_raw[13]);
    fragmentId = static_cast<uint8_t>(data_raw[14]);
    #ifdef DEBUG_MODE
    // Debugging output to confirm correct interpretation of flags
    std::cout << "Deserialized Fragment Information - isFragment: " << static_cast<int>(isFragment)
              << ", isLastFragment: " << static_cast<int>(isLastFragment)
              << ", fragmentId: " << static_cast<int>(fragmentId) << std::endl;
    #endif
    // Extract Payload
    payload.assign(data_raw.begin() + 15, data_raw.end());
}
