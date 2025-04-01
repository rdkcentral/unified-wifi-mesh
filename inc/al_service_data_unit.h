#ifndef AL_SERVICE_DATA_UNIT_H
#define AL_SERVICE_DATA_UNIT_H

#include <iostream>
#include <iomanip>
#include <vector>
#include <array>

//Used to store MacAddress as array
using MacAddress = std::array<uint8_t, 6>;

class AlServiceDataUnit {
private:
    MacAddress sourceAlMacAddress;        // Source MAC address (using std::array)
    MacAddress destinationAlMacAddress;   // Destination MAC address (using std::array)
    uint8_t isFragment;                   //indicates if the sdu is fragemented
    uint8_t isLastFragment;               //indicates if this is the last fragment
    uint8_t fragmentId;                   // Fragment ID number
    std::vector<unsigned char> payload;   // Buffer for storing payload binary data 

public:
    // Constructor
    AlServiceDataUnit();

    // Setter and gettters for AL MAC addresses
    void setSourceAlMacAddress(const MacAddress& mac);
    void setDestinationAlMacAddress(const MacAddress& mac);
    const MacAddress& getSourceAlMacAddress() const;
    const MacAddress& getDestinationAlMacAddress() const;
    
    // Setter and getter for isFragment 
    void setIsFragment(uint8_t id);
    uint8_t getIsFragment() const;
    
    // Setter and getter for isLastFragment 
    void setIsLastFragment(uint8_t id);
    uint8_t getIsLastFragment() const;
    
    // Setter and getter for Fragment ID
    void setFragmentId(uint8_t id);
    uint8_t getFragmentId() const;
        
    // Setter and getter Payload
    void setPayload(const std::vector<unsigned char>& buffer);
    std::vector<unsigned char>& getPayload();
    void appendToPayload(const unsigned char* data, size_t length);

    // Serialization and deserialization methods
    std::vector<unsigned char> serialize() const;
    void deserialize(const std::vector<unsigned char>& data);
    
};

#endif // AL_SERVICE_DATA_UNIT_H
