#ifndef AL_SERVICE_DATA_UNIT_H
#define AL_SERVICE_DATA_UNIT_H

#include <iostream>
#include <iomanip>
#include <vector>
#include <array>
#include <cstdint>

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
    
	/**!
	 * @brief Constructor for the AlServiceDataUnit class.
	 *
	 * Initializes a new instance of the AlServiceDataUnit class.
	 *
	 * @note This constructor does not take any parameters and does not return any values.
	 */
	AlServiceDataUnit();

    // Setter and gettters for AL MAC addresses
    
	/**!
	 * @brief Sets the source AL MAC address.
	 *
	 * This function assigns the provided MAC address to the source AL.
	 *
	 * @param[in] mac The MAC address to be set as the source AL MAC address.
	 */
	void setSourceAlMacAddress(const MacAddress& mac);
    
	/**!
	 * @brief Sets the destination MAC address for the AL service.
	 *
	 * This function updates the destination MAC address used in the AL service data unit.
	 *
	 * @param[in] mac The MAC address to be set as the destination.
	 *
	 * @note Ensure the MAC address is valid before calling this function.
	 */
	void setDestinationAlMacAddress(const MacAddress& mac);
    
	/**!
	 * @brief Retrieves the source AL MAC address.
	 *
	 * This function returns a constant reference to the source AL MAC address.
	 *
	 * @returns A constant reference to the source AL MAC address.
	 */
	const MacAddress& getSourceAlMacAddress() const;
    
	/**!
	 * @brief Retrieves the destination AL MAC address.
	 *
	 * This function returns a constant reference to the MAC address
	 * that represents the destination AL (Access Layer) MAC address.
	 *
	 * @returns A constant reference to the destination AL MAC address.
	 */
	const MacAddress& getDestinationAlMacAddress() const;
    
    // Setter and getter for isFragment 
    
	/**!
	 * @brief Sets the fragment status for a given ID.
	 *
	 * This function updates the fragment status associated with the specified ID.
	 *
	 * @param[in] id The identifier for which the fragment status is to be set.
	 *
	 * @note Ensure that the ID is valid and within the expected range before calling this function.
	 */
	void setIsFragment(uint8_t id);
    
	/**!
	 * @brief Retrieves the fragment status.
	 *
	 * This function checks if the current data unit is a fragment.
	 *
	 * @returns uint8_t
	 * @retval 1 if the data unit is a fragment.
	 * @retval 0 if the data unit is not a fragment.
	 *
	 * @note This function does not modify any member variables.
	 */
	uint8_t getIsFragment() const;
    
    // Setter and getter for isLastFragment 
    
	/**!
	 * @brief Sets the last fragment status for a given ID.
	 *
	 * This function updates the status of whether the fragment with the specified ID is the last one.
	 *
	 * @param[in] id The identifier of the fragment to be updated.
	 *
	 * @note Ensure that the ID is valid and corresponds to an existing fragment.
	 */
	void setIsLastFragment(uint8_t id);
    
	/**!
	 * @brief Retrieves the status of the last fragment.
	 *
	 * This function checks if the current data unit is the last fragment in a sequence.
	 *
	 * @returns uint8_t
	 * @retval 1 if it is the last fragment.
	 * @retval 0 if it is not the last fragment.
	 *
	 * @note This function does not modify any member variables.
	 */
	uint8_t getIsLastFragment() const;
    
    // Setter and getter for Fragment ID
    
	/**!
	 * @brief Sets the fragment ID.
	 *
	 * This function assigns a new fragment ID to the data unit.
	 *
	 * @param[in] id The fragment ID to be set.
	 */
	void setFragmentId(uint8_t id);
    
	/**!
	 * @brief Retrieves the fragment ID.
	 *
	 * This function returns the fragment ID associated with the service data unit.
	 *
	 * @returns The fragment ID as an unsigned 8-bit integer.
	 */
	uint8_t getFragmentId() const;
        
    // Setter and getter Payload
    
	/**!
	 * @brief Sets the payload with the provided buffer.
	 *
	 * This function assigns the given buffer to the payload, replacing any existing data.
	 *
	 * @param[in] buffer A vector of unsigned char containing the data to be set as the payload.
	 *
	 * @note Ensure that the buffer contains valid data before calling this function.
	 */
	void setPayload(const std::vector<unsigned char>& buffer);
    
	/**!
	 * @brief Retrieves the payload data.
	 *
	 * This function returns a reference to a vector containing the payload data.
	 *
	 * @returns A reference to a vector of unsigned char representing the payload.
	 *
	 * @note The returned reference allows for direct modification of the payload data.
	 */
	std::vector<unsigned char>& getPayload();
    
	/**!
	 * @brief Appends data to the payload.
	 *
	 * This function takes a pointer to a data buffer and its length, appending the data to the existing payload.
	 *
	 * @param[in] data Pointer to the data buffer to be appended.
	 * @param[in] length Size of the data buffer in bytes.
	 *
	 * @note Ensure that the data buffer is valid and the length is correct to avoid buffer overflow.
	 */
	void appendToPayload(const unsigned char* data, size_t length);

    // Serialization and deserialization methods
    
	/**!
	 * @brief Serializes the data unit into a vector of bytes.
	 *
	 * This function converts the current state of the data unit into a sequence of bytes
	 * that can be stored or transmitted.
	 *
	 * @returns A vector of unsigned char containing the serialized data.
	 *
	 * @note Ensure that the data unit is in a valid state before serialization.
	 */
	std::vector<unsigned char> serialize() const;
    
	/**!
	 * @brief Deserializes the given data into a usable format.
	 *
	 * This function takes a vector of unsigned characters and processes it to extract meaningful information.
	 *
	 * @param[in] data A vector containing the serialized data.
	 *
	 * @note Ensure that the data vector is properly formatted before calling this function.
	 */
	void deserialize(const std::vector<unsigned char>& data);
    
};

#endif // AL_SERVICE_DATA_UNIT_H
