#ifndef AL_SERVICE_EXCEPTION_H
#define AL_SERVICE_EXCEPTION_H

#include <stdexcept>
#include <string>

// Enum representing different errors during primitive operation
//some of them may be are not used yet but the value has beer reserved for future use
enum class PrimitiveError {
    RequestFailed,            ///< Failed to send a request (e.g., send() failed).
    IndicationFailed,         ///< Failed to receive a message (e.g., recv() failed).
    ConnectionFailed,         ///< Failed to connect to the Unix socket.
    SocketCreationFailed,     ///< Failed to create the Unix socket.
    SocketClosed,             ///< The socket was closed or is unavailable.
    InvalidMessage,           ///< Received an invalid or incomplete message.
    Timeout,                  ///< Operation timed out.
    ServiceNotRegistered,     ///< Service not registered.
    SerializationError,       ///< Error during serialization
    DeserializationError,     ///< Error during deserialization
    UnknownError,             ///< An unspecified or unknown error occurred.
    RegistrationError,         ///< Registration was not succesflu
    FragmentOutOfOrder       //fragementation failure
};

// Custom exception class for AlServiceAccessPoint, take advantage of standard exception handling while also providing custom behavior.
class AlServiceException : public std::runtime_error {
public:
    // This constructor initializes the exception with a custom error message (message) and a PrimitiveError value (error).
    // The message parameter is passed to the base class (std::runtime_error), allowing AlServiceException to store and later return the error message when what() is called.
    // The PrimitiveError parameter (error) is stored in a private member variable, which represents a specific error code or type relevant to the application.
    
    
	/**!
	 * @brief Constructor for AlServiceException.
	 *
	 * Initializes a new instance of the AlServiceException class with a specified error message and error type.
	 *
	 * @param[in] message A string representing the error message.
	 * @param[in] Error A PrimitiveError object representing the error type.
	 */
	AlServiceException(const std::string& message, PrimitiveError Error);

    // Function to retrieve the PrimitiveReceipt value
    
	/**!
	 * @brief Retrieves the primitive error associated with the service exception.
	 *
	 * This function provides access to the underlying primitive error code that
	 * caused the service exception to be thrown. It is useful for debugging and
	 * logging purposes to understand the specific error condition.
	 *
	 * @returns The primitive error code as a PrimitiveError object.
	 *
	 * @note This function does not modify any member variables and is thread-safe.
	 */
	PrimitiveError getPrimitiveError() const;

private:
    PrimitiveError error;
};

#endif // AL_SERVICE_EXCEPTION_H
