#include "client.h"

#include "../common/common.h"
#include "../utils/convert_data.h"
#include "messages.h"

/**
 * @brief The function checks if the response from the server is valid, checks the method and parameters, save de important parameters for communication.
 * 
 * @param response 
 * @return true If the response is valid, 
 * @return false If the response is not valid
 */
bool is_valid_response_from_server(std::string response) {
    bool is_valid = false;

    std::size_t fin_pos = response.find(END_OF_MESSAGE);
    if (fin_pos == std::string::npos) {
        std::cerr << "[ERROR]: The " << END_OF_MESSAGE << " delimiter was not found in the response." << "\n";
        return is_valid;
    }

    std::string json_response = response.substr(0, fin_pos);
    json data;
    try {
        data = json::parse(json_response);
    } catch (json::parse_error& e) {
        std::cerr << "[ERROR] Json could not be parsed: " << e.what() << "\n";
        return is_valid;
    }

    if (data["method"] == "WhatsUpFIUNAM") {
        std::cout << "Server ID: " << data["server_ID"] << "\n";
        std::cout << "Server nounce: " << data["nounce"] << "\n";
        //std::cout << "Signature: " << data["signature"] << "\n";
        // ToDo, verify signature, verify all parameters
        is_valid = true;
    }
    else if (data["method"] == "StartConversation") {
        std::cout << "[Client] Server agreed to the parameters" << "\n";
        std::cout << "Server simetric key: " << data["symetric_key"] << "\n";
        std::cout << "Server nounce: " << data["nounce"] << "\n";
        //ToDo, save symetric key, etc. verify all parameters
        is_valid = true;
    }
    else if (data["method"] == "conn_continue") {
        is_valid = true;
    }

    return is_valid;
}

bool Client::establish_secure_connection_with_server() {

    std::string message, response;

    std::cout << "[Client] Starting hand shake to stablish secure connection with server" << "\n";

    // ToDo, replace with actual device ID, send only hash
    message = get_hello_message("12345", get_nounce(), bin_to_hex_string(session_keys_asymetric.public_key, crypto_kx_PUBLICKEYBYTES),
                                bin_to_hex_string(session_keys_asymetric.long_term_public_key, crypto_sign_PUBLICKEYBYTES),
                                bin_to_hex_string(session_keys_asymetric.signature, crypto_sign_BYTES));
    send_message(message);

    response = receive_message();
    if (!is_valid_response_from_server(response)) //ToDo, check if response is valid
        return false;

    message = get_agree_params_message("public_key", "P_256", get_nounce()); // ToDo, replace with real public key and algorithm
    send_message(message);

    response = receive_message();
    if (!is_valid_response_from_server(response)) //ToDo, check if response is valid
        return false;

    std::cout << "[Client] Encrypted connection established with server" << "\n";

    return true;
}

int main() {
    Client client("127.0.0.1", "8080");

    if (!client.establish_secure_connection_with_server()) {
        std::cerr << "[ERROR] Could not establish a secure connection with server." << "\n";
        return 1;
    }

    while (true) {
        std::cout << "[Client][Input] Write simple message: ";
        std::string msg_to_server;
        std::getline(std::cin, msg_to_server);

        client.send_message(get_simple_message(msg_to_server));

        std::string response = client.receive_message();
        std::cout << "[Client] Received response: " << response << "\n";

        if (!is_valid_response_from_server(response)) {
            std::cerr << "[ERROR] Invalid response from server." << "\n";
            break;
        }
    }

    client.stop_socket();

    return 0;
}