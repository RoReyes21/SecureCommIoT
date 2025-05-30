#include "client.h"

#include "../common/common.h"
#include "../utils/convert_data.h"
#include "messages.h"

bool Client::validate_signature(json data) {

    std::vector<unsigned char> signature_bin = hex_string_to_bin(data["signature_hex"]);
    std::vector<unsigned char> public_key_bin = hex_string_to_bin(data["public_key_hex"]);
    std::vector<unsigned char> long_term_public_key_bin = hex_string_to_bin(data["long_term_public_key_hex"]);

    if (crypto_sign_verify_detached(signature_bin.data(), public_key_bin.data(), public_key_bin.size(), long_term_public_key_bin.data()) != 0) {
        std::cerr << "[Error] Invalid signature from Server" << "\n";
        return false;
    }

    SessionKeysSymetric skeysim(session_keys_asymetric.public_key, session_keys_asymetric.private_key, public_key_bin, false);
    session_keys_symetric = skeysim;

    std::cout << "[Server] Validated signature from Server" << "\n";

    return true;
}

/**
 * @brief The function checks if the response from the server is valid, checks the method and parameters, save de important parameters for communication.
 * 
 * @param response 
 * @return true If the response is valid, 
 * @return false If the response is not valid
 */
bool Client::is_valid_response_from_server(std::string response) {
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
        if (validate_signature(data))
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
        std::string  msg_clearly = decrypt_message(session_keys_symetric.rx, hex_string_to_bin(data["message"]), hex_string_to_bin(data["nounce"]));
        std::cout << "[Client] Decrypted message from server: " << msg_clearly << "\n";
        is_valid = true;
    }

    return is_valid;
}

bool Client::establish_secure_connection_with_server() {
    std::string message, response;

    std::cout << "[Client] Starting hand shake to stablish secure connection with server" << "\n";

    // Intentar conexión normal primero
    message = get_hello_message(device_id, get_nounce(), bin_to_hex_string(session_keys_asymetric.public_key, crypto_kx_PUBLICKEYBYTES),
                                bin_to_hex_string(session_keys_asymetric.long_term_public_key, crypto_sign_PUBLICKEYBYTES),
                                bin_to_hex_string(session_keys_asymetric.signature, crypto_sign_BYTES));
    send_message(message);

    response = receive_message();
    
    // Verificar si necesitamos registrarnos
    if (response.find("authentication FAILED") != std::string::npos || 
        response.find("NOT TRUSTED") != std::string::npos ||
        response.empty()) {
        
        std::cout << "[Client] Device not trusted, attempting registration...\n";
        
        // Solicitar registro explícito
        message = get_registration_request_message(device_id, 
                                                 bin_to_hex_string(session_keys_asymetric.public_key, crypto_kx_PUBLICKEYBYTES),
                                                 bin_to_hex_string(session_keys_asymetric.long_term_public_key, crypto_sign_PUBLICKEYBYTES),
                                                 "DEV_TOKEN_12345");
        send_message(message);
        
        response = receive_message();
        std::cout << "[Client] Registration response: " << response << "\n";
        
        if (response.find("RegistrationApproved") != std::string::npos) {
            std::cout << "[Client] ✓ Device registration approved! Retrying handshake...\n";
            
            // Reintentar handshake después del registro exitoso
            message = get_hello_message(device_id, get_nounce(), bin_to_hex_string(session_keys_asymetric.public_key, crypto_kx_PUBLICKEYBYTES),
                                        bin_to_hex_string(session_keys_asymetric.long_term_public_key, crypto_sign_PUBLICKEYBYTES),
                                        bin_to_hex_string(session_keys_asymetric.signature, crypto_sign_BYTES));
            send_message(message);
            response = receive_message();
        } else {
            std::cout << "[Client] ✗ Device registration rejected\n";
            return false;
        }
    }

    if (!is_valid_response_from_server(response)) {
        std::cout << "[Client] Invalid response during handshake: " << response << "\n";
        return false;
    }

    message = get_agree_params_message("ChaCha20", get_nounce());
    send_message(message);

    response = receive_message();
    if (!is_valid_response_from_server(response)) {
        std::cout << "[Client] Invalid response during parameter agreement: " << response << "\n";
        return false;
    }

    std::cout << "[Client] ✓ Encrypted connection established with server for device: " << device_id << "\n";
    return true;
}

int main(int argc, char* argv[]) {
    std::string device_id = "client1"; // Valor por defecto
    
    // Si se proporciona device ID como argumento, usarlo
    if (argc > 1) {
        device_id = argv[1];
    }
    
    std::cout << "[Client] Using device ID: " << device_id << "\n";
    
    Client client("127.0.0.1", "8080", device_id);

    if (!client.establish_secure_connection_with_server()) {
        std::cerr << "[ERROR] Could not establish a secure connection with server." << "\n";
        return 1;
    }

    while (true) {
        std::cout << "[Client][Input] Write simple message: ";
        std::string msg_to_server;
        std::getline(std::cin, msg_to_server);

        std::vector<unsigned char> nonce;
        std::vector<unsigned char> ciphertext = encrypt_message(client.get_session_keys_symetric().tx, msg_to_server, nonce);

        std::string string_cipher_text = bin_to_hex_string(ciphertext.data(), ciphertext.size());
        std::string string_nonce = bin_to_hex_string(nonce.data(), nonce.size());
        client.send_message(get_simple_message(string_cipher_text, string_nonce)); //Todo, encrypt the whole message

        std::string response = client.receive_message();
        std::cout << "[Client] Received response: " << response << "\n";

        if (!client.is_valid_response_from_server(response)) {

    return 0;
}    }

    client.stop_socket();

    return 0;
}