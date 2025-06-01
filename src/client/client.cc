#include "client.h"
#include "../utils/hash_utils.h"
#include "../common/common.h"
#include "../utils/convert_data.h"
#include "../utils/logger.h"
#include "messages.h"

bool Client::validate_signature(json data) {

    std::vector<unsigned char> signature_bin = hex_string_to_bin(data["signature_hex"]);
    std::vector<unsigned char> public_key_bin = hex_string_to_bin(data["public_key_hex"]);
    std::vector<unsigned char> long_term_public_key_bin = hex_string_to_bin(data["long_term_public_key_hex"]);

    if (crypto_sign_verify_detached(signature_bin.data(), public_key_bin.data(), public_key_bin.size(), long_term_public_key_bin.data()) != 0) {
        LOG_ERROR("Invalid signature from Server");
        CONSOLE_ONLY("[Client] ✗ Server signature verification failed");
        return false;
    }

    SessionKeysSymetric skeysim(session_keys_asymetric.public_key, session_keys_asymetric.private_key, public_key_bin, false);
    session_keys_symetric = skeysim;

    LOG_INFO("Server signature validated successfully");
    CONSOLE_ONLY("[Client] ✓ Server authenticated");

    return true;
}

bool Client::is_valid_response_from_server(std::string response) {
    bool is_valid = false;

    std::size_t fin_pos = response.find(END_OF_MESSAGE);
    if (fin_pos == std::string::npos) {
        LOG_ERROR("The " + std::string(END_OF_MESSAGE) + " delimiter was not found in the response.");
        if (response.empty()) {
            LOG_ERROR("Received empty response, server might have closed the connection.");
            CONSOLE_ONLY("[Client] ✗ Connection lost with server");
        }
        return is_valid;
    }

    std::string json_response = response.substr(0, fin_pos);
    json data;
    try {
        data = json::parse(json_response);
    } catch (json::parse_error& e) {
        LOG_ERROR("Json could not be parsed: " + std::string(e.what()));
        return is_valid;
    }

    LOG_INFO("Processing server response method: " + std::string(data["method"]));

    if (data["method"] == "WhatsUpFIUNAM") {
        if (validate_signature(data))
            is_valid = true;
    }
    else if (data["method"] == "StartConversation") {
        LOG_INFO("Server agreed to parameters - nounce: " + std::string(data["nounce"]));
        CONSOLE_ONLY("[Client] ✓ Secure channel established");
        is_valid = true;
    }
    else if (data["method"] == "conn_continue") {
        try {
            std::string msg_clearly = decrypt_message(session_keys_symetric.rx, hex_string_to_bin(data["message"]), hex_string_to_bin(data["nounce"]));
            LOG_COMMUNICATION("Decrypted server response: " + msg_clearly);
            CONSOLE_ONLY("[Server]: " + msg_clearly);
            is_valid = true;
        } catch (const std::runtime_error& e) {
            LOG_SECURITY("SECURITY ALERT - Decryption failed for server message: " + std::string(e.what()));
            LOG_SECURITY("Server message might have been tampered with. Closing connection.");
            CONSOLE_ONLY("[Client] ✗ Security violation detected - closing connection");
            is_valid = false;
        }
    }

    return is_valid;
}

std::string Client::get_random_nonce() {
    unsigned char random_bytes[16];
    randombytes_buf(random_bytes, sizeof(random_bytes));
    return bin_to_hex_string(random_bytes, sizeof(random_bytes));
}

bool Client::establish_secure_connection_with_server() {
    std::string message, response;

    CONSOLE_ONLY("[Client] Establishing secure connection...");
    LOG_INFO("Starting handshake to establish secure connection with server");

    message = get_hello_message(device_id, get_random_nonce(), bin_to_hex_string(session_keys_asymetric.public_key, crypto_kx_PUBLICKEYBYTES),
                                bin_to_hex_string(session_keys_asymetric.long_term_public_key, crypto_sign_PUBLICKEYBYTES),
                                bin_to_hex_string(session_keys_asymetric.signature, crypto_sign_BYTES));
    
    LOG_INFO("Sending HelloFIUNAM message to server");
    send_message(message);

    response = receive_message();
    
    if (response.find("authentication FAILED") != std::string::npos || 
        response.find("NOT TRUSTED") != std::string::npos ||
        response.empty()) {
        
        CONSOLE_ONLY("[Client] Device not trusted, requesting registration...");
        LOG_INFO("Device not trusted, attempting registration");
        
        message = get_registration_request_message(device_id, 
                                                 bin_to_hex_string(session_keys_asymetric.public_key, crypto_kx_PUBLICKEYBYTES),
                                                 bin_to_hex_string(session_keys_asymetric.long_term_public_key, crypto_sign_PUBLICKEYBYTES),
                                                 "DEV_TOKEN_12345");
        send_message(message);
        
        response = receive_message();
        LOG_INFO("Registration response received: " + response);
        
        if (response.find("RegistrationApproved") != std::string::npos) {
            CONSOLE_ONLY("[Client] ✓ Registration approved! Retrying handshake...");
            LOG_INFO("Device registration approved, retrying handshake");
            
            message = get_hello_message(device_id, get_random_nonce(), bin_to_hex_string(session_keys_asymetric.public_key, crypto_kx_PUBLICKEYBYTES),
                                        bin_to_hex_string(session_keys_asymetric.long_term_public_key, crypto_sign_PUBLICKEYBYTES),
                                        bin_to_hex_string(session_keys_asymetric.signature, crypto_sign_BYTES));
            send_message(message);
            response = receive_message();
        } else {
            CONSOLE_ONLY("[Client] ✗ Registration rejected");
            LOG_ERROR("Device registration rejected");
            return false;
        }
    }

    if (!is_valid_response_from_server(response)) {
        LOG_ERROR("Invalid response during handshake: " + response);
        CONSOLE_ONLY("[Client] ✗ Handshake failed");
        return false;
    }

    LOG_INFO("Sending parameter agreement (ChaCha20)");
    message = get_agree_params_message("ChaCha20", get_random_nonce());
    send_message(message);

    response = receive_message();
    if (!is_valid_response_from_server(response)) {
        LOG_ERROR("Invalid response during parameter agreement: " + response);
        CONSOLE_ONLY("[Client] ✗ Parameter agreement failed");
        return false;
    }

    CONSOLE_ONLY("[Client] ✓ Secure connection established with device: " + device_id);
    LOG_INFO("Encrypted connection established with server for device: " + device_id);
    return true;
}

int main(int argc, char* argv[]) {
    std::string device_id = "client1";
    
    if (argc > 1) {
        device_id = argv[1];
    } else {
        // Generar device_id único basado en timestamp si no se proporciona
        auto now = std::chrono::system_clock::now();
        auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
        device_id = "client_" + std::to_string(timestamp % 10000);
    }
    
    CONSOLE_ONLY("[Client] Starting client with device ID: " + device_id);
    LOG_INFO("Client initialized with device ID: " + device_id);
    
    Client client("127.0.0.1", "8080", device_id);

    if (!client.establish_secure_connection_with_server()) {
        CONSOLE_ONLY("[Client] ✗ Failed to establish secure connection");
        LOG_ERROR("Could not establish a secure connection with server");
        return 1;
    }

    CONSOLE_ONLY("\n=== Secure Chat Started ===");
    CONSOLE_ONLY("Type your messages below (Ctrl+C to exit):");

    while (true) {
        std::cout << "\n[" + device_id + "] > ";
        std::string msg_to_server;
        std::getline(std::cin, msg_to_server);

        if (msg_to_server.empty()) continue;

        LOG_INFO("User input: " + msg_to_server);

        // Cálculo del hash del mensaje original
        std::vector<unsigned char> msg_bytes(msg_to_server.begin(), msg_to_server.end());
        std::string sha256_digest = sha256_hex(msg_bytes);

        LOG_INFO("Message SHA-256: " + sha256_digest);

        // Encriptar el mensaje
        std::vector<unsigned char> nonce;
        std::vector<unsigned char> ciphertext = encrypt_message(client.get_session_keys_symetric().tx, msg_to_server, nonce);

        std::string string_cipher_text = bin_to_hex_string(ciphertext.data(), ciphertext.size());
        std::string string_nonce = bin_to_hex_string(nonce.data(), nonce.size());

        LOG_INFO("Message encrypted - ciphertext: " + string_cipher_text);
        LOG_INFO("Encryption nonce: " + string_nonce);

        // Generar mensaje extendido con el hash
        json simple_msg_json = {
            {"method", "simple_message"},
            {"message", string_cipher_text},
            {"nounce", string_nonce},
            {"sha256", sha256_digest}
        };

        // Enviar
        LOG_INFO("Sending encrypted message to server");
        client.send_message(simple_msg_json.dump() + END_OF_MESSAGE);

        std::string response = client.receive_message();

        if (!client.is_valid_response_from_server(response)) {
            CONSOLE_ONLY("[Client] ✗ Security violation - connection terminated");
            LOG_ERROR("Exiting due to invalid or tampered server response");
            break; 
        }
    }

    LOG_INFO("Client shutting down");
    client.stop_socket();

    return 0;
}
