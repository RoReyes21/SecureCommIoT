#include "server.h"

#include "messages.h"
#include "../utils/convert_data.h"

asio::io_context io;

void handle_signal(const asio::error_code& error, int signal_number) {
    if (!error) {
        std::cout << "[INFO] Signal " << signal_number << " received, stopping server...\n";
        io.stop();
    }
}

bool Server::is_client_trusted(const std::string& public_key_hex, const std::string& long_term_public_key_hex) {
    return SessionKeysAsymetric::is_client_registered(public_key_hex, long_term_public_key_hex);
}

bool Server::authenticate_new_device(int client_id, json data) {
    std::string device_id = data.value("device_ID", "unknown");
    std::string public_key_hex = data.value("public_key_hex", "");
    std::string long_term_public_key_hex = data.value("long_term_public_key_hex", "");
    std::string auth_token = data.value("auth_token", "");
    
    return SessionKeysAsymetric::authenticate_and_register_device(
        device_id, public_key_hex, long_term_public_key_hex, auth_token);
}

bool Server::handle_device_registration_request(int client_id, json data, std::shared_ptr<tcp::socket> socket) {
    std::string device_id = data.value("device_ID", "unknown");
    
    std::cout << "[Server] Device registration request from " << device_id << "\n";
    
    if (authenticate_new_device(client_id, data)) {

        json approval_response = {
            {"method", "RegistrationApproved"},
            {"device_ID", device_id},
            {"status", "approved"},
            {"message", "Device successfully registered as trusted"}
        };
        
        std::string response = approval_response.dump() + END_OF_MESSAGE;
        asio::write(*socket, asio::buffer(response));
        
        std::cout << "[Server] Client #" << client_id << " - Device " << device_id << " registration APPROVED\n";
        return true;
    } else {

        json rejection_response = {
            {"method", "RegistrationRejected"},
            {"device_ID", device_id},
            {"status", "rejected"},
            {"message", "Device authentication failed"}
        };
        
        std::string response = rejection_response.dump() + END_OF_MESSAGE;
        asio::write(*socket, asio::buffer(response));
        
        std::cout << "[Server] Client #" << client_id << " Device " << device_id << " registration REJECTED\n";
        return false;
    }
}

bool Server::validate_signature(int client_id, json data) {
    std::vector<unsigned char> signature_bin = hex_string_to_bin(data["signature_hex"]);
    std::vector<unsigned char> public_key_bin = hex_string_to_bin(data["public_key_hex"]);
    std::vector<unsigned char> long_term_public_key_bin = hex_string_to_bin(data["long_term_public_key_hex"]);

    if (!is_client_trusted(data["public_key_hex"], data["long_term_public_key_hex"])) {
        std::cout << "[Server] Client #" << client_id << " not in trusted list, attempting authentication...\n";
        
        if (authenticate_new_device(client_id, data)) {
            std::cout << "[Server] Client #" << client_id << " successfully authenticated and added to trusted list\n";
        } else {
            std::cerr << "[Error] Client #" << client_id << " authentication FAILED - Connection rejected\n";
            client_sockets[client_id]->close();
            client_sockets.erase(client_id);
            return false;
        }
    }

    if (crypto_sign_verify_detached(signature_bin.data(), public_key_bin.data(), public_key_bin.size(), long_term_public_key_bin.data()) != 0) {
        std::cerr << "[Error] Invalid signature from Client #" << client_id << "\n";
        client_sockets[client_id]->close();
        client_sockets.erase(client_id);
        return false;
    }

    SessionKeysAsymetric session_keys_asymetric;
    session_keys_asymetric_map.insert({client_id, session_keys_asymetric});
    
    session_keys_symetric_map.insert({client_id, SessionKeysSymetric(
        session_keys_asymetric.public_key,
        session_keys_asymetric.private_key,
        public_key_bin, 
        true
    )}); 

    std::cout << "[Server] Client #" << client_id << " - TRUSTED CLIENT - Unique session keys generated\n";
    return true;
}

void Server::manage_message_from_client(std::string message, std::shared_ptr<tcp::socket> socket, int client_id) {

    std::size_t fin_pos = message.find(END_OF_MESSAGE);
    if (fin_pos == std::string::npos) {
        std::cerr << "[ERROR]: The " << END_OF_MESSAGE << " delimiter was not found in the response." << "\n";
        return;
    }

    std::string json_message = message.substr(0, fin_pos);
    json data;

    try {
        data = json::parse(json_message);
    } catch (json::parse_error& e) {
        std::cerr << "[ERROR] Json could not be parsed: " << e.what() << "\n";
    }

    std::string response;

    if (data["method"] == "HelloFIUNAM") {
        std::cout << "[Server] Client #" << client_id << " - Received of a request to establish a secure connection\n";

        if (!validate_signature(client_id, data))
            return;        

        response = get_whats_up_message("12345", get_nounce(), 
                                bin_to_hex_string(session_keys_asymetric_map[client_id].public_key, crypto_kx_PUBLICKEYBYTES),
                                bin_to_hex_string(session_keys_asymetric_map[client_id].long_term_public_key, crypto_sign_PUBLICKEYBYTES),
                                bin_to_hex_string(session_keys_asymetric_map[client_id].signature, crypto_sign_BYTES));
    }
    else if (data["method"] == "RequestRegistration") {

        std::cout << "[Server] Client #" << client_id << " - Device registration request\n";
        if (handle_device_registration_request(client_id, data, socket)) {
            std::cout << "[Server] Client #" << client_id << " - Registration completed, awaiting HelloFIUNAM\n";
            return;
        } else {
            client_sockets[client_id]->close();
            client_sockets.erase(client_id);
            return;
        }
    }
    else if (data["method"] == "AgreeParams") {
        std::cout << "[Server] Client #" << client_id << " - Received of a parameters to establish a secure connection\n";

        if (data["algorithm"] == "ChaCha20")
            response = get_start_secure_conversartion_message("ok", get_nounce());
        else {
            client_sockets[client_id]->close();
            client_sockets.erase(client_id);
            std::cout << "[Server] Client #" << client_id << " - Closed connection due to unsupported algorithm: " << data["algorithm"] <<" \n";
        }
    }
    else if (data["method"] == "simple_message") {
        std::cout << "[Server] Client #" << client_id << " - Received simple message crypted: " << data["message"] << "\n";
        std::cout << "[Server] Client #" << client_id << " - Nounce: " << data["nounce"] << "\n";

        std::string msg_clearly = decrypt_message(session_keys_symetric_map[client_id].rx, hex_string_to_bin(data["message"]), hex_string_to_bin(data["nounce"]));
        std::cout << "[Server] Client #" << client_id << " - Decrypted message: " << msg_clearly << "\n";
        
        std::vector<unsigned char> nonce;
        std::string hardcode_msg = "is_all_ok"; // ToDo, replace with a coherent message
        std::vector<unsigned char> ciphertext = encrypt_message(session_keys_symetric_map[client_id].tx, hardcode_msg, nonce);
        std::string string_cipher_text = bin_to_hex_string(ciphertext.data(), ciphertext.size());
        std::string string_nonce = bin_to_hex_string(nonce.data(), nonce.size());

        response = get_simple_response(string_cipher_text, string_nonce);
    }
    else {
        std::cerr << "[Server] Client #" << client_id << " - Unknown message: " << data << "\n";
    }

    if (response.empty())
        return;

    asio::async_write(*socket, asio::buffer(response),
        [this, socket, client_id, response](const asio::error_code& ec, std::size_t /*length*/) {
            if (!ec) {
                std::cout << "[Server] Client #" << client_id << " - Response sent: " << response << "\n";
                handle_client(socket, client_id);
            } else {
                std::cerr << "[Server] Client #" << client_id << " - Write error: " << ec.message() << "\n";
                session_keys_asymetric_map.erase(client_id);
                session_keys_symetric_map.erase(client_id);
                client_sockets.erase(client_id);
            }
        });
}

void Server::start_accept() {
    auto socket = std::make_shared<tcp::socket>(io_);
    acceptor_.async_accept(*socket,
        [this, socket](const asio::error_code& ec) {
            if (!ec) {
                int client_id = ++connection_counter_;
                auto remote = socket->remote_endpoint();
                std::cout << "[INFO] New connection #" << client_id
                          << " from " << remote.address().to_string()
                          << ":" << remote.port() << "\n";
                handle_client(socket, client_id);
            } else {
                std::cerr << "[ERROR] Accept failed: " << ec.message() << "\n";
            }
            start_accept();
        });
}

void Server::handle_client(std::shared_ptr<tcp::socket> socket, int client_id) {
        auto buffer = std::make_shared<asio::streambuf>();

        asio::async_read_until(*socket, *buffer, END_OF_MESSAGE,
            [this, socket, buffer, client_id](const asio::error_code& ec, std::size_t length) {
                if (!ec) {
                    std::istream is(buffer.get());
                    std::string message;
                    std::getline(is, message);
                    std::cout << "[Server] Client #" << client_id << " - Received: '" << message << "'\n";
                    client_sockets.insert({client_id, socket});

                    manage_message_from_client(message, socket, client_id);

                } else if (ec == asio::error::eof) {
                    std::cout << "[Server] Client #" << client_id << " disconnected\n";
                    session_keys_asymetric_map.erase(client_id);
                    session_keys_symetric_map.erase(client_id);
                    client_sockets.erase(client_id);
                } else {
                    std::cerr << "[Server] Client #" << client_id << " - Read error: " << ec.message() << "\n";
                    session_keys_asymetric_map.erase(client_id);
                    session_keys_symetric_map.erase(client_id);
                    client_sockets.erase(client_id);
                }
            });
    }

int main() {
    try {
        Server server(io, 8080);
        server.start();

        asio::signal_set signals(io, SIGINT, SIGTERM);
        signals.async_wait(handle_signal);

        std::cout << "[INFO] Server running on port 8080...\n";
        io.run();
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Exception: " << e.what() << "\n";
    }

    return 0;
}
