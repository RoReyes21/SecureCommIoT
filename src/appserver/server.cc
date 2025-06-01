#include "server.h"

#include "messages.h"
#include "../utils/convert_data.h"
#include "../utils/logger.h"

asio::io_context io;

void handle_signal(const asio::error_code& error, int signal_number) {
    if (!error) {
        LOG_INFO("Signal " + std::to_string(signal_number) + " received, stopping server...");
        CONSOLE_ONLY("[INFO] Server shutting down...");
        io.stop();
    }
}

bool Server::is_client_trusted(const std::string& public_key_hex, const std::string& long_term_public_key_hex) {
    bool is_trusted = SessionKeysAsymetric::is_client_registered(public_key_hex, long_term_public_key_hex);
    LOG_INFO("Client trust check - Result: " + std::string(is_trusted ? "TRUSTED" : "NOT_TRUSTED"));
    return is_trusted;
}

bool Server::authenticate_new_device(int client_id, json data) {
    std::string device_id = data.value("device_ID", "unknown");
    std::string public_key_hex = data.value("public_key_hex", "");
    std::string long_term_public_key_hex = data.value("long_term_public_key_hex", "");
    std::string auth_token = data.value("auth_token", "");
    
    LOG_INFO("Authenticating device: " + device_id + " for client #" + std::to_string(client_id));
    
    bool result = SessionKeysAsymetric::authenticate_and_register_device(
        device_id, public_key_hex, long_term_public_key_hex, auth_token);
    
    LOG_INFO("Device authentication result for " + device_id + ": " + 
             std::string(result ? "SUCCESS" : "FAILED"));
    
    return result;
}

bool Server::handle_device_registration_request(int client_id, json data, std::shared_ptr<tcp::socket> socket) {
    std::string device_id = data.value("device_ID", "unknown");
    
    LOG_COMMUNICATION("[Server] Device registration request from " + device_id);
    
    if (authenticate_new_device(client_id, data)) {

        json approval_response = {
            {"method", "RegistrationApproved"},
            {"device_ID", device_id},
            {"status", "approved"},
            {"message", "Device successfully registered as trusted"}
        };
        
        std::string response = approval_response.dump() + END_OF_MESSAGE;
        asio::write(*socket, asio::buffer(response));
        
        LOG_COMMUNICATION("[Server] Client #" + std::to_string(client_id) + 
                         " - Device " + device_id + " registration APPROVED");
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
        
        LOG_SECURITY("Client #" + std::to_string(client_id) + 
                    " Device " + device_id + " registration REJECTED");
        return false;
    }
}

bool Server::validate_signature(int client_id, json data) {
    std::vector<unsigned char> signature_bin = hex_string_to_bin(data["signature_hex"]);
    std::vector<unsigned char> public_key_bin = hex_string_to_bin(data["public_key_hex"]);
    std::vector<unsigned char> long_term_public_key_bin = hex_string_to_bin(data["long_term_public_key_hex"]);

    if (!is_client_trusted(data["public_key_hex"], data["long_term_public_key_hex"])) {
        LOG_SECURITY("Client #" + std::to_string(client_id) + 
                    " not in trusted list, attempting authentication...");
        
        if (authenticate_new_device(client_id, data)) {
            LOG_SECURITY("Client #" + std::to_string(client_id) + 
                        " successfully authenticated and added to trusted list");
        } else {
            LOG_ERROR("Client #" + std::to_string(client_id) + 
                     " authentication FAILED - Connection rejected");
            if (client_sockets.count(client_id)) {
                client_sockets[client_id]->close();
                client_sockets.erase(client_id);}
            return false;
        }
    }

    if (crypto_sign_verify_detached(signature_bin.data(), public_key_bin.data(), public_key_bin.size(), long_term_public_key_bin.data()) != 0) {
        LOG_ERROR("Invalid signature from Client #" + std::to_string(client_id));
        if (client_sockets.count(client_id)) {
            client_sockets[client_id]->close();
            client_sockets.erase(client_id);}
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

    LOG_COMMUNICATION("[Server] Client #" + std::to_string(client_id) + 
                     " - TRUSTED CLIENT - Unique session keys generated");
    return true;
}

void Server::manage_message_from_client(std::string message, std::shared_ptr<tcp::socket> socket, int client_id) {

    std::size_t fin_pos = message.find(END_OF_MESSAGE);
    if (fin_pos == std::string::npos) {
        LOG_ERROR("The " + std::string(END_OF_MESSAGE) + " delimiter was not found in the response.");
        return;
    }

    std::string json_message = message.substr(0, fin_pos);
    json data;

    try {
        data = json::parse(json_message);
    } catch (json::parse_error& e) {
        LOG_ERROR("Json could not be parsed: " + std::string(e.what()));
    }

    std::string response;

    if (data["method"] == "HelloFIUNAM") {
        LOG_COMMUNICATION("[Server] Client #" + std::to_string(client_id) + 
                         " - Received request to establish secure connection");

        if (!validate_signature(client_id, data))
            return;        

        response = get_whats_up_message("12345", get_nounce(), 
                                bin_to_hex_string(session_keys_asymetric_map[client_id].public_key, crypto_kx_PUBLICKEYBYTES),
                                bin_to_hex_string(session_keys_asymetric_map[client_id].long_term_public_key, crypto_sign_PUBLICKEYBYTES),
                                bin_to_hex_string(session_keys_asymetric_map[client_id].signature, crypto_sign_BYTES));
    }
    else if (data["method"] == "RequestRegistration") {

        LOG_INFO("Client #" + std::to_string(client_id) + " - Device registration request");
        if (handle_device_registration_request(client_id, data, socket)) {
            LOG_INFO("Client #" + std::to_string(client_id) + " - Registration completed, awaiting HelloFIUNAM");
            return;
        } else {return;}
    }
    else if (data["method"] == "AgreeParams") {
        LOG_COMMUNICATION("[Server] Client #" + std::to_string(client_id) + 
                         " - Received parameters to establish secure connection");

        if (data["algorithm"] == "ChaCha20")
            response = get_start_secure_conversartion_message("ok", get_nounce());
        else {
            if (client_sockets.count(client_id)) {
                client_sockets[client_id]->close();
                client_sockets.erase(client_id);}
            LOG_WARNING("Client #" + std::to_string(client_id) + 
                       " - Closed connection due to unsupported algorithm: " + 
                       std::string(data["algorithm"]));
            return;
        }
    }
    else if (data["method"] == "simple_message") {
        LOG_INFO("Client #" + std::to_string(client_id) + 
                " - Received simple message crypted: " + std::string(data["message"]));
        LOG_INFO("Client #" + std::to_string(client_id) + 
                " - Nounce: " + std::string(data["nounce"]));

        std::string msg_clearly;
        try {
            msg_clearly = decrypt_message(session_keys_symetric_map[client_id].rx, hex_string_to_bin(data["message"]), hex_string_to_bin(data["nounce"]));
            LOG_COMMUNICATION("[Server] Client #" + std::to_string(client_id) + 
                             " - Decrypted message: " + msg_clearly);
            
            std::vector<unsigned char> nonce_response; 
            std::string hardcode_msg = "is_all_ok";
            std::vector<unsigned char> ciphertext_response = encrypt_message(session_keys_symetric_map[client_id].tx, hardcode_msg, nonce_response);
            std::string string_cipher_text_response = bin_to_hex_string(ciphertext_response.data(), ciphertext_response.size());
            std::string string_nonce_response = bin_to_hex_string(nonce_response.data(), nonce_response.size());

            response = get_simple_response(string_cipher_text_response, string_nonce_response);

        } catch (const std::runtime_error& e) {
            LOG_SECURITY("SECURITY ALERT - Client #" + std::to_string(client_id) + 
                        " - " + std::string(e.what()));
            LOG_SECURITY("ANTI-TAMPERING - Closing connection with Client #" + 
                        std::to_string(client_id) + " due to message tampering.");
            
            if (client_sockets.count(client_id)) {
                socket->close(); 
                session_keys_asymetric_map.erase(client_id);
                session_keys_symetric_map.erase(client_id);
                client_sockets.erase(client_id);
            }
            return; 
        }
    }
    else {
        LOG_WARNING("Client #" + std::to_string(client_id) + 
                   " - Unknown message: " + data.dump());
    }

    if (response.empty())
        return;

    asio::async_write(*socket, asio::buffer(response),
        [this, socket, client_id, response](const asio::error_code& ec, std::size_t /*length*/) {
            if (!ec) {
                LOG_INFO("Client #" + std::to_string(client_id) + 
                        " - Response sent: " + response);
                handle_client(socket, client_id);
            } else {
                LOG_ERROR("Client #" + std::to_string(client_id) + 
                         " - Write error: " + ec.message());
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
                LOG_COMMUNICATION("[Server] New connection #" + std::to_string(client_id) +
                                 " from " + remote.address().to_string() +
                                 ":" + std::to_string(remote.port()));
                handle_client(socket, client_id);
            } else {
                LOG_ERROR("Accept failed: " + ec.message());
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
                    LOG_INFO("Client #" + std::to_string(client_id) + 
                            " - Received: '" + message + "'");
                    client_sockets.insert({client_id, socket});

                    manage_message_from_client(message, socket, client_id);

                } else if (ec == asio::error::eof) {
                    LOG_COMMUNICATION("[Server] Client #" + std::to_string(client_id) + 
                                     " disconnected");
                    session_keys_asymetric_map.erase(client_id);
                    session_keys_symetric_map.erase(client_id);
                    client_sockets.erase(client_id);
                } else {
                    LOG_ERROR("Client #" + std::to_string(client_id) + 
                             " - Read error: " + ec.message());
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

        CONSOLE_ONLY("[INFO] Server running on port 8080...");
        LOG_INFO("Server initialized and running on port 8080");
        io.run();
    } catch (const std::exception& e) {
        LOG_ERROR("Exception: " + std::string(e.what()));
        CONSOLE_ONLY("[ERROR] Server exception: " + std::string(e.what()));
    }

    return 0;
}
