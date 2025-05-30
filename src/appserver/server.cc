#include "server.h"
#include "../common/common.h" // Asegúrate de que esta línea esté al principio
#include "messages.h"
#include "../utils/convert_data.h"


asio::io_context io;

void handle_signal(const asio::error_code& error, int signal_number) {
    if (!error) {
        std::cout << "[INFO] Signal " << signal_number << " received, stopping server...\n";
        io.stop();
    }
}

bool Server::validate_signature(int client_id, json data) {

    std::vector<unsigned char> signature_bin = hex_string_to_bin(data["signature_hex"]);
    std::vector<unsigned char> public_key_bin = hex_string_to_bin(data["public_key_hex"]);
    std::vector<unsigned char> long_term_public_key_bin = hex_string_to_bin(data["long_term_public_key_hex"]);

    if (crypto_sign_verify_detached(signature_bin.data(), public_key_bin.data(), public_key_bin.size(), long_term_public_key_bin.data()) != 0) {
        std::cerr << "[Error] Invalid signature from Client #" << client_id << "\n";
        client_sockets[client_id]->close();
        client_sockets.erase(client_id); //Todo, handle this better
        return false;
    }

    SessionKeysAsymetric session_keys_asymetric;
    session_keys_asymetric_map.insert({client_id, session_keys_asymetric});
    session_keys_symetric_map.insert({client_id, SessionKeysSymetric(session_keys_asymetric.public_key, session_keys_asymetric.private_key, public_key_bin, true)}); 

    std::cout << "[Server] Validated signature from Client #" << client_id << "\n";

    return true;
}

void Server::manage_message_from_client(std::string message, std::shared_ptr<tcp::socket> socket, int client_id) {
    json data;
    std::string response;

    std::size_t fin_pos = message.find(END_OF_MESSAGE);
    if (fin_pos == std::string::npos) {
        std::cerr << "[ERROR]: The " << END_OF_MESSAGE << " delimiter was not found in the response." << "\n";
        return;
    }

    std::string json_response = message.substr(0, fin_pos);
    try {
        data = json::parse(json_response);
    } catch (json::parse_error& e) {
        std::cerr << "[ERROR] Json could not be parsed: " << e.what() << "\n";
        return;
    }

    std::string json_message = message.substr(0, fin_pos);
    try {
        data = json::parse(json_message);
    } catch (json::parse_error& e) {
        std::cerr << "[ERROR] Json could not be parsed: " << e.what() << "\n";
    }

    if (data["method"] == "HelloFIUNAM") {
        std::cout << "[Server] Client #" << client_id << " - Received of a request to establish a secure connection\n";

        if (!validate_signature(client_id, data))
            return;        

        // ToDo, replace with actual server ID, send only hash
        response = get_whats_up_message("12345", get_nounce(), bin_to_hex_string(session_keys_asymetric_map[client_id].public_key, crypto_kx_PUBLICKEYBYTES),
                                bin_to_hex_string(session_keys_asymetric_map[client_id].long_term_public_key, crypto_sign_PUBLICKEYBYTES),
                                bin_to_hex_string(session_keys_asymetric_map[client_id].signature, crypto_sign_BYTES));
    }
    else if (data["method"] == "AgreeParams") {
        std::cout << "[Server] Client #" << client_id << " - Received of a parameters to establish a secure connection\n";

        if (data["algorithm"] == "ChaCha20") // ToDo, create a variable with the supported algorithms
            response = get_start_secure_conversartion_message("ok", get_nounce());
        else {
            client_sockets[client_id]->close();
            client_sockets.erase(client_id); //ToDo, handle this better
            std::cout << "[Server] Client #" << client_id << " - Closed connection due to unsupported algorithm: " << data["algorithm"] <<" \n";
        }
    }
    /*else if (data["method"] == "simple_message") {
        std::cout << "[Server] Client #" << client_id << " - Received simple message crypted: " << data["message"] << "\n";
        std::cout << "[Server] Client #" << client_id << " - Nounce: " << data["nounce"] << "\n";

        std::string msg_clearly = decrypt_message(session_keys_symetric_map[client_id].rx, hex_string_to_bin(data["message"]), hex_string_to_bin(data["nounce"]));
        std::cout << "[Server] Client #" << client_id << " - Decrypted message: " << msg_clearly << "\n";
        
        std::vector<unsigned char> nonce;
        std::string hardcode_msg = "is_all_ok"; // ToDo, replace with a coherent message
        std::vector<unsigned char> ciphertext = encrypt_message(session_keys_symetric_map[client_id].tx, hardcode_msg, nonce);
        std::string string_cipher_text = bin_to_hex_string(ciphertext.data(), ciphertext.size());
        std::string string_nonce = bin_to_hex_string(nonce.data(), nonce.size());

        response = get_simple_response(string_cipher_text, string_nonce); //ToDo, encrypt the whole message
    }
    else {
        std::cerr << "[Server] Client #" << client_id << " - Unknown message: " << data << "\n";
    }
   

    if (response.empty())
        return;

    asio::async_write(*socket, asio::buffer(response),
        [this, socket, client_id, response](const asio::error_code& ec, std::size_t /*length*//*) {
            if (!ec) {
                std::cout << "[Server] Client #" << client_id << " - Response sent: " << response << "\n";
                handle_client(socket, client_id);
            } else {
                std::cerr << "[Server] Client #" << client_id << " - Write error: " << ec.message() << "\n";
            }
        });
}*/

    
    else if (data["method"] == "simple_message") {
        std::cout << "[Server] Client #" << client_id << " - Received simple message crypted: " << data["message"] << "\n";
        std::cout << "[Server] Client #" << client_id << " - Nounce: " << data["nounce"] << "\n";

        std::string msg_clearly; 
        
    /*//--- MODIFICACION PARA SIMULAR ATAQUE ---
        std::vector<unsigned char> received_ciphertext = hex_string_to_bin(data["message"]);
        std::vector<unsigned char> received_nonce = hex_string_to_bin(data["nounce"]);

        // Simular Tampering: Cambiar un byte del ciphertext
        // Esto debería causar que la autenticación falle en decrypt_message
        if (!received_ciphertext.empty()) {
            std::cout << "[Server][TEST] Tampering with received ciphertext for testing purposes..." << std::endl;
            // Invierte el primer byte del ciphertext.
            received_ciphertext[0] = ~received_ciphertext[0];}

        // Llamada a la nueva decrypt_message con el mensaje POTENCIALMENTE ALTERADO
        if (!decrypt_message(session_keys_symetric_map[client_id].rx, 
                             received_ciphertext, // ¡Pasamos el ciphertext alterado aquí!
                             received_nonce, 
                             msg_clearly)) {
            std::cerr << "[Server] Client #" << client_id << " - [ANTI-TAMPERING] Authentication failed for simple_message. Closing connection." << "\n";
            socket->close(); 
            return; 
        }
        std::cout << "[Server] Client #" << client_id << " - Decrypted message: " << msg_clearly << "\n";
    
    //--- MODIFICACION PARA SIMULAR ATAQUE ---*/

      // LLamada a la nueva decrypt_message y CHEQUEO DE SU RETORNO para autenticación
        if (!decrypt_message(session_keys_symetric_map[client_id].rx, // Usamos la clave de recepción
                             hex_string_to_bin(data["message"]), 
                             hex_string_to_bin(data["nounce"]), 
                             msg_clearly)) {
            // Si decrypt_message devuelve 'false', la autenticación falló.
            // Esto es una detección de Message Tampering.
            std::cerr << "[Server] Client #" << client_id << " - [ANTI-TAMPERING] Authentication failed for simple_message. Closing connection." << "\n";
            // ¡ACCIÓN CRUCIAL! Cierra la conexión inmediatamente para mitigar el ataque.
            socket->close(); 
            return; // Detener el procesamiento de este cliente, ya que la sesión está comprometida.
        }
        std::cout << "[Server] Client #" << client_id << " - Decrypted message: " << msg_clearly << "\n";
        
        // AÑADIDO: El servidor también encripta su respuesta
        std::vector<unsigned char> nonce_server; // Nuevo nonce para el mensaje de respuesta del servidor
        std::string hardcode_msg = "is_all_ok"; // ToDo, reemplazar con un mensaje coherente
        
        // Cifra la respuesta del servidor usando su clave 'tx' (transmisión)
        std::vector<unsigned char> ciphertext_server = encrypt_message(session_keys_symetric_map[client_id].tx, hardcode_msg, nonce_server);
        std::string string_cipher_text_server = bin_to_hex_string(ciphertext_server.data(), ciphertext_server.size());
        std::string string_nonce_server = bin_to_hex_string(nonce_server.data(), nonce_server.size());

        response = get_simple_response(string_cipher_text_server, string_nonce_server); // ToDo, encriptar todo el mensaje si es necesario, pero el contenido ya va cifrado
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
                } else {
                    std::cerr << "[Server] Client #" << client_id << " - Read error: " << ec.message() << "\n";
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

