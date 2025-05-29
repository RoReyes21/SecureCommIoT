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

bool Server::validate_signature(int client_id, json data) {

    std::vector<unsigned char> signature_bin = hex_string_to_bin(data["signature_hex"]);
    std::vector<unsigned char> public_key_bin = hex_string_to_bin(data["public_key_hex"]);
    std::vector<unsigned char> long_term_public_key_bin = hex_string_to_bin(data["long_term_public_key_hex"]);

    if (crypto_sign_verify_detached(signature_bin.data(), public_key_bin.data(), public_key_bin.size(), long_term_public_key_bin.data()) != 0) {
        std::cerr << "[Error] Invalid signature from Client #" << client_id << "\n";
        client_sockets[client_id]->close();
        client_sockets.erase(client_id);
        return false;
    }

    SessionKeysAsymetric session_keys_asymetric;
    session_keys_asymetric_map.insert({client_id, session_keys_asymetric});
    session_keys_symetric_map.insert({client_id, SessionKeySymetric(session_keys_asymetric.public_key, session_keys_asymetric.private_key, public_key_bin)}); 

    std::cout << "[Server] Validated signature from Client #" << client_id << "\n";

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

        // ToDo, replace with actual server ID, send only hash
        response = get_whats_up_message("12345", get_nounce(), bin_to_hex_string(session_keys_asymetric_map[client_id].public_key, crypto_kx_PUBLICKEYBYTES),
                                bin_to_hex_string(session_keys_asymetric_map[client_id].long_term_public_key, crypto_sign_PUBLICKEYBYTES),
                                bin_to_hex_string(session_keys_asymetric_map[client_id].signature, crypto_sign_BYTES));
    }
    else if (data["method"] == "AgreeParams") {
        std::cout << "[Server] Client #" << client_id << " - Received of a parameters to establish a secure connection\n";
        // ToDo, verify data, validate all
        response = get_start_secure_conversartion_message("symmetric_key_example", "ok", get_nounce()); // ToDo, replace with symmetric key for this client ID, etc.
    }
    else if (data["method"] == "simple_message") {
        std::cout << "[Server] Client #" << client_id << " - Received simple message: " << data["message"] << "\n";
        response = get_simple_response();
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
