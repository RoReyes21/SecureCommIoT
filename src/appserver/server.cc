#include "server.h"

asio::io_context io;

void handle_signal(const asio::error_code& error, int signal_number) {
    if (!error) {
        std::cout << "[INFO] Signal " << signal_number << " received, stopping server...\n";
        io.stop();
    }
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

                    std::string response = "msg_response";
                    response += END_OF_MESSAGE;
                    asio::async_write(*socket, asio::buffer(response),
                        [this, socket, client_id, response](const asio::error_code& ec, std::size_t /*length*/) {
                            if (!ec) {
                                std::cout << "[Server] Client #" << client_id << " - Response sent: " << response << "\n";
                                handle_client(socket, client_id);
                            } else {
                                std::cerr << "[Server] Client #" << client_id << " - Write error: " << ec.message() << "\n";
                            }
                        });
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
