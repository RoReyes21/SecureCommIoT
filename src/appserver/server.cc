#include "server.h"

void handle_signal(const asio::error_code& error, int signal_number) {
    if (!error) {
        std::cout << "\n[INFO] Closing server for (" << signal_number << ") signal..." << std::endl;
        io.stop();
    }
}

void handle_client(std::shared_ptr<tcp::socket> socket, int client_id) {
    auto buffer = std::make_shared<asio::streambuf>();
    std::cout << "[Server] Client #" << client_id << " - Waiting message..." << std::endl;
    
    asio::async_read_until(*socket, *buffer, '\n',
        [socket, buffer, client_id](const asio::error_code& ec, std::size_t length) {
            on_read(socket, buffer, ec, length, client_id);
        });
}

void on_read(std::shared_ptr<tcp::socket> socket, std::shared_ptr<asio::streambuf> buffer,
             const asio::error_code& ec, std::size_t length, int client_id) {
    if (!ec) {
        std::istream is(buffer.get());
        std::string mensaje;
        std::getline(is, mensaje);
        
        std::cout << "[Server] Client #" << client_id << " sent (" << length << " bytes): '" << mensaje << "'" << std::endl;
        
        std::string respuesta = "Hello Client #" + std::to_string(client_id) + "!\n";
        std::cout << "[Server] Sending response #" << client_id << "..." << std::endl;
        
        asio::async_write(*socket, asio::buffer(respuesta),
            [socket, client_id](const asio::error_code& ec, std::size_t length) {
                on_write(socket, ec, length, client_id);
            });
    } else if (ec == asio::error::eof) {
        std::cout << "[Server] Client #" << client_id << " was disconnected" << std::endl;
    } else {
        std::cerr << "[Server] Client #" << client_id << " - Error while reading: " << ec.message() << std::endl;
    }
}

void on_write(std::shared_ptr<tcp::socket> socket, const asio::error_code& error_code, std::size_t /*length*/, int client_id) {
    if (!error_code) {
        std::cout << "[Server] Client #" << client_id << " - Response sending, waiting next message..." << std::endl;
        handle_client(socket, client_id);
    } else {
        std::cerr << "[Server] Client #" << client_id << " - Error while sending response: " << error_code.message() << std::endl;
    }
}

void on_accept(std::shared_ptr<tcp::socket> socket, tcp::acceptor& acceptor, const asio::error_code& error_code) {
    if (!error_code) {
        int client_id = ++connection_counter;
        
        auto remote_endpoint = socket->remote_endpoint();
        std::cout << "[INFO] New connection #" << client_id 
                  << " from " << remote_endpoint.address().to_string() 
                  << ":" << remote_endpoint.port() << std::endl;
        
        handle_client(socket, client_id);
    } else {
        std::cerr << "[ERROR] Error accepting connection: " << error_code.message() << std::endl;
    }
    
    start_accept(acceptor);
}

void start_accept(tcp::acceptor& acceptor) {
    auto socket = std::make_shared<tcp::socket>(io);
    acceptor.async_accept(*socket,
        [socket, &acceptor](const asio::error_code& ec) {
            on_accept(socket, acceptor, ec);
        });
}

int main() {
    try {
        tcp::acceptor acceptor(io, tcp::endpoint(tcp::v4(), 8080));
        
        asio::signal_set signals(io, SIGINT, SIGTERM);
        signals.async_wait(handle_signal);
        
        std::cout << "[INFO] Initializing server, listening in port 8080..." << std::endl;
        start_accept(acceptor);
        io.run();
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}