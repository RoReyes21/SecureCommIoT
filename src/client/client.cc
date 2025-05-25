#include "client.h"

void do_write(std::shared_ptr<tcp::socket> socket, const std::string& message) {
    asio::async_write(*socket, asio::buffer(message),
        [socket](const asio::error_code& ec, std::size_t length) {
            on_write(socket, ec, length);
        });
}

void on_write(std::shared_ptr<tcp::socket> socket, const asio::error_code& ec, std::size_t /*length*/) {
    if (!ec) {
        std::cout << "[Client] Message sent, awaiting reply..." << std::endl;
        do_read(socket); // Después de enviar, espera la respuesta
    } else {
        std::cerr << "Error on_write: " << ec.message() << std::endl;
    }
}

void do_read(std::shared_ptr<tcp::socket> socket) {
    auto buffer = std::make_shared<asio::streambuf>();
    asio::async_read_until(*socket, *buffer, '\n',
        [socket, buffer](const asio::error_code& ec, std::size_t length) {
            on_read(socket, buffer, ec, length);
        });
}

void on_read(std::shared_ptr<tcp::socket> socket, std::shared_ptr<asio::streambuf> buffer,
             const asio::error_code& ec, std::size_t length) {
    if (!ec) {
        std::istream is(buffer.get());
        std::string response;
        std::getline(is, response);
        
        std::cout << "[Client] Server response (" << length << " bytes): '" << response << "'" << std::endl;
        
        // Solicitar nuevo mensaje al usuario
        std::string message;
        std::cout << "Write a message: ";
        std::getline(std::cin, message);
        
        message += '\n';
        do_write(socket, message);
    } else if (ec == asio::error::eof) {
        std::cout << "[Client] Server closed connection" << std::endl;
    } else {
        std::cerr << "[Client] Error on_read: " << ec.message() << std::endl;
    }
}

void send_first_message(std::shared_ptr<tcp::socket> socket) {
    std::string message;
    std::cout << "Wirite a message: ";
    std::getline(std::cin, message);
    message += '\n';
    
    do_write(socket, message);
}

int main() {
    try {
        tcp::resolver resolver(io);
        auto endpoints = resolver.resolve("127.0.0.1", "8080");
        
        auto socket = std::make_shared<tcp::socket>(io);
        asio::connect(*socket, endpoints);
        
        std::cout << "Conectado al servidor. Escribe mensajes y presiona Enter.\n";
        
        send_first_message(socket);
        
        io.run();
    } catch (std::exception& e) {
        std::cerr << "Excepción: " << e.what() << std::endl;
    }
}