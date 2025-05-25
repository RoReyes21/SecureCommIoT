#include "client.h"

void do_write(std::shared_ptr<tcp::socket> socket, const std::string& message) {
    asio::async_write(*socket, asio::buffer(message),
        [socket](const asio::error_code& ec, std::size_t length) {
            on_write(socket, ec, length);
        });
}

void on_write(std::shared_ptr<tcp::socket> socket, const asio::error_code& ec, std::size_t /*length*/) {
    if (!ec) {
        std::cout << "[Cliente] Mensaje enviado, esperando respuesta..." << std::endl;
        do_read(socket); // Después de enviar, espera la respuesta
    } else {
        std::cerr << "Error escribiendo: " << ec.message() << std::endl;
    }
}

void do_read(std::shared_ptr<tcp::socket> socket) {
    auto buffer = std::make_shared<std::array<char, 1024>>();
    socket->async_read_some(asio::buffer(*buffer),
        [socket, buffer](const asio::error_code& ec, std::size_t length) {
            on_read(socket, buffer, ec, length);
        });
}

void on_read(std::shared_ptr<tcp::socket> socket, std::shared_ptr<std::array<char, 1024>> buffer,
             const asio::error_code& ec, std::size_t length) {
    if (!ec) {
        std::string respuesta(buffer->data(), length);
        std::cout << "[Cliente] Recibido del servidor: '" << respuesta << "'" << std::endl;
        
        // Solicitar nuevo mensaje al usuario
        std::string mensaje;
        std::cout << "Tu mensaje: ";
        std::getline(std::cin, mensaje);
        mensaje += '\n';
        
        do_write(socket, mensaje);
    } else {
        std::cerr << "Error leyendo: " << ec.message() << std::endl;
    }
}

void send_first_message(std::shared_ptr<tcp::socket> socket) {
    std::string mensaje;
    std::cout << "Tu mensaje: ";
    std::getline(std::cin, mensaje);
    mensaje += '\n';
    
    do_write(socket, mensaje);
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