#include "server.h"

void handle_signal(const asio::error_code& error, int signal_number) {
    if (!error) {
        std::cout << "\n[INFO] Closing server for (" << signal_number << ") signal..." << std::endl;
        io.stop();
    }
}

void handle_client(std::shared_ptr<tcp::socket> socket) {
    auto buffer = std::make_shared<asio::streambuf>();
    std::cout << "[Servidor] Esperando mensaje del cliente..." << std::endl;
    
    asio::async_read_until(*socket, *buffer, '\n',
        [socket, buffer](const asio::error_code& ec, std::size_t length) {
            on_read(socket, buffer, ec, length);
        });
}

void on_read(std::shared_ptr<tcp::socket> socket, std::shared_ptr<asio::streambuf> buffer,
             const asio::error_code& ec, std::size_t length) {
    if (!ec) {
        std::istream is(buffer.get());
        std::string mensaje;
        std::getline(is, mensaje);
        
        std::cout << "[Servidor] Recibido mensaje (" << length << " bytes): '" << mensaje << "'" << std::endl;
        
        std::string respuesta = "Que paso\n";
        std::cout << "[Servidor] Enviando respuesta..." << std::endl;
        
        asio::async_write(*socket, asio::buffer(respuesta),
            [socket](const asio::error_code& ec, std::size_t length) {
                on_write(socket, ec, length);
            });
    } else if (ec == asio::error::eof) {
        std::cout << "[Servidor] Cliente desconectado" << std::endl;
    } else {
        std::cerr << "[Servidor] Error en lectura: " << ec.message() << std::endl;
    }
}

void on_write(std::shared_ptr<tcp::socket> socket, const asio::error_code& error_code, std::size_t /*length*/) {
    if (!error_code) {
        std::cout << "[Servidor] Respuesta enviada, esperando siguiente mensaje..." << std::endl;
        handle_client(socket); // Continuar escuchando más mensajes
    } else {
        std::cerr << "[Servidor] Error enviando respuesta: " << error_code.message() << std::endl;
    }
}

void on_accept(std::shared_ptr<tcp::socket> socket, tcp::acceptor& acceptor, const asio::error_code& error_code) {
    if (!error_code) {
        std::cout << "[INFO] Nueva conexión establecida" << std::endl;
        handle_client(socket); // Comenzar a manejar este cliente
    } else {
        std::cerr << "[ERROR] Error aceptando conexión: " << error_code.message() << std::endl;
    }
    
    start_accept(acceptor); // Continuar aceptando nuevas conexiones
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