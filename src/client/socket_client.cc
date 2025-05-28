#include "socket_client.h"

SocketClient::SocketClient(const std::string& host, const std::string& port) : io_(), socket_(io_) {

    try {
        tcp::resolver resolver(io_);
        auto endpoints = resolver.resolve(host, port);
        asio::connect(socket_, endpoints);
        std::cout << "[Socket] Connected to the server\n";
    } catch (const std::exception& e) {
        std::cerr << "[Socket] Connection error: " << e.what() << "\n";
    }
}

void SocketClient::send_message(const std::string& message) {
    try {
        asio::write(socket_, asio::buffer(message));
        std::cout << "[Socket] Sent to server: " << message << "\n";
    } catch (const std::exception& e) {
        std::cerr << "[Socket] Send error: " << e.what() << "\n";
    }
}

std::string SocketClient::receive_message() {
    asio::streambuf buffer;
    asio::read_until(socket_, buffer, END_OF_MESSAGE);
    std::istream is(&buffer);
    std::string line;
    std::getline(is, line);
    std::cout << "[Socket] Receive message from server: " << line << "\n";
    return line;
}
