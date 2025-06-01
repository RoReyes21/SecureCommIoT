#include "socket_client.h"
#include "../utils/logger.h"

SocketClient::SocketClient(const std::string& host, const std::string& port) : io_(), socket_(io_) {

    try {
        tcp::resolver resolver(io_);
        auto endpoints = resolver.resolve(host, port);
        asio::connect(socket_, endpoints);
        LOG_INFO("Connected to server at " + host + ":" + port);
    } catch (const std::exception& e) {
        LOG_ERROR("Connection error: " + std::string(e.what()));
        CONSOLE_ONLY("[Client] ✗ Failed to connect to server");
    }
}

void SocketClient::send_message(const std::string& message) {
    try {
        asio::write(socket_, asio::buffer(message));
        LOG_INFO("Message sent to server: " + message);
    } catch (const std::exception& e) {
        LOG_ERROR("Send error: " + std::string(e.what()));
        CONSOLE_ONLY("[Client] ✗ Failed to send message");
    }
}

std::string SocketClient::receive_message() {
    asio::streambuf buffer;
    asio::read_until(socket_, buffer, END_OF_MESSAGE);
    std::istream is(&buffer);
    std::string line;
    std::getline(is, line);
    LOG_INFO("Message received from server: " + line);
    return line;
}
