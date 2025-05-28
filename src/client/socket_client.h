#ifndef SOCKET_CLIENT_H
#define SOCKET_CLIENT_H

#include <asio.hpp>
#include <iostream>
#include <memory>
#include <string>
#include <nlohmann/json.hpp>

#include "../common/common.h"

using asio::ip::tcp;
using json = nlohmann::json;

class SocketClient {
public:
    SocketClient(const std::string& host, const std::string& port);

    void run() { io_.run(); }
    void stop() { io_.stop(); }
    void send_message(const std::string& message);
    std::string receive_message();

private:
    asio::io_context io_;
    tcp::socket socket_;
};


#endif // SOCKET_CLIENT_H