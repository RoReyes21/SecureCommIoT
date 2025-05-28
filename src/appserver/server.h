#ifndef SERVER_H
#define SERVER_H

#include <asio.hpp>
#include <iostream>
#include <memory>
#include <atomic>
#include <csignal>
#include <nlohmann/json.hpp>

#include "../common/common.h"

using asio::ip::tcp;
using json = nlohmann::json;

class Server {
public:
    Server(asio::io_context& io, unsigned short port) : io_(io), acceptor_(io, tcp::endpoint(tcp::v4(), port)), connection_counter_(0) {}
    void start() { start_accept(); }

private:

    void start_accept();
    void handle_client(std::shared_ptr<tcp::socket> socket, int client_id);
    
    asio::io_context& io_;
    tcp::acceptor acceptor_;
    std::atomic<int> connection_counter_;
};

#endif // SERVER_H