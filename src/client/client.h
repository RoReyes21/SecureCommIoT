#ifndef CLIENT_H
#define CLIENT_H

#include <asio.hpp>
#include <iostream>
#include <memory>
#include <thread>

using asio::ip::tcp;
asio::io_context io;

void do_write(std::shared_ptr<tcp::socket> socket, const std::string& message);
void do_read(std::shared_ptr<tcp::socket> socket);
void on_write(std::shared_ptr<tcp::socket> socket, const asio::error_code& ec, std::size_t length);
void on_read(std::shared_ptr<tcp::socket> socket, std::shared_ptr<std::array<char, 1024>> buffer, const asio::error_code& ec, std::size_t length);

#endif // CLIENT_H