#ifndef SERVER_H
#define SERVER_H

#include <asio.hpp>
#include <iostream>
#include <memory>
#include <csignal>

using asio::ip::tcp;
asio::io_context io;

void handle_signal(const asio::error_code& error, int signal_number);
void handle_client(std::shared_ptr<tcp::socket> socket);
void on_read(std::shared_ptr<tcp::socket> socket, std::shared_ptr<asio::streambuf> buffer,
             const asio::error_code& ec, std::size_t length);
void on_write(std::shared_ptr<tcp::socket> socket, const asio::error_code& error_code, std::size_t length);
void on_accept(std::shared_ptr<tcp::socket> socket, tcp::acceptor& acceptor, const asio::error_code& error_code);
void start_accept(tcp::acceptor& acceptor);

#endif // SERVER_H