#ifndef CLIENT_H
#define CLIENT_H

#include <asio.hpp>
#include <iostream>
#include <memory>
#include <thread>
#include <nlohmann/json.hpp>

using asio::ip::tcp;
asio::io_context io;
using json = nlohmann::json;

int response_counter = 0;

void do_write(std::shared_ptr<tcp::socket> socket, const std::string& message);
void do_read(std::shared_ptr<tcp::socket> socket);
void on_write(std::shared_ptr<tcp::socket> socket, const asio::error_code& ec, std::size_t length);
void on_read(std::shared_ptr<tcp::socket> socket, std::shared_ptr<asio::streambuf> buffer, const asio::error_code& ec, std::size_t length);
void manage_response_from_server(std::shared_ptr<tcp::socket> socket, std::string response);
void send_first_message(std::shared_ptr<tcp::socket> socket);

#endif // CLIENT_H