#ifndef SERVER_H
#define SERVER_H

#include <asio.hpp>
#include <iostream>
#include <memory>
#include <atomic>
#include <csignal>
#include <nlohmann/json.hpp>
#include <map>
#include <sodium.h>

#include "../common/common.h"
#include "../encryption/data_encryp.h"

using asio::ip::tcp;
using json = nlohmann::json;

class Server {
public:
    Server(asio::io_context& io, unsigned short port) : io_(io), acceptor_(io, tcp::endpoint(tcp::v4(), port)), connection_counter_(0) {
        SessionKeysAsymetric::initialize_trusted_clients_if_needed();
        SessionKeysAsymetric::auto_register_first_client();
    }
    void start() { start_accept(); }
    int get_nounce() { return nounce++; }

private:

    void start_accept();
    void handle_client(std::shared_ptr<tcp::socket> socket, int client_id);
    void manage_message_from_client(std::string message, std::shared_ptr<tcp::socket> socket, int client_id);

    bool validate_signature(int client_id, json data);
    bool is_client_trusted(const std::string& public_key_hex, const std::string& long_term_public_key_hex);
    bool authenticate_new_device(int client_id, json data);
    bool handle_device_registration_request(int client_id, json data, std::shared_ptr<tcp::socket> socket);
    
    asio::io_context& io_;
    tcp::acceptor acceptor_;
    std::atomic<int> connection_counter_;
    int nounce = 0;

    SessionKeysAsymetric server_keys{"keys/server_keys.bin"};
    std::map<int, SessionKeysSymetric> session_keys_symetric_map;
    std::map<int, SessionKeysAsymetric> session_keys_asymetric_map;
    std::map<int, std::shared_ptr<tcp::socket>> client_sockets;
    std::map<int, int> current_situation_client_map;
};

#endif // SERVER_H