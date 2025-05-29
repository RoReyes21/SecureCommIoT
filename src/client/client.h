#ifndef CLIENT_H
#define CLIENT_H

#include <iostream>
#include <nlohmann/json.hpp>
#include <thread>
#include <chrono>

#include "socket_client.h"
#include "../encryption/data_encryp.h"

class Client {
public:
    Client(const std::string& server_ip, const std::string& server_port) : socket_client(server_ip, server_port) {
        io_thread = std::thread([this]() {
            socket_client.run();
        });
    }
    
    ~Client() { stop_socket(); }

    void stop_socket() { socket_client.stop(); io_thread.join(); }
    void send_message(const std::string& message) { socket_client.send_message(message); }
    std::string receive_message() { return socket_client.receive_message(); }
    bool establish_secure_connection_with_server();
    bool is_valid_response_from_server(std::string response);
    bool validate_signature(json data);
    int get_nounce() { return nounce++; }
    SessionKeysSymetric get_session_keys_symetric() {
        return session_keys_symetric;
    }

private:
    SocketClient socket_client;
    std::thread io_thread;
    int nounce = 0;
    SessionKeysAsymetric session_keys_asymetric;
    SessionKeysSymetric session_keys_symetric;   
};


#endif // CLIENT_H