#ifndef CLIENT_H
#define CLIENT_H

#include <iostream>
#include <nlohmann/json.hpp>
#include <thread>
#include <chrono>
#include <set>
#include <sodium.h>

#include "socket_client.h"
#include "../encryption/data_encryp.h"

class Client {
public:
    Client(const std::string& server_ip, const std::string& server_port, const std::string& client_id = "default") 
        : socket_client(server_ip, server_port), device_id(client_id), session_keys_asymetric("keys/client_" + client_id + "_keys.bin") {
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
    std::string get_device_id() const { return device_id; }
    bool is_nonce_repeated(const std::string& nonce_hex) { //Valida nonce
        if (received_nonces.count(nonce_hex)) {
            std::cerr << "[Client][Security] ⚠ Nonce repetido detectado: " << nonce_hex << "\n";
            return true;
        }
        received_nonces.insert(nonce_hex);
        return false;
    }


private:
    SocketClient socket_client;
    std::thread io_thread;
    int nounce = 0;
    std::string device_id;
    SessionKeysAsymetric session_keys_asymetric;
    SessionKeysSymetric session_keys_symetric;
    std::set<std::string> received_nonces; // para evitar duplicados
};


#endif // CLIENT_H