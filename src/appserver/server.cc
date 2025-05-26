#include "server.h"

#include "../common/common.h"

void handle_signal(const asio::error_code& error, int signal_number) {
    if (!error) {
        std::cout << "\n[INFO] Closing server for (" << signal_number << ") signal..." << "\n";
        io.stop();
    }
}

int get_nounce() { // ToDo, replace with random nounce
    static int nounce = 0;
    return ++nounce;
}

std::string get_whats_up_msg() {
    json response = {
        {"method", "WhatsUpFIUNAM"},
        {"server_ID", 12345},
        {"nounce", get_nounce()},
        {"signature", "ToDo"} // ToDo, replace with signature
    };
    return response.dump() + END_OF_MESSAGE;
}

std::string get_connection_ok_msg() {
    json response = {
        {"method", "StartConversation"},
        {"symetric_key", "ToDo"}, // ToDo, replace with symetric key for this client
        {"nounce", get_nounce()}
    };
    return response.dump() + END_OF_MESSAGE;
}

void manage_message_from_client(std::shared_ptr<tcp::socket> socket, const std::string& message, int client_id) {
    
    std::size_t fin_pos = message.find(END_OF_MESSAGE);
    if (fin_pos == std::string::npos) {
        std::cerr << "[ERROR]: The " << END_OF_MESSAGE << " delimiter was not found in the message." << "\n";
        return;
    }

    std::string msg_response;

    std::string json_message = message.substr(0, fin_pos);
    json data;
    try {
        data = json::parse(json_message);
    } catch (json::parse_error& e) {
        std::cerr << "[ERROR] Json could not be parsed: " << e.what() << "\n";
    }

    if (data["method"] == "HelloFIUNAM") {

        std::cout << "Device ID: " << data["device_ID"] << "\n";
        std::cout << "Device nounce: " << data["nounce"] << "\n";
        //std::cout << "Signature: " << data["signature"] << "\n";
        // ToDo, verify signature
        msg_response = get_whats_up_msg();
    }
    else if (data["method"] == "AgreeParams") {
        std::cout << "[Client] Server agreed to the parameters. Client ID: " << client_id << "\n";
        std::cout << "Client public key: " << data["public_key"] << "\n";
        std::cout << "Algorithm: " << data["algorithm"] << "\n";
        std::cout << "Client nounce: " << data["nounce"] << "\n";
        //ToDo, Create map with keys and active clients, etc. relevant data. Too verify all data
        msg_response = get_connection_ok_msg();
    }
    else if (data["method"] == "data") {
        //ToDo, verify check that the user is already logged in, if not close socket with this user
        // If the user is logged in, process the data, save it in txt idk
        json resp = {
            {"method", "conn_continue"}
        };
        msg_response = resp.dump() + END_OF_MESSAGE;
    }
    
    if (msg_response.empty()) {
        std::cout << "[Server] Client #" << client_id << " - Error in message, closing connection." << "\n";
        socket->close();
        return;
    }

    asio::async_write(*socket, asio::buffer(msg_response),
        [socket, client_id](const asio::error_code& ec, std::size_t length) {
            on_write(socket, ec, length, client_id);
        });
    
    return;
}

void handle_client(std::shared_ptr<tcp::socket> socket, int client_id) {
    auto buffer = std::make_shared<asio::streambuf>();
    std::cout << "[Server] Client #" << client_id << " - Waiting message..." << "\n";
    
    asio::async_read_until(*socket, *buffer, END_OF_MESSAGE,
        [socket, buffer, client_id](const asio::error_code& ec, std::size_t length) {
            on_read(socket, buffer, ec, length, client_id);
        });
}

void on_read(std::shared_ptr<tcp::socket> socket, std::shared_ptr<asio::streambuf> buffer,
             const asio::error_code& ec, std::size_t length, int client_id) {
    
    if (!ec) {
        std::istream is(buffer.get());
        std::string message;
        std::getline(is, message);

        std::cout << "[Server] Client #" << client_id << " - Received message: '" << message << "'" << "\n";

        manage_message_from_client(socket, message, client_id);
        
    } else if (ec == asio::error::eof) {
        std::cout << "[Server] Client #" << client_id << " was disconnected" << "\n";
    } else {
        std::cerr << "[Server] Client #" << client_id << " - Error while reading: " << ec.message() << "\n";
    }
}

void on_write(std::shared_ptr<tcp::socket> socket, const asio::error_code& error_code, std::size_t /*length*/, int client_id) {
    if (!error_code) {
        std::cout << "[Server] Client #" << client_id << " - Response sending, waiting next message..." << "\n";
        handle_client(socket, client_id);
    } else {
        std::cerr << "[Server] Client #" << client_id << " - Error while sending response: " << error_code.message() << "\n";
    }
}

void on_accept(std::shared_ptr<tcp::socket> socket, tcp::acceptor& acceptor, const asio::error_code& error_code) {
    if (!error_code) {
        int client_id = ++connection_counter;
        
        auto remote_endpoint = socket->remote_endpoint();
        std::cout << "[INFO] New connection #" << client_id 
                  << " from " << remote_endpoint.address().to_string() 
                  << ":" << remote_endpoint.port() << "\n";
        
        handle_client(socket, client_id);
    } else {
        std::cerr << "[ERROR] Error accepting connection: " << error_code.message() << "\n";
    }
    
    start_accept(acceptor);
}

void start_accept(tcp::acceptor& acceptor) {
    auto socket = std::make_shared<tcp::socket>(io);
    acceptor.async_accept(*socket,
        [socket, &acceptor](const asio::error_code& ec) {
            on_accept(socket, acceptor, ec);
        });
}

int main() {
    try {
        tcp::acceptor acceptor(io, tcp::endpoint(tcp::v4(), 8080));
        
        asio::signal_set signals(io, SIGINT, SIGTERM);
        signals.async_wait(handle_signal);
        
        std::cout << "[INFO] Initializing server, listening in port 8080..." << "\n";
        start_accept(acceptor);
        io.run();
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
    }
}