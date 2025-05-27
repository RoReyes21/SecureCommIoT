#include "client.h"

#include "../common/common.h"

int get_nounce() { // ToDo, replace with random nounce
    static int nounce = 0;
    return ++nounce;
}

std::string get_agree_params_msg() {
    json agree_params = {
        {"method", "AgreeParams"},
        {"public_key", 12345}, // ToDo, replace with real public key
        {"algorithm", "P_256"},
        {"nounce", get_nounce()}
    };
    return agree_params.dump() + END_OF_MESSAGE;
}

/**
 * @brief Manage the response from the server.
 * 
 * @param response 
 * @return std::string If the response is valid, return the next message to send to the server. Else, return an empty string.
 */
void manage_response_from_server(std::shared_ptr<tcp::socket> socket, std::string response) {
    std::string msg_to_server;

    std::size_t fin_pos = response.find(END_OF_MESSAGE);
    if (fin_pos == std::string::npos) {
        std::cerr << "[ERROR]: The " << END_OF_MESSAGE << " delimiter was not found in the response." << "\n";
        return;
    }

    std::string json_response = response.substr(0, fin_pos);
    json data;
    try {
        data = json::parse(json_response);
    } catch (json::parse_error& e) {
        std::cerr << "[ERROR] Json could not be parsed: " << e.what() << "\n";
    }

    if (data["method"] == "WhatsUpFIUNAM") {

        std::cout << "Server ID: " << data["server_ID"] << "\n";
        std::cout << "Server nounce: " << data["nounce"] << "\n";
        //std::cout << "Signature: " << data["signature"] << "\n";
        // ToDo, verify signature
        msg_to_server = get_agree_params_msg();
    }
    else if (data["method"] == "StartConversation") {
        std::cout << "[Client] Server agreed to the parameters." << "\n";
        std::cout << "Server simetric key: " << data["symetric_key"] << "\n";
        std::cout << "Server nounce: " << data["nounce"] << "\n";
        //ToDo, save symetric key, etc.
        std::cout << "Wirite a message: ";
        std::getline(std::cin, msg_to_server);
        msg_to_server += END_OF_MESSAGE;
    }
    else if (data["method"] == "conn_continue") {
        std::cout << "Wirite a message: ";
        std::getline(std::cin, msg_to_server);
        msg_to_server += END_OF_MESSAGE;
    }

    if (msg_to_server.empty())
        io.stop();
    else
        std::cout << "[Client] Sending message to server: '" << msg_to_server << "'" << "\n";
        do_write(socket, msg_to_server);

    return;
}

void do_write(std::shared_ptr<tcp::socket> socket, const std::string& message) {
    std::cout << "[Client] Sending message: '" << message << "'" << "\n";
    asio::async_write(*socket, asio::buffer(message),
        [socket](const asio::error_code& ec, std::size_t length) {
            on_write(socket, ec, length);
        });
}

void on_write(std::shared_ptr<tcp::socket> socket, const asio::error_code& ec, std::size_t /*length*/) {
    if (!ec) {
        std::cout << "[Client] Message sent, awaiting reply..." << "\n";
        do_read(socket);
    } else {
        std::cerr << "Error on_write: " << ec.message() << "\n";
    }
}

void do_read(std::shared_ptr<tcp::socket> socket) {
    auto buffer = std::make_shared<asio::streambuf>();
    asio::async_read_until(*socket, *buffer, END_OF_MESSAGE,
        [socket, buffer](const asio::error_code& ec, std::size_t length) {
            on_read(socket, buffer, ec, length);
        });
}

void on_read(std::shared_ptr<tcp::socket> socket, std::shared_ptr<asio::streambuf> buffer,
             const asio::error_code& error_code, std::size_t length) {
    if (!error_code) {
        response_counter++;
        std::istream is(buffer.get());
        std::string response;
        std::getline(is, response);
        
        std::cout << "[Client] Server response (" << length << " bytes): '" << response << "'" << "\n";
        
        std::string message;

        manage_response_from_server(socket, response);

    } else if (error_code == asio::error::eof) {
        std::cout << "[Client] Server closed connection" << "\n";
    } else {
        std::cerr << "[Client] Error on_read: " << error_code.message() << "\n";
    }
}

void send_first_message(std::shared_ptr<tcp::socket> socket) {

    json first_message = {
        {"method", "HelloFIUNAM"},
        {"device_ID", 12345}, // ToDo, replace with actual device ID, send only hash
        {"nounce", get_nounce()}
        //{"signature", "signature"}
    };

    std::string message = first_message.dump() + END_OF_MESSAGE;
    
    do_write(socket, message);
}

int main() {
    try {
        tcp::resolver resolver(io);
        auto endpoints = resolver.resolve("127.0.0.1", "8080");
        
        auto socket = std::make_shared<tcp::socket>(io);
        asio::connect(*socket, endpoints);
        
        std::cout << "Connected to the server\n";
        
        send_first_message(socket);
        
        io.run();
    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
    }
}