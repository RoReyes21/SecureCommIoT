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
}

void send_first_message(std::shared_ptr<tcp::socket> socket) {

    json first_message = {
        {"method", "HelloFIUNAM"},
        {"device_ID", 12345}, // ToDo, replace with actual device ID, send only hash
        {"nounce", get_nounce()}
        //{"signature", "signature"}
    };

    std::string message = first_message.dump() + END_OF_MESSAGE;
    
}

int main() {
    SocketClient client("127.0.0.1", "8080");

    std::thread io_thread([&client]() {
        client.run();
    });

    json first_message = {
        {"method", "HelloFIUNAM"},
        {"device_ID", 12345}, // ToDo, replace with actual device ID, send only hash
        {"nounce", 12345}
        //{"signature", "signature"}
    };

    std::string message = first_message.dump() + END_OF_MESSAGE;
    client.send_message(message);

    std::string response = client.receive_message();
    std::cout << "[Client] Received response: " << response << "\n";

    while (true) {
        std::string msg_to_server;
        std::getline(std::cin, msg_to_server);

        client.send_message(msg_to_server + END_OF_MESSAGE);

        std::string response = client.receive_message();
        std::cout << "[Client] Received response: " << response << "\n";
    }

    client.stop();
    io_thread.join();

    return 0;
}