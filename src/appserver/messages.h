#ifndef MESSAGES_H
#define MESSAGES_H

#include <string>
#include <nlohmann/json.hpp>
#include "../common/common.h"

using Json = nlohmann::json;

std::string get_whats_up_message(std::string device_id, std::string nounce, std::string public_key, std::string long_term_public_key, std::string signature) {
    Json whats_msg = {
        {"method", "WhatsUpFIUNAM"},
        {"server_ID", device_id},
        {"nounce", nounce},
        {"signature_hex", signature},
        {"public_key_hex", public_key},
        {"long_term_public_key_hex", long_term_public_key}
    };
    return whats_msg.dump() + END_OF_MESSAGE;
}

std::string get_start_secure_conversartion_message(std::string is_ok, std::string nounce) {
    Json start_message = {
        {"method", "StartConversation"},
        {"OK", is_ok},
        {"nounce", nounce}
    };
    return start_message.dump() + END_OF_MESSAGE;
}

std::string get_simple_response(std::string message, std::string nounce) {
    Json simple_msg = {
        {"method", "conn_continue"},
        {"message", message},
        {"nounce", nounce}
    };
    return simple_msg.dump() + END_OF_MESSAGE;
}

#endif // MESSAGES_H