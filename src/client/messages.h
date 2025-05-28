#ifndef MESSAGES_H
#define MESSAGES_H

#include <string>
#include <nlohmann/json.hpp>
#include "../common/common.h"

using Json = nlohmann::json;

std::string get_hello_message(std::string device_id, int nounce) {
    Json hello_msg = {
        {"method", "HelloFIUNAM"},
        {"device_ID", device_id},
        {"nounce", nounce}
        //{"signature", "signature"} // TODO: check how to sign signature
    };
    return hello_msg.dump() + END_OF_MESSAGE;
}

std::string get_agree_params_message(std::string public_key, std::string algorithm, int nounce) {
    Json agree_params = {
        {"method", "AgreeParams"},
        {"public_key", public_key},
        {"algorithm", algorithm},
        {"nounce", nounce}
    };
    return agree_params.dump() + END_OF_MESSAGE;
}

std::string get_simple_message(std::string message) {
    Json simple_msg = {
        {"method", "simple_message"},
        {"message", message}
    };
    return simple_msg.dump() + END_OF_MESSAGE;
}

#endif // MESSAGES_H