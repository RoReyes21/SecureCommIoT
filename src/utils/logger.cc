#include "logger.h"

Logger& Logger::getInstance() {
    static Logger instance;
    return instance;
}

Logger::Logger() {
    std::filesystem::create_directories("logs");
    // Detectar si es cliente o servidor por el nombre del ejecutable
    set_log_file("logs/client.log");
}

Logger::~Logger() {
    if (log_file_.is_open()) {
        log_file_.close();
    }
}

void Logger::set_log_file(const std::string& filename) {
    if (log_file_.is_open()) {
        log_file_.close();
    }
    
    log_filename_ = filename;
    log_file_.open(log_filename_, std::ios::app);
    
    if (log_file_.is_open()) {
        log_file_ << "\n" << std::string(50, '=') << "\n";
        if (filename.find("client") != std::string::npos) {
            log_file_ << "Client started at: " << get_timestamp() << "\n";
        } else {
            log_file_ << "Server started at: " << get_timestamp() << "\n";
        }
        log_file_ << std::string(50, '=') << "\n";
    }
}

void Logger::log_to_file(LogLevel level, const std::string& message) {
    if (log_file_.is_open()) {
        log_file_ << "[" << get_timestamp() << "] " 
                  << "[" << level_to_string(level) << "] " 
                  << message << std::endl;
        log_file_.flush();
    }
}

void Logger::log_to_console(const std::string& message) {
    std::cout << message << std::endl;
}

void Logger::log_communication(const std::string& message) {
    // Mostrar en consola
    std::cout << message << std::endl;
    // También guardar en log
    log_to_file(LogLevel::COMMUNICATION, message);
}

std::string Logger::get_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    ss << "." << std::setfill('0') << std::setw(3) << ms.count();
    return ss.str();
}

std::string Logger::level_to_string(LogLevel level) {
    switch (level) {
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARNING: return "WARNING";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::SECURITY: return "SECURITY";
        case LogLevel::COMMUNICATION: return "COMM";
        default: return "UNKNOWN";
    }
}
