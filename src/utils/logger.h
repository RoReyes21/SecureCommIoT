#ifndef LOGGER_H
#define LOGGER_H

#include <iostream>
#include <fstream>
#include <string>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <filesystem>

class Logger {
public:
    enum class LogLevel {
        INFO,
        WARNING,
        ERROR,
        SECURITY,
        COMMUNICATION
    };

    static Logger& getInstance();
    
    void log_to_file(LogLevel level, const std::string& message);
    void log_to_console(const std::string& message);
    void log_communication(const std::string& message);
    
    void set_log_file(const std::string& filename);

private:
    Logger();
    ~Logger();
    
    std::string get_timestamp();
    std::string level_to_string(LogLevel level);
    
    std::ofstream log_file_;
    std::string log_filename_;
};

// Macros para facilitar el uso
#define LOG_INFO(msg) Logger::getInstance().log_to_file(Logger::LogLevel::INFO, msg)
#define LOG_WARNING(msg) Logger::getInstance().log_to_file(Logger::LogLevel::WARNING, msg)
#define LOG_ERROR(msg) Logger::getInstance().log_to_file(Logger::LogLevel::ERROR, msg)
#define LOG_SECURITY(msg) Logger::getInstance().log_to_file(Logger::LogLevel::SECURITY, msg)
#define LOG_COMMUNICATION(msg) Logger::getInstance().log_communication(msg)
#define CONSOLE_ONLY(msg) Logger::getInstance().log_to_console(msg)

#endif // LOGGER_H
