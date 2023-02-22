#pragma once

#include <cstdarg>
#include <sstream>
#include <stdexcept>

// Create an exception with an arbitrary message using printf convention
#define errorf(...) error_obj::create() <<  "Exception: (" <<  \
    __func__ << "@" << __FILE__ << ":" << __LINE__ << ") " << \
    error_obj::format(__VA_ARGS__)

class error_obj : public std::exception {

    std::stringstream _buffer;
    std::string _message;
    error_obj() {}

public:

    /**
     * @brief Used by the throw mechanism
     */
    error_obj(const error_obj& rhs) {
        this->_message = rhs._message;
    }

    /**
     * @brief Creates new exception class
     */
    static
    error_obj create()
    {
        return error_obj();
    }

    /**
     * @brief Append to message arbitrary info
     */
    template <typename T>
    error_obj& operator<<(const T& rhs)
    {
        _buffer << rhs;
        _message = _buffer.str();
        return *this;
    }

    /**
     * @brief A log command. Adds formatted message.
     */
    static
    std::string format(const char* fmt, ...)
    {
        std::va_list args;
        va_start(args, fmt);
        size_t size = vsnprintf( nullptr, 0, fmt, args) + 1;
        char buffer[size];
        va_start(args, fmt);
        vsnprintf(buffer, size, fmt, args);
        return std::string(buffer);
    }

    virtual const char*
    what() const noexcept
    {
        return _message.c_str();
    }
};

