#include <cstring>
#include <mutex>

#include "log.h"

#define MAX_LOG_SIZE 1024

static char buffer[MAX_LOG_SIZE];
static int position = 0;
static std::mutex lck;

void
log_stderr(const char* msg)
{
    fprintf(stderr, "%s", msg);
    fflush(stderr);
}

void
log_config(const char* msg,
           log_callback_t callback)
{
    static log_callback_t cb;
    if (callback) {
        cb = callback;
    }
    if (cb && msg) {
        cb(msg);
    }
}

void
log_fmt_msg(const char* fmt, ...)
{
    /* Acquires "lck", release when scope ends */
    const std::lock_guard<std::mutex> lock(lck);
    va_list args;
    va_start(args, fmt);
    size_t size = vsnprintf(NULL, 0, fmt, args)+1;
    if (position + size >= MAX_LOG_SIZE) {
        size = MAX_LOG_SIZE - position - 1;
    }
    va_start(args, fmt);
    vsnprintf(buffer+position, size, fmt, args);
    position = (position + size - 1) % MAX_LOG_SIZE;
}

void
log_flush() {
    log_config(buffer, NULL);
    position = 0;
}

void
print_progress(const char* message, size_t current, size_t size)
{
    if ( (size ==0) || (current < 0) ) {
        MESSAGE("\r%s... Done   \n", message);
    } else {
        int checkpoint = size < 100 ? 1 : size/100;
        if (current%checkpoint==0) {
            MESSAGE("\r%s... (%lu%%)", message, current/checkpoint);
        }
    }
}

