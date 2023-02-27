#ifndef ZSTREAM_H
#define ZSTREAM_H

#include <cstring>
#include <cstdint>
#include <string>
#include <zlib.h>

namespace cbmapper {

class zstream {
    gzFile f;
public:

    zstream()
    : f(nullptr)
    {}

    ~zstream()
    {
        if (f) {
            gzclose(f);
        }
    }

    void
    open_write(const char *filename)
    {
        f = gzopen(filename, "w9");
    }

    void
    open_read(const char *filename)
    {
        f = gzopen(filename, "rb");
    }

    zstream&
    operator<<(uint32_t element)
    {
        gzwrite(f, &element, sizeof(uint32_t));
        return *this;
    }

    zstream&
    operator<<(const char *string)
    {
        gzwrite(f, string, strlen(string));
        return *this;
    }

    uint32_t
    read_u32()
    {
        uint32_t b;
        gzread(f, &b, sizeof(b));
        return b;
    }

    std::string
    read_string(int length)
    {
        std::string str;
        char *buffer = new char[length + 1];
        memset(buffer, 0, length+1);
        gzread(f, buffer, length);
        str = buffer;
        delete[] buffer;
        return str;
    }
};

};

#endif