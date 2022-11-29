#ifndef RANDOM_H
#define RANDOM_H

#include <random>

class random_core {
public:
    
    static void
    set_seed(int seed = 0)
    {
        get_random_generator().seed(seed);
    }

    /* Random uint32_t */
    static inline std::mt19937 &
    get_random_generator()
    {
        static std::mt19937 generator;
        return generator;
    }

    static inline uint32_t
    random_uint32()
    {
        static std::uniform_int_distribution<uint32_t> d(0,0xFFFFFFFF);
        return d(get_random_generator());
    }

};

#endif 
