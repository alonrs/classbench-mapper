#pragma once
#include <list>
#include <vector>
#include "random.h"

/**
 * @brief Generates random number between low and high (inclusive)
 */
uint32_t
gen_uniform_random_uint32(uint32_t low, uint32_t high)
{
    if (low == high) return low;
    return random_core::random_uint32() % (high-low) + low;
}

/**
 * @brief A set of integer intervals.
 */

class IntegerIntervalSet {
private:

    struct range {
        uint32_t low;
        uint32_t high;
        range(uint32_t low, uint32_t high) :
            low(low), high(high) {}
    };

    std::list<range> _intervals;

    /**
     * @brief Initiate empty list
     */
    IntegerIntervalSet() {};

public:

    /**
     * @brief Initiate a new interval
     * @param low The interval low value (inclusive)
     * @param high The interval high value (inclusive)
     */
    IntegerIntervalSet(uint32_t low, uint32_t high)
    {
        _intervals.push_back(range(low, high));
    }

    /**
     * @brief Subtract a region from this, and return the intersection
     * between it and this.
     * @param low The interval low value (inclusive)
     * @param high The interval high value (inclusive)
     * @returns The intersection between this and the region.
     */
    IntegerIntervalSet remove(uint32_t low, uint32_t high)
    {

        IntegerIntervalSet output;
        uint32_t left_cursor = low;
        uint32_t right_cursor = high;
        uint32_t maximum = high;

        for (std::list<range>::iterator it = _intervals.begin();
             it != _intervals.end(); ++it) {
            range& r = *it;

            // Skip intervals in case they do not intersect the rule
            if (r.high < left_cursor) continue;
            if (right_cursor < r.low) break;

            // At this point, the interval r intersect the rule

            // Get the valid lower bound between cursor and the interval
            uint32_t min = std::max(left_cursor, r.low);
            // Get the valid upper bound between the cursor and the interval
            uint32_t max = std::min(right_cursor, r.high);
            if (max > maximum) max = maximum;
            // Add the current interval as valid interval to the output
            output._intervals.push_back(range(min, max));

            // Update additional interval in case required
            if (max < r.high) {
                auto position = it;
                _intervals.insert(++position, range(max+1, r.high));
            }

            // Update the current interval in case required
            r.high = min - 1;
            if (min == 0 || r.high < r.low) {
                it = _intervals.erase(it);
                --it;
            }

            // Update the cursor
            left_cursor = max + 1;
            if (right_cursor > maximum) break;
        }

        return output;
    }

    /**
     * @brief Returns a valid random value inside this
     */
    uint32_t
    random_value() const
    {
        uint32_t val;
        // In case the rule covers nothing, return 0
        if (_intervals.size() == 0) return 0;
        uint32_t x = gen_uniform_random_uint32(0, _intervals.size()-1);
        // Get any interval within this
        auto it = _intervals.begin();
        for (uint32_t i=0; i<x; ++i, ++it);
        // Get any value within the interval
        const range* intvl = &(*it);
        val = gen_uniform_random_uint32(intvl->low, intvl->high);
        return val;
    }

    /**
     * @brief Returns the number of intervals in this
     */
    uint32_t
    size() const
    {
        return _intervals.size();
    }

    /**
     * @brief Returns true iff this contains "value"
     */
    bool
    contains(uint32_t value)
    {
        for (auto it : _intervals) {
            if ( (value >= it.low) && (value <= it.high) ) {
                return true;
            }
        }
        return false;
    }

    /**
     * @brief Used for debugging. Print this
     */
    void
    print() const
    {
        for (auto it : _intervals) {
            fprintf(stderr, "[%u, %u] ", it.low, it.high);
        }
        fprintf(stderr,"\n");
    }
};

