#include <fstream>
#include <iostream>
#include <set>
#include <vector>
#include <string>
#include "ruleset.h"
#include "string-ops.h"

namespace cbmapper {

/**
 * @brief Parse an IPv4-mask string (xxx.xxx.xxx.xxx/xx)
 * @param ip_address The IP-mask string
 * @return The range (in 32bit space) as {start, end}
 */
static rule_field
parse_ip_mask_address(const std::string& ip_address)
{
    // Split to parts by delimiters "." and "/"
    string_ops<uint32_t> strops;
    std::vector<uint32_t> parts =
        strops.split(ip_address, "./", strops.str2uint);

    if (parts.size() != 5) {
        throw errorf("IP/mask string is invalid");
    }
    uint8_t prefix = parts[4];
    // Mask
    if (parts[4]>0) parts[4] = 0xffffffff << (32-parts[4]) & 0xffffffff;
    else parts[4]=0;

    uint32_t ip_start = (parts[0] << 24 | parts[1] << 16 |
                         parts[2] << 8 | parts[3]) & parts[4];
    uint32_t ip_end   = ip_start | ~parts[4];
    return {ip_start, ip_end, prefix};
}

/**
 * @brief Parses protocol range (0xXXXX/0xXXXX)
 */
static rule_field
parse_protocol(const std::string& str)
{
    string_ops<uint32_t> strops;
    std::vector<uint32_t> values = strops.split(str, "/", strops.hex2int);
    if (values[1] != 255) {
        return {0, 255, 24};
    } else {
        uint32_t value = values[0];
        return {value, value, 32};
    }
}

/**
 * @brief Parses classbench port range using longest prefix.
 * Sets the field as the lonest possible wildcard combination
 * of low, mask
 */
static rule_field
parse_port(uint32_t low, uint32_t high)
{
    // Get longest shared prefix
    uint32_t val = low ^ high;
    uint8_t prefix = 0;
    // How many MSB bits are shared between low & high?
    while ( (prefix < 32) && ((val&0x80000000) == 0) ) {
        prefix++;
        val<<=1;
    }

    // Calculate high value
    uint32_t mask = (prefix == 32) ?
                    (0xffffffff) :
                    (0xffffffff << (32-prefix) & 0xffffffff);
    high = (low | ~mask);
    return {low, high, prefix};
}

ruleset<5>
ruleset_read_classbench_file(const char* filename, bool reverse_priorities)
{

    ruleset<5> output;
    uint32_t from, to;
    uint32_t id = 1;

    std::set<rule<5>> set_of_rules;

    // Open file
    std::fstream fs;
    fs.open(filename, std::fstream::in);

    while (1) {

        // Stop reading file
        if (fs.eof()) break;

        // Read next line
        char line_buffer[2048];
        fs.getline(line_buffer, 2048);
        std::string line(line_buffer);

        // Stop reading file
        if (fs.eof()) {
            break;
        }
        // Check for errors
        else if (fs.fail()) {
            throw errorf("Error while reading file: "
                         "logial error on i/o operation");
        } else if (fs.bad()) {
            throw errorf("Error while reading file: "
                         "read/writing error on i/o operation");
        }

        // Skip empty lines
        if (line.size() == 0) {
            continue;
        }

        // Split line according to delimiters
        string_ops<std::string> strops;
        auto fields = strops.split(line, "@ \t",
                      [](const std::string& s) { return s; });

        // Validate there are 6 fields:
        if (fields.size() != 10) {
            throw errorf("Classbench line has illegal number of fields: %lu",
                         fields.size());
        }

        // Validate the fields 3 and 6 are ":" according to the Classbench format
        if (fields[3].compare(":") || fields[6].compare(":")) {
            throw errorf("Classbench line: field 3 is '%s', "
                         "field 6 is '%s'; both should be ':'",
                         fields[3].c_str(), fields[6].c_str());
        }

        // Create new rule
        rule<5> rule;
        rule.unique_id = id;
        // rule.match = (void*)rule.unique_id; // For debug

        rule[0] = parse_protocol(fields[8]);        // protocol
        rule[1] = parse_ip_mask_address(fields[0]); // src-ip
        rule[2] = parse_ip_mask_address(fields[1]); // src-ip

        from = strops.str2uint(fields[2]), // src-port from
        to = strops.str2uint(fields[4]), // src-port to
        rule[3] = parse_port(from, to);

        from = strops.str2uint(fields[5]), // dst-port from
        to = strops.str2uint(fields[7]), // dst-port to
        rule[4] = parse_port(from, to);

        // In case the rule is a duplication of a previous one
        if (set_of_rules.find(rule) != set_of_rules.end()) {
            continue;
        }

        // Update output
        output.push_back(rule);
        set_of_rules.insert(rule);
        id++;
    }

    // Set rule priorities, largest priority is highest
    // (priority 0 is invalid)
    int priority = output.size();
    for (auto& rule : output) {
        if (reverse_priorities) {
            rule.priority = priority;
        } else {
            rule.priority = rule.unique_id;
        }
        priority--;
    }

    return output;
}

};