#include <list>
#include <fstream>
#include <vector>
#include <queue>
#include <set>
#include <map>
#include <atomic>
#include <iostream>
#include <algorithm>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <pthread.h>

#include "errorf.h"
#include "integer-interval-set.h"
#include "log.h"
#include "libcommon/lib/arguments.h"
#include "ruleset.h"

using namespace std;

// Holds arguments information
static arguments args[] = {
// Name                R  B  Def        Help
// Mandatory arguments
{"out",                1, 0, NULL,      "Output filename."},
// Mode Mapping
{"mode-mapping",       0, 1, NULL,      "(Mode Mapping) Generate a unique "
                                        "packet for each rule in the ruleset."},
{"num-of-flows",       0, 0, "1000000", "(Mode Mapping) Number of unique "
                                        "flows to generate."},
{"ruleset",            0, 0, NULL,      "(Mode Mapping / Mode OVS Flows) "
                                        "ClassBench ruleset to analyze."},
// Mode OVS flows
{"mode-ovs-flows",     0, 1, NULL,      "(Mode OVS Flows) Generate OVS flows "
                                        "script from a ruleset."},
{"full-action",        0, 1, NULL,      "(Mode OVS Flows) Makes the OVS rules "
                                        "change src & dst IP addresses for "
                                        "checking correctness."},
{NULL,                 0, 0, NULL,      "Analyzes ClassBench ruleset files. "
                                        "Generates either a unique packet to "
                                        "match per flow, or textual file with "
                                        "Open vSwitch (OVS) flows."}
};

static constexpr int F = 5;

/**
 * @brief A mapping between a rule index to a unique packet
 * that maches that rule.
 */
typedef map<int, std::vector<packet_header<F>>> rule_mapping_t;

/**
 * @brief Prints progres to the screen
 * @param message Message to show
 * @param current Current iteration
 * @param size Total iterations (or 0 - to show complete message)
 */
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

/**
 * @brief Generates a packet within the required rule. Does not always succeed.
 * @param rule_db The ruleset
 * @param rule_idx The required rule index
 * @param tries Number of tries
 * @param packet[out] The generated packet
 * @returns True on success
 */
static bool
gen_packet_in_rule(const Ruleset<F>& rule_db,
                   int rule_idx, int tries,
                   packet_header<F>& packet)
{
    const MatchingRule<F>& rule = rule_db[rule_idx];

    while (tries > 0) {

        // Choose field values by random
        for (int j=0; j<F; ++j) {
            packet[j] = gen_uniform_random_uint32(rule[j].low, rule[j].high);
            // In case of ip-proto field, make sure to be either
            // TCP, UDP, or ICMP
            if (j == 0) {
                if ( (rule[j].low <= 17) && (rule[j].high >= 17) ) {
                    packet[j] = 17;
                } else if ( (rule[j].low <= 6) && (rule[j].high >= 6) ) {
                    packet[j] = 6;
                } else if ( (rule[j].low <= 1) && (rule[j].high >= 1) ) {
                    packet[j] = 1;
                }
            }
            if ( (packet[j] < rule[j].low) || (packet[j] > rule[j].high) ) {
                return false;
            }
        }

        // Validate the generated packet does not match
        // any rule with higher priority (unique mapping)
        bool previous_match = false;

        for (int r=0; r<rule_idx-1; ++r) {
            int match=1;
            // For each filed
            for (uint32_t j=0; j<F; ++j) {
                // Get rule boundaries
                uint32_t field_start = rule_db[r].fields[j].low;
                uint32_t field_end = rule_db[r].fields[j].high;
                // Check collision
                if ( (packet[j] < field_start) || (packet[j] > field_end ) ) {
                    match=0;
                    break;
                }
            }
            // In case the packet does not match the current rule
            if (match){
                previous_match = true;
                break;
            }
        }

        // If none of the previous rules match,
        // we can guarantee uniqueness
        if (!previous_match) {
            return true;
        }

        tries--;
    }
    // Return False
    return false;
}

/**
 * @brief Generates a mapping between a rule to a random header
 * packet that matches the rule.
 * @param Ruleset<F> The ruleset
 * @param num_of_flows Number of unique flows to generate
 * @returns A mapping rule_prio->header
 */
static rule_mapping_t *
generate_mapping(const Ruleset<F>& rule_db, int num_of_flows)
{
    rule_mapping_t* output = new rule_mapping_t();

    // Count how many non-unique rules are there
    set<int> non_unique;

    // Initiate output
    int avg_flows_per_rule = num_of_flows / rule_db.size();
    for (size_t i=0; i<rule_db.size(); ++i) {
        (*output)[rule_db[i].priority] = std::vector<packet_header<F>>();
        (*output).at(rule_db[i].priority).resize(avg_flows_per_rule);
    }

    // For each field
    for (uint32_t f=0; f<F; ++f) {
        // Build an interval-list for the current field
        IntegerIntervalSet interval(0, 0xffffffff);
        auto rule = rule_db.begin();

        // Count how many non-unique rules are there in the current field
        set<int> current_non_unique;

        char message[256];
        snprintf(message, 256,
            "Calculating integer-interval-set for field %d", f);

        for (size_t i=0; i<rule_db.size(); ++i) {
            // Print progress to screen
            print_progress(message, i, rule_db.size());
            // Calculate the interval for the current rule
            auto sub_interval = interval.remove(rule->fields[f].low,
                rule->fields[f].high);
            // Can we guarantee unique mapping?
            bool can_guarantee = false;

            uint32_t low = rule->fields[f].low;
            uint32_t high = rule->fields[f].high;

            // In case we can guarantee unique value for the current rule
            if (sub_interval.size() > 0) {
                // Fill values for the current field
                for (int i=0; i<avg_flows_per_rule; ++i) {
                    (*output)[rule->priority][i][f] = sub_interval.random_value();
                }
                can_guarantee = true;
            }
            else {
                for (int i=0; i<avg_flows_per_rule; ++i) {
                    (*output)[rule->priority][i][f] =
                        gen_uniform_random_uint32(low, high);
                }
            }

            // In case of ip-proto field, make sure to be either
            // TCP, UDP, or ICMP
            if (f == 0){
                if (sub_interval.contains(17)) {
                    for (int i=0; i<avg_flows_per_rule; ++i) {
                        (*output)[rule->priority][i][f] = 17;
                    }
                }
                else if (sub_interval.contains(6)) {
                    for (int i=0; i<avg_flows_per_rule; ++i) {
                        (*output)[rule->priority][i][f] = 6;
                    }
                }
                else if (sub_interval.contains(1)) {
                    for (int i=0; i<avg_flows_per_rule; ++i) {
                        (*output)[rule->priority][i][f] = 1;
                    }
                } else {
                    for (int i=0; i<avg_flows_per_rule; ++i) {
                        if ( (low <= 17) && (high >= 17) ) {
                            (*output)[rule->priority][i][f] = 17;
                        } else if ( (low <= 6) && (high >= 6) ) {
                            (*output)[rule->priority][i][f] = 6;
                        } else if ( (low <= 1) && (high >= 1) ) {
                            (*output)[rule->priority][i][f] = 1;
                        }
                    }
                    can_guarantee = false;
                }
            }

            // We cannot guarantee a unique mapping
            if (!can_guarantee) {
                current_non_unique.insert(i);
            }

            ++rule;
        }

        // Update the non_unique rule set
        if (f == 0) {
            non_unique = current_non_unique;
        } else {
            set<int> intersect;
            set_intersection(
                    non_unique.begin(), non_unique.end(),
                    current_non_unique.begin(), current_non_unique.end(),
                    std::inserter(intersect, intersect.begin()));
            non_unique = intersect;
        }

        // Print progress to screen
        print_progress(message, -1, 0);
    }

    // Update mapping for non-unique rules
    MESSAGE("Non-unique rules: %lu\n", non_unique.size());
    int unreachable_rules = 0;

    // Handle non-unique rules...
    int counter = 0;
    for (auto idx : non_unique) {
        print_progress("Handling non-unique rules",
            counter++, non_unique.size());
        int priority = rule_db[idx].priority;
        // Remove all trace packets for this rule
        (*output)[priority].clear();
        // Try to generate a header that matches the rule. No more than 5 times.
        packet_header<F> packet;
        bool valid_packet = gen_packet_in_rule(rule_db, idx, 5, packet);
        if (valid_packet) {
            (*output)[priority].push_back(packet);
        } else {
            unreachable_rules++;
        }
    }
    print_progress("Handling non-unique rules", 0, 0);
    if (unreachable_rules > 0) {
        MESSAGE("Could not generate mapping for %d rules.\n",
            unreachable_rules);
    }

    return output;
}

/**
 * @brief Writes a script that sets up OVS flows for a ruleset.
 */
void
ovs_flows_create(const char* filename,
                 const Ruleset<F>& rule_db,
                 bool full_action)
{
    FILE* file = fopen(filename, "w");
    if (file == NULL) {
        throw errorf("Cannot open \"%s\" for writing", filename);
    }

    // Create protocol string
    auto create_proto = [](const MatchingRule<F>& rule,
                           int field_idx,
                           char* dst)
    {
        if (rule.fields[field_idx].prefix == 32) {
            snprintf(dst, 15, "%d", rule.fields[field_idx].low);
        } else {
            snprintf(dst, 15, "0x00/0x00");
        }
    };

    // Create IP address string from field
    auto create_ip_address = [](const MatchingRule<F>& rule,
                                int field_idx,
                                char* dst)
    {
        uint32_t val = rule.fields[field_idx].low;
        sprintf(dst, "%d.%d.%d.%d/%d",
            (val>>24)&0xff, (val>>16)&0xff, (val>>8)&0xff, (val)&0xff,
            rule.fields[field_idx].prefix);
    };

    // Create port string from field
    auto create_port = [](const MatchingRule<F>& rule,
                          int field_idx,
                          char* dst)
    {
        uint32_t prefix = rule.fields[field_idx].prefix;
        uint32_t mask = (prefix == 32) ?
            (0xffffffff) :
            0xffffffff << (32-prefix) & 0xffffffff;
        uint32_t low = rule.fields[field_idx].low;
        uint32_t mask_of = mask & 0xffff;
        snprintf(dst, 15, "0x%x/0x%x", low, mask_of);
    };

    int of_priority = 65535;

    for (size_t i=0; i<rule_db.size(); ++i) {

        print_progress("Creating OVS flows", i, rule_db.size());

        const MatchingRule<F>& current = rule_db[i];

        char ip_proto[16], src_ip[20], dst_ip[20],
             src_port[16], dst_port[16];

        // Create fields with prefix
        create_proto(current, 0, ip_proto);
        create_port(current, 3, src_port);
        create_port(current, 4, dst_port);

        // Create IP address
        create_ip_address(current, 1, src_ip);
        create_ip_address(current, 2, dst_ip);

        // We must check whether the current rule collides with
        // any of the previous. If so, we must assign a lower
        // of_priority.
        for (size_t j=0; j<i; ++j) {
            if (rule_db[j].collide(rule_db[i])) {
                of_priority--;
                break;
            }
        }

        if (of_priority <=0) {
            throw errorf("All OpenFlow priority options are exhausted");
        }

        // Full action - modift src & dst IP addresses. Useful for checking
        // correctness of OVS classification.
        if (full_action) {
            char priority_as_ip[16];
            sprintf(priority_as_ip, "%d.%d.%d.%d",
                    (current.priority>>24)&0xff, (current.priority>>16)&0xff,
                    (current.priority>>8)&0xff, (current.priority)&0xff);

            fprintf(file,
                "add "
                "dl_type=0x0800, nw_proto=%s, "
                "nw_src=%s, nw_dst=%s, tp_src=%s, tp_dst=%s, "
                "priority=%d, "
                "actions=set_field:9.9.9.9->nw_src, "
                "set_field:%s->nw_dst,2\n",
                ip_proto, src_ip, dst_ip, src_port, dst_port,
                of_priority, priority_as_ip
                );
        }
        // No full action - just return the packet to the input port
        else {
            fprintf(file,
                "add "
                "dl_type=0x0800, nw_proto=%s, "
                "nw_src=%s, nw_dst=%s, tp_src=%s, tp_dst=%s, "
                "priority=%d, "
                "actions=2\n",
                ip_proto, src_ip, dst_ip, src_port, dst_port,
                of_priority);
        }
    }

    print_progress("Creating OVS flows", 0, 0);

    fclose(file);
}

/**
 * @brief Operate in mapping mode
 */
void
mode_mapping()
{
    MESSAGE("Mode mapping enabled\n");

    const char* out_filename = ARG_STRING(args, "out", NULL);

    const char* in_fname = ARG_STRING(args, "ruleset", NULL);
    if (in_fname == NULL) {
        throw errorf("Mode mapping requires ruleset argument.");
    }
    MESSAGE("Reading ruleset from \"%s\"...\n", in_fname);
    Ruleset<F> rule_db = ruleset_read_classbench_file(in_fname);

    int num_of_flows = ARG_INTEGER(args, "num-of-flows", 0);

    // Generate mapping
    rule_mapping_t* mapping = generate_mapping(rule_db, num_of_flows);

    // Write to file
    MESSAGE("Writing mapping to file \"%s\"...\n", out_filename);
    FILE* file_desc = fopen(out_filename, "w");
    if (!file_desc) {
        throw errorf("cannot open output filename for writing.");
    }
    for (auto map_it : *mapping) {
        for (auto pck_it : map_it.second) {
            fprintf(file_desc, "%d:", map_it.first);
            for (int i=0; i<F; ++i) {
                fprintf(file_desc, " %u", pck_it[i]);
            }
            fprintf(file_desc, "\n");
        }
    }

    delete mapping;

    fclose(file_desc);
}

/**
 * @brief Generate OVS ruleset file (flows)
 */
void
mode_ovs_flows()
{
    const char* out_filename = ARG_STRING(args, "out", NULL);
    const char* in_fname = ARG_STRING(args, "ruleset", NULL);
    if (in_fname == NULL) {
        throw errorf("Mode mapping requires ruleset argument.");
    }
    MESSAGE("Reading ruleset from \"%s\"...\n", in_fname);
    Ruleset<F> rule_db = ruleset_read_classbench_file(in_fname);

    bool full_action = ARG_BOOL(args, "full-action", 0);

    // Create OVS flows
    ovs_flows_create(out_filename, rule_db, full_action);
}

/**
 * @brief Application entry point
 */
int
main(int argc, char** argv)
{

    LOG_SET_STDOUT;

    // Parse arguments
    arg_parse(argc, argv, args);

    try {
        // Act according to mode
        if (ARG_BOOL(args, "mode-mapping", 0)) {
            mode_mapping();
        } else if(ARG_BOOL(args, "mode-ovs-flows", 0)) {
            mode_ovs_flows();
        } else {
            throw errorf("No mode was specified");
        }
    } catch (std::exception & e) {
        MESSAGE("Error: %s\n", e.what());
        return 1;
    }

    return 0;
}

