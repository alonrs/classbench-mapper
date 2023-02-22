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

#include "arguments.h"
#include "errorf.h"
#include "integer-interval-set.h"
#include "log.h"
#include "mapping.h"
#include "random.h"
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
{"out-binary",         0, 0, NULL,      "(Mode Mapping) Generate binary file "
                                        "with rule and packet header data."},
// Mode OVS flows
{"mode-ovs-flows",     0, 1, NULL,      "(Mode OVS Flows) Generate OVS flows "
                                        "script from a ruleset."},
{"full-action",        0, 1, NULL,      "(Mode OVS Flows) Makes the OVS rules "
                                        "change src & dst IP addresses for "
                                        "checking correctness."},
// Others
{"ruleset",            0, 0, NULL,      "ClassBench ruleset to analyze."},
{"seed",               0, 0, "0",       "Random seed. Use 0 for randomized "
                                        "seed."},
{"reverse-priorities", 0, 0, NULL,      "Reverse rule priorities; e.g., rule "
                                        "#1 will have the highest priority, "
                                        "and rule #N will have priority = 1"},
{NULL,                 0, 0, NULL,      "Analyzes ClassBench ruleset files. "
                                        "Generates either a unique packet to "
                                        "match per flow, or textual file with "
                                        "Open vSwitch (OVS) flows."}
};

static constexpr int F = 5;

/**
 * @brief Writes a script that sets up OVS flows for a ruleset.
 */
void
ovs_flows_create(const char* filename,
                 const ruleset<F>& rule_db,
                 bool full_action)
{
    FILE* file = fopen(filename, "w");
    if (file == NULL) {
        throw errorf("Cannot open \"%s\" for writing", filename);
    }

    // Create protocol string
    auto create_proto = [](const rule<F>& rule,
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
    auto create_ip_address = [](const rule<F>& rule,
                                int field_idx,
                                char* dst)
    {
        uint32_t val = rule.fields[field_idx].low;
        sprintf(dst, "%d.%d.%d.%d/%d",
            (val>>24)&0xff, (val>>16)&0xff, (val>>8)&0xff, (val)&0xff,
            rule.fields[field_idx].prefix);
    };

    // Create port string from field
    auto create_port = [](const rule<F>& rule,
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

        const rule<F>& current = rule_db[i];

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
    mapping<F> mp;

    MESSAGE("Mode mapping enabled\n");
    const char* in_fname     = ARG_STRING(args, "ruleset", NULL);
    if (in_fname == NULL) {
        throw errorf("Mode mapping requires ruleset argument.");
    }

    bool reverse = ARG_STRING(args, "reverse-priorities", 0);
    MESSAGE("Reading ruleset from \"%s\"...\n", in_fname);
    ruleset<F> rule_db = ruleset_read_classbench_file(in_fname, reverse);

    int num_of_flows = ARG_INTEGER(args, "num-of-flows", 0);

    // Generate mapping
    mp.run(rule_db, num_of_flows);

    const char* out_filename = ARG_STRING(args, "out", NULL);
    mp.save_text_mapping(out_filename);

    const char *out_binary   = ARG_STRING(args, "out-binary", NULL);
    if (out_binary) {
        mp.save_binary_format(out_filename);
    }
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

    bool reverse = ARG_STRING(args, "reverse-priorities", 0);
    MESSAGE("Reading ruleset from \"%s\"...\n", in_fname);
    ruleset<F> rule_db = ruleset_read_classbench_file(in_fname, reverse);

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

    int seed = ARG_INTEGER(args, "seed", 0);
    MESSAGE("Running with seed %d\n", seed);
    random_core::set_seed(seed);

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

