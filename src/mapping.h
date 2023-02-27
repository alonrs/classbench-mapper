#ifndef MAPPING_H
#define MAPPING_H

#include <array>
#include <chrono>
#include <set>
#include <map>
#include <thread>

#include "random.h"
#include "ruleset.h"
#include "zstream.h"

namespace cbmapper {

template <int F>
class mapping {

    static constexpr int TRIES = 5;
    using packet_hdr = packet_header<F>;
    using field_mapping = std::map<int, std::vector<uint32_t>>;
    using rule_mapping = std::map<int, std::vector<packet_hdr>>;

    /**
     * @brief Returns true iff "rule_idx" matches "hdr"
    */
    static inline bool
    hdr_matches_rule(const ruleset<F>& rule_db,
                     int rule_idx,
                     const packet_hdr &hdr)
    {
        for (uint32_t j=0; j<F; ++j) {
            uint32_t field_start = rule_db[rule_idx].fields[j].low;
            uint32_t field_end = rule_db[rule_idx].fields[j].high;
            if ((hdr[j] < field_start)||(hdr[j] > field_end)) {
                return false;
            }
        }
        return true;
    }

    /**
     * @brief Populates "out" with a new packet. Tries to generate packet that
     * matches "rule_idx", but this might not succeed. Returns true if "out" is
     * valid.
     */
    static bool
    gen_packet(const ruleset<F>& rule_db, int rule_idx, packet_hdr &out)
    {
        const rule<F>& rule = rule_db[rule_idx];
        bool previous_match;

        for (int i=0; i<TRIES; ++i) {

            for (int j=0; j<F; ++j) {
                out[j] = random_core::random_uint32(rule[j].low,
                                                    rule[j].high);
                if ((out[j] < rule[j].low) || (out[j] > rule[j].high)) {
                    return false;
                }
            }

            previous_match = false;
            for (int r=0; r<rule_idx-1; ++r) {
                if (!hdr_matches_rule(rule_db, rule_idx, out)) {
                    continue;
                }
                previous_match = true;
                break;
            }

            if (!previous_match) {
                return true;
            }
        }
        return false;
    }

    /**
     * @brief Processes the rules in field "f". Generates "num" values per rule,
     * fills "out" with results.
    */
    static void
    process_field(const ruleset<F>& rule_db,
                  int f,
                  int num,
                  std::set<int> &non_unique,
                  field_mapping &out,
                  std::atomic<int> &percent)
    {
        integer_interval_set interval(0, 0xffffffff);
        bool can_guarantee;

        for (size_t i=0; i<rule_db.size(); ++i) {

            uint32_t lo = rule_db[i].fields[f].low;
            uint32_t hi = rule_db[i].fields[f].high;

            if (out.find(i) == out.end()) {
                out[i].resize(num);
            }

            integer_interval_set sub_interval = interval.remove(lo, hi);
            can_guarantee = sub_interval.size() > 0;

            for (int j=0; j<num; ++j) {
                out[i][j] = can_guarantee ?
                               sub_interval.random_value() :
                               random_core::random_uint32(lo, hi);
            }

            /* We cannot guarantee a unique mapping */
            if (!can_guarantee) {
                non_unique.insert(i);
            }

            percent.store(i*100.0/rule_db.size());
        }
        percent.store(100);
    }

    /**
     * @brief Prints the status of all "process_field" threads to stdout.
    */
    bool
    print_status(const std::array<std::atomic<int>, F> &status)
    {
        bool finished = true;
        MESSAGE("\rStatus: ");
        for (int i=0; i<F; ++i) {
            MESSAGE("field-%d: %d%% ", i, status[i].load());
            finished &= status[i] >= 100;
        }
        MESSAGE("\r");
        return finished;
    }

    const ruleset<F> *rule_db;
    rule_mapping rmap;

public:

    /**
     * @brief Processes "rule_db" and generates a total "flow_num" packets.
    */
    void
    run(const ruleset<F> &rule_db, int flow_num)
    {
        std::array<std::set<int>,   F> non_unqiue_field;
        std::array<field_mapping,   F> field_values;
        std::array<std::thread,     F> threads;
        std::array<std::atomic<int>,F> status;
        packet_header<F> packet;
        bool valid;

        this->rule_db = &rule_db;

        int num = flow_num / rule_db.size();
        for (int i=0; i<rule_db.size(); i++) {
            rmap[i].resize(num);
        }

        MESSAGE("Starting packet header mapping threads...\n");
        for (uint32_t f=0; f<F; ++f) {
            std::thread current(process_field,
                                std::cref(rule_db),
                                f,
                                num,
                                std::ref(non_unqiue_field[f]),
                                std::ref(field_values[f]),
                                std::ref(status[f]));
            threads[f].swap(current);
        }

        /* Print status */
        do {
            std::this_thread::sleep_for(std::chrono::milliseconds(700));
        } while (!print_status(status));

        for (uint32_t f=0; f<F; ++f) {
            threads[f].join();
        }

        std::set<int> non_unique = std::move(non_unqiue_field[0]);
        for (uint32_t f=1; f<F; ++f) {
            std::set<int> intersect;
            set_intersection(non_unique.begin(),
                             non_unique.end(),
                             non_unqiue_field[f].begin(),
                             non_unqiue_field[f].end(),
                             std::inserter(intersect, intersect.begin()));
            non_unique = intersect;
        }

        /* Update unique packets */
        MESSAGE("\nUpdating unique packet headers... \n");
        for (uint32_t f=0; f<F; ++f) {
            for (int i=0; i<rule_db.size(); i++) {
                if (non_unique.find(i) != non_unique.end()) {
                    continue;
                }
                for (int j=0; j<num; j++) {
                    rmap[i][j][f] = field_values[f][i][j];
                }
            }
        }

        // Update mapping for non-unique rules
        MESSAGE("Non-unique rules: %lu\n", non_unique.size());
        int unreachable_rules = 0;

        // Handle non-unique rules...
        int counter = 0;
        for (auto idx : non_unique) {
            print_progress("Handling non-unique rules", counter++,
                           non_unique.size());
            valid = gen_packet(rule_db, idx, packet);
            if (valid) {
                rmap[idx].push_back(packet);
            } else {
                unreachable_rules++;
            }
        }
        print_progress("Handling non-unique rules", 0, 0);

        if (unreachable_rules > 0) {
            MESSAGE("Could not generate mapping for %d rules.\n",
                unreachable_rules);
        }

        /* Check that mapping is correct */
        MESSAGE("Checking that the generated mapping is correct...\n");
        typename rule_mapping::const_iterator it;
        for (it = rmap.begin(); it != rmap.end(); ++it) {
            const std::vector<packet_hdr> &hdr_vec = it->second;
            const int &id = it->first;
            for (const packet_hdr &hdr : hdr_vec) {
                if (!hdr_matches_rule(rule_db, id, hdr)) {
                    MESSAGE("Error! \n");
                    exit(1);
                }
            }
        }
    }

    /**
     * @brief Saves the packet mapping into a textual file in format
     * RULE-ID: FIELD0 FIELD1 ...
    */
    void
    save_text_mapping(const char *filename)
    {
        MESSAGE("Writing mapping to file \"%s\"...\n", filename);
        FILE* file_desc = fopen(filename, "w");
        if (!file_desc) {
            throw errorf("cannot open output filename for writing.");
        }
        for (auto map_it : rmap) {
            for (auto pck_it : map_it.second) {
                fprintf(file_desc, "%d:", map_it.first);
                for (int i=0; i<F; ++i) {
                    fprintf(file_desc, " %u", pck_it[i]);
                }
                fprintf(file_desc, "\n");
            }
        }
        fclose(file_desc);
    }

    /**
     * @brief Saves the rule-db and packet data into a compreseed bunary-file
     * that can be loaded later in order to replay packets.
     */
    void
    save_binary_format(const char *filename)
    {
        zstream file;
        typename rule_mapping::const_iterator it;

        MESSAGE("Writing bianry data to file %s...\n", filename);
        file.open_write(filename);

        /* Write rule database */
        file << "ruledb"
             << rule_db->size()
             << F;

        for (size_t i=0; i<rule_db->size(); ++i) {
            file << rule_db->at(i).priority;
            for (int f=0; f<F; ++f) {
                file << rule_db->at(i).fields[f].low
                     << rule_db->at(i).fields[f].high;
            }
        }

        size_t header_num = 0;
        for (it = rmap.begin(); it != rmap.end(); ++it) {
            header_num += it->second.size();
        }

        /* Write packet database */
        file << "packetdb"
             << header_num;

        for (it = rmap.begin(); it != rmap.end(); ++it) {
            const std::vector<packet_hdr> &hdr_vec = it->second;
            const int &id = it->first;

            for (const packet_hdr &hdr : hdr_vec) {
                for (int f=0; f<F; ++f) {
                    file << hdr[f];
                }
                file << id;
            }
        }
    }

};

};

#endif /* MAPPING_H */
