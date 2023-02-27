#ifndef READER_H
#define READER_H

#include <array>
#include <cstdint>
#include <vector>
#include <set>
#include <unordered_map>

#include "errorf.h"
#include "random.h"
#include "zstream.h"

namespace cbmapper {

class reader {
public:
    using field  = std::array<uint32_t, 2>;
    using rule   = std::vector<field>;
    using header = std::vector<uint32_t>;

private:
    std::vector<rule> rules;

    /* A lsit of headers. Does not change. */
    std::vector<header> headers;
    /* The rule-id that matches each header. Does not change. */
    std::vector<int> header_matching_rule_ids;
    /* Rule priorities */
    std::vector<int> rule_priorities;
    /* Mapping between rule-id to header index. Does not change. */
    std::unordered_map<int, int> rule_id_to_hdr_idx;

    size_t field_num;
    size_t header_num;

    /**
     * @brief Read rule from file
    */
    rule
    read_rule(zstream &file)
    {
        rule out;
        out.resize(field_num);
        for (int i=0; i<field_num; ++i) {
            out[i][0] = file.read_u32();
            out[i][1] = file.read_u32();
        }
        return out;
    }

    /**
     * @brief Reads a header from "file", updates "headers" and
     * "header_matching_rule_ids" in index "idx". Also updates
     * "rule_id_to_hdr_idx".
    */
    void
    read_header(zstream &file, int idx)
    {
        int idx_num, rule_idx;

        headers[idx].resize(field_num);

        for (int i=0; i<field_num; ++i) {
            headers[idx][i] = file.read_u32();
        }

        rule_idx = file.read_u32();
        header_matching_rule_ids[idx] = rule_idx;
        rule_id_to_hdr_idx[rule_idx] = idx;
    }

public:

    /**
     * @brief Reads rules and packet headers from the binary file "filename".
     */
    void
    read(const char *filename)
    {
        zstream file;
        file.open_read(filename);

        if (file.read_string(6) != "ruledb") {
            throw errorf("Cannot read file: header mismatch");
        }

        rules.resize(file.read_u32());
        rule_priorities.resize(rules.size());
        field_num = file.read_u32();

        for (size_t i=0; i<rules.size(); ++i) {
            rule_priorities[i] = file.read_u32();
            rules[i] = read_rule(file);
        }

        if (file.read_string(8) != "packetdb") {
            throw errorf("Cannot read file: header mismatch");
        }

        header_num = file.read_u32();
        headers.resize(header_num);
        header_matching_rule_ids.resize(header_num);

        for (int i=0; i<header_num; ++i) {
            read_header(file, i);
        }
    }

    /**
     * @brief Returns the number of files
     */
    size_t
    get_field_num()
    {
        return field_num;
    }

    /**
     * @brief Returns the number of header fields.
     */
    size_t
    get_header_num()
    {
        return header_num;
    }

    /**
     * @brief Returns the number of rules
     */
    size_t
    get_rule_num()
    {
        return rules.size();
    }

    /**
     * @brief Returns rule with ID "idx"
     */
    const rule&
    get_rule(size_t idx)
    {
        return rules[idx];
    }

    /**
     * @brief Returns the rule priority for rule with ID idx
     */
    int
    get_rule_prio(size_t idx)
    {
        return rule_priorities[idx];
    }

    /**
     * @brief Returns packet header with ID "idx"
     */
    const header&
    get_header(size_t idx)
    {
        return headers[idx];
    }

    /**
     * @brief Returns the rule ID that match header ID "idx"
     */
    int
    get_header_match(size_t idx)
    {
        return header_matching_rule_ids[idx];
    }

    /**
     * @brief Returns the header ID that match rule ID "idx".
     */
    int
    get_header_index(size_t matching_rule_id)
    {
        return rule_id_to_hdr_idx[matching_rule_id];
    }
};

};

#endif