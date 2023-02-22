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

class reader {
public:
    using field  = std::array<uint32_t, 2>;
    using rule   = std::vector<field>;
    using header = std::vector<uint32_t>;

private:
    std::vector<rule> rules;

    /* A lsit of headers. Does not change. */
    std::vector<header> headers;
    /* A list of rule-ids that match each header. Does not change. */
    std::vector<std::vector<int>> header_matching_rule_ids;
    /* Mapping between rule-ids and header indices. Does not change. */
    std::unordered_map<int, std::vector<int>> rule_id_to_hdr_idx;

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

        for (int i=0; i<field_num; ++i) {
            headers[idx][i] = file.read_u32();
        }

        idx_num = file.read_u32();
        header_matching_rule_ids[idx].resize(idx_num);
        for (int i=0; i<idx_num; ++i) {
            rule_idx = file.read_u32();
            header_matching_rule_ids[idx][i] = rule_idx;
            /* Reserve space for 4 header indices per rule id */
            if (rule_id_to_hdr_idx.find(rule_idx) == rule_id_to_hdr_idx.end()) {
                rule_id_to_hdr_idx[rule_idx].reserve(4);
            }
            rule_id_to_hdr_idx[rule_idx].push_back(rule_idx);
        }
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
        field_num = file.read_u32();

        for (size_t i=0; i<rules.size(); ++i) {
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
     * @brief Returns packet header with ID "idx"
     */
    const header&
    get_header(size_t idx)
    {
        return headers[idx];
    }

    /**
     * @brief Returns a vector with rule IDs that match header ID "idx"
     */
    const std::vector<int>&
    get_header_matches(size_t idx)
    {
        return header_matching_rule_ids[idx];
    }

    /**
     * @brief Returns a vector of header IDs that match rule ID "idx".
     */
    const std::vector<int>&
    get_header_indices(size_t matching_rule_id)
    {
        return rule_id_to_hdr_idx[matching_rule_id];
    }
};

#endif