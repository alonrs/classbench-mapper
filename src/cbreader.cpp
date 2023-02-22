#include <atomic>
#include <algorithm>
#include <cerrno>
#include <exception>
#include "reader.h"

static const char *msg;

struct cbreader {
    reader rdr;
    std::vector<int> avaialble_rules_v0;
    std::vector<int> avaialble_rules_v1;
    std::vector<int> avaialble_rules_v2;
    std::atomic<int> version;
    std::atomic<int> readers_v0;
    std::atomic<int> readers_v1;
    std::atomic<int> readers_v2;
};

/* Returns the pending set for updateing the rules. Must be in sync. */
static std::vector<int>&
get_pending_vec(cbreader *cbr)
{
    int ver = cbr->version.load(std::memory_order::memory_order_acquire);
    /* Wait for all readers to complete */
    switch (ver & 0x2) {
    case 0:  while (cbr->readers_v0.load()); break;
    case 1:  while (cbr->readers_v1.load()); break;
    default: while (cbr->readers_v2.load()); break;
    }
    /* Returns the relevant vector */
    switch (ver & 0x2) {
    case 0:  return cbr->avaialble_rules_v1;
    case 1:  return cbr->avaialble_rules_v2;
    default: return cbr->avaialble_rules_v0;
    }
}

static int
acquire_active(cbreader *cbr)
{
    int ver = cbr->version.load(std::memory_order::memory_order_relaxed);
    switch (ver & 0x2) {
    case 0:  cbr->readers_v0.fetch_add(1);
    case 1:  cbr->readers_v1.fetch_add(1);
    default: cbr->readers_v2.fetch_add(1);
    }
    return ver;
}

static void
release_active(cbreader *cbr, int ver)
{
    switch (ver & 0x2) {
    case 0:  cbr->readers_v0.fetch_sub(1);
    case 1:  cbr->readers_v1.fetch_sub(1);
    default: cbr->readers_v2.fetch_sub(1);
    }
}

/* Returns the active set for reading the rules. Does not have to be in sync. */
static std::vector<int>&
get_active_vec(cbreader *cbr, int ver)
{
    switch (ver & 0x2) {
    case 0:  return cbr->avaialble_rules_v0;
    case 1:  return cbr->avaialble_rules_v1;
    default: return cbr->avaialble_rules_v2;
    }
}

const char *
get_last_error()
{
    return msg;
}

cbreader *
cbreader_init(const char *filename, int seed)
{
    cbreader *out;
    try {
        out = new cbreader;
        out->rdr.read(filename);
        out->version.store(0);
        random_core::set_seed(seed);
        return out;
    } catch (std::exception &e) {
        msg = e.what();
        return NULL;
    }
}

void
cbreader_destroy(cbreader *cbr)
{
    if (!cbr) {
        return;
    }
    delete cbr;
}

size_t
cbreader_get_field_num(cbreader *cbr)
{
    if (!cbr) {
        return 0;
    }
    return cbr->rdr.get_field_num();
}

size_t
cbreader_get_header_num(cbreader *cbr)
{
    if (!cbr) {
        return 0;
    }
    return cbr->rdr.get_header_num();
}

size_t
cbreader_get_rule_num(cbreader *cbr)
{
    if (!cbr) {
        return 0;
    }
    return cbr->rdr.get_rule_num();
}

int
cbreader_get_rule(cbreader *cbr, size_t idx, uint32_t *data)
{
    if (!cbr || !data || idx >= cbr->rdr.get_rule_num()) {
        return -EINVAL;
    }
    try {
        const reader::rule &r = cbr->rdr.get_rule(idx);
        int c = 0;
        for (int i=0; i<cbr->rdr.get_field_num(); ++i) {
            data[c] = r[i][0];
            data[c+1] = r[i][0];
            c+=2;
        }
        return 0;
    } catch (std::exception &e) {
        msg = e.what();
        return -EAGAIN;
    }
}

int
cbreader_prepare_rules(cbreader *cbr, int num_rules, uint32_t *data)
{
    static constexpr int tries = 128;

    if (!cbr || !data) {
        return -EINVAL;
    }

    int out = 0;
    try {
        /* Randomize "tries" rule IDs */
        std::vector<int> rule_ids;
        rule_ids.resize(tries);
        for (size_t i=0; i<tries; ++i) {
            rule_ids[i] = random_core::random_uint32() %
                          cbr->rdr.get_rule_num();
        }
        std::sort(rule_ids.begin(), rule_ids.end());

        std::vector<int> &pending_vec = get_pending_vec(cbr);
        size_t cursor = 0;

        /* Both "pending_vec" and "rule_ids" are sorted. Mark "rule_ids" that
         * are already presented in "pending_vec" */
        for (size_t i=0; i<pending_vec.size(); ++i) {
            while (cursor < tries && rule_ids[cursor] < pending_vec[i]) {
                cursor++;
            }
            if (cursor == tries) {
                break;
            }
            if (rule_ids[cursor] == pending_vec[i]) {
                rule_ids[cursor] = -1;
            }
        }

        /* Shuffle rule-ids, select first "num_rules" valid entries. */
        random_core::shuffle(rule_ids.begin(), rule_ids.end());

        cursor = 0;
        while (num_rules) {
            while (cursor < tries && rule_ids[cursor] == -1) {
                continue;
            }
            if (cursor == tries) {
                break;
            }
            pending_vec.push_back(rule_ids[cursor]);
            data[out] = rule_ids[cursor];
            out++;
        }

        std::sort(pending_vec.begin(), pending_vec.end());
        return out;
    } catch (std::exception &e) {
        msg = e.what();
        return -EAGAIN;
    }
}

int
cbreader_clear_rules(cbreader *cbr)
{
    if (!cbr) {
        return -EINVAL;
    }
    try {
        get_pending_vec(cbr).clear();
        return 0;
    } catch (std::exception &e) {
        msg = e.what();
        return -EAGAIN;
    }
}

int
cbreader_update(cbreader *cbr)
{
    if (!cbr) {
        return -EINVAL;
    }
    try {
        int ver = cbr->version.fetch_add(1) + 1;
        /* Copy "active" to pending. Must be in sync. */
        switch (ver & 0x2) {
        case 0:  cbr->avaialble_rules_v1 = cbr->avaialble_rules_v0; break;
        case 1:  cbr->avaialble_rules_v2 = cbr->avaialble_rules_v1; break;
        default: cbr->avaialble_rules_v0 = cbr->avaialble_rules_v2; break;
        }
        return 0;
    } catch (std::exception &e) {
        msg = e.what();
        return -EAGAIN;
    }
}

int
cbreader_select_headers(cbreader *cbr,
                        int hdr_num,
                        const uint32_t **hdr_data,
                        uint32_t *results)
{
    if (!cbr) {
        return -EINVAL;
    }
    try {
        int ver = acquire_active(cbr);
        std::vector<int> &avaialble_rules = get_active_vec(cbr, ver);
        if (!avaialble_rules.size()) {
            release_active(cbr, ver);
            return 0;
        }
        for (int i=0; i<hdr_num; ++i) {
            int idx = random_core::random_uint32() % avaialble_rules.size();
            int hdr_idx = avaialble_rules[idx];
            const reader::header &hdr = cbr->rdr.get_header(hdr_idx);
            hdr_data[i] = (const uint32_t*)&hdr;
            results[i] = cbr->rdr.get_header_match(hdr_idx);
        }
        release_active(cbr, ver);
        return hdr_num;
    } catch (std::exception &e) {
        msg = e.what();
        return -EAGAIN;
    }
}
