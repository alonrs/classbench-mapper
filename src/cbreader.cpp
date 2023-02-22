#include <atomic>
#include <cerrno>
#include <exception>
#include "reader.h"

static const char *msg;

struct cbreader {
    reader rdr;
    std::set<int> avaialble_rules_v0;
    std::set<int> avaialble_rules_v1;
    std::set<int> avaialble_rules_v2;
    std::atomic<int> version;
};

/* Returns the pending set for updateing the rules. Must be in sync. */
static std::set<int>&
get_pending_set(cbreader *cbr)
{
    int ver = cbr->version.load(std::memory_order::memory_order_acquire);
    switch (ver & 0x2) {
    case 0:  return cbr->avaialble_rules_v1;
    case 1:  return cbr->avaialble_rules_v2;
    default: return cbr->avaialble_rules_v0;
    }
}

/* Returns the active set for reading the rules. Does not have to be in sync. */
static std::set<int>&
get_active_set(cbreader *cbr)
{
    int ver = cbr->version.load(std::memory_order::memory_order_relaxed);
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
cbreader_select_rules(cbreader *cbr, int num_rules, uint32_t *data)
{
    if (!cbr || !data) {
        return -EINVAL;
    }

    int tries = 100;
    int out = 0;
    try {
        std::set<int> &pending_set = get_pending_set(cbr);
        while (num_rules) {
            int idx = random_core::random_uint32() % cbr->rdr.get_rule_num();
            if (pending_set.find(idx) != pending_set.end()) {
                tries--;
                if (tries <=0 ) {
                    return out;
                }
            }
            pending_set.insert(idx);
            data[out] = idx;
            out++;
        }
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
        get_pending_set(cbr).clear();
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
cbreader_select_headers(cbreader *cbr, int num_headers, uint32_t **data)
{
    if (!cbr) {
        return -EINVAL;
    }
    try {
        std::set<int> &avaialble_rules = get_active_set(cbr);
        if (!avaialble_rules.size()) {
            return 0;
        }

    } catch (std::exception &e) {
        msg = e.what();
        return -EAGAIN;
    }
}
