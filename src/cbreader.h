/* CBReader library header. Read compressed binary files that hold N-tuple rules
 * and packet headers that match these rules. Use this library for managing
 * multi-threaded environments (single writer multiple readers) that test
 * new classifiers.
 *
 * MIT License. Copyright (c) 2023 Alon Rashelbach.
 *
 * If you happen to use this library for an academic paper, please cite
 * Scaling Open vSwitch with a Computational Cache, USENIX NSDI 2022.
 *
 * For source code and utilities for generating these bianry files, see
 * https://github.com/alonrs/classbench-mapper. */

#ifndef CBREADER_H
#define CBREADER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdint.h>

struct cbreader;

/**
 * @brief Returns a string representation of the last library error.
 */
const char * cbreader_get_last_error();

/**
 * @brief Initiates a new cbreader object from binary file "filename".
 * Sets random seed to be "seed".
 * @returns A new cbreader object, or NULL in case of an error.
 */
struct cbreader * cbreader_init(const char *filename, int seed);

/**
 * @brief Destroies the cbreader object "cbr".
 */
void cbreader_destroy(struct cbreader *cbr);

/**
 * @brief Returns the number of fields per rule / header.
 */
size_t cbreader_get_field_num(struct cbreader *cbr);

/**
 * @brief Returns the number of headers available in this
 */
size_t cbreader_get_header_num(struct cbreader *cbr);

/**
 * @brief Returns the number of rules avaialble in this.
 */
size_t cbreader_get_rule_num(struct cbreader *cbr);

/**
 * @brief Returns a rule by its index.
 * @param cbr The cbreader object.
 * @param idx The rule index.
 * @param data Preallocated memory for holding the result. Must contain 2F
 * elements, where F = cbreader_get_field_num(cbr). Each two adjacent values
 * represent the lo and hi values per field.
 * @param prio Set by this. The rule priority.
 * @returns
 *  - -EINVAL in case of invalid arguments
 *  - -EAGAIN in case of internal error
 *  - Zero on success.
 */
int cbreader_get_rule(struct cbreader *cbr,
                      size_t idx,
                      uint32_t *data,
                      int *prio);

/**
 * @brief Select rules for insertion in the next classifier update.
 * Only a single writer thread may call this method.
 * @param cbr The cbreader object.
 * @param num_rules Number of rule to prepare
 * @param data Preallocated memory for holding the result. Must contain
 * "num_rules" elements. This method populates "data" with the indices of
 * the selected rules.
 * @returns
 *  - -EINVAL in case of invalid arguments
 *  - -EAGAIN in case of internal error
 *  - A non-negative number with the number of rule selected for the next
 *    update.
 */
int cbreader_prepare_rules(struct cbreader *cbr, int num_rules, uint32_t *data);

/**
 * @brief Clear all rules in the next classifier update.
 * Only a single writer thread may call this method.
 * @param cbr The cbreader object.
 * @returns
 *  - -EINVAL in case of invalid arguments
 *  - -EAGAIN in case of internal error
 *  - Zero on success
 */
int cbreader_clear_rules(struct cbreader *cbr);

/**
 * @brief Set all rules in the next classifier update.
 * Only a single writer thread may call this method.
 * @param cbr The cbreader object.
 * @returns
 *  - -EINVAL in case of invalid arguments
 *  - -EAGAIN in case of internal error
 *  - Zero on success
 */
int cbreader_set_all_rules(struct cbreader *cbr);

/**
 * @brief Atomically updates the classifier with the pending rules.
 * Only a single writer thread may call this method.
 * @param cbr The cbreader object.
 * @returns
 *  - -EINVAL in case of invalid arguments
 *  - -EAGAIN in case of internal error
 *  - Zero on success
 */
int cbreader_update(struct cbreader *cbr);

/**
 * @brief Generates headers and their corresponding matching rule index for the
 * current version of the classifier. Thread safe. Multiple concurrent readers
 * are allowed.
 * @param cbr The cbreader object.
 * @param hdr_num Number of header to generate
 * @param hdr_data Preallocated memory for holding the result. Must contain
 * "hdr_num" elements. This method populates "hdr_data" with pointers to headers
 * each with F fields (F = cbreader_get_field_num(cbr)).
 * @param results Preallocated memory for holding the result. Must contain
 * "hdr_num" elements. This method populates "results" with the matching rule
 * index per generated header.
 * @returns
 *  - -EINVAL in case of invalid arguments
 *  - -EAGAIN in case of internal error
 *  - Non-negative number in case of success. Number of generated headers.
 */
int cbreader_select_headers(struct cbreader *cbr,
                            int hdr_num,
                            const uint32_t **hdr_data,
                            uint32_t *results);

/**
 * @brief Search "rule_id" in one of "cbr"'s internal data structues.
 * Returns a bit-mask with the data structure indices that hold "rule-id".
 * Only a single writer thread may call this method.
 * @returns
 *  - -EINVAL in case of invalid arguments
 *  - -EAGAIN in case of internal error
 *  - Zero if the rule was not found.
 *  - A positive integer (bit-mask) if the rule was found.
*/
int cbreader_search_rule(struct cbreader *cbr, int rule_id);

#ifdef __cplusplus
}
#endif

#endif /* CBREADER_H */
