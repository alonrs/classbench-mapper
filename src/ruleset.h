#pragma once

#include <algorithm>
#include <vector>
#include <map>
#include <unordered_map>
#include <random>

#include "errorf.h"

/**
 * @brief A field is a range of 32-bit integers
 */
struct MatchingRuleField {
	/// Both are inclusive
	uint32_t low, high;
	/// How many bits are exact match (0-32)
	uint8_t prefix;

	/**
	 * @brief For using MatchingRuleField in STL containers
	 */
	bool
    operator<(const MatchingRuleField& other) const
    {
		if (low == other.low) {
			return (high < other.high);
		} else {
			return (low < other.low);
		}
	}
};

/**
 * @brief A matching rule
 * @tparam F Number of 32-bit fields
 */
template <int F>
struct MatchingRule {

	/// All fields of this
	std::array<MatchingRuleField, F> fields;

	/// Negative priority == invalid rule
	int priority;

    int unique_id;

	MatchingRule()
    : priority(-1)
	{
        static uint32_t counter = 1;
        this->unique_id = counter++;
		for (size_t i=0; i<F; ++i) {
			fields[i].low = 0;
			fields[i].high = 0xffffffff;
			fields[i].prefix = 0;
		}
	}

	/**
	 * @brief Returns the header in the position
	 */
	const MatchingRuleField&
    operator[] (uint32_t idx) const
    {
        return fields.at(idx);
    }

	MatchingRuleField&
    operator[] (uint32_t idx)
    {
        return fields.at(idx);
    }

	/**
	 * @brief Returns true iff this collides with other
	 */
	bool
    collide(const MatchingRule& other) const
    {
		if (&other == this) {
            return true;
        }
		for (int i=0; i<F; ++i) {
			bool collide_low  = ( (fields[i].low >= other.fields[i].low)  && 
                                  (fields[i].low <= other.fields[i].high) );
			bool collide_high = ( (fields[i].high >= other.fields[i].low) &&
                                  (fields[i].high <= other.fields[i].high) );
			if (!collide_low && !collide_high) {
                return false;
            }
		}
		return true;
	}

	/**
	 * @brief For using MatchingRule in STL containers
	 */
	bool
    operator< (const MatchingRule<F>& other) const
    {
		int my_smallest_field = F, other_smallest_field = F;
		for (int i=0; i<F; ++i) {
			if (fields[i] < other.fields[i]) {
				my_smallest_field = std::min(my_smallest_field, i);
			}
			if (other.fields[i] < fields[i]) {
				other_smallest_field = std::min(other_smallest_field, i);
			}
		}
		return my_smallest_field < other_smallest_field;
	}
};

/**
 * @brief A set of matching rules
 * @tparam F number of fields in rule
 */
template<int F>
class Ruleset {
public:

	/// Ruleset iterator is vector iterator
	using iterator = typename
        std::vector<MatchingRule<F>>::iterator;
	using const_iterator = typename 
        std::vector<MatchingRule<F>>::const_iterator;

	/// Get rules by index
	const MatchingRule<F>&
	operator[](int index) const
    {
		return rule_vector[index];
	}

	/// Get rules by index
	MatchingRule<F>&
	operator[](int index)
    {
		return rule_vector[index];
	}

	/// Get number of rules
	size_t
	size() const
    {
		return rule_vector.size();
	}

	/// Returns an iterator to the beginning of this
	iterator
	begin()
    {
		return rule_vector.begin();
	}

	/// Returns an iterator to the end of this
	iterator
    end()
    {
		return rule_vector.end();
	}

	/// Returns an iterator to the beginning of this
	const_iterator
	begin() const
    {
		return rule_vector.begin();
	}

	/// Returns an iterator to the end of this
	const_iterator end()
    const
    {
		return rule_vector.end();
	}

	/**
	 * @brief Pushes new rule into this.
	 * @throws In case the rule does not have a unique id.
	 */
	void
	push_back(const MatchingRule<F>& r)
    {
		if (id_map.find(r.unique_id) != id_map.end()) {
			throw errorf("Cannot insert rule to Ruleset: "
                         "rule's id is not unique");
		}
		id_map[r.unique_id] = rule_vector.size();
		rule_vector.push_back(r);
	}

	/**
	 * @brief Shuffles the Ruleset according to seed
	 */
	void
	shuffle(size_t seed)
    {
		std::mt19937 g(seed);
		std::shuffle(rule_vector.begin(), rule_vector.end(), g);
		id_map.clear();
		for(size_t pos=0; pos<rule_vector.size(); ++pos) {
			auto& rule = rule_vector[pos];
			if (id_map.find(rule.unique_id) != id_map.end()) {
				throw errorf("Rule ID after shuffle is not unique!");
			}
			id_map[rule.unique_id] = pos;
		}
	}

	/**
	 * @brief Erases a rule from this by id
	 * @throws In case id is not found.
	 */
	void
	erase(uint32_t id)
    {
		if (id_map.find(id) == id_map.end()) {
			throw errorf("Cannot erase rule: id is not found");
		}

		size_t pos = id_map[id];
		size_t id_back = rule_vector.back().unique_id;

		if (id != id_back) {
			rule_vector[pos] = rule_vector.back();
			id_map[id_back] = pos;
		}

		rule_vector.pop_back();
		id_map.erase(id);

	}

	/**
	 * @brief Erases a rule from this by iterator
	 */
	void
	erase(iterator position)
    {
		if (position == rule_vector.end()) {
			return;
		}
		erase(rule_vector[position].unique_id);
	}

	/**
	 * @brief Get a rule by its unique id.
	 * @throws in case there is no such rule
	 */
	const MatchingRule<F>&
	get_by_id(uint32_t id) const
    {
		if (id_map.find(id) == id_map.end()) {
			throw errorf("Ruleset cannot find rule with id=%u", id);
		}
		return rule_vector[id_map.at(id)];
	}

	/**
	 * @brief Get a rule by its unique id.
	 * @throws in case there is no such rule
	 */
	MatchingRule<F>&
	get_by_id(uint32_t id)
    {
		if (id_map.find(id) == id_map.end()) {
			throw errorf("Ruleset cannot find rule with id=%u", id);
		}
		return rule_vector[id_map[id]];
	}

	/**
	 * @brief Returns true iff this contains a rule with "id"
	 */
	bool
	contains(uint32_t id) const
    {
		return id_map.find(id) != id_map.end();
	}

	/**
	 * @brief Clears all rules from this
	 */
	void
	clear()
    {
		rule_vector.clear();
		id_map.clear();
	}

	/**
	 * @brief Insert a list of rules at the back of this
	 * @param start Iterator that points to the beginning of the list
	 * @param end Iterator that points to the end of the list
	 */
	void
	insert(iterator start, iterator end)
    {
		for (; start != end; start++) {
			this->push_back(*start);
		}
	}

private:

	std::vector<MatchingRule<F>> rule_vector;
	std::unordered_map<uint32_t, size_t> id_map;
};

/**
 * @brief A packet header is an array of values, one per field.
 */
template<int F>
using packet_header = std::array<uint32_t, F>;

/**
 * @brief Reads Classbench file, returns a ruleset
 * @param filename Path to a Classbench file
 * @throw IO error, file format error
 */
Ruleset<5> ruleset_read_classbench_file(const char* filename);

