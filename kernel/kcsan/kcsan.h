/* SPDX-License-Identifier: GPL-2.0 */

/*
 * The Kernel Concurrency Sanitizer (KCSAN) infrastructure. For more info please
 * see Documentation/dev-tools/kcsan.rst.
 */

#ifndef _KERNEL_KCSAN_KCSAN_H
#define _KERNEL_KCSAN_KCSAN_H

#include <linux/kcsan.h>

/* The number of adjacent watchpoints to check. */
#define KCSAN_CHECK_ADJACENT 1

/*
 * Globally enable and disable KCSAN.
 */
extern bool kcsan_enabled;

/*
 * Initialize debugfs file.
 */
void kcsan_debugfs_init(void);

enum kcsan_counter_id {
	/*
	 * Number of watchpoints currently in use.
	 */
	KCSAN_COUNTER_USED_WATCHPOINTS,

	/*
	 * Total number of watchpoints set up.
	 */
	KCSAN_COUNTER_SETUP_WATCHPOINTS,

	/*
	 * Total number of data races.
	 */
	KCSAN_COUNTER_DATA_RACES,

	/*
	 * Number of times no watchpoints were available.
	 */
	KCSAN_COUNTER_NO_CAPACITY,

	/*
	 * A thread checking a watchpoint raced with another checking thread;
	 * only one will be reported.
	 */
	KCSAN_COUNTER_REPORT_RACES,

	/*
	 * Observed data value change, but writer thread unknown.
	 */
	KCSAN_COUNTER_RACES_UNKNOWN_ORIGIN,

	/*
	 * The access cannot be encoded to a valid watchpoint.
	 */
	KCSAN_COUNTER_UNENCODABLE_ACCESSES,

	/*
	 * Watchpoint encoding caused a watchpoint to fire on mismatching
	 * accesses.
	 */
	KCSAN_COUNTER_ENCODING_FALSE_POSITIVES,

	KCSAN_COUNTER_COUNT, /* number of counters */
};

/*
 * Increment/decrement counter with given id; avoid calling these in fast-path.
 */
extern void kcsan_counter_inc(enum kcsan_counter_id id);
extern void kcsan_counter_dec(enum kcsan_counter_id id);

/*
 * Returns true if data races in the function symbol that maps to func_addr
 * (offsets are ignored) should *not* be reported.
 */
extern bool kcsan_skip_report_debugfs(unsigned long func_addr);

enum kcsan_report_type {
	/*
	 * The thread that set up the watchpoint and briefly stalled was
	 * signalled that another thread triggered the watchpoint.
	 */
	KCSAN_REPORT_RACE_SIGNAL,

	/*
	 * A thread found and consumed a matching watchpoint.
	 */
	KCSAN_REPORT_CONSUMED_WATCHPOINT,

	/*
	 * No other thread was observed to race with the access, but the data
	 * value before and after the stall differs.
	 */
	KCSAN_REPORT_RACE_UNKNOWN_ORIGIN,
};

/*
 * Print a race report from thread that encountered the race.
 */
extern void kcsan_report(const volatile void *ptr, size_t size, bool is_write,
			 bool value_change, int cpu_id, enum kcsan_report_type type);

#endif /* _KERNEL_KCSAN_KCSAN_H */
