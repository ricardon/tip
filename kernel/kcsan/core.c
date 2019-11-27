// SPDX-License-Identifier: GPL-2.0

#include <linux/atomic.h>
#include <linux/bug.h>
#include <linux/delay.h>
#include <linux/export.h>
#include <linux/init.h>
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/uaccess.h>

#include "atomic.h"
#include "encoding.h"
#include "kcsan.h"

bool kcsan_enabled;

/* Per-CPU kcsan_ctx for interrupts */
static DEFINE_PER_CPU(struct kcsan_ctx, kcsan_cpu_ctx) = {
	.disable_count		= 0,
	.atomic_next		= 0,
	.atomic_nest_count	= 0,
	.in_flat_atomic		= false,
};

/*
 * Helper macros to index into adjacent slots slots, starting from address slot
 * itself, followed by the right and left slots.
 *
 * The purpose is 2-fold:
 *
 *	1. if during insertion the address slot is already occupied, check if
 *	   any adjacent slots are free;
 *	2. accesses that straddle a slot boundary due to size that exceeds a
 *	   slot's range may check adjacent slots if any watchpoint matches.
 *
 * Note that accesses with very large size may still miss a watchpoint; however,
 * given this should be rare, this is a reasonable trade-off to make, since this
 * will avoid:
 *
 *	1. excessive contention between watchpoint checks and setup;
 *	2. larger number of simultaneous watchpoints without sacrificing
 *	   performance.
 *
 * Example: SLOT_IDX values for KCSAN_CHECK_ADJACENT=1, where i is [0, 1, 2]:
 *
 *   slot=0:  [ 1,  2,  0]
 *   slot=9:  [10, 11,  9]
 *   slot=63: [64, 65, 63]
 */
#define NUM_SLOTS (1 + 2*KCSAN_CHECK_ADJACENT)
#define SLOT_IDX(slot, i) (slot + ((i + KCSAN_CHECK_ADJACENT) % NUM_SLOTS))

/*
 * SLOT_IDX_FAST is used in the fast-path. Not first checking the address's primary
 * slot (middle) is fine if we assume that data races occur rarely. The set of
 * indices {SLOT_IDX(slot, i) | i in [0, NUM_SLOTS)} is equivalent to
 * {SLOT_IDX_FAST(slot, i) | i in [0, NUM_SLOTS)}.
 */
#define SLOT_IDX_FAST(slot, i) (slot + i)

/*
 * Watchpoints, with each entry encoded as defined in encoding.h: in order to be
 * able to safely update and access a watchpoint without introducing locking
 * overhead, we encode each watchpoint as a single atomic long. The initial
 * zero-initialized state matches INVALID_WATCHPOINT.
 *
 * Add NUM_SLOTS-1 entries to account for overflow; this helps avoid having to
 * use more complicated SLOT_IDX_FAST calculation with modulo in the fast-path.
 */
static atomic_long_t watchpoints[CONFIG_KCSAN_NUM_WATCHPOINTS + NUM_SLOTS-1];

/*
 * Instructions to skip watching counter, used in should_watch(). We use a
 * per-CPU counter to avoid excessive contention.
 */
static DEFINE_PER_CPU(long, kcsan_skip);

static inline atomic_long_t *find_watchpoint(unsigned long addr,
					     size_t size,
					     bool expect_write,
					     long *encoded_watchpoint)
{
	const int slot = watchpoint_slot(addr);
	const unsigned long addr_masked = addr & WATCHPOINT_ADDR_MASK;
	atomic_long_t *watchpoint;
	unsigned long wp_addr_masked;
	size_t wp_size;
	bool is_write;
	int i;

	BUILD_BUG_ON(CONFIG_KCSAN_NUM_WATCHPOINTS < NUM_SLOTS);

	for (i = 0; i < NUM_SLOTS; ++i) {
		watchpoint = &watchpoints[SLOT_IDX_FAST(slot, i)];
		*encoded_watchpoint = atomic_long_read(watchpoint);
		if (!decode_watchpoint(*encoded_watchpoint, &wp_addr_masked,
				       &wp_size, &is_write))
			continue;

		if (expect_write && !is_write)
			continue;

		/* Check if the watchpoint matches the access. */
		if (matching_access(wp_addr_masked, wp_size, addr_masked, size))
			return watchpoint;
	}

	return NULL;
}

static inline atomic_long_t *
insert_watchpoint(unsigned long addr, size_t size, bool is_write)
{
	const int slot = watchpoint_slot(addr);
	const long encoded_watchpoint = encode_watchpoint(addr, size, is_write);
	atomic_long_t *watchpoint;
	int i;

	/* Check slot index logic, ensuring we stay within array bounds. */
	BUILD_BUG_ON(SLOT_IDX(0, 0) != KCSAN_CHECK_ADJACENT);
	BUILD_BUG_ON(SLOT_IDX(0, KCSAN_CHECK_ADJACENT+1) != 0);
	BUILD_BUG_ON(SLOT_IDX(CONFIG_KCSAN_NUM_WATCHPOINTS-1, KCSAN_CHECK_ADJACENT) != ARRAY_SIZE(watchpoints)-1);
	BUILD_BUG_ON(SLOT_IDX(CONFIG_KCSAN_NUM_WATCHPOINTS-1, KCSAN_CHECK_ADJACENT+1) != ARRAY_SIZE(watchpoints) - NUM_SLOTS);

	for (i = 0; i < NUM_SLOTS; ++i) {
		long expect_val = INVALID_WATCHPOINT;

		/* Try to acquire this slot. */
		watchpoint = &watchpoints[SLOT_IDX(slot, i)];
		if (atomic_long_try_cmpxchg_relaxed(watchpoint, &expect_val, encoded_watchpoint))
			return watchpoint;
	}

	return NULL;
}

/*
 * Return true if watchpoint was successfully consumed, false otherwise.
 *
 * This may return false if:
 *
 *	1. another thread already consumed the watchpoint;
 *	2. the thread that set up the watchpoint already removed it;
 *	3. the watchpoint was removed and then re-used.
 */
static inline bool
try_consume_watchpoint(atomic_long_t *watchpoint, long encoded_watchpoint)
{
	return atomic_long_try_cmpxchg_relaxed(watchpoint, &encoded_watchpoint, CONSUMED_WATCHPOINT);
}

/*
 * Return true if watchpoint was not touched, false if consumed.
 */
static inline bool remove_watchpoint(atomic_long_t *watchpoint)
{
	return atomic_long_xchg_relaxed(watchpoint, INVALID_WATCHPOINT) != CONSUMED_WATCHPOINT;
}

static inline struct kcsan_ctx *get_ctx(void)
{
	/*
	 * In interrupts, use raw_cpu_ptr to avoid unnecessary checks, that would
	 * also result in calls that generate warnings in uaccess regions.
	 */
	return in_task() ? &current->kcsan_ctx : raw_cpu_ptr(&kcsan_cpu_ctx);
}

static inline bool is_atomic(const volatile void *ptr)
{
	struct kcsan_ctx *ctx = get_ctx();

	if (unlikely(ctx->atomic_next > 0)) {
		/*
		 * Because we do not have separate contexts for nested
		 * interrupts, in case atomic_next is set, we simply assume that
		 * the outer interrupt set atomic_next. In the worst case, we
		 * will conservatively consider operations as atomic. This is a
		 * reasonable trade-off to make, since this case should be
		 * extremely rare; however, even if extremely rare, it could
		 * lead to false positives otherwise.
		 */
		if ((hardirq_count() >> HARDIRQ_SHIFT) < 2)
			--ctx->atomic_next; /* in task, or outer interrupt */
		return true;
	}
	if (unlikely(ctx->atomic_nest_count > 0 || ctx->in_flat_atomic))
		return true;

	return kcsan_is_atomic(ptr);
}

static inline bool should_watch(const volatile void *ptr, int type)
{
	/*
	 * Never set up watchpoints when memory operations are atomic.
	 *
	 * Need to check this first, before kcsan_skip check below: (1) atomics
	 * should not count towards skipped instructions, and (2) to actually
	 * decrement kcsan_atomic_next for consecutive instruction stream.
	 */
	if ((type & KCSAN_ACCESS_ATOMIC) != 0 || is_atomic(ptr))
		return false;

	if (this_cpu_dec_return(kcsan_skip) >= 0)
		return false;

	/*
	 * NOTE: If we get here, kcsan_skip must always be reset in slow path
	 * via reset_kcsan_skip() to avoid underflow.
	 */

	/* this operation should be watched */
	return true;
}

static inline void reset_kcsan_skip(void)
{
	long skip_count = CONFIG_KCSAN_SKIP_WATCH -
			  (IS_ENABLED(CONFIG_KCSAN_SKIP_WATCH_RANDOMIZE) ?
				   prandom_u32_max(CONFIG_KCSAN_SKIP_WATCH) :
				   0);
	this_cpu_write(kcsan_skip, skip_count);
}

static inline bool kcsan_is_enabled(void)
{
	return READ_ONCE(kcsan_enabled) && get_ctx()->disable_count == 0;
}

static inline unsigned int get_delay(void)
{
	unsigned int delay = in_task() ? CONFIG_KCSAN_UDELAY_TASK :
					 CONFIG_KCSAN_UDELAY_INTERRUPT;
	return delay - (IS_ENABLED(CONFIG_KCSAN_DELAY_RANDOMIZE) ?
				prandom_u32_max(delay) :
				0);
}

/*
 * Pull everything together: check_access() below contains the performance
 * critical operations; the fast-path (including check_access) functions should
 * all be inlinable by the instrumentation functions.
 *
 * The slow-path (kcsan_found_watchpoint, kcsan_setup_watchpoint) are
 * non-inlinable -- note that, we prefix these with "kcsan_" to ensure they can
 * be filtered from the stacktrace, as well as give them unique names for the
 * UACCESS whitelist of objtool. Each function uses user_access_save/restore(),
 * since they do not access any user memory, but instrumentation is still
 * emitted in UACCESS regions.
 */

static noinline void kcsan_found_watchpoint(const volatile void *ptr,
					    size_t size,
					    bool is_write,
					    atomic_long_t *watchpoint,
					    long encoded_watchpoint)
{
	unsigned long flags;
	bool consumed;

	if (!kcsan_is_enabled())
		return;
	/*
	 * Consume the watchpoint as soon as possible, to minimize the chances
	 * of !consumed. Consuming the watchpoint must always be guarded by
	 * kcsan_is_enabled() check, as otherwise we might erroneously
	 * triggering reports when disabled.
	 */
	consumed = try_consume_watchpoint(watchpoint, encoded_watchpoint);

	/* keep this after try_consume_watchpoint */
	flags = user_access_save();

	if (consumed) {
		kcsan_report(ptr, size, is_write, true, raw_smp_processor_id(),
			     KCSAN_REPORT_CONSUMED_WATCHPOINT);
	} else {
		/*
		 * The other thread may not print any diagnostics, as it has
		 * already removed the watchpoint, or another thread consumed
		 * the watchpoint before this thread.
		 */
		kcsan_counter_inc(KCSAN_COUNTER_REPORT_RACES);
	}
	kcsan_counter_inc(KCSAN_COUNTER_DATA_RACES);

	user_access_restore(flags);
}

static noinline void
kcsan_setup_watchpoint(const volatile void *ptr, size_t size, bool is_write)
{
	atomic_long_t *watchpoint;
	union {
		u8 _1;
		u16 _2;
		u32 _4;
		u64 _8;
	} expect_value;
	bool value_change = false;
	unsigned long ua_flags = user_access_save();
	unsigned long irq_flags;

	/*
	 * Always reset kcsan_skip counter in slow-path to avoid underflow; see
	 * should_watch().
	 */
	reset_kcsan_skip();

	if (!kcsan_is_enabled())
		goto out;

	if (!check_encodable((unsigned long)ptr, size)) {
		kcsan_counter_inc(KCSAN_COUNTER_UNENCODABLE_ACCESSES);
		goto out;
	}

	/*
	 * Disable interrupts & preemptions to avoid another thread on the same
	 * CPU accessing memory locations for the set up watchpoint; this is to
	 * avoid reporting races to e.g. CPU-local data.
	 *
	 * An alternative would be adding the source CPU to the watchpoint
	 * encoding, and checking that watchpoint-CPU != this-CPU. There are
	 * several problems with this:
	 *   1. we should avoid stealing more bits from the watchpoint encoding
	 *      as it would affect accuracy, as well as increase performance
	 *      overhead in the fast-path;
	 *   2. if we are preempted, but there *is* a genuine data race, we
	 *      would *not* report it -- since this is the common case (vs.
	 *      CPU-local data accesses), it makes more sense (from a data race
	 *      detection point of view) to simply disable preemptions to ensure
	 *      as many tasks as possible run on other CPUs.
	 */
	local_irq_save(irq_flags);

	watchpoint = insert_watchpoint((unsigned long)ptr, size, is_write);
	if (watchpoint == NULL) {
		/*
		 * Out of capacity: the size of 'watchpoints', and the frequency
		 * with which should_watch() returns true should be tweaked so
		 * that this case happens very rarely.
		 */
		kcsan_counter_inc(KCSAN_COUNTER_NO_CAPACITY);
		goto out_unlock;
	}

	kcsan_counter_inc(KCSAN_COUNTER_SETUP_WATCHPOINTS);
	kcsan_counter_inc(KCSAN_COUNTER_USED_WATCHPOINTS);

	/*
	 * Read the current value, to later check and infer a race if the data
	 * was modified via a non-instrumented access, e.g. from a device.
	 */
	switch (size) {
	case 1:
		expect_value._1 = READ_ONCE(*(const u8 *)ptr);
		break;
	case 2:
		expect_value._2 = READ_ONCE(*(const u16 *)ptr);
		break;
	case 4:
		expect_value._4 = READ_ONCE(*(const u32 *)ptr);
		break;
	case 8:
		expect_value._8 = READ_ONCE(*(const u64 *)ptr);
		break;
	default:
		break; /* ignore; we do not diff the values */
	}

	if (IS_ENABLED(CONFIG_KCSAN_DEBUG)) {
		kcsan_disable_current();
		pr_err("KCSAN: watching %s, size: %zu, addr: %px [slot: %d, encoded: %lx]\n",
		       is_write ? "write" : "read", size, ptr,
		       watchpoint_slot((unsigned long)ptr),
		       encode_watchpoint((unsigned long)ptr, size, is_write));
		kcsan_enable_current();
	}

	/*
	 * Delay this thread, to increase probability of observing a racy
	 * conflicting access.
	 */
	udelay(get_delay());

	/*
	 * Re-read value, and check if it is as expected; if not, we infer a
	 * racy access.
	 */
	switch (size) {
	case 1:
		value_change = expect_value._1 != READ_ONCE(*(const u8 *)ptr);
		break;
	case 2:
		value_change = expect_value._2 != READ_ONCE(*(const u16 *)ptr);
		break;
	case 4:
		value_change = expect_value._4 != READ_ONCE(*(const u32 *)ptr);
		break;
	case 8:
		value_change = expect_value._8 != READ_ONCE(*(const u64 *)ptr);
		break;
	default:
		break; /* ignore; we do not diff the values */
	}

	/* Check if this access raced with another. */
	if (!remove_watchpoint(watchpoint)) {
		/*
		 * No need to increment 'data_races' counter, as the racing
		 * thread already did.
		 */
		kcsan_report(ptr, size, is_write, size > 8 || value_change,
			     smp_processor_id(), KCSAN_REPORT_RACE_SIGNAL);
	} else if (value_change) {
		/* Inferring a race, since the value should not have changed. */
		kcsan_counter_inc(KCSAN_COUNTER_RACES_UNKNOWN_ORIGIN);
		if (IS_ENABLED(CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN))
			kcsan_report(ptr, size, is_write, true,
				     smp_processor_id(),
				     KCSAN_REPORT_RACE_UNKNOWN_ORIGIN);
	}

	kcsan_counter_dec(KCSAN_COUNTER_USED_WATCHPOINTS);
out_unlock:
	local_irq_restore(irq_flags);
out:
	user_access_restore(ua_flags);
}

static __always_inline void check_access(const volatile void *ptr, size_t size,
					 int type)
{
	const bool is_write = (type & KCSAN_ACCESS_WRITE) != 0;
	atomic_long_t *watchpoint;
	long encoded_watchpoint;

	/*
	 * Avoid user_access_save in fast-path: find_watchpoint is safe without
	 * user_access_save, as the address that ptr points to is only used to
	 * check if a watchpoint exists; ptr is never dereferenced.
	 */
	watchpoint = find_watchpoint((unsigned long)ptr, size, !is_write,
				     &encoded_watchpoint);
	/*
	 * It is safe to check kcsan_is_enabled() after find_watchpoint in the
	 * slow-path, as long as no state changes that cause a data race to be
	 * detected and reported have occurred until kcsan_is_enabled() is
	 * checked.
	 */

	if (unlikely(watchpoint != NULL))
		kcsan_found_watchpoint(ptr, size, is_write, watchpoint,
				       encoded_watchpoint);
	else if (unlikely(should_watch(ptr, type)))
		kcsan_setup_watchpoint(ptr, size, is_write);
}

/* === Public interface ===================================================== */

void __init kcsan_init(void)
{
	BUG_ON(!in_task());

	kcsan_debugfs_init();

	/*
	 * We are in the init task, and no other tasks should be running;
	 * WRITE_ONCE without memory barrier is sufficient.
	 */
	if (IS_ENABLED(CONFIG_KCSAN_EARLY_ENABLE))
		WRITE_ONCE(kcsan_enabled, true);
}

/* === Exported interface =================================================== */

void kcsan_disable_current(void)
{
	++get_ctx()->disable_count;
}
EXPORT_SYMBOL(kcsan_disable_current);

void kcsan_enable_current(void)
{
	if (get_ctx()->disable_count-- == 0) {
		/*
		 * Warn if kcsan_enable_current() calls are unbalanced with
		 * kcsan_disable_current() calls, which causes disable_count to
		 * become negative and should not happen.
		 */
		kcsan_disable_current(); /* restore to 0, KCSAN still enabled */
		kcsan_disable_current(); /* disable to generate warning */
		WARN(1, "Unbalanced %s()", __func__);
		kcsan_enable_current();
	}
}
EXPORT_SYMBOL(kcsan_enable_current);

void kcsan_nestable_atomic_begin(void)
{
	/*
	 * Do *not* check and warn if we are in a flat atomic region: nestable
	 * and flat atomic regions are independent from each other.
	 * See include/linux/kcsan.h: struct kcsan_ctx comments for more
	 * comments.
	 */

	++get_ctx()->atomic_nest_count;
}
EXPORT_SYMBOL(kcsan_nestable_atomic_begin);

void kcsan_nestable_atomic_end(void)
{
	if (get_ctx()->atomic_nest_count-- == 0) {
		/*
		 * Warn if kcsan_nestable_atomic_end() calls are unbalanced with
		 * kcsan_nestable_atomic_begin() calls, which causes
		 * atomic_nest_count to become negative and should not happen.
		 */
		kcsan_nestable_atomic_begin(); /* restore to 0 */
		kcsan_disable_current(); /* disable to generate warning */
		WARN(1, "Unbalanced %s()", __func__);
		kcsan_enable_current();
	}
}
EXPORT_SYMBOL(kcsan_nestable_atomic_end);

void kcsan_flat_atomic_begin(void)
{
	get_ctx()->in_flat_atomic = true;
}
EXPORT_SYMBOL(kcsan_flat_atomic_begin);

void kcsan_flat_atomic_end(void)
{
	get_ctx()->in_flat_atomic = false;
}
EXPORT_SYMBOL(kcsan_flat_atomic_end);

void kcsan_atomic_next(int n)
{
	get_ctx()->atomic_next = n;
}
EXPORT_SYMBOL(kcsan_atomic_next);

void __kcsan_check_access(const volatile void *ptr, size_t size, int type)
{
	check_access(ptr, size, type);
}
EXPORT_SYMBOL(__kcsan_check_access);

/*
 * KCSAN uses the same instrumentation that is emitted by supported compilers
 * for ThreadSanitizer (TSAN).
 *
 * When enabled, the compiler emits instrumentation calls (the functions
 * prefixed with "__tsan" below) for all loads and stores that it generated;
 * inline asm is not instrumented.
 *
 * Note that, not all supported compiler versions distinguish aligned/unaligned
 * accesses, but e.g. recent versions of Clang do. We simply alias the unaligned
 * version to the generic version, which can handle both.
 */

#define DEFINE_TSAN_READ_WRITE(size)                                           \
	void __tsan_read##size(void *ptr)                                      \
	{                                                                      \
		check_access(ptr, size, 0);                                    \
	}                                                                      \
	EXPORT_SYMBOL(__tsan_read##size);                                      \
	void __tsan_unaligned_read##size(void *ptr)                            \
		__alias(__tsan_read##size);                                    \
	EXPORT_SYMBOL(__tsan_unaligned_read##size);                            \
	void __tsan_write##size(void *ptr)                                     \
	{                                                                      \
		check_access(ptr, size, KCSAN_ACCESS_WRITE);                   \
	}                                                                      \
	EXPORT_SYMBOL(__tsan_write##size);                                     \
	void __tsan_unaligned_write##size(void *ptr)                           \
		__alias(__tsan_write##size);                                   \
	EXPORT_SYMBOL(__tsan_unaligned_write##size)

DEFINE_TSAN_READ_WRITE(1);
DEFINE_TSAN_READ_WRITE(2);
DEFINE_TSAN_READ_WRITE(4);
DEFINE_TSAN_READ_WRITE(8);
DEFINE_TSAN_READ_WRITE(16);

void __tsan_read_range(void *ptr, size_t size)
{
	check_access(ptr, size, 0);
}
EXPORT_SYMBOL(__tsan_read_range);

void __tsan_write_range(void *ptr, size_t size)
{
	check_access(ptr, size, KCSAN_ACCESS_WRITE);
}
EXPORT_SYMBOL(__tsan_write_range);

/*
 * The below are not required by KCSAN, but can still be emitted by the
 * compiler.
 */
void __tsan_func_entry(void *call_pc)
{
}
EXPORT_SYMBOL(__tsan_func_entry);
void __tsan_func_exit(void)
{
}
EXPORT_SYMBOL(__tsan_func_exit);
void __tsan_init(void)
{
}
EXPORT_SYMBOL(__tsan_init);
