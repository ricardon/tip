// SPDX-License-Identifier: GPL-2.0

#include <linux/atomic.h>
#include <linux/bsearch.h>
#include <linux/bug.h>
#include <linux/debugfs.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "kcsan.h"

/*
 * Statistics counters.
 */
static atomic_long_t counters[KCSAN_COUNTER_COUNT];

/*
 * Addresses for filtering functions from reporting. This list can be used as a
 * whitelist or blacklist.
 */
static struct {
	unsigned long	*addrs;		/* array of addresses */
	size_t		size;		/* current size */
	int		used;		/* number of elements used */
	bool		sorted;		/* if elements are sorted */
	bool		whitelist;	/* if list is a blacklist or whitelist */
} report_filterlist = {
	.addrs		= NULL,
	.size		= 8,		/* small initial size */
	.used		= 0,
	.sorted		= false,
	.whitelist	= false,	/* default is blacklist */
};
static DEFINE_SPINLOCK(report_filterlist_lock);

static const char *counter_to_name(enum kcsan_counter_id id)
{
	switch (id) {
	case KCSAN_COUNTER_USED_WATCHPOINTS:		return "used_watchpoints";
	case KCSAN_COUNTER_SETUP_WATCHPOINTS:		return "setup_watchpoints";
	case KCSAN_COUNTER_DATA_RACES:			return "data_races";
	case KCSAN_COUNTER_NO_CAPACITY:			return "no_capacity";
	case KCSAN_COUNTER_REPORT_RACES:		return "report_races";
	case KCSAN_COUNTER_RACES_UNKNOWN_ORIGIN:	return "races_unknown_origin";
	case KCSAN_COUNTER_UNENCODABLE_ACCESSES:	return "unencodable_accesses";
	case KCSAN_COUNTER_ENCODING_FALSE_POSITIVES:	return "encoding_false_positives";
	case KCSAN_COUNTER_COUNT:
		BUG();
	}
	return NULL;
}

void kcsan_counter_inc(enum kcsan_counter_id id)
{
	atomic_long_inc(&counters[id]);
}

void kcsan_counter_dec(enum kcsan_counter_id id)
{
	atomic_long_dec(&counters[id]);
}

/*
 * The microbenchmark allows benchmarking KCSAN core runtime only. To run
 * multiple threads, pipe 'microbench=<iters>' from multiple tasks into the
 * debugfs file.
 */
static void microbenchmark(unsigned long iters)
{
	cycles_t cycles;

	pr_info("KCSAN: %s begin | iters: %lu\n", __func__, iters);

	cycles = get_cycles();
	while (iters--) {
		/*
		 * We can run this benchmark from multiple tasks; this address
		 * calculation increases likelyhood of some accesses overlapping
		 * (they still won't conflict because all are reads).
		 */
		unsigned long addr =
			iters % (CONFIG_KCSAN_NUM_WATCHPOINTS * PAGE_SIZE);
		__kcsan_check_read((void *)addr, sizeof(long));
	}
	cycles = get_cycles() - cycles;

	pr_info("KCSAN: %s end   | cycles: %llu\n", __func__, cycles);
}

static int cmp_filterlist_addrs(const void *rhs, const void *lhs)
{
	const unsigned long a = *(const unsigned long *)rhs;
	const unsigned long b = *(const unsigned long *)lhs;

	return a < b ? -1 : a == b ? 0 : 1;
}

bool kcsan_skip_report_debugfs(unsigned long func_addr)
{
	unsigned long symbolsize, offset;
	unsigned long flags;
	bool ret = false;

	if (!kallsyms_lookup_size_offset(func_addr, &symbolsize, &offset))
		return false;
	func_addr -= offset; /* Get function start */

	spin_lock_irqsave(&report_filterlist_lock, flags);
	if (report_filterlist.used == 0)
		goto out;

	/* Sort array if it is unsorted, and then do a binary search. */
	if (!report_filterlist.sorted) {
		sort(report_filterlist.addrs, report_filterlist.used,
		     sizeof(unsigned long), cmp_filterlist_addrs, NULL);
		report_filterlist.sorted = true;
	}
	ret = !!bsearch(&func_addr, report_filterlist.addrs,
			report_filterlist.used, sizeof(unsigned long),
			cmp_filterlist_addrs);
	if (report_filterlist.whitelist)
		ret = !ret;

out:
	spin_unlock_irqrestore(&report_filterlist_lock, flags);
	return ret;
}

static void set_report_filterlist_whitelist(bool whitelist)
{
	unsigned long flags;

	spin_lock_irqsave(&report_filterlist_lock, flags);
	report_filterlist.whitelist = whitelist;
	spin_unlock_irqrestore(&report_filterlist_lock, flags);
}

/* Returns 0 on success, error-code otherwise. */
static ssize_t insert_report_filterlist(const char *func)
{
	unsigned long flags;
	unsigned long addr = kallsyms_lookup_name(func);
	ssize_t ret = 0;

	if (!addr) {
		pr_err("KCSAN: could not find function: '%s'\n", func);
		return -ENOENT;
	}

	spin_lock_irqsave(&report_filterlist_lock, flags);

	if (report_filterlist.addrs == NULL) {
		/* initial allocation */
		report_filterlist.addrs =
			kmalloc_array(report_filterlist.size,
				      sizeof(unsigned long), GFP_KERNEL);
		if (report_filterlist.addrs == NULL) {
			ret = -ENOMEM;
			goto out;
		}
	} else if (report_filterlist.used == report_filterlist.size) {
		/* resize filterlist */
		size_t new_size = report_filterlist.size * 2;
		unsigned long *new_addrs =
			krealloc(report_filterlist.addrs,
				 new_size * sizeof(unsigned long), GFP_KERNEL);

		if (new_addrs == NULL) {
			/* leave filterlist itself untouched */
			ret = -ENOMEM;
			goto out;
		}

		report_filterlist.size = new_size;
		report_filterlist.addrs = new_addrs;
	}

	/* Note: deduplicating should be done in userspace. */
	report_filterlist.addrs[report_filterlist.used++] =
		kallsyms_lookup_name(func);
	report_filterlist.sorted = false;

out:
	spin_unlock_irqrestore(&report_filterlist_lock, flags);

	return ret;
}

static int show_info(struct seq_file *file, void *v)
{
	int i;
	unsigned long flags;

	/* show stats */
	seq_printf(file, "enabled: %i\n", READ_ONCE(kcsan_enabled));
	for (i = 0; i < KCSAN_COUNTER_COUNT; ++i)
		seq_printf(file, "%s: %ld\n", counter_to_name(i),
			   atomic_long_read(&counters[i]));

	/* show filter functions, and filter type */
	spin_lock_irqsave(&report_filterlist_lock, flags);
	seq_printf(file, "\n%s functions: %s\n",
		   report_filterlist.whitelist ? "whitelisted" : "blacklisted",
		   report_filterlist.used == 0 ? "none" : "");
	for (i = 0; i < report_filterlist.used; ++i)
		seq_printf(file, " %ps\n", (void *)report_filterlist.addrs[i]);
	spin_unlock_irqrestore(&report_filterlist_lock, flags);

	return 0;
}

static int debugfs_open(struct inode *inode, struct file *file)
{
	return single_open(file, show_info, NULL);
}

static ssize_t
debugfs_write(struct file *file, const char __user *buf, size_t count, loff_t *off)
{
	char kbuf[KSYM_NAME_LEN];
	char *arg;
	int read_len = count < (sizeof(kbuf) - 1) ? count : (sizeof(kbuf) - 1);

	if (copy_from_user(kbuf, buf, read_len))
		return -EFAULT;
	kbuf[read_len] = '\0';
	arg = strstrip(kbuf);

	if (!strcmp(arg, "on")) {
		WRITE_ONCE(kcsan_enabled, true);
	} else if (!strcmp(arg, "off")) {
		WRITE_ONCE(kcsan_enabled, false);
	} else if (!strncmp(arg, "microbench=", sizeof("microbench=") - 1)) {
		unsigned long iters;

		if (kstrtoul(&arg[sizeof("microbench=") - 1], 0, &iters))
			return -EINVAL;
		microbenchmark(iters);
	} else if (!strcmp(arg, "whitelist")) {
		set_report_filterlist_whitelist(true);
	} else if (!strcmp(arg, "blacklist")) {
		set_report_filterlist_whitelist(false);
	} else if (arg[0] == '!') {
		ssize_t ret = insert_report_filterlist(&arg[1]);

		if (ret < 0)
			return ret;
	} else {
		return -EINVAL;
	}

	return count;
}

static const struct file_operations debugfs_ops =
{
	.read	 = seq_read,
	.open	 = debugfs_open,
	.write	 = debugfs_write,
	.release = single_release
};

void __init kcsan_debugfs_init(void)
{
	debugfs_create_file("kcsan", 0644, NULL, NULL, &debugfs_ops);
}
