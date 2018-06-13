// SPDX-License-Identifier: GPL-2.0
/*
 * Detect hard lockups on a system
 *
 * started by Ricardo Neri, Copyright (C) 2018 Intel Corporation.
 *
 * Note: All of this code comes from the previous perf-specific hardlockup
 * detector.
 */

#define pr_fmt(fmt) "NMI perf watchdog: " fmt

#include <linux/nmi.h>
#include <linux/atomic.h>
#include <linux/module.h>
#include <linux/sched/debug.h>
#include <linux/perf_event.h>
#include <asm/irq_regs.h>

static DEFINE_PER_CPU(struct perf_event *, watchdog_ev);
static DEFINE_PER_CPU(struct perf_event *, dead_event);
static struct cpumask dead_events_mask;

static atomic_t watchdog_cpus = ATOMIC_INIT(0);

static struct perf_event_attr wd_hw_attr = {
	.type		= PERF_TYPE_HARDWARE,
	.config		= PERF_COUNT_HW_CPU_CYCLES,
	.size		= sizeof(struct perf_event_attr),
	.pinned		= 1,
	.disabled	= 1,
};

/* Callback function for perf event subsystem */
static void watchdog_overflow_callback(struct perf_event *event,
				       struct perf_sample_data *data,
				       struct pt_regs *regs)
{
	/* Ensure the watchdog never gets throttled */
	event->hw.interrupts = 0;
	inspect_for_hardlockups(regs);
}

static int hardlockup_detector_event_create(void)
{
	unsigned int cpu = smp_processor_id();
	struct perf_event_attr *wd_attr;
	struct perf_event *evt;

	wd_attr = &wd_hw_attr;
	wd_attr->sample_period = hw_nmi_get_sample_period(watchdog_thresh);

	/* Try to register using hardware perf events */
	evt = perf_event_create_kernel_counter(wd_attr, cpu, NULL,
					       watchdog_overflow_callback, NULL);
	if (IS_ERR(evt)) {
		pr_info("Perf event create on CPU %d failed with %ld\n", cpu,
			PTR_ERR(evt));
		return PTR_ERR(evt);
	}
	this_cpu_write(watchdog_ev, evt);
	return 0;
}

/**
 * hardlockup_detector_perf_enable - Enable the local event
 */
static void hardlockup_detector_perf_enable(void)
{
	if (hardlockup_detector_event_create())
		return;

	/* use original value for check */
	if (!atomic_fetch_inc(&watchdog_cpus))
		pr_info("Enabled. Permanently consumes one hw-PMU counter.\n");

	perf_event_enable(this_cpu_read(watchdog_ev));
}

/**
 * hardlockup_detector_perf_disable - Disable the local event
 */
static void hardlockup_detector_perf_disable(void)
{
	struct perf_event *event = this_cpu_read(watchdog_ev);

	if (event) {
		perf_event_disable(event);
		this_cpu_write(watchdog_ev, NULL);
		this_cpu_write(dead_event, event);
		cpumask_set_cpu(smp_processor_id(), &dead_events_mask);
		atomic_dec(&watchdog_cpus);
	}
}

/**
 * hardlockup_detector_perf_cleanup - Cleanup disabled events and destroy them
 *
 * Called from lockup_detector_cleanup(). Serialized by the caller.
 */
static void hardlockup_detector_perf_cleanup(void)
{
	int cpu;

	for_each_cpu(cpu, &dead_events_mask) {
		struct perf_event *event = per_cpu(dead_event, cpu);

		/*
		 * Required because for_each_cpu() reports  unconditionally
		 * CPU0 as set on UP kernels. Sigh.
		 */
		if (event)
			perf_event_release_kernel(event);
		per_cpu(dead_event, cpu) = NULL;
	}
	cpumask_clear(&dead_events_mask);
}

/**
 * hardlockup_detector_perf_stop - Globally stop watchdog events
 *
 * Special interface for x86 to handle the perf HT bug.
 */
void __init hardlockup_detector_perf_stop(void)
{
	int cpu;

	lockdep_assert_cpus_held();

	for_each_online_cpu(cpu) {
		struct perf_event *event = per_cpu(watchdog_ev, cpu);

		if (event)
			perf_event_disable(event);
	}
}

/**
 * hardlockup_detector_perf_restart - Globally restart watchdog events
 *
 * Special interface for x86 to handle the perf HT bug.
 */
void __init hardlockup_detector_perf_restart(void)
{
	int cpu;

	lockdep_assert_cpus_held();

	if (!(watchdog_enabled & NMI_WATCHDOG_ENABLED))
		return;

	for_each_online_cpu(cpu) {
		struct perf_event *event = per_cpu(watchdog_ev, cpu);

		if (event)
			perf_event_enable(event);
	}
}

/**
 * hardlockup_detector_perf_init - Probe whether NMI event is available at all
 */
static int __init hardlockup_detector_perf_init(void)
{
	int ret = hardlockup_detector_event_create();

	if (ret) {
		pr_info("Perf NMI watchdog permanently disabled\n");
	} else {
		perf_event_release_kernel(this_cpu_read(watchdog_ev));
		this_cpu_write(watchdog_ev, NULL);
	}

	return ret;
}

struct nmi_watchdog_ops hardlockup_detector_perf_ops = {
	.init		= hardlockup_detector_perf_init,
	.enable		= hardlockup_detector_perf_enable,
	.disable	= hardlockup_detector_perf_disable,
	.cleanup	= hardlockup_detector_perf_cleanup,
};
