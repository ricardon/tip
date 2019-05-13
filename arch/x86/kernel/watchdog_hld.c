// SPDX-License-Identifier: GPL-2.0
/*
 * A shim hardlockup detector for x86 to select between the perf- and HPET-
 * driven implementations.
 *
 * Copyright (C) Intel Corporation 2023
 */

#define pr_fmt(fmt) "watchdog: " fmt

#include <linux/nmi.h>
#include <asm/hpet.h>

enum x86_hardlockup_detector {
	X86_HARDLOCKUP_DETECTOR_PERF,
	X86_HARDLOCKUP_DETECTOR_HPET,
};

static enum x86_hardlockup_detector detector_type __ro_after_init;

int watchdog_nmi_enable(unsigned int cpu)
{
	switch (detector_type) {
	case X86_HARDLOCKUP_DETECTOR_PERF:
		hardlockup_detector_perf_enable();
		break;
	case X86_HARDLOCKUP_DETECTOR_HPET:
		hardlockup_detector_hpet_enable(cpu);
		break;
	default:
		return -ENODEV;
	}

	return 0;
}

void watchdog_nmi_disable(unsigned int cpu)
{
	switch (detector_type) {
	case X86_HARDLOCKUP_DETECTOR_PERF:
		hardlockup_detector_perf_disable();
		break;
	case X86_HARDLOCKUP_DETECTOR_HPET:
		hardlockup_detector_hpet_disable(cpu);
		break;
	}
}

int __init watchdog_nmi_probe(void)
{
	int ret;

	/*
	 * Try first with the HPET hardlockup detector. It will only succeed if
	 * requested via the kernel command line. The perf-based detector is
	 * used by default.
	 */
	ret = hardlockup_detector_hpet_init();
	if (!ret) {
		detector_type = X86_HARDLOCKUP_DETECTOR_HPET;
		return ret;
	}

	ret = hardlockup_detector_perf_init();
	if (!ret) {
		detector_type = X86_HARDLOCKUP_DETECTOR_PERF;
		return ret;
	}

	return 0;
}

void watchdog_nmi_stop(void)
{
	/* Only the HPET lockup detector defines a stop function. */
	if (detector_type == X86_HARDLOCKUP_DETECTOR_HPET)
		hardlockup_detector_hpet_stop();
}

void watchdog_nmi_start(void)
{
	if (!(watchdog_enabled & NMI_WATCHDOG_ENABLED))
		return;

	/* Only the HPET lockup detector defines a start function. */
	if (detector_type == X86_HARDLOCKUP_DETECTOR_HPET)
		hardlockup_detector_hpet_start();
}

void hardlockup_detector_mark_hpet_hld_unavailable(void)
{
	if (detector_type != X86_HARDLOCKUP_DETECTOR_HPET)
		return;

	pr_warn("TSC is unstable. Stopping the HPET NMI watchdog.");
	hardlockup_detector_mark_unavailable();
}
