// SPDX-License-Identifier: GPL-2.0
/*
 * A shim hardlockup detector. It overrides the weak stubs of the generic
 * implementation to select between the perf- or the hpet-based implementation.
 *
 * Copyright (C) Intel Corporation 2019
 */

#include <linux/nmi.h>
#include <asm/hpet.h>

enum x86_hardlockup_detector {
	X86_HARDLOCKUP_DETECTOR_PERF,
	X86_HARDLOCKUP_DETECTOR_HPET,
};

static enum __read_mostly x86_hardlockup_detector detector_type;

int watchdog_nmi_enable(unsigned int cpu)
{
	if (detector_type == X86_HARDLOCKUP_DETECTOR_PERF) {
		hardlockup_detector_perf_enable();
		return 0;
	}

	if (detector_type == X86_HARDLOCKUP_DETECTOR_HPET) {
		hardlockup_detector_hpet_enable(cpu);
		return 0;
	}

	return -ENODEV;
}

void watchdog_nmi_disable(unsigned int cpu)
{
	if (detector_type == X86_HARDLOCKUP_DETECTOR_PERF) {
		hardlockup_detector_perf_disable();
		return;
	}

	if (detector_type == X86_HARDLOCKUP_DETECTOR_HPET) {
		hardlockup_detector_hpet_disable(cpu);
		return;
	}
}

int __init watchdog_nmi_probe(void)
{
	int ret;

	/*
	 * Try first with the HPET hardlockup detector. It will only
	 * succeed if selected at build time and the nmi_watchdog
	 * command-line parameter is configured. This ensure that the
	 * perf-based detector is used by default, if selected at
	 * build time.
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

	return ret;
}

void watchdog_nmi_stop(void)
{
	/* Only the HPET lockup detector defines a stop function. */
	if (detector_type == X86_HARDLOCKUP_DETECTOR_HPET)
		hardlockup_detector_hpet_stop();
}

void hardlockup_detector_switch_to_perf(void)
{
	detector_type = X86_HARDLOCKUP_DETECTOR_PERF;
	hardlockup_detector_hpet_stop();
	hardlockup_start_all();
}
