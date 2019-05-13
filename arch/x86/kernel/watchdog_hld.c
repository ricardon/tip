// SPDX-License-Identifier: GPL-2.0
/*
 * A shim hardlockup detector. It overrides the weak stubs of the generic
 * implementation to select between the perf- or the hpet-based implementation.
 *
 * Copyright (C) Intel Corporation 2022
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
	 * Try first with the HPET hardlockup detector. It will only
	 * succeed if selected at build time and requested in the
	 * nmi_watchdog command-line parameter. This ensures that the
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
	/* Only the HPET lockup detector defines a start function. */
	if (detector_type == X86_HARDLOCKUP_DETECTOR_HPET)
		hardlockup_detector_hpet_start();
}

void hardlockup_detector_switch_to_perf(void)
{
	detector_type = X86_HARDLOCKUP_DETECTOR_PERF;
	lockup_detector_reconfigure();
}
