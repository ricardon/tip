// SPDX-License-Identifier: GPL-2.0
/*
 * A hardlockup detector driven by an HPET channel.
 *
 * Copyright (C) Intel Corporation 2023
 *
 * An HPET channel is reserved for the detector. The channel issues an NMI to
 * one of the CPUs in @watchdog_allowed_mask. This CPU monitors itself for
 * hardlockups and sends an NMI IPI to the rest of the CPUs in the system.
 *
 * The detector uses IPI shorthands. Thus, all CPUs in the system get the NMI
 * (offline CPUs also get the NMI but they "ignore" it). A cpumask is used to
 * specify whether a CPU must check for hardlockups.
 *
 * The NMI also disturbs isolated CPUs. The detector fails to initialize if
 * tick_nohz_full is enabled.
 */

#define pr_fmt(fmt) "NMI hpet watchdog: " fmt

#include <linux/cpumask.h>
#include <linux/interrupt.h>
#include <linux/jump_label.h>
#include <linux/nmi.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/tick.h>

#include <asm/apic.h>
#include <asm/hpet.h>
#include <asm/nmi.h>
#include <asm/tsc.h>

#include "apic/local.h"

static struct hpet_hld_data *hld_data;

static void __init setup_hpet_channel(struct hpet_hld_data *hdata)
{
	u32 v;

	v = hpet_readl(HPET_Tn_CFG(hdata->channel));
	if (hdata->has_periodic)
		v |= HPET_TN_PERIODIC;
	else
		v &= ~HPET_TN_PERIODIC;

	/*
	 * Use 32-bit mode to limit the number of register accesses. If we are
	 * here the HPET frequency is sufficiently low to accommodate this mode.
	 */
	v |= HPET_TN_32BIT;

	/* If we are here, FSB mode is supported. */
	v |= HPET_TN_FSB;

	hpet_writel(v, HPET_Tn_CFG(hdata->channel));
}

/**
 * kick_timer() - Reprogram timer to expire in the future
 * @hdata:	A data structure describing the HPET channel
 * @force:	Force reprogramming
 *
 * Reprogram the timer to expire in watchdog_thresh seconds in the future.
 * If the timer supports periodic mode, it is not kicked unless @force is
 * true.
 */
static void kick_timer(struct hpet_hld_data *hdata, bool force)
{
	u64 new_compare, count, period = 0;

	/* Kick the timer only when needed. */
	if (!force && hdata->has_periodic)
		return;

	/*
	 * Update the comparator in increments of watch_thresh seconds relative
	 * to the current count. Since watch_thresh is given in seconds, we can
	 * safely update the comparator before the counter reaches such new
	 * value.
	 *
	 * Let it wrap around if needed.
	 */

	count = hpet_readl(HPET_COUNTER);
	new_compare = count + watchdog_thresh * hdata->ticks_per_second;

	if (!hdata->has_periodic) {
		hpet_writel(new_compare, HPET_Tn_CMP(hdata->channel));
		return;
	}

	period = watchdog_thresh * hdata->ticks_per_second;
	hpet_set_comparator_periodic(hdata->channel, (u32)new_compare,
				     (u32)period);
}

static void disable_timer(struct hpet_hld_data *hdata)
{
	u32 v;

	v = hpet_readl(HPET_Tn_CFG(hdata->channel));
	v &= ~HPET_TN_ENABLE;

	/*
	 * Prepare to flush out any outstanding interrupt. This can only be
	 * done in level-triggered mode.
	 */
	v |= HPET_TN_LEVEL;
	hpet_writel(v, HPET_Tn_CFG(hdata->channel));

	/*
	 * Even though we use the HPET channel in edge-triggered mode, hardware
	 * seems to keep an outstanding interrupt and posts an MSI message when
	 * making any change to it (e.g., enabling or setting to FSB mode).
	 * Flush out the interrupt status bit of our channel.
	 */
	hpet_writel(1 << hdata->channel, HPET_STATUS);
}

static void enable_timer(struct hpet_hld_data *hdata)
{
	u32 v;

	v = hpet_readl(HPET_Tn_CFG(hdata->channel));
	v &= ~HPET_TN_LEVEL;
	v |= HPET_TN_ENABLE;
	hpet_writel(v, HPET_Tn_CFG(hdata->channel));
}

/**
 * is_hpet_hld_interrupt() - Check if the HPET channel caused the interrupt
 * @hdata:	A data structure describing the HPET channel
 *
 * Returns:
 * True if the HPET watchdog timer caused the interrupt. False otherwise.
 */
static bool is_hpet_hld_interrupt(struct hpet_hld_data *hdata)
{
	return false;
}

/**
 * hardlockup_detector_nmi_handler() - NMI Interrupt handler
 * @type:	Type of NMI handler; not used.
 * @regs:	Register values as seen when the NMI was asserted
 *
 * Check if our HPET channel caused the NMI. If yes, inspect for lockups by
 * issuing an IPI to the rest of the CPUs. Also, kick the timer if it is
 * non-periodic.
 *
 * Returns:
 * NMI_DONE if the HPET timer did not cause the interrupt. NMI_HANDLED
 * otherwise.
 */
static int hardlockup_detector_nmi_handler(unsigned int type,
					   struct pt_regs *regs)
{
	struct hpet_hld_data *hdata = hld_data;
	int cpu;

	/*
	 * The CPU handling the HPET NMI will land here and trigger the
	 * inspection of hardlockups in the rest of the monitored
	 * CPUs.
	 */
	if (is_hpet_hld_interrupt(hdata)) {
		/*
		 * Kick the timer first. If the HPET channel is periodic, it
		 * helps to reduce the delta between the expected TSC value and
		 * its actual value the next time the HPET channel fires.
		 */
		kick_timer(hdata, !(hdata->has_periodic));

		if (cpumask_weight(hld_data->monitored_cpumask) > 1) {
			/*
			 * Since we cannot know the source of an NMI, the best
			 * we can do is to use a flag to indicate to all online
			 * CPUs that they will get an NMI and that the source of
			 * that NMI is the hardlockup detector. Offline CPUs
			 * also receive the NMI but they ignore it.
			 */
			cpumask_copy(hld_data->inspect_cpumask,
				     cpu_online_mask);

			/* If we are here, IPI shorthands are enabled. */
			apic->send_IPI_allbutself(NMI_VECTOR);
		}

		inspect_for_hardlockups(regs);
		return NMI_HANDLED;
	}

	/* The rest of the CPUs will land here after receiving the IPI. */
	cpu = smp_processor_id();
	if (cpumask_test_and_clear_cpu(cpu, hld_data->inspect_cpumask)) {
		if (cpumask_test_cpu(cpu, hld_data->monitored_cpumask))
			inspect_for_hardlockups(regs);

		return NMI_HANDLED;
	}

	return NMI_DONE;
}

/**
 * setup_hpet_irq() - Install the interrupt handler of the detector
 * @data:	Data associated with the instance of the HPET channel
 *
 * Returns:
 * 0 success. An error code if setup was unsuccessful.
 */
static int setup_hpet_irq(struct hpet_hld_data *hdata)
{
	int ret;

	/*
	 * hld_data::irq was configured to deliver the interrupt as
	 * NMI. Thus, there is no need for a regular interrupt handler.
	 */
	ret = request_irq(hld_data->irq, no_action, IRQF_TIMER,
			  "hpet_hld", hld_data);
	if (ret)
		return ret;

	ret = register_nmi_handler(NMI_LOCAL,
				   hardlockup_detector_nmi_handler, 0,
				   "hpet_hld");
	if (ret)
		free_irq(hld_data->irq, hld_data);

	return ret;
}

/**
 * hardlockup_detector_hpet_enable() - Enable the hardlockup detector
 * @cpu:	CPU Index in which the watchdog will be enabled.
 *
 * Enable the hardlockup detector in @cpu. Also, start the detector if not done
 * before.
 */
void hardlockup_detector_hpet_enable(unsigned int cpu)
{
	cpumask_set_cpu(cpu, hld_data->monitored_cpumask);

	/*
	 * If this is the first CPU on which the detector is enabled, designate
	 * @cpu as the handling CPU and start everything. The HPET channel is
	 * disabled at this point.
	 */
	if (cpumask_weight(hld_data->monitored_cpumask) == 1) {
		hld_data->handling_cpu = cpu;

		if (irq_set_affinity(hld_data->irq,
				     cpumask_of(hld_data->handling_cpu))) {
			pr_warn_once("Failed to set affinity. Hardlockdup detector not started");
			return;
		}

		kick_timer(hld_data, true);
		enable_timer(hld_data);
	}
}

/**
 * hardlockup_detector_hpet_disable() - Disable the hardlockup detector
 * @cpu:	CPU index in which the watchdog will be disabled
 *
 * Disable the hardlockup detector in @cpu. If @cpu is also handling the NMI
 * from the HPET channel, update the affinity of the interrupt.
 */
void hardlockup_detector_hpet_disable(unsigned int cpu)
{
	cpumask_clear_cpu(cpu, hld_data->monitored_cpumask);

	if (hld_data->handling_cpu != cpu)
		return;

	disable_timer(hld_data);
	if (!cpumask_weight(hld_data->monitored_cpumask))
		return;

	/*
	 * If watchdog_thresh is zero, then the hardlockup detector is being
	 * disabled.
	 */
	if (!watchdog_thresh)
		return;

	hld_data->handling_cpu = cpumask_any_but(hld_data->monitored_cpumask,
						 cpu);
	/*
	 * Only update the affinity of the HPET channel interrupt when
	 * disabled.
	 */
	if (irq_set_affinity(hld_data->irq,
			     cpumask_of(hld_data->handling_cpu))) {
		pr_warn_once("Failed to set affinity. Hardlockdup detector stopped");
		return;
	}

	enable_timer(hld_data);
}

void hardlockup_detector_hpet_stop(void)
{
	disable_timer(hld_data);
}

void hardlockup_detector_hpet_start(void)
{
	kick_timer(hld_data, true);
	enable_timer(hld_data);
}

static const char hpet_hld_init_failed[] = "Initialization failed:";

/**
 * hardlockup_detector_hpet_init() - Initialize the hardlockup detector
 *
 * Only initialize and configure the detector if an HPET is available on the
 * system, the TSC is stable, IPI shorthands are enabled, and there are no
 * isolated CPUs.
 *
 * Returns:
 * 0 success. An error code if initialization was unsuccessful.
 */
int __init hardlockup_detector_hpet_init(void)
{
	int ret;

	if (!is_hpet_enabled()) {
		pr_info("%s HPET unavailable\n", hpet_hld_init_failed);
		return -ENODEV;
	}

	if (tick_nohz_full_enabled()) {
		pr_info("%s nohz_full in use\n", hpet_hld_init_failed);
		return -EPERM;
	}

	if (!static_branch_likely(&apic_use_ipi_shorthand)) {
		pr_info("%s APIC IPI shorthands disabled\n", hpet_hld_init_failed);
		return -ENODEV;
	}

	if (check_tsc_unstable())
		return -ENODEV;

	hld_data = hpet_hld_get_timer();
	if (!hld_data)
		return -ENODEV;

	disable_timer(hld_data);

	setup_hpet_channel(hld_data);

	ret = setup_hpet_irq(hld_data);
	if (ret)
		goto err_no_irq;

	if (!zalloc_cpumask_var(&hld_data->monitored_cpumask, GFP_KERNEL))
		goto err_no_monitored_cpumask;

	if (!zalloc_cpumask_var(&hld_data->inspect_cpumask, GFP_KERNEL))
		goto err_no_inspect_cpumask;

	return 0;

err_no_inspect_cpumask:
	free_cpumask_var(hld_data->monitored_cpumask);
err_no_monitored_cpumask:
	ret = -ENOMEM;
err_no_irq:
	hpet_hld_free_timer(hld_data);
	hld_data = NULL;

	return ret;
}
