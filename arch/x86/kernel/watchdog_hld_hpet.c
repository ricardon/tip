// SPDX-License-Identifier: GPL-2.0
/*
 * A hardlockup detector driven by an HPET timer.
 *
 * Copyright (C) Intel Corporation 2022
 *
 * A hardlockup detector driven by an HPET timer. It implements the same
 * interfaces as the PMU-based hardlockup detector.
 *
 * The HPET timer channel designated for the hardlockup detector sends an
 * NMI to the one of the CPUs in the watchdog_allowed_mask. Such CPU then
 * sends an NMI IPI to the rest of the CPUs in the system. Each individual
 * CPU checks for hardlockups.
 *
 * This detector only is enabled when the system has IPI shorthands
 * enabled. Therefore, all the CPUs in the system get the broadcast NMI.
 * A cpumask is used to check if a specific CPU needs to check for hard-
 * lockups. CPUs that are offline, have their local APIC soft-disabled.
 * They will also get the NMI but "ignore" it in the NMI handler.
 */

#define pr_fmt(fmt) "NMI hpet watchdog: " fmt

#include <linux/cpumask.h>
#include <linux/interrupt.h>
#include <linux/jump_label.h>
#include <linux/nmi.h>
#include <linux/printk.h>
#include <linux/slab.h>

#include <asm/apic.h>
#include <asm/hpet.h>
#include <asm/tsc.h>

static struct hpet_hld_data *hld_data;
static bool hardlockup_use_hpet;
static u64 tsc_next_error;

extern struct static_key_false apic_use_ipi_shorthand;

static void __init setup_hpet_channel(struct hpet_hld_data *hdata)
{
	u32 v;

	v = hpet_readl(HPET_Tn_CFG(hdata->channel));
	if (hdata->has_periodic)
		v |= HPET_TN_PERIODIC;
	else
		v &= ~HPET_TN_PERIODIC;

	v |= HPET_TN_32BIT;
	hpet_writel(v, HPET_Tn_CFG(hdata->channel));
}

/**
 * kick_timer() - Reprogram timer to expire in the future
 * @hdata:	A data structure with the timer instance to update
 * @force:	Force reprogramming
 *
 * Reprogram the timer to expire within watchdog_thresh seconds in the future.
 * If the timer supports periodic mode, it is not kicked unless @force is
 * true.
 *
 * Also, compute the expected value of the time-stamp counter at the time of
 * expiration as well as a deviation from the expected value.
 */
static void kick_timer(struct hpet_hld_data *hdata, bool force)
{
	u64 tsc_curr, tsc_delta, new_compare, count, period = 0;

	tsc_curr = rdtsc();

	/*
	 * Compute the delta between the value of the TSC now and the value
	 * it will have the next time the HPET channel fires.
	 */
	tsc_delta = watchdog_thresh * tsc_khz * 1000L;
	hdata->tsc_next = tsc_curr + tsc_delta;

	/*
	 * Define an error window between the expected TSC value and the actual
	 * value it will have the next time the HPET channel fires. Define this
	 * error as percentage of tsc_delta.
	 *
	 * The systems that have been tested so far exhibit an error of 0.05%
	 * of the expected TSC value once the system is up and running. Systems
	 * that refine tsc_khz exhibit a larger initial error up to 0.2%.
	 *
	 * To be safe, allow a maximum error of ~0.4%. This error value can be
	 * computed by left-shifting tsc_delta by 8 positions. Shift 9
	 * positions to calculate half the error. When the HPET channel fires,
	 * check if the actual TSC value is in the range
	 *  [tsc_next - (tsc_next_error / 2), tsc_next + (tsc_next_error / 2)]
	 */
	tsc_next_error = tsc_delta >> 9;

	/* Kick the timer only when needed. */
	if (!force && hdata->has_periodic)
		return;

	/*
	 * Update the comparator in increments of watch_thresh seconds relative
	 * to the current count. Since watch_thresh is given in seconds, we
	 * are able to update the comparator before the counter reaches such new
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
 * is_hpet_hld_interrupt() - Check if an HPET timer caused the interrupt
 * @hdata:	A data structure with the timer instance to enable
 *
 * Checking whether the HPET was the source of this NMI is not possible.
 * Determining the sources of NMIs is not possible. Furthermore, we have
 * programmed the HPET channel for MSI delivery, which does not have a
 * status bit. Also, reading HPET registers is slow.
 *
 * Instead, we just assume that any NMI delivered within a time window
 * of when the HPET was expected to fire probably came from the HPET.
 *
 * The window is estimated using the TSC counter. Check the comments in
 * kick_timer() for details on the size of the time window.
 *
 * Returns:
 * True if the HPET watchdog timer caused the interrupt. False otherwise.
 */
static bool is_hpet_hld_interrupt(struct hpet_hld_data *hdata)
{
	u64 tsc_curr, tsc_curr_min, tsc_curr_max;

	if (smp_processor_id() != hdata->handling_cpu)
		return false;

	tsc_curr = rdtsc();
	tsc_curr_min = tsc_curr - tsc_next_error;
	tsc_curr_max = tsc_curr + tsc_next_error;

	return time_in_range64(hdata->tsc_next, tsc_curr_min, tsc_curr_max);
}

/**
 * hardlockup_detector_nmi_handler() - NMI Interrupt handler
 * @type:	Type of NMI handler; not used.
 * @regs:	Register values as seen when the NMI was asserted
 *
 * Check if it was caused by the expiration of the HPET timer. If yes, inspect
 * for lockups by issuing an IPI to the rest of the CPUs. Also, kick the
 * timer if it is non-periodic.
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
			 *
			 * Even though we are in NMI context, we have concluded
			 * that the NMI came from the HPET channel assigned to
			 * the detector, an event that is infrequent and only
			 * occurs in the handling CPU. There should not be races
			 * with other NMIs.
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
 * setup_hpet_irq() - Configure the interrupt delivery of an HPET timer
 * @data:	Data associated with the instance of the HPET timer to configure
 *
 * Configure the interrupt parameters of an HPET timer. If supported, configure
 * interrupts to be delivered via the Front-Side Bus. Also, install an interrupt
 * handler.
 *
 * Returns:
 * 0 success. An error code if setup was unsuccessful.
 */
static int setup_hpet_irq(struct hpet_hld_data *hdata)
{
	int ret;
	u32 v;

	/*
	 * hld_data->irq was configured to deliver the interrupt as
	 * NMI. Thus, there is no need for a regular interrupt handler.
	 */
	ret = request_irq(hld_data->irq, no_action,
			  IRQF_TIMER | IRQF_NOBALANCING,
			  "hpet_hld", hld_data);
	if (ret)
		return ret;

	ret = register_nmi_handler(NMI_WATCHDOG,
				   hardlockup_detector_nmi_handler, 0,
				   "hpet_hld");

	if (ret) {
		free_irq(hld_data->irq, hld_data);
		return ret;
	}

	v = hpet_readl(HPET_Tn_CFG(hdata->channel));
	v |= HPET_TN_FSB;

	hpet_writel(v, HPET_Tn_CFG(hdata->channel));

	return 0;
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
	 * If this is the first CPU on which the detector is enabled,
	 * start everything. The HPET channel is disabled at this point.
	 */
	if (cpumask_weight(hld_data->monitored_cpumask) == 1) {
		hld_data->handling_cpu = cpu;
		/*
		 * Only update the affinity of the HPET channel interrupt when
		 * disabled.
		 */
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
 * from the HPET timer, update the affinity of the interrupt.
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

/**
 * hardlockup_detector_hpet_setup() - Parse command-line parameters
 * @str:	A string containing the kernel command line
 *
 * Parse the nmi_watchdog parameter from the kernel command line. If
 * selected by the user, use this implementation to detect hardlockups.
 */
static int __init hardlockup_detector_hpet_setup(char *str)
{
	if (!str)
		return -EINVAL;

	if (parse_option_str(str, "hpet"))
		hardlockup_use_hpet = true;

	if (!nmi_watchdog_user_enabled && hardlockup_use_hpet)
		pr_err("Selecting HPET NMI watchdog has no effect with NMI watchdog disabled\n");

	return 0;
}
early_param("nmi_watchdog", hardlockup_detector_hpet_setup);

/**
 * hardlockup_detector_hpet_init() - Initialize the hardlockup detector
 *
 * Only initialize and configure the detector if an HPET is available on the
 * system, the TSC is stable, and IPI shorthands are enabled.
 *
 * Returns:
 * 0 success. An error code if initialization was unsuccessful.
 */
int __init hardlockup_detector_hpet_init(void)
{
	int ret;

	if (!hardlockup_use_hpet)
		return -ENODEV;

	if (!is_hpet_enabled())
		return -ENODEV;

	if (!static_branch_likely(&apic_use_ipi_shorthand))
		return -ENODEV;

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
