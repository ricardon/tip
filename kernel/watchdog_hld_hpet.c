// SPDX-License-Identifier: GPL-2.0
/*
 * A hardlockup detector driven by an HPET timer.
 *
 * Copyright (C) Intel Corporation 2018
 */

#define pr_fmt(fmt) "NMI hpet watchdog: " fmt

#include <linux/nmi.h>
#include <linux/hpet.h>
#include <asm/hpet.h>
#include <asm/irq_remapping.h>

#undef pr_fmt
#define pr_fmt(fmt) "NMI hpet watchdog: " fmt

static struct hpet_hld_data *hld_data;

/**
 * get_count() - Get the current count of the HPET timer
 *
 * Returns:
 *
 * Value of the main counter of the HPET timer
 */
static inline unsigned long get_count(void)
{
	return hpet_readq(HPET_COUNTER);
}

/**
 * set_comparator() - Update the comparator in an HPET timer instance
 * @hdata:	A data structure with the timer instance to update
 * @cmp:	The value to write in the in the comparator registere
 *
 * Returns:
 *
 * None
 */
static inline void set_comparator(struct hpet_hld_data *hdata,
				  unsigned long cmp)
{
	hpet_writeq(cmp, HPET_Tn_CMP(hdata->num));
}

/**
 * kick_timer() - Reprogram timer to expire in the future
 * @hdata:	A data structure with the timer instance to update
 *
 * Reprogram the timer to expire within watchdog_thresh seconds in the future.
 *
 * Returns:
 *
 * None
 */
static void kick_timer(struct hpet_hld_data *hdata)
{
	unsigned long new_compare, count;

	/*
	 * Update the comparator in increments of watch_thresh seconds relative
	 * to the current count. Since watch_thresh is given in seconds, we
	 * are able to update the comparator before the counter reaches such new
	 * value.
	 *
	 * Let it wrap around if needed.
	 */
	count = get_count();

	new_compare = count + watchdog_thresh * hdata->ticks_per_second;

	set_comparator(hdata, new_compare);
}

/**
 * disable() - Disable an HPET timer instance
 * @hdata:	A data structure with the timer instance to disable
 *
 * Returns:
 *
 * None
 */
static void disable(struct hpet_hld_data *hdata)
{
	unsigned int v;

	v = hpet_readl(HPET_Tn_CFG(hdata->num));
	v &= ~HPET_TN_ENABLE;
	hpet_writel(v, HPET_Tn_CFG(hdata->num));
}

/**
 * enable() - Enable an HPET timer instance
 * @hdata:	A data structure with the timer instance to enable
 *
 * Returns:
 *
 * None
 */
static void enable(struct hpet_hld_data *hdata)
{
	unsigned long v;

	/* Clear any previously active interrupt. */
	hpet_writel(BIT(hdata->num), HPET_STATUS);

	v = hpet_readl(HPET_Tn_CFG(hdata->num));
	v |= HPET_TN_ENABLE;
	hpet_writel(v, HPET_Tn_CFG(hdata->num));
}

/**
 * set_periodic() - Set an HPET timer instance in periodic mode
 * @hdata:	A data structure with the timer instance to enable
 *
 * If the timer supports periodic mode, configure it in such mode.
 * Returns:
 *
 * None
 */
static void set_periodic(struct hpet_hld_data *hdata)
{
	unsigned long v;

	v = hpet_readl(HPET_Tn_CFG(hdata->num));
	if (v & HPET_TN_PERIODIC_CAP) {
		v |= HPET_TN_PERIODIC;
		hpet_writel(v, HPET_Tn_CFG(hdata->num));
		hdata->flags |= HPET_DEV_PERI_CAP;
	}
}

/**
 * is_hpet_wdt_interrupt() - Determine if an HPET timer caused interrupt
 * @hdata:	A data structure with the timer instance to enable
 *
 * To be used when the timer is programmed in level-triggered mode, determine
 * if an instance of an HPET timer indicates that it asserted an interrupt by
 * checking the status register.
 *
 * Returns:
 *
 * True if a level-triggered timer asserted an interrupt. False otherwise.
 */
static bool is_hpet_wdt_interrupt(struct hpet_hld_data *hdata)
{
	unsigned long this_isr;
	unsigned int lvl_trig;

	this_isr = hpet_readl(HPET_STATUS) & BIT(hdata->num);

	lvl_trig = hpet_readl(HPET_Tn_CFG(hdata->num)) & HPET_TN_LEVEL;

	if (lvl_trig && this_isr)
		return true;

	return false;
}

#if 0
/**
 * hardlockup_detector_irq_handler() - Interrupt handler
 * @irq:	Interrupt number
 * @data:	Data associated with the interrupt
 *
 * A simple interrupt handler. Simply kick the timer and acknowledge the
 * interrupt.
 *
 * Returns:
 *
 * IRQ_NONE if the HPET timer did not cause the interrupt. IRQ_HANDLED
 * otherwise.
 */
static irqreturn_t hardlockup_detector_irq_handler(int irq, void *data)
{
	struct hpet_hld_data *hdata = data;
	unsigned int use_fsb;

	use_fsb = hdata->flags & HPET_DEV_FSB_CAP;

	if (!use_fsb && !is_hpet_wdt_interrupt(hdata))
		return IRQ_NONE;

	if (!(hdata->flags & HPET_DEV_PERI_CAP))
		kick_timer(hdata);

	pr_err("This interrupt should not have happened. Ensure delivery mode is NMI.\n");

	/* Acknowledge interrupt if in level-triggered mode */
	if (!use_fsb)
		hpet_writel(BIT(hdata->num), HPET_STATUS);

	return IRQ_HANDLED;
}
#endif

/**
 * hardlockup_detector_nmi_handler() - NMI Interrupt handler
 * @val:	Attribute associated with the NMI. Not used.
 * @regs:	Register values as seen when the NMI was asserted
 *
 * When an NMI is issued, look for hardlockups. If the timer is not periodic,
 * kick it. The interrupt is always handled when if delivered via the
 * Front-Side Bus.
 *
 * Returns:
 *
 * NMI_DONE if the HPET timer did not cause the interrupt. NMI_HANDLED
 * otherwise.
 */
static int hardlockup_detector_nmi_handler(unsigned int val,
					   struct pt_regs *regs)
{
	struct hpet_hld_data *hdata = hld_data;
	unsigned int use_fsb;

	/*
	 * If FSB delivery mode is used, the timer interrupt is programmed as
	 * edge-triggered and there is no need to check the ISR register.
	 */
	use_fsb = hdata->flags & HPET_DEV_FSB_CAP;

	if (!use_fsb && !is_hpet_wdt_interrupt(hdata))
		return NMI_DONE;

	inspect_for_hardlockups(regs);

	if (!(hdata->flags & HPET_DEV_PERI_CAP))
		kick_timer(hdata);

	/* Acknowledge interrupt if in level-triggered mode */
	if (!use_fsb)
		hpet_writel(BIT(hdata->num), HPET_STATUS);

	return NMI_HANDLED;
}

/**
 * setup_irq_msi_mode() - Configure the timer to deliver an MSI interrupt
 * @data:	Data associated with the instance of the HPET timer to configure
 *
 * Configure an instance of the HPET timer to deliver interrupts via the Front-
 * Side Bus.
 *
 * Returns:
 *
 * 0 success. An error code in configuration was unsuccessful.
 */
static int setup_irq_msi_mode(struct hpet_hld_data *hdata)
{
	unsigned int v;

	v = hpet_readl(HPET_Tn_CFG(hdata->num));

	/*
	 * If FSB interrupt delivery is used, configure as edge-triggered
	 * interrupt. We are certain the interrupt comes from the HPET timer as
	 * we receive the MSI message.
	 *
	 * Also, the FSB delivery mode and the FSB route are configured when the
	 * interrupt is unmasked.
	 */
	v &= ~HPET_TN_LEVEL;

	hpet_writel(v, HPET_Tn_CFG(hdata->num));

	return 0;
}

/**
 * setup_irq_legacy_mode() - Configure the timer to deliver an pin interrupt
 * @data:	Data associated with the instance of the HPET timer to configure
 *
 * Configure an instance of the HPET timer to deliver interrupts via a pin of
 * the IO APIC.
 *
 * Returns:
 *
 * 0 success. An error code in configuration was unsuccessful.
 */
static int setup_irq_legacy_mode(struct hpet_hld_data *hdata)
{
#if 0
	int hwirq = hdata->irq;
	unsigned long v;

	v = hpet_readl(HPET_Tn_CFG(hdata->num));

	v |= hwirq << HPET_TN_ROUTE_SHIFT;
	hpet_writel(v, HPET_Tn_CFG(hdata->num));

	/*
	 * If IO APIC interrupt delivery is used, configure as level-triggered.
	 * In this way, the ISR register can be used to determine if this HPET
	 * timer caused the interrupt at the IO APIC pin.
	 */
	v |= HPET_TN_LEVEL;

	/* Disable Front-Side Bus delivery. */
	v &= ~HPET_TN_FSB;

	hpet_writel(v, HPET_Tn_CFG(hdata->num));
#endif
	return 0;
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
 *
 * 0 success. An error code in configuration was unsuccessful.
 */
static int setup_hpet_irq(struct hpet_hld_data *hdata)
{
#if 0
	int hwirq = hdata->irq,;
#endif
	int ret;

	if (hdata->flags & HPET_DEV_FSB_CAP)
		ret = setup_irq_msi_mode(hdata);
#if 0
	else
		ret = setup_irq_legacy_mode(hdata);
#endif
	if (ret)
		return ret;

	/* Register the NMI handler, which will be the actual handler we use. */
	ret = register_nmi_handler(NMI_LOCAL, hardlockup_detector_nmi_handler,
				   0, "hpet_hld");
	if (ret)
		return ret;

#if 0
	/*
	 * Request an interrupt to activate the irq in all the needed domains.
	 */
	ret = request_irq(hwirq, hardlockup_detector_irq_handler,
			  IRQF_TIMER | IRQF_DELIVER_AS_NMI,
			  "hpet_hld", hdata);
	if (ret)
		unregister_nmi_handler(NMI_LOCAL, "hpet_hld");

#endif
	return ret;
}

/**
 * hardlockup_detector_hpet_enable() - Enable the hardlockup detector
 *
 * The hardlockup detector is enabled for the CPU that executes the
 * function. It is only enabled if such CPU is allowed to be monitored
 * by the lockup detector.
 *
 * Returns:
 *
 * None
 *
 */
static void hardlockup_detector_hpet_enable(void)
{
	struct cpumask *allowed = watchdog_get_allowed_cpumask();
	unsigned int cpu = smp_processor_id();

	if (!hld_data)
		return;

	if (!cpumask_test_cpu(cpu, allowed))
		return;

	spin_lock(&hld_data->lock);

	cpumask_set_cpu(cpu, &hld_data->monitored_mask);

	/*
	 * If this is the first CPU to be monitored, set everything in motion:
	 * move the interrupt to this CPU, kick and enable the timer.
	 */
	if (cpumask_weight(&hld_data->monitored_mask) == 1) {
		if (irq_set_affinity(hld_data->irq, cpumask_of(cpu))) {
			spin_unlock(&hld_data->lock);
			pr_err("Unable to enable on CPU %d.!\n", cpu);
			return;
		}

		kick_timer(hld_data);
		enable(hld_data);
	}

	spin_unlock(&hld_data->lock);
}

/**
 * hardlockup_detector_hpet_disable() - Disable the hardlockup detector
 *
 * The hardlockup detector is disabled for the CPU that executes the
 * function.
 *
 * None
 */
static void hardlockup_detector_hpet_disable(void)
{
	if (!hld_data)
		return;

	spin_lock(&hld_data->lock);

	cpumask_clear_cpu(smp_processor_id(), &hld_data->monitored_mask);

	/* Only disable the timer if there are no more CPUs to monitor. */
	if (!cpumask_weight(&hld_data->monitored_mask))
		disable(hld_data);

	spin_unlock(&hld_data->lock);
}

/**
 * hardlockup_detector_hpet_stop() - Stop the NMI watchdog on all CPUs
 *
 * Returns:
 *
 * None
 */
static void hardlockup_detector_hpet_stop(void)
{
	disable(hld_data);

	spin_lock(&hld_data->lock);
	cpumask_clear(&hld_data->monitored_mask);
	spin_unlock(&hld_data->lock);
}

/**
 * hardlockup_detector_hpet_init() - Initialize the hardlockup detector
 *
 * Only initialize and configure the detector if an HPET is available on the
 * system.
 *
 * Returns:
 *
 * 0 success. An error code if initialization was unsuccessful.
 */
static int __init hardlockup_detector_hpet_init(void)
{
	int ret;

	if (!is_hpet_enabled())
		return -ENODEV;

	hld_data = hpet_hardlockup_detector_assign_timer();
	if (!hld_data)
		return -ENODEV;

	/* Disable before configuring. */
	disable(hld_data);

	set_periodic(hld_data);

	ret = setup_hpet_irq(hld_data);
	if (ret)
		return -ENODEV;

	/* Set timer for the first time relative to the current count. */
	kick_timer(hld_data);
	/*
	 * Timer might have been enabled when the interrupt was unmasked.
	 * This should be done via the .enable operation.
	 */
	disable(hld_data);

	spin_lock_init(&hld_data->lock);

	spin_lock(&hld_data->lock);
	cpumask_clear(&hld_data->monitored_mask);
	spin_unlock(&hld_data->lock);

	return 0;
}

struct nmi_watchdog_ops hardlockup_detector_hpet_ops = {
	.init		= hardlockup_detector_hpet_init,
	.enable		= hardlockup_detector_hpet_enable,
	.disable	= hardlockup_detector_hpet_disable,
	.stop		= hardlockup_detector_hpet_stop
};
