// SPDX-License-Identifier: GPL-2.0
/*
 * A hardlockup detector driven by an HPET timer.
 *
 * Copyright (C) Intel Corporation 2021
 *
 * A hardlockup detector driven by an HPET timer. It implements the same
 * interfaces as the PMU-based hardlockup detector.
 *
 * A single HPET timer is used to monitor all the CPUs from the allowed_mask
 * from kernel/watchdog.c. Thus, the timer is programmed to expire every
 * watchdog_thresh/cpumask_weight(watchdog_allowed_cpumask). The timer targets
 * CPUs in round robin manner. Thus, every cpu in watchdog_allowed_mask is
 * monitored every watchdog_thresh seconds.
 */

#define pr_fmt(fmt) "NMI hpet watchdog: " fmt

#include <linux/nmi.h>
#include <linux/slab.h>

#include <asm/apic.h>
#include <asm/hpet.h>

static struct hpet_hld_data *hld_data;
static bool hardlockup_use_hpet;
static u64 tsc_next_error;

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
 * expiration as well as a deviation from the expected value. The maximum
 * deviation is of ~1.5%. This deviation can be easily computed by shifting
 * by 6 positions the delta between the current and expected time-stamp values.
 */
static void kick_timer(struct hpet_hld_data *hdata, bool force)
{
	u64 tsc_curr, tsc_delta, new_compare, count, period = 0;

	tsc_curr = rdtsc();

	tsc_delta = (unsigned long)watchdog_thresh * hdata->tsc_ticks_per_group;
	hdata->tsc_next = tsc_curr + tsc_delta;
	tsc_next_error = tsc_delta >> 6;

	/* kick the timer only when needed */
	if (!force && hdata->has_periodic)
		return;

	/*
	 * Update the comparator in increments of watch_thresh seconds relative
	 * to the current count. Since watch_thresh is given in seconds, we
	 * are able to update the comparator before the counter reaches such new
	 * value.
	 *
	 * Each CPU must be monitored every watch_thresh seconds. In order to
	 * keep the HPET channel interrupt under 1 per second, CPUs are targeted
	 * by groups. Each group is target separately.
	 *
	 *   ticks_per_group = watch_thresh * ticks_per_second / nr_groups
	 *
	 * as computed in update_ticks_per_group().
	 *
	 * Let it wrap around if needed.
	 */

	count = hpet_readl(HPET_COUNTER);
	new_compare = count + watchdog_thresh * hdata->ticks_per_group;

	if (!hdata->has_periodic) {
		hpet_writel(new_compare, HPET_Tn_CMP(hdata->channel));
		return;
	}

	period = watchdog_thresh * hdata->ticks_per_group;
	hpet_set_comparator_periodic(hdata->channel, (u32)new_compare,
				     (u32)period);
}

static void disable_timer(struct hpet_hld_data *hdata)
{
	u32 v;

	v = hpet_readl(HPET_Tn_CFG(hdata->channel));
	v &= ~HPET_TN_ENABLE;
	if (hld_data->has_periodic)
		v &= ~HPET_TN_PERIODIC;

	hpet_writel(v, HPET_Tn_CFG(hdata->channel));
}

static void enable_timer(struct hpet_hld_data *hdata)
{
	u32 v;

	v = hpet_readl(HPET_Tn_CFG(hdata->channel));
	/* Make sure we flush any outstanding interrupt. */
	v |= HPET_TN_LEVEL;
	hpet_writel(v, HPET_Tn_CFG(hdata->channel));
	hpet_writel(1 << hdata->channel, HPET_STATUS);

	v &= ~HPET_TN_LEVEL;
	if (hld_data->has_periodic)
		v |= HPET_TN_PERIODIC;
	else
		v &= ~HPET_TN_PERIODIC;

	v |= HPET_TN_ENABLE;
	hpet_writel(v, HPET_Tn_CFG(hdata->channel));
}

/**
 * is_hpet_wdt_interrupt() - Check if an HPET timer caused the interrupt
 * @hdata:	A data structure with the timer instance to enable
 *
 * Returns:
 * True if the HPET watchdog timer caused the interrupt. False otherwise.
 */
static bool is_hpet_wdt_interrupt(struct hpet_hld_data *hdata)
{
	if (smp_processor_id() == hdata->handling_cpu) {
		u64 tsc_curr;

		tsc_curr = rdtsc();

		return (tsc_curr - hdata->tsc_next) + tsc_next_error <
		       2 * tsc_next_error;
	}

	return false;
}

/**
 * compose_msi_msg() - Populate address and data fields of an MSI message
 * @hdata:	A data strucure with the message to populate
 *
 * Initialize the fields of the MSI message to deliver an NMI interrupt. This
 * function only initialize the files that don't change during the operation of
 * the detector. This function does not populate the Destination ID; which
 * should be populated using update_msi_destid().
 */
static void compose_msi_msg(struct hpet_hld_data *hdata)
{
	struct msi_msg *msg = &hdata->msi_msg;

	memset(msg, 0, sizeof(*msg));
	/*
	 * The HPET FSB Interrupt Route register does not have an
	 * address_hi part.
	 */
	msg->address_hi = X86_MSI_BASE_ADDRESS_HIGH;
	msg->arch_addr_lo.base_address = X86_MSI_BASE_ADDRESS_LOW;
	msg->arch_addr_lo.dest_mode_logical = apic->dest_mode_logical;

	/*
	 * Since delivery mode is NMI, no irq vector is needed.
	 */
	msg->arch_data.delivery_mode = APIC_DELIVERY_MODE_NMI;
}

/**
 * update_msi_destid() - Update APIC destid of handling CPU
 * @hdata:	A data strucure with the MSI message to update
 *
 * Update the APIC destid of the MSI message generated by the HPET timer
 * on expiration.
 */
static int update_msi_destid(struct hpet_hld_data *hdata)
{
	u32 destid;

	if (hdata->intr_remap_enabled) {
		int ret;

		ret = irq_set_affinity(hdata->irq,
				       cpumask_of(hdata->handling_cpu));
		return ret;
	}

	destid = apic->calc_dest_apicid(hdata->handling_cpu);
	/*
	 * HPET only suppports a 32-bit MSI address register. Thus, only
	 * 8-bit APIC IDs are supported. Systems with more than 256 CPUs
	 * should use interrupt remapping.
	 */
	WARN_ON_ONCE(destid > 0xff);

	hdata->msi_msg.arch_addr_lo.destid_0_7 = destid & 0xff;

	hpet_writel(hdata->msi_msg.address_lo,
		    HPET_Tn_ROUTE(hdata->channel) + 4);

	return 0;
}

/**
 * get_first_cpu_in_next_pkg() - Find the first CPU in the next package
 * @start_cpu:	CPU from which we start looking
 * @hdata:	A data structure with the monitored CPUs mask
 *
 * Find the first CPU in the package next to the package of @start_cpu.
 * If there is only one package in the system, return @start_cpu.
 */
static unsigned int get_first_cpu_in_next_pkg(int start_cpu,
					      struct hpet_hld_data *hdata)
{
	u16 this_cpu_pkg_id, next_cpu_pkg_id;
	int next_cpu = start_cpu;
	int safe = 0;

	if (start_cpu < 0 || start_cpu >= nr_cpu_ids)
		return -EINVAL;

	if (!cpumask_test_cpu(start_cpu, hdata->monitored_cpumask))
		return -ENODEV;

	this_cpu_pkg_id = topology_physical_package_id(start_cpu);
	next_cpu_pkg_id = this_cpu_pkg_id;

	/* If there is only one online package, return @start_cpu */
	while (this_cpu_pkg_id == next_cpu_pkg_id && safe < 400) {
		safe++;

		next_cpu = cpumask_next_wrap(next_cpu,
					     hdata->monitored_cpumask,
					     nr_cpu_ids,
					     true);
		/* Wrapped-around */
		if (next_cpu >= nr_cpu_ids)
			continue;

		/* Returned to starting point */
		next_cpu_pkg_id = topology_physical_package_id(next_cpu);
		if (next_cpu == start_cpu)
			break;
	}

	if (safe == 200)
		pr_err("BUG!! %s safe reached :(\n", __func__);

	return next_cpu;
}

/**
 * update_ipi_target_cpumask() - Update IPI mask for the next HPET interrupt
 * @hdata:	 Data strucure with the monitored cpumask and handling CPU info
 *
 * Update the target_cpumask of @hdata with the set of CPUs to which the
 * handling_cpu of @hdata will issue an IPI. Normally, the handling_cpu and the
 * CPUs in the updated target_cpumask are in the same package.
 */
static void update_ipi_target_cpumask(struct hpet_hld_data *hdata)
{
	int next_cpu, i;
	int safe = 0;

	next_cpu = hld_data->handling_cpu;

	/*
	 * If we start from an invalid CPU, instead of failing, just use the
	 * first monitored CPU.
	 */
	if (next_cpu < 0 || next_cpu >= nr_cpu_ids)
		next_cpu = cpumask_first(hdata->monitored_cpumask);

retry:
	safe++;
	if (safe == 100) {
		pr_err("BUG!! %s safe reached :(\n", __func__);
		return;
	}

	cpumask_clear(hdata->target_cpumask);

	for (i = 0 ; i < hdata->pkgs_per_group; i++) {
		next_cpu = get_first_cpu_in_next_pkg(next_cpu, hdata);
		if (next_cpu < 0 || next_cpu >= nr_cpu_ids) {
			/*
			 * Something went wrong. Restart the cycle with the
			 * first monitored CPU
			 */
			next_cpu = cpumask_first(hdata->monitored_cpumask);
			goto retry;
		}

		/* Select all the CPUs in the same package as @next_cpu */
		cpumask_or(hdata->target_cpumask, hdata->target_cpumask,
			   topology_core_cpumask(next_cpu));
	}

	/* Only select the CPUs that need to be monitored */
	cpumask_and(hdata->target_cpumask, hdata->target_cpumask,
		    hdata->monitored_cpumask);
}

/**
 * count_monitored_packages() - Count the packages with monitored CPUs
 * @hdata:	A data structure with the monitored cpumask
 *
 * Return the number of packages with at least one CPU in the monitored_cpumask
 * of @hdata
 */
static u32 count_monitored_packages(struct hpet_hld_data *hdata)
{
	int c = cpumask_first(hdata->monitored_cpumask);
	u16 start_id, id;
	u32 nr_pkgs = 0;

	start_id = topology_physical_package_id(c);
	id = ~start_id;

	do {
		nr_pkgs++;
		c = get_first_cpu_in_next_pkg(c, hdata);
		id = topology_physical_package_id(c);
	} while (start_id != id);

	return nr_pkgs;
}

static void setup_cpu_groups(struct hpet_hld_data *hdata)
{
	u32 monitored_pkgs = count_monitored_packages(hdata);

	hdata->pkgs_per_group = 0;
	hdata->nr_groups = U32_MAX;

	/*
	 * To keep the HPET timer to fire each 1 second or less frequently,
	 * the condition watchdog_thresh >= nr_groups nust be met. Thus,
	 * group together one or more packages until such condition is reached.
	 */
	while (watchdog_thresh < hdata->nr_groups) {
		hdata->pkgs_per_group++;
		hdata->nr_groups = DIV_ROUND_UP(monitored_pkgs,
						hdata->pkgs_per_group);
	}
}

static void update_timer_irq_affinity(struct irq_work *work)
{
	struct hpet_hld_data *hdata = container_of(work, struct hpet_hld_data,
						   affinity_work);

	update_ipi_target_cpumask(hdata);

	hdata->handling_cpu = cpumask_first(hdata->target_cpumask);
	update_msi_destid(hdata);
}

/**
 * hardlockup_detector_nmi_handler() - NMI Interrupt handler
 * @type:	Type of NMI handler; not used.
 * @regs:	Register values as seen when the NMI was asserted
 *
 * Check if it was caused by the expiration of the HPET timer. If yes, inspect
 * for lockups by issuing an IPI to all the monitored CPUs. Also, kick the
 * timer if it is non-periodic. Lastly, start IRQ work to update the
 * target_cpumask
 *
 * Returns:
 * NMI_DONE if the HPET timer did not cause the interrupt. NMI_HANDLED
 * otherwise.
 */
static int hardlockup_detector_nmi_handler(unsigned int type,
					   struct pt_regs *regs)
{
	struct hpet_hld_data *hdata = hld_data;
	int cpu = smp_processor_id();

	if (is_hpet_wdt_interrupt(hdata)) {
		/*
		 * Make a copy of the target mask. We need this as once a CPU
		 * gets the watchdog NMI it will clear itself from ipi_cpumask.
		 * Also, target_cpumask will be updated in a workqueue for the
		 * next NMI IPI.
		 */
		cpumask_copy(hld_data->ipi_cpumask, hld_data->target_cpumask);
		/*
		 * Even though the NMI IPI will be sent to all CPUs but self,
		 * clear the CPU to identify a potential unrelated NMI.
		 */
		cpumask_clear_cpu(cpu, hld_data->ipi_cpumask);
		if (cpumask_weight(hld_data->ipi_cpumask))
			apic->send_IPI_mask_allbutself(hld_data->ipi_cpumask,
						       NMI_VECTOR);

		irq_work_queue(&hdata->affinity_work);
		kick_timer(hdata, !(hdata->has_periodic));

		inspect_for_hardlockups(regs);

		return NMI_HANDLED;
	}

	if (cpumask_test_and_clear_cpu(cpu, hld_data->ipi_cpumask)) {
		inspect_for_hardlockups(regs);
		return NMI_HANDLED;
	}

	return NMI_DONE;
}

/*
 * When interrupt remapping is enabled, we request the irq for the detector
 * using request_irq() and then we fixup the delivery mode to NMI using
 * is_hpet_irq_hardlockup_detector(). If the latter fails, we will see a non-
 * NMI interrupt.
 *
 */
static irqreturn_t hardlockup_detector_irq_handler(int irq, void *data)
{
	pr_err_once("Received a non-NMI interrupt. The HLD detector always uses NMIs!\n");
	return IRQ_HANDLED;
}

/**
 * setup_irq_msi_mode() - Configure the timer to deliver an MSI interrupt
 * @data:	Data associated with the instance of the HPET timer to configure
 *
 * Configure the HPET timer to deliver interrupts via the Front-
 * Side Bus.
 *
 * Returns:
 * 0 success. An error code if setup was unsuccessful.
 */
static int setup_irq_msi_mode(struct hpet_hld_data *hdata)
{
	s32 ret;
	u32 v;

	if (hdata->intr_remap_enabled) {
		ret = request_irq(hld_data->irq, hardlockup_detector_irq_handler,
				  IRQF_TIMER, "hpet_hld", hld_data);
		if (ret)
			return ret;
	} else {
		compose_msi_msg(hdata);
		hpet_writel(hdata->msi_msg.data, HPET_Tn_ROUTE(hdata->channel));
		hpet_writel(hdata->msi_msg.address_lo,
			    HPET_Tn_ROUTE(hdata->channel) + 4);
	}

	v = hpet_readl(HPET_Tn_CFG(hdata->channel));
	v |= HPET_TN_FSB;

	hpet_writel(v, HPET_Tn_CFG(hdata->channel));

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
 * 0 success. An error code if setup was unsuccessful.
 */
static int setup_hpet_irq(struct hpet_hld_data *hdata)
{
	int ret;

	ret = setup_irq_msi_mode(hdata);
	if (ret)
		return ret;

	ret = register_nmi_handler(NMI_WATCHDOG,
				   hardlockup_detector_nmi_handler, 0,
				   "hpet_hld");

	init_irq_work(&hdata->affinity_work, update_timer_irq_affinity);
	return ret;
}

/**
 * update_ticks_per_group() - Update the number of HPET ticks CPU group
 * @hdata:     struct with the timer's the ticks-per-second and CPU mask
 *
 * From the overall ticks-per-second of the timer, compute the number of ticks
 * after which the timer should expire to monitor each CPU every watch_thresh
 * seconds. The monitored CPUs have been partitioned into groups, and the HPET
 * channel targets one group at a time.
 */
static void update_ticks_per_group(struct hpet_hld_data *hdata)
{
	u64 ticks = hdata->ticks_per_second;

	/* Only update if there are CPUs to monitor. */
	if (!hdata->nr_groups)
		return;

	do_div(ticks, hdata->nr_groups);
	hdata->ticks_per_group = ticks;

	ticks = (unsigned long)tsc_khz * 1000L;
	do_div(ticks, hdata->nr_groups);
	hdata->tsc_ticks_per_group = ticks;
}

/**
 * hardlockup_detector_hpet_enable() - Enable the hardlockup detector
 * @cpu:	CPU Index in which the watchdog will be enabled.
 *
 * Enable the hardlockup detector in @cpu. This means adding it to the
 * cpumask of monitored CPUs and starting the detectot if not done
 * before.
 */
void hardlockup_detector_hpet_enable(unsigned int cpu)
{
	cpumask_set_cpu(cpu, hld_data->monitored_cpumask);

	setup_cpu_groups(hld_data);
	update_ticks_per_group(hld_data);

	update_ipi_target_cpumask(hld_data);

	/*
	 * If this is the first CPU on which the detector is enabled,
	 * start everything.
	 */
	if (cpumask_weight(hld_data->monitored_cpumask) == 1) {
		hld_data->handling_cpu = cpu;
		update_msi_destid(hld_data);
		kick_timer(hld_data, true);
		enable_timer(hld_data);
		return;
	}

	/*
	 * Kick timer in case the number of monitored CPUs requires a change in
	 * the timer period.
	 */
	kick_timer(hld_data, hld_data->has_periodic);
}

/**
 * hardlockup_detector_hpet_disable() - Disable the hardlockup detector
 * @cpu:	CPU index in which the watchdog will be disabled
 *
 * @cpu is removed from the cpumask of monitored CPUs. If @cpu is also the CPU
 * handling the timer interrupt, update it to be the next available, monitored,
 * CPU.
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

	hld_data->handling_cpu = cpumask_first(hld_data->monitored_cpumask);
	update_msi_destid(hld_data);

	setup_cpu_groups(hld_data);
	update_ticks_per_group(hld_data);

	update_ipi_target_cpumask(hld_data);

	/*
	 * Kick timer in case the number of monitored CPUs requires a change in
	 * the timer period.
	 */
	kick_timer(hld_data, hld_data->has_periodic);
	enable_timer(hld_data);
}

void hardlockup_detector_hpet_stop(void)
{
	disable_timer(hld_data);
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
 * system.
 *
 * Returns:
 * 0 success. An error code if initialization was unsuccessful.
 */
int __init hardlockup_detector_hpet_init(void)
{
	int ret;
	u32 v;

	if (!hardlockup_use_hpet)
		return -ENODEV;

	if (!is_hpet_enabled())
		return -ENODEV;

	if (check_tsc_unstable())
		return -ENODEV;

	hld_data = hpet_hld_get_timer();
	if (!hld_data)
		return -ENODEV;

	disable_timer(hld_data);

	ret = setup_hpet_irq(hld_data);
	if (ret)
		goto err_no_irq;

	if (!zalloc_cpumask_var(&hld_data->monitored_cpumask, GFP_KERNEL))
		goto err_no_monitored_cpumask;

	if (!zalloc_cpumask_var(&hld_data->ipi_cpumask, GFP_KERNEL))
		goto err_no_ipi_cpumask;

	if (!zalloc_cpumask_var(&hld_data->target_cpumask, GFP_KERNEL))
		goto err_no_target_cpumask;

	v = hpet_readl(HPET_Tn_CFG(hld_data->channel));
	v |= HPET_TN_32BIT;

	hpet_writel(v, HPET_Tn_CFG(hld_data->channel));

	return ret;

err_no_target_cpumask:
	free_cpumask_var(hld_data->ipi_cpumask);
err_no_ipi_cpumask:
	free_cpumask_var(hld_data->monitored_cpumask);
err_no_monitored_cpumask:
	ret = -ENOMEM;
err_no_irq:
	kfree(hld_data);
	hld_data = NULL;

	return ret;
}
