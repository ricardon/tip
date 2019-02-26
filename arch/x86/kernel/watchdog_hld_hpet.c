// SPDX-License-Identifier: GPL-2.0
/*
 * A hardlockup detector driven by an HPET timer.
 *
 * Copyright (C) Intel Corporation 2019
 *
 * A hardlockup detector driven by an HPET timer. It implements the same
 * interfaces as the PERF-based hardlockup detector.
 *
 * In order to minimize the reconfiguration of interrupts, the HPET timer
 * always target the same CPU (the first CPU present in the
 * watchdog_allowed_mask cpumask, the handling CPU). If the HPET caused
 * an NMI on the handling CPU, an NMI interprocessor interrupt is sent
 * to the other CPUs in the watchdog_allowed_mask.
 *
 * This detector relies on an HPET timer that is periodic and capable
 * of using Front Side Bus interrupts.
 */

#include <linux/nmi.h>
#include <linux/hpet.h>
#include <asm/msidef.h>
#include <asm/hpet.h>
/*==============*/
#include <linux/slab.h>
#include <linux/debugfs.h>
/*==================*/

static struct hpet_hld_data *hld_data;
static bool hardlockup_use_hpet;


/*==========================================================================*/
#define NIBBLE4(x, s) (((0xffffL << (s*16)) & x) >> s*16)
#define PR_REG(s, r) #s ": 0x%04lx:%04lx:%04lx:%04lx\n", NIBBLE4((r), 3), NIBBLE4((r), 2), NIBBLE4((r), 1), NIBBLE4((r), 0)

static void dump_regs(struct hpet_hld_data *hdata, int i)
{
	ricardo_printk("Registers %x\n", i);
	ricardo_printk("HPET_ID: 0x%lx\n", hpet_readq(HPET_ID));
	ricardo_printk("HPET_CFG: 0x%lx\n", hpet_readq(HPET_CFG));
	//ricardo_printk("HPET_Tn_CFG(hdev->num): 0x%lx\n", hpet_readq(HPET_Tn_CFG(hdata->num)));
	//ricardo_printk("HPET_Tn_CMP(hdev->num): 0x%lx\n", hpet_readq(HPET_Tn_CMP(hdata->num)));
	//ricardo_printk("HPET_Tn_ROUTE(hdev->num): 0x%lx\n", hpet_readq(HPET_Tn_ROUTE(hdata->num)));
}

struct hpet_debugfs_data {
	unsigned char name[10];
	unsigned int num;
};

static int set_destid_show(struct seq_file *m, void *data)
{
	struct hpet_hld_data *hdata = m->private;
	struct msi_msg msg;
	unsigned int destid, new_destid;

	if (!hdata)
		return -ENODEV;

	msg.address_lo = hpet_readl(HPET_Tn_ROUTE(hdata->num) + 4);

	//seq_printf(m, PR_REG(DATAREG, msg.address_lo));

	//seq_printf(m, "msg.address_lo && MSI_ADDR_DEST_ID_MASK: %x\n",
	//	   msg.address_lo & MSI_ADDR_DEST_ID_MASK);
	//seq_printf(m, "msg.address_lo && MSI_ADDR_DEST_ID_MASK >> : %x\n",
	//	   (msg.address_lo & MSI_ADDR_DEST_ID_MASK) >> MSI_ADDR_DEST_ID_SHIFT);
	destid = (msg.address_lo & MSI_ADDR_DEST_ID_MASK) >> MSI_ADDR_DEST_ID_SHIFT;
	new_destid = (destid + 1) % 8;
	//seq_printf(m, "destid %d new_destid %d\n", destid, new_destid);

	msg.address_lo &= ~0xff000;
	msg.address_lo |= MSI_ADDR_DEST_ID(new_destid);

	hpet_writel(msg.address_lo, HPET_Tn_ROUTE(hdata->num) + 4);
	seq_printf(m, "DestID was %d, now is %d\n", destid, new_destid);

	return 0;

}

DEFINE_SHOW_ATTRIBUTE(set_destid);

static int hld_data_debugfs_show(struct seq_file *m, void *data)
{
	struct hpet_hld_data *hdata = m->private;

	if (!hdata)
		return -ENODEV;

	seq_printf(m, "CPU mask: 0x%lx\n", *hdata->cpu_monitored_mask.bits);
	//seq_printf(m, "Timer: %d\n", hdata->num);
	//seq_printf(m, "IRQ: %d\n", hdata->irq);
	//seq_printf(m, "Flags: %d\n", hdata->flags);
	seq_printf(m, "TPS: %lld\n", hdata->ticks_per_second);

	return 0;
}

DEFINE_SHOW_ATTRIBUTE(hld_data_debugfs);

static void kick_timer(struct hpet_hld_data *hdata);

static int kick_timer_show(struct seq_file *m, void *data)
{
	struct hpet_hld_data *hdata = m->private;

	if (!hdata)
		return -ENODEV;

	kick_timer(hdata);
	seq_printf(m, "timer kicked\n");
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(kick_timer);

static bool nmi_enable = 1;
static int enable_nmi_show(struct seq_file *m, void *data)
{
	if (nmi_enable)
		nmi_enable = 0;
	else
		nmi_enable = 1;
	seq_printf(m, "enabled NMIs\n");
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(enable_nmi);

static int regset_dump_show(struct seq_file *m, void *data)
{
	unsigned long val;
	struct hpet_debugfs_data *hpet_dbgfs_data = m->private;
	unsigned int num;

	if(!hpet_dbgfs_data)
		return -ENODEV;

	num = hpet_dbgfs_data->num;

	val = hpet_readq(HPET_ID);
	seq_printf(m, PR_REG(\nHPET_ID, val));
	seq_printf(m, "REV_ID         : %02lx\n", val & 0xffL);
	seq_printf(m, "NUM_TIM_CAP    : %02lx\n", (val >> 8) & 0x1fL);
	seq_printf(m, "COUNT_SIZE_CAP : %lx\n", (val >> 13) & 0x1L);
	seq_printf(m, "RES:           : %lx\n", (val >> 14) & 0x1L);
	seq_printf(m, "LEG_ROUTE_CAP  : %lx\n", (val >> 15) & 0x1L);
	seq_printf(m, "VENDOR_ID      : %04lx\n", (val >> 16) & 0xffffL);
	seq_printf(m, "COUNTER_CLK_PER: %08lx\n", (val >> 32) & 0xffffffffL);

	val = hpet_readq(HPET_CFG);
	seq_printf(m, PR_REG(\nHPET_CFG, val));
	seq_printf(m, "ENABLE_CFG     : %lx\n", val & 0x1L);
	seq_printf(m, "LEG_RT_CFG     : %lx\n", (val >> 1) & 0x1L);
	seq_printf(m, "RES1           : %02lx\n", (val >> 2) & 0x3fL);
	seq_printf(m, "RES2           : %02lx\n", (val >> 8) & 0xffL);
	seq_printf(m, "RES3           : %012lx\n", (val >> 16) & 0xffffffffffffL);

	seq_printf(m, "\n");
	val = hpet_readq(HPET_STATUS);
	seq_printf(m, PR_REG(\nHPET_STATUS, val));
	val = hpet_readq(HPET_COUNTER);
	seq_printf(m, PR_REG(\nHPET_COUNTER, val));

	val = hpet_readq(HPET_Tn_CFG(num));
	seq_printf(m, PR_REG(\nHPET_Tn_CFG, val));
	seq_printf(m, "RES                : %lx\n", val & 0x1L);
	seq_printf(m, "TN_INT_TYPE_CNF    : %lx\n", (val >> 1) & 0x1L);
	seq_printf(m, "TN_INT_ENB_CNF     : %lx\n", (val >> 2) & 0x1L);
	seq_printf(m, "TN_TYPE_CNF        : %lx\n", (val >> 3) & 0x1L);
	seq_printf(m, "TN_PER_INT_CAP     : %lx\n", (val >> 4) & 0x1L);
	seq_printf(m, "TN_SIZE_CAP        : %lx\n", (val >> 5) & 0x1L);
	seq_printf(m, "TN_VAL_SET_CNF     : %lx\n", (val >> 6) & 0x1L);
	seq_printf(m, "RES                : %lx\n", (val >> 7) & 0x1L);
	seq_printf(m, "TN_32MODE_CNF      : %lx\n", (val >> 8) & 0x1L);
	seq_printf(m, "TN_INT_ROUTE_CNF   : %02lx\n", (val >> 9) & 0x1fL);
	seq_printf(m, "TN_FSB_EN_CNF      : %lx\n", (val >> 14) & 0x1L);
	seq_printf(m, "TN_FSB_INT_DEL_CAP : %lx\n", (val >> 15) & 0x1L);
	seq_printf(m, "RES                : %04lx\n", (val >> 16) & 0xffffL);
	seq_printf(m, "TN_INT_ROUTE_CAP   : %08lx\n", (val >> 32) & 0xffffffffL);

	val = hpet_readq(HPET_Tn_CMP(num));
	seq_printf(m, PR_REG(\nHPET_Tn_CMP, val));

	val = hpet_readq(HPET_Tn_ROUTE(num));
	seq_printf(m, PR_REG(\nHPET_Tn_ROUTE, val));
	seq_printf(m, "MSI_ADDR_0FEE     : %03lx\n", (val >> (20 + 32)) & 0xfff);
	seq_printf(m, "MSI_ADDR_DestID   : %02lx\n", (val >> (12 + 32)) & 0xff);
	seq_printf(m, "MSI_ADDR_RES      : %02lx\n", (val >> (4 + 32)) & 0xff);
	seq_printf(m, "MSI_ADDR_RH       : %lx\n", (val >> (3 + 32)) & 0x1);
	seq_printf(m, "MSI_ADDR_DM       : %lx\n", (val >> (2 + 32)) & 0x1);
	seq_printf(m, "MSI_ADDR_RES      : %lx\n", (val >> (0 + 32)) & 0x3);
	seq_printf(m, "MSI_DATA_RES      : %04lx\n", (val >> 16) & 0xffff);
	seq_printf(m, "MSI_DATA_TM       : %lx\n", (val >> 15) & 0x1);
	seq_printf(m, "MSI_DATA_LVL      : %lx\n", (val >> 14) & 0x1);
	seq_printf(m, "MSI_DATA_RES      : %lx\n", (val >> 11) & 0x3);
	seq_printf(m, "MSI_DATA_DelMode  : %lx\n", (val >> 8) & 0x7);
	seq_printf(m, "MSI_DATA_VEC      : %02lx\n", val & 0xff);
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(regset_dump);

void __init debugfs_init(struct hpet_hld_data *hdata)
{
	struct dentry *hpet_debug_root;
	unsigned long val;
	unsigned int i, timers;

	hpet_debug_root = debugfs_create_dir("hpet_wdt", NULL);
	if (!hpet_debug_root)
		return;

	debugfs_create_file("params", 0444, hpet_debug_root, hld_data,
			    &hld_data_debugfs_fops);

	debugfs_create_file("kick_timer", 0444, hpet_debug_root, hld_data,
			    &kick_timer_fops);

	debugfs_create_file("enable_nmi", 0444, hpet_debug_root, NULL,
			    &enable_nmi_fops);

	debugfs_create_file("set_destid", 0444, hpet_debug_root, hld_data,
			    &set_destid_fops);

	val = hpet_readq(HPET_ID);
	timers = 1 + ((val & HPET_ID_NUMBER) >> HPET_ID_NUMBER_SHIFT);

	for (i = 0; i < timers; i++){
		/*TODO: free memory on error */
		struct hpet_debugfs_data *priv = kzalloc(sizeof(*priv),
							 GFP_KERNEL);

		priv->num = i;
		sprintf(priv->name, "regset%d", priv->num);

		debugfs_create_file(priv->name, 0444, hpet_debug_root,
				    priv, &regset_dump_fops);
	}
}

/*==========================================================================*/


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
 * Also compute the expected value of the time-stamp counter at the time of
 * expiration as well as a deviation from the expected value. The maximum
 * deviation is of ~1.5%. This deviation can be easily computed by shifting
 * by 6 positions the delta between the current and expected time-stamp values.
 *
 * Returns:
 *
 * None
 */
#define TSC_NEXT_ERRROR 6
static void kick_timer(struct hpet_hld_data *hdata)
{
	unsigned long tsc_curr, tsc_delta, new_compare, count;

	/* Start obtaining the current TSC and HPET counts. */
	tsc_curr = rdtsc();
	count = get_count();

	tsc_delta = (unsigned long)watchdog_thresh * (unsigned long)tsc_khz
		    * 1000L;
	hdata->tsc_next = tsc_curr + tsc_delta;
	hdata->tsc_next_error = tsc_delta >> 6;

	/*
	 * Update the comparator in increments of watch_thresh seconds relative
	 * to the current count. Since watch_thresh is given in seconds, we
	 * are able to update the comparator before the counter reaches such new
	 * value.
	 *
	 * Let it wrap around if needed.
	 */
	new_compare = count + watchdog_thresh * hdata->ticks_per_second;

	set_comparator(hdata, new_compare);
}

/**
 * disable_timer() - Disable an HPET timer instance
 * @hdata:	A data structure with the timer instance to disable
 *
 * Returns:
 *
 * None
 */
static void disable_timer(struct hpet_hld_data *hdata)
{
	unsigned int v;

	v = hpet_readl(HPET_Tn_CFG(hdata->num));
	v &= ~HPET_TN_ENABLE;
	hpet_writel(v, HPET_Tn_CFG(hdata->num));
}

/**
 * enable_timer() - Enable an HPET timer instance
 * @hdata:	A data structure with the timer instance to enable
 *
 * Returns:
 *
 * None
 */
static void enable_timer(struct hpet_hld_data *hdata)
{
	unsigned long v;

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
	v |= HPET_TN_PERIODIC;
	hpet_writel(v, HPET_Tn_CFG(hdata->num));
}

/**
 * is_hpet_wdt_interrupt() - Determine if an HPET timer caused interrupt
 * @hdata:	A data structure with the timer instance to enable
 *
 * Returns:
 *
 * True if the HPET watchdog timer caused the interrupt. False otherwise.
 */
static bool is_hpet_wdt_interrupt(struct hpet_hld_data *hdata)
{
	ricardo_printk("%d here\n", smp_processor_id());
	if (smp_processor_id() == hdata->handling_cpu) {
		unsigned long tsc_curr;

		tsc_curr = rdtsc();
		ricardo_printk("%d here curr%ld next %ld error %ld\n",
			       smp_processor_id(), tsc_curr, hdata->tsc_next, hdata->tsc_next_error);
		if (abs(tsc_curr - hdata->tsc_next) < hdata->tsc_next_error)
			return true;
	}

	return false;
}

/**
 * compose_msi_msg() - Populate address and data fields of an MSI message
 * @hdata:	A data strucure with the message to populate
 *
 * Populate an MSI message to deliver an NMI interrupt. Fields are populated
 * as in the MSI interrupt domain. This function does not populate the
 * Destination ID.
 *
 * Returns: none
 */
static void compose_msi_msg(struct hpet_hld_data *hdata)
{
	struct msi_msg *msg = &hdata->msi_msg;

	/*
	 * The HPET FSB Interrupt Route register does not have an
	 * address_hi part.
	 */
	msg->address_lo = MSI_ADDR_BASE_LO;

	if (apic->irq_dest_mode == 0)
		msg->address_lo |= MSI_ADDR_DEST_MODE_PHYSICAL;
	else
		msg->address_lo |= MSI_ADDR_DEST_MODE_LOGICAL;

	msg->address_lo |= MSI_ADDR_REDIRECTION_CPU;

	/*
	 * On edge trigger, we don't care about assert level. Also,
	 * since delivery mode is NMI, no irq vector is needed.
	 */
	msg->data = MSI_DATA_TRIGGER_EDGE | MSI_DATA_LEVEL_ASSERT |
		    MSI_DATA_DELIVERY_NMI;
}

/** update_handling_cpu() - Update APIC destid of handling CPU
 * @hdata:	A data strucure with the MSI message to update
 *
 * Update the APIC destid of the MSI message generated by the HPET timer
 * on expiration.
 */
static int update_handling_cpu(struct hpet_hld_data *hdata)
{
	unsigned int destid;

	hdata->msi_msg.address_lo &= ~MSI_ADDR_DEST_ID_MASK;
	destid = apic->calc_dest_apicid(hdata->handling_cpu);
	hdata->msi_msg.address_lo |= MSI_ADDR_DEST_ID(destid);

	hpet_writel(hdata->msi_msg.address_lo, HPET_Tn_ROUTE(hdata->num) + 4);

	return 0;
}

/**
 * hardlockup_detector_nmi_handler() - NMI Interrupt handler
 * @val:	Attribute associated with the NMI. Not used.
 * @regs:	Register values as seen when the NMI was asserted
 *
 * When in NMI context, check if it was caused by the expiration of the
 * HPET timer. If yes, create a CPU mask to issue an IPI to the rest
 * of monitored CPUs. Upon receiving their own NMI, the other CPUs will
 * check such mask to determine if they need to also look for lockups.
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
	unsigned int cpu = smp_processor_id();

	ricardo_printk("%d here\n", smp_processor_id());
	if (is_hpet_wdt_interrupt(hdata)) {
		ricardo_printk("%d here\n", smp_processor_id());
		/* Get ready to check other CPUs for hardlockups. */
		cpumask_copy(&hdata->cpu_monitored_mask,
			     watchdog_get_allowed_cpumask());
		cpumask_clear_cpu(smp_processor_id(),
				  &hdata->cpu_monitored_mask);

		apic->send_IPI_mask_allbutself(&hdata->cpu_monitored_mask,
					       NMI_VECTOR);

		kick_timer(hdata);

		inspect_for_hardlockups(regs);

		return NMI_HANDLED;
	}

	ricardo_printk("%d here\n", smp_processor_id());

	if (cpumask_test_and_clear_cpu(cpu, &hdata->cpu_monitored_mask)) {
		ricardo_printk("%d here\n", smp_processor_id());
		inspect_for_hardlockups(regs);
		return NMI_HANDLED;
	}

	return NMI_DONE;
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

	compose_msi_msg(hdata);
	hpet_writel(hdata->msi_msg.data, HPET_Tn_ROUTE(hdata->num));
	hpet_writel(hdata->msi_msg.address_lo, HPET_Tn_ROUTE(hdata->num) + 4);

	/*
	 * Since FSB interrupt delivery is used, configure as edge-triggered
	 * interrupt.
	 */
	v = hpet_readl(HPET_Tn_CFG(hdata->num));
	v &= ~HPET_TN_LEVEL;
	v |= HPET_TN_FSB;

	hpet_writel(v, HPET_Tn_CFG(hdata->num));

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
	int ret;

	ret = setup_irq_msi_mode(hdata);
	if (ret)
		return ret;

	ret = register_nmi_handler(NMI_LOCAL, hardlockup_detector_nmi_handler,
				   NMI_FLAG_FIRST, "hpet_hld");

	return ret;
}

/**
 * hardlockup_detector_hpet_enable() - Enable the hardlockup detector
 *
 * This function is called for each CPU that enables the lockup watchdog.
 * Since the HPET timer only targets the handling CPU, configure the timer
 * only in such case.
 *
 * Returns:
 *
 * None
 */
void hardlockup_detector_hpet_enable(void)
{
	struct cpumask *allowed = watchdog_get_allowed_cpumask();
	unsigned int cpu = smp_processor_id();

	if (!hld_data)
		return;

	hld_data->handling_cpu = cpumask_first(allowed);

	if (cpu == hld_data->handling_cpu) {
		update_handling_cpu(hld_data);
		kick_timer(hld_data);
		enable_timer(hld_data);
	}
}

/**
 * hardlockup_detector_hpet_disable() - Disable the hardlockup detector
 *
 * The hardlockup detector is disabled for the CPU that executes the
 * function.
 *
 * None
 */
void hardlockup_detector_hpet_disable(void)
{
	struct cpumask *allowed = watchdog_get_allowed_cpumask();

	if (!hld_data)
		return;

	/* Only disable the timer if there are no more CPUs to monitor. */
	if (!cpumask_weight(allowed))
		disable_timer(hld_data);
}

/**
 * hardlockup_detector_hpet_stop() - Stop the NMI watchdog on all CPUs
 *
 * Returns:
 *
 * None
 */
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
	if (strstr(str, "hpet"))
		hardlockup_use_hpet = true;

	return 0;
}
__setup("nmi_watchdog=", hardlockup_detector_hpet_setup);

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
int __init hardlockup_detector_hpet_init(void)
{
	int ret;

	ricardo_printk("here\n");
	if (!hardlockup_use_hpet)
		return -ENODEV;

	ricardo_printk("here\n");
	if (!is_hpet_enabled())
		return -ENODEV;

	if (check_tsc_unstable())
		return -ENODEV;

	hld_data = hpet_hardlockup_detector_assign_timer();
	if (!hld_data)
		return -ENODEV;

	ricardo_printk("here\n");
	disable_timer(hld_data);

	set_periodic(hld_data);
	ricardo_printk("here\n");

	ret = setup_hpet_irq(hld_data);
	if (ret)
		return -ENODEV;
	ricardo_printk("here\n");

	debugfs_init(hld_data);

	return 0;
}
