// SPDX-License-Identifier: GPL-2.0
/*
 * A hardlockup detector driven by an HPET timer.
 *
 * Copyright (C) Intel Corporation 2019
 *
 * A hardlockup detector driven by an HPET timer. It implements the same
 * interfaces as the PERF-based hardlockup detector.
 *
 * A single HPET timer is used to monitor all the CPUs from the allowed_mask
 * from kernel/watchdog.c. Thus, the timer is programmed to expire every
 * watchdog_thresh/cpumask_weight(watchdog_allowed_cpumask). The timer targets
 * CPUs in round robin manner. Thus, every cpu in watchdog_allowed_mask is
 * monitored every watchdog_thresh seconds.
 */

#define pr_fmt(fmt) "NMI hpet watchdog: " fmt

#include <linux/nmi.h>
#include <linux/hpet.h>
#include <linux/slab.h>
#include <asm/msidef.h>
#include <asm/irq_remapping.h>
#include <asm/hpet.h>
/*==============*/
#include <linux/slab.h>
#include <linux/debugfs.h>
/*==================*/

static struct hpet_hld_data *hld_data;
static bool hardlockup_use_hpet;
static u64 tsc_next_error;

/*==========================================================================*/
#define NIBBLE4(x, s) (((0xffffL << (s*16)) & x) >> s*16)
#define PR_REG(s, r) #s ": 0x%04lx:%04lx:%04lx:%04lx\n", NIBBLE4((r), 3), NIBBLE4((r), 2), NIBBLE4((r), 1), NIBBLE4((r), 0)

static void dump_regs(struct hpet_hld_data *hdata, int i)
{
	ricardo_printk("Registers %x\n", i);
	ricardo_printk("HPET_ID: 0x%lx\n", hpet_readq(HPET_ID));
	ricardo_printk("HPET_CFG: 0x%lx\n", hpet_readq(HPET_CFG));
	//ricardo_printk("HPET_Tn_CFG(hdev->num): 0x%lx\n", hpet_readq(HPET_Tn_CFG(hdata->channel)));
	//ricardo_printk("HPET_Tn_CMP(hdev->num): 0x%lx\n", hpet_readq(HPET_Tn_CMP(hdata->channel)));
	//ricardo_printk("HPET_Tn_ROUTE(hdev->num): 0x%lx\n", hpet_readq(HPET_Tn_ROUTE(hdata->channel)));
}

struct hpet_debugfs_data {
	unsigned char name[10];
	unsigned int num;
};

static int send_nmi_show(struct seq_file *m, void *data)
{
	struct cpumask cpumask_test;

	cpumask_clear(&cpumask_test);
	cpumask_set_cpu(3, &cpumask_test);
	apic->send_IPI_mask_allbutself(&cpumask_test, NMI_VECTOR);

	return 0;
}

DEFINE_SHOW_ATTRIBUTE(send_nmi);


static int switch_to_perf_show(struct seq_file *m, void *data)
{
	hardlockup_detector_switch_to_perf();
	seq_printf(m, "Switched to perf\n");

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(switch_to_perf);

static int set_destid_show(struct seq_file *m, void *data)
{
	struct hpet_hld_data *hdata = m->private;
	struct msi_msg msg;
	unsigned int destid, new_destid;

	if (!hdata)
		return -ENODEV;

	msg.address_lo = hpet_readl(HPET_Tn_ROUTE(hdata->channel) + 4);

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

	hpet_writel(msg.address_lo, HPET_Tn_ROUTE(hdata->channel) + 4);
	seq_printf(m, "DestID was %d, now is %d\n", destid, new_destid);

	return 0;

}

DEFINE_SHOW_ATTRIBUTE(set_destid);

static int hld_data_debugfs_show(struct seq_file *m, void *data)
{
	struct hpet_hld_data *hdata = m->private;
	struct cpumask *mask;

	if (!hdata)
		return -ENODEV;

	seq_printf(m, "Timer: %d\n", hdata->channel);
	mask = to_cpumask(hdata->cpu_monitored_mask);
	seq_printf(m, "CPU mask: 0x%lx\n", *mask->bits);
	//seq_printf(m, "IRQ: %d\n", hdata->irq);
	seq_printf(m, "TPS: %lld\n", hdata->ticks_per_second);

	return 0;
}

DEFINE_SHOW_ATTRIBUTE(hld_data_debugfs);

static void kick_timer(struct hpet_hld_data *hdata, bool force);
static void disable_timer(struct hpet_hld_data *hdata);
static void enable_timer(struct hpet_hld_data *hdata);

static int kick_timer_show(struct seq_file *m, void *data)
{
	struct hpet_hld_data *hdata = m->private;

	if (!hdata)
		return -ENODEV;

	//disable_timer(hdata);
	//seq_printf(m, "timer disabled\n");
	kick_timer(hdata, true);
	seq_printf(m, "timer kicked\n");
	//enable_timer(hdata);
	//seq_printf(m, "timer re-enabled\n");
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(kick_timer);

static int disable_timer_show(struct seq_file *m, void *dat)
{
	struct hpet_hld_data *hdata = m->private;

	if (!hdata)
		return -ENODEV;

	disable_timer(hdata);
	seq_printf(m, "timer disabled\n");
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(disable_timer);

static int enable_timer_show(struct seq_file *m, void *dat)
{
	struct hpet_hld_data *hdata = m->private;

	if (!hdata)
		return -ENODEV;

	enable_timer(hdata);
	seq_printf(m, "timer enabled\n");
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(enable_timer);

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

	debugfs_create_file("enable_timer", 0444, hpet_debug_root, hld_data,
			    &enable_timer_fops);

	debugfs_create_file("disable_timer", 0444, hpet_debug_root, hld_data,
			    &disable_timer_fops);

	debugfs_create_file("enable_nmi", 0444, hpet_debug_root, NULL,
			    &enable_nmi_fops);

	debugfs_create_file("set_destid", 0444, hpet_debug_root, hld_data,
			    &set_destid_fops);

	debugfs_create_file("send_nmi", 0444, hpet_debug_root, NULL,
			    &send_nmi_fops);

	debugfs_create_file("switch_to_perf", 0444, hpet_debug_root, NULL,
			    &switch_to_perf_fops);

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
	bool kick_needed = force || !(hdata->has_periodic);

	tsc_curr = rdtsc();

	tsc_delta = (unsigned long)watchdog_thresh * hdata->tsc_ticks_per_cpu;
	hdata->tsc_next = tsc_curr + tsc_delta;
	tsc_next_error = tsc_delta >> 6;

	/*
	 * Update the comparator in increments of watch_thresh seconds relative
	 * to the current count. Since watch_thresh is given in seconds, we
	 * are able to update the comparator before the counter reaches such new
	 * value.
	 *
	 * Each CPU must be monitored every watch_thresh seconds. Since the
	 * timer targets one CPU at a time, it must expire every
	 *
	 *        ticks_per_cpu = watch_thresh * ticks_per_second /enabled_cpus
	 *
	 * as computed in update_ticks_per_cpu().
	 *
	 * Let it wrap around if needed.
	 */

	if (!kick_needed)
		return;

	count = hpet_readl(HPET_COUNTER);
	new_compare = count + watchdog_thresh * hdata->ticks_per_cpu;

	if (!hdata->has_periodic) {
		hpet_writel(new_compare, HPET_Tn_CMP(hdata->channel));
		ricardo_printk("Timer kicked cnt:%lx cmp:%lx tsccurr:%lu tscnext:%lu\n", count, new_compare, tsc_curr, hdata->tsc_next);
		return;
	}

	period = watchdog_thresh * hdata->ticks_per_cpu;
	hpet_set_comparator_periodic(hdata->channel, (u32)new_compare,
				     (u32)period);

	ricardo_printk("Timer kicked cnt:%lx cmp:%lx per:%lx tsccurr:%lu tscnext:%lu\n", count, new_compare, period, tsc_curr, hdata->tsc_next);
}

static void disable_timer(struct hpet_hld_data *hdata)
{
	u32 v;

	v = hpet_readl(HPET_Tn_CFG(hdata->channel));
	v &= ~(HPET_TN_ENABLE | HPET_TN_FSB);
	hpet_writel(v, HPET_Tn_CFG(hdata->channel));
}

static void enable_timer(struct hpet_hld_data *hdata)
{
	u32 v;

	v = hpet_readl(HPET_Tn_CFG(hdata->channel));
	v |= HPET_TN_ENABLE | HPET_TN_FSB;
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
	ricardo_printk("%d here\n", smp_processor_id());
	if (smp_processor_id() == hdata->handling_cpu) {
		unsigned long tsc_curr;

		tsc_curr = rdtsc();

		ricardo_printk("%d here curr%ld next %ld error %ld\n",
			       smp_processor_id(), tsc_curr, hdata->tsc_next, tsc_next_error);

		return (tsc_curr - hdata->tsc_next) + tsc_next_error <
		       2 * tsc_next_error;
	}

	return false;
}

/** irq_remapping_enabled() - Detect if interrupt remapping is enabled
 * @hdata:	A data structure with the HPET block id
 *
 * Determine if the HPET block that the hardlockup detector is under
 * the remapped interrupt domain.
 *
 * Returns: True interrupt remapping is enabled. False otherwise.
 */
static bool irq_remapping_enabled(struct hpet_hld_data *hdata)
{
	struct irq_alloc_info info;

	init_irq_alloc_info(&info, NULL);
	info.type = X86_IRQ_ALLOC_TYPE_HPET;
	info.hpet_id = hdata->blockid;

	return !!irq_remapping_get_ir_irq_domain(&info);
}

/**
 * compose_msi_msg() - Populate address and data fields of an MSI message
 * @hdata:	A data strucure with the message to populate
 *
 * Initialize the fields of the MSI message to deliver an NMI interrupt. This
 * function only initialize the files that don't change during the operation of
 * of the detector. This function does not populate the Destination ID; which
 * should be populated using update_msi_destid().
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

/** update_msi_destid() - Update APIC destid of handling CPU
 * @hdata:	A data strucure with the MSI message to update
 *
 * Update the APIC destid of the MSI message generated by the HPET timer
 * on expiration.
 */
static int update_msi_destid(struct hpet_hld_data *hdata)
{
	u32 destid;

	if (irq_remapping_enabled(hdata))
		return hld_hpet_intremap_activate_irq(hdata);

	hdata->msi_msg.address_lo &= ~MSI_ADDR_DEST_ID_MASK;
	destid = apic->calc_dest_apicid(hdata->handling_cpu);
	hdata->msi_msg.address_lo |= MSI_ADDR_DEST_ID(destid);

	hpet_writel(hdata->msi_msg.address_lo,
		    HPET_Tn_ROUTE(hdata->channel) + 4);

	return 0;
}

static void update_timer_irq_affinity(struct irq_work *work)
{
	struct hpet_hld_data *hdata = container_of(work, struct hpet_hld_data,
					      affinity_work);
	u32 cpu = smp_processor_id();

	cpu = cpumask_next(cpu, to_cpumask(hdata->cpu_monitored_mask));
	if (cpu >= nr_cpu_ids)
		cpu = cpumask_first(to_cpumask(hdata->cpu_monitored_mask));

	hdata->handling_cpu = cpu;
	update_msi_destid(hdata);
}

/**
 * hardlockup_detector_nmi_handler() - NMI Interrupt handler
 * @type:	Type of NMI handler; not used.
 * @regs:	Register values as seen when the NMI was asserted
 *
 * Check if it was caused by the expiration of the HPET timer. If yes, inspect
 * for lockups. Also, prepare the HPET timer to target the next monitored CPU
 * and kick it.
 *
 * Returns:
 * NMI_DONE if the HPET timer did not cause the interrupt. NMI_HANDLED
 * otherwise.
 */
static int hardlockup_detector_nmi_handler(unsigned int type,
					   struct pt_regs *regs)
{
	struct hpet_hld_data *hdata = hld_data;

	if (!is_hpet_wdt_interrupt(hdata))
		return NMI_DONE;

	inspect_for_hardlockups(regs);

	irq_work_queue(&hdata->affinity_work);
	kick_timer(hdata, !(hdata->has_periodic));

	return NMI_HANDLED;
}

/**
 * setup_irq_msi_mode() - Configure the timer to deliver an MSI interrupt
 * @data:	Data associated with the instance of the HPET timer to configure
 *
 * Configure the HPET timer to deliver interrupts via the Front-
 * Side Bus.
 *
 * Returns:
 * 0 success. An error code in configuration was unsuccessful.
 */
static int setup_irq_msi_mode(struct hpet_hld_data *hdata)
{
	s32 ret;
	u32 v;

	if (irq_remapping_enabled(hdata)) {
		ret = hld_hpet_intremap_alloc_irq(hdata);
		if (ret)
			return ret;
	} else {
		compose_msi_msg(hdata);
	}

	hpet_writel(hdata->msi_msg.data, HPET_Tn_ROUTE(hdata->channel));
	hpet_writel(hdata->msi_msg.address_lo,
		    HPET_Tn_ROUTE(hdata->channel) + 4);

	/*
	 * Since FSB interrupt delivery is used, configure as edge-triggered
	 * interrupt.
	 */
	v = hpet_readl(HPET_Tn_CFG(hdata->channel));
	v &= ~HPET_TN_LEVEL;
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
 * 0 success. An error code in configuration was unsuccessful.
 */
static int setup_hpet_irq(struct hpet_hld_data *hdata)
{
	int ret;

	ret = setup_irq_msi_mode(hdata);
	if (ret)
		return ret;

	ret = register_nmi_handler(NMI_WATCHDOG,
			           hardlockup_detector_nmi_handler, NMI_FLAG_FIRST,
				   "hpet_hld");

	init_irq_work(&hdata->affinity_work, update_timer_irq_affinity);
	return ret;
}

/**
 * update_ticks_per_cpu() - Update the number of HPET ticks per CPU
 * @hdata:     struct with the timer's the ticks-per-second and CPU mask
 *
 * From the overall ticks-per-second of the timer, compute the number of ticks
 * after which the timer should expire to monitor each CPU every watch_thresh
 * seconds. The ticks-per-cpu quantity is computed using the number of CPUs that
 * the watchdog currently monitors.
 */
static void update_ticks_per_cpu(struct hpet_hld_data *hdata)
{
	u64 temp = hdata->ticks_per_second;

	/* Only update if there are monitored CPUs. */
	if (!hdata->enabled_cpus)
		return;

	do_div(temp, hdata->enabled_cpus);
	hdata->ticks_per_cpu = temp;

	temp = (unsigned long)tsc_khz * 1000L;
	do_div(temp, hdata->enabled_cpus);
	hdata->tsc_ticks_per_cpu = temp;
}

/**
 * hardlockup_detector_hpet_enable() - Enable the hardlockup detector
 * @cpu:	CPU Index in which the watchdog will be enabled.
 *
 * Enable the hardlockup detector in @cpu. This means adding it to the
 * cpumask of monitored CPUs. If @cpu is the first one for which the
 * hardlockup detector is enabled, enable and kick the timer.
 */
void hardlockup_detector_hpet_enable(unsigned int cpu)
{
	cpumask_set_cpu(cpu, to_cpumask(hld_data->cpu_monitored_mask));

	hld_data->enabled_cpus++;
	update_ticks_per_cpu(hld_data);

	if (hld_data->enabled_cpus == 1) {
		hld_data->handling_cpu = cpu;
		update_msi_destid(hld_data);
		/* Force timer kick when detector is just enabled */
		kick_timer(hld_data, true);
		enable_timer(hld_data);
	}

	/*
	 * When in periodic mode, we only kick the timer here. Hence,
	 * as there are now more CPUs to monitor, we need to adjust the
	 * periodic expiration.
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
	cpumask_clear_cpu(cpu, to_cpumask(hld_data->cpu_monitored_mask));
	hld_data->enabled_cpus--;

	update_ticks_per_cpu(hld_data);

	ricardo_printk("here\n");
	if (hld_data->handling_cpu != cpu)
		return;

	ricardo_printk("here\n");

	disable_timer(hld_data);
	if (!hld_data->enabled_cpus)
		return;

	ricardo_printk("here\n");

	cpu = cpumask_first(to_cpumask(hld_data->cpu_monitored_mask));
	hld_data->handling_cpu = cpu;
	update_msi_destid(hld_data);
	ricardo_printk("here\n");

	kick_timer(hld_data, true);
	ricardo_printk("here\n");
	enable_timer(hld_data);
	ricardo_printk("here\n");
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

	if (parse_option_str(str, "hpet")) {
		printk(KERN_ERR ">>> found hpet\n");
		hardlockup_use_hpet = true;
	}

	if (!nmi_watchdog_user_enabled && hardlockup_use_hpet)
		pr_warn("Selecting HPET NMI watchdog has no effect with NMI watchdog disabled\n");

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

	ricardo_printk("here\n");
	if (!hardlockup_use_hpet)
		return -ENODEV;

	ricardo_printk("here\n");
	if (!is_hpet_enabled())
		return -ENODEV;

	ricardo_printk("here\n");
	if (check_tsc_unstable())
		return -ENODEV;

	hld_data = hpet_hardlockup_detector_get_timer();
	ricardo_printk("here\n");
	if (!hld_data)
		return -ENODEV;

	ricardo_printk("here\n");
	disable_timer(hld_data);

	ricardo_printk("here\n");

	ret = setup_hpet_irq(hld_data);
	if (ret) {
		kfree(hld_data);
		hld_data = NULL;
	}

	v = hpet_readl(HPET_Tn_CFG(hld_data->channel));
	v |= HPET_TN_32BIT;

	if (hld_data->has_periodic)
		v |= HPET_TN_PERIODIC;
	else
		v &= ~HPET_TN_PERIODIC;

	hpet_writel(v, HPET_Tn_CFG(hld_data->channel));

	ricardo_printk("here\n");

	debugfs_init(hld_data);

	return ret;
}
