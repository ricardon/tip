// SPDX-License-Identifier: GPL-2.0
/*
 * A hardlockup detector driven by an HPET timer.
 *
 * Copyright (C) Intel Corporation 2018
 */

#define pr_fmt(fmt) "NMI hpet watchdog: " fmt

#include <linux/nmi.h>
#include <linux/hpet.h>
#include <linux/slab.h>
#include <asm/hpet.h>
#include <asm/cpumask.h>
#include <asm/irq_remapping.h>

#include <linux/debugfs.h>

#undef pr_fmt
#define pr_fmt(fmt) "NMI hpet watchdog: " fmt

static struct hpet_hld_data *hld_data;

static void dump_regs(struct hpet_hld_data *hdata, int i)
{
	ricardo_printk("Registers %x\n", i);
	ricardo_printk("HPET_ID: 0x%lx\n", hpet_readq(HPET_ID));
	ricardo_printk("HPET_CFG: 0x%lx\n", hpet_readq(HPET_CFG));
	ricardo_printk("HPET_Tn_CFG(hdev->num): 0x%lx\n", hpet_readq(HPET_Tn_CFG(hdata->num)));
	ricardo_printk("HPET_Tn_CMP(hdev->num): 0x%lx\n", hpet_readq(HPET_Tn_CMP(hdata->num)));
	ricardo_printk("HPET_Tn_ROUTE(hdev->num): 0x%lx\n", hpet_readq(HPET_Tn_ROUTE(hdata->num)));
}

struct hpet_debugfs_data {
	unsigned char name[10];
	unsigned int num;
};

static int hld_data_debugfs_show(struct seq_file *m, void *data)
{
	struct hpet_hld_data *hdata = m->private;

	if (!hdata)
		return -ENODEV;

	seq_printf(m, "CPU mask: 0x%lx\n", *hdata->monitored_mask.bits);
	seq_printf(m, "Timer: %d\n", hdata->num);
	seq_printf(m, "IRQ: %d\n", hdata->irq);
	seq_printf(m, "Flags: %d\n", hdata->flags);
	seq_printf(m, "TPS: %lld\n", hdata->ticks_per_second);
	seq_printf(m, "TPC: %lld\n", hdata->ticks_per_cpu);

	return 0;
}

DEFINE_SHOW_ATTRIBUTE(hld_data_debugfs);

#define NIBBLE4(x, s) (((0xffffL << (s*16)) & x) >> s*16)
#define PR_REG(s, r) #s ": 0x%04lx:%04lx:%04lx:%04lx\n", NIBBLE4((r), 3), NIBBLE4((r), 2), NIBBLE4((r), 1), NIBBLE4((r), 0)
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
	 * The timer must monitor each CPU every watch_thresh seconds. Hence the
	 * timer expiration must be:
	 *
	 *    watch_thresh/N
	 *
	 * where N is the number of monitored CPUs.
	 *
	 * in order to monitor all the online CPUs. ticks_per_cpu gives the
	 * number of ticks needed to meet the condition above.
	 *
	 * Let it wrap around if needed.
	 */
	count = get_count();

	new_compare = count + watchdog_thresh * hdata->ticks_per_cpu;

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

/**
 * update_ticks_per_cpu() - Update the number of HPET ticks per CPU
 * @hdata:	struct with the timer's the ticks-per-second and CPU mask
 *
 * From the overall ticks-per-second of the timer, compute the number of ticks
 * after which the timer should expire to monitor each CPU every watch_thresh
 * seconds. The ticks-per-cpu quantity is computed using the number of CPUs that
 * the watchdog currently monitors.
 *
 * Returns:
 *
 * None
 *
 */
static void update_ticks_per_cpu(struct hpet_hld_data *hdata)
{
	unsigned int num_cpus = cpumask_weight(&hdata->monitored_mask);
	unsigned long long temp = hdata->ticks_per_second;

	/* Only update if there are monitored CPUs. */
	if (!num_cpus)
		return;

	do_div(temp, num_cpus);
	hdata->ticks_per_cpu = temp;
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
 * kick it. Move the interrupt to the next monitored CPU. The interrupt is
 * always handled when if delivered via the Front-Side Bus.
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
	unsigned int use_fsb, cpu;

	/*
	 * If FSB delivery mode is used, the timer interrupt is programmed as
	 * edge-triggered and there is no need to check the ISR register.
	 */
	use_fsb = hdata->flags & HPET_DEV_FSB_CAP;

	if (!use_fsb && !is_hpet_wdt_interrupt(hdata))
		return NMI_DONE;

	/* There are no CPUs to monitor. */
	if (!cpumask_weight(&hdata->monitored_mask))
		return NMI_HANDLED;

	inspect_for_hardlockups(regs);

	/*
	 * Target a new CPU. Keep trying until we find a monitored CPU. CPUs
	 * are addded and removed to this mask at cpu_up() and cpu_down(),
	 * respectively. Thus, the interrupt should be able to be moved to
	 * the next monitored CPU.
	 */
	spin_lock(&hld_data->lock);
	for_each_cpu_wrap(cpu, &hdata->monitored_mask, smp_processor_id() + 1) {
		if (!irq_set_affinity(hld_data->irq, cpumask_of(cpu)))
			break;
		pr_err("Could not assign interrupt to CPU %d. Trying with next present CPU.\n",
		       cpu);
	}
	spin_unlock(&hld_data->lock);

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
			  IRQF_TIMER | IRQF_DELIVER_AS_NMI | IRQF_NOBALANCING,
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
	update_ticks_per_cpu(hld_data);

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
	update_ticks_per_cpu(hld_data);

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

	debugfs_init(hld_data);

	return 0;
}

struct nmi_watchdog_ops hardlockup_detector_hpet_ops = {
	.init		= hardlockup_detector_hpet_init,
	.enable		= hardlockup_detector_hpet_enable,
	.disable	= hardlockup_detector_hpet_disable,
	.stop		= hardlockup_detector_hpet_stop
};
