// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright © 2018 Intel Corporation.
 *
 * Authors: Gayatri Kammela <gayatri.kammela@intel.com>
 *          Jacob Pan <jacob.jun.pan@linux.intel.com>
 *          Sohil Mehta <sohil.mehta@intel.com>
 */

#define pr_fmt(fmt)     "INTEL_IOMMU: " fmt
#include <linux/debugfs.h>
#include <linux/dmar.h>
#include <linux/err.h>
#include <linux/intel-iommu.h>
#include <linux/intel-svm.h>
#include <linux/io.h>
#include <linux/iommu.h>
#include <linux/pci.h>
#include <linux/pm_runtime.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>

#include "irq_remapping.h"

#define TOTAL_BUS_NR	256	/* full bus range */

static void ctx_tbl_entry_show(struct seq_file *m, struct intel_iommu *iommu,
			       int bus, bool ext)
{
	const char *ct = ext ? "Lower Context Table" : "Context Table";
	struct context_entry *context;
	unsigned long flags;
	int ctx;

	seq_printf(m, "%s Entries for Bus: %d\n", ct, bus);
	seq_puts(m, "[entry]\tDevice B:D.F\tLow\t\tHigh\n");

	spin_lock_irqsave(&iommu->lock, flags);

	/* Publish either context entries or extended context entries */
	for (ctx = 0; ctx < (ext ? 128 : 256); ctx++) {
		context = iommu_context_addr(iommu, bus, ctx, 0);
		if (!context)
			goto out;

		if (!context_present(context))
			continue;

		seq_printf(m, "[%d]\t%04x:%02x:%02x.%x\t%llx\t%llx\n", ctx,
			   iommu->segment, bus, PCI_SLOT(ctx), PCI_FUNC(ctx),
			   context[0].lo, context[0].hi);

		if (!ecap_ecs(iommu->ecap))
			continue;

		seq_printf(m, "Higher Context Table Entries for Bus: %d\n",
			   bus);
		seq_printf(m, "[%d]\t%04x:%02x:%02x.%x\t%llx\t%llx\n", ctx,
			   iommu->segment, bus, PCI_SLOT(ctx), PCI_FUNC(ctx),
			   context[1].lo, context[1].hi);
	}
out:
	spin_unlock_irqrestore(&iommu->lock, flags);
}

static void root_tbl_entry_show(struct seq_file *m, struct intel_iommu *iommu)
{
	u64 rtaddr_reg = dmar_readq(iommu->reg + DMAR_RTADDR_REG);
	bool ext = !!(rtaddr_reg & DMA_RTADDR_RTT);
	const char *rt = ext ? "Extended Root Table" : "Root Table";
	int bus;

	seq_printf(m, "IOMMU %s: %s Address:%llx\n", iommu->name, rt,
		   rtaddr_reg);
	/* Publish extended root table entries or root table entries here */
	for (bus = 0; bus < TOTAL_BUS_NR; bus++) {
		if (!iommu->root_entry[bus].lo)
			continue;

		seq_printf(m, "%s Entries:\n", rt);
		seq_printf(m, "Bus %d L: %llx H: %llx\n", bus,
			   iommu->root_entry[bus].lo,
			   iommu->root_entry[bus].hi);

		ctx_tbl_entry_show(m, iommu, bus, ext);
	}
}

static int dmar_translation_struct_show(struct seq_file *m, void *unused)
{
	struct dmar_drhd_unit *drhd;
	struct intel_iommu *iommu;

	rcu_read_lock();
	for_each_active_iommu(iommu, drhd) {
		root_tbl_entry_show(m, iommu);
		seq_putc(m, '\n');
	}
	rcu_read_unlock();

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(dmar_translation_struct);

void __init intel_iommu_debugfs_init(void)
{
	struct dentry *iommu_debug_root;

	iommu_debug_root = debugfs_create_dir("intel_iommu", NULL);
	if (!iommu_debug_root)
		return;

	debugfs_create_file("dmar_translation_struct", 0444, iommu_debug_root,
			    NULL, &dmar_translation_struct_fops);
}
