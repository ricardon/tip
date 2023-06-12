/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __X86_MICROCODE_INTERNAL_H__
#define __X86_MICROCODE_INTERNAL_H__

extern unsigned long control;

/* Loader control flags. */
enum control_flags {
	__LATE_ALL_THREADS = 0,
	__CONTROL_FLAGS_NUM,
};

#define LATE_ALL_THREADS	BIT_ULL(__LATE_ALL_THREADS)
#define CONTROL_FLAGS_MASK	~(BIT_ULL(__CONTROL_FLAGS_NUM) - 1)

#endif /* __X86_MICROCODE_INTERNAL_H__ */
