/* SPDX-License-Identifier: GPL-2.0 */
/* UINTR register layout adapted from Flux kmod/uintr.h, commit 8ffa052e. */
#ifndef KVM_UINTR_STATE_H
#define KVM_UINTR_STATE_H
#include <linux/types.h>
#include <asm/extable.h>
#include <asm/fpu/types.h>
#include "registers.h"

#define XFEATURE_UINTR 14
#define XFEATURE_MASK_UINTR BIT_ULL(XFEATURE_UINTR)

struct uintr_state {
	u64 handler;
	u64 stack_adjust;
	struct {
		u32 uitt_size;
		u8 uinv;
		u8 pad1;
		u8 pad2;
		u8 pad3 : 7;
		u8 uif : 1;
	} __packed misc;
	u64 upid_addr;
	u64 uirr;
	u64 uitt_addr;
} __packed;

struct uintr_xstate {
	struct xregs_state xregs;
	struct uintr_state uintr;
} __packed __aligned(64);

/* Exception-table fixup keeps an invalid state from faulting host kernel text. */
#define KU_XSTATE_OP(op, st, lmask, hmask, err) \
	asm volatile("1:" op "\n\t" \
		     "xor %[err], %[err]\n" \
		     "2:\n\t" _ASM_EXTABLE_TYPE(1b, 2b, EX_TYPE_FAULT_MCE_SAFE) \
		     : [err] "=a"(err) \
		     : "D"(st), "m"(*st), "a"(lmask), "d"(hmask) \
		     : "memory", "cc")

int ku_init(void);
void ku_exit(void);
#endif
