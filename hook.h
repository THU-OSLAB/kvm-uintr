/* SPDX-License-Identifier: GPL-2.0 */
#ifndef KVM_UINTR_HOOK_H
#define KVM_UINTR_HOOK_H
#include <linux/atomic.h>
#include <linux/ftrace.h>

struct ku_hook {
	const char *name;
	void *func;
	void *orig;
	unsigned long address;
	atomic_t *active_calls;
	struct ftrace_ops ops;
};

struct ku_hook_group {
	const char *name;
	struct ku_hook *hooks;
	size_t nr_hooks;
};

#define KU_HOOK(symbol, wrapper, original, active) \
	{ .name = (symbol), .func = (wrapper), .orig = (original), \
	  .active_calls = (active) }

int ku_symbols_init(void);
unsigned long ku_lookup_symbol(const char *name);
int ku_hook_group_install(struct ku_hook_group *group);
void ku_hook_group_remove(struct ku_hook_group *group);
#endif
