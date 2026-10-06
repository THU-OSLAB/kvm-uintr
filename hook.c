// SPDX-License-Identifier: GPL-2.0
/* Adapted from Flux kmod/hook.c and kmod/compat/symbols.c, commit 8ffa052e. */
#define pr_fmt(fmt) "kvm_uintr: " fmt
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include "hook.h"

static unsigned long (*lookup_name)(const char *name);

int ku_symbols_init(void)
{
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
	int ret = register_kprobe(&kp);

	if (ret)
		return ret;
	lookup_name = (void *)kp.addr;
	unregister_kprobe(&kp);
	return lookup_name ? 0 : -ENXIO;
}

unsigned long ku_lookup_symbol(const char *name)
{
	return lookup_name ? lookup_name(name) : 0;
}

static void notrace ku_thunk(unsigned long ip, unsigned long parent_ip,
			    struct ftrace_ops *ops, struct ftrace_regs *regs)
{
	struct ku_hook *hook = container_of(ops, struct ku_hook, ops);

	if (!within_module(parent_ip, THIS_MODULE)) {
		atomic_inc(hook->active_calls);
		ftrace_get_regs(regs)->ip = (unsigned long)hook->func;
	}
}

static void ku_remove_hook(struct ku_hook *hook)
{
	if (!hook->address)
		return;
	/* Unregistration synchronizes callbacks before releasing module text. */
	unregister_ftrace_function(&hook->ops);
	ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	hook->address = 0;
}

int ku_hook_group_install(struct ku_hook_group *group)
{
	size_t i;
	int ret;

	for (i = 0; i < group->nr_hooks; i++) {
		struct ku_hook *hook = &group->hooks[i];

		hook->address = ku_lookup_symbol(hook->name);
		if (!hook->address) {
			pr_err("unresolved symbol: %s\n", hook->name);
			ret = -ENOENT;
			goto unwind;
		}
		*(unsigned long *)hook->orig = hook->address;
		hook->ops.func = ku_thunk;
		hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION |
				  FTRACE_OPS_FL_IPMODIFY;
		ret = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 1);
		if (ret) {
			hook->address = 0;
			goto unwind;
		}
		ret = register_ftrace_function(&hook->ops);
		if (ret) {
			ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
			hook->address = 0;
			goto unwind;
		}
	}
	return 0;
unwind:
	while (i)
		ku_remove_hook(&group->hooks[--i]);
	while (atomic_read(group->hooks[0].active_calls))
		cond_resched();
	synchronize_rcu_tasks();
	return ret;
}

void ku_hook_group_remove(struct ku_hook_group *group)
{
	size_t i = group->nr_hooks;

	while (i)
		ku_remove_hook(&group->hooks[--i]);
	while (atomic_read(group->hooks[0].active_calls))
		cond_resched();
	synchronize_rcu_tasks();
}
