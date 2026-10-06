// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include "hook.h"
#include "uintr.h"

static int __init kvm_uintr_module_init(void)
{
	int ret = ku_symbols_init();

	return ret ? ret : ku_init();
}

static void __exit kvm_uintr_module_exit(void)
{
	ku_exit();
}

module_init(kvm_uintr_module_init);
module_exit(kvm_uintr_module_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Experimental standalone KVM/VMX UINTR state bridge");
