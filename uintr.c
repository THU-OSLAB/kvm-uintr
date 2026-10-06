// SPDX-License-Identifier: GPL-2.0
/* Opt-in VMX UINTR state bridge for the validated 6.8 host ABI. */
#define pr_fmt(fmt) "kvm_uintr: " fmt
#include "uintr.h"
#include "hook.h"
#include <asm/cpufeature.h>
#include <asm/msr.h>
#include <asm/vmx.h>
#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/utsname.h>
#include <linux/version.h>
#include <linux/xarray.h>

#include <asm/tlbflush.h>

#define VM_ENTRY_LOAD_UINV BIT(19)
#define VM_EXIT_CLEAR_UINV BIT(27)
#define GUEST_UINV_FIELD 0x0814
#define UINTR_CR4 BIT_ULL(25)
#define UINTR_MISC_VALID 0x000000ffffffffffULL
#define UINTR_XSAVES ".byte 0x48,0x0f,0xc7,0x2f"
#define UINTR_XRSTORS ".byte 0x48,0x0f,0xc7,0x1f"
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 17, 0)
#define KU_RDMSR_SAFE rdmsrq_safe
#else
#define KU_RDMSR_SAFE rdmsrl_safe
#endif

static bool enable;
module_param(enable, bool, 0444);
MODULE_PARM_DESC(enable, "Opt in to experimental KVM guest UINTR (requires validated 6.8 host)");

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0) &&                                              \
     LINUX_VERSION_CODE < KERNEL_VERSION(6, 9, 0)) ||                                              \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 17, 0) &&                                             \
     LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0))
struct guest_uintr {
	struct uintr_xstate regs;
	bool xss_enabled;
};
static DEFINE_XARRAY(guests);
static atomic_t active_calls = ATOMIC_INIT(0);
static struct module *vmx_module;
static bool ready;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 9, 0)
static u64 *host_cr4_reserved;
static u64 original_cr4_reserved;
#endif
static void (*original_cpuid)(struct kvm_vcpu *);
static void (*original_cpuid_runtime)(struct kvm_vcpu *);
static int (*original_get_msr)(struct kvm_vcpu *, struct msr_data *);
static int (*original_set_msr)(struct kvm_vcpu *, struct msr_data *);
static void (*original_load_guest)(struct kvm_vcpu *);
static void (*original_load_host)(struct kvm_vcpu *);
static void (*original_free)(struct kvm_vcpu *);

static unsigned long read_vmcs(unsigned long field)
{
	unsigned long value;
	asm volatile("vmread %1, %0" : "=r"(value) : "r"(field) : "cc");
	return value;
}
static void write_vmcs(unsigned long field, unsigned long value)
{
	asm volatile("vmwrite %0, %1" : : "r"(value), "r"(field) : "cc", "memory");
}
static void init_state(struct uintr_xstate *state)
{
	memset(state, 0, sizeof(*state));
	state->xregs.header.xfeatures = XFEATURE_MASK_UINTR;
	state->xregs.header.xcomp_bv = XCOMP_BV_COMPACTED_FORMAT | XFEATURE_MASK_UINTR;
}
static int save_state(struct uintr_xstate *state)
{
	int err;
	KU_XSTATE_OP(UINTR_XSAVES, state, XFEATURE_MASK_UINTR, 0, err);
	/* XSAVES may omit an initial component, leaving its old bytes untouched. */
	if (!err && !(state->xregs.header.xfeatures & XFEATURE_MASK_UINTR))
		memset(&state->uintr, 0, sizeof(state->uintr));
	return err;
}
static int load_state(struct uintr_xstate *state)
{
	int err;
	u64 misc;
	rdmsrl(MSR_IA32_UINTR_MISC, misc);
	wrmsrl(MSR_IA32_UINTR_MISC, misc & ~(0xffULL << 32));
	KU_XSTATE_OP(UINTR_XRSTORS, state, XFEATURE_MASK_UINTR, 0, err);
	return err;
}
static struct kvm_cpuid_entry2 *entry(struct kvm_vcpu *vcpu, u32 function, u32 index)
{
	unsigned int i;
	for (i = 0; i < vcpu->arch.cpuid_nent; ++i) {
		struct kvm_cpuid_entry2 *e = &vcpu->arch.cpuid_entries[i];
		if (e->function == function && e->index == index)
			return e;
	}
	return NULL;
}
static void update_compacted_size(struct kvm_vcpu *vcpu, struct guest_uintr *state)
{
	struct kvm_cpuid_entry2 *supervisor = entry(vcpu, 0xd, 1);
	u64 mask = vcpu->arch.xcr0 | vcpu->arch.ia32_xss;
	u32 size = 512 + 64;
	unsigned int bit;

	if (!state || !supervisor)
		return;
	if (state->xss_enabled)
		mask |= XFEATURE_MASK_UINTR;
	for (bit = 2; bit < 64; bit++) {
		struct kvm_cpuid_entry2 *component;

		if (!(mask & BIT_ULL(bit)))
			continue;
		component = entry(vcpu, 0xd, bit);
		if (!component)
			continue;
		if (component->ecx & BIT(1))
			size = ALIGN(size, 64);
		size += component->eax;
	}
	/* XSS bit 14 lives outside KVM's base mask but still contributes to size. */
	supervisor->ebx = size;
}
static void hooked_cpuid_runtime(struct kvm_vcpu *vcpu)
{
	original_cpuid_runtime(vcpu);
	update_compacted_size(vcpu, xa_load(&guests, (unsigned long)vcpu));
	atomic_dec(&active_calls);
}
static void hooked_cpuid(struct kvm_vcpu *vcpu)
{
	struct guest_uintr *state;
	struct kvm_cpuid_entry2 *features, *supervisor, *component, *copy;
	unsigned int n;
	u32 a, b, c, d;
	state = NULL;
	if (!smp_load_acquire(&ready))
		goto out;
	state = xa_load(&guests, (unsigned long)vcpu);
	if (!state) {
		if (!try_module_get(THIS_MODULE))
			goto out;
		state = kzalloc(sizeof(*state), GFP_KERNEL);
		if (!state) {
			module_put(THIS_MODULE);
			goto out;
		}
		init_state(&state->regs);
		if (xa_err(xa_store(&guests, (unsigned long)vcpu, state, GFP_KERNEL))) {
			kfree(state);
			state = NULL;
			module_put(THIS_MODULE);
			goto out;
		}
	}
	features = entry(vcpu, 7, 0);
	supervisor = entry(vcpu, 0xd, 1);
	if (!features || !supervisor)
		goto out;
	component = entry(vcpu, 0xd, XFEATURE_UINTR);
	if (!component) {
		n = vcpu->arch.cpuid_nent;
		if (n >= KVM_MAX_CPUID_ENTRIES)
			goto out;
		copy = kvmalloc_array(n + 1, sizeof(*copy), GFP_KERNEL);
		if (!copy)
			goto out;
		memcpy(copy, vcpu->arch.cpuid_entries, n * sizeof(*copy));
		memset(&copy[n], 0, sizeof(copy[n]));
		copy[n].function = 0xd;
		copy[n].index = XFEATURE_UINTR;
		copy[n].flags = KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
		kvfree(vcpu->arch.cpuid_entries);
		vcpu->arch.cpuid_entries = copy;
		vcpu->arch.cpuid_nent = n + 1;
		features = entry(vcpu, 7, 0);
		supervisor = entry(vcpu, 0xd, 1);
		component = &copy[n];
	}
	cpuid_count(0xd, XFEATURE_UINTR, &a, &b, &c, &d);
	component->eax = a;
	component->ebx = b;
	component->ecx = c;
	component->edx = d;
	features->edx |= BIT(5);
	supervisor->eax |= BIT(3);
	supervisor->ecx |= XFEATURE_MASK_UINTR;
out:
	original_cpuid(vcpu);
	update_compacted_size(vcpu, state);
	if (state && entry(vcpu, 7, 0) && (entry(vcpu, 7, 0)->edx & BIT(5)))
		vcpu->arch.cr4_guest_rsvd_bits &= ~UINTR_CR4;
	atomic_dec(&active_calls);
}
static int state_msr(struct guest_uintr *state, struct msr_data *msr, bool write)
{
	u64 *slot;
	switch (msr->index) {
	case MSR_IA32_UINTR_HANDLER:
		slot = &state->regs.uintr.handler;
		break;
	case MSR_IA32_UINTR_STACKADJUST:
		if (write && (msr->data & 6))
			return 1;
		slot = &state->regs.uintr.stack_adjust;
		break;
	case MSR_IA32_UINTR_PD:
		if (write && (msr->data & 63))
			return 1;
		slot = &state->regs.uintr.upid_addr;
		break;
	case MSR_IA32_UINTR_RR:
		slot = &state->regs.uintr.uirr;
		break;
	case MSR_IA32_UINTR_TT:
		if (write && (msr->data & 14))
			return 1;
		slot = &state->regs.uintr.uitt_addr;
		break;
	case MSR_IA32_UINTR_MISC:
		if (write) {
			if (msr->data & ~UINTR_MISC_VALID)
				return 1;
			state->regs.xregs.header.xfeatures |= XFEATURE_MASK_UINTR;
			state->regs.uintr.misc.uitt_size = (u32)msr->data;
			state->regs.uintr.misc.uinv = (u8)(msr->data >> 32);
		} else {
			msr->data = state->regs.uintr.misc.uitt_size |
				    ((u64)state->regs.uintr.misc.uinv << 32);
		}
		return 0;
	default:
		return -ENOENT;
	}
	if (write) {
		*slot = msr->data;
		state->regs.xregs.header.xfeatures |= XFEATURE_MASK_UINTR;
	} else
		msr->data = *slot;
	return 0;
}
static int hooked_get_msr(struct kvm_vcpu *vcpu, struct msr_data *msr)
{
	struct guest_uintr *state = xa_load(&guests, (unsigned long)vcpu);
	int ret = -ENOENT;
	if (state) {
		ret = state_msr(state, msr, false);
		if (msr->index == MSR_IA32_XSS) {
			ret = original_get_msr(vcpu, msr);
			if (!ret && state->xss_enabled)
				msr->data |= XFEATURE_MASK_UINTR;
		}
	}
	if (ret == -ENOENT)
		ret = original_get_msr(vcpu, msr);
	atomic_dec(&active_calls);
	return ret;
}
static int hooked_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr)
{
	struct guest_uintr *state = xa_load(&guests, (unsigned long)vcpu);
	int ret = -ENOENT;
	if (state) {
		ret = state_msr(state, msr, true);
		if (msr->index == MSR_IA32_XSS) {
			struct msr_data base = *msr;
			base.data &= ~((u64)XFEATURE_MASK_UINTR);
			ret = original_set_msr(vcpu, &base);
			if (!ret)
				state->xss_enabled = !!(msr->data & XFEATURE_MASK_UINTR);
			if (!ret)
				update_compacted_size(vcpu, state);
		}
	}
	if (ret == -ENOENT)
		ret = original_set_msr(vcpu, msr);
	atomic_dec(&active_calls);
	return ret;
}
struct host_uintr {
	struct uintr_xstate regs;
	u64 xss;
	unsigned long cr4;
	unsigned long vmcs_cr4;
	bool loaded;
};
static DEFINE_PER_CPU(struct host_uintr, saved_host);
static void hooked_load_guest(struct kvm_vcpu *vcpu)
{
	struct guest_uintr *state = xa_load(&guests, (unsigned long)vcpu);
	struct host_uintr *host = this_cpu_ptr(&saved_host);
	u64 guest_xss;
	u8 uinv;
	if (!state) {
		original_load_guest(vcpu);
		goto out;
	}
	/* Without TPR shadow, SENDUIPI can address the physical host APIC. */
	if (!(read_vmcs(CPU_BASED_VM_EXEC_CONTROL) & CPU_BASED_TPR_SHADOW)) {
		write_vmcs(GUEST_CR4, read_vmcs(GUEST_CR4) & ~UINTR_CR4);
		write_vmcs(GUEST_UINV_FIELD, 0);
		kvm_make_request(KVM_REQ_TRIPLE_FAULT, vcpu);
		original_load_guest(vcpu);
		goto out;
	}
	/* KVM invokes this pair with IRQs and preemption disabled. */
	host->cr4 = cr4_read_shadow();
	host->vmcs_cr4 = read_vmcs(HOST_CR4);
	cr4_set_bits(UINTR_CR4);
	write_vmcs(HOST_CR4, host->cr4 | UINTR_CR4);
	rdmsrl(MSR_IA32_XSS, host->xss);
	wrmsrl(MSR_IA32_XSS, host->xss | XFEATURE_MASK_UINTR);
	init_state(&host->regs);
	if (WARN_ON_ONCE(save_state(&host->regs))) {
		wrmsrl(MSR_IA32_XSS, host->xss);
		write_vmcs(HOST_CR4, host->vmcs_cr4);
		if (!(host->cr4 & UINTR_CR4))
			cr4_clear_bits(UINTR_CR4);
		original_load_guest(vcpu);
		goto out;
	}
	original_load_guest(vcpu);
	rdmsrl(MSR_IA32_XSS, guest_xss);
	wrmsrl(MSR_IA32_XSS, guest_xss | XFEATURE_MASK_UINTR);
	uinv = state->regs.uintr.misc.uinv;
	state->regs.uintr.misc.uinv = 0;
	if (WARN_ON_ONCE(load_state(&state->regs))) {
		state->regs.uintr.misc.uinv = uinv;
		load_state(&host->regs);
		wrmsrl(MSR_IA32_XSS, guest_xss);
		write_vmcs(HOST_CR4, host->vmcs_cr4);
		if (!(host->cr4 & UINTR_CR4))
			cr4_clear_bits(UINTR_CR4);
		goto out;
	}
	state->regs.uintr.misc.uinv = uinv;
	write_vmcs(GUEST_UINV_FIELD, uinv);
	write_vmcs(VM_ENTRY_CONTROLS, read_vmcs(VM_ENTRY_CONTROLS) | VM_ENTRY_LOAD_UINV);
	write_vmcs(VM_EXIT_CONTROLS, read_vmcs(VM_EXIT_CONTROLS) | VM_EXIT_CLEAR_UINV);
	wrmsrl(MSR_IA32_XSS, guest_xss | (state->xss_enabled ? XFEATURE_MASK_UINTR : 0));
	host->loaded = true;
out:
	atomic_dec(&active_calls);
}
static void hooked_load_host(struct kvm_vcpu *vcpu)
{
	struct guest_uintr *state = xa_load(&guests, (unsigned long)vcpu);
	struct host_uintr *host = this_cpu_ptr(&saved_host);
	u64 xss;
	if (state && host->loaded) {
		rdmsrl(MSR_IA32_XSS, xss);
		wrmsrl(MSR_IA32_XSS, xss | XFEATURE_MASK_UINTR);
		WARN_ON_ONCE(save_state(&state->regs));
		state->regs.uintr.misc.uinv = (u8)read_vmcs(GUEST_UINV_FIELD);
		WARN_ON_ONCE(load_state(&host->regs));
		wrmsrl(MSR_IA32_XSS, host->xss);
		write_vmcs(HOST_CR4, host->vmcs_cr4);
		if (!(host->cr4 & UINTR_CR4))
			cr4_clear_bits(UINTR_CR4);
		host->loaded = false;
	}
	original_load_host(vcpu);
	atomic_dec(&active_calls);
}
static void hooked_free(struct kvm_vcpu *vcpu)
{
	struct guest_uintr *state = xa_erase(&guests, (unsigned long)vcpu);
	original_free(vcpu);
	if (state) {
		kfree(state);
		module_put(THIS_MODULE);
	}
	atomic_dec(&active_calls);
}
static struct ku_hook hooks[] = {
    KU_HOOK("kvm_vcpu_after_set_cpuid", hooked_cpuid, &original_cpuid, &active_calls),
    KU_HOOK("kvm_update_cpuid_runtime", hooked_cpuid_runtime, &original_cpuid_runtime,
	    &active_calls),
    KU_HOOK("vmx_get_msr", hooked_get_msr, &original_get_msr, &active_calls),
    KU_HOOK("vmx_set_msr", hooked_set_msr, &original_set_msr, &active_calls),
    KU_HOOK("kvm_load_guest_xsave_state", hooked_load_guest, &original_load_guest, &active_calls),
    KU_HOOK("kvm_load_host_xsave_state", hooked_load_host, &original_load_host, &active_calls),
    KU_HOOK("vmx_vcpu_free", hooked_free, &original_free, &active_calls),
};
static struct ku_hook_group group = {
    .name = "KVM UINTR",
    .hooks = hooks,
    .nr_hooks = ARRAY_SIZE(hooks),
};
#endif

int ku_init(void)
{
	if (!enable)
		return 0;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0) &&                                              \
     LINUX_VERSION_CODE < KERNEL_VERSION(6, 9, 0)) ||                                              \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 17, 0) &&                                             \
     LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0))
	{
		u64 entry_caps, exit_caps;
		unsigned long address;
		int ret;
		struct module *(*module_address)(unsigned long);
		if (strcmp(utsname()->release, "6.8.0-146-generic") &&
		    strcmp(utsname()->release, "6.17.13-flux"))
			return -EOPNOTSUPP;
		{
			u32 a, b, c, d;
			cpuid_count(7, 0, &a, &b, &c, &d);
			if (!(d & BIT(5)))
				return -EOPNOTSUPP;
			cpuid_count(0xd, XFEATURE_UINTR, &a, &b, &c, &d);
			if (a != sizeof(struct uintr_state) || !(c & BIT(0)))
				return -EOPNOTSUPP;
		}
		if (KU_RDMSR_SAFE(MSR_IA32_VMX_TRUE_ENTRY_CTLS, &entry_caps) ||
		    KU_RDMSR_SAFE(MSR_IA32_VMX_TRUE_EXIT_CTLS, &exit_caps))
			return -EOPNOTSUPP;
		if (!(entry_caps & ((u64)VM_ENTRY_LOAD_UINV << 32)) ||
		    !(exit_caps & ((u64)VM_EXIT_CLEAR_UINV << 32)))
			return -EOPNOTSUPP;
		address = ku_lookup_symbol("vmx_vcpu_run");
		if (!address)
			return -ENODEV;
		module_address = (void *)ku_lookup_symbol("__module_address");
		if (!module_address)
			return -ENOENT;
		preempt_disable();
		vmx_module = module_address(address);
		if (vmx_module && !try_module_get(vmx_module))
			vmx_module = NULL;
		preempt_enable();
		if (!vmx_module)
			return -ENODEV;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 9, 0)
		host_cr4_reserved = (void *)ku_lookup_symbol("cr4_reserved_bits");
		if (!host_cr4_reserved ||
		    module_address((unsigned long)host_cr4_reserved) == NULL ||
		    strcmp(module_address((unsigned long)host_cr4_reserved)->name, "kvm")) {
			module_put(vmx_module);
			vmx_module = NULL;
			return -EOPNOTSUPP;
		}
		original_cr4_reserved = READ_ONCE(*host_cr4_reserved);
#endif
		ret = ku_hook_group_install(&group);
		if (ret) {
			module_put(vmx_module);
			vmx_module = NULL;
			return ret;
		}
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 9, 0)
		WRITE_ONCE(*host_cr4_reserved, original_cr4_reserved & ~UINTR_CR4);
#endif
		smp_store_release(&ready, true);
		pr_info("enabled opt-in VMX UINTR state bridge\n");
		return 0;
	}
#else
	return -EOPNOTSUPP;
#endif
}
void ku_exit(void)
{
	if (!enable)
		return;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0) &&                                              \
     LINUX_VERSION_CODE < KERNEL_VERSION(6, 9, 0)) ||                                              \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 17, 0) &&                                             \
     LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0))
	smp_store_release(&ready, false);
	ku_hook_group_remove(&group);
	while (atomic_read(&active_calls))
		cpu_relax();
	WARN_ON_ONCE(!xa_empty(&guests));
	xa_destroy(&guests);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 9, 0)
	WRITE_ONCE(*host_cr4_reserved, original_cr4_reserved);
#endif
	if (vmx_module)
		module_put(vmx_module);
#endif
}
