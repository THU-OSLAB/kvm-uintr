// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include "../registers.h"
#include <fcntl.h>
#include <linux/kvm.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#define CHECK(x)                                                                                   \
	do {                                                                                       \
		if (!(x)) {                                                                        \
			perror(#x);                                                                \
			exit(2);                                                                   \
		}                                                                                  \
	} while (0)
static struct kvm_segment seg(unsigned sel, unsigned type, unsigned dpl, unsigned longmode)
{
	return (struct kvm_segment){.base = 0,
				    .limit = 0xffffffff,
				    .selector = sel,
				    .type = type,
				    .present = 1,
				    .s = 1,
				    .dpl = dpl,
				    .db = !longmode,
				    .l = longmode,
				    .g = 1};
}
static void reject_msr(int vcpu, unsigned index, uint64_t value)
{
	struct kvm_msrs *msrs = calloc(1, sizeof(*msrs) + sizeof(struct kvm_msr_entry));
	CHECK(msrs);
	msrs->nmsrs = 1;
	msrs->entries[0].index = index;
	msrs->entries[0].data = value;
	CHECK(ioctl(vcpu, KVM_SET_MSRS, msrs) == 0);
	CHECK(ioctl(vcpu, KVM_GET_MSRS, msrs) == 1);
	CHECK(msrs->entries[0].data == 0);
	free(msrs);
}
int main(int argc, char **argv)
{
	CHECK(argc == 2 || (argc == 3 && !strcmp(argv[2], "migrate")));
	alarm(15);
	int dev = open("/dev/kvm", O_RDWR | O_CLOEXEC);
	CHECK(dev >= 0);
	int vm = ioctl(dev, KVM_CREATE_VM, 0);
	CHECK(vm >= 0);
	CHECK(ioctl(vm, KVM_CREATE_IRQCHIP, 0) == 0);
	unsigned char *mem =
	    mmap(NULL, 4 * 1024 * 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(mem != MAP_FAILED);
	uint64_t *pml = (void *)(mem + 0x1000), *pdp = (void *)(mem + 0x2000),
		 *pd = (void *)(mem + 0x3000);
	pml[0] = 0x2007;
	pdp[0] = 0x3007;
	for (int i = 0; i < 2; i++)
		pd[i] = (i * 0x200000UL) | 0x87;
	int binary = open(argv[1], O_RDONLY);
	CHECK(binary >= 0);
	CHECK(read(binary, mem + 0x10000, 65536) > 0);
	close(binary);
	struct kvm_userspace_memory_region region = {.slot = 0,
						     .guest_phys_addr = 0,
						     .memory_size = 4 * 1024 * 1024,
						     .userspace_addr = (uintptr_t)mem};
	CHECK(ioctl(vm, KVM_SET_USER_MEMORY_REGION, &region) == 0);
	int vcpu = ioctl(vm, KVM_CREATE_VCPU, 0);
	CHECK(vcpu >= 0);
	struct kvm_cpuid2 *cp = calloc(1, sizeof(*cp) + 256 * sizeof(struct kvm_cpuid_entry2));
	CHECK(cp);
	cp->nent = 256;
	CHECK(ioctl(dev, KVM_GET_SUPPORTED_CPUID, cp) == 0);
	CHECK(ioctl(vcpu, KVM_SET_CPUID2, cp) == 0);
	reject_msr(vcpu, MSR_IA32_UINTR_STACKADJUST, 2);
	reject_msr(vcpu, MSR_IA32_UINTR_PD, 1);
	reject_msr(vcpu, MSR_IA32_UINTR_TT, 2);
	reject_msr(vcpu, MSR_IA32_UINTR_MISC, 1ULL << 40);
	reject_msr(vcpu, MSR_IA32_XSS, 1ULL << 63);
	struct kvm_sregs s;
	CHECK(ioctl(vcpu, KVM_GET_SREGS, &s) == 0);
	s.cs = seg(8, 11, 0, 1);
	s.ds = s.es = s.fs = s.gs = s.ss = seg(16, 3, 0, 0);
	s.tr = (struct kvm_segment){
	    .base = 0x6000, .limit = 0xffff, .selector = 40, .type = 11, .present = 1};
	s.ldt.unusable = 1;
	s.cr3 = 0x1000;
	s.cr0 = 0x80000033;
	s.cr4 = 0x40620;
	s.efer = 0xd01;
	CHECK(ioctl(vcpu, KVM_SET_SREGS, &s) == 0);
	struct kvm_regs r = {.rip = 0x10000, .rsp = 0x1ff00, .rflags = 2};
	CHECK(ioctl(vcpu, KVM_SET_REGS, &r) == 0);
	int size = ioctl(dev, KVM_GET_VCPU_MMAP_SIZE, 0);
	CHECK(size > 0);
	struct kvm_run *run = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpu, 0);
	CHECK(run != MAP_FAILED);
	unsigned exits = 0;
	int passed = 0;
	for (unsigned i = 0; i < 1000; i++) {
		if (argc == 3) {
			cpu_set_t set;
			CPU_ZERO(&set);
			CPU_SET(i & 1 ? 4 : 2, &set);
			CHECK(sched_setaffinity(0, sizeof(set), &set) == 0);
		}
		CHECK(ioctl(vcpu, KVM_RUN, 0) == 0);
		if (run->exit_reason == KVM_EXIT_IO) {
			unsigned char val = *((unsigned char *)run + run->io.data_offset);
			if (run->io.port == 0x505) {
				exits++;
				continue;
			}
			if (run->io.port == 0x504) {
				passed = val == 42;
				printf("KVM_UINTR_MSR result=%u exits=%u\n", val, exits);
				break;
			}
		}
		printf("Unexpected exit=%u hardware_reason=%llu\n", run->exit_reason,
		       (unsigned long long)run->fail_entry.hardware_entry_failure_reason);
		break;
	}
	uint64_t *state = (void *)(mem + 0x18000);
	printf("XSAVE handler=%llx stack=%llu misc=%llx upid=%llx uirr=%llx uitt=%llx\n",
	       (unsigned long long)state[0], (unsigned long long)state[1],
	       (unsigned long long)state[2], (unsigned long long)state[3],
	       (unsigned long long)state[4], (unsigned long long)state[5]);
	CHECK(passed && exits == 100 && state[0] == 0x12000 && state[4] == 0x1234);
	close(vcpu);
	close(vm);
	close(dev);
	munmap(run, size);
	munmap(mem, 4 * 1024 * 1024);
	free(cp);
	puts("PASS KVM UINTR MSR and XSAVES");
	return 0;
}
