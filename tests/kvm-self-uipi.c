// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/kvm.h>
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
int main(int argc, char **argv)
{
	CHECK(argc == 2);
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
	uint64_t *gdt = (void *)(mem + 0x5000);
	gdt[0] = 0;
	gdt[1] = 0x00af9b000000ffffULL;
	gdt[2] = 0x00cf93000000ffffULL;
	gdt[3] = 0x00affb000000ffffULL;
	gdt[4] = 0x00cff3000000ffffULL;
	gdt[5] = 0x00008b0060000067ULL;
	gdt[6] = 0;
	*(uint64_t *)(mem + 0x6004) = 0x1ff00;
	int vcpu = ioctl(vm, KVM_CREATE_VCPU, 0);
	CHECK(vcpu >= 0);
	struct kvm_cpuid2 *cp = calloc(1, sizeof(*cp) + 256 * sizeof(struct kvm_cpuid_entry2));
	CHECK(cp);
	cp->nent = 256;
	CHECK(ioctl(dev, KVM_GET_SUPPORTED_CPUID, cp) == 0);
	CHECK(ioctl(vcpu, KVM_SET_CPUID2, cp) == 0);
	struct kvm_sregs s;
	CHECK(ioctl(vcpu, KVM_GET_SREGS, &s) == 0);
	s.cs = seg(8, 11, 0, 1);
	s.ds = s.es = s.fs = s.gs = s.ss = seg(16, 3, 0, 0);
	s.tr = (struct kvm_segment){
	    .base = 0x6000, .limit = 0xffff, .selector = 40, .type = 11, .present = 1};
	s.ldt.unusable = 1;
	s.gdt.base = 0x5000;
	s.gdt.limit = 55;
	s.cr3 = 0x1000;
	s.cr0 = 0x80000033;
	s.cr4 = 0x40620;
	s.efer = 0xd01;
	CHECK(ioctl(vcpu, KVM_SET_SREGS, &s) == 0);
	struct kvm_lapic_state apic;
	CHECK(ioctl(vcpu, KVM_GET_LAPIC, &apic) == 0);
	*(uint32_t *)(apic.regs + 0xf0) = 0x1ff;
	CHECK(ioctl(vcpu, KVM_SET_LAPIC, &apic) == 0);
	struct kvm_regs r = {.rip = 0x10000, .rsp = 0x1ff00, .rflags = 2};
	CHECK(ioctl(vcpu, KVM_SET_REGS, &r) == 0);
	int size = ioctl(dev, KVM_GET_VCPU_MMAP_SIZE, 0);
	CHECK(size > 0);
	struct kvm_run *run = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpu, 0);
	CHECK(run != MAP_FAILED);
	unsigned exits = 0;
	int passed = 0;
	for (unsigned i = 0; i < 1000; i++) {
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
	printf("UIPI count=%llu\n", (unsigned long long)*(uint64_t *)(mem + 0x1b000));
	CHECK(passed && exits == 100 && *(uint64_t *)(mem + 0x1b000) == 100);
	close(vcpu);
	close(vm);
	close(dev);
	munmap(run, size);
	munmap(mem, 4 * 1024 * 1024);
	free(cp);
	puts("PASS KVM self SENDUIPI/UIRET across VM exits");
	return 0;
}
