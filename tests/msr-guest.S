/* SPDX-License-Identifier: GPL-2.0 */
#include "../registers.h"
.section .text
.global _start
.code64
_start:
 mov $MSR_IA32_XSS,%ecx
 mov $0x4000,%eax
 xor %edx,%edx
 wrmsr
 mov %cr4,%rax
 or $(1<<25),%rax
 mov %rax,%cr4
 mov $MSR_IA32_UINTR_HANDLER,%ecx
 mov $0x12000,%eax
 xor %edx,%edx
 wrmsr
 mov $MSR_IA32_UINTR_STACKADJUST,%ecx
 mov $128,%eax
 wrmsr
 mov $MSR_IA32_UINTR_MISC,%ecx
 xor %eax,%eax
 mov $0xf1,%edx
 wrmsr
 mov $MSR_IA32_UINTR_PD,%ecx
 mov $0x18000,%eax
 xor %edx,%edx
 wrmsr
 mov $MSR_IA32_UINTR_RR,%ecx
 mov $0x1234,%eax
 wrmsr
 mov $MSR_IA32_UINTR_TT,%ecx
 mov $0x19001,%eax
 wrmsr
 mov $7,%eax
 xor %ecx,%ecx
 cpuid
 test $(1<<5),%edx
 jz fail
 mov $0xd,%eax
 mov $1,%ecx
 cpuid
 test $0x4000,%ecx
 jz fail
 cmp $624,%ebx
 jne fail
 mov $100,%r8d
1:
 mov $0x505,%edx
 mov $1,%eax
 out %al,%dx
 mov $MSR_IA32_UINTR_HANDLER,%ecx
 rdmsr
 cmp $0x12000,%eax
 jne fail
 mov $MSR_IA32_XSS,%ecx
 rdmsr
 test $0x4000,%eax
 jz fail
 mov $MSR_IA32_UINTR_RR,%ecx
 rdmsr
 cmp $0x1234,%eax
 jne fail
 dec %r8d
 jnz 1b
 mov $0x80010000,%eax
 mov %eax,0x17fc0
 xor %ecx,%ecx
 mov %ecx,0x17fc4
 mov $0x4000,%eax
 xor %edx,%edx
 mov $0x17dc0,%edi
 .byte 0x48,0x0f,0xc7,0x2f
 /* Initial-state XRSTORS leaves no live UINTR register values. */
 mov $MSR_IA32_UINTR_MISC,%ecx
 xor %eax,%eax
 xor %edx,%edx
 wrmsr
 movq $0x4000,0x1c208
 movl $0x80000000,0x1c20c
 mov $0x4000,%eax
 xor %edx,%edx
 mov $0x1c000,%edi
 .byte 0x48,0x0f,0xc7,0x1f
 mov $MSR_IA32_UINTR_RR,%ecx
 rdmsr
 or %edx,%eax
 jnz fail
 mov $MSR_IA32_UINTR_HANDLER,%ecx
 rdmsr
 or %edx,%eax
 jnz fail
 mov $MSR_IA32_UINTR_HANDLER,%ecx
 mov $0x1a000,%eax
 xor %edx,%edx
 wrmsr
 mov $MSR_IA32_UINTR_STACKADJUST,%ecx
 rdmsr
 or %edx,%eax
 jnz fail
 mov $MSR_IA32_UINTR_TT,%ecx
 rdmsr
 or %edx,%eax
 jnz fail
 mov $0x504,%edx
 mov $42,%eax
 out %al,%dx
 hlt
fail:
 mov $0x504,%edx
 mov $99,%eax
 out %al,%dx
 hlt
