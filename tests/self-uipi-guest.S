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
 mov $handler,%eax
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
 mov $MSR_IA32_UINTR_TT,%ecx
 mov $0x19001,%eax
 wrmsr
 movl $0xf10000,0x18000
 movq $0,0x18008
 movq $1,0x19000
 movq $0x18000,0x19008
 movq $0,0x1b000
 pushq $0x23
 pushq $0x1ef00
 pushq $0x3202
 pushq $0x1b
 pushq $user
 iretq
user:
 stui
 mov $100,%r8d
 mov $1,%r9d
1:
 xor %eax,%eax
 senduipi %rax
2:
 cmp %r9,0x1b000
 je 3f
 pause
 jmp 2b
3:
 testui
 jnc fail
 mov $0x505,%edx
 mov $1,%eax
 out %al,%dx
 inc %r9
 dec %r8d
 jnz 1b
 mov $0x504,%edx
 mov $42,%eax
 out %al,%dx
4:
 pause
 jmp 4b
fail:
 mov $0x504,%edx
 mov $99,%eax
 out %al,%dx
 jmp 4b
handler:
 incq 0x1b000
 add $8,%rsp
 uiret
