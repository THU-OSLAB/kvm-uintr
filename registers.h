/* SPDX-License-Identifier: GPL-2.0 */
#ifndef KVM_UINTR_REGISTERS_H
#define KVM_UINTR_REGISTERS_H
#ifdef __KERNEL__
#include <asm/msr-index.h>
#endif
/* Shared by the module and bare-guest assembly tests. */
#ifndef MSR_IA32_XSS
#define MSR_IA32_XSS 0xda0
#elif MSR_IA32_XSS != 0xda0
#error Unexpected IA32_XSS address
#endif
#define MSR_IA32_UINTR_RR 0x985
#define MSR_IA32_UINTR_HANDLER 0x986
#define MSR_IA32_UINTR_STACKADJUST 0x987
#define MSR_IA32_UINTR_MISC 0x988
#define MSR_IA32_UINTR_PD 0x989
#define MSR_IA32_UINTR_TT 0x98a
#endif
