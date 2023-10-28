#ifndef MSR_H
#define MSR_H

#define MSR_IA32_FEATURE_CONTROL                    0x03A
#define MSR_IA32_SYSENTER_CS                        0x174
#define MSR_IA32_SYSENTER_ESP                       0x175
#define MSR_IA32_SYSENTER_EIP                       0x176
#define MSR_IA32_DEBUGCTL                           0x1D9
#define MSR_IA32_VMX_BASIC                          0x480
#define MSR_IA32_VMX_PINBASED_CTLS                  0x481
#define MSR_IA32_VMX_PROCBASED_CTLS                 0x482
#define MSR_IA32_VMX_EXIT_CTLS                      0x483
#define MSR_IA32_VMX_ENTRY_CTLS                     0x484
#define MSR_IA32_VMX_MISC                           0x485
#define MSR_IA32_VMX_CR0_FIXED0                     0x486
#define MSR_IA32_VMX_CR0_FIXED1                     0x487
#define MSR_IA32_VMX_CR4_FIXED0                     0x488
#define MSR_IA32_VMX_CR4_FIXED1                     0x489
#define MSR_IA32_VMX_PROCBASED_CTLS2				0x48B
#define MSR_IA32_VMX_EPT_VPID_CAP					0x48C
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS				0x48D
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS			0x48E
#define MSR_IA32_VMX_TRUE_EXIT_CTLS					0x48F
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS				0x490
#define MSR_IA32_VMX_VMFUNC							0x491

#define IA32_FEATURE_CONTROL_MSR_LOCK                     0x0001
#define IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON_INSIDE_SMX  0x0002
#define IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON_OUTSIDE_SMX 0x0004
#define IA32_FEATURE_CONTROL_MSR_SENTER_PARAM_CTL         0x7f00
#define IA32_FEATURE_CONTROL_MSR_ENABLE_SENTER            0x8000

#define	MSR_IA32_FS_BASE    				   0xc0000100
#define	MSR_IA32_GS_BASE	                   0xc0000101

#define MSR_STAR 0xc0000081
#define MSR_LSTAR 0xc0000082
#define MSR_CSTAR 0xc0000083
#define MSR_KERNEL_GS_BASE 0xc0000102
#define MSR_SYSCALL_MASK 0xc0000084 
#define MSR_IA32_TSC			0x00000010

#define MSR_IA32_MISC_ENABLE		0x000001a0

#define MSR_IA32_MISC_ENABLE_FAST_STRING_BIT		0
#define MSR_IA32_MISC_ENABLE_FAST_STRING		(1ULL << MSR_IA32_MISC_ENABLE_FAST_STRING_BIT)

#endif
