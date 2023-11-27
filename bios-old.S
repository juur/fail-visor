#include "asm.h"

	.code16gcc

.macro SAVE_BIOSREGS
    pushl   %fs
    pushl   %es
    pushl   %ds
    pushl   %edi
    pushl   %esi
    pushl   %ebp
    pushl   %edx
    pushl   %ecx
    pushl   %ebx
    pushl   %eax
.endm

.macro RESTORE_BIOSREGS
    popl    %fs
    popl    %es
    popl    %ds
    popl    %edi
    popl    %esi
    popl    %ebp
    popl    %edx
    popl    %ecx
    popl    %ebx
    popl    %eax
.endm

ENTRY(bios_intfake)
	orl $EFLAGS_CF, 0x4(%esp)
	.byte 0xcf
ENTRY_END(bios_intfake)


ENTRY(bios_int15)
	SAVE_BIOSREGS

	//movl	%esp, %eax
	movl	%esp, %edi
	call	int15_handler
	
	RESTORE_BIOSREGS
	.byte 0xcf
ENTRY_END(bios_int15)
