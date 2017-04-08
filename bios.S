#include "asm.h"

	.code16gcc

.macro SAVE_BIOSREGS
    pushl   %fs
    pushl   %es
    pushl   %ds
    pushl   %edi
    pushl   %esi
    pushl   %ebp
    pushl   %esp
    pushl   %edx
    pushl   %ecx
    pushl   %ebx
    pushl   %eax
.endm

.macro RESTORE_BIOSREGS
    popl    %eax
    popl    %ebx
    popl    %ecx
    popl    %edx
    popl    %esp
    popl    %ebp
    popl    %esi
    popl    %edi
    popl    %ds
    popl    %es
    popl    %fs
.endm

ENTRY(bios_intfake)
	orl $EFLAGS_CF, 0x4(%esp)
	.byte 0xcf
ENTRY_END(bios_intfake)


ENTRY(bios_int15)
	SAVE_BIOSREGS

	movl	%esp, %eax
	call	int15_handler
	
	RESTORE_BIOSREGS
	.byte 0xcf
ENTRY_END(bios_int15)
