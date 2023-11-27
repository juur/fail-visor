org 0xF0000
bits 16

BDA_START	equ 0x400
BDA_LEN		equ 0x100
EBDA_START	equ 0x90000
EBDA_LEN	equ 0x10000
BIOS_START	equ 0xf0000
BIOS_LEN	equ 0x10000
VGA_RAM_START	equ 0xa0000
VGA_RAM_LEN	equ 0x20000
VGA_ROM_START	equ 0xc0000
VGA_ROM_LEN	equ 0x08000
KERNEL_START	equ 0x100000
KERNEL_LEN	equ 512 * 1024 * 1024

bios_start:
	hlt
	jmp bios_start

int15_handler:
	cmp eax, 0xe820
	je _e820
	iretw

_e820:
	cmp edx, 0x534d4150
	jne .fail

	cmp ecx, 20
	jl .fail

	cmp ebx, 4
	jg .fail

.first:
	cmp ebx, 0
	jne .second
	mov [es:di], dword 0
	mov [es:di+4], dword 0
	mov [es:di+8], dword EBDA_START
	mov [es:di+12], dword 0
	mov [es:di+16], dword 1
	mov ebx, 1
	jmp .done

.second:
	cmp ebx, 1
	jne .third
	mov [es:di], dword EBDA_START
	mov [es:di+4], dword 0
	mov [es:di+8], dword EBDA_LEN
	mov [es:di+12], dword 0
	mov [es:di+16], dword 2
	mov ebx, 2
	jmp .done

.third:
	cmp ebx, 2
	jne .forth
	mov [es:di], dword BIOS_START
	mov [es:di+4], dword 0
	mov [es:di+8], dword BIOS_LEN
	mov [es:di+12], dword 0
	mov [es:di+16], dword 2
	mov ebx, 3
	jmp .done
.forth:
	cmp ebx, 3
	jne .fail
	mov [es:di], dword KERNEL_START
	mov [es:di+4], dword 0
	mov [es:di+8], dword KERNEL_LEN - KERNEL_START
	mov [es:di+12], dword 0
	mov [es:di+16], dword 1
	mov ebx, 0
	jmp .done

.done:
	mov eax, 0x534d4150 
	mov ecx, 20
	and [esp + 4], word 0xfffe
	iretw

.fail:
	mov eax, 0x534d4150
	mov ecx, 20
	mov ebx, 0
	or [esp + 4], word 1
	iretw

times 0xf000 - ($-$$)	    db 0

bios_intfake:
	iretw
	nop
	nop
	nop

bios_int15:
	jmp int15_handler
	nop
