; asmsyntax=nasm
org 0xffff0000
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

CR0_EM equ  (1<<2)
CR0_NE equ  (1<<5)

IDE0_DR	    equ 0x1f0

IDE0_ER	    equ 0x1f1
IDE0_FR	    equ 0x1f1

IDE0_SCR    equ 0x1f2

IDE0_SNR    equ	0x1f3
IDE0_LBALO  equ	0x1f3

IDE0_CLR    equ	0x1f4
IDE0_LBAMID equ	0x1f4

IDE0_CHR    equ	0x1f5
IDE0_LBAHI  equ	0x1f5

IDE0_DHR    equ	0x1f6

IDE0_SR	    equ	0x1f7
IDE0_CR	    equ	0x1f7

IDE0_DCR    equ	0x3f6

MASTER	    equ 0xe0

SR_DRQ	    equ (1<<3)
SR_RDY	    equ (1<<6)
SR_BSY	    equ (1<<7)

DCR_NIEN    equ (1<<1)
DCR_SRST    equ (1<<2)

DHR_DRV	    equ (1<<4)
DHR_LBA	    equ (1<<6)
DHR_ALWAYS  equ ((1<<5)|(1<<7))

CMD_READ_SECTORS equ	0x20




bios_start:
	sti

	mov ax, cs
	mov ds, ax
	mov ss, ax
	mov ax, 0
	mov es, ax
	mov ax, ds

	mov dx, 0x3c0
	mov al, 0x0c
	out dx, al

	mov dx, 0x3d4
	mov al, 0xa3
	out dx, al

	mov ax, ds
	mov es:(0 * 4 + 2), ax
	lea ax, [bios_int00]
	mov es:((0 * 4) + 0), ax

	mov ax, ds
	mov es:(0x6 * 4 + 2), ax
	lea ax, [bios_int06]
	mov es:((0x6 * 4) + 0), ax

	mov ax, ds
	mov es:(0x10 * 4 + 2), ax
	lea ax, [bios_int10]
	mov es:((0x10 * 4) + 0), ax

	mov ax, ds
	mov es:(0x15 * 4 + 2), ax
	lea ax, [bios_int15]
	mov es:((0x15 * 4) + 0), ax

	mov ax, ds
	mov es:(0x13 * 4 + 2), ax
	lea ax, [bios_int13]
	mov es:((0x13 * 4) + 0), ax

	mov ax, ds
	mov es:(0x18 * 4 + 2), ax
	lea ax, [bios_int18]
	mov es:((0x18 * 4) + 0), ax

	mov eax, cr0
	and eax, ~(CR0_EM|CR0_NE)
	mov cr0, eax

	fninit

reset_ide0:
	mov dx, IDE0_DCR
	mov al, DCR_NIEN|DCR_SRST
	out dx, al
	mov al, DCR_NIEN
	out dx, al

	mov dx, IDE0_SR
	in al, dx
	in al, dx
	in al, dx
	in al, dx
.again:
	in al, dx
	and al, SR_BSY|SR_RDY
	cmp al, SR_RDY
	jne .again

	mov dx, IDE0_DHR
	mov al, DHR_ALWAYS|DHR_LBA
	out dx, al

	mov dx, IDE0_SCR
	mov al, 1
	out dx, al	    ; 1 sector

	mov dx, IDE0_LBALO
	mov al, 0
	out dx, al

	mov dx, IDE0_LBAMID
	mov al, 0
	out dx, al

	mov dx, IDE0_LBAHI
	mov al, 0
	out dx, al

	mov dx, IDE0_CR
	mov al, CMD_READ_SECTORS
	out dx, al

	mov dx, IDE0_SR
.loop:
	in al, dx
	and al, SR_DRQ|SR_BSY
	cmp al, SR_DRQ
	jne .loop

	mov ax, 0
	mov es, ax
	mov di, 0x7c00

	mov ecx, 256

	mov dx, IDE0_DR

	rep insw

	mov dl, 0x80
	jmp 0x0:0x7c00

halt:
	hlt
	jmp halt


int00_handler:
	hlt
	jmp int00_handler


int06_handler:
	hlt
	jmp int06_handler


int10_handler:
	out 0xe9, al
	
	iret


int13_handler:
	cmp ah, 0x00
	jne .not0

	; *************************************************
	; Reset Disk System
	clc		; success
	xor ah, ah	; error code
	jmp int13_return
.not0:

	cmp ah, 0x02
	jne .not2

	; *************************************************
	; Read Sector(s) Into Memory
	;
	; AL = #sectors to read
	; CH = [0:7] cylinder low
	; CL = [0:5] sector, [6:7] cylinder high
	; DH = drive head
	; DL = drive number [bit 7 = hdd]
	; ES:BX = buffer

	push di
	push ax
	push ax
	push dx

	; buffer starts as es:bx
	mov di, bx

.next_sector:
	mov dx, IDE0_SR
	in al, dx
	in al, dx
	in al, dx
	in al, dx
.again:
	in al, dx
	and al, SR_BSY|SR_RDY
	cmp al, SR_RDY
	jne .again


	mov dx, IDE0_DHR
	mov al, DHR_ALWAYS
	out dx, al

	; sector count
	mov dx, IDE0_SCR
	mov al, 1
	out dx, al
	
	; sector
	mov dx, IDE0_SNR
	mov al, cl
	and al, 0x3f
	out dx, al

	; cylinder low
	mov dx, IDE0_CLR
	mov al, ch
	out dx, al

	; cyclinder high
	mov dx, IDE0_CHR
	mov al, cl
	shr al, 6
	out dx, al

	; drive head
	pop dx
	mov al, dh
	mov dx, IDE0_DHR
	out dx, al

	; TODO drive number

	mov dx, IDE0_CR
	mov al, CMD_READ_SECTORS
	out dx, al

	mov dx, IDE0_SR
.loop:
	in al, dx
	and al, SR_DRQ|SR_BSY
	cmp al, SR_DRQ
	jne .loop

	mov ecx, 256
	mov dx, IDE0_DR
	rep insw


	pop ax
	dec al
	push ax
	cmp al, 0
	jne .next_sector
	pop ax
	pop ax
	pop di

	clc
	mov ah, 0
	xchg bx, bx
	jmp int13_return
.not2:

	cmp ah, 0x08	
	jne .not8

	; *************************************************
	; Read Drive Parameters
	cmp dl, 0x00	; fdd#0
	jne .notfda

	; floppy 0
	stc		; failure
	mov ah, 0x7	; drive parameter error
	jmp int13_return
.notfda:

	cmp dl, 0x80	; bit 7 = HDD, so test for hdd#0
	jne .nothda

	; hdd 0
	clc		; success
	mov dl, 1	; number of drives
	mov dh, 16-1	; heads - 1
	mov ch, 256-1	; cylinders - -1 (0:7)
	mov cl, 32-1	; cylinders - -1 (6:7)
			; sectors - 1    (0:5)
	xor bl, bl	; drive type (floppy)
	xor di, di	; drive parameter table (floppy)
	xor ax, ax	; status
	mov es, ax	; drive parameter table (floppy)
	jmp int13_return

.nothda:
	
	stc		; failure
	mov ah, 0x7	; drive parameter error
	jmp int13_return
.not8:

	cmp ah, 0x41	
	jne .not41
	cmp bx, 0x55aa
	jne .not41

	; *************************************************
	; Check Extensions Present
	stc		; failure
	mov ah, 0x01	; invalid function
	jmp int13_return
.not41:

int13_return:
	iretw

int15_handler:
	cmp eax, 0xe820
	je _e820
	iretw

	; Input:
	;
	; EAX	= E820h
	; EBX	= Continuation (0 for first)
	; ES:DS	= Buffer
	; ECX	= Size
	; EDX	= Signature 'SMAP'
	;
	; Output:
	;
	; CF    = Used for error condition
	; EAX   = Signature 'SMAP'
	; ES:DI = Supposed to be the same as start
	; ECX   = Buffer size
	; EBX   = Continuation or 0

_e820:
	; check the signature
	cmp edx, 0x534d4150
	jne .fail

	; check the destination size
	cmp ecx, 20
	jl .fail

	; check the continuation (number of members)
	cmp ebx, 4
	jg .fail

	; es:di is already set
	
	; ecx needs to be adjusted to the size we have (which is the minimum)
	mov ecx, 20

	; ds:si needs to be set to our src, plus ebx * 20
	push ds
	mov eax, 0xf800
	mov ds, eax
	mov esi, 0x0000

	; skip over source
	mov eax, ecx
.loop:
	cmp eax, 0
	je .loop_done
	add esi, ecx
	dec eax
	jmp .loop
.loop_done:

	push es
	push edi

	; copy ecx bytes from ds:[si] to es:[di]
	cld
	rep movsb

	pop edi
	pop es

	; bump continuation, or set to 0 if done
	inc ebx
	cmp ebx, 4
	jle .not_finished
	xor ebx, ebx
.not_finished:

	pop ds
	mov eax, 0x534d4150 
	and [esp + 4], word 0xfffe
	iretw

.fail:
	mov eax, 0x534d4150
	mov ecx, 20
	mov ebx, 0
	or [esp + 4], word 0x0001
	iretw


int18_handler:
	hlt
	jmp int18_handler
	iretw


vgaptr:	dw  0


times 0x8000 - ($-$$)	    db 0

bda:	dd  0, 0
	dd  EBDA_START, 0
	dd  1

	dd  EBDA_START, 0
	dd  EBDA_LEN, 0
	dd  2

	dd  BIOS_START, 0
	dd  BIOS_LEN, 0
	dd  2

	dd  KERNEL_START, 0
	dd  KERNEL_LEN - KERNEL_START, 0
	dd  1

times 0xf000 - ($-$$)	    db 0

bios_intfake:
	iretw
	nop
	nop
	nop

bios_int00:
	jmp 0xf000:int00_handler
	nop

bios_int06:
	jmp 0xf000:int06_handler
	nop

bios_int10:
	jmp 0xf000:int10_handler
	nop

bios_int13:
	jmp 0xf000:int13_handler
	nop

bios_int15:
	jmp 0xf000:int15_handler
	nop

bios_int18:
	jmp 0xf000:int18_handler
	nop

times 0xfff0 - ($-$$)	    db 0
	wbinvd
	jmp 0xf000:bios_start

times 0x10000 - ($-$$)	    db 0

; vim:ft=nasm ts=8 sw=8 noexpandtab
