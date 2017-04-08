	.org 0
	.code64

	.globl bios_rom
bios_rom:
	.incbin "bios.bin"
	.global bios_rom_end
bios_rom_end:
