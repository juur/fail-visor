OUTPUT_FORMAT("elf32-i386","elf32-i386","elf32-i386")
OUTPUT_ARCH(i386)

SECTIONS {
	. = 0x00e0000;
	__bios_start = .;
	.text : { *(.text) }
	.rodata : { *(.rodata*) }
	__bios_end = .;
	.data 0x700 : AT (__bios_end) { __data_start = .; *(.data); __data_end = .;}
	.bss : { __bss_start = . ; *(.bss*) *(COMMON); __bss_end = .;}

	/DISCARD/ : {
		*(.debug*)
		*(.eh_frame*)
		*(.comment*)
		*(.stab)
		*(.stabstr)
		*(.note)
	}
}
