OUTPUT_FORMAT("elf32-i386")
OUTPUT_ARCH(i386)

SECTIONS {
	/*. = 0x00e0000;*/
	. = 0xf0000;
	__bios_start = .;
	.text : { *(.text) }
	.rodata : { __rodata_start = .; *(.rodata*); __rodata_end = .;}
	.data : { __data_start = .; *(.data); __data_end = .;}
	.bss :  { __bss_start = . ; *(.bss*) *(COMMON); __bss_end = .;}
	__bios_end = .;

	/*.data 0x700 : AT (__bios_end) { __data_start = .; *(.data); __data_end = .;}*/

	/DISCARD/ : {
		*(.debug*)
		*(.eh_frame*)
		*(.comment*)
		*(.stab)
		*(.stabstr)
		*(.note)
	}
}
