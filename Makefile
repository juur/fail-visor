CC := gcc
CFLAGS := -ggdb3 -std=c11 -Wall -Wextra -Og
LDFLAGS := -lncurses
BIOS := -g \
	-std=c11 \
	-Wall \
	-Wextra \
	-mgeneral-regs-only \
	-mno-red-zone \
	-m16 \
	-fomit-frame-pointer \
	-ffreestanding

	#-mregparm=3 \

default:	main

#bios2.o: bios2.c code16gcc.h e820.h
#	$(CC) $(BIOS) -o bios2.o -c bios2.c

#bios.o: bios.S asm.h
#	$(CC) $(BIOS) -o bios.o -c bios.S

#bios.elf: bios.o bios2.o bios.ld
#	$(LD) -static -m elf_i386 -T bios.ld -o bios.elf bios.o bios2.o

#bios.bin: bios.elf
#	objcopy -O binary bios.elf bios.bin
#

bios.bin: bios.s
	nasm -Wall bios.s -o bios.bin

bios-rom.o: bios-rom.S bios.bin

#bios.h: bios.elf
#	nm bios.elf | awk '/ [TtBR] / { print "#define _SYM_"$$3 "\t0x"$$1 }' > bios.h

#main.c: bios.h e820.h pci.h

main: main.o bios-rom.o
	$(CC) $(LDFLAGS) -o main main.o bios-rom.o

clean:
	rm -f *.o bios.bin bios.elf
