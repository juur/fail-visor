CC := gcc
CFLAGS := -g -std=gnu11
BIOS := -m32 -march=i386 -fno-stack-protector -fno-builtin -fno-pic -fomit-frame-pointer -fdata-sections

default:	main

bios2.o: bios2.c code16gcc.h e820.h
	$(CC) -include code16gcc.h $(BIOS) -o bios2.o -c bios2.c

bios.o: bios.S
	$(CC) $(BIOS) -o bios.o -c bios.S

bios.elf: bios.o bios2.o bios.ld
	$(LD) -T bios.ld -o bios.elf bios.o bios2.o

bios.bin: bios.elf
	objcopy -O binary bios.elf bios.bin

bios-rom.o: bios-rom.S bios.bin

bios.h: bios.elf
	nm bios.elf | awk '/ [TtBR] / { print "#define _SYM_"$$3 "\t0x"$$1 }' > bios.h

main.c: bios.h e820.h pci.h

main: main.o bios-rom.o
	$(CC) -o main main.o bios-rom.o

clean:
	rm -f *.o bios.bin bios.elf
