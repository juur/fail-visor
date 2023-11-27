#include <stdint.h>

struct e820entry {
	uint32_t	addr_low;
	uint32_t	addr_high;
	uint32_t	size_low;
	uint32_t	size_high;
	uint32_t	type;
} __attribute__((packed));

#define E820MAX    128
#define __SYM_E820		0x9fc00

struct e820map {
	uint32_t	nr_map;
	struct e820entry map[E820MAX];
} __attribute__((packed));

#define E820_RAM 1
#define E820_RESERVED 2
