//__asm__(".code16gcc");

typedef unsigned long uint32_t;
typedef unsigned short uint16_t;
typedef unsigned long long uint64_t;
typedef unsigned char uint8_t;
typedef _Bool bool;

#define true 1
#define false 0

#include "e820.h"

struct biosregs {
    uint32_t fs,es,ds;
    uint32_t edi,esi,ebp;
    uint32_t edx,ecx,ebx,eax;
	uint32_t eip;
    uint32_t cs;
	uint32_t eflags;
} __attribute__((packed));

//#define __attribute__((regparm(3)))
static void outportb(uint16_t port, uint8_t data)
{
	__asm__ volatile("outb %1, %0" : : "Nd" (port), "a" (data));
}

static inline uint8_t inportb(uint16_t port)
{
	uint8_t rv = 0;
	__asm__ volatile("inb %1, %0" : "=a" (rv) : "dN" (port));
	return rv;
}
static void set_fs(uint16_t seg)
{
	__asm__ volatile("movw %0,%%fs"::"rm"(seg));
}

static uint8_t rdfs8(uint32_t addr)
{
	uint8_t ret;
	__asm__ volatile("addr32 movb %%fs:%1,%0":"=q"(ret):"m"(*(uint32_t *)addr));
	return ret;
}
/*
static uint16_t rdfs16(uint32_t addr)
{
	uint16_t ret;
	__asm__ volatile("addr32 movw %%fs:%1,%0":"=q"(ret):"m"(*(uint32_t *)addr));
	return ret;
}
*/

static uint32_t rdfs32(uint32_t addr)
{
	uint32_t ret = 0;
	if(addr != 0)
		__asm__ volatile("addr32 movl %%fs:%1,%0":"=q"(ret):"m"(*(uint32_t *)addr));
	return ret;
}


static bool isprint(uint8_t c)
{
	return (c>32 && c<177) ? true : false;
}

static inline void putch(uint8_t c)
{
	if(!isprint(c)) 
        return;

	//              COM1  SER_LSR  SER_LSR_THR
	while( (inportb(0x3f8 + 0x5) & (1<<5)) == 0 ) {
		__asm__("pause");
	}
	outportb(0x3f8, c);
}

static inline void putsn(const char *s, int length)
{
	for(int i=0;i<length;i++)
        outportb(0x3f8, s[i]);
}

static int strlen(const char *s)
{
	int retval;
	for(retval=0;s[retval]!='\0';retval++) ;

	return retval;
}
static void puts(const char *s)
{
    while (*s)
        putch(*s++);
}

static void printnibble(uint8_t val)
{
	if(val>9) putch('a'+(val-10));
	else putch('0'+val);
}

static void printbyte(uint8_t val)
{
	uint8_t high = (val & 0xf0) >> 4;
	uint8_t low = (val & 0x0f);

	printnibble(high);
	printnibble(low);
}

static void printu32(uint32_t val)
{
	int i;
	uint8_t *tmp = (uint8_t *)&val;
	for(i=3;i>=0;i--)
	{
		printbyte(tmp[i] & 0xff);
	}
}


static void printu16(uint16_t val)
{
	//int i;
	uint8_t *tmp = (uint8_t *)&val;
	printbyte(tmp[1] & 0xff);
	printbyte(tmp[0] & 0xff);
}

static void doe820(volatile struct biosregs *r)
{
	uint16_t idx = (uint16_t)(r->ebx & 0xffff);
	uint32_t i;
	uint16_t fs = (__SYM_E820 >> 4);

	set_fs(fs);
	uint32_t cnt = rdfs32(__SYM_E820 - (fs<<4));

	if (r->edx != 0x534d4150 || idx >= cnt || r->ecx < sizeof(struct e820entry)) {
		r->eflags |= 0x1;
		return;
	}

	uint8_t *dst = (void *)r->edi;
	uint8_t *src = (uint8_t *)(__SYM_E820 + sizeof(uint32_t)+ (sizeof(struct e820entry) * idx));
	uint32_t saddr;
	//,daddr;

	for(i=0;i<sizeof(struct e820entry);i++) {
		saddr = (uint32_t)src++;
		fs = (saddr>>4);
		set_fs(fs);
		*dst++ = rdfs8(saddr - (fs<<4));
	}

	if (idx >= cnt)
		r->ebx = 0;
	else
		r->ebx = ++idx;

	r->eax = 0x534d4150;
	r->ecx = sizeof(struct e820entry);
	r->eflags &= ~0x1;
}


void int15_handler(volatile struct biosregs *r)
{
	switch (r->eax & 0xffff) {
        case 0x88:
            r->eax = 64 * 1024;
            r->eflags &= ~0x1;
            break;
		case 0xe820:
			doe820(r);
			break;
		default:
			r->eflags |= 0x1;
			break;
	}
}
