#ifndef _SERIAL_H
#define _SERIAL_H

#define COM1	0x3f8
#define	COM2	0x2f8
#define	COM3	0x3e8
#define	COM4	0x2e8

#define KBD_DATA	0x60
#define	KBD_STAT	0x64
#define	KBD_CMD		0x64

#define KBD_SR_OUTB	0x1
#define	KBD_SR_INB	0x2
#define	KBD_SR_SYS	0x4
#define	KBD_SR_CD	0x8
#define	KBD_SR_TO_ERR	0x40
#define	KBD_SR_PR_ERR	0x80

#define	SER_DATA	0x0
#define	SER_INTEN	0x1
#define	SER_LSB_DIV	0x0
#define	SER_MSB_DIV	0x1
#define	SER_CTRL	0x2
#define SER_FCR		0x2
#define	SER_LCR		0x3
#define	SER_MCR		0x4
#define	SER_LSR		0x5
#define	SER_MSR		0x6
#define	SER_SCRATCH	0x7

#define	SER_FCR_ENABLE	(1<<0)
#define	SER_FCR_CLR_RX	(1<<1)
#define SER_FCR_CLR_TX	(1<<2)
#define SER_FCR_DMA_1	(1<<3)
#define	SER_FCR_4B		(1<<6)
#define	SER_FCR_8B		(1<<7)
#define	SER_FCR_14B		(SER_FCR_4B|SER_FCR_8B)

#define	SER_LCR_DLAB	(1<<7)
#define	SER_LCR_SBR		(1<<6)
#define	SER_LCR_STICK	(1<<5)
#define	SER_LCR_EVEN	(1<<4)
#define	SER_LCR_5		0x0
#define	SER_LCR_6		0x1
#define	SER_LCR_7		0x2
#define	SER_LCR_8		0x3

#define	SER_MSR_DCD		(1<<7)
#define	SER_MSR_RI		(1<<6)
#define	SER_MSR_DSR		(1<<5)
#define	SER_MSR_CTS		(1<<4)
#define	SER_MSR_DDCD	(1<<3)
#define	SER_MSR_TERI	(1<<2)
#define	SER_MSR_DDSR	(1<<1)
#define	SER_MSR_DCTS	(1<<0)

#define	SER_MCR_DTR		(1<<0)
#define	SER_MCR_RTS		(1<<1)

#define	SER_LSR_DR			(1<<0)
#define	SER_LSR_THR			(1<<5)
#define	SER_LSR_THR_IDLE	(1<<6)
#endif
