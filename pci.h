#include <stdint.h>

/*

struct pci_dev;
struct pci_bus;

struct pci_bus {
	struct pci_bus *next;
	struct pci_bus *parent;
	struct pci_bus *children;
	struct pci_dev *devices;
	struct pci_dev *self;
	int id;
};

struct pci_dev {
	struct pci_dev *next;
	struct pci_bus *bus;
	uint16_t vendorID;
	uint16_t deviceID;
	uint16_t subID;
	uint16_t subvendorID;
	int dev,func;
	int class_code;
	uint32_t bar[6];
	uint8_t barsize[6];
};
*/
struct pci_bar {
	unsigned is_io:1;
	union {
		struct {
			unsigned type:2;
			unsigned prefetchable:3;
			unsigned base:28;
		} mem;
		struct {
			unsigned res:1;
			unsigned base:30;
		} io;
		unsigned val:31;
	};
} __attribute__((packed));

union pci_config_addr {
	struct {
		unsigned offset:2;
		unsigned reg:6;
		unsigned func:3;
		unsigned dev:5;
		unsigned bus:8;
		unsigned _res:7;
		unsigned ena:1;
	};
	uint32_t val;
};

struct msix_cap {
	uint8_t cap;
	uint8_t next;
	uint16_t ctrl;
	uint32_t table_off;
	uint32_t pba_off;
} __attribute__((packed));

struct pci_config_head {
	uint16_t vendor, device, command, status;
	uint8_t revision, prog, subclass, classcode;
	uint8_t cache, timer, header_type, bist;
	uint32_t bars[6];
	uint32_t cis_ptr;
	uint16_t sub_vendor, sub;
	uint32_t rom_base;
	uint8_t cap_ptr;
	uint8_t pad0[3+4];
	uint8_t int_line, int_pin, grant, latency;
	struct msix_cap msix_cap;
	uint32_t pad1[136];
	uint32_t bars_size[6];
} __attribute__((packed));

#define PCI_DEVICE_ID_VIRTIO_NET        0x1000
#define PCI_DEVICE_ID_VIRTIO_BLK        0x1001
#define PCI_DEVICE_ID_VIRTIO_CONSOLE    0x1003
#define PCI_DEVICE_ID_VIRTIO_RNG        0x1004
#define PCI_DEVICE_ID_VIRTIO_BLN        0x1005
#define PCI_DEVICE_ID_VIRTIO_SCSI       0x1008
#define PCI_DEVICE_ID_VIRTIO_9P         0x1009
