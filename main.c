#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <stdbool.h>
#include <term.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>

#include <linux/kvm.h>
#include <asm/bootparam.h>
#include <linux/pci_regs.h>

#include "pci.h"
#include "pci_ids.h"
#include "apicdef.h"
#include "bios.h"
#include "serial.h"
#include "msr.h"

#define __SYM_E820      0x9fc00

#define ONE_MB 0x100000

struct mem_slot {
    struct mem_slot	*next;
    void	*host;
    uint64_t	guest;
    size_t	size;
};

struct irq_handler {
    unsigned int irq;
    unsigned long addr;
    size_t	size;
    void *handler;
};

struct e820entry {
    uint64_t addr;
    uint64_t size;
    uint32_t type;
} __attribute__((packed));

#define E820MAX 128
#define E820_X_MAX E820MAX
#define E820_RAM 1
#define E820_RESERVED 2

struct e820map {
    uint32_t nr_map;
    struct e820entry map[E820_X_MAX];
};

#define NR_INTR_VECTORS	256

struct intr_entry {
    uint16_t offset;
    uint16_t segment;
} __attribute__((packed));

struct intr_table {
    struct intr_entry entries[NR_INTR_VECTORS];
};

uint8_t bios_intfake[] = {
    0x67, 0x66, 0x83, 0x4c, 0x24, 0x01,
    0xcf,
    0x90
};

enum BIOS { 
    BDA_START = 0x400, BDA_END = 0x4ff, 
    EBDA_START = 0x90000, EBDA_END = 0x9ffff,
    MB_BIOS_START = 0xf0000,
    //    _SYM___bios_start
    MB_BIOS_END = 0xfffff,
    VGA_RAM_START = 0xa0000, VGA_RAM_END = 0xbffff,
    VGA_ROM_START = 0xc0000, VGA_ROM_END = 0xc7fff,
    KERNEL_START = 0x100000UL,
};

#define PCI_MAX_DEVICES	0xf

static union pci_config_addr pci_dev_addr[PCI_MAX_DEVICES];
static struct pci_config_head pci_dev_head[PCI_MAX_DEVICES];
static struct mem_slot *mem_slots;
static bool opt_linux_kernel = false;

static inline unsigned char bcd(unsigned val)
{
    return ((val/10)<<4)+val%10;
}

static void *guest_to_host(uint64_t offset)
{
    struct mem_slot *slot;

    for (slot = mem_slots; slot; slot = slot->next) {
        if (offset >= slot->guest && offset < slot->guest + slot->size)
            return slot->host + (offset - slot->guest);
    }

    return NULL;
}

static void set_irq_routing(struct kvm_irq_routing *route, uint32_t gsi, 
        uint32_t type, uint32_t irqchip, uint32_t pin)
{
    route->entries[route->nr++] =
        (struct kvm_irq_routing_entry) {
            .gsi = gsi,
            .type = type,
            .u.irqchip.irqchip = irqchip,
            .u.irqchip.pin = pin,
        };
}

static struct pci_config_head *find_pci(uint32_t id)
{
    int i;
    union pci_config_addr c;
    c.val = id;

    for(i = 0; i < PCI_MAX_DEVICES; i++)
        if(pci_dev_addr[i].bus == c.bus && 
                pci_dev_addr[i].dev == c.dev && 
                pci_dev_addr[i].func == c.func) return &pci_dev_head[i];
    return NULL;
}

static void show_usage(void)
{
    printf("Usage: fail-visor [-kh] IMAGE [INITRD] [KERNEL_ARGS]\n"
            "\n"
            "  -k     IMAGE refers to a Linux kernel, enabling\n"
            "         INITRD and KERNEL_ARGS options.\n"
            "  -h     display help\n");
}

void *floppy;

static void load_floppy(const char *file_name, const struct kvm_userspace_memory_region *kvm_mm __attribute__((unused)),
        struct kvm_regs *regs, struct kvm_sregs *sregs __attribute__((unused)))
{
    int fd_fd0;
    int rc;

    if (file_name == NULL)
        err(EXIT_FAILURE, "load_floppy: no image");

    if ((fd_fd0 = open(file_name, O_RDONLY)) == -1)
        err(EXIT_FAILURE, "load_floppy: open");

    struct stat sb;

    if (fstat(fd_fd0, &sb) == -1)
        err(EXIT_FAILURE, "load_floppy: fstat");

    void *target = guest_to_host(0x7c00);

    if ((floppy = malloc(sb.st_size)) == NULL)
        err(EXIT_FAILURE, "load_floppy: malloc");

    if ((rc = read(fd_fd0, floppy, sb.st_size)) != sb.st_size) {
        if (rc == -1)
            err(EXIT_FAILURE, "load_floppy: read");
        else
            errx(EXIT_FAILURE, "load_floppy: short read");
    }

    close(fd_fd0);

    memcpy(target, floppy, 512);

    memset(regs, 0, sizeof(struct kvm_regs));

    regs->rip = 0x7c00;
    regs->rdx = 0x0;
    regs->rflags = 0x2ULL;

    sregs->cs.selector = 0;
    sregs->cs.base     = 0;
}

static void load_linux_kernel(const char *file_name, const char *initrd_file_name, 
        const char *cmdline, const struct kvm_userspace_memory_region *kvm_mm, struct kvm_regs *regs,
        struct kvm_sregs *sregs)
{
    int ret;

    if (file_name == NULL) 
        err(EXIT_FAILURE, "load_linux_kernel: no kernel specified");

    int fd_kernel;

    if ((fd_kernel = open(file_name, O_RDONLY)) == -1)
        err(EXIT_FAILURE, "load_linux_kernel: cannot open kernel %s", file_name);

    if (lseek(fd_kernel, 0, SEEK_SET) == -1) err(EXIT_FAILURE, "lseek fd_kernel");

#define BOOT_SELECTOR	0x1000
#define BOOT_RIP		0x0000
#define BOOT_SP			0x8000

    regs->rflags = 0x2ULL;
    regs->rip = BOOT_RIP + 0x268; /* why? */
    regs->rsp = BOOT_SP;
    regs->rbp = BOOT_SP;

    struct boot_params *kern_boot;
    struct boot_params boot;

    if ((ret = read(fd_kernel, &boot, sizeof(boot))) != sizeof(boot))
        err(EXIT_FAILURE, "load_linux_kernel: read fd_kernel boot");

    if (memcmp(&boot.hdr.header, "HdrS", 4))
        err(EXIT_FAILURE, "load_linux_kernel: bad magic header");

    if (!boot.hdr.setup_sects) boot.hdr.setup_sects = 4;

    if (lseek(fd_kernel, 0, SEEK_SET) == -1) err(EXIT_FAILURE, "lseek fd_kernel");

    int size = (boot.hdr.setup_sects + 1) << 9;
    void *boot_loader;

    boot_loader = guest_to_host(((uint32_t)BOOT_SELECTOR << 4) + BOOT_RIP);

    if ((ret = read(fd_kernel, boot_loader, size)) != size)
        err(EXIT_FAILURE, "read fd_kernel setup_sects");
    else
        printf("bootloader: read %#x bytes into boot_loader\n", ret);


    printf("load_linux_kernel: boot:     read %#x bytes\n", ret);
    printf("load_linux_kernel: boot.hdr: version     = %#04x\n", boot.hdr.version);
    printf("load_linux_kernel: boot.hdr: setup_sects = %#x\n", boot.hdr.setup_sects);
    printf("root_flags:       %#x\n", boot.hdr.root_flags);
    printf("syssize:          %#x\n", boot.hdr.syssize);
    printf("vid_mode:         %#x\n", boot.hdr.vid_mode);
    printf("root_dev:         %#x\n", boot.hdr.root_flags);
    printf("boot_flag:        %#x\n", boot.hdr.boot_flag);
    printf("kernel_ver:       %#x\n", boot.hdr.kernel_version);
    printf("type_of_ldr:      %#x\n", boot.hdr.type_of_loader);
    printf("loadflags:        %#x : ", boot.hdr.loadflags);
    if (boot.hdr.loadflags & (1<<0)) printf("LOADED_HIGH ");
    if (boot.hdr.loadflags & (1<<1)) printf("KASLR_FLAG ");
    if (boot.hdr.loadflags & (1<<5)) printf("QUIET_FLAG ");
    if (boot.hdr.loadflags & (1<<6)) printf("KEEP_SEGMENTS ");
    if (boot.hdr.loadflags & (1<<7)) printf("CAN_USE_HEAP ");
    printf("\n");
    printf("rd_image:         %#x\n", boot.hdr.ramdisk_image);
    printf("rd_size:          %#x\n", boot.hdr.ramdisk_size);
    printf("heap_end_ptr:     %#x\n", boot.hdr.heap_end_ptr);
    printf("ext_loader_ver:   %#x\n", boot.hdr.ext_loader_ver);
    printf("ext_loader_type:  %#x\n", boot.hdr.ext_loader_type);
    printf("cmd_line_ptr:     %#x\n", boot.hdr.cmd_line_ptr);
    printf("initrd_addr_max:  %#08x\n", boot.hdr.initrd_addr_max);
    printf("kernel_align:     %#x\n", boot.hdr.kernel_alignment);
    printf("reloc_kernel:     %#x\n", boot.hdr.relocatable_kernel);
    printf("min_alignment:    %#x\n", boot.hdr.min_alignment);
    printf("xloadflags:       %#x : ", boot.hdr.xloadflags);
    if (boot.hdr.xloadflags & (1<<0)) printf("XLF_KERNEL_64 ");
    if (boot.hdr.xloadflags & (1<<1)) printf("XLF_CAN_BE_LOADED_ABOVE_4G ");
    if (boot.hdr.xloadflags & (1<<2)) printf("XLF_EFI_HANDOVER_32 ");
    if (boot.hdr.xloadflags & (1<<3)) printf("XLF_EFI_HANDOVER_64 ");
    if (boot.hdr.xloadflags & (1<<4)) printf("XLF_EFI_KEXEC ");
    printf("\n");
    printf("cmdline_size:     %#x\n", boot.hdr.cmdline_size);
    printf("hardware_subarch: %#x\n", boot.hdr.hardware_subarch);
    printf("hw_subarch_data:  %#llx\n", boot.hdr.hardware_subarch_data);
    printf("payload_offset:   %#x\n", boot.hdr.payload_offset);
    printf("payload_length:   %#x\n", boot.hdr.payload_length);
    printf("setup_data:       %#llx\n", boot.hdr.setup_data);
    printf("pref_address:     %#llx\n", boot.hdr.pref_address);
    printf("init_size:        %#x\n", boot.hdr.init_size);
    printf("handover_offset:  %#08x\n", boot.hdr.handover_offset);
    printf("kern_info_offset: %#08x\n", boot.hdr.kernel_info_offset);

    void *kernel_start;
    kernel_start = guest_to_host(KERNEL_START);
    struct stat stat;
    if (fstat(fd_kernel, &stat) == -1)
        err(EXIT_FAILURE, "fstat fd_kernel");
    if ((ret = read(fd_kernel, kernel_start, stat.st_size)) == -1)
        err(EXIT_FAILURE, "read fd_kernel KERNEL_START");
    else
        printf("kernel_start: read %#x/%#x bytes into %p\n", 
                ret, (unsigned int)stat.st_size, kernel_start);

    kern_boot = guest_to_host(BOOT_SELECTOR << 4);
    memcpy(kern_boot, &boot, sizeof(boot));
    kern_boot->hdr.cmd_line_ptr = 0x20000;
    kern_boot->hdr.type_of_loader = 0xff;
    kern_boot->hdr.heap_end_ptr = 0xfe00;
    kern_boot->hdr.loadflags |= CAN_USE_HEAP;
    kern_boot->hdr.vid_mode = 0;

    close(fd_kernel);

    if(initrd_file_name && strlen(initrd_file_name)) {
        int fd_initrd;
        uint32_t addr;
        void *initrd_start;

        if ((fd_initrd = open(initrd_file_name, O_RDONLY)) == -1)
            err(EXIT_FAILURE, "Cannot open initrd %s", initrd_file_name);

        if (fstat(fd_initrd, &stat) == -1)
            err(EXIT_FAILURE, "fstat fd_initrd");

        addr = boot.hdr.initrd_addr_max & ~0xfffff;
        printf("BOOT: init_rd: requested = %0x\n", addr);

        addr = kvm_mm->guest_phys_addr;
        addr += kvm_mm->memory_size;
        addr -= stat.st_size;
        addr &= ~0xfffff;

        printf("BOOT: init_rd: selected = %0x\n", addr);

        initrd_start = guest_to_host(addr);
        printf("init_rd host = %p\n", initrd_start);

        if ((ret = read(fd_initrd, initrd_start, stat.st_size)) == -1)
            err(EXIT_FAILURE, "read fd_initrd %p", initrd_start);
        if (ret != stat.st_size)
            err(0, "read fd_initrd %p only read %x", initrd_start, ret);

        printf("BOOT: init_rd: read %x into %p\n",
                ret, initrd_start);

        kern_boot->hdr.ramdisk_image = addr;
        kern_boot->hdr.ramdisk_size = stat.st_size;
    }

    if(cmdline)
    {
        void *cmdline_start;
        uint32_t len = strlen(cmdline)+1;

        if (len > boot.hdr.cmdline_size)
            boot.hdr.cmdline_size = len;

        cmdline_start = guest_to_host(kern_boot->hdr.cmd_line_ptr);
        memset(cmdline_start, 0, boot.hdr.cmdline_size);
        memcpy(cmdline_start, cmdline, len-1);
        printf("BOOT: setting cmdline to: ");
        fwrite(cmdline_start, len-1, 1, stdout);
        printf("\n");
    }

    //kern_boot->hdr.vid_mode = 0xfffd;

    sregs->cs.selector = BOOT_SELECTOR;
    sregs->cs.base = (uint32_t)(sregs->cs.selector<<4);
    sregs->ss.selector = BOOT_SELECTOR;
    sregs->ss.base = (uint32_t)(sregs->ss.selector<<4);
    sregs->ds.selector = BOOT_SELECTOR;
    sregs->ds.base = (uint32_t)(sregs->ds.selector<<4);
    sregs->es.selector = BOOT_SELECTOR;
    sregs->es.base = (uint32_t)(sregs->es.selector<<4);
    sregs->fs.selector = BOOT_SELECTOR;
    sregs->fs.base = (uint32_t)(sregs->fs.selector<<4);
    sregs->gs.selector = BOOT_SELECTOR;
    sregs->gs.base = (uint32_t)(sregs->gs.selector<<4);

#undef BOOT_SELECTOR
#undef BOOT_RIP
#undef BOOT_SP
}

static void draw_screen(void)
{
    static const char *term_clear = NULL;
    if (term_clear == NULL)
        term_clear = tigetstr("clear");
    static const uint16_t *vga = NULL;
    if (vga == NULL) 
        vga = guest_to_host(0xb8000);
    if (term_clear && term_clear != (char *)-1)
        putp(term_clear);
    for (int row = 0; row < 24; row++) {
        for (int col = 0; col < 80; col++) {
            uint16_t val = vga[(row * 80) + col];
            if (isprint((val & 0xff))) {
                putchar((val & 0xff));
            } else {
                putchar(' ');
            }
        }
        putchar('\n');
    }
    usleep(2000);
}


int main(int ac, char *av[])
{
    int ret,i;
    const int kvm_caps[] = {
        KVM_CAP_COALESCED_MMIO,
        KVM_CAP_SET_TSS_ADDR,
        KVM_CAP_PIT2,
        KVM_CAP_USER_MEMORY,
        KVM_CAP_IRQ_ROUTING,
        KVM_CAP_IRQCHIP,
        KVM_CAP_HLT,
        KVM_CAP_IRQ_INJECT_STATUS,
        KVM_CAP_EXT_CPUID,
        -1
    };

    struct kvm_run *kvm_run = NULL;
    struct kvm_sregs sregs;
    uint8_t *mem;
    int kvm_fd = -1;
    int vcpufd = -1;
    int vmfd = -1;
    const struct kvm_userspace_memory_region *kvm_mm;

    if ((kvm_fd = open("/dev/kvm", O_RDWR|O_CLOEXEC)) == -1) 
        err(EXIT_FAILURE, "/dev/kvm");

    if ((ret = ioctl(kvm_fd, KVM_GET_API_VERSION, 0)) != 12)
        errx(1, "KVM_GET_API_VERSION=%d != 12", ret);

    if ((vmfd = ioctl(kvm_fd, KVM_CREATE_VM, 0)) == -1) 
        err(EXIT_FAILURE, "KVM_CREATE_VM");

    for (i=0;kvm_caps[i]!=-1;i++)
        if ((ret = ioctl(kvm_fd, KVM_CHECK_EXTENSION, kvm_caps[i])) == -1)
            errx(1, "KVM_CHECK_EXTENSION %0x", kvm_caps[i]);

    if ((ret = ioctl(vmfd, KVM_SET_TSS_ADDR, 0xfffbd000)) == -1)
        err(EXIT_FAILURE, "KVM_SET_TSS_ADDR");

    const struct kvm_pit_config kvm_pit_config = { .flags = 0, };

    if ((ret = ioctl(vmfd, KVM_CREATE_PIT2, &kvm_pit_config)) == -1)
        err(EXIT_FAILURE, "KVM_CREATE_PIT2");

    if ((ret = ioctl(vmfd, KVM_CREATE_IRQCHIP)) == -1)
        err(EXIT_FAILURE, "KVM_CREATE_IRQCHIP");

    if (!(mem_slots = malloc(sizeof(*mem_slots))))
        err(EXIT_FAILURE, "malloc mem_slots");

    if (!(mem = mmap(NULL, 512 * ONE_MB, 
                    PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, 
                    -1, 0)))
        err(EXIT_FAILURE, "mmap mem");

    madvise(mem, 512 * ONE_MB, MADV_MERGEABLE);

    mem_slots->next = NULL;
    mem_slots->host = mem;
    mem_slots->guest = 0x0;
    mem_slots->size = 512 * ONE_MB;

    const struct kvm_userspace_memory_region reg_ram[] = {
        {
            .slot = 0,
            .flags = 0,
            .guest_phys_addr = mem_slots->guest,
            .memory_size = mem_slots->size,
            .userspace_addr = (uint64_t)mem_slots->host,
        }
    };

    kvm_mm = &reg_ram[0];

    printf("slot[%0x] { guest=%0llx, size=%0llx, host=%0llx }\n",
            kvm_mm->slot,
            kvm_mm->guest_phys_addr,
            kvm_mm->memory_size,
            kvm_mm->userspace_addr);

    if ((ret = ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &reg_ram)) == -1)
        err(EXIT_FAILURE, "KVM_SET_USER_MEMORY_REGION");

    if ((vcpufd = ioctl(vmfd, KVM_CREATE_VCPU, 0)) == -1) 
        err(EXIT_FAILURE, "KVM_CREATE_VCPU");

    size_t kvm_run_size;

    if ((kvm_run_size = ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0)) == (size_t)-1 )
        err(EXIT_FAILURE, "KVM_GET_VCPU_MMAP_SIZE");

    if (kvm_run_size < sizeof(*kvm_run))
        errx(1, "KVM_GET_VCPU_MMAP_SIZE too small");

    if ((kvm_run = mmap(NULL, kvm_run_size, PROT_READ|PROT_WRITE, MAP_SHARED,
                    vcpufd, 0)) == NULL)
        err(EXIT_FAILURE, "mmap kvm_run");

    struct local_apic lapic;
    if (ioctl(vcpufd, KVM_GET_LAPIC, &lapic) == -1)
        err(EXIT_FAILURE, "KVM_GET_LAPIC");

    lapic.lvt_lint0.delivery_mode = APIC_MODE_EXTINT;
    lapic.lvt_lint1.delivery_mode = APIC_MODE_NMI;

    if (ioctl(vcpufd, KVM_SET_LAPIC, &lapic) == -1)
        err(EXIT_FAILURE, "KVM_SET_LAPIC");

    struct kvm_irq_routing *irq_routing;

    irq_routing = calloc(sizeof(*irq_routing) + 64 * sizeof(struct kvm_irq_routing_entry), 1);
    if (!irq_routing)
        err(EXIT_FAILURE, "calloc irq_routing");

#define IRQCHIP_MASTER 0
#define IRQCHIP_SLAVE 1
#define IRQCHIP_IOAPIC 2

    for (i=0;i<8;i++)
        if (i!=2)
            set_irq_routing(irq_routing, i, KVM_IRQ_ROUTING_IRQCHIP, 
                    IRQCHIP_MASTER, i);

    for (i=8;i<16;i++)
        set_irq_routing(irq_routing, i, KVM_IRQ_ROUTING_IRQCHIP, 
                IRQCHIP_SLAVE, i-8);

    for (i=0;i<24;i++)
        if (i==0)
            set_irq_routing(irq_routing, i, KVM_IRQ_ROUTING_IRQCHIP, 
                    IRQCHIP_IOAPIC, 2);
        else if (i!=2)
            set_irq_routing(irq_routing, i, KVM_IRQ_ROUTING_IRQCHIP, 
                    IRQCHIP_IOAPIC, i);

    if (ioctl(vmfd, KVM_SET_GSI_ROUTING, irq_routing) == -1)
        err(EXIT_FAILURE, "KVM_SET_GSI_ROUTING");

    struct kvm_msrs *msrs = calloc(1, 
            sizeof(*msrs) + (sizeof(struct kvm_msr_entry) * 100));
    if (!msrs)
        err(EXIT_FAILURE, "calloc msrs");

#define SET_MSR(_a,_b) (struct kvm_msr_entry) { .index = _a, .data = _b }

    i = 0;
    msrs->entries[i++] = SET_MSR(MSR_IA32_SYSENTER_CS, 0x0);
    msrs->entries[i++] = SET_MSR(MSR_IA32_SYSENTER_ESP, 0x0);
    msrs->entries[i++] = SET_MSR(MSR_IA32_SYSENTER_EIP, 0x0);
    msrs->entries[i++] = SET_MSR(MSR_STAR, 0x0);
    msrs->entries[i++] = SET_MSR(MSR_CSTAR, 0x0);
    msrs->entries[i++] = SET_MSR(MSR_KERNEL_GS_BASE, 0x0);
    msrs->entries[i++] = SET_MSR(MSR_SYSCALL_MASK, 0x0);
    msrs->entries[i++] = SET_MSR(MSR_LSTAR, 0x0);
    msrs->entries[i++] = SET_MSR(MSR_IA32_TSC, 0x0);
    msrs->entries[i++] = SET_MSR(MSR_IA32_MISC_ENABLE, 
            MSR_IA32_MISC_ENABLE_FAST_STRING);
    msrs->nmsrs = i;

#undef SET_MSR

    memset(guest_to_host(BDA_START), 0, BDA_END - BDA_START);
    memset(guest_to_host(EBDA_START), 0, EBDA_END - EBDA_START);
    memset(guest_to_host(MB_BIOS_START), 0, MB_BIOS_END - MB_BIOS_START);
    memset(guest_to_host(VGA_RAM_START), 0, VGA_RAM_END - VGA_RAM_START);
    memset(guest_to_host(VGA_ROM_START), 0, VGA_ROM_END - VGA_ROM_START);

    struct e820map *e820;
    struct e820entry *e820_entry;

    e820 = guest_to_host(EBDA_START);
    e820_entry = e820->map;
    i = 0;

#define E820(_a,_s,_t) (struct e820entry) \
    { .addr = _a, .size = _s, .type = _t }

    e820_entry[i++] = E820(0x0, EBDA_START, E820_RAM);
    e820_entry[i++] = E820(EBDA_START, VGA_RAM_START - EBDA_START, E820_RESERVED);
    e820_entry[i++] = E820(MB_BIOS_START, MB_BIOS_END - MB_BIOS_START, E820_RESERVED);
    e820_entry[i++] = E820(KERNEL_START, mem_slots->size - KERNEL_START, E820_RAM);
    e820->nr_map = i;

#undef E820

    /*
    for (i = 0; i < e820->nr_map; i++)
        printf("setup: e820_entry[%02d] = {%08lx, %08lx, %x}\n", i,
                e820_entry[i].addr,
                e820_entry[i].addr + e820_entry[i].size,
                e820_entry[i].type);
                */

    if (ioctl(vcpufd, KVM_SET_MSRS, msrs) == -1)
        err(EXIT_FAILURE, "KVM_SET_MSRS");

    {
        int opt = 0;
        while ((opt = getopt(ac, av, "kh")) != -1)
        {
            switch (opt)
            {
                case 'k': opt_linux_kernel = true ; break;
                case 'h': show_usage(); exit(EXIT_SUCCESS); break;
                default: 
usage_fail:
                          show_usage(); 
                          exit(EXIT_FAILURE); 
                          break;
            }
        }

        if (optind == ac)
            goto usage_fail;

        /* TODO: optind vs argc checks */
    }

    struct kvm_regs regs = {0};

    if ((ret = ioctl(vcpufd, KVM_GET_SREGS, &sregs)) == -1)
        err(EXIT_FAILURE, "KVM_GET_SREGS");

    if (opt_linux_kernel)
        load_linux_kernel(
                (ac - optind) > 0 ? av[optind]   : NULL,
                (ac - optind) > 1 ? av[optind+1] : NULL,
                (ac - optind) > 2 ? av[optind+2] : NULL,
                kvm_mm,
                &regs,
                &sregs
                );
    else
        load_floppy((ac - optind) > 0 ? av[optind] : NULL, kvm_mm, &regs, &sregs);

    union {
        struct __attribute__((packed)) {
            unsigned invalid_op:1;
            unsigned denormal_op:1;
            unsigned zero_divide:1;
            unsigned overflow:1;
            unsigned underflow:1;
            unsigned precision:1;
            unsigned pad0:2;
            unsigned prec_ctrl:2;
            unsigned round_ctrl:2;
            unsigned inf_ctrl:1;
            unsigned pad1:3;
        } s;
        uint16_t w;
    } fcw_val = {
        .w = 0x374
    };

    union {
        struct __attribute__((packed)) {
            unsigned invalid_op:1;
            unsigned denormal_op:1;
            unsigned zero_divide:1;
            unsigned overflow:1;
            unsigned underflow:1;
            unsigned precision:1;
            unsigned denorma_zero:1;
            unsigned invalid_op_mask:1;
            unsigned denormal_op_mask:1;
            unsigned zero_divide_mask:1;
            unsigned overflow_mask:1;
            unsigned underflow_mask:1;
            unsigned prec_mask:1;
            unsigned round_ctrl:2;
            unsigned flush_to_zero:1;
        } s;
        uint32_t w;
    } mxcsr_val = {
        .w = 0x1f80
    };

    /* See 13.6 SDM VOL 1 */
    struct kvm_fpu fpu = {
        .fcw = fcw_val.w,
        .fsw = 0,
        .mxcsr = mxcsr_val.w,
    };

    if ((ret = ioctl(vcpufd, KVM_SET_FPU, &fpu)) == -1)
        err(EXIT_FAILURE, "KVM_SET_FPU");

    if ((ret = ioctl(vcpufd, KVM_SET_SREGS, &sregs)) == -1)
        err(EXIT_FAILURE, "KVM_SET_SREGS");

    struct kvm_cpuid2 *kvm_cpuid;

    kvm_cpuid = calloc(1, 
            sizeof(*kvm_cpuid) + 100 * sizeof(struct kvm_cpuid_entry2));
    if (!kvm_cpuid) err(EXIT_FAILURE, "calloc kvm_cpuid");

    kvm_cpuid->nent = 40;
    if (ioctl(kvm_fd, KVM_GET_SUPPORTED_CPUID, kvm_cpuid) == -1)
        err(EXIT_FAILURE, "KVM_GET_SUPPORTED_CPUID");

    for (i=0; i < (int)kvm_cpuid->nent; i++)
    {
        struct kvm_cpuid_entry2 *entry = &kvm_cpuid->entries[i];

        //unsigned int sig[3];

        switch(entry->function) {
            case 0:
                //memcpy(sig, "GenuineIntel", 12);
                //entry->ebx = sig[0];
                //entry->ecx = sig[1];
                //entry->edx = sig[2];
                break;
            case 1:
                if (entry->index == 0) entry->ecx |= (1<<31);
                break;
            case 6:
                entry->ecx = entry->ecx & ~(1<<3);
                break;
            default:
                break;
        }
    }

    if (ioctl(vcpufd, KVM_SET_CPUID2, kvm_cpuid) == -1)
        err(EXIT_FAILURE, "KVM_SET_CPUID2");

    free(kvm_cpuid);

    extern void bios_rom();
    extern void bios_rom_end();

    void *bios_start;
    memcpy((bios_start = guest_to_host(MB_BIOS_START)), bios_rom, 
            bios_rom_end-bios_rom );
    printf("bios_start = %#x\n", MB_BIOS_START);
    printf("bios_end   = %#x\n", MB_BIOS_END);
    printf("bios_len   = %#x\n", MB_BIOS_END - MB_BIOS_START);

    struct intr_table irq_table;

    memset(&irq_table, 0, sizeof(irq_table));

#define REAL_SEGMENT(addr) ((addr)>>4)
#define REAL_OFFSET(addr) ((addr)&((1<<4)-1))

    for (int i=0;i<NR_INTR_VECTORS;i++) {
        switch(i) {
            case 0x15:
                irq_table.entries[i].segment = REAL_SEGMENT(MB_BIOS_START);
                irq_table.entries[i].offset = 0xF004;//(uint16_t)_SYM_bios_int15;
                break;
            default:
                irq_table.entries[i].segment = REAL_SEGMENT(MB_BIOS_START);
                irq_table.entries[i].offset = 0xF000;//(uint16_t)_SYM_bios_intfake;
                break;
        }
        /*
        if(i<0x20)
            printf("irq_0x%02x { 0x%04x:0x%08x }\n", 
                i, 
                irq_table.entries[i].segment,
                irq_table.entries[i].offset
                );
                */
    }

    void *guest_irq_table;
    memcpy(guest_irq_table = guest_to_host(0), irq_table.entries, 
            sizeof(irq_table.entries));
    printf("guest_irq_table: %#lx bytes copied to %p\n", sizeof(irq_table.entries),
            guest_irq_table);

    uint8_t *data;

#define PCI_DEVICE_ID_VIRTIO_9P 0x1009

    /*
       pci_root = new_pci_bus(PCI_VENDOR_ID_REDHAT_QUMRANET, 0, pci_max_bus_id++, NULL);
       struct pci_dev *virt9p = new_pci_dev(PCI_BASE_CLASS_NETWORK, PCI_VENDOR_ID_REDHAT_QUMRANET, 
       PCI_DEVICE_ID_VIRTIO_9P, pci_root);
       virt9p->subID = 0x0009;
       virt9p->subvendorID = PCI_VENDOR_ID_REDHAT_QUMRANET;
       virt9p->bar[0] = (0xc000 << 2)|(0x1);
       virt9p->bar[1] = (0xfebc1000 << 4);
       virt9p->bar[2] = (0xfebf0000 << 4)|(1 << 3)|(0x02<<1);
       */

    memset(pci_dev_addr, 0, sizeof(pci_dev_addr));
    for(i = 0; i < PCI_MAX_DEVICES; i ++) {
        memset(&pci_dev_head[i], 0, sizeof(struct pci_config_head));
    }

    int virtio_id = 0;
    int free_irq = 6;
    int max_pci_dev = 0;

    pci_dev_head[max_pci_dev] = 
        (struct pci_config_head) {
            .vendor = PCI_VENDOR_ID_REDHAT_QUMRANET,
            .device = PCI_DEVICE_ID_VIRTIO_9P,
            .classcode = (uint8_t)PCI_BASE_CLASS_NETWORK,
            .sub_vendor = PCI_VENDOR_ID_REDHAT_QUMRANET,
            .sub = virtio_id++,
            .int_line = free_irq++,
            .int_pin = 0x1,
            .command = PCI_COMMAND_IO|PCI_COMMAND_MEMORY,
            .status = PCI_STATUS_CAP_LIST,
            .header_type = 0x0,
            .cap_ptr = (void *)&pci_dev_head[max_pci_dev].msix_cap - (void *)&pci_dev_head[max_pci_dev],
            .bars[0] = 0xc000 | 0x1,
            .bars_size[0] = 0x400,
            .bars[1] = 0xfebc1000,
            .bars_size[1] = 0x200,
            .bars[2] = 0xfebf0000|(1<<3)|(2<<1),
            .bars_size[2] = 0x400,
        };

    pci_dev_addr[max_pci_dev] = 
        (union pci_config_addr) {
            .dev = max_pci_dev,
        };

    max_pci_dev++;

    pci_dev_head[max_pci_dev] =
        (struct pci_config_head) {
            .vendor = PCI_VENDOR_ID_REDHAT_QUMRANET,
            .device = PCI_DEVICE_ID_VIRTIO_NET,
            .classcode = (uint8_t)PCI_CLASS_NETWORK_ETHERNET,
            .sub_vendor = PCI_VENDOR_ID_REDHAT_QUMRANET,
            .sub = virtio_id++,
            .int_line = free_irq++,
            .int_pin = 0x1,
            .command = PCI_COMMAND_IO|PCI_COMMAND_MEMORY,
            .status = PCI_STATUS_CAP_LIST,
            .cap_ptr = (void *)&pci_dev_head[max_pci_dev].msix_cap - (void *)&pci_dev_head[max_pci_dev],
            .bars[0] = 0xc100 | 0x1,
            .bars_size[0] = 0x400,
            .bars[1] = 0xfebc0000,
            .bars_size[1] = 0x200,
            .bars[2] = 0xfebec000|(1<<3)|(2<<1),
            .bars_size[2] = 0x400,
        };

    pci_dev_addr[max_pci_dev] = 
        (union pci_config_addr) {
            .dev = max_pci_dev,
        };

    max_pci_dev++;

    if ((ret = ioctl(vcpufd, KVM_SET_REGS, &regs)) == -1)
        err(EXIT_FAILURE, "KVM_SET_REGS");

    ioctl(vcpufd, KVM_GET_REGS,&regs);
    printf("Initial RIP: %#llx\n", regs.rip);

    int dlab = 0;
    int offset;
    uint8_t cmos_reg = 0;
    struct tm *tm;
    time_t now;
    void *dest;
    uint8_t ser_inten = 0x0;
    uint8_t ser_lcr = SER_LCR_8;
    uint8_t ser_iir = 0x0;
    uint8_t ser_mcr = 0x0;
    uint8_t ser_lsb_div = 0x1;
    uint8_t ser_msb_div = 0x0;
    uint8_t ps2_data_prt = 0x0;
    uint8_t ps2_status_reg = 0x0;
    uint8_t ser_msr = SER_MSR_CTS;
    uint8_t ser_scratch = 0;
    //uint32_t tmp32=0;
    uint32_t *ptr32;//=&tmp32;
    union pci_config_addr pciaddr;
    uint8_t pci_forwarding_reg = 0;
    uint16_t vga_offset = 0;
    uint8_t vga_ctrl_register = 0;
    int pcireg;
    struct pci_config_head *pcidev = NULL;

    struct kvm_guest_debug kvm_guest_debug = {
        .control = KVM_GUESTDBG_ENABLE|KVM_GUESTDBG_SINGLESTEP,
    };

    if (ioctl(vcpufd, KVM_SET_GUEST_DEBUG, &kvm_guest_debug) == -1)
        warn("KVM_SET_GUEST_DEBUG");

    setupterm(NULL, STDOUT_FILENO, NULL);

    signal(SIGALRM, draw_screen);

    alarm(1);

    while (1) {
        //struct kvm_regs regs;
        ret = ioctl(vcpufd, KVM_RUN, NULL);
        if (ret == -1) {
            if (errno != EINTR)
                err(EXIT_FAILURE, "KVM_RUN");
            else
                continue;
        }
        switch (kvm_run->exit_reason) {
            case KVM_EXIT_DEBUG:
                {
                    static int count = 101;

                    if (count > 100) {
                        draw_screen();
                        count = 0;
                    }
                    /*
                       ioctl(vcpufd, KVM_GET_REGS, &regs);
                       ioctl(vcpufd, KVM_GET_SREGS, &sregs);
                       printf(
                       "RIP: %#016llx "
                       "RSP: %#016llx "
                       "CS: %#016llx.%#08x "
                       "RFLAGS: %#llx - %s%s%s%s%s%s%s"
                       "\n", 
                       regs.rip, 
                       regs.rsp, 
                       sregs.cs.base,
                       sregs.cs.limit,
                       regs.rflags,
                       (regs.rflags & (1<<0)) ? "CF " : "",
                       (regs.rflags & (1<<2)) ? "PF " : "",
                       (regs.rflags & (1<<4)) ? "AF " : "",
                       (regs.rflags & (1<<6)) ? "ZF " : "",
                       (regs.rflags & (1<<7)) ? "SF " : "",
                       (regs.rflags & (1<<8)) ? "TF " : "",
                       (regs.rflags & (1<<9)) ? "IF " : ""
                       );*/
                }
                break;
            case KVM_EXIT_HLT:
                puts("KVM_EXIT_HLT");
                return 0;
            case KVM_EXIT_IO:
                //draw_screen();
                data = (uint8_t *)kvm_run + kvm_run->io.data_offset;

                /*
                if (kvm_run->io.port < 0x3f8 || kvm_run->io.port > 0x3ff) {
                    printf("KVM_EXIT_IO %s (%#x * %#x)bytes @ %#x", 
                            kvm_run->io.direction ? "wr" : "rd",
                            kvm_run->io.size,
                            kvm_run->io.count,
                            kvm_run->io.port);
                    if(kvm_run->io.direction)
                        printf(" data[0]=%x", data[0]);
                    printf("\n");
                }*/
                switch(kvm_run->io.port) {
                    case 0x60: /* PS/2 controller Data Port */
                        if (kvm_run->io.direction) {
                            ps2_data_prt = data[0];
                            ps2_status_reg |= 2; /* input buffer full */
                        } else {
                            data[0] = ps2_data_prt;
                            ps2_status_reg &= ~1; /* output buffer empty */
                        }
                        break;
                    case 0x64: /* PS/2 controller */
                        if (kvm_run->io.direction) {
                            /* Command Register */
                            switch (data[0])
                            {
                                case 0x20: /* Read "byte 0" -> Controller Config Byte */
                                    ps2_data_prt = (1<<2)|(1<<4)|(1<<5);
                                    ps2_status_reg |= 1; /* output buffer full */
                                    break;

                            }
                        } else {
                            /* Status Register */
                            data[0] = ps2_status_reg;
                        }
                    case 0x70: /* CMOS register select */
                        cmos_reg = data[0] & 0x7f; /* 0x80 is NMI, so ignore */
                        break;
                    case 0x71: /* CM0S register data */
                        time(&now);
                        tm = gmtime(&now);
                        if(kvm_run->io.direction) {
                        } else {
                            switch (cmos_reg) {
                                case 0x00: // seconds
                                    data[0] = bcd(tm->tm_sec);
                                    break;
                                case 0x02: // minutes
                                    data[0] = bcd(tm->tm_min);
                                    break;
                                case 0x04: // hours
                                    data[0] = bcd(tm->tm_hour);
                                    break;
                                case 0x06: // weekday
                                    data[0] = bcd(tm->tm_wday+1);
                                    break;
                                case 0x07: // DoM
                                    data[0] = bcd(tm->tm_mday);
                                    break;
                                case 0x08: // month
                                    data[0] = bcd(tm->tm_mon+1);
                                    break;
                                case 0x09: // year
                                    data[0] = bcd((tm->tm_year+1900)%100);
                                    break;
                                case 0x32: // century
                                    data[0] = bcd((tm->tm_year+1900)/100);
                                    break;
                                default:
                                    break;
                            }
                        }
                        break;
                    case 0x80: /* POST information */
                        if(kvm_run->io.direction){
                            usleep(1);
                        } else {
                            data[0] = 0;
                        }
                        break;
                    case 0xf0:
                    case 0xf1:
                        break;
                    case (COM1+SER_DATA): // Data +0
                        //printf("COM1.SER_DATA\n");
                        if(!dlab) {
                            if(kvm_run->io.direction) {
                                printf("%c",data[0]);
                                fflush(stdout);
                            } else {
                                data[0] = 0x0;
                            }
                        } else {
                            if(kvm_run->io.direction) {
                                ser_lsb_div = data[0];
                            } else {
                                data[0] = ser_lsb_div;
                            }
                        }
                        break;
                    case (COM1+SER_INTEN): // IER/DLL +1
                        //printf("COM1.SER_INTEN\n");
                        if(dlab) {
                            if(kvm_run->io.direction) {
                                ser_msb_div = data[0];
                            } else {
                                data[0] = ser_msb_div;
                            }
                        } else {
                            if(kvm_run->io.direction) {
                                ser_inten = data[0];
                            } else {
                                data[0] = ser_inten;
                            }
                        }
                        break;
                    case (COM1+SER_FCR): // IIR/FCR +2
                        printf("COM1.SER_FCR\n");
                        if(kvm_run->io.direction) {
                            // we're an 8250 so no FCR
                        } else {
                            data[0] = ser_iir;
                        }
                        break;
                    case (COM1+SER_LCR): // LCR +3
                        printf("COM1.SER_LCR\n");
                        if(kvm_run->io.direction) {
                            if(data[0] & SER_LCR_DLAB) dlab = 1;
                            else dlab = 0;
                            ser_lcr = data[0];
                        } else {
                            data[0] = ser_lcr;
                        }
                        break;
                    case (COM1+SER_MCR): // MCR +4
                        printf("COM1.SER_MCR\n");
                        if(kvm_run->io.direction) {
                            ser_mcr = data[0];
                        } else {
                            data[0] = ser_mcr;
                        }
                        break;
                    case (COM1+SER_LSR): // LSR +5
                        //printf("COM1.SER_LSR\n");
                        if(kvm_run->io.direction) {
                        } else {
                            data[0] = SER_LSR_THR|SER_LSR_THR_IDLE;
                        }
                        break;
                    case (COM1+SER_MSR): // MSR +6
                        printf("COM1.SER_MSR\n");
                        if(kvm_run->io.direction) {
                        } else {
                            data[0] = ser_msr;
                        }
                        break;
                    case (COM1+SER_SCRATCH):
                        printf("COM1.SER_SCRATCH\n");
                        if(kvm_run->io.direction) {
                            ser_scratch = data[0];
                        } else {
                            data[0] = ser_scratch;
                        }
                        break;
                    case 0xcfb: // PCI conf1
                        break;
                    case 0xcf8: // PCI ADDRESS
                        //printf("PCI ADDRESS: ");
                        if(kvm_run->io.direction) {
                            pciaddr.val = *(uint32_t*)data;
                            //printf("%#08x ", pciaddr.val);
                            pcidev = find_pci(pciaddr.val);
                            if(pcidev){
                                /*
                                printf("pci-addr: %x [%x.%x.%x] ", 
                                        pciaddr.val,
                                        pciaddr.bus, pciaddr.dev, pciaddr.func);
                                printf("pci-dev: %p\n", pcidev);*/
                            }
                        } else {
                        }
                        //printf("\n");
                        break;
                    case 0xcfa: // PCI Forwarding Register
                        if(kvm_run->io.direction) {
                            pci_forwarding_reg = data[0];
                        } else {
                            data[0] = pci_forwarding_reg;
                        }
                        break;
                    case 0xcfc:
                    case 0xcfd:
                    case 0xcfe:
                    case 0xcff:
                        //draw_screen();
#define PCI_REG_BAR(x) (((x)-0x10)/4)
                        ptr32 = (uint32_t *)data;
                        pcireg = pciaddr.reg<<2;
                        offset = kvm_run->io.port - 0xcfc;
                        printf("pci: %s reg=%x len=%x\n", 
                                kvm_run->io.direction ? "wr" : "rd",
                                pcireg,
                                kvm_run->io.size);
                        if(kvm_run->io.direction) {
                            break;
                            if(pcidev) {
                                if(pcireg >= 0x10 && pcireg < 0x28) {
                                    //									tmp32 = (pcireg - 0x10)/4;
                                    /*
                                       printf("pci-conf: WRITE bar=%x\n",tmp32);
                                       printf("pci-conf: WRITE TO=%02x LEN=%01x PORT=%x\n",
                                       pciaddr.reg<<2,
                                       kvm_run->io.size,
                                       kvm_run->io.port);
                                       printf("pci-conf: DATA=%08x\n", *ptr32);
                                       */
                                    pcidev->bars[PCI_REG_BAR(pcireg)] = *ptr32;
                                }
                            }
                        } else {
                            int cnt = kvm_run->io.count * kvm_run->io.size;
                            while(cnt)
                                data[cnt--] = 0;
                            break;
                            if(pcidev) {
                                dest = pcidev;
                                dest += pcireg;
                                dest += offset;

                                //printf("pci-head: xfer FROM=%p{%02x.%02x} TO=%p LEN=%01x PORT=%x\n", 
                                  //      dest,
                                  //      pcireg, 
                                  //      offset, 
                                  //      data,
                                  //      kvm_run->io.size,
                                  //      kvm_run->io.port);

                                if(pcireg >= 0x10 && pcireg < 0x28 && pcidev->bars[PCI_REG_BAR(pcireg)] == 0xffffffff) {
                                    dest = &pcidev->bars_size[PCI_REG_BAR(pcireg)];
                                }
                                memcpy(data, dest, kvm_run->io.size);
                                if(pcireg >= 0x10 && pcireg < 0x28 && pcidev->bars[PCI_REG_BAR(pcireg)] == 0xffffffff) {
                                    *data = (~(*data)) - 1;
                                }
                                //								printf("pci-head: xfer=");
                                //								
                                //								for(i=0;i<kvm_run->io.size;i++)
                                //									printf("%02x ", data[i]);
                                //								printf("\n");
                            } else {
                                switch(pciaddr.reg) {
                                    case 0x00: *ptr32 = 0x0000ffff; break;
                                    default: *data = 0x0; break;
                                }
                            }
                        }
                        break;
                    case 0x3ce: /* Graphics Address Register */
                        //printf("VGA Address Register: index=%x\n", data[0]);
                        break;
                    case 0x3cf: /* Graphics Data Register */
                        //printf("VGA Address Register: value=%x\n", data[0]);
                        break;
                    case 0x3d4: /* VGA Control Register */
                        //printf("VGA_CTRL_REGISTER: ");
                        if (kvm_run->io.direction == KVM_EXIT_IO_OUT) {
                            //printf("WRITE ");
                            vga_ctrl_register = data[0];
                            if (data[0] == 0x0f /* VGA_OFFSET_LOW */) {
                                //printf("VGA_OFFSET_LOW");
                            } else if (data[0] == 0x0e /* VGA_OFFSET_HIGH */) {
                                //printf("VGA_OFFSET_HIGH");
                            } else {
                                //printf("??? [%02x]", data[0]);
                            }
                        } else {
                            //printf("READ ");
                        }
                        //printf("\n");
                        break;
                    case 0x3d5:
                        //printf("VGA_DATA_REGISTER: %s %02x\n", kvm_run->io.direction == KVM_EXIT_IO_OUT ? "OUT": "IN", data[0]);
                        if (kvm_run->io.direction == KVM_EXIT_IO_OUT) {
                            if (vga_ctrl_register == 0x0f /* VGA_OFFSET_LOW */)
                                vga_offset = (vga_offset & 0xff00) | data[0];
                            else if (vga_ctrl_register == 0x0e)
                                vga_offset = (vga_offset & 0x00ff) | (((uint16_t)data[0]) << 8);
                        }
                        break;
                    case 0x3ef:
                    case 0x3e9:
                    case 0x3e8:
                    case 0x3eb:
                    case 0x3ea:
                    case 0x3ec:
                        data[0] = 0;
                        break;
                    case 0x2ff:
                    case 0x2fa:
                    case 0x2f8:
                    case 0x2f9:
                    case 0x2fb:
                    case 0x2fc:
                        data[0] = 0;
                        break;
                    case 0x2ef:
                    case 0x2ea:
                    case 0x2e8:
                    case 0x2ee:
                    case 0x2e9:
                    case 0x2eb:
                    case 0x2ec:
                        data[0] = 0;
                        break;
                    default:
                        if(kvm_run->io.port >= 0xc000 &&
                                kvm_run->io.port <= 0xcf0a) {
                            data[0] = 0;
                            data[1] = 0;
                            break;
                        } else if(kvm_run->io.port != 0x3fd && 
                                kvm_run->io.port != 0x3f8 &&
                                kvm_run->io.port != 0x3f9) {
                            /*
                            printf("KVM_EXIT_IO: "
                                    "io.out?=%#x "
                                    "io.size=%#x "
                                    "io.port=%#x "
                                    "io.count=%#x "
                                    "io.data=%#x\n",
                                    kvm_run->io.direction,
                                    kvm_run->io.size,
                                    kvm_run->io.port,
                                    kvm_run->io.count,
                                    data[0]
                                  );*/
                        }
                        break;
                }
                break;
            case KVM_EXIT_MMIO:
                printf("KVM_EXIT_MMIO: io.phys_addr=%#llx, "
                        "io.len=%#x, is_write=%#x\n",
                        kvm_run->mmio.phys_addr,
                        kvm_run->mmio.len,
                        kvm_run->mmio.is_write);
                exit(EXIT_FAILURE);
                break;
            case KVM_EXIT_FAIL_ENTRY:
                errx(EXIT_FAILURE, "KVM_EXIT_FAIL_ENTRY: "
                        "hardware_entry_failure_reason = %#x",
                        (unsigned int)kvm_run->fail_entry.hardware_entry_failure_reason);
            case KVM_EXIT_INTERNAL_ERROR:
                errx(EXIT_FAILURE, "KVM_EXIT_INTERNAL_ERROR: suberror = %#x", 
                        kvm_run->internal.suberror);
            default:
                warnx("KVM_EXIT_%#x", kvm_run->exit_reason);
        }
    }
}
