#define EFLAGS_CF (1<<0)

#define __ALIGN .p2align 4, 0x90

#define ENTRY(name) \
__ALIGN;\
.globl name;\
name:

#define GLOBAL(name) \
.globl name; \
name:

#define ENTRY_END(name) GLOBAL(name##_end)
