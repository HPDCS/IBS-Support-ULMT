#include <linux/types.h>
#include <linux/cpu.h>
#include <linux/smp.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/interrupt.h>
#include <linux/kprobes.h>
#include <linux/device.h>
#include <linux/delay.h>
#include <linux/version.h>
#include <asm/irq_regs.h>
#include <asm/irq.h>
#include <asm/desc.h>
#include <asm/apic.h>
#include <asm/apicdef.h>
#include <asm/uaccess.h>

#include "ibs-api.h"
#include "ibs-vtpmo.h"
#include "ibs-disassemble.h"


#define IBS_OP                      0
#define IBS_FETCH                   1


/********************************************************************************/
/*                           CPUID REGISTERS & MASKS                            */
/*                             (check IBS support)                              */

#define CPUID_AMD_FAM10h            0x10
#define CPUID_AMD_FAM17h            0x17

#define FAM17H_MSR_WA_1				0xc0011020
#define FAM17H_MSR_WA_1_BITS		0x40000000000000ULL
#define FAM17H_MSR_WA_2				0xc0011029
#define FAM17H_MSR_WA_2_BITS		0x80000ULL
#define FAM17H_MSR_WA_3				0xc0010296
#define FAM17H_MSR_WA_3_BITS		0x404040ULL
#define CPUID_EXT_FEATURES			0xc0011005

#ifndef topology_sibling_cpumask
#define topology_sibling_cpumask(cpu)	(per_cpu(cpu_sibling_map, cpu))
#endif

#define CPUID_Fn8000_001B_EAX       cpuid_eax(0x8000001B)
#define  IBS_CPUID_IBSFFV           1ULL
#define  IBS_CPUID_FetchSam         (1ULL<<1)
#define  IBS_CPUID_OpSam            (1ULL<<2)
#define  IBS_CPUID_RdWrOpCnt        (1ULL<<3)
#define  IBS_CPUID_OpCnt            (1ULL<<4)
#define  IBS_CPUID_BrnTrgt          (1ULL<<5)

#define CPUID_Fn8000_0001_ECX       cpuid_ecx(0x80000001)
#define  IBS_SUPPORT_EXIST          (1ULL<<10)


/********************************************************************************/
/*                            IBS REGISTERS & MASKS                             */
/*                  (enable/disable/configure MSR registers)                    */

#define MSR_IBS_CONTROL             0xc001103a
#define  IBS_LVT_OFFSET_VAL         (1ULL<<8)
#define  IBS_LVT_OFFSET             0xfULL

#define MSR_IBS_FETCH_CTL           0xc0011030
#define  IBS_FETCH_CNT_CTL          (0xffffULL<<16)
#define  IBS_FETCH_VAL              (1ULL<<49)
#define  IBS_FETCH_EN               (1ULL<<48)
#define  IBS_FETCH_CNT_MAX          0xffffULL

#define MSR_IBS_OP_CTL              0xc0011033
#define  IBS_OP_CNT_CTL             (1ULL << 19)             /* When 1, count dispatched. When 0, count clock cycles. */
#define  IBS_OP_VAL                 (1ULL << 18)             /* Set-by-HW. When 1, execution data available. Stop counting until SW clear. */
#define  IBS_OP_EN                  (1ULL << 17)             /* When 1, execution sampling enables. */
#define  IBS_OP_CNT_MAX             0xfffffULL               /* 20 Bit. 1048576 increments. */
#define  IBS_OP_MAX_CNT_MAX         (IBS_OP_CNT_MAX >> 4)    /* Bits 15:0 are programmed. The 4 LSb are always zero. */
#define  IBS_OP_CUR_CNT_MAX         (IBS_OP_CNT_MAX)         /* Bits 51:32 are programmed. */

#define DEFAULT_MIN_CNT             0xd000UL
#define DEFAULT_MAX_CNT             0xfffffUL


int ibs_open(struct inode *, struct file *);
int ibs_release(struct inode *, struct file *);
long ibs_ioctl(struct file *, unsigned int, unsigned long);

void handle_ibs_irq(struct pt_regs *regs);


/********************************************************************************/
/*                                 IBS DEVICES                                  */
/*                                  (macros)                                    */

#define IBS_MINOR(flavor, cpu)      ((cpu << 1) | flavor)
#define IBS_CPU(minor)              (minor >> 1)
#define IBS_FLAVOR(minor)           (minor & 1)


/********************************************************************************/
/*             APIC CONFIGURATION AND IBS REGISTERS INITIALIZATION              */
/*                          (variables and functions)                           */

static unsigned ibs_vector = NR_VECTORS-1;

static int ibs_op_supported;
static int ibs_fetch_supported;

static int workaround_fam10h_err_420 = 0;
static int workaround_fam17h_zn = 0;

static int workarounds_started = 0;

static int* pcpu_num_devices_enabled;
static spinlock_t * pcpu_workaround_lock;

static u64 fam17h_old_1 = 0;
static u64 fam17h_old_2 = 0;
static u64 fam17h_old_3 = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
static unsigned int old_call_operand = 0x0;
static unsigned int new_call_operand = 0x0;
static unsigned int *call_operand_address = NULL;
#else
static gate_desc old_ibs;


extern void ibs_entry(void);
asm(
"    .globl ibs_entry\n"
"ibs_entry:\n"
"    cld\n"
"    testq $3,8(%rsp)\n"
"    jz    1f\n"
"    swapgs\n"
"1:\n"
"    pushq $0\n" /* error code */
"    pushq %rdi\n"
"    pushq %rsi\n"
"    pushq %rdx\n"
"    pushq %rcx\n"
"    pushq %rax\n"
"    pushq %r8\n"
"    pushq %r9\n"
"    pushq %r10\n"
"    pushq %r11\n"
"    pushq %rbx\n"
"    pushq %rbp\n"
"    pushq %r12\n"
"    pushq %r13\n"
"    pushq %r14\n"
"    pushq %r15\n"
"    mov %rsp, %rdi\n"
"1:  call handle_ibs_irq\n"
"    popq %r15\n"
"    popq %r14\n"
"    popq %r13\n"
"    popq %r12\n"
"    popq %rbp\n"
"    popq %rbx\n"
"    popq %r11\n"
"    popq %r10\n"
"    popq %r9\n"
"    popq %r8\n"
"    popq %rax\n"
"    popq %rcx\n"
"    popq %rdx\n"
"    popq %rsi\n"
"    popq %rdi\n"
"    addq $8,%rsp\n"
"    testq $3,8(%rsp)\n"
"    jz 2f\n"
"    swapgs\n"
"2:\n"
"    iretq"
);
#endif


static inline u64 custom_rdmsrl_on_cpu(unsigned int cpu, u32 msr_no)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0)
	u64 ret_val;
	rdmsrl_on_cpu(cpu, msr_no, &ret_val);
	return ret_val;
#else
	u32 lo, hi;
	rdmsr_on_cpu(cpu, msr_no, &lo, &hi);
	return (u64)lo | ((u64)hi << 32ULL);
#endif
}

static inline void custom_wrmsrl_on_cpu(unsigned int cpu, u32 msr_no, u64 val)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0)
	wrmsrl_on_cpu(cpu, msr_no, val);
#else
	u32 lo, hi;
	lo = val & 0xffffffff;
	hi = val >> 32;
	wrmsr_on_cpu(cpu, msr_no, lo, hi);
#endif
}

static void init_fam17h_zn_workaround(void)
{
	rdmsrl(FAM17H_MSR_WA_1, fam17h_old_1);
	rdmsrl(FAM17H_MSR_WA_2, fam17h_old_2);
	rdmsrl(FAM17H_MSR_WA_3, fam17h_old_3);
}

static int init_workaround_structs(void)
{
	struct cpuinfo_x86 *c;

	if (workarounds_started)
		return 0;

	c = &boot_cpu_data;

	if (c->x86_vendor == X86_VENDOR_AMD && c->x86 == CPUID_AMD_FAM17h && c->x86_model == 0x1)
	{
		init_fam17h_zn_workaround();
	}

	pcpu_num_devices_enabled = alloc_percpu(int);
	if (!pcpu_num_devices_enabled)
		return -1;

	pcpu_workaround_lock = alloc_percpu(spinlock_t);
	if (!pcpu_workaround_lock)
	{
		free_percpu(pcpu_num_devices_enabled);
		return -1;
	}

	workarounds_started = 1;

	return 0;
}

static void free_workaround_structs(void)
{
	if (workarounds_started)
	{
		free_percpu(pcpu_num_devices_enabled);
		free_percpu(pcpu_workaround_lock);
	}
}

static void init_workaround_initialize(void)
{
	unsigned int cpu;

	if (!workarounds_started)
		return;

	cpu = 0;

	for_each_possible_cpu(cpu)
	{
		spinlock_t *workaround_lock;
		int *num_devs = per_cpu_ptr(pcpu_num_devices_enabled, cpu);

		*num_devs = 0;

		workaround_lock = per_cpu_ptr(pcpu_workaround_lock, cpu);

		spin_lock_init(workaround_lock);
	}
}

static void start_fam17h_zn_static_workaround(const int cpu)
{
	u64 cur;
	int cpu_to_offline = -1, cpu_to_online = -1;

	if (!workarounds_started)
	{
		init_workaround_structs();
		init_workaround_initialize();
	}

	cur = custom_rdmsrl_on_cpu(cpu, CPUID_EXT_FEATURES);
	cur |= (1ULL << 42);
	custom_wrmsrl_on_cpu(cpu, CPUID_EXT_FEATURES, cur);

	cur = custom_rdmsrl_on_cpu(cpu, FAM17H_MSR_WA_2);

	if (cur & FAM17H_MSR_WA_2_BITS)
		return;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
	for_each_cpu(cpu_to_offline, topology_sibling_cpumask(cpu))
#else
	for_each_cpu_mask(cpu_to_offline, topology_core_siblings(cpu))
#endif
	{
		if (cpu_to_offline != cpu)
		{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
			remove_cpu(cpu_to_offline);
#else
			cpu_down(cpu_to_offline);
#endif
			cpu_to_online = cpu_to_offline;
		}
	}

	custom_wrmsrl_on_cpu(cpu, FAM17H_MSR_WA_2, (cur | FAM17H_MSR_WA_2_BITS));
	if (cpu_to_online != -1)
	{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
		add_cpu(cpu_to_online);
#else
		cpu_up(cpu_to_online);
#endif
	}
}

static void stop_fam17h_zn_static_workaround(const int cpu)
{
	u64 cur;
	unsigned int cpu_to_use;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
	cpu_to_use = cpumask_first(topology_sibling_cpumask(cpu));
#else
	cpu_to_use = first_cpu(topology_core_siblings(cpu));
#endif

	if (cpu_to_use == cpu)
	{
		cur = custom_rdmsrl_on_cpu(cpu_to_use, FAM17H_MSR_WA_2);
		cur = fam17h_old_2 | (cur & ~FAM17H_MSR_WA_2_BITS);
		custom_wrmsrl_on_cpu(cpu, FAM17H_MSR_WA_2, cur);
	}

	cur = custom_rdmsrl_on_cpu(cpu, CPUID_EXT_FEATURES);
	cur &= ~(1ULL << 42);
	custom_wrmsrl_on_cpu(cpu, CPUID_EXT_FEATURES, cur);
}

int check_for_ibs_support(void)
{
	struct cpuinfo_x86 *c;
	unsigned int feature_id;

	c = &boot_cpu_data;

	if (c->x86_vendor != X86_VENDOR_AMD)
	{
		pr_err("IBS: required AMD processor.\n");
		return -EINVAL;
	}

	feature_id = CPUID_Fn8000_0001_ECX;

	if (c->x86 == CPUID_AMD_FAM10h)
	{
		if (!(feature_id & IBS_SUPPORT_EXIST))
		{
			pr_err("IBS: CPUID_Fn8000_0001 indicates no IBS support\n");
			return -EINVAL;	
		}
		else
		{
			pr_info("IBS: Startup enabling workaround for Family 10h CPUs\n");
			workaround_fam10h_err_420 = 1;
		}
	}
	else if (c->x86 == CPUID_AMD_FAM17h)
	{
		if (!(feature_id & IBS_SUPPORT_EXIST))
		{
			if ((c->x86_model >= 0x0 && c->x86_model <= 0x2f) || (c->x86_model >= 0x50 && c->x86_model < 0x5f))
			{
				unsigned int cpu = 0;

				pr_info("IBS: Startup enabling workaround for Family 17h first-gen CPUs\n");
				workaround_fam17h_zn = 1;

				for_each_online_cpu(cpu)
				{
					start_fam17h_zn_static_workaround(cpu);
				}
			}
			else
			{
				pr_err("IBS: CPUID_Fn8000_0001 indicates no IBS support\n");
				return -EINVAL;	
			}
		}
	}
	else
	{
		pr_err("IBS: this module is designed only for Fam 10h and 17h\n");
		return -EINVAL;
	}

	feature_id = CPUID_Fn8000_001B_EAX;

	if (!(feature_id & IBS_CPUID_IBSFFV))
	{
		pr_err("IBS: CPUID_Fn8000_001B indicates no IBS support\n");
		return -EINVAL;
	}

	ibs_fetch_supported = feature_id & IBS_CPUID_FetchSam;
	ibs_op_supported = feature_id & IBS_CPUID_OpSam;
	ibs_op_supported |= feature_id & IBS_CPUID_RdWrOpCnt;
	ibs_op_supported |= feature_id & IBS_CPUID_OpCnt;

	if (!ibs_fetch_supported)
	{
		pr_err("IBS: CPUID_Fn800_001B says no Op support\n");
		return -EINVAL;
	}

	if (!ibs_op_supported)
	{
		pr_err("IBS: CPUID_Fn800_001B says no Fetch support\n");
		return -EINVAL;
	}
	
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
static int select_vector_by_inspect_push_operand(unsigned char *byte)
{
	unsigned int opcode;
	unsigned int operand;

	opcode = ((unsigned int) byte[0]) & 0xff;

	if (opcode == 0x68) /* push imm16/imm32 */
	{
		operand = ~(((unsigned int) byte[1]) | (((unsigned int) byte[2]) << 8) |
			(((unsigned int) byte[3]) << 16) | (((unsigned int) byte[4]) << 24));
		if (operand == 0xFF) /* SPURIOUS_APIC_VECTOR */
			return 1;
	}
	else if (opcode == 0x6A) /* push imm8 */
	{
		operand = ~(((unsigned int) byte[1]) & 0xff);
		if (operand == 0xFF) /* SPURIOUS_APIC_VECTOR */
			return 1;
	}

	return 0;
}

# if LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,2)
static long select_vector_by_counting_jmp_addresses(unsigned char *byte)
{
	unsigned int opcode;
	unsigned int operand;

	opcode = ((unsigned int) byte[0]) & 0xff;

	if (opcode == 0x68) /* push imm16/imm32 */
	{
		opcode = ((unsigned int) byte[5]) & 0xff;

		if (opcode == 0xE9) /* jmp imm16/imm32 */
		{
			operand = ((unsigned int) byte[6]) | (((unsigned int) byte[7]) << 8) |
				(((unsigned int) byte[8]) << 16) | (((unsigned int) byte[9]) << 24);
			return ((long) &byte[10]) + (long) operand; /* RIP + operand */
		}
		else if (opcode == 0xEB) /* jmp imm8 */
		{
			operand = ((unsigned int) byte[6]) & 0xff;
			return ((long) &byte[7]) + (long) operand; /* RIP + operand */
		}
	}
	else if (opcode == 0x6A) /* push imm8 */
	{
		opcode = ((unsigned int) byte[2]) & 0xff;

		if (opcode == 0xE9) /* jmp imm16/imm32 */
		{
			operand = ((unsigned int) byte[3]) | (((unsigned int) byte[4]) << 8) |
				(((unsigned int) byte[5]) << 16) | (((unsigned int) byte[6]) << 24);
			return ((long) &byte[7]) + (long) operand; /* RIP + operand */
		}
		else if (opcode == 0xEB) /* jmp imm8 */
		{
			operand = ((unsigned int) byte[3]) & 0xff;
			return ((long) &byte[4]) + (long) operand; /* RIP + operand */
		}
	}

	return 0;
}
# endif
#endif

static int acquire_free_vector(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
	struct desc_ptr idtr;
	gate_desc *gate_ptr;

# if LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,2)
	int i;
	long addr;
	unsigned int max_count;
	long address[NR_VECTORS-FIRST_SYSTEM_VECTOR+1] = { 0 };
	unsigned int vector[NR_VECTORS-FIRST_SYSTEM_VECTOR+1] = { 0 };
	unsigned int counter[NR_VECTORS-FIRST_SYSTEM_VECTOR+1] = { 0 };
# endif

	store_idt(&idtr);

	while (1)
	{
		if (ibs_vector < FIRST_SYSTEM_VECTOR)
		{
# if LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,2)
			for (max_count=1, i=0; i<NR_VECTORS-FIRST_SYSTEM_VECTOR+1; i++)
			{
				if (counter[i] > max_count)
				{
					ibs_vector = vector[i];
					max_count = counter[i];
				}
			}

			if (max_count > 1)
				break;
# endif
			pr_err("IBS: no free IDT vector is found.\n");
			return -ENODATA;
		}

		gate_ptr = (gate_desc *) (idtr.address + ibs_vector * sizeof(gate_desc));

		if (select_vector_by_inspect_push_operand((unsigned char *) (((unsigned long) gate_ptr->offset_low) |
																		((unsigned long) gate_ptr->offset_middle << 16) |
																			((unsigned long) gate_ptr->offset_high << 32))))
			break;

# if LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,2)
		addr = select_vector_by_counting_jmp_addresses((unsigned char *) (((unsigned long) gate_ptr->offset_low) |
																				((unsigned long) gate_ptr->offset_middle << 16) |
																					((unsigned long) gate_ptr->offset_high << 32)));

		for (i=0; i<NR_VECTORS-FIRST_SYSTEM_VECTOR+1; i++)
		{
			if (address[i] == 0 || address[i] == addr)
			{
				counter[i] += 1;
				if (address[i] == 0)
				{
					vector[i] = ibs_vector;
					address[i] = addr;
				}
				break;
			}
		}
# endif

		ibs_vector--;
	}
#else
	while (test_bit(ibs_vector, used_vectors))
	{
		if (ibs_vector == 0x40)
		{
			pr_err("IBS: no free IDT vector is found.\n");
			return -1;
		}
		ibs_vector--;
	}
	set_bit(ibs_vector, used_vectors);
#endif

	pr_info("IBS: IDT vector 0x%x acquired.\n", ibs_vector);

	return 0;
}

static unsigned long _force_order_;

static inline unsigned long _read_cr0(void)
{
	unsigned long val;
	asm volatile("mov %%cr0, %0" : "=r" (val), "=m" (_force_order_));
	return val;
}

static inline void _write_cr0(unsigned long val)
{
	asm volatile("mov %0, %%cr0" : : "r" (val), "m" (_force_order_));
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
static inline long get_address_entry_idt(unsigned int vector)
{
    struct desc_ptr idtr;
    gate_desc *gate_ptr;

    store_idt(&idtr);

    gate_ptr = (gate_desc *) (idtr.address + vector * sizeof(gate_desc));

    return (long) ((unsigned long) (gate_ptr->offset_low) |
    				((unsigned long) (gate_ptr->offset_middle) << 16) |
    					((unsigned long) (gate_ptr->offset_high) << 32));
}

static inline int get_address_from_symbol(unsigned long *address, const char *symbol)
{
    int ret;
    struct kprobe kp = {};

    kp.symbol_name = symbol;

    ret = register_kprobe(&kp);

    if (ret < 0)
    {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,7)
        pr_info("[IPI Module INFO] - Symbol %s not found. Returned value %d.\n", symbol, ret);
        return ret;
#else
# ifdef CONFIG_KALLSYMS
        unsigned long addr;
        if ((addr = kallsyms_lookup_name(symbol)) == 0UL)
        {
# endif
            pr_err("[IPI Module INFO] - Symbol %s not found. Returned value %d.\n", symbol, ret);
            return ret;
# ifdef CONFIG_KALLSYMS
        }
        else
        {
            *address = addr;
        }
# endif
#endif
    }
    else
    {
        *address = (unsigned long) kp.addr;
        unregister_kprobe(&kp);
    }

    pr_info("[IPI Module INFO] - Symbol %s found at 0x%lx.\n", symbol, *address);

    return 0;
}
#endif

static unsigned long replace_call_address_through_binary_inspection(unsigned long entry_address, unsigned long spurious_address)
{
    unsigned int b;
    unsigned int count;
    unsigned int level = 0;
    unsigned int level_0_call_count = 0;
    
    unsigned long cr0;

    unsigned char disassembled[BUFFER_SIZE];

    unsigned char *byte;
    unsigned long level_address[MAX_LEVEL + 1] = { 0UL };

    unsigned long address = 0UL;

    if (spurious_address)
    	pr_info("[IPI Module INFO] - Try to find the target CALL instruction with the knowledge obtained from source code analysis.\n");

    if (sys_vtpmo(entry_address) != NO_MAP)
    {
        level_address[level] = entry_address;

follow_the_flow:
        byte = (unsigned char *) level_address[level];

        for (b=0, count=0; b<SEQUENCE_MAX_BYTES; b+=count)
        {
            count = disassemble(&byte[b], SEQUENCE_MAX_BYTES - b, ((unsigned int) (((unsigned long) &byte[b]) & 0xffffffffUL)), disassembled);

            if (byte[b] == 0xC2 || byte[b] == 0xC3 || byte[b] == 0xCA || byte[b] == 0xCB || byte[b] == 0xCF) // RET
            {
                if (level)
                {
                    level_address[level--] = 0UL;
                    goto follow_the_flow;
                }
                else
                	break;
            }
            else if (byte[b] == 0xE9 || byte[b] == 0xEA || byte[b] == 0xEB) // JMP
            {
                long jmp_address;

                if ((jmp_address = resolve_jmp_address(&byte[b], count)) == 0)
                	break;

                if (sys_vtpmo(jmp_address) != NO_MAP)
                {
                    level_address[level] = *((unsigned long *) &jmp_address);
                    goto follow_the_flow;
                }
                else
                    break;
            }
            else if (byte[b] == 0x9A || byte[b] == 0xE8) // CALL
            {
                long call_address;

                if ((call_address = resolve_call_address(&byte[b], count)) == 0)
                	break;

                if (spurious_address)
                {
                	/* Either symbols have been exported or the address
                	   has been recovered via the kprobe service ... in
                	   any case we know which is the operand to replace
                	   within spurious irq-entry routine. */
                	if (call_address == spurious_address)
                	{
                		old_call_operand = get_call_operand(&byte[b], count);
						new_call_operand = (unsigned int) ((long) handle_ipi_irq - ((long) &byte[b+count]));
						call_operand_address = (unsigned int *) &byte[b+1];

						cr0 = _read_cr0();
						_write_cr0(cr0 & ~X86_CR0_WP);


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
						arch_cmpxchg(call_operand_address, old_call_operand, new_call_operand);
#else
						cmpxchg(call_operand_address, old_call_operand, new_call_operand);
#endif

						_write_cr0(cr0);

						pr_info("[IPI Module INFO] - Address 0x%lx of the spurious interrupt handler is called at 0x%lx.\n", spurious_address, (long) &byte[b]);

                        address = call_address;
                        break;
                	}
                }
                else if (level == 0)
                {
                    /* Symbols may also be non-exported, nor readable
                       by kallsysm_lookup, but the entry_64.S source code
                       doesn's lie ... the second CALL instruction encountered
                       within the spurious irq-entry routine gives control to
                       the spurious interrupt handler. */
                    if ((++level_0_call_count) == 2)
                    {
                    	old_call_operand = get_call_operand(&byte[b], count);
						new_call_operand = (unsigned int) ((long) handle_ipi_irq - ((long) &byte[b+count]));
						call_operand_address = (unsigned int *) &byte[b+1];

						cr0 = _read_cr0();
						_write_cr0(cr0 & ~X86_CR0_WP);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
						arch_cmpxchg(call_operand_address, old_call_operand, new_call_operand);
#else
						cmpxchg(call_operand_address, old_call_operand, new_call_operand);
#endif

						_write_cr0(cr0);

						pr_info("[IPI Module INFO] - Address of the spurious interrupt handler (unknown symbol) is called at 0x%lx.\n", (long) &byte[b]);

                        address = call_address;
                        break;
                    }
                }

                if (call_address)
                {
                    if (sys_vtpmo(call_address) != NO_MAP)
                    {
                        if (level < MAX_LEVEL)
                        {
                            level_address[level++] = (unsigned long) &byte[b + count];
                            level_address[level] = *((unsigned long *) &call_address);
                            goto follow_the_flow;
                        }
                    }
                }
            }
        }
    }

    return address;
}

static int setup_idt_entry(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
	unsigned long entry_spurious_address;
	unsigned long smp_spurious_address;

	if (!(entry_spurious_address = get_address_entry_idt(ibs_vector)))
		return -ENODATA;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
	if (get_address_from_symbol(&smp_spurious_address, "sysvec_spurious_apic_interrupt"))
#else
	if (get_address_from_symbol(&smp_spurious_address, "smp_spurious_interrupt"))
#endif
	{
// #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,7)
		if (replace_call_address_through_binary_inspection(entry_spurious_address, 0UL))
			return 0;
// #endif
		pr_err("IBS: Unable to find and replace the operand of the CALL instruction.\n");
		return -ENODATA;
	}

	if (replace_call_address_through_binary_inspection(entry_spurious_address, smp_spurious_address))
		return 0;

	return -ENODATA;
#else
	struct desc_ptr idtr;
	gate_desc ibs_desc;

	store_idt(&idtr);

	memcpy(&old_ibs, (void*)(idtr.address + ibs_vector * sizeof(gate_desc)), sizeof(gate_desc));
	
	pack_gate(&ibs_desc, GATE_INTERRUPT, (unsigned long)ibs_entry, 0, 0, 0);

	cr0 = _read_cr0();
	_write_cr0(cr0 & ~X86_CR0_WP);

	write_idt_entry((gate_desc*)idtr.address, ibs_vector, &ibs_desc);

	_write_cr0(cr0);

	return 0;
#endif
}

static void restore_idt_entry(void)
{
	unsigned long cr0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
	cr0 = _read_cr0();
	_write_cr0(cr0 & ~X86_CR0_WP);

# if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
	arch_cmpxchg(call_operand_address, new_call_operand, old_call_operand);
# else
	cmpxchg(call_operand_address, new_call_operand, old_call_operand);
# endif

	_write_cr0(cr0);
#else
	struct desc_ptr idtr;

	store_idt(&idtr);

	cr0 = _read_cr0();
	_write_cr0(cr0 & ~X86_CR0_WP);

	write_idt_entry((gate_desc*)idtr.address, ibs_vector, &old_ibs);

	_write_cr0(cr0);
#endif
}

static void setup_ibs_lvt(void *err)
{
	u64 reg;
	u64 ibs_ctl;
	u32 entry;
	u32 new_entry;
	u8 offset;

	rdmsrl(MSR_IBS_CONTROL, ibs_ctl);
	if (!(ibs_ctl & IBS_LVT_OFFSET_VAL))
	{
		pr_err("IBS: APIC setup failed - invalid offset by MSR_bits: %llu\n", ibs_ctl);
		goto no_offset;
	}

	offset = ibs_ctl & IBS_LVT_OFFSET;
	pr_info("IBS: IBS_CTL offset is %u\n", offset);

	reg = APIC_EILVTn(offset);
	entry = apic_read(reg);

	/* Print the 2 LSB in APIC register : | mask | msg_type | vector | */
	pr_info("IBS: APIC of CPU %u - READ offset %u -> | %lu | %lu | %lu |\n",
		smp_processor_id(), offset, ((entry >> 16) & 0xFUL), ((entry >> 8) & 0xFUL), (entry & 0xFFUL));

	new_entry = (0UL) | (APIC_EILVT_MSG_FIX << 8) | (ibs_vector);

	if (entry != new_entry || !((entry >> 16) & 0xFUL))
	{
		if (!setup_APIC_eilvt(offset, 0, 0, 1))
		{
			pr_info("IBS: cleared LVT entry 0x%x on cpu %i\n", offset, smp_processor_id());
			reg = APIC_EILVTn(offset);
			entry = apic_read(reg);
		}
		else
			goto fail;
	}

	if (!setup_APIC_eilvt(offset, ibs_vector, APIC_EILVT_MSG_FIX, 0))
		pr_info("IBS: LVT entry 0x%x setup on cpu %i\n", offset, smp_processor_id());
	else
		goto fail;

	return;

fail:
	pr_err("IBS: APIC setup failed - cannot set up the LVT entry 0x%x on cpu %i\n", offset, smp_processor_id());
no_offset:
	*((int*)err) = -1;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0)
static void mask_ibs_lvt(void *err)
{
	u64 reg;
	u64 ibs_ctl;
	u32 entry;
	u8 offset;

	rdmsrl(MSR_IBS_CONTROL, ibs_ctl);

	offset = ibs_ctl & IBS_LVT_OFFSET;

	reg = APIC_EILVTn(offset);
	entry = apic_read(reg);

	if (setup_APIC_eilvt(offset, (entry & 0xFFUL), ((entry >> 8) & 0xFUL), 1UL))
		goto fail;

	return;

fail:
	*((int*)err) = -1;
	pr_err("IBS: APIC setup failed - cannot mask the LVT entry #%i on cpu %i\n", offset, smp_processor_id());
}
#endif

int setup_ibs_irq(void)
{
	int err;
	
	err = acquire_free_vector();
	if (err)
		goto out;

	err = setup_idt_entry();
	if (err)
		goto out;
	
	on_each_cpu(setup_ibs_lvt, &err, 1);

out:
	return err;
}

void cleanup_ibs_irq(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
	restore_idt_entry();

	pr_info("IBS: call to smp_spurious_interrupt has been correctly restored.\n");
#else
	int err = 0;

	on_each_cpu(mask_ibs_lvt, &err, 1);

	if (err)
	{
		pr_err("IBS: while masking the LVT, trying to restore the IDT.\n");
	}

	restore_idt_entry();

	clear_bit(ibs_vector, used_vectors);

	pr_info("IBS: IRQ cleaned.\n");
#endif
}


/********************************************************************************/
/*                   IBS DEVICES CREATION AND INITIALIZATION                    */
/*                    (structures, variables and functions)                     */

struct ibs_dev {
	u64 ctl;                      /* Copy of op/fetch ctl MSR to store control options. */
	struct mutex ctl_lock;        /* Lock for device control options. */

	int ibs_thread;               /* ID of threads registered to this device. */
	unsigned long ibs_callback;   /* Callback functions to give control for each registered thread. */
	unsigned long text_start;     /* Program's text section start address. */
	unsigned long text_end;       /* Program's text section end address. */

	int cpu;                      /* This device's CPU-ID. */
	int flavor;                   /* IBS_FETCH or IBS_OP. */
	atomic_t in_use;              /* Non-Zero when device is open. */
};

static const struct file_operations ibs_fops = {
	.open           = ibs_open,
	.owner          = THIS_MODULE,
	.release        = ibs_release,
	.unlocked_ioctl = ibs_ioctl,
};


void *pcpu_op_dev;
void *pcpu_fetch_dev;

static int ibs_major;
static struct class *ibs_class;


static char *ibs_devnode(struct device *dev, umode_t *mode)
{
	int minor = MINOR(dev->devt);
	return kasprintf(GFP_KERNEL, "cpu/%u/ibs/%s", IBS_CPU(minor), IBS_FLAVOR(minor) == IBS_OP ? "op" : "fetch");
}

static int ibs_uevent(struct device *dev, struct kobj_uevent_env *env)
{
	add_uevent_var(env, "DEVMODE=%#o", 0666);
	return 0;
}

static void init_ibs_dev(struct ibs_dev *dev, int cpu, int flavor)
{
	mutex_init(&dev->ctl_lock);

	dev->ibs_thread = -1;
	dev->ibs_callback = 0x0;
	dev->text_start = 0x0;
	dev->text_end = 0x0;

	dev->cpu = cpu;
	dev->flavor = flavor;
	atomic_set(&dev->in_use, 0);
}

static int ibs_device_create(int flavor, int cpu)
{
	struct device *dev;

	dev = device_create(ibs_class, NULL, MKDEV(ibs_major, IBS_MINOR(flavor, cpu)),
						NULL, "ibs_%s%u", flavor == IBS_OP ? "op" : "fetch", cpu);

	return IS_ERR(dev) ? PTR_ERR(dev) : 0;
}

static void ibs_device_destroy(int flavor, int cpu)
{
	device_destroy(ibs_class, MKDEV(ibs_major, IBS_MINOR(flavor, cpu)));
}

int setup_ibs_devices(void)
{
	int err = 0;
	unsigned int cpu;

	pcpu_op_dev = alloc_percpu(struct ibs_dev);
	if (!pcpu_op_dev)
	{
		pr_err("IBS: failed to allocate IBS device metadata; exiting\n");
		err = -ENOMEM;
		goto out;
	}

	pcpu_fetch_dev = alloc_percpu(struct ibs_dev);
	if (!pcpu_fetch_dev)
	{
		pr_err("IBS: failed to allocate IBS device metadata.\n");
		err = -ENOMEM;
		goto out_op_dev;
	}

	if (init_workaround_structs())
	{
		pr_err("Failed to allocate IBS device metadata; exiting\n");
		err = -ENOMEM;
		goto out_fetch_dev;
	}

	for_each_possible_cpu(cpu)
	{
		init_ibs_dev(per_cpu_ptr(pcpu_op_dev, cpu), cpu, IBS_OP);
		init_ibs_dev(per_cpu_ptr(pcpu_fetch_dev, cpu), cpu, IBS_FETCH);
		init_workaround_initialize();
	}

	ibs_major = __register_chrdev(0, 0, NR_CPUS, "cpu/ibs", &ibs_fops);
	if (ibs_major < 0)
	{
		pr_err("IBS: unable to retrieve IBS device number.\n");
		err = -ENOMEM;
		goto out_fetch_dev;
	}

	ibs_class = class_create(THIS_MODULE, "ibs");
	if (IS_ERR(ibs_class))
	{
		err = PTR_ERR(ibs_class);
		pr_err("IBS: failed to create IBS class.\n");
		goto out_chrdev;
	}

	ibs_class->devnode = ibs_devnode;
	ibs_class->dev_uevent = ibs_uevent;

	for_each_possible_cpu(cpu)
	{
		if (ibs_op_supported)
			err = ibs_device_create(IBS_OP, cpu);
		if (err != 0)
			goto out_chrdev;
		if (ibs_fetch_supported)
			err = ibs_device_create(IBS_FETCH, cpu);
		if (err != 0)
			goto out_chrdev;
	}

	goto out;

out_chrdev:
	__unregister_chrdev(ibs_major, 0, NR_CPUS, "cpu/ibs");
out_fetch_dev:
	free_percpu(pcpu_fetch_dev);
out_op_dev:
	free_percpu(pcpu_op_dev);
out:
	return err;
}

static void enable_fam17h_zn_dyn_workaround(const int cpu)
{
	__u64 set_bits;
	__u64 op_ctl, fetch_ctl;
	__u64 cur1, cur3;

	unsigned int cpu_to_use = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
	for_each_cpu(cpu_to_use, topology_sibling_cpumask(cpu))
#else
	for_each_cpu_mask(cpu_to_use, topology_core_siblings(cpu))
#endif
	{
		op_ctl = custom_rdmsrl_on_cpu(cpu_to_use, MSR_IBS_OP_CTL);
		fetch_ctl = custom_rdmsrl_on_cpu(cpu_to_use, MSR_IBS_FETCH_CTL);

		if ((op_ctl & IBS_OP_EN) || (fetch_ctl & IBS_FETCH_EN))
			return;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
	cpu_to_use = cpumask_first(topology_sibling_cpumask(cpu));
#else
	cpu_to_use = first_cpu(topology_core_siblings(cpu));
#endif

	cur1 = custom_rdmsrl_on_cpu(cpu_to_use, FAM17H_MSR_WA_1);
	cur3 = custom_rdmsrl_on_cpu(cpu_to_use, FAM17H_MSR_WA_3);

	set_bits = cur1 | FAM17H_MSR_WA_1_BITS;
	custom_wrmsrl_on_cpu(cpu_to_use, FAM17H_MSR_WA_1, set_bits);

	set_bits = cur3 & ~FAM17H_MSR_WA_3_BITS;
	custom_wrmsrl_on_cpu(cpu_to_use, FAM17H_MSR_WA_3, set_bits);
}

static void disable_fam17h_zn_dyn_workaround(const int cpu)
{
	__u64 op_ctl, fetch_ctl;
	__u64 cur1, cur3, set_bits;

	unsigned int cpu_to_use = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
	for_each_cpu(cpu_to_use, topology_sibling_cpumask(cpu))
#else
	for_each_cpu_mask(cpu_to_use, topology_core_siblings(cpu))
#endif
	{
		op_ctl = custom_rdmsrl_on_cpu(cpu_to_use, MSR_IBS_OP_CTL);
		fetch_ctl = custom_rdmsrl_on_cpu(cpu_to_use, MSR_IBS_FETCH_CTL);

		if ((op_ctl & IBS_OP_EN) || (fetch_ctl & IBS_FETCH_EN))
			return;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
	cpu_to_use = cpumask_first(topology_sibling_cpumask(cpu));
#else
	cpu_to_use = first_cpu(topology_core_siblings(cpu));
#endif

	cur1 = custom_rdmsrl_on_cpu(cpu_to_use, FAM17H_MSR_WA_1);
	cur3 = custom_rdmsrl_on_cpu(cpu_to_use, FAM17H_MSR_WA_3);

	set_bits = cur1 & ~FAM17H_MSR_WA_1_BITS;
	set_bits |= fam17h_old_1;
	custom_wrmsrl_on_cpu(cpu_to_use, FAM17H_MSR_WA_1, set_bits);

	set_bits = cur3 | FAM17H_MSR_WA_3_BITS;
	set_bits |= fam17h_old_3;
	custom_wrmsrl_on_cpu(cpu_to_use, FAM17H_MSR_WA_3, set_bits);
}

static void start_fam17h_zn_dyn_workaround(const int cpu)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
	int cpu_to_use = cpumask_first(topology_sibling_cpumask(cpu));
#else
	int cpu_to_use = first_cpu(topology_core_siblings(cpu));
#endif
	spinlock_t *cpu_workaround_lock = per_cpu_ptr(pcpu_workaround_lock, cpu_to_use);

	spin_lock(cpu_workaround_lock);
	enable_fam17h_zn_dyn_workaround(cpu);
	spin_unlock(cpu_workaround_lock);
}

static void stop_fam17h_zn_dyn_workaround(const int cpu)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
	int cpu_to_use = cpumask_first(topology_sibling_cpumask(cpu));
#else
	int cpu_to_use = first_cpu(topology_core_siblings(cpu));
#endif
	spinlock_t *cpu_workaround_lock = per_cpu_ptr(pcpu_workaround_lock, cpu_to_use);

	spin_lock(cpu_workaround_lock);
	disable_fam17h_zn_dyn_workaround(cpu);
	spin_unlock(cpu_workaround_lock);
}

static inline void enable_ibs_op_on_cpu(struct ibs_dev *dev, const int cpu, const u64 op_ctl)
{
	if (workaround_fam17h_zn)
		start_fam17h_zn_dyn_workaround(cpu);
    wrmsrl_on_cpu(cpu, MSR_IBS_OP_CTL, op_ctl);
}

static void do_fam10h_workaround_420(const int cpu)
{
	__u64 old_op_ctl;
	rdmsrl_on_cpu(cpu, MSR_IBS_OP_CTL, &old_op_ctl);
	old_op_ctl = (old_op_ctl | IBS_OP_VAL) & (~IBS_OP_MAX_CNT_MAX);
	wrmsrl_on_cpu(cpu, MSR_IBS_OP_CTL, old_op_ctl);
}

static void disable_ibs_op(void *info)
{
	wrmsrl(MSR_IBS_OP_CTL, IBS_OP_VAL);
	udelay(1);
	wrmsrl(MSR_IBS_OP_CTL, 0ULL);
}

static void disable_ibs_op_on_cpu(struct ibs_dev *dev, const int cpu)
{
	if (workaround_fam10h_err_420)
    	do_fam10h_workaround_420(cpu);
	smp_call_function_single(cpu, disable_ibs_op, NULL, 1);
	if (workaround_fam17h_zn)
		stop_fam17h_zn_dyn_workaround(cpu);
}

static inline void enable_ibs_fetch_on_cpu(struct ibs_dev *dev, const int cpu, const u64 fetch_ctl)
{
	if (workaround_fam17h_zn)
		start_fam17h_zn_dyn_workaround(cpu);
    wrmsrl_on_cpu(cpu, MSR_IBS_FETCH_CTL, fetch_ctl);
}

static void disable_ibs_fetch_on_cpu(struct ibs_dev *dev, const int cpu)
{
    wrmsrl_on_cpu(cpu, MSR_IBS_FETCH_CTL, 0ULL);
    if (workaround_fam17h_zn)
		stop_fam17h_zn_dyn_workaround(cpu);
}

void cleanup_ibs_devices(void)
{
	unsigned int cpu;

	for_each_online_cpu(cpu)
	{
		disable_ibs_op_on_cpu(per_cpu_ptr(pcpu_op_dev, cpu), cpu);
		disable_ibs_fetch_on_cpu(per_cpu_ptr(pcpu_fetch_dev, cpu), cpu);
	}

	for_each_possible_cpu(cpu)
	{
		ibs_device_destroy(IBS_OP, cpu);
		ibs_device_destroy(IBS_FETCH, cpu);
	}

	__unregister_chrdev(ibs_major, 0, NR_CPUS, "cpu/ibs");

	cpu = 0;
	
	for_each_possible_cpu(cpu)
	{
		if (workaround_fam17h_zn)
			stop_fam17h_zn_static_workaround(cpu);
	}

	free_percpu(pcpu_fetch_dev);
	free_percpu(pcpu_op_dev);

	free_workaround_structs();

	class_destroy(ibs_class);
}


/********************************************************************************/
/*                            IBS DEVICE OPERATIONS                             */
/*                                 (functions)                                  */

static void set_ibs_defaults(struct ibs_dev *dev)
{
	if (dev->flavor == IBS_OP)
		dev->ctl = (0ULL) | ((DEFAULT_MAX_CNT >> 4) & IBS_OP_MAX_CNT_MAX);
	else
		dev->ctl = (0ULL); // TODO: must be implemented for FETCH sampling
}

int ibs_open(struct inode *inode, struct file *file)
{
	unsigned int minor = iminor(inode);
	struct ibs_dev *dev;

	if (IBS_FLAVOR(minor) == IBS_OP)
		dev = per_cpu_ptr(pcpu_op_dev, IBS_CPU(minor));
	else
		dev = per_cpu_ptr(pcpu_fetch_dev, IBS_CPU(minor));

	if (atomic_cmpxchg(&dev->in_use, 0, 1) != 0)
		return -EBUSY;

	file->private_data = dev;

	mutex_lock(&dev->ctl_lock);

	set_ibs_defaults(dev);
	
	mutex_unlock(&dev->ctl_lock);

	pr_info("IBS: %s-Dev OPEN on CPU %d.\n", (dev->flavor == IBS_OP) ? "OP" : "FETCH", dev->cpu);

	return 0;
}

int ibs_release(struct inode *inode, struct file *file)
{
	struct ibs_dev *dev = file->private_data;

	mutex_lock(&dev->ctl_lock);

	if (dev->flavor == IBS_OP)
		disable_ibs_op_on_cpu(dev, dev->cpu);
	else
		disable_ibs_fetch_on_cpu(dev, dev->cpu);

	set_ibs_defaults(dev);

	dev->ibs_thread = -1;
	dev->ibs_callback = 0x0;
	dev->text_start = 0x0;
	dev->text_end = 0x0;

	atomic_set(&dev->in_use, 0);

	mutex_unlock(&dev->ctl_lock);

	pr_info("IBS: %s-Dev CLOSE on CPU %d.\n", (dev->flavor == IBS_OP) ? "OP" : "FETCH", dev->cpu);

	return 0;
}

long ibs_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	long retval = 0;
	struct ibs_dev *dev = file->private_data;
	int cpu = dev->cpu;

	mutex_lock(&dev->ctl_lock);

	if (cmd == SET_CUR_CNT || cmd == SET_CNT || cmd == SET_MAX_CNT || cmd == SET_CNT_CTL || cmd == SET_RAND_EN) {
		if ((dev->flavor == IBS_OP && dev->ctl & IBS_OP_EN) ||
				(dev->flavor == IBS_FETCH && dev->ctl & IBS_FETCH_EN)) {
			mutex_unlock(&dev->ctl_lock);
			return -EBUSY;
		}
	}

	switch (cmd) {
		case IBS_ENABLE:
			if (dev->flavor == IBS_OP) {
				arg = (arg < DEFAULT_MIN_CNT) ? DEFAULT_MIN_CNT : ((arg > DEFAULT_MAX_CNT) ? DEFAULT_MAX_CNT : arg);
				dev->ctl = (0ULL) | ((arg >> 4) & IBS_OP_MAX_CNT_MAX) | IBS_OP_EN;
				pr_info("IBS:  OP-Dev ENABLE IBS on CPU %d. MaxOpCnt is set to %lu.\n", dev->cpu, arg);
				enable_ibs_op_on_cpu(dev, cpu, dev->ctl);
			} else {
				dev->ctl |= IBS_FETCH_EN;
				pr_info("IBS:  FETCH-Dev ENABLE IBS on CPU %d.\n", dev->cpu);
				enable_ibs_fetch_on_cpu(dev, cpu, dev->ctl);
			}
			break;
		case IBS_DISABLE:
			if (dev->flavor == IBS_OP) {
				disable_ibs_op_on_cpu(dev, cpu);
				dev->ctl &= ~IBS_OP_EN;
				pr_info("IBS:  OP-Dev DISABLE IBS on CPU %d.\n", dev->cpu);
			} else {
				disable_ibs_fetch_on_cpu(dev, cpu);
				dev->ctl &= ~IBS_FETCH_EN;
				pr_info("IBS:  FETCH-Dev DISABLE IBS on CPU %d.\n", dev->cpu);
			}
			break;
		case IBS_REGISTER_THREAD:
			dev->ibs_thread = current->pid;
			dev->ibs_callback = arg;
			pr_info("IBS:   %s-Dev REGISTER THREAD %d on CPU %d. CB-function is at 0x%lx.\n",
				(dev->flavor == IBS_OP) ? "OP" : "FETCH", current->pid, dev->cpu, arg);
			break;
		case IBS_UNREGISTER_THREAD:
			dev->ibs_thread = -1;
			dev->ibs_callback = 0x0;
			pr_info("IBS:   %s-Dev DEREGISTER THREAD %d on CPU %d.\n",
				(dev->flavor == IBS_OP) ? "OP" : "FETCH", current->pid, dev->cpu);
			break;
		case IBS_SET_TEXT_START:
			dev->text_start = arg;
			pr_info("IBS:    %s-Dev SET TEXT-START to 0x%lx for thread %d on CPU %d.\n",
				(dev->flavor == IBS_OP) ? "OP" : "FETCH", arg, current->pid, dev->cpu);
			break;
		case IBS_SET_TEXT_END:
			dev->text_end = arg;
			pr_info("IBS:    %s-Dev SET TEXT-END to 0x%lx for thread %d on CPU %d.\n",
				(dev->flavor == IBS_OP) ? "OP" : "FETCH", arg, current->pid, dev->cpu);
			break;
		case SET_CUR_CNT:
		case SET_CNT:
			break;
		case GET_CUR_CNT:
		case GET_CNT:
			break;
		case SET_MAX_CNT:
			break;
		case GET_MAX_CNT:
			break;
		case SET_CNT_CTL:
			break;
		case GET_CNT_CTL:
			break;
		case SET_RAND_EN:
			break;
		case GET_RAND_EN:
			break;
		default:	/* Command not recognized */
			retval = -ENOTTY;
			break;
	}
	mutex_unlock(&dev->ctl_lock);
	return retval;
}


/********************************************************************************/
/*                            IBS INTERRUPT ANDLER                              */
/*                                 (function)                                   */

void handle_ibs_irq(struct pt_regs *regs)
{
	u64 tmp;
	unsigned long stack_pointer;
	struct pt_regs *old_regs;
	struct ibs_dev *dev;

	preempt_disable();

	dev = this_cpu_ptr(pcpu_op_dev);

	/* AMD family 10th workaround. */
	if (workaround_fam10h_err_420)
	{
		rdmsrl(MSR_IBS_OP_CTL, tmp);
		if (!(tmp & IBS_OP_MAX_CNT_MAX))
		{
			wrmsrl(MSR_IBS_OP_CTL, dev->ctl);
			apic->write(APIC_EOI, APIC_EOI_ACK);
			preempt_enable();
			return;
		}
	}

	/* This is a kernel thread. */
	if(current->mm == NULL)
	{
		wrmsrl(MSR_IBS_OP_CTL, dev->ctl);
		apic->write(APIC_EOI, APIC_EOI_ACK);
		preempt_enable();
		return;
	}

	/* Interrupted in kernel mode. */
	if ((old_regs = set_irq_regs(regs)) != NULL)
	{
		set_irq_regs(old_regs);
		wrmsrl(MSR_IBS_OP_CTL, dev->ctl);
		apic->write(APIC_EOI, APIC_EOI_ACK);
		preempt_enable();
		return;
	}

	if (dev->ibs_thread == current->pid && dev->ibs_callback != regs->ip &&
			dev->text_start <= regs->ip && dev->text_end >= regs->ip)
	{
		stack_pointer = regs->sp;
		stack_pointer -= sizeof(regs->ip);
		__put_user(regs->ip, *((unsigned long **) &stack_pointer));
		regs->sp = stack_pointer;
		regs->ip = dev->ibs_callback;
	}

	set_irq_regs(old_regs);
	wrmsrl(MSR_IBS_OP_CTL, dev->ctl);
	apic->write(APIC_EOI, APIC_EOI_ACK);
	preempt_enable();
	return;
}


/********************************************************************************/
/*                        IBS KENEL MODULE INIT & EXIT                          */
/*                      (functions and per-module macros)                       */

static __init int ibs_init(void)
{
	int err;

	pr_info("IBS: starting module initialization.\n");

	err = check_for_ibs_support();
	if (err)
		goto out;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,11)
	if(static_cpu_has(X86_FEATURE_PTI))
	    pr_info("IBS: kernel page table isolation (PTI) is enabled.\n");
	else
	    pr_info("IBS: kernel page table isolation (PTI) is disabled.\n");
#endif

	err = setup_ibs_irq();
	if (err)
		goto out;

	err = setup_ibs_devices();
	if (err)
		goto out_ibs_irq;

	pr_info("IBS: module initialization completed.\n");

	goto out;

out_ibs_irq:
	cleanup_ibs_irq();
out:
	return err;
}

static __exit void ibs_exit(void)
{
	pr_info("IBS: starting module finalization.\n");

	cleanup_ibs_devices();
	cleanup_ibs_irq();

	pr_info("IBS: module finalization completed.\n");
}


module_init(ibs_init);
module_exit(ibs_exit);


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Emiliano Silvestri <silvestri@diag.uniroma1.it>");
MODULE_DESCRIPTION("Perform user-space CFV setup for registered threads");
