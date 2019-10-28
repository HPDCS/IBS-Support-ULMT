#include <asm/irq.h>
#include <asm/desc.h>
#include <asm/apic.h>
#include <asm/apicdef.h>
#include <asm/uaccess.h>
#include <linux/smp.h>
#include <linux/percpu.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/interrupt.h>
#include <linux/device.h>
#include <linux/delay.h>

#include "ibs-api.h"


#define IBS_OP                      0
#define IBS_FETCH                   1


/********************************************************************************/
/*                           CPUID REGISTERS & MASKS                            */
/*                             (check IBS support)                              */

#define CPUID_AMD_FAM10h            0x10

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

unsigned ibs_vector = 0xffU;

int ibs_op_supported;
int ibs_fetch_supported;

gate_desc old_ibs;


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

int check_for_ibs_support(void)
{
	struct cpuinfo_x86 *c;
	unsigned int feature_id;

	c = &boot_cpu_data;

	if (c->x86_vendor != X86_VENDOR_AMD)
	{
		pr_err("IBS ERROR: required AMD processor.\n");
		return -EINVAL;
	}

	if (c->x86 != CPUID_AMD_FAM10h)
	{
		pr_err("IBS ERROR: this module is designed only for Fam 10h\n");
		return -EINVAL;
	}

	if (!(CPUID_Fn8000_0001_ECX & IBS_SUPPORT_EXIST))
	{
		pr_err("IBS ERROR: CPUID_Fn8000_0001 indicates no IBS support\n");
		return -EINVAL;	
	}

	feature_id = CPUID_Fn8000_001B_EAX;

	if (!(feature_id & IBS_CPUID_IBSFFV))
	{
		pr_err("IBS ERROR: CPUID_Fn8000_001B indicates no IBS support\n");
		return -EINVAL;
	}

	ibs_fetch_supported = feature_id & IBS_CPUID_FetchSam;
	ibs_op_supported = feature_id & IBS_CPUID_OpSam;
	ibs_op_supported |= feature_id & IBS_CPUID_RdWrOpCnt;
	ibs_op_supported |= feature_id & IBS_CPUID_OpCnt;

	if (!ibs_fetch_supported)
	{
		pr_err("IBS ERROR: CPUID_Fn800_001B says no Op support\n");
		return -EINVAL;
	}

	if (!ibs_op_supported)
	{
		pr_err("IBS ERROR: CPUID_Fn800_001B says no Fetch support\n");
		return -EINVAL;
	}
	
	return 0;
}

static int acquire_free_vector(void)
{
	while (test_bit(ibs_vector, used_vectors))
	{
		if (ibs_vector == 0x40)
		{
			pr_err("IBS ERROR: no free vector found\n");
			return -1;
		}
		ibs_vector--;
	}
	set_bit(ibs_vector, used_vectors);

	pr_info("IBS: got vector 0x%x\n", ibs_vector);

	return 0;
}

static int setup_idt_entry(void)
{
	struct desc_ptr idtr;
	gate_desc ibs_desc;
	unsigned long cr0;

	store_idt(&idtr);

	memcpy(&old_ibs, (void*)(idtr.address + ibs_vector * sizeof(gate_desc)), sizeof(gate_desc));
	
	pack_gate(&ibs_desc, GATE_INTERRUPT, (unsigned long)ibs_entry, 0, 0, 0);

	cr0 = read_cr0();
	write_cr0(cr0 & ~X86_CR0_WP);

	write_idt_entry((gate_desc*)idtr.address, ibs_vector, &ibs_desc);

	write_cr0(cr0);

	return 0;
}

static void restore_idt_entry(void)
{
	struct desc_ptr idtr;
	unsigned long cr0;

	store_idt(&idtr);

	cr0 = read_cr0();
	write_cr0(cr0 & ~X86_CR0_WP);

	write_idt_entry((gate_desc*)idtr.address, ibs_vector, &old_ibs);

	write_cr0(cr0);
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
		pr_err("IBS ERROR: APIC setup failed - invalid offset by MSR_bits: %llu\n", ibs_ctl);
		goto no_offset;
	}

	offset = ibs_ctl & IBS_LVT_OFFSET;
	pr_info("IBS: IBS_CTL offset is %u\n", offset);

	reg = APIC_EILVTn(offset);
	entry = apic_read(reg);

	/* Print the 2 LSB in APIC register : | mask | msg_type | vector | */
	pr_info("[APIC] CPU %u - READ offset %u -> | %lu | %lu | %lu |\n", smp_processor_id(), offset,
								((entry >> 16) & 0xFUL), ((entry >> 8) & 0xFUL), (entry & 0xFFUL));

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
	pr_err("IBS ERROR: APIC setup failed - cannot set up the LVT entry 0x%x on cpu %i\n", offset, smp_processor_id());
no_offset:
	*((int*)err) = -1;
}

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
	pr_err("IBS ERROR: APIC setup failed - cannot mask the LVT entry #%i on cpu %i\n", offset, smp_processor_id());
}

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
	int err = 0;

	on_each_cpu(mask_ibs_lvt, &err, 1);

	if (err)
		pr_err("IBS ERROR: while masking the LVT, trying to restore the IDT\n");

	restore_idt_entry();

	clear_bit(ibs_vector, used_vectors);
	
	pr_info("IBS: IRQ cleaned\n");
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
		pr_err("IBS ERROR: failed to allocate IBS device metadata; exiting\n");
		err = -ENOMEM;
		goto out;
	}

	pcpu_fetch_dev = alloc_percpu(struct ibs_dev);
	if (!pcpu_fetch_dev)
	{
		pr_err("IBS ERROR: failed to allocate IBS device metadata; exiting\n");
		err = -ENOMEM;
		goto out_op_dev;
	}

	for_each_possible_cpu(cpu)
	{
		init_ibs_dev(per_cpu_ptr(pcpu_op_dev, cpu), cpu, IBS_OP);
		init_ibs_dev(per_cpu_ptr(pcpu_fetch_dev, cpu), cpu, IBS_FETCH);
	}

	ibs_major = __register_chrdev(0, 0, NR_CPUS, "cpu/ibs", &ibs_fops);
	if (ibs_major < 0)
	{
		pr_err("IBS ERROR: unable to retrieve IBS device number.\n");
		err = -ENOMEM;
		goto out_fetch_dev;
	}

	ibs_class = class_create(THIS_MODULE, "ibs");
	if (IS_ERR(ibs_class))
	{
		err = PTR_ERR(ibs_class);
		pr_err("Failed to create IBS class; exiting\n");
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

static inline void enable_ibs_op_on_cpu(struct ibs_dev *dev, const int cpu, const u64 op_ctl)
{
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
    do_fam10h_workaround_420(cpu);
	smp_call_function_single(cpu, disable_ibs_op, NULL, 1);
}

static inline void enable_ibs_fetch_on_cpu(struct ibs_dev *dev, const int cpu, const u64 fetch_ctl)
{
    wrmsrl_on_cpu(cpu, MSR_IBS_FETCH_CTL, fetch_ctl);
}

static void disable_ibs_fetch_on_cpu(struct ibs_dev *dev, const int cpu)
{
    wrmsrl_on_cpu(cpu, MSR_IBS_FETCH_CTL, 0ULL);
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

	free_percpu(pcpu_fetch_dev);
	free_percpu(pcpu_op_dev);

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
	rdmsrl(MSR_IBS_OP_CTL, tmp);
	if (!(tmp & IBS_OP_MAX_CNT_MAX))
	{
		wrmsrl(MSR_IBS_OP_CTL, dev->ctl);
		apic->write(APIC_EOI, APIC_EOI_ACK);
		preempt_enable();
		return;
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

	pr_info("IBS: starting module initialization\n");

	err = check_for_ibs_support();
	if (err)
		goto out;

	err = setup_ibs_irq();
	if (err)
		goto out;

	err = setup_ibs_devices();
	if (err)
		goto out_ibs_irq;

	goto out;

out_ibs_irq:
	cleanup_ibs_irq();
out:
	return err;
}

static __exit void ibs_exit(void)
{
	cleanup_ibs_devices();
	cleanup_ibs_irq();
	pr_info("IBS: exited IBS module\n");
}


module_init(ibs_init);
module_exit(ibs_exit);


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Emiliano Silvestri <silvestri@diag.uniroma1.it>");
MODULE_DESCRIPTION("Perform user-space CFV setup for registered threads");
