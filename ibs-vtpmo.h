#ifndef __IBS_VTPMO__
#define __IBS_VTPMO__

#define ADDRESS_MASK		0xfffffffffffff000
#define PAGE_TABLE_ADDRESS	phys_to_virt(__read_cr3() & ADDRESS_MASK)
#define PT_ADDRESS_MASK		0x7ffffffffffff000
#define VALID				0x1
#define LH_MAPPING			0x80

#define PML4(addr) (((long long)(addr) >> 39) & 0x1ff)
#define PDP(addr)  (((long long)(addr) >> 30) & 0x1ff)
#define PDE(addr)  (((long long)(addr) >> 21) & 0x1ff)
#define PTE(addr)  (((long long)(addr) >> 12) & 0x1ff)

const int NO_MAP = -1;

static int sys_vtpmo(unsigned long vaddr)
{
	void* target_address;

	pud_t* pdp;
	pmd_t* pde;
	pte_t* pte;
	pgd_t *pml4;

	int frame_number;
	unsigned long frame_addr;


	target_address = (void*)vaddr;

	pml4  = PAGE_TABLE_ADDRESS;

	if(!(((ulong)(pml4[PML4(target_address)].pgd)) & VALID))
		return NO_MAP;

	pdp = __va((ulong)(pml4[PML4(target_address)].pgd) & PT_ADDRESS_MASK);

	if(!((ulong)(pdp[PDP(target_address)].pud) & VALID))
		return NO_MAP;

	pde = __va((ulong)(pdp[PDP(target_address)].pud) & PT_ADDRESS_MASK);

	if(!((ulong)(pde[PDE(target_address)].pmd) & VALID))
		return NO_MAP;

	if((ulong)pde[PDE(target_address)].pmd & LH_MAPPING)
	{
		frame_addr = (ulong)(pde[PDE(target_address)].pmd) & PT_ADDRESS_MASK;

		frame_number = frame_addr >> 12;

		return frame_number;
	}

	pte = __va((ulong)(pde[PDE(target_address)].pmd) & PT_ADDRESS_MASK);

	if(!((ulong)(pte[PTE(target_address)].pte) & VALID))
		return NO_MAP;

	frame_addr = (ulong)(pte[PTE(target_address)].pte) & PT_ADDRESS_MASK;

	frame_number = frame_addr >> 12;

	return frame_number;
}

#endif