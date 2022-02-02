// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <elf.h>
#include <sys/auxv.h>
#include "vdso.h"

oe_result_t test_vdso(vdso_sgx_enter_enclave_t *vdso_pointer);

struct vdso_symtab {
	Elf64_Sym *elf_symtab;
	const char *elf_symstrtab;
	Elf64_Word *elf_hashtab;
};

static Elf64_Dyn *vdso_get_dyntab(void *addr)
{
	Elf64_Ehdr *ehdr = addr;
	Elf64_Phdr *phdrtab = (Elf64_Phdr*)((uint64_t)addr + ehdr->e_phoff);
	int i;

	for (i = 0; i < ehdr->e_phnum; i++)
		if (phdrtab[i].p_type == PT_DYNAMIC)
			return (Elf64_Dyn*)((uint64_t)addr + phdrtab[i].p_offset);

	return NULL;
}

static void *vdso_get_dyn(void *addr, Elf64_Dyn *dyntab, Elf64_Sxword tag)
{
	int i;

	for (i = 0; dyntab[i].d_tag != DT_NULL; i++)
		if (dyntab[i].d_tag == tag)
			return (void*)((uint64_t)addr + dyntab[i].d_un.d_ptr);

	return NULL;
}

static bool vdso_get_symtab(void *addr, struct vdso_symtab *symtab)
{
	Elf64_Dyn *dyntab = vdso_get_dyntab(addr);

	symtab->elf_symtab = vdso_get_dyn(addr, dyntab, DT_SYMTAB);
	if (!symtab->elf_symtab)
		return false;

	symtab->elf_symstrtab = vdso_get_dyn(addr, dyntab, DT_STRTAB);
	if (!symtab->elf_symstrtab)
		return false;

	symtab->elf_hashtab = vdso_get_dyn(addr, dyntab, DT_HASH);
	if (!symtab->elf_hashtab)
		return false;

	return true;
}

static unsigned long elf_sym_hash(const char *name)
{
	unsigned long h = 0, high;
    char* ptr = (char*)name;

	while (*ptr) {
		h = (h << 4) + (uint64_t)*ptr;
		high = h & 0xf0000000;
        ptr++;

		if (high)
			h ^= high >> 24;

		h &= ~high;
	}

	return h;
}

static Elf64_Sym *vdso_symtab_get(struct vdso_symtab *symtab, const char *name)
{
	Elf64_Word bucketnum = symtab->elf_hashtab[0];
	Elf64_Word *buckettab = &symtab->elf_hashtab[2];
	Elf64_Word *chaintab = &symtab->elf_hashtab[2 + bucketnum];
	Elf64_Sym *sym;
	Elf64_Word i;

	for (i = buckettab[elf_sym_hash(name) % bucketnum]; i != STN_UNDEF;
	     i = chaintab[i]) {
		sym = &symtab->elf_symtab[i];
		if (!strcmp(name, &symtab->elf_symstrtab[sym->st_name]))
			return sym;
	}

	return NULL;
}

oe_result_t test_vdso(vdso_sgx_enter_enclave_t *vdso_pointer)
{
    oe_result_t result = OE_FAILURE;
    Elf64_Sym *sgx_enter_enclave_sym = NULL;
    void* addr;
    struct vdso_symtab symtab;

    addr = (void*)getauxval(AT_SYSINFO_EHDR);
	if (!addr)
		goto done;

	if (!vdso_get_symtab(addr, &symtab))
		goto done;

	sgx_enter_enclave_sym = vdso_symtab_get(&symtab, "__vdso_sgx_enter_enclave");
	if (!sgx_enter_enclave_sym)
		goto done;

    *vdso_pointer = *(vdso_sgx_enter_enclave_t*)((uint64_t)addr + sgx_enter_enclave_sym->st_value);

    result = OE_OK;

done:
    return result;
}
