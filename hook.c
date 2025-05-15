// hook.c
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <link.h>
#include <dlfcn.h>
#include <elf.h>

static int (*real_puts)(const char *) = NULL;

int my_puts(const char *str) {
    return real_puts("[HOOKED] I've intercepted your puts!");
}

int phdr_callback(struct dl_phdr_info *info, size_t size, void *data) {
    Elf64_Addr base = info->dlpi_addr;

    for (int i = 0; i < info->dlpi_phnum; ++i) {
        const Elf64_Phdr *phdr = &info->dlpi_phdr[i];
        if (phdr->p_type == PT_DYNAMIC) {
            Elf64_Dyn *dyn = (Elf64_Dyn *)(base + phdr->p_vaddr);
            Elf64_Rela *jmprel = NULL;
            Elf64_Sym *symtab = NULL;
            const char *strtab = NULL;
            size_t relasz = 0;

            for (; dyn->d_tag != DT_NULL; ++dyn) {
                if (dyn->d_tag == DT_JMPREL) jmprel = (Elf64_Rela *)(base + dyn->d_un.d_ptr);
                if (dyn->d_tag == DT_PLTRELSZ) relasz = dyn->d_un.d_val;
                if (dyn->d_tag == DT_SYMTAB) symtab = (Elf64_Sym *)(base + dyn->d_un.d_ptr);
                if (dyn->d_tag == DT_STRTAB) strtab = (char *)(base + dyn->d_un.d_ptr);
            }

            if (!jmprel || !symtab || !strtab) return 0;

            for (size_t i = 0; i < relasz / sizeof(Elf64_Rela); ++i) {
                Elf64_Rela *r = &jmprel[i];
                Elf64_Sym *sym = &symtab[ELF64_R_SYM(r->r_info)];
                const char *name = &strtab[sym->st_name];
                if (strcmp(name, "puts") == 0) {
                    void **got_entry = (void **)(base + r->r_offset);
                    real_puts = *got_entry;
                    *got_entry = my_puts;
                    return 1;
                }
            }
        }
    }
    return 0;
}

__attribute__((constructor))
void init_hook() {
    dl_iterate_phdr(phdr_callback, NULL);
}