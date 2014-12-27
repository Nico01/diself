#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <inttypes.h>

#include "disassemble.h"
#include "elf_32.h"
#include "elf_64.h"

size_t file_size(const char *fileName)
{
    struct stat st; 

    if (stat(fileName, &st) == 0)
        return st.st_size;

    return -1; 
}

void disasm(uint64_t addr, uint32_t offset, size_t size, cs_arch arch, cs_mode mode, uint8_t *data)
{
    int i;
    csh handle = 0;
    cs_insn *insn;
    const uint8_t *code;

    if (cs_open(arch, mode, &handle) != CS_ERR_OK) {
        printf("ERROR: Failed to initialize engine!\n");
        exit(EXIT_FAILURE);
    }

    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);   

    printf("Disassembly of section .text:\n");

    for (i = offset; i < offset + size; i++) {
        code = &data[i];
        insn = cs_malloc(handle);

        while(cs_disasm_iter(handle, &code, &size, &addr, insn)) {
            printf("0x%"PRIx64":\t%s\t\t%s\n", insn->address, insn->mnemonic, insn->op_str);
        }
        cs_free(insn, 1);
    }
    cs_close(&handle);
}

void elf_disasm_64(Elf64_Ehdr *ehdr, Elf64_Shdr *shdr, char *str_table, uint8_t *data)
{
    uint32_t offset = get_section_offset_64(ehdr, shdr, str_table, ".text");
    size_t size = get_section_size_64(ehdr, shdr, str_table, ".text");

    disasm(ehdr->e_entry, offset, size, CS_ARCH_X86, CS_MODE_64, data);
}

void elf_disasm_32(Elf32_Ehdr *ehdr, Elf32_Shdr *shdr, char *str_table, uint8_t *data)
{
    uint32_t offset = get_section_offset_32(ehdr, shdr, str_table, ".text");
    size_t size = get_section_size_32(ehdr, shdr, str_table, ".text");

    disasm(ehdr->e_entry, offset, size, CS_ARCH_X86, CS_MODE_32, data);
}
