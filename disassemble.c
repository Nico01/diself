#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <capstone/capstone.h>

#include "disassemble.h"

size_t file_size(const char *fileName) {
    struct stat st; 

    if (stat(fileName, &st) == 0)
        return st.st_size;

    return -1; 
}

Elf64_Ehdr *read_elf_header(FILE *fd)
{
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *) malloc(sizeof(Elf64_Ehdr));

    if (fseek(fd, 0, SEEK_SET) != 0) {
        free(ehdr);
        return NULL;
    }

    if (fread(ehdr, sizeof(Elf64_Ehdr), 1, fd) != 1) {
        free(ehdr);
        return NULL;
    }

	if (ehdr->e_ident[EI_MAG0] != 0x7f ||
        ehdr->e_ident[EI_MAG1] != 'E' ||
        ehdr->e_ident[EI_MAG2] != 'L' ||
        ehdr->e_ident[EI_MAG3] != 'F') {
        free(ehdr);
        return NULL;
    }

    ehdr = (Elf64_Ehdr *) realloc(ehdr, ehdr->e_ehsize);

    return ehdr;
}

Elf32_Ehdr *read_elf_header_32(FILE *fd)
{
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *) malloc(sizeof(Elf32_Ehdr));

    if (fseek(fd, 0, SEEK_SET) != 0) {
        free(ehdr);
        return NULL;
    }

    if (fread(ehdr, sizeof(Elf32_Ehdr), 1, fd) != 1) {
        free(ehdr);
        return NULL;
    }

	if (ehdr->e_ident[EI_MAG0] != 0x7f ||
        ehdr->e_ident[EI_MAG1] != 'E' ||
        ehdr->e_ident[EI_MAG2] != 'L' ||
        ehdr->e_ident[EI_MAG3] != 'F') {
        free(ehdr);
        return NULL;
    }

    ehdr = (Elf32_Ehdr *) realloc(ehdr, ehdr->e_ehsize);

    return ehdr;
}

Elf64_Shdr *read_section_header(Elf64_Ehdr *ehdr, FILE *fd)
{
    size_t size = ehdr->e_shnum * ehdr->e_shentsize;
    Elf64_Shdr *shdr = (Elf64_Shdr *) malloc(size);

    if (fseek(fd, ehdr->e_shoff, SEEK_SET) != 0) {
        free(shdr);
        return NULL;
    }

    if (fread(shdr, size, 1, fd) != 1) {
        free(shdr);
        return NULL;
    }

    return shdr;
}

Elf32_Shdr *read_section_header_32(Elf32_Ehdr *ehdr, FILE *fd)
{
    size_t size = ehdr->e_shnum * ehdr->e_shentsize;
    Elf32_Shdr *shdr = (Elf32_Shdr *) malloc(size);

    if (fseek(fd, ehdr->e_shoff, SEEK_SET) != 0) {
        free(shdr);
        return NULL;
    }

    if (fread(shdr, size, 1, fd) != 1) {
        free(shdr);
        return NULL;
    }

    return shdr;
}

char *load_string_table(Elf64_Ehdr *ehdr, Elf64_Shdr *shdr_table, FILE *fd)
{
    Elf64_Shdr *shdr = shdr_table + ehdr->e_shstrndx;
    char *string_table;

    string_table = (char *) malloc(shdr->sh_size);
    fseek(fd, shdr->sh_offset, SEEK_SET);
    fread(string_table, shdr->sh_size, 1, fd);

    return string_table;
}

char *load_string_table_32(Elf32_Ehdr *ehdr, Elf32_Shdr *shdr_table, FILE *fd)
{
    Elf32_Shdr *shdr = shdr_table + ehdr->e_shstrndx;
    char *string_table;

    string_table = (char *) malloc(shdr->sh_size);
    fseek(fd, shdr->sh_offset, SEEK_SET);
    fread(string_table, shdr->sh_size, 1, fd);

    return string_table;
}

void elf_disasm(Elf64_Ehdr *ehdr, Elf64_Shdr *shdr, char *str_table, uint8_t *data)
{
    int i, k;
    Elf64_Off offset;
    size_t size;
    
    csh handle = 0;
	uint64_t address;
	cs_insn *insn;
	const uint8_t *code;

    for (i = 0; i < ehdr->e_shnum; i++) {        
        if ((strcmp(&str_table[shdr[i].sh_name], ".text")) == 0) {
            offset = shdr[i].sh_offset;
            size = shdr[i].sh_size;
        }
    }
    
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        printf("ERROR: Failed to initialize engine!\n");
        exit(EXIT_FAILURE);
    }
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);   

    printf("Disassembly of section .text:\n");

    for (k = offset; k < offset + size; k++) {
        address = ehdr->e_entry;
        code = &data[k];
        insn = cs_malloc(handle);

        while(cs_disasm_iter(handle, &code, &size, &address, insn)) {
			printf("0x%"PRIx64":\t%s\t\t%s\n",
                    insn->address, insn->mnemonic, insn->op_str);
        }        
    }
    cs_close(&handle);
}

void elf_disasm_32(Elf32_Ehdr *ehdr, Elf32_Shdr *shdr, char *str_table, uint8_t *data)
{
    int i, k;
    Elf32_Off offset;
    size_t size;
    
    csh handle = 0;
	uint64_t address;
	cs_insn *insn;
	const uint8_t *code;

    for (i = 0; i < ehdr->e_shnum; i++) {        
        if ((strcmp(&str_table[shdr[i].sh_name], ".text")) == 0) {
            offset = shdr[i].sh_offset;
            size = shdr[i].sh_size;
        }
    }
    
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK) {
        printf("ERROR: Failed to initialize engine!\n");
        exit(EXIT_FAILURE);
    }
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);   

    printf("Disassembly of section .text:\n");

    for (k = offset; k < offset + size; k++) {
        address = ehdr->e_entry;
        code = &data[k];
        insn = cs_malloc(handle);

        while(cs_disasm_iter(handle, &code, &size, &address, insn)) {
			printf("0x%"PRIx64":\t%s\t\t%s\n",
                    insn->address, insn->mnemonic, insn->op_str);
        }        
    }
    cs_close(&handle);
}
