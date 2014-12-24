#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "elf_32.h"

Elf32_Ehdr *read_elf_header_32(FILE *fd)
{
    Elf32_Ehdr *ehdr = malloc(sizeof(Elf32_Ehdr));

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

Elf32_Shdr *read_section_header_32(Elf32_Ehdr *ehdr, FILE *fd)
{
    size_t size = ehdr->e_shnum * ehdr->e_shentsize;
    Elf32_Shdr *shdr = malloc(size);

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

char *load_string_table_32(Elf32_Ehdr *ehdr, Elf32_Shdr *shdr_table, FILE *fd)
{
    Elf32_Shdr *shdr = shdr_table + ehdr->e_shstrndx;
    char *string_table = malloc(shdr->sh_size);

    if (fseek(fd, shdr->sh_offset, SEEK_SET) != 0) {
        free(string_table);
        return NULL;
    }

    if (fread(string_table, shdr->sh_size, 1, fd) != 1) {
        free(string_table);
        return NULL;
    }

    return string_table;
}

uint32_t get_section_offset_32(Elf32_Ehdr *ehdr, Elf32_Shdr *shdr, char *str_table, char *name)
{
    uint32_t offset = 0;
    int i;

    for (i = 0; i < ehdr->e_shnum; i++) {        
        if ((strcmp(&str_table[shdr[i].sh_name], name)) == 0) {
            offset = shdr[i].sh_offset;
        }
    }
    return offset;
}

size_t get_section_size_32(Elf32_Ehdr *ehdr, Elf32_Shdr *shdr, char *str_table, char *name)
{
    size_t size = 0;
    int i;

    for (i = 0; i < ehdr->e_shnum; i++) {        
        if ((strcmp(&str_table[shdr[i].sh_name], name)) == 0) {
            size = shdr[i].sh_size;
        }
    }
    return size;
}
