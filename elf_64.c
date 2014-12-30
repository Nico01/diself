#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "elf_parser.h"

Elf64_Ehdr *read_elf_header_64(FILE *fd)
{
    Elf64_Ehdr *ehdr = malloc(sizeof(Elf64_Ehdr));

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

Elf64_Shdr *read_section_header_64(Elf64_Ehdr *ehdr, FILE *fd)
{
    size_t size = ehdr->e_shnum * ehdr->e_shentsize;
    Elf64_Shdr *shdr = malloc(size);

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

char *load_string_table_64(Elf64_Ehdr *ehdr, Elf64_Shdr *shdr, FILE *fd)
{
    Elf64_Shdr *shdr_table = shdr + ehdr->e_shstrndx;
    char *string_table = malloc(shdr_table->sh_size);

    if (fseek(fd, shdr_table->sh_offset, SEEK_SET) != 0) {
        free(string_table);
        return NULL;
    }

    if (fread(string_table, shdr_table->sh_size, 1, fd) != 1) {
        free(string_table);
        return NULL;
    }

    return string_table;
}

uint32_t get_section_offset_64(Elf64_Ehdr *ehdr, Elf64_Shdr *shdr, char *str_table, char *name)
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

size_t get_section_size_64(Elf64_Ehdr *ehdr, Elf64_Shdr *shdr, char *str_table, char *name)
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
