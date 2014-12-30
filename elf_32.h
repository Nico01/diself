#include <elf.h>
#include <stdlib.h>

/* ELF 32 functions */
Elf32_Ehdr *read_elf_header_32(FILE *fd);

Elf32_Shdr *read_section_header_32(Elf32_Ehdr *ehdr, FILE *fd);

char *load_string_table_32(Elf32_Ehdr *ehdr, Elf32_Shdr *shdr, FILE *fd);

uint32_t get_section_offset_32(Elf32_Ehdr *ehdr, Elf32_Shdr *shdr, char *str_table, char *name);

size_t get_section_size_32(Elf32_Ehdr *ehdr, Elf32_Shdr *shdr, char *str_table, char *name);
