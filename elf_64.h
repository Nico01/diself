#include <elf.h>
#include <stdlib.h>

/* ELF 64 functions */
Elf64_Ehdr *read_elf_header_64(FILE *fd);

Elf64_Shdr *read_section_header_64(Elf64_Ehdr *ehdr, FILE *fd);

char *load_string_table_64(Elf64_Ehdr *ehdr, Elf64_Shdr *shdr, FILE *fd);

uint32_t get_section_offset_64(Elf64_Ehdr *ehdr, Elf64_Shdr *shdr, char *str_table, char *name);

size_t get_section_size_64(Elf64_Ehdr *ehdr, Elf64_Shdr *shdr, char *str_table, char *name);
