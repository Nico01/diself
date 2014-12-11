#include <elf.h>
#include <stdlib.h>

size_t file_size(const char *fileName);

/* ELF 64 functions */
Elf64_Ehdr *read_elf_header(FILE *fd);

Elf64_Shdr *read_section_header(Elf64_Ehdr *ehdr, FILE *fd);

char *load_string_table(Elf64_Ehdr *ehdr, Elf64_Shdr *shdr_table, FILE *fd);

void elf_disasm(Elf64_Ehdr *ehdr, Elf64_Shdr *shdr, char *str_table, uint8_t *data);

/* ELF 32 functions */
Elf32_Ehdr *read_elf_header_32(FILE *fd);

Elf32_Shdr *read_section_header_32(Elf32_Ehdr *ehdr, FILE *fd);

char *load_string_table_32(Elf32_Ehdr *ehdr, Elf32_Shdr *shdr_table, FILE *fd);

void elf_disasm_32(Elf32_Ehdr *ehdr, Elf32_Shdr *shdr, char *str_table, uint8_t *data);
